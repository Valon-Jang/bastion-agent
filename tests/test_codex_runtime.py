import os
import tempfile
import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from human_codex.codex_runtime import CodexRuntime
from human_codex.paths import PortablePaths
from human_codex.process import CommandResult


class CodexRuntimeTests(unittest.TestCase):
    def test_ensure_home_merges_required_security_policy_without_losing_safe_settings(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = PortablePaths(root / "repo", root / "data")
            runtime = CodexRuntime(paths, executable="codex")
            config = runtime.ensure_home() / "config.toml"
            parsed = tomllib.loads(config.read_text(encoding="utf-8"))
            self.assertEqual(parsed["cli_auth_credentials_store"], "keyring")
            self.assertTrue(runtime._has_security_policy(parsed))
            self.assertEqual(parsed["windows"], {"sandbox": "elevated"})
            self.assertEqual(
                parsed["permissions"][runtime.SECURITY_PROFILE]["filesystem"][":root"],
                "deny",
            )
            self.assertEqual(
                parsed["permissions"][runtime.READ_ONLY_PROFILE]["filesystem"][":root"],
                "deny",
            )
            config.write_text('model_reasoning_effort = "high"\n', encoding="utf-8")
            runtime.ensure_home()
            merged = tomllib.loads(config.read_text(encoding="utf-8"))
            self.assertEqual(merged["model_reasoning_effort"], "high")
            self.assertTrue(runtime._has_security_policy(merged))

    def test_ensure_home_rejects_conflicting_permissions_or_non_keyring_auth(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = PortablePaths(Path(temp) / "repo", Path(temp) / "data")
            runtime = CodexRuntime(paths, executable="codex")
            paths.ensure_data_layout()
            config = paths.codex_home / "config.toml"
            config.write_text('default_permissions = "unsafe"\n', encoding="utf-8")
            with self.assertRaisesRegex(Exception, "permission profile conflicts"):
                runtime.ensure_home()
            config.write_text('cli_auth_credentials_store = "file"\n', encoding="utf-8")
            with self.assertRaisesRegex(Exception, "OS keyring"):
                runtime.ensure_home()

    def test_ensure_home_rejects_legacy_sandbox_mcp_and_external_tool_overrides(self) -> None:
        for unsafe in (
            'sandbox_mode = "danger-full-access"\n',
            '[mcp_servers.leak]\nurl = "https://example.invalid"\n',
            'web_search = "disabled"\n',
            '[apps._default]\nenabled = true\n',
            '[model_providers.leak]\nbase_url = "https://example.invalid"\n',
        ):
            with self.subTest(unsafe=unsafe), tempfile.TemporaryDirectory() as temp:
                paths = PortablePaths(Path(temp) / "repo", Path(temp) / "data")
                runtime = CodexRuntime(paths, executable="codex")
                paths.ensure_data_layout()
                (paths.codex_home / "config.toml").write_text(unsafe, encoding="utf-8")
                with self.assertRaisesRegex(Exception, "security-sensitive"):
                    runtime.ensure_home()

    def test_ensure_home_upgrades_the_previous_app_owned_profile(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = PortablePaths(Path(temp) / "repo", Path(temp) / "data")
            runtime = CodexRuntime(paths, executable="codex")
            paths.ensure_data_layout()
            config = paths.codex_home / "config.toml"
            config.write_text(
                runtime._PROFILE_CONFIG
                + 'cli_auth_credentials_store = "keyring"\n'
                + 'model_reasoning_effort = "high"\n',
                encoding="utf-8",
            )
            runtime.ensure_home()
            content = config.read_text(encoding="utf-8")
            parsed = tomllib.loads(content)
            self.assertIn(runtime._MANAGED_BEGIN, content)
            self.assertTrue(runtime._has_security_policy(parsed))
            self.assertEqual(parsed["model_reasoning_effort"], "high")

    def test_ensure_home_removes_only_legacy_project_trust_entries(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = PortablePaths(Path(temp) / "repo", Path(temp) / "data")
            runtime = CodexRuntime(paths, executable="codex")
            paths.ensure_data_layout()
            config = paths.codex_home / "config.toml"
            config.write_text(
                'cli_auth_credentials_store = "keyring"\n'
                '[projects."C:\\\\legacy"]\n'
                'trust_level = "trusted"\n',
                encoding="utf-8",
            )
            runtime.ensure_home()
            parsed = tomllib.loads(config.read_text(encoding="utf-8"))
            self.assertNotIn("projects", parsed)
            self.assertTrue(runtime._has_security_policy(parsed))

            config.write_text(
                '[projects."C:\\\\legacy"]\n'
                'trust_level = "trusted"\n'
                'extra = "unsafe"\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(Exception, "security-sensitive"):
                runtime.ensure_home()

    def test_codex_environment_is_app_specific(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = PortablePaths(Path(temp) / "repo", Path(temp) / "data")
            environment = paths.codex_environment()
            self.assertEqual(environment["CODEX_HOME"], str(paths.codex_home))
            self.assertEqual(environment["CODEX_SQLITE_HOME"], str(paths.codex_home))

    def test_codex_environment_drops_ambient_secrets_and_credentialed_proxies(self) -> None:
        with tempfile.TemporaryDirectory() as temp, patch.dict(
            os.environ,
            {
                "OPENAI_API_KEY": "never-inherit-this-value",
                "HC_PRIVATE_TOKEN": "never-inherit-this-value",
                "HTTPS_PROXY": "http://user:password@proxy.example:8080",
                "HTTP_PROXY": "http://proxy.example:8080",
            },
            clear=False,
        ):
            paths = PortablePaths(Path(temp) / "repo", Path(temp) / "data")
            environment = paths.codex_environment()
            self.assertNotIn("OPENAI_API_KEY", environment)
            self.assertNotIn("HC_PRIVATE_TOKEN", environment)
            self.assertNotIn("HTTPS_PROXY", environment)
            self.assertEqual(environment["HTTP_PROXY"], "http://proxy.example:8080")

    def test_inspect_uses_advertised_help_not_assumptions(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            paths = PortablePaths(Path(temp) / "repo", Path(temp) / "data")
            runtime = CodexRuntime(paths, executable="codex")

            def fake_run(*args: str, **_: object) -> CommandResult:
                output = {
                    ("--version",): "codex-cli 0.147.0",
                    ("--help",): "Commands: app-server",
                    ("app-server", "--help"): "generate-ts generate-json-schema",
                    ("login", "status"): "Logged in using ChatGPT",
                }[args]
                return CommandResult(args=args, returncode=0, stdout=output, stderr="")

            with patch.object(runtime, "run", side_effect=fake_run):
                info = runtime.inspect()
            self.assertEqual(info.version, "0.147.0")
            self.assertTrue(info.app_server)
            self.assertTrue(info.schema_generation)
            self.assertTrue(info.typescript_generation)
            self.assertEqual(info.login_status, "logged_in")

    def test_unelevated_diagnostic_uses_scoped_policy_without_changing_config(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = PortablePaths(root / "repo", root / "data")
            runtime = CodexRuntime(paths, executable="codex.exe")
            requests: list[tuple[str, dict]] = []

            class FakeClient:
                def __init__(self, _runtime, **kwargs):
                    self.override = kwargs.get("windows_sandbox_override")

                def __enter__(self):
                    self.assert_override = self.override
                    return self

                def __exit__(self, *_args):
                    return None

                def notify(self, *_args):
                    return None

                def request(self, method, params, **_kwargs):
                    requests.append((method, params))
                    if method == "initialize":
                        return {}
                    Path(params["cwd"], "created.txt").write_text(
                        "created", encoding="utf-8"
                    )
                    return {
                        "exitCode": 0,
                        "stdout": (
                            "HC_UNELEVATED_STARTED\n"
                            "HC_UNELEVATED_READ_PASS\n"
                            "HC_UNELEVATED_WRITE_PASS\n"
                            "HC_UNELEVATED_OUTSIDE_DENIED\n"
                            "HC_UNELEVATED_FINISHED\n"
                        ),
                        "stderr": "",
                    }

            with patch("human_codex.app_server.AppServerClient", FakeClient):
                result = runtime.unelevated_sandbox_diagnostic()

            self.assertTrue(result["command_launch"])
            self.assertTrue(result["workspace_read"])
            self.assertTrue(result["workspace_write"])
            self.assertTrue(result["outside_write_denied"])
            self.assertTrue(result["diagnostic_only"])
            self.assertFalse(result["configuration_changed"])
            command_params = requests[1][1]
            self.assertNotIn("permissionProfile", command_params)
            self.assertEqual(command_params["sandboxPolicy"]["type"], "workspaceWrite")
            self.assertFalse(command_params["sandboxPolicy"]["networkAccess"])
            parsed = tomllib.loads(
                (paths.codex_home / "config.toml").read_text(encoding="utf-8")
            )
            self.assertEqual(parsed["windows"]["sandbox"], "elevated")

    def test_corporate_sandbox_test_is_scoped_redacted_and_eligible_for_activation(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = PortablePaths(root / "repo", root / "data")
            paths.repository_root.mkdir()
            runtime = CodexRuntime(paths, executable="codex.exe")
            progress: list[tuple[int, int, str]] = []
            requests: list[dict] = []

            class FakeClient:
                def __init__(self, _runtime, **kwargs):
                    self.override = kwargs.get("windows_sandbox_override")
                    self.default_permissions = kwargs.get(
                        "default_permissions_override"
                    )

                def __enter__(self):
                    self.test_case.assertEqual(self.override, "unelevated")
                    self.test_case.assertEqual(self.default_permissions, ":workspace")
                    return self

                def __exit__(self, *_args):
                    return None

                def notify(self, *_args):
                    return None

                def request(self, method, params, **_kwargs):
                    if method == "initialize":
                        return {}
                    requests.append(params)
                    env = params["env"]
                    command = params["command"]
                    joined = " ".join(command)
                    if "HC_ACL_READY" in joined:
                        stdout = "HC_ACL_READY"
                    elif "child-probe.bat" in joined:
                        Path(env["HC_CHILD_CREATED"]).write_text("ok", encoding="utf-8")
                        stdout = "\n".join(
                            (
                                "HC_CHILD_STARTED",
                                "HC_CHILD_WORKSPACE_WRITE_PASS",
                                "HC_CHILD_OUTSIDE_READ_DENIED",
                                "HC_CHILD_OUTSIDE_WRITE_DENIED",
                                "HC_CHILD_SECRET_DENIED",
                                "HC_CHILD_FINISHED",
                            )
                        )
                    elif "HC_NETWORK_FINISHED" in joined:
                        stdout = "\n".join(
                            (
                                "HC_IPV4_DENIED",
                                "HC_DNS_DENIED",
                                "HC_LOOPBACK_DENIED",
                                "HC_ADMIN_DENIED",
                                "HC_REGISTRY_DENIED",
                                "HC_NETWORK_FINISHED",
                            )
                        )
                    elif Path(command[0]).name.casefold() == "powershell.exe":
                        stdout = "\n".join(
                            (
                                "HC_PS_STARTED",
                                "HC_ADMIN_DENIED",
                                "HC_REGISTRY_DENIED",
                                "HC_IPV4_DENIED",
                                "HC_DNS_DENIED",
                                "HC_LOOPBACK_DENIED",
                                "HC_PS_FINISHED",
                            )
                        )
                    elif params.get("permissionProfile") == runtime.SECURITY_PROFILE:
                        Path(env["HC_PROFILE_CREATED"]).write_text("ok", encoding="utf-8")
                        stdout = "\n".join(
                            (
                                "HC_PROFILE_STARTED",
                                "HC_PROFILE_READ_PASS",
                                "HC_PROFILE_WRITE_PASS",
                                "HC_PROFILE_ENV_DENIED",
                                "HC_PROFILE_KEY_DENIED",
                                "HC_PROFILE_METADATA_DENIED",
                                "HC_PROFILE_OUTSIDE_DENIED",
                                "HC_PROFILE_FINISHED",
                            )
                        )
                    elif params.get("permissionProfile") == ":read-only":
                        stdout = "\n".join(
                            (
                                "HC_RO_STARTED",
                                "HC_RO_READ_PASS",
                                "HC_RO_WRITE_DENIED",
                                "HC_RO_OUTSIDE_DENIED",
                                "HC_RO_CHILD_WRITE_DENIED",
                                "HC_RO_FINISHED",
                            )
                        )
                    elif "link-probe.bat" in joined:
                        stdout = "\n".join(
                            (
                                "HC_JUNCTION_READ_DENIED",
                                "HC_JUNCTION_WRITE_DENIED",
                                "HC_HARDLINK_READ_DENIED",
                                "HC_HARDLINK_WRITE_DENIED",
                                "HC_LINK_FINISHED",
                            )
                        )
                    else:
                        Path(env["HC_WS_CREATED"]).write_text("ok", encoding="utf-8")
                        stdout = "\n".join(
                            (
                                "HC_DIRECT_STARTED",
                                "HC_WS_READ_PASS",
                                "HC_WS_WRITE_PASS",
                                "HC_OUTSIDE_READ_DENIED",
                                "HC_OUTSIDE_WRITE_DENIED",
                                "HC_CODEX_HOME_READ_DENIED",
                                "HC_CODEX_HOME_WRITE_DENIED",
                                "HC_SECRET_ENV_DENIED",
                                "HC_SECRET_KEY_DENIED",
                                "HC_METADATA_READ_PASS",
                                "HC_METADATA_WRITE_DENIED",
                                "HC_DIRECT_FINISHED",
                            )
                        )
                    return {"exitCode": 0, "stdout": stdout, "stderr": ""}

            FakeClient.test_case = self
            with (
                patch("human_codex.app_server.AppServerClient", FakeClient),
                patch.object(runtime, "_windows_filesystem_name", return_value="NTFS"),
                patch.object(runtime, "_create_directory_junction", return_value=True),
                patch.object(runtime, "prepare_corporate_workspace_roots"),
            ):
                result = runtime.corporate_sandbox_test(
                    progress_callback=lambda completed, total, stage: progress.append(
                        (completed, total, stage)
                    )
                )

            self.assertEqual(result["checks_total"], 47)
            self.assertEqual(result["checks_passed"], 47)
            self.assertEqual(result["verdict"], "candidate")
            self.assertTrue(result["activation_eligible"])
            self.assertTrue(result["test_only"])
            self.assertFalse(result["production_approved"])
            self.assertFalse(result["chat_unlocked"])
            self.assertFalse(result["configuration_changed"])
            self.assertEqual(progress[-1], (47, 47, "cleanup"))
            self.assertEqual(len(requests), 8)
            self.assertTrue(
                all(
                    params.get("sandboxPolicy", {}).get("networkAccess") is False
                    or params.get("permissionProfile")
                    in {":read-only", runtime.SECURITY_PROFILE}
                    for params in requests
                )
            )
            self.assertEqual(
                {
                    params.get("permissionProfile")
                    for params in requests
                },
                {None, ":read-only", runtime.SECURITY_PROFILE},
            )
            self.assertNotIn("stdout", result)
            parsed = tomllib.loads(
                (paths.codex_home / "config.toml").read_text(encoding="utf-8")
            )
            self.assertEqual(parsed["windows"]["sandbox"], "elevated")

    def test_sandbox_log_evidence_returns_allowlisted_codes_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            paths = PortablePaths(root / "repo", root / "data")
            runtime = CodexRuntime(paths, executable="codex.exe")
            sandbox = paths.codex_home / ".sandbox"
            sandbox.mkdir(parents=True)
            (sandbox / "sandbox.log").write_text(
                "ERROR_LOGON_TYPE_NOT_GRANTED 1385 AppLocker access is denied SECRET=never-return",
                encoding="utf-8",
            )
            self.assertEqual(
                runtime.sandbox_log_evidence(),
                ["windows_error_1385", "application_control", "access_denied"],
            )


if __name__ == "__main__":
    unittest.main()
