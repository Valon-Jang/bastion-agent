from __future__ import annotations

import json
import os
import re
import shutil
import uuid
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, urlopen

from human_codex.paths import PortablePaths, require_within


class SkillError(RuntimeError):
    """A bounded, user-facing failure while discovering or installing a skill."""


class SkillManager:
    """Install inert skill files into the portable Codex home.

    Downloaded files are validated and staged, but scripts are never executed by
    the installer. Codex decides when a skill is invoked in a later Turn.
    """

    OFFICIAL_OWNER = "openai"
    OFFICIAL_REPOSITORY = "skills"
    OFFICIAL_REF = "main"
    OFFICIAL_ROOT = "skills/.curated"
    API_ROOT = "https://api.github.com"
    MAX_RESPONSE_BYTES = 8 * 1024 * 1024
    MAX_FILE_BYTES = 5 * 1024 * 1024
    MAX_TOTAL_BYTES = 25 * 1024 * 1024
    MAX_FILES = 256
    MAX_DEPTH = 12
    NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
    REPOSITORY_PART = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")

    def __init__(self, paths: PortablePaths) -> None:
        self.paths = paths
        self.paths.ensure_data_layout()

    def list_installed(self) -> list[dict[str, Any]]:
        installed: list[dict[str, Any]] = []
        for folder in sorted(self.paths.skills_root.iterdir(), key=lambda item: item.name.casefold()):
            skill_file = folder / "SKILL.md"
            if not folder.is_dir() or not skill_file.is_file():
                continue
            try:
                text = skill_file.read_text(encoding="utf-8")[:64_000]
            except (OSError, UnicodeError):
                continue
            metadata = self._frontmatter(text)
            installed.append(
                {
                    "name": str(metadata.get("name") or folder.name)[:120],
                    "folder": folder.name,
                    "description": str(metadata.get("description") or "")[:500],
                    "path": str(folder),
                }
            )
        return installed

    def catalog(self, query: str = "") -> list[dict[str, Any]]:
        normalized = query.strip().casefold()
        entries = self._json(
            f"{self.API_ROOT}/repos/{self.OFFICIAL_OWNER}/{self.OFFICIAL_REPOSITORY}"
            f"/contents/{self.OFFICIAL_ROOT}?ref={self.OFFICIAL_REF}"
        )
        if not isinstance(entries, list):
            raise SkillError("공식 스킬 목록 형식이 올바르지 않습니다")
        installed = {item["folder"].casefold() for item in self.list_installed()}
        result: list[dict[str, Any]] = []
        for entry in entries:
            if not isinstance(entry, dict) or entry.get("type") != "dir":
                continue
            name = entry.get("name")
            if not isinstance(name, str) or not self.NAME.fullmatch(name):
                continue
            if normalized and normalized not in name.casefold():
                continue
            result.append(
                {
                    "name": name,
                    "source": name,
                    "url": f"https://github.com/openai/skills/tree/main/{self.OFFICIAL_ROOT}/{name}",
                    "installed": name.casefold() in installed,
                    "source_type": "openai",
                    "repository": "openai/skills",
                }
            )
        if normalized:
            try:
                result.extend(self._github_catalog(query.strip(), installed))
            except SkillError:
                # Keep useful official results when repository discovery is rate
                # limited. If nothing was found, expose the network failure.
                if not result:
                    raise
        deduplicated: dict[str, dict[str, Any]] = {}
        for item in result:
            deduplicated.setdefault(str(item["url"]).casefold(), item)
        return sorted(
            deduplicated.values(),
            key=lambda item: (
                item.get("source_type") != "openai",
                str(item["name"]).casefold(),
                str(item.get("repository", "")).casefold(),
            ),
        )[:100]

    def _github_catalog(
        self, query: str, installed: set[str]
    ) -> list[dict[str, Any]]:
        if not 1 <= len(query) <= 120:
            raise SkillError("GitHub 스킬 검색어는 1~120자로 입력하세요")
        parameters = urlencode(
            {
                "q": f"{query} codex skill",
                "sort": "stars",
                "order": "desc",
                "per_page": "8",
            }
        )
        response = self._json(f"{self.API_ROOT}/search/repositories?{parameters}")
        repositories = response.get("items") if isinstance(response, dict) else None
        if not isinstance(repositories, list):
            raise SkillError("GitHub 저장소 검색 결과가 올바르지 않습니다")
        results: list[dict[str, Any]] = []
        for repository_entry in repositories[:8]:
            if not isinstance(repository_entry, dict):
                continue
            full_name = repository_entry.get("full_name")
            default_branch = repository_entry.get("default_branch")
            if not isinstance(full_name, str) or not isinstance(default_branch, str):
                continue
            parts = full_name.split("/", 1)
            if (
                len(parts) != 2
                or not self.REPOSITORY_PART.fullmatch(parts[0])
                or not self.REPOSITORY_PART.fullmatch(parts[1])
                or not self.REPOSITORY_PART.fullmatch(default_branch)
            ):
                continue
            owner, repository = parts
            tree = self._json(
                f"{self.API_ROOT}/repos/{owner}/{repository}/git/trees/"
                f"{quote(default_branch, safe='')}?recursive=1"
            )
            entries = tree.get("tree") if isinstance(tree, dict) else None
            if not isinstance(entries, list):
                continue
            repository_results = 0
            for entry in entries:
                if not isinstance(entry, dict) or entry.get("type") != "blob":
                    continue
                path = entry.get("path")
                if not isinstance(path, str) or not path.casefold().endswith("/skill.md"):
                    continue
                skill_path = str(PurePosixPath(path).parent)
                self._safe_relative(skill_path)
                name = PurePosixPath(skill_path).name
                if not self.NAME.fullmatch(name):
                    continue
                url = (
                    f"https://github.com/{owner}/{repository}/tree/"
                    f"{default_branch}/{skill_path}"
                )
                results.append(
                    {
                        "name": name,
                        "source": url,
                        "url": url,
                        "installed": name.casefold() in installed,
                        "source_type": "github",
                        "repository": full_name,
                    }
                )
                repository_results += 1
                if repository_results >= 3 or len(results) >= 30:
                    break
            if len(results) >= 30:
                break
        return results

    def install(self, source: str, *, approved: bool) -> dict[str, Any]:
        if approved is not True:
            raise SkillError("스킬 설치에는 사용자 확인이 필요합니다")
        owner, repository, ref, repository_path = self._parse_source(source)
        destination_name = PurePosixPath(repository_path).name
        if not self.NAME.fullmatch(destination_name):
            raise SkillError("스킬 폴더 이름이 올바르지 않습니다")
        destination = self.paths.skills_root / destination_name
        if destination.exists():
            raise SkillError("같은 이름의 스킬이 이미 설치되어 있습니다")

        staging_parent = self.paths.data_root / "temp"
        staging = staging_parent / f"skill-install-{uuid.uuid4().hex}"
        staged_skill = staging / destination_name
        try:
            staged_skill.mkdir(parents=True, exist_ok=False)
            state = {"files": 0, "bytes": 0}
            self._download_directory(
                owner, repository, ref, repository_path, staged_skill, state, depth=0
            )
            if not (staged_skill / "SKILL.md").is_file():
                raise SkillError("선택한 폴더에 필수 SKILL.md 파일이 없습니다")
            os.replace(staged_skill, destination)
        except FileExistsError as exc:
            raise SkillError("같은 이름의 스킬이 이미 설치되어 있습니다") from exc
        except OSError as exc:
            raise SkillError("설치 폴더에 스킬을 저장하지 못했습니다") from exc
        finally:
            shutil.rmtree(staging, ignore_errors=True)
        return {
            "installed": True,
            "name": destination_name,
            "path": str(destination),
            "source": f"https://github.com/{owner}/{repository}/tree/{ref}/{repository_path}",
            "files": state["files"],
            "bytes": state["bytes"],
            "scripts_executed": False,
        }

    def _parse_source(self, source: str) -> tuple[str, str, str, str]:
        value = source.strip()
        if not value or len(value) > 2_048:
            raise SkillError("스킬 이름 또는 GitHub 주소를 입력하세요")
        if self.NAME.fullmatch(value):
            available = {item["name"].casefold(): item["name"] for item in self.catalog(value)}
            canonical = available.get(value.casefold())
            if canonical is None:
                raise SkillError("OpenAI 공식 스킬 목록에서 해당 이름을 찾지 못했습니다")
            return (
                self.OFFICIAL_OWNER,
                self.OFFICIAL_REPOSITORY,
                self.OFFICIAL_REF,
                f"{self.OFFICIAL_ROOT}/{canonical}",
            )

        try:
            parsed = urlsplit(value)
        except ValueError as exc:
            raise SkillError("GitHub 스킬 주소가 올바르지 않습니다") from exc
        if parsed.scheme != "https" or parsed.hostname != "github.com" or parsed.query or parsed.fragment:
            raise SkillError("https://github.com 주소만 설치할 수 있습니다")
        parts = [item for item in parsed.path.split("/") if item]
        if len(parts) < 5 or parts[2] != "tree":
            raise SkillError("GitHub의 /owner/repo/tree/ref/path 주소를 입력하세요")
        owner, repository, _, ref, *path_parts = parts
        if repository.endswith(".git"):
            repository = repository[:-4]
        if (
            not self.REPOSITORY_PART.fullmatch(owner)
            or not self.REPOSITORY_PART.fullmatch(repository)
            or not self.REPOSITORY_PART.fullmatch(ref)
            or not path_parts
        ):
            raise SkillError("GitHub 스킬 주소가 올바르지 않습니다")
        repository_path = str(PurePosixPath(*path_parts))
        self._safe_relative(repository_path)
        return owner, repository, ref, repository_path

    def _download_directory(
        self,
        owner: str,
        repository: str,
        ref: str,
        repository_path: str,
        destination: Path,
        state: dict[str, int],
        *,
        depth: int,
    ) -> None:
        if depth > self.MAX_DEPTH:
            raise SkillError("스킬 폴더 깊이가 허용 범위를 초과했습니다")
        encoded_path = quote(repository_path, safe="/")
        entries = self._json(
            f"{self.API_ROOT}/repos/{owner}/{repository}/contents/{encoded_path}?ref={quote(ref, safe='')}"
        )
        if not isinstance(entries, list):
            raise SkillError("GitHub 스킬 폴더를 읽지 못했습니다")
        for entry in entries:
            if not isinstance(entry, dict):
                raise SkillError("GitHub 응답 형식이 올바르지 않습니다")
            name = entry.get("name")
            kind = entry.get("type")
            path = entry.get("path")
            if not isinstance(name, str) or not isinstance(path, str):
                raise SkillError("GitHub 응답에 파일 경로가 없습니다")
            self._safe_relative(name)
            target = destination / name
            require_within(target, destination)
            if kind == "dir":
                target.mkdir(parents=False, exist_ok=False)
                self._download_directory(
                    owner, repository, ref, path, target, state, depth=depth + 1
                )
                continue
            if kind != "file":
                raise SkillError("심볼릭 링크나 하위 저장소가 포함된 스킬은 설치할 수 없습니다")
            if state["files"] >= self.MAX_FILES:
                raise SkillError("스킬 파일 수가 허용 범위를 초과했습니다")
            download_url = entry.get("download_url")
            if not isinstance(download_url, str):
                raise SkillError("스킬 파일 다운로드 주소가 없습니다")
            parsed_download = urlsplit(download_url)
            if parsed_download.scheme != "https" or parsed_download.hostname != "raw.githubusercontent.com":
                raise SkillError("신뢰할 수 없는 스킬 파일 다운로드 주소입니다")
            data = self._bytes(download_url, self.MAX_FILE_BYTES)
            if state["bytes"] + len(data) > self.MAX_TOTAL_BYTES:
                raise SkillError("스킬 전체 크기가 허용 범위를 초과했습니다")
            target.write_bytes(data)
            state["files"] += 1
            state["bytes"] += len(data)

    def _json(self, url: str) -> Any:
        try:
            return json.loads(self._bytes(url, self.MAX_RESPONSE_BYTES))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise SkillError("웹에서 받은 스킬 정보 형식이 올바르지 않습니다") from exc

    @staticmethod
    def _frontmatter(text: str) -> dict[str, str]:
        if not text.startswith("---"):
            return {}
        end = text.find("\n---", 3)
        if end < 0:
            return {}
        result: dict[str, str] = {}
        for line in text[3:end].splitlines():
            key, separator, value = line.partition(":")
            if separator and key.strip() in {"name", "description"}:
                result[key.strip()] = value.strip().strip("'\"")
        return result

    @staticmethod
    def _safe_relative(value: str) -> None:
        path = PurePosixPath(value)
        if (
            not value
            or path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
            or any(":" in part or "\\" in part for part in path.parts)
        ):
            raise SkillError("스킬에 안전하지 않은 파일 경로가 포함되어 있습니다")

    def _bytes(self, url: str, maximum: int) -> bytes:
        request = Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "Human-Codex-Skill-Installer/1",
            },
        )
        try:
            with urlopen(request, timeout=20) as response:
                declared = response.headers.get("Content-Length")
                if declared and int(declared) > maximum:
                    raise SkillError("웹 응답 크기가 허용 범위를 초과했습니다")
                data = response.read(maximum + 1)
        except SkillError:
            raise
        except (HTTPError, URLError, TimeoutError, OSError, ValueError) as exc:
            raise SkillError("GitHub에서 스킬 정보를 가져오지 못했습니다") from exc
        if len(data) > maximum:
            raise SkillError("웹 응답 크기가 허용 범위를 초과했습니다")
        return data
