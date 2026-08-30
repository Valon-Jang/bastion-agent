import tempfile
import unittest
from pathlib import Path

from human_codex.vault import AesGcmVault, DpapiMasterKeyStore, VaultError


@unittest.skipUnless(__import__("os").name == "nt", "DPAPI requires Windows")
class VaultTests(unittest.TestCase):
    def test_dpapi_key_and_aes_gcm_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            store = DpapiMasterKeyStore(Path(temp) / "master_key.dpapi")
            key = store.load_or_create()
            self.assertEqual(key, store.load_or_create())
            self.assertNotIn(key, (Path(temp) / "master_key.dpapi").read_bytes())
            vault = AesGcmVault(key)
            sealed = vault.encrypt(b"secret", context="project:alpha")
            self.assertEqual(vault.decrypt(sealed, context="project:alpha"), b"secret")

    def test_existing_invalid_key_path_is_never_overwritten(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "master_key.dpapi"
            path.write_bytes(b"invalid-existing-value")
            with self.assertRaises(VaultError):
                DpapiMasterKeyStore(path).load_or_create()
            self.assertEqual(path.read_bytes(), b"invalid-existing-value")

    def test_tampering_and_context_change_are_rejected(self) -> None:
        vault = AesGcmVault(bytes(range(32)))
        sealed = vault.encrypt(b"secret", context="project:alpha")
        with self.assertRaises(VaultError):
            vault.decrypt(sealed, context="project:beta")
        tampered = sealed.as_dict()
        tampered["ciphertext"] = tampered["ciphertext"][:-2] + "AA"
        with self.assertRaises(VaultError):
            vault.decrypt(tampered, context="project:alpha")

    def test_blind_indexes_are_deterministic_context_bound_and_non_plaintext(self) -> None:
        vault = AesGcmVault(b"i" * 32)
        first = vault.blind_index("D:\\Sensitive\\Project", context="path")
        self.assertEqual(first, vault.blind_index("d:\\sensitive\\project", context="path"))
        self.assertNotEqual(first, vault.blind_index("D:\\Sensitive\\Project", context="other"))
        self.assertNotIn("Sensitive", first)


if __name__ == "__main__":
    unittest.main()
