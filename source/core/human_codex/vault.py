from __future__ import annotations

import base64
import ctypes
import hashlib
import hmac
import os
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class VaultError(RuntimeError):
    """Raised without including plaintext, keys, or ciphertext in diagnostics."""


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]


CRYPTPROTECT_UI_FORBIDDEN = 0x1


def _blob(data: bytes) -> tuple[_DataBlob, ctypes.Array[ctypes.c_char]]:
    buffer = ctypes.create_string_buffer(data, len(data))
    return _DataBlob(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))), buffer


class DpapiMasterKeyStore:
    """Stores only a Windows-user-bound encrypted 256-bit AES key on disk."""

    def __init__(self, key_path: Path) -> None:
        self.key_path = key_path

    def load_or_create(self) -> bytes:
        if self.key_path.exists():
            return self._load_existing()
        key = os.urandom(32)
        protected = self._protect(key)
        self.key_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor: int | None = None
        created = False
        try:
            descriptor = os.open(
                self.key_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
                0o600,
            )
            created = True
        except FileExistsError:
            return self._load_existing()
        try:
            assert descriptor is not None
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = None
                handle.write(protected)
                handle.flush()
                os.fsync(handle.fileno())
            persisted = self._unprotect(self.key_path.read_bytes())
            if not hmac.compare_digest(persisted, key):
                raise VaultError("DPAPI master key verification failed")
            return key
        except Exception as exc:
            if descriptor is not None:
                os.close(descriptor)
            if created:
                try:
                    self.key_path.unlink(missing_ok=True)
                except OSError:
                    pass
            if isinstance(exc, VaultError):
                raise
            raise VaultError("DPAPI master key could not be stored") from exc

    def _load_existing(self) -> bytes:
        try:
            if (
                not self.key_path.is_file()
                or self.key_path.is_symlink()
                or (
                    hasattr(os.path, "isjunction")
                    and os.path.isjunction(self.key_path)
                )
            ):
                raise VaultError("DPAPI master key path is unsafe")
            protected = self.key_path.read_bytes()
        except VaultError:
            raise
        except OSError as exc:
            raise VaultError("DPAPI master key could not be read") from exc
        return self._unprotect(protected)

    @staticmethod
    def _protect(data: bytes) -> bytes:
        if os.name != "nt":
            raise VaultError("DPAPI is unavailable on this operating system")
        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        input_blob, _input_buffer = _blob(data)
        output_blob = _DataBlob()
        crypt32.CryptProtectData.argtypes = [ctypes.POINTER(_DataBlob), wintypes.LPCWSTR, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DataBlob)]
        crypt32.CryptProtectData.restype = wintypes.BOOL
        if not crypt32.CryptProtectData(ctypes.byref(input_blob), "Human Codex master key", None, None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(output_blob)):
            raise VaultError(f"DPAPI protect failed with Windows error {ctypes.get_last_error()}")
        try:
            return ctypes.string_at(output_blob.pbData, output_blob.cbData)
        finally:
            kernel32.LocalFree(output_blob.pbData)

    @staticmethod
    def _unprotect(data: bytes) -> bytes:
        if os.name != "nt":
            raise VaultError("DPAPI is unavailable on this operating system")
        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        input_blob, _input_buffer = _blob(data)
        output_blob = _DataBlob()
        crypt32.CryptUnprotectData.argtypes = [ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DataBlob)]
        crypt32.CryptUnprotectData.restype = wintypes.BOOL
        if not crypt32.CryptUnprotectData(ctypes.byref(input_blob), None, None, None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(output_blob)):
            raise VaultError("DPAPI unprotect failed for the current Windows user")
        try:
            return ctypes.string_at(output_blob.pbData, output_blob.cbData)
        finally:
            kernel32.LocalFree(output_blob.pbData)


@dataclass(frozen=True)
class VaultCiphertext:
    version: str
    nonce: str
    ciphertext: str

    def as_dict(self) -> dict[str, str]:
        return {"version": self.version, "nonce": self.nonce, "ciphertext": self.ciphertext}


class AesGcmVault:
    """AES-256-GCM vault; caller-supplied context is authenticated additional data."""

    VERSION = "hc-vault/1"

    def __init__(self, master_key: bytes) -> None:
        if len(master_key) != 32:
            raise VaultError("master key must be 256 bits")
        self._cipher = AESGCM(master_key)
        self._index_key = hmac.new(master_key, b"hc-vault-index/1", hashlib.sha256).digest()

    def encrypt(self, plaintext: bytes, *, context: str) -> VaultCiphertext:
        nonce = os.urandom(12)
        encrypted = self._cipher.encrypt(nonce, plaintext, self._aad(context))
        return VaultCiphertext(
            self.VERSION,
            base64.b64encode(nonce).decode("ascii"),
            base64.b64encode(encrypted).decode("ascii"),
        )

    def decrypt(self, value: VaultCiphertext | dict[str, str], *, context: str) -> bytes:
        payload = VaultCiphertext(**value) if isinstance(value, dict) else value
        if payload.version != self.VERSION:
            raise VaultError("unsupported vault ciphertext version")
        try:
            return self._cipher.decrypt(
                base64.b64decode(payload.nonce, validate=True),
                base64.b64decode(payload.ciphertext, validate=True),
                self._aad(context),
            )
        except Exception as exc:
            raise VaultError("vault ciphertext failed authentication") from exc

    def _aad(self, context: str) -> bytes:
        return f"{self.VERSION}:{context}".encode("utf-8")

    def blind_index(self, value: str, *, context: str) -> str:
        """Return a deterministic, keyed lookup token without exposing ``value``."""

        normalized = value.casefold().encode("utf-8")
        return hmac.new(
            self._index_key,
            f"{self.VERSION}:{context}:".encode("utf-8") + normalized,
            hashlib.sha256,
        ).hexdigest()
