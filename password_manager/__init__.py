"""Educational password manager package."""

from .manager import Credential, PasswordManager, PasswordManagerError, StoragePaths

__all__ = [
    "Credential",
    "PasswordManager",
    "PasswordManagerError",
    "StoragePaths",
]
