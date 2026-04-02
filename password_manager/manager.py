"""Core vault and cryptography logic for the password manager."""

from __future__ import annotations

import base64
import json
import secrets
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Literal, Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

PBKDF2_ITERATIONS = 480_000
SALT_SIZE = 16
DEFAULT_PASSWORD_LENGTH = 16
MIN_MASTER_PASSWORD_LENGTH = 8
MIN_GENERATED_PASSWORD_LENGTH = 8
MAX_GENERATED_PASSWORD_LENGTH = 128
SetupStatus = Literal["missing", "ready", "incomplete"]


class PasswordManagerError(Exception):
    """Base exception for password manager failures."""


class IncompleteSetupError(PasswordManagerError):
    """Raised when only part of the login material exists on disk."""


class NotLoggedInError(PasswordManagerError):
    """Raised when a vault action is attempted without a valid key."""


class VaultCorruptedError(PasswordManagerError):
    """Raised when encrypted vault data cannot be decoded safely."""


@dataclass(frozen=True)
class StoragePaths:
    """Filesystem locations used by the password manager."""

    vault_file: Path = Path("vault.enc")
    master_hash_file: Path = Path("master.hash")
    salt_file: Path = Path("salt.bin")


@dataclass(frozen=True)
class Credential:
    """A single saved credential entry."""

    username: str
    password: str


class PasswordManager:
    """Manage encrypted password storage for the CLI application."""

    def __init__(self, storage_paths: Optional[StoragePaths] = None) -> None:
        self.storage_paths = storage_paths or StoragePaths()
        self.logged_in = False
        self._key: Optional[bytes] = None

    def setup_status(self) -> SetupStatus:
        """Return whether local setup is missing, incomplete, or ready."""
        master_hash_exists = self.storage_paths.master_hash_file.exists()
        salt_exists = self.storage_paths.salt_file.exists()

        if not master_hash_exists and not salt_exists:
            return "missing"

        if master_hash_exists and salt_exists:
            return "ready"

        return "incomplete"

    def create_master_password(self, password: str, confirmation: str) -> None:
        """Create the master password and initialize an empty encrypted vault."""
        self._validate_master_password(password, confirmation)

        salt = secrets.token_bytes(SALT_SIZE)
        master_hash = self._hash_master_password(password, salt)

        self.storage_paths.salt_file.write_bytes(salt)
        self.storage_paths.master_hash_file.write_bytes(master_hash)

        self._key = self._derive_key(password, salt)
        self.logged_in = True
        self._save_vault({})

    def login(self, password: str) -> bool:
        """Attempt to unlock the vault with the provided master password."""
        if self.setup_status() == "incomplete":
            raise IncompleteSetupError(
                "Login files are incomplete. Restore both 'master.hash' and 'salt.bin'."
            )

        salt = self.storage_paths.salt_file.read_bytes()
        stored_hash = self.storage_paths.master_hash_file.read_bytes()
        entered_hash = self._hash_master_password(password, salt)

        if not secrets.compare_digest(stored_hash, entered_hash):
            return False

        self._key = self._derive_key(password, salt)
        self.logged_in = True
        return True

    def add_password(self, site: str, username: str, password: str) -> None:
        """Save credentials for a site."""
        normalized_site = site.strip()
        if not normalized_site:
            raise ValueError("Site name cannot be empty.")

        if not password:
            raise ValueError("Password cannot be empty.")

        vault = self._load_vault()
        vault[normalized_site] = Credential(username=username, password=password)
        self._save_vault(vault)

    def get_password(self, site: str) -> Optional[Credential]:
        """Return credentials for a site if they exist."""
        vault = self._load_vault()
        return vault.get(site.strip())

    def edit_password(
        self,
        site: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
    ) -> bool:
        """Update an existing credential entry."""
        normalized_site = site.strip()
        vault = self._load_vault()
        current = vault.get(normalized_site)

        if current is None:
            return False

        vault[normalized_site] = Credential(
            username=current.username if username is None else username,
            password=current.password if password is None else password,
        )
        self._save_vault(vault)
        return True

    def list_sites(self) -> List[str]:
        """Return all stored site names in sorted order."""
        vault = self._load_vault()
        return sorted(vault)

    def delete_password(self, site: str) -> bool:
        """Delete credentials for a site."""
        normalized_site = site.strip()
        vault = self._load_vault()

        if normalized_site not in vault:
            return False

        del vault[normalized_site]
        self._save_vault(vault)
        return True

    @staticmethod
    def generate_password(length: int = DEFAULT_PASSWORD_LENGTH) -> str:
        """Generate a strong random password with mixed character classes."""
        if not isinstance(length, int):
            raise ValueError("Password length must be a whole number.")

        if length < MIN_GENERATED_PASSWORD_LENGTH:
            raise ValueError(
                "Password length must be at least "
                f"{MIN_GENERATED_PASSWORD_LENGTH} characters."
            )

        if length > MAX_GENERATED_PASSWORD_LENGTH:
            raise ValueError(
                "Password length must be no more than "
                f"{MAX_GENERATED_PASSWORD_LENGTH} characters."
            )

        lowercase = "abcdefghijklmnopqrstuvwxyz"
        uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        digits = "0123456789"
        symbols = "!@#$%^&*"
        alphabet = lowercase + uppercase + digits + symbols

        password_chars = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(symbols),
        ]
        password_chars.extend(
            secrets.choice(alphabet) for _ in range(length - len(password_chars))
        )
        secrets.SystemRandom().shuffle(password_chars)
        return "".join(password_chars)

    @staticmethod
    def _validate_master_password(password: str, confirmation: str) -> None:
        if not password:
            raise ValueError("Master password cannot be empty.")

        if len(password) < MIN_MASTER_PASSWORD_LENGTH:
            raise ValueError(
                "Master password must be at least "
                f"{MIN_MASTER_PASSWORD_LENGTH} characters long."
            )

        if password != confirmation:
            raise ValueError("Passwords don't match.")

    @staticmethod
    def _derive_key(password: str, salt: bytes) -> bytes:
        """Derive the Fernet key used to encrypt the vault."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))

    @staticmethod
    def _hash_master_password(password: str, salt: bytes) -> bytes:
        """Hash the master password for later verification."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
        )
        return kdf.derive(password.encode("utf-8"))

    def _load_vault(self) -> Dict[str, Credential]:
        """Decrypt and deserialize the vault."""
        key = self._require_key()
        vault_file = self.storage_paths.vault_file

        if not vault_file.exists():
            return {}

        encrypted_payload = vault_file.read_bytes()
        cipher = Fernet(key)

        try:
            decrypted_payload = cipher.decrypt(encrypted_payload)
        except InvalidToken as error:
            raise VaultCorruptedError(
                "Vault could not be decrypted. The password is wrong "
                "or the vault was modified."
            ) from error

        try:
            raw_vault = json.loads(decrypted_payload.decode("utf-8"))
        except json.JSONDecodeError as error:
            raise VaultCorruptedError(
                "Vault contents are corrupted and could not be decoded."
            ) from error

        if not isinstance(raw_vault, dict):
            raise VaultCorruptedError("Vault contents are corrupted and invalid.")

        vault: Dict[str, Credential] = {}
        for site, entry in raw_vault.items():
            if not isinstance(site, str) or not isinstance(entry, dict):
                raise VaultCorruptedError("Vault contents are corrupted and invalid.")

            username = entry.get("username")
            password = entry.get("password")
            if not isinstance(username, str) or not isinstance(password, str):
                raise VaultCorruptedError("Vault contents are corrupted and invalid.")

            vault[site] = Credential(username=username, password=password)

        return vault

    def _save_vault(self, vault: Dict[str, Credential]) -> None:
        """Encrypt and persist the vault."""
        key = self._require_key()
        serialized_vault = {
            site: asdict(credential) for site, credential in sorted(vault.items())
        }
        encrypted_payload = Fernet(key).encrypt(
            json.dumps(serialized_vault, sort_keys=True).encode("utf-8")
        )
        self.storage_paths.vault_file.write_bytes(encrypted_payload)

    def _require_key(self) -> bytes:
        if self._key is None:
            raise NotLoggedInError("You must login first.")
        return self._key
