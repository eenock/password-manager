"""Unit tests for the password manager core."""

import tempfile
import unittest
from pathlib import Path

from password_manager.manager import (
    MIN_GENERATED_PASSWORD_LENGTH,
    Credential,
    PasswordManager,
    StoragePaths,
)


class PasswordManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        base_path = Path(self.temp_dir.name)
        self.storage_paths = StoragePaths(
            vault_file=base_path / "vault.enc",
            master_hash_file=base_path / "master.hash",
            salt_file=base_path / "salt.bin",
        )
        self.manager = PasswordManager(storage_paths=self.storage_paths)

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def test_create_login_and_vault_roundtrip(self) -> None:
        self.manager.create_master_password(
            "correct horse battery staple",
            "correct horse battery staple",
        )

        self.assertTrue(self.storage_paths.vault_file.exists())
        self.assertTrue(self.manager.logged_in)

        self.manager.add_password("github", "enock", "SecretPass123!")
        self.assertEqual(
            self.manager.get_password("github"),
            Credential(username="enock", password="SecretPass123!"),
        )
        self.assertEqual(self.manager.list_sites(), ["github"])

        logged_out_manager = PasswordManager(storage_paths=self.storage_paths)
        self.assertTrue(logged_out_manager.login("correct horse battery staple"))
        self.assertEqual(
            logged_out_manager.get_password("github"),
            Credential(username="enock", password="SecretPass123!"),
        )

    def test_generate_password_contains_mixed_character_types(self) -> None:
        password = self.manager.generate_password(24)

        self.assertTrue(any(character.islower() for character in password))
        self.assertTrue(any(character.isupper() for character in password))
        self.assertTrue(any(character.isdigit() for character in password))
        self.assertTrue(any(character in "!@#$%^&*" for character in password))

    def test_generate_password_rejects_short_length(self) -> None:
        with self.assertRaises(ValueError):
            self.manager.generate_password(MIN_GENERATED_PASSWORD_LENGTH - 1)


if __name__ == "__main__":
    unittest.main()
