"""CLI for the educational password manager."""

from __future__ import annotations

import threading
from getpass import getpass
from typing import Callable, Dict

from .manager import (
    DEFAULT_PASSWORD_LENGTH,
    Credential,
    IncompleteSetupError,
    PasswordManager,
    PasswordManagerError,
)

CLIPBOARD_CLEAR_SECONDS = 20

try:
    import pyperclip
except ImportError:
    pyperclip = None  # type: ignore[assignment]

MenuHandler = Callable[[PasswordManager], None]


def run() -> int:
    """Run the interactive password manager CLI."""
    manager = PasswordManager()
    if not _authenticate(manager):
        return 0

    _main_loop(manager)
    return 0


def _authenticate(manager: PasswordManager) -> bool:
    while not manager.logged_in:
        status = manager.setup_status()

        if status == "missing":
            if not _create_master_password(manager):
                return False
            continue

        if status == "incomplete":
            print(
                "❌ Login files are incomplete. Restore both "
                "'master.hash' and 'salt.bin'."
            )
            return False

        password = getpass("Enter master password: ")
        try:
            if manager.login(password):
                print("✅ Login successful!")
                return True
        except IncompleteSetupError as error:
            print(f"❌ {error}")
            return False

        print("❌ Incorrect master password!")
        if not _confirm_retry():
            return False

    return True


def _create_master_password(manager: PasswordManager) -> bool:
    print("\n" + "=" * 40)
    print("CREATE MASTER PASSWORD")
    print("=" * 40)

    while True:
        password = getpass("Master password: ")
        confirmation = getpass("Confirm: ")

        try:
            manager.create_master_password(password, confirmation)
        except ValueError as error:
            print(f"❌ {error}")
            if not _confirm_retry():
                return False
            continue
        except PasswordManagerError as error:
            print(f"❌ {error}")
            return False

        print("✅ Master password created!")
        return True


def _main_loop(manager: PasswordManager) -> None:
    actions: Dict[str, MenuHandler] = {
        "1": _handle_add_password,
        "2": _handle_get_password,
        "3": _handle_list_sites,
        "4": _handle_delete_password,
        "5": _handle_edit_password,
        "6": _handle_generate_password,
    }

    while True:
        _print_menu()
        choice = input("\nChoice: ").strip()

        if choice == "7":
            print("✅ Vault locked. Goodbye!")
            return

        action = actions.get(choice)
        if action is None:
            print("❌ Invalid choice")
            continue

        try:
            action(manager)
        except (PasswordManagerError, ValueError) as error:
            print(f"❌ {error}")


def _print_menu() -> None:
    print("\n" + "=" * 40)
    print("PASSWORD MANAGER")
    print("=" * 40)
    print("1. ➕ Add password")
    print("2. 👁️  Get password")
    print("3. 📋 List all sites")
    print("4. 🗑️  Delete password")
    print("5. 📝 Edit password")
    print("6. 🎲 Generate password")
    print("7. 🚪 Exit")


def _handle_add_password(manager: PasswordManager) -> None:
    site = input("Site name: ").strip()
    username = input("Username: ").strip()
    password = getpass("Password (leave blank to generate): ")

    if not password:
        password = manager.generate_password(DEFAULT_PASSWORD_LENGTH)
        print(f"Generated password: {password}")

    manager.add_password(site, username, password)
    print(f"✅ Password for '{site}' saved!")


def _handle_get_password(manager: PasswordManager) -> None:
    site = input("Site name: ").strip()
    credential = manager.get_password(site)

    if credential is None:
        print(f"❌ No entry found for '{site}'")
        return

    _print_credential(site, credential)
    _copy_password_to_clipboard(credential.password)


def _handle_list_sites(manager: PasswordManager) -> None:
    sites = manager.list_sites()
    if not sites:
        print("Vault is empty.")
        return

    print("\n📁 Stored sites:")
    for site in sites:
        print(f"   - {site}")


def _handle_delete_password(manager: PasswordManager) -> None:
    site = input("Site name: ").strip()
    confirm = input(f"Delete '{site}'? (y/n): ").strip().lower()
    if confirm != "y":
        return

    if manager.delete_password(site):
        print(f"✅ '{site}' deleted!")
        return

    print(f"❌ No entry found for '{site}'")


def _handle_edit_password(manager: PasswordManager) -> None:
    site = input("Site name: ").strip()
    credential = manager.get_password(site)

    if credential is None:
        print(f"❌ No entry found for '{site}'")
        return

    print(f"\n📝 Editing '{site}' (press Enter to keep current value)")
    new_username = input(f"Username [{credential.username}]: ").strip()
    new_password = getpass("Password [hidden]: ")

    username = None if not new_username else new_username
    password = None if not new_password else new_password
    manager.edit_password(site, username=username, password=password)
    print(f"✅ '{site}' updated successfully!")


def _handle_generate_password(manager: PasswordManager) -> None:
    raw_length = input(f"Length (default {DEFAULT_PASSWORD_LENGTH}): ").strip()
    length = DEFAULT_PASSWORD_LENGTH if not raw_length else int(raw_length)
    print(f"Generated: {manager.generate_password(length)}")


def _print_credential(site: str, credential: Credential) -> None:
    print(f"\n📄 {site}")
    print(f"   Username: {credential.username}")
    print(f"   Password: {credential.password}")


def _copy_password_to_clipboard(password: str) -> None:
    if pyperclip is None:
        print(
            "   ⚠️  Clipboard support unavailable. "
            "Install with: pip install pyperclip"
        )
        return

    try:
        pyperclip.copy(password)
    except pyperclip.PyperclipException as error:
        print(f"   ⚠️  Could not copy to clipboard: {error}")
        return

    print(
        "   📋 Password copied to clipboard! It will clear in "
        f"{CLIPBOARD_CLEAR_SECONDS} seconds if unchanged."
    )
    timer = threading.Timer(
        CLIPBOARD_CLEAR_SECONDS,
        _clear_clipboard_if_unchanged,
        args=(password,),
    )
    timer.daemon = True
    timer.start()


def _clear_clipboard_if_unchanged(expected_value: str) -> None:
    if pyperclip is None:
        return

    try:
        if pyperclip.paste() == expected_value:
            pyperclip.copy("")
    except pyperclip.PyperclipException:
        return


def _confirm_retry() -> bool:
    retry = input("Try again? (y/n): ").strip().lower()
    return retry == "y"
