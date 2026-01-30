import os
import json
import base64
import secrets
from getpass import getpass

# Cryptography library - simple and secure
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# For clipboard functionality
try:
    import pyperclip
    CLIPBOARD_AVAILABLE = True
except ImportError:
    pyperclip = None  # type: ignore
    CLIPBOARD_AVAILABLE = False
    print("⚠️  pyperclip not installed. Clipboard feature disabled.")
    print("   Install with: pip install pyperclip")


class PasswordManager:
    """
    A simple password manager for learning file handling and hashing.
    DO NOT use for highly sensitive data - this is an educational tool!
    """
    
    def __init__(self, vault_file="vault.enc"):
        self.vault_file = vault_file
        self.master_hash_file = "master.hash"
        self.salt_file = "salt.bin"
        self.logged_in = False
        self.key = None  # Encryption key derived from master password
    
    # =========================================================================
    # PASSWORD HASHING & KEY DERIVATION
    # =========================================================================
    
    def _derive_key(self, password, salt):
        """
        Derive a 32-byte encryption key from password using PBKDF2.
        Same password + same salt = same key (deterministic)
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # Fernet requires 32-byte key
            salt=salt,
            iterations=480000,  # OWASP recommended minimum (slows attacks)
        )
        # PBKDF2 makes it computationally expensive to brute-force
        return base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    def _hash_master_password(self, password, salt):
        """
        Hash master password for secure storage/verification.
        We store this hash to check if login password is correct.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )
        return kdf.derive(password.encode())
    
    # =========================================================================
    # FIRST-TIME SETUP
    # =========================================================================
    
    def create_master_password(self):
        """Create master password for first-time use."""
        print("\n" + "="*40)
        print("CREATE MASTER PASSWORD")
        print("="*40)
        
        password = getpass("Master password: ")
        confirm = getpass("Confirm: ")
        
        if password != confirm:
            print("❌ Passwords don't match!")
            return False
        
        # Generate random salt (prevents rainbow table attacks)
        salt = secrets.token_bytes(16)
        
        # Hash master password (store only the hash, never plaintext)
        master_hash = self._hash_master_password(password, salt)
        
        # Derive encryption key from password
        self.key = self._derive_key(password, salt)
        
        # Save salt and hash to separate files
        with open(self.salt_file, "wb") as f:
            f.write(salt)
        
        with open(self.master_hash_file, "wb") as f:
            f.write(master_hash)
        
        # Create empty, encrypted vault
        self._save_vault({})
        
        print("✅ Master password created!")
        self.logged_in = True
        return True
    
    # =========================================================================
    # LOGIN
    # =========================================================================
    
    def login(self):
        """Verify master password against stored hash."""
        if not os.path.exists(self.master_hash_file):
            print("No master password found. Creating new one...")
            return self.create_master_password()
        
        # Load salt
        with open(self.salt_file, "rb") as f:
            salt = f.read()
        
        password = getpass("Enter master password: ")
        
        # Verify by hashing entered password and comparing to stored hash
        stored_hash = open(self.master_hash_file, "rb").read()
        entered_hash = self._hash_master_password(password, salt)
        
        # Use secrets.compare_digest to prevent timing attacks
        if secrets.compare_digest(stored_hash, entered_hash):
            self.key = self._derive_key(password, salt)
            self.logged_in = True
            print("✅ Login successful!")
            return True
        else:
            print("❌ Incorrect master password!")
            return False
    
    # =========================================================================
    # FILE HANDLING - ENCRYPTED VAULT
    # =========================================================================
    
    def _save_vault(self, data):
        """Encrypt data and save to vault file."""
        if not self.logged_in or self.key is None:
            print("You must login first!")
            return
        
        # Convert dict → JSON string → bytes → encrypt → save
        f = Fernet(self.key)
        encrypted = f.encrypt(json.dumps(data).encode())
        
        with open(self.vault_file, "wb") as file:
            file.write(encrypted)
        print("(Vault saved and encrypted)")
    
    def _load_vault(self):
        """Load and decrypt vault data."""
        if not self.logged_in or self.key is None:
            print("You must login first!")
            return {}
        
        if not os.path.exists(self.vault_file):
            return {}
        
        with open(self.vault_file, "rb") as file:
            encrypted = file.read()
        
        try:
            f = Fernet(self.key)
            decrypted = f.decrypt(encrypted)  # Will fail if key is wrong
            return json.loads(decrypted.decode())
        except Exception as e:
            print(f"❌ Error loading vault: {e}")
            return {}
    
    # =========================================================================
    # PASSWORD MANAGEMENT
    # =========================================================================
    
    def add_password(self, site, username, password):
        """Add new credentials to vault."""
        if not self.logged_in:
            return
        
        vault = self._load_vault()
        
        vault[site] = {
            "username": username,
            "password": password  # Gets encrypted in vault file!
        }
        
        self._save_vault(vault)
        print(f"✅ Password for '{site}' saved!")
    
    def get_password(self, site):
        """Retrieve credentials for a site."""
        if not self.logged_in:
            return None
        
        vault = self._load_vault()
        
        if site in vault:
            entry = vault[site]
            print(f"\n📄 {site}")
            print(f"   Username: {entry['username']}")
            print(f"   Password: {entry['password']}")
            # NEW: Copy password to clipboard
            if CLIPBOARD_AVAILABLE and pyperclip is not None:
                try:
                    pyperclip.copy(entry['password'])
                    print("   📋 Password copied to clipboard!")
                except Exception as e:
                    print(f"   ⚠️  Could not copy to clipboard: {e}")
            return entry
        else:
            print(f"❌ No entry found for '{site}'")
            return None
    
    # NEW: Edit/Update password feature
    def edit_password(self, site):
        """Edit existing credentials."""
        if not self.logged_in:
            return
        
        vault = self._load_vault()
        
        if site not in vault:
            print(f"❌ No entry found for '{site}'")
            return
        
        print(f"\n📝 Editing '{site}' (press Enter to keep current value)")
        current = vault[site]
        
        new_username = input(f"Username [{current['username']}]: ").strip()
        new_password = getpass(f"Password [{'*' * 8}]: ")
        
        if new_username:
            current['username'] = new_username
        if new_password:
            current['password'] = new_password
        
        vault[site] = current
        self._save_vault(vault)
        print(f"✅ '{site}' updated successfully!")
    
    def list_sites(self):
        """Show all stored sites."""
        if not self.logged_in:
            return
        
        vault = self._load_vault()
        
        if not vault:
            print("Vault is empty.")
            return
        
        print("\n📁 Stored sites:")
        for site in sorted(vault.keys()):
            print(f"   - {site}")
    
    def delete_password(self, site):
        """Remove a site from vault."""
        if not self.logged_in:
            return
        
        vault = self._load_vault()
        
        if site in vault:
            del vault[site]
            self._save_vault(vault)
            print(f"✅ '{site}' deleted!")
        else:
            print(f"❌ No entry found for '{site}'")
    
    def generate_password(self, length=16):
        """Generate a strong random password."""
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        return password

# =========================================================================
# MAIN MENU
# =========================================================================

def main():
    pm = PasswordManager()
    
    # Login loop
    while not pm.logged_in:
        if not pm.login():
            retry = input("Try again? (y/n): ").strip()
            if retry.lower() != 'y':
                return
    
    # Main menu loop
    while True:
        print("\n" + "="*40)
        print("PASSWORD MANAGER")
        print("="*40)
        print("1. ➕ Add password")
        print("2. 👁️  Get password")
        print("3. 📋 List all sites")
        print("4. 🗑️  Delete password")
        print("5. 📝 Edit password")  # NEW OPTION
        print("6. 🎲 Generate password")
        print("7. 🚪 Exit")
        
        choice = input("\nChoice: ").strip()
        
        if choice == "1":
            site = input("Site name: ").strip()
            username = input("Username: ").strip()
            password = getpass("Password (leave blank to generate): ")
            if not password:
                password = pm.generate_password()
                print(f"Generated password: {password}")
            pm.add_password(site, username, password)
        
        elif choice == "2":
            site = input("Site name: ").strip()
            pm.get_password(site)
        
        elif choice == "3":
            pm.list_sites()
        
        elif choice == "4":
            site = input("Site name: ").strip()
            confirm = input(f"Delete '{site}'? (y/n): ").strip()
            if confirm.lower() == 'y':
                pm.delete_password(site)
        
        elif choice == "5":  # NEW: Edit password
            site = input("Site name: ").strip()
            pm.edit_password(site)
        
        elif choice == "6":
            length = input("Length (default 16): ").strip()
            length = int(length) if length else 16
            print(f"Generated: {pm.generate_password(length)}")
        
        elif choice == "7":
            print("✅ Vault locked. Goodbye!")
            break
        
        else:
            print("❌ Invalid choice")

if __name__ == "__main__":
    main()