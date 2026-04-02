🔐 EDUCATIONAL PASSWORD MANAGER (PYTHON)

────────────────────────────────────────
A simple, security-focused password manager built in Python to explore
real-world cryptography and secure storage concepts.

This project is intentionally minimal and transparent, designed to help
developers understand how password managers work internally rather than
hiding logic behind abstractions.

⚠️ Educational use only — NOT for production.
────────────────────────────────────────

🎯 PURPOSE & LEARNING GOALS

This project was built to:

🧠 Learn secure password handling
🔑 Understand hashing vs encryption
🧪 Practice key derivation and salting
📁 Work with encrypted files on disk
🛡️ Apply basic defensive security practices

It prioritizes clarity and correctness over convenience.

────────────────────────────────────────

✨ FEATURES

🔑 Master password protection
🔒 Encrypted credential vault (data at rest)
➕ Add new credentials
👁️ Retrieve stored credentials
📋 List stored sites (no secrets exposed)
📝 Edit existing entries
🗑️ Delete credentials securely
🎲 Generate strong random passwords
📋 Copy passwords to clipboard with auto-clear (optional)
🚫 Zero-knowledge design (master password never stored)

────────────────────────────────────────

🛡️ SECURITY ARCHITECTURE

Master Password
│
▼
🔐 PBKDF2 (480,000 iterations + salt)
│
├──▶ Stored hash (verification only)
│
└──▶ Derived encryption key
│
▼
🔒 Encrypted Vault File

✔ No plaintext passwords on disk
✔ Salted & slow key derivation
✔ Authenticated encryption
✔ Timing-safe comparisons
✔ Tamper detection on vault file

────────────────────────────────────────

🔐 CRYPTOGRAPHY DETAILS

🔁 Key derivation: PBKDF2
🔢 Iterations: 480,000 (OWASP-aligned)
🧂 Salt: 16 bytes (random)
🔐 Encryption: Fernet (AES-128-CBC + HMAC)
🎲 Randomness: os.urandom / secrets
⏱️ Timing-safe checks: secrets.compare_digest

────────────────────────────────────────

📦 INSTALLATION

Requirements:
🐍 Python 3.8+

Install dependencies:

pip install cryptography

Optional clipboard support:

pip install pyperclip

Optional development checks:

python -m unittest discover -s tests -v

Runtime files generated locally:

master.hash
salt.bin
vault.enc

These files are ignored by git and should stay private on your machine.

────────────────────────────────────────

🚀 RUNNING THE APPLICATION

git clone https://github.com/eenock/password-manager.git

cd password-manager
python -m password_manager

On first run, you will be prompted to create a master password.
This password encrypts all stored credentials.

────────────────────────────────────────

🧭 USAGE OVERVIEW

Menu options:

1️⃣ Add password
2️⃣ Get password
3️⃣ List all sites
4️⃣ Delete password
5️⃣ Edit password
6️⃣ Generate password
7️⃣ Exit

Passwords are decrypted only in memory and never written in plaintext.

────────────────────────────────────────

📁 FILE STRUCTURE

password_manager/ → Python package
password_manager/cli.py → Interactive terminal interface
password_manager/manager.py → Vault, crypto, and storage logic
password_manager/__main__.py → `python -m password_manager` entrypoint
tests/test_manager.py → Unit tests for core behavior
pyproject.toml → Project metadata and dependencies
master.hash → Derived master password hash
salt.bin → Random salt for key derivation
vault.enc → Encrypted credential vault

⚠️ IMPORTANT
If salt.bin or master.hash is lost or altered, the vault becomes permanently
unrecoverable.

────────────────────────────────────────

🚨 DATA LOSS WARNING

There is NO password recovery.

If the master password is forgotten or cryptographic files are lost,
ALL stored data is permanently inaccessible — by design.

────────────────────────────────────────

🔍 SECURITY VERIFICATION

You can verify security properties manually:

✔ vault.enc contains encrypted binary data
✔ master.hash and salt.bin are not readable text
✔ Modifying vault.enc causes decryption failure

────────────────────────────────────────

🎓 WHAT YOU’LL LEARN

🧩 Why fast hashes (MD5, SHA-1) are insecure
🐢 Why slow hashing resists brute-force attacks
🧂 Why salts defeat rainbow tables
🔐 How encryption protects data at rest
🧠 Difference between hashing and encryption
📁 Secure binary file handling in Python

────────────────────────────────────────

⚠️ DISCLAIMER

🚫 FOR EDUCATIONAL PURPOSES ONLY 🚫

Do NOT use this project for:
🏦 Banking credentials
💼 Work or enterprise secrets
📧 Personal email accounts
🚀 Production environments

For real-world usage, consider:
🔹 KeePassXC
🔹 Bitwarden

────────────────────────────────────────

📜 LICENSE

MIT License
Copyright (c) 2026 Eringata Enock Emuye

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
────────────────────────────────────────

⭐ If this project helped you learn security fundamentals,
consider starring the repository!

────────────────────────────────────────

END OF FILE
