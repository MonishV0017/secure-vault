import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def generate_key(passphrase: str, salt: bytes, iterations: int = 100000) -> bytes: # Derives a secure key from a passphrase
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    key = kdf.derive(passphrase.encode())
    return base64.urlsafe_b64encode(key)

def encrypt_file(file_path: str, passphrase: str) -> tuple[str, bytes]: # Encrypts a file and returns its new path and salt
    salt = os.urandom(16)
    key = generate_key(passphrase, salt)
    f = Fernet(key)

    with open(file_path, "rb") as infile:
        data = infile.read()

    encrypted_data = f.encrypt(data)
    encrypted_path = file_path + ".enc"
    with open(encrypted_path, "wb") as outfile:
        outfile.write(encrypted_data)

    return encrypted_path, salt

def decrypt_file_in_memory(encrypted_path: str, salt: bytes, passphrase: str) -> bytes: # Decrypts a file's content into memory
    key = generate_key(passphrase, salt)
    f = Fernet(key)

    with open(encrypted_path, "rb") as infile:
        encrypted_data = infile.read()

    decrypted_data = f.decrypt(encrypted_data)
    return decrypted_data