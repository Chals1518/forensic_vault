# encryption.py
# One place for all encryption logic — import this everywhere else

import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EncryptionService:
    """
    AES-256-GCM encryption service.
    One instance shared across the whole app.
    """

    def __init__(self, key: bytes):
        # Key must be exactly 32 bytes (256 bits)
        if len(key) != 32:
            raise ValueError("Key must be exactly 32 bytes")
        self.aesgcm = AESGCM(key)

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a string and return a base64 string safe to store in a database.
        Format stored: base64(nonce + ciphertext)
        """
        nonce = os.urandom(12)                          # fresh random nonce every time
        ciphertext = self.aesgcm.encrypt(
            nonce,
            plaintext.encode(),
            None
        )
        # combine nonce + ciphertext so we can split them on decryption
        combined = nonce + ciphertext
        return base64.b64encode(combined).decode()      # safe to store in any DB column

    def decrypt(self, stored: str) -> str:
        """
        Decrypt a base64 string that was produced by encrypt().
        """
        combined = base64.b64decode(stored.encode())
        nonce      = combined[:12]                      # first 12 bytes are the nonce
        ciphertext = combined[12:]                      # rest is the ciphertext
        plaintext  = self.aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode()


def load_key_from_env() -> bytes:
    """
    Load the AES key from an environment variable.
    NEVER hardcode keys in source code.
    """
    key_b64 = os.environ.get("ENCRYPTION_KEY")
    if not key_b64:
        raise RuntimeError("ENCRYPTION_KEY environment variable not set")
    key = base64.b64decode(key_b64)
    if len(key) != 32:
        raise ValueError("ENCRYPTION_KEY must be 32 bytes when decoded")
    return key


def generate_new_key() -> str:
    """
    Run this ONCE to generate a key. Save the output as your ENCRYPTION_KEY env var.
    Never run this again — you will lose access to all existing encrypted data.
    """
    key = os.urandom(32)
    return base64.b64encode(key).decode()


# Run this file directly to generate a key:
# python encryption.py
if __name__ == "__main__":
    print("Your new encryption key:")
    print(generate_new_key())
    print("\nSave this as your ENCRYPTION_KEY environment variable.")
    print("Keep it secret. Lose it = lose all your data.")