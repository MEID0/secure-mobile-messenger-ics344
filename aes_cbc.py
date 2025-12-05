import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

AES_KEY_SIZE = 32      # 32 bytes = 256-bit key (AES-256)
AES_BLOCK_SIZE = 128   # in bits, required by PKCS7 padder
IV_SIZE = 16           # 16 bytes = AES block size


def generate_aes_key() -> bytes:
    """Generate a random 256-bit AES key."""
    return os.urandom(AES_KEY_SIZE)


def encrypt_aes_cbc(key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext using AES-CBC with PKCS#7 padding.
    Returns (iv, ciphertext).
    """
    iv = os.urandom(IV_SIZE)

    # PKCS#7 padding
    padder = padding.PKCS7(AES_BLOCK_SIZE).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    return iv, ciphertext


def encrypt_aes_cbc_with_iv(key: bytes, plaintext: bytes, iv: bytes) -> bytes:
    """
    Encrypt plaintext using AES-CBC with PKCS#7 padding,
    but using a GIVEN IV (no randomness).
    This is ONLY for the IV reuse attack demo.
    """
    # PKCS#7 padding
    padder = padding.PKCS7(AES_BLOCK_SIZE).padder()
    padded = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()
    return ciphertext



def decrypt_aes_cbc(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """
    Decrypt AES-CBC with PKCS#7 unpadding.
    """
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(AES_BLOCK_SIZE).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext


if __name__ == "__main__":
    # Quick self-test
    key = generate_aes_key()
    msg = b"Hello ICS344!"
    iv, ct = encrypt_aes_cbc(key, msg)
    pt = decrypt_aes_cbc(key, iv, ct)
    print("OK:", pt == msg, pt)
