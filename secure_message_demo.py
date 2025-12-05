"""
Demo of combining AES-CBC (PKCS#7) + RSA digital signatures.

- Sender:
    * AES encrypts plaintext  -> iv, ciphertext
    * Signs (iv || ciphertext) with RSA private key
    * Sends JSON packet with base64-encoded fields

- Receiver:
    * Parses JSON, base64-decodes fields
    * Verifies signature using sender's public key
    * If valid -> AES decrypts ciphertext and recovers plaintext
"""

import base64
import json

from aes_cbc import generate_aes_key, encrypt_aes_cbc, decrypt_aes_cbc
from rsa_sign import (
    generate_rsa_keypair,
    sign_message,
    verify_signature,
    export_public_key_pem,
    load_public_key_pem,
)


def b64encode(data: bytes) -> str:
    """Bytes -> base64 string (for JSON)."""
    return base64.b64encode(data).decode("ascii")


def b64decode(data_str: str) -> bytes:
    """Base64 string -> bytes."""
    return base64.b64decode(data_str.encode("ascii"))


def sender_create_packet(aes_key: bytes, sender_priv_key, sender_pub_key, plaintext: str) -> str:
    """
    Encrypt and sign a plaintext message.

    Returns: JSON string representing the packet.
    """
    # 1) AES-CBC encryption
    plaintext_bytes = plaintext.encode("utf-8")
    iv, ciphertext = encrypt_aes_cbc(aes_key, plaintext_bytes)

    # 2) Sign (iv || ciphertext) with RSA private key
    to_sign = iv + ciphertext
    signature = sign_message(sender_priv_key, to_sign)

    # 3) Export sender public key (so receiver can verify)
    sender_pub_pem = export_public_key_pem(sender_pub_key)

    # 4) Build JSON-safe packet (everything base64)
    packet = {
        "iv": b64encode(iv),
        "ciphertext": b64encode(ciphertext),
        "signature": b64encode(signature),
        "sender_public_key": b64encode(sender_pub_pem),
        # Later we can add: "nonce", "timestamp", etc. for replay protection
    }

    json_packet = json.dumps(packet)
    return json_packet


def receiver_process_packet(aes_key: bytes, json_packet: str) -> str:
    """
    Receiver side:
    - Parse JSON
    - Verify signature
    - Decrypt if valid
    """
    packet = json.loads(json_packet)

    iv = b64decode(packet["iv"])
    ciphertext = b64decode(packet["ciphertext"])
    signature = b64decode(packet["signature"])
    sender_pub_pem = b64decode(packet["sender_public_key"])

    # Rebuild the data that was signed
    to_verify = iv + ciphertext

    # Load public key and verify signature
    sender_pub_key = load_public_key_pem(sender_pub_pem)
    is_valid = verify_signature(sender_pub_key, to_verify, signature)

    if not is_valid:
        raise ValueError("Signature verification FAILED! Message may be tampered.")

    # Signature is valid: decrypt ciphertext
    plaintext_bytes = decrypt_aes_cbc(aes_key, iv, ciphertext)
    plaintext = plaintext_bytes.decode("utf-8")
    return plaintext


if __name__ == "__main__":
    # ====== Setup (shared secret + keys) ======
    print("Generating AES key and RSA keypair...")
    aes_key = generate_aes_key()
    sender_priv, sender_pub = generate_rsa_keypair(2048)

    # ====== Sender side ======
    original_message = "Hello, this is a secure message for ICS344 project!"
    print("\n[Sender] Original message:", original_message)

    packet_json = sender_create_packet(aes_key, sender_priv, sender_pub, original_message)
    print("\n[Sender] JSON packet to send:")
    print(packet_json)

    # ====== Receiver side ======
    print("\n[Receiver] Processing received packet...")
    recovered_message = receiver_process_packet(aes_key, packet_json)
    print("[Receiver] Recovered plaintext:", recovered_message)

    print("\nSuccess:", recovered_message == original_message)
