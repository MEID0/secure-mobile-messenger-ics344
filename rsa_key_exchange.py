"""
RSA Key Exchange Module
Implements RSA-OAEP encryption for secure AES key distribution
ICS344 - Group P26
"""

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import base64
from typing import Tuple

def encrypt_aes_key(receiver_public_key_pem: bytes, aes_key: bytes) -> bytes:
    """
    Encrypt AES key using receiver's RSA public key with OAEP padding
    
    Args:
        receiver_public_key_pem: Receiver's public key in PEM format
        aes_key: 256-bit AES key to encrypt
    
    Returns:
        Encrypted AES key
    """
    # Load the public key
    public_key = serialization.load_pem_public_key(
        receiver_public_key_pem, 
        backend=default_backend()
    )
    
    # Encrypt AES key using RSA-OAEP
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return encrypted_key

def decrypt_aes_key(private_key_pem: bytes, encrypted_aes_key: bytes) -> bytes:
    """
    Decrypt AES key using private RSA key
    
    Args:
        private_key_pem: Private key in PEM format
        encrypted_aes_key: RSA-encrypted AES key
    
    Returns:
        Decrypted 256-bit AES key
    """
    # Load the private key
    private_key = serialization.load_pem_private_key(
        private_key_pem, 
        password=None,
        backend=default_backend()
    )
    
    # Decrypt AES key
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    return aes_key

def create_key_exchange_packet(
    sender_private_key: bytes,
    receiver_public_key: bytes, 
    aes_key: bytes
) -> dict:
    """
    Create a key exchange packet with encrypted AES key
    
    Args:
        sender_private_key: Sender's private key for signing (PEM format)
        receiver_public_key: Receiver's public key for encryption (PEM format)
        aes_key: AES key to exchange
    
    Returns:
        JSON-serializable packet with encrypted key and signature
    """
    from rsa_sign import sign_message as sign
    from rsa_sign import load_private_key_pem
    import json
    
    # Encrypt the AES key
    encrypted_aes = encrypt_aes_key(receiver_public_key, aes_key)
    
    # Load private key from PEM and sign the encrypted key
    private_key_obj = load_private_key_pem(sender_private_key)
    signature = sign(private_key_obj, encrypted_aes)
    
    # Export sender's public key (not private key!)
    from rsa_sign import export_public_key_pem
    sender_public_key_pem = export_public_key_pem(private_key_obj.public_key())
    
    # Create the packet
    packet = {
        "type": "key_exchange",
        "encrypted_aes_key": base64.b64encode(encrypted_aes).decode('utf-8'),
        "signature": base64.b64encode(signature).decode('utf-8'),
        "sender_public_key": base64.b64encode(sender_public_key_pem).decode('utf-8')
    }
    
    return packet

def process_key_exchange_packet(
    packet: dict,
    receiver_private_key: bytes,
    sender_public_key: bytes
) -> bytes:
    """
    Process received key exchange packet and extract AES key
    
    Args:
        packet: Key exchange packet
        receiver_private_key: Receiver's private key for decryption
        sender_public_key: Sender's public key for verification
    
    Returns:
        Decrypted AES key
    
    Raises:
        ValueError: If signature verification fails
    """
    from rsa_sign import verify_signature, load_public_key_pem
    
    # Decode the packet components
    encrypted_aes = base64.b64decode(packet["encrypted_aes_key"])
    signature = base64.b64decode(packet["signature"])
    
    # Load public key from PEM if needed
    if isinstance(sender_public_key, bytes):
        sender_pub_obj = load_public_key_pem(sender_public_key)
    else:
        sender_pub_obj = sender_public_key
    
    # Verify the signature
    if not verify_signature(sender_pub_obj, encrypted_aes, signature):
        raise ValueError("Key exchange signature verification failed!")
    
    # Decrypt the AES key
    aes_key = decrypt_aes_key(receiver_private_key, encrypted_aes)
    
    return aes_key