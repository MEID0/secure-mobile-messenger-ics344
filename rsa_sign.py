from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization


def generate_rsa_keypair(key_size: int = 2048):
    """
    Generate an RSA private/public key pair.
    key_size: 2048 or 3072 bits.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def sign_message(private_key, message: bytes) -> bytes:
    """
    Sign a message using RSA-PSS with SHA-256.
    Returns the signature bytes.
    """
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


def verify_signature(public_key, message: bytes, signature: bytes) -> bool:
    """
    Verify an RSA-PSS signature.
    Returns True if valid, False otherwise.
    """
    from cryptography.exceptions import InvalidSignature

    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def export_private_key_pem(private_key) -> bytes:
    """Export private key in PEM format (no password for simplicity)."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return pem


def export_public_key_pem(public_key) -> bytes:
    """Export public key in PEM format."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return pem


def load_private_key_pem(pem: bytes):
    """Load a private key from PEM bytes (no password)."""
    private_key = serialization.load_pem_private_key(
        pem,
        password=None,
    )
    return private_key


def load_public_key_pem(pem: bytes):
    """Load a public key from PEM bytes."""
    public_key = serialization.load_pem_public_key(pem)
    return public_key


if __name__ == "__main__":
    # Quick self-test
    priv, pub = generate_rsa_keypair(2048)
    msg = b"Hello RSA signatures!"
    sig = sign_message(priv, msg)
    print("Signature length:", len(sig))
    print("Valid:", verify_signature(pub, msg, sig))
