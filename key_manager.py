"""
Key Management System
Handles key storage, retrieval, and rotation
ICS344 - Group P26
"""

import json
import os
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64
from typing import Dict, Optional, Tuple
import time
from datetime import datetime

class KeyManager:
    """Manages cryptographic keys with encrypted storage"""
    
    def __init__(self, storage_dir: str = "keys", master_password: str = None):
        self.storage_dir = storage_dir
        os.makedirs(storage_dir, exist_ok=True)
        
        # Derive encryption key from master password
        if master_password:
            self.storage_key = self._derive_key(master_password)
        else:
            # For demo purposes - in production, always require password
            self.storage_key = Fernet.generate_key()
        
        self.fernet = Fernet(self.storage_key)
        
        # Load or initialize key store
        self.key_store_path = os.path.join(storage_dir, "keystore.enc")
        self.keys = self._load_keystore()
    
    def _derive_key(self, password: str) -> bytes:
        """Derive encryption key from password"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'stable_salt_for_demo',  # In production, use random salt
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    
    def _load_keystore(self) -> Dict:
        """Load encrypted keystore from disk"""
        if os.path.exists(self.key_store_path):
            try:
                with open(self.key_store_path, 'rb') as f:
                    encrypted_data = f.read()
                decrypted = self.fernet.decrypt(encrypted_data)
                return json.loads(decrypted)
            except Exception as e:
                print(f"Error loading keystore: {e}")
                return {}
        return {}
    
    def _save_keystore(self):
        """Save encrypted keystore to disk"""
        data = json.dumps(self.keys).encode()
        encrypted = self.fernet.encrypt(data)
        with open(self.key_store_path, 'wb') as f:
            f.write(encrypted)
    
    def store_key_pair(self, identifier: str, private_key: bytes, public_key: bytes):
        """Store RSA key pair"""
        self.keys[identifier] = {
            'type': 'rsa_keypair',
            'private_key': base64.b64encode(private_key).decode('utf-8'),
            'public_key': base64.b64encode(public_key).decode('utf-8'),
            'created_at': time.time()
        }
        self._save_keystore()
    
    def store_aes_key(self, identifier: str, aes_key: bytes):
        """Store AES key"""
        self.keys[identifier] = {
            'type': 'aes',
            'key': base64.b64encode(aes_key).decode('utf-8'),
            'created_at': time.time()
        }
        self._save_keystore()
    
    def get_rsa_keypair(self, identifier: str) -> Optional[Tuple[bytes, bytes]]:
        """Retrieve RSA key pair"""
        if identifier in self.keys and self.keys[identifier]['type'] == 'rsa_keypair':
            entry = self.keys[identifier]
            private = base64.b64decode(entry['private_key'])
            public = base64.b64decode(entry['public_key'])
            return private, public
        return None
    
    def get_aes_key(self, identifier: str) -> Optional[bytes]:
        """Retrieve AES key"""
        if identifier in self.keys and self.keys[identifier]['type'] == 'aes':
            return base64.b64decode(self.keys[identifier]['key'])
        return None
    
    def list_keys(self) -> Dict[str, str]:
        """List all stored keys"""
        return {
            k: f"{v['type']} (created: {datetime.fromtimestamp(v['created_at'])})"
            for k, v in self.keys.items()
        }
    
    def delete_key(self, identifier: str) -> bool:
        """Delete a key from storage"""
        if identifier in self.keys:
            del self.keys[identifier]
            self._save_keystore()
            return True
        return False
    
    def export_public_key(self, identifier: str) -> Optional[str]:
        """Export public key for sharing"""
        keypair = self.get_rsa_keypair(identifier)
        if keypair:
            _, public_key = keypair
            return base64.b64encode(public_key).decode('utf-8')
        return None
    
    def import_public_key(self, identifier: str, public_key_b64: str):
        """Import someone else's public key"""
        public_key = base64.b64decode(public_key_b64)
        self.keys[f"contact_{identifier}"] = {
            'type': 'public_key',
            'public_key': public_key_b64,
            'created_at': time.time()
        }
        self._save_keystore()
    
    def get_public_key(self, identifier: str) -> Optional[bytes]:
        """Get a stored public key"""
        if identifier in self.keys:
            if self.keys[identifier]['type'] == 'public_key':
                return base64.b64decode(self.keys[identifier]['public_key'])
            elif self.keys[identifier]['type'] == 'rsa_keypair':
                return base64.b64decode(self.keys[identifier]['public_key'])
        return None