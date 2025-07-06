"""
zkAEDI Authenticated Encryption Module
======================================
Provides authenticated encryption with zero-knowledge properties
"""

import os
import hmac
import hashlib
import json
from typing import Dict, Tuple, Optional, Any, Union
from dataclasses import dataclass
from datetime import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64


@dataclass
class EncryptedData:
    """Encrypted data container with authentication"""
    ciphertext: str
    nonce: str
    tag: str
    algorithm: str = "AES-256-GCM"
    timestamp: datetime = None
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()
        if self.metadata is None:
            self.metadata = {}


class AuthenticatedEncryption:
    """Authenticated encryption with additional data (AEAD)"""

    def __init__(self, master_key: Optional[bytes] = None):
        if master_key is None:
            master_key = os.urandom(32)
        self.master_key = master_key
        self.backend = default_backend()

    def derive_key(self, context: str, salt: Optional[bytes] = None) -> bytes:
        """Derive a key for specific context using PBKDF2"""
        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )

        return kdf.derive(self.master_key + context.encode())

    def encrypt(self,
                plaintext: Union[str, bytes],
                associated_data: Optional[bytes] = None) -> EncryptedData:
        """Encrypt data with AES-256-GCM"""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        # Generate nonce
        nonce = os.urandom(12)  # 96 bits for GCM

        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.master_key),
            modes.GCM(nonce),
            backend=self.backend
        )

        encryptor = cipher.encryptor()

        # Add associated data if provided
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)

        # Encrypt
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return EncryptedData(
            ciphertext=base64.b64encode(ciphertext).decode('utf-8'),
            nonce=base64.b64encode(nonce).decode('utf-8'),
            tag=base64.b64encode(encryptor.tag).decode('utf-8'),
            algorithm="AES-256-GCM"
        )

    def decrypt(self,
                encrypted_data: EncryptedData,
                associated_data: Optional[bytes] = None) -> bytes:
        """Decrypt data with authentication verification"""
        # Decode from base64
        ciphertext = base64.b64decode(encrypted_data.ciphertext)
        nonce = base64.b64decode(encrypted_data.nonce)
        tag = base64.b64decode(encrypted_data.tag)

        # Create cipher
        cipher = Cipher(
            algorithms.AES(self.master_key),
            modes.GCM(nonce, tag),
            backend=self.backend
        )

        decryptor = cipher.decryptor()

        # Add associated data if provided
        if associated_data:
            decryptor.authenticate_additional_data(associated_data)

        # Decrypt and verify
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        return plaintext

    def encrypt_json(self, data: Dict[str, Any]) -> EncryptedData:
        """Encrypt JSON data"""
        json_bytes = json.dumps(data, sort_keys=True).encode('utf-8')
        return self.encrypt(json_bytes)

    def decrypt_json(self, encrypted_data: EncryptedData) -> Dict[str, Any]:
        """Decrypt JSON data"""
        plaintext = self.decrypt(encrypted_data)
        return json.loads(plaintext.decode('utf-8'))


class ZKAuthenticatedEncryption(AuthenticatedEncryption):
    """Authenticated encryption with zero-knowledge properties"""

    def __init__(self, master_key: Optional[bytes] = None):
        super().__init__(master_key)
        self.commitments: Dict[str, str] = {}

    def encrypt_with_proof(self,
                           plaintext: Union[str, bytes],
                           proof_data: Dict[str, Any]) -> Tuple[
            EncryptedData, str]:
        """Encrypt data and bind zero-knowledge proof"""
        # Create commitment to plaintext
        if isinstance(plaintext, str):
            plaintext_bytes = plaintext.encode('utf-8')
        else:
            plaintext_bytes = plaintext
        commitment = self._commit_to_data(plaintext_bytes)

        # Use commitment as associated data
        associated_data = commitment.encode('utf-8')

        # Encrypt with commitment binding
        encrypted = self.encrypt(plaintext_bytes, associated_data)

        # Store commitment
        proof_id = base64.b64encode(os.urandom(16)).decode('utf-8')
        self.commitments[proof_id] = commitment

        # Add proof data to metadata
        encrypted.metadata['proof_id'] = proof_id
        encrypted.metadata['proof_data'] = proof_data

        return encrypted, commitment

    def decrypt_with_verification(
            self,
            encrypted_data: EncryptedData,
            expected_commitment: str) -> Tuple[bytes, bool]:
        """Decrypt and verify commitment"""
        # Get commitment from metadata
        proof_id = encrypted_data.metadata.get('proof_id')
        if not proof_id or proof_id not in self.commitments:
            return b"", False

        stored_commitment = self.commitments[proof_id]

        # Verify commitment matches
        if stored_commitment != expected_commitment:
            return b"", False

        # Decrypt with commitment as associated data
        associated_data = expected_commitment.encode('utf-8')

        try:
            plaintext = self.decrypt(encrypted_data, associated_data)

            # Verify decrypted data matches commitment
            computed_commitment = self._commit_to_data(plaintext)
            if computed_commitment != expected_commitment:
                return b"", False

            return plaintext, True

        except Exception:
            return b"", False

    def _commit_to_data(self, data: bytes) -> str:
        """Create commitment to data using hash"""
        return hashlib.sha256(data).hexdigest()

    def create_data_proof(self, data: bytes, statement: str) -> Dict[str, Any]:
        """Create a proof about encrypted data without revealing it"""
        # Hash-based commitment
        commitment = self._commit_to_data(data)

        # Create proof structure
        proof = {
            "commitment": commitment,
            "statement": statement,
            "timestamp": datetime.utcnow().isoformat(),
            "proof_type": "data_knowledge",
            "hash_algorithm": "SHA256"
        }

        # Sign the proof
        proof_bytes = json.dumps(proof, sort_keys=True).encode('utf-8')
        signature = hmac.new(
            self.master_key, proof_bytes, hashlib.sha256).hexdigest()
        proof["signature"] = signature

        return proof

    def verify_data_proof(self, proof: Dict[str, Any]) -> bool:
        """Verify a data proof"""
        try:
            # Extract signature
            signature = proof.pop("signature")

            # Recompute signature
            proof_bytes = json.dumps(proof, sort_keys=True).encode('utf-8')
            expected_signature = hmac.new(
                self.master_key, proof_bytes, hashlib.sha256).hexdigest()

            # Add signature back
            proof["signature"] = signature

            return hmac.compare_digest(signature, expected_signature)

        except Exception:
            return False


def create_authenticated_encryption(
        key: Optional[bytes] = None) -> AuthenticatedEncryption:
    """Factory function to create authenticated encryption instance"""
    return AuthenticatedEncryption(key)


def create_zk_authenticated_encryption(
        key: Optional[bytes] = None) -> ZKAuthenticatedEncryption:
    """Factory function to create ZK authenticated encryption instance"""
    return ZKAuthenticatedEncryption(key)
