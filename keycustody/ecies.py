"""ECIES: ephemeral X25519 -> HKDF-SHA256 -> AES-256-GCM. Blob = eph_pub(32) | nonce(12) | ct."""
import os
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

def _key(shared, eph_pub, rcpt_pub):
    return HKDF(hashes.SHA256(), 32, None, b"keycustody-v1" + eph_pub + rcpt_pub).derive(shared)

def seal(rcpt_pub: bytes, plaintext: bytes, aad: bytes) -> bytes:
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes_raw()
    key = _key(eph.exchange(X25519PublicKey.from_public_bytes(rcpt_pub)), eph_pub, rcpt_pub)
    nonce = os.urandom(12)
    return eph_pub + nonce + AESGCM(key).encrypt(nonce, plaintext, aad)

def open_(priv: X25519PrivateKey, blob: bytes, aad: bytes) -> bytes:
    eph_pub, nonce, ct = blob[:32], blob[32:44], blob[44:]
    rcpt_pub = priv.public_key().public_bytes_raw()
    key = _key(priv.exchange(X25519PublicKey.from_public_bytes(eph_pub)), eph_pub, rcpt_pub)
    return AESGCM(key).decrypt(nonce, ct, aad)
