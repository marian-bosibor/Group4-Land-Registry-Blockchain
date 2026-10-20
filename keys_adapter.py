"""
keys_adapter.py - bridge between key_generation.py and certificates.py.

"""
import contextlib
import hashlib
import io

from key_generation import generate_key_pair


def new_keypair(role: str) -> dict:
    with contextlib.redirect_stdout(io.StringIO()):
        priv, pub = generate_key_pair(role)
    pub_hex = pub.format(compressed=True).hex()
    return {
        "role": role,
        "private_key": priv.to_hex(),
        "public_key": pub_hex,
        # Placeholder address (first 20 bytes of SHA-256 of the public key); not Member 1's.
        "address": hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()[:40],
    }