
"""
CNS 4206 - Milestone 3
Member 3: P2PKH Scripts and Stack Interpreter

Implements a simplified Pay-to-Public-Key-Hash (P2PKH) script
using a stack-based interpreter and ECDSA signature verification.
"""

import hashlib
from coincurve import PublicKey

# Supported script operations
OP_DUP = "OP_DUP"
OP_HASH160 = "OP_HASH160"
OP_EQUALVERIFY = "OP_EQUALVERIFY"
OP_CHECKSIG = "OP_CHECKSIG"


def hash160(data: bytes) -> bytes:
    """Apply SHA-256 followed by RIPEMD-160."""
    sha256_hash = hashlib.sha256(data).digest()
    return hashlib.new("ripemd160", sha256_hash).digest()


def create_p2pkh_locking_script(public_key_hash: bytes) -> list:
    """Create the locking script for the owner of a public-key hash."""
    if not isinstance(public_key_hash, bytes):
        raise TypeError("public_key_hash must be bytes")

    if len(public_key_hash) != 20:
        raise ValueError("Public key hash must be exactly 20 bytes")

    return [
        OP_DUP,
        OP_HASH160,
        public_key_hash,
        OP_EQUALVERIFY,
        OP_CHECKSIG,
    ]


def create_unlocking_script(signature: bytes, public_key: bytes) -> list:
    """Create an unlocking script containing a signature and public key."""
    if not isinstance(signature, bytes):
        raise TypeError("signature must be bytes")

    if not isinstance(public_key, bytes):
        raise TypeError("public_key must be bytes")

    return [signature, public_key]


def execute_script(
    unlocking_script: list,
    locking_script: list,
    message: bytes,
) -> bool:
    """
    Execute the unlocking and locking scripts.

    Returns True only when the public-key hash matches and the
    signature correctly verifies the supplied message.
    """
    if not isinstance(message, bytes):
        return False

    if not isinstance(unlocking_script, list):
        return False

    if not isinstance(locking_script, list):
        return False

    stack = []

    try:
        # Execute the unlocking script by pushing its data onto the stack.
        for item in unlocking_script:
            if not isinstance(item, bytes):
                return False
            stack.append(item)

        # Execute each operation in the locking script.
        for operation in locking_script:

            if operation == OP_DUP:
                if len(stack) < 1:
                    return False

                stack.append(stack[-1])

            elif operation == OP_HASH160:
                if len(stack) < 1:
                    return False

                data = stack.pop()
                stack.append(hash160(data))

            elif isinstance(operation, bytes):
                # Data items in the locking script are pushed to the stack.
                stack.append(operation)

            elif operation == OP_EQUALVERIFY:
                if len(stack) < 2:
                    return False

                first = stack.pop()
                second = stack.pop()

                if first != second:
                    return False

            elif operation == OP_CHECKSIG:
                if len(stack) < 2:
                    return False

                public_key_bytes = stack.pop()
                signature = stack.pop()

                public_key = PublicKey(public_key_bytes)

                # coincurve uses SHA-256 by default for ECDSA verification.
                if not public_key.verify(signature, message):
                    return False

                stack.append(b"\x01")

            else:
                # Reject unsupported operations.
                return False

        # A successful script must finish with exactly one true value.
        return len(stack) == 1 and stack[0] == b"\x01"

    except (ValueError, TypeError, IndexError):
        return False
