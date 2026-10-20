"""
certificates.py - certificate issuance and verification (Group 4: Land Title Registry).

A certificate binds an identity/role to a secp256k1 public key. In our case study the issuer
is the Ministry of Lands registry CA ("MOL-CA"); subjects are registry officers (who sign
transfers), landowners, advocates, etc.

Keys are hex strings: 32-byte private scalar, 33-byte compressed public key.
"""
import json
from datetime import datetime, timezone

from coincurve import PrivateKey, PublicKey

UNSIGNED_FIELDS = (
    "version", "serial", "subject_id", "subject_role",
    "subject_public_key", "issuer_id", "not_before", "not_after",
)


def canonical_bytes(cert: dict) -> bytes:
    """Deterministic serialization of every field except the signature."""
    body = {k: v for k, v in cert.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def issue_certificate(issuer_id, issuer_private_key_hex, subject_id, subject_role,
                      subject_public_key_hex, not_before, not_after, serial=1) -> dict:
    """not_before / not_after: ISO-8601 strings with offset, e.g. '2026-01-01T00:00:00+00:00'."""
    cert = {
        "version": 1,
        "serial": serial,
        "subject_id": subject_id,
        "subject_role": subject_role,
        "subject_public_key": subject_public_key_hex,
        "issuer_id": issuer_id,
        "not_before": not_before,
        "not_after": not_after,
    }
    sk = PrivateKey.from_hex(issuer_private_key_hex)
    cert["signature"] = sk.sign(canonical_bytes(cert)).hex()  # SHA-256 by default
    return cert


def verify_certificate(cert: dict, issuer_public_key_hex: str,
                       trusted_issuer_id: str, now: datetime = None):
    """Returns (ok: bool, reason: str). Never raises on malformed input."""
    try:
        missing = [f for f in UNSIGNED_FIELDS + ("signature",) if f not in cert]
        if missing:
            return False, f"FAIL: missing fields {missing}"

        # 1. Signature over canonical bytes (checked first so any edit is reported as tampering)
        pk = PublicKey(bytes.fromhex(issuer_public_key_hex))
        if not pk.verify(bytes.fromhex(cert["signature"]), canonical_bytes(cert)):
            return False, "FAIL: signature invalid (certificate altered or not signed by this issuer)"

        # 2. Issuer identity
        if cert["issuer_id"] != trusted_issuer_id:
            return False, f"FAIL: issuer '{cert['issuer_id']}' is not the trusted issuer '{trusted_issuer_id}'"

        # 3. Validity period
        now = now or datetime.now(timezone.utc)
        nb = datetime.fromisoformat(cert["not_before"])
        na = datetime.fromisoformat(cert["not_after"])
        if now < nb:
            return False, "FAIL: certificate not yet valid"
        if now > na:
            return False, "FAIL: certificate expired"

        return True, "OK: signature valid, issuer trusted, within validity period"
    except Exception as e:  # malformed hex/DER, bad dates, wrong key length, etc.
        return False, f"FAIL: malformed certificate or key ({type(e).__name__}: {e})"


# ---------------------------------------------------------------------------
# Digital signatures on messages (e.g. a land transfer request)
# ---------------------------------------------------------------------------
def sign_message(private_key_hex: str, message: bytes) -> str:
    """ECDSA/secp256k1 over SHA-256(message); returns hex DER signature."""
    return PrivateKey.from_hex(private_key_hex).sign(message).hex()


def verify_message(public_key_hex: str, message: bytes, signature_hex: str) -> bool:
    """True only if signature_hex is a valid signature on message by this public key."""
    try:
        return PublicKey(bytes.fromhex(public_key_hex)).verify(
            bytes.fromhex(signature_hex), message)
    except Exception:
        return False


def verify_signed_message(cert: dict, issuer_public_key_hex: str, trusted_issuer_id: str,
                          message: bytes, signature_hex: str, now: datetime = None):
    """Full check: (1) the signer's certificate is valid, (2) the signature on the message
    verifies under the public key INSIDE that certificate. Returns (ok, reason)."""
    ok, reason = verify_certificate(cert, issuer_public_key_hex, trusted_issuer_id, now)
    if not ok:
        return False, f"FAIL: signer's certificate rejected -> {reason}"
    if not verify_message(cert["subject_public_key"], message, signature_hex):
        return False, "FAIL: certificate valid, but signature does not match message/signer"
    return True, f"OK: certificate valid and message signed by {cert['subject_id']} ({cert['subject_role']})"