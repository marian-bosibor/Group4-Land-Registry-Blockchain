"""
demo_certificates.py - Run: python demo_certificates.py
All keys are generated fresh for demonstration only; none hold value.
"""
import copy
import json
from datetime import datetime, timezone

from certificates import issue_certificate, verify_certificate
from keys_adapter import new_keypair as generate_keypair

ISSUER_ID = "MOL-CA"  # Ministry of Lands registry certificate authority
NB, NA = "2026-01-01T00:00:00+00:00", "2027-01-01T00:00:00+00:00"
NOW = datetime(2026, 10, 15, tzinfo=timezone.utc)  # fixed so output is reproducible


def show(title, cert, issuer_pub, now=NOW):
    ok, reason = verify_certificate(cert, issuer_pub, ISSUER_ID, now)
    print(f"  -> {'PASS' if ok else 'REJECTED'}  {reason}\n")
    return ok


print("=" * 70)
print("1. KEY PAIRS (demo only)")
print("=" * 70)
ca = generate_keypair("ministry_ca")
officer = generate_keypair("registry_officer")
owner = generate_keypair("landowner")
for kp in (ca, officer, owner):
    print(f"[{kp['role']}]\n  public_key: {kp['public_key']}\n  address:    {kp['address']}")

print("\n" + "=" * 70)
print("2. ISSUANCE: MOL-CA certifies a registry officer")
print("=" * 70)
cert = issue_certificate(ISSUER_ID, ca["private_key"], "officer:REG-0042",
                         "registry_official", officer["public_key"], NB, NA, serial=1)
print(json.dumps(cert, indent=2))

print("\n" + "=" * 70)
print("3. VERIFICATION SUCCESS")
print("=" * 70)
show("valid", cert, ca["public_key"])

print("=" * 70)
print("4. TAMPER DETECTION (one field altered each time)")
print("=" * 70)

print("a) subject_id changed (officer:REG-0042 -> officer:REG-0001)")
t = copy.deepcopy(cert); t["subject_id"] = "officer:REG-0001"
show("tamper id", t, ca["public_key"])

print("b) subject_role escalated (registry_official -> registry_admin)")
t = copy.deepcopy(cert); t["subject_role"] = "registry_admin"
show("tamper role", t, ca["public_key"])

print("c) subject_public_key swapped for attacker's key (key substitution attack)")
attacker = generate_keypair("attacker")
t = copy.deepcopy(cert); t["subject_public_key"] = attacker["public_key"]
show("tamper key", t, ca["public_key"])

print("d) validity extended (not_after -> 2099)")
t = copy.deepcopy(cert); t["not_after"] = "2099-01-01T00:00:00+00:00"
show("tamper validity", t, ca["public_key"])

print("=" * 70)
print("5. OTHER FAILURE CASES")
print("=" * 70)

print("e) forged certificate: attacker self-signs claiming to be MOL-CA")
forged = issue_certificate(ISSUER_ID, attacker["private_key"], "officer:FAKE",
                           "registry_official", attacker["public_key"], NB, NA, serial=99)
show("forged", forged, ca["public_key"])

print("f) expired certificate (verified at 2027-06-01)")
show("expired", cert, ca["public_key"], now=datetime(2027, 6, 1, tzinfo=timezone.utc))

print("g) not yet valid (verified at 2025-12-01)")
show("early", cert, ca["public_key"], now=datetime(2025, 12, 1, tzinfo=timezone.utc))

print("h) certificate verified against wrong trusted issuer name")
ok, reason = verify_certificate(cert, ca["public_key"], "SOME-OTHER-CA", NOW)
print(f"  -> {'PASS' if ok else 'REJECTED'}  {reason}\n")

print("i) landowner certificate (second role) issued and verified")
oc = issue_certificate(ISSUER_ID, ca["private_key"], "owner:KE-ID-DEMO-001",
                       "landowner", owner["public_key"], NB, NA, serial=2)
show("owner", oc, ca["public_key"])

print("=" * 70)
print("6. DIGITAL SIGNATURES CHECKED AGAINST CERTIFICATES")
print("=" * 70)
from certificates import sign_message, verify_signed_message
msg = b"Transfer request for land parcel LR-001"
sig = sign_message(officer["private_key"], msg)
print(f"Message: {msg.decode()}\nSigner: officer:REG-0042\nSignature: {sig}\n")

print("j) genuine message + valid certificate")
print("  ->", verify_signed_message(cert, ca["public_key"], ISSUER_ID, msg, sig, NOW)[1], "\n")

print("k) message altered after signing (LR-001 -> LR-999)")
print("  ->", verify_signed_message(cert, ca["public_key"], ISSUER_ID,
      b"Transfer request for land parcel LR-999", sig, NOW)[1], "\n")

print("l) signed by someone else (landowner's key) but presented with officer's certificate")
bad = sign_message(owner["private_key"], msg)
print("  ->", verify_signed_message(cert, ca["public_key"], ISSUER_ID, msg, bad, NOW)[1], "\n")

print("m) genuine signature but officer's certificate has expired")
print("  ->", verify_signed_message(cert, ca["public_key"], ISSUER_ID, msg, sig,
      datetime(2027, 6, 1, tzinfo=timezone.utc))[1], "\n")

print("=" * 70)
print("WHAT THIS PROVES / DOES NOT PROVE")
print("=" * 70)
print("Proves: MOL-CA's key signed this exact (subject, role, public key, validity).")
print("Does NOT prove: the person is truly a registrar/owner, is honest, or that")
print("their private key is uncompromised. No revocation list in this model.")