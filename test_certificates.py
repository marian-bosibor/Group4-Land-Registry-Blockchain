"""Repeatable tests for certificates.py. Run: python -m unittest test_certificates -v"""
import copy
import unittest
from datetime import datetime, timezone

from certificates import (issue_certificate, verify_certificate, sign_message,
                          verify_message, verify_signed_message)
from keys_adapter import new_keypair as generate_keypair

ISSUER = "MOL-CA"
NB, NA = "2026-01-01T00:00:00+00:00", "2027-01-01T00:00:00+00:00"
NOW = datetime(2026, 10, 15, tzinfo=timezone.utc)


class CertificateTests(unittest.TestCase):
    def setUp(self):
        self.ca = generate_keypair("ministry_ca")
        self.officer = generate_keypair("registry_officer")
        self.cert = issue_certificate(ISSUER, self.ca["private_key"], "officer:REG-0042",
                                      "registry_official", self.officer["public_key"], NB, NA)

    def verify(self, cert, now=NOW, issuer=ISSUER):
        return verify_certificate(cert, self.ca["public_key"], issuer, now)[0]

    def test_valid_certificate_passes(self):
        self.assertTrue(self.verify(self.cert))

    def test_deterministic_signature(self):
        again = issue_certificate(ISSUER, self.ca["private_key"], "officer:REG-0042",
                                  "registry_official", self.officer["public_key"], NB, NA)
        self.assertEqual(self.cert["signature"], again["signature"])

    def test_every_signed_field_is_protected(self):
        changes = {"serial": 2, "subject_id": "x", "subject_role": "registry_admin",
                   "subject_public_key": generate_keypair("a")["public_key"],
                   "issuer_id": "EVIL-CA", "not_before": "2020-01-01T00:00:00+00:00",
                   "not_after": "2099-01-01T00:00:00+00:00", "version": 2}
        for field, value in changes.items():
            t = copy.deepcopy(self.cert)
            t[field] = value
            self.assertFalse(self.verify(t), f"tampering {field} was not detected")

    def test_forged_certificate_rejected(self):
        fake = generate_keypair("attacker")
        forged = issue_certificate(ISSUER, fake["private_key"], "officer:FAKE",
                                   "registry_official", fake["public_key"], NB, NA)
        self.assertFalse(self.verify(forged))

    def test_expired_and_not_yet_valid(self):
        self.assertFalse(self.verify(self.cert, now=datetime(2027, 6, 1, tzinfo=timezone.utc)))
        self.assertFalse(self.verify(self.cert, now=datetime(2025, 6, 1, tzinfo=timezone.utc)))

    def test_wrong_trusted_issuer_name(self):
        self.assertFalse(self.verify(self.cert, issuer="OTHER-CA"))

    def test_missing_field_and_garbage_do_not_crash(self):
        t = copy.deepcopy(self.cert)
        del t["signature"]
        self.assertFalse(self.verify(t))
        t = copy.deepcopy(self.cert)
        t["signature"] = "zz"
        self.assertFalse(self.verify(t))

    def test_signature_valid_altered_and_wrong_signer(self):
        msg = b"Transfer request for land parcel LR-001"
        sig = sign_message(self.officer["private_key"], msg)
        self.assertTrue(verify_message(self.officer["public_key"], msg, sig))
        self.assertFalse(verify_message(self.officer["public_key"], b"LR-999", sig))
        other = generate_keypair("landowner")
        self.assertFalse(verify_message(other["public_key"], msg, sig))
        self.assertFalse(verify_message(self.officer["public_key"], msg, "zz"))

    def test_signed_message_requires_valid_certificate(self):
        msg = b"Transfer request for land parcel LR-001"
        sig = sign_message(self.officer["private_key"], msg)
        args = (self.ca["public_key"], ISSUER)
        self.assertTrue(verify_signed_message(self.cert, *args, msg, sig, NOW)[0])
        self.assertFalse(verify_signed_message(self.cert, *args, b"LR-999", sig, NOW)[0])
        late = datetime(2027, 6, 1, tzinfo=timezone.utc)
        self.assertFalse(verify_signed_message(self.cert, *args, msg, sig, late)[0])
        t = copy.deepcopy(self.cert); t["subject_role"] = "registry_admin"
        self.assertFalse(verify_signed_message(t, *args, msg, sig, NOW)[0])


if __name__ == "__main__":
    unittest.main()