"""
Milestone 2 integration tests - Case Study 4: Land Title Registry (Group 4).
Run from the repo root:   python -m unittest integration.test_integration -v
Test IDs (IT-xx) match the integration test plan in the report.
"""
import math, unittest
from datetime import datetime, timezone
from integration import adapter as A

RECORDS = A.load_records()          # 8 real records from data/land_records.json -> tree depth 3

def forge(rec):  return {**rec, "new_owner": "ATTACKER", "owner": "ATTACKER"}

class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ca      = A.generate_keypair("ministry_ca")
        cls.officer = A.generate_keypair("registry_official")
        cls.owner   = A.generate_keypair("landowner")
        cls.cert    = A.issue_certificate(cls.ca["private_key"], "officer:REG-0042",
                                          "registry_official", cls.officer["public_key"])

class TestKeys(Base):
    def test_IT01_roles_have_distinct_keys(self):
        self.assertNotEqual(self.officer["private_key"], self.owner["private_key"])
        self.assertNotEqual(self.officer["public_key"], self.owner["public_key"])
        self.assertNotEqual(self.officer["address"], self.owner["address"])
    def test_IT02_signature_roundtrip(self):
        sig = A.sign(self.officer["private_key"], b"approve")
        self.assertTrue(A.verify_signature(self.officer["public_key"], b"approve", sig))
    def test_IT03_wrong_key_rejects_signature(self):
        sig = A.sign(self.officer["private_key"], b"approve")
        self.assertFalse(A.verify_signature(self.owner["public_key"], b"approve", sig))
    def test_IT04_altered_message_rejects_signature(self):
        sig = A.sign(self.officer["private_key"], b"approve parcel 1")
        self.assertFalse(A.verify_signature(self.officer["public_key"], b"approve parcel 2", sig))

class TestCertificates(Base):
    def test_IT05_valid_certificate_verifies(self):
        self.assertTrue(A.verify_certificate(self.cert, self.ca["public_key"])[0])
    def test_IT06_altered_field_fails(self):
        bad = dict(self.cert, subject_id="officer:REG-0001")
        self.assertFalse(A.verify_certificate(bad, self.ca["public_key"])[0])
    def test_IT07_swapped_public_key_fails(self):
        bad = dict(self.cert, subject_public_key=self.owner["public_key"])
        self.assertFalse(A.verify_certificate(bad, self.ca["public_key"])[0])
    def test_IT08_wrong_issuer_key_fails(self):
        self.assertFalse(A.verify_certificate(self.cert, self.owner["public_key"])[0])
    def test_IT09_expired_certificate_fails(self):
        late = datetime(2027, 6, 1, tzinfo=timezone.utc)
        ok, reason = A.verify_certificate(self.cert, self.ca["public_key"], now=late)
        self.assertFalse(ok); self.assertIn("expired", reason)

class TestMerkle(Base):
    def test_IT10_root_is_deterministic(self):
        self.assertEqual(A.merkle_root(RECORDS), A.merkle_root(list(RECORDS)))
    def test_IT11_every_leaf_proof_verifies(self):
        root = A.merkle_root(RECORDS)
        for i, rec in enumerate(RECORDS):
            self.assertTrue(A.verify_proof(rec, A.get_proof(RECORDS, i), root), f"leaf {i}")
    def test_IT12_altered_record_fails_proof(self):
        root, proof = A.merkle_root(RECORDS), A.get_proof(RECORDS, 0)
        self.assertFalse(A.verify_proof(forge(RECORDS[0]), proof, root))
    def test_IT13_odd_number_of_records(self):
        odd = RECORDS[:7]; root = A.merkle_root(odd)
        for i, rec in enumerate(odd):
            self.assertTrue(A.verify_proof(rec, A.get_proof(odd, i), root), f"leaf {i}")
    def test_IT14_proof_size_grows_logarithmically(self):
        self.assertEqual(len(A.get_proof(RECORDS, 0)), 3)                          # 8 records
        big = [{"parcel_id": f"KEN-NAI-{i:04d}"} for i in range(1024)]
        self.assertEqual(len(A.get_proof(big, 0)), math.ceil(math.log2(1024)))     # 10, not 1024
    def test_IT15_changing_order_changes_root(self):
        self.assertNotEqual(A.merkle_root(RECORDS), A.merkle_root(RECORDS[::-1]))

class TestEndToEnd(Base):
    """Chain of trust: CA cert -> officer key -> signed Merkle root -> inclusion proof -> record."""
    def _verifier(self, cert, root, sig, record, proof):
        ok, reason = A.verify_signed_message(cert, self.ca["public_key"], root.encode(), sig)
        if not ok:
            return "certificate rejected" if "certificate rejected" in reason else "root signature rejected"
        if not A.verify_proof(record, proof, root):
            return "inclusion proof rejected"
        return "accepted"
    def setUp(self):
        self.root = A.merkle_root(RECORDS)
        self.sig  = A.sign(self.officer["private_key"], self.root.encode())
    def test_IT16_full_chain_succeeds(self):
        self.assertEqual(self._verifier(self.cert, self.root, self.sig, RECORDS[3], A.get_proof(RECORDS, 3)), "accepted")
    def test_IT17_forged_record_is_caught(self):
        self.assertEqual(self._verifier(self.cert, self.root, self.sig, forge(RECORDS[3]), A.get_proof(RECORDS, 3)), "inclusion proof rejected")
    def test_IT18_root_signed_by_unauthorised_key_is_caught(self):
        bad_sig = A.sign(self.owner["private_key"], self.root.encode())       # landowner is not the officer
        self.assertEqual(self._verifier(self.cert, self.root, bad_sig, RECORDS[3], A.get_proof(RECORDS, 3)), "root signature rejected")
    def test_IT19_tampered_certificate_is_caught(self):
        fake = dict(self.cert, subject_public_key=self.owner["public_key"])
        bad_sig = A.sign(self.owner["private_key"], self.root.encode())
        self.assertEqual(self._verifier(fake, self.root, bad_sig, RECORDS[3], A.get_proof(RECORDS, 3)), "certificate rejected")
    def test_IT20_limit_authorised_but_false_record_passes(self):
        """DOCUMENTS A LIMITATION: a corrupt officer signs a fraudulent record; every check still passes."""
        recs = RECORDS[:]; recs[0] = forge(RECORDS[0])
        root = A.merkle_root(recs); sig = A.sign(self.officer["private_key"], root.encode())
        self.assertEqual(self._verifier(self.cert, root, sig, recs[0], A.get_proof(recs, 0)), "accepted")

if __name__ == "__main__":
    unittest.main(verbosity=2)
