import unittest

from src.merkle_tree import build_merkle_tree, get_merkle_root, load_records
from src.merkle_proof import generate_merkle_proof, verify_merkle_proof, proof_size


class TestMerkleProof(unittest.TestCase):

    def setUp(self):
        self.records = load_records("data/land_records.json")
        self.tree = build_merkle_tree(self.records)
        self.root = get_merkle_root(self.records)

    def test_valid_record_passes(self):
        proof = generate_merkle_proof(self.tree, 2)
        self.assertTrue(verify_merkle_proof(self.records[2], proof, self.root))

    def test_every_record_passes(self):
        for i, record in enumerate(self.records):
            proof = generate_merkle_proof(self.tree, i)
            self.assertTrue(verify_merkle_proof(record, proof, self.root))

    def test_altered_record_fails(self):
        proof = generate_merkle_proof(self.tree, 2)
        altered = dict(self.records[2])
        altered["parcel_id"] = "KEN-FAKE-999"
        self.assertFalse(verify_merkle_proof(altered, proof, self.root))

    def test_tampered_proof_fails(self):
        proof = generate_merkle_proof(self.tree, 2)
        proof[0] = {"hash": "0" * 64, "position": proof[0]["position"]}
        self.assertFalse(verify_merkle_proof(self.records[2], proof, self.root))

    def test_wrong_root_fails(self):
        proof = generate_merkle_proof(self.tree, 2)
        self.assertFalse(verify_merkle_proof(self.records[2], proof, "f" * 64))

    def test_proof_of_another_record_fails(self):
        proof_for_5 = generate_merkle_proof(self.tree, 5)
        self.assertFalse(verify_merkle_proof(self.records[2], proof_for_5, self.root))

    def test_eight_records_proof_has_three_hashes(self):
        proof = generate_merkle_proof(self.tree, 0)
        self.assertEqual(proof_size(proof), (3, 96))

    def test_odd_number_of_records(self):
        odd = self.records[:7]
        tree = build_merkle_tree(odd)
        root = get_merkle_root(odd)
        for i, record in enumerate(odd):
            proof = generate_merkle_proof(tree, i)
            self.assertTrue(verify_merkle_proof(record, proof, root))

    def test_single_record_has_empty_proof(self):
        one = self.records[:1]
        tree = build_merkle_tree(one)
        root = get_merkle_root(one)
        proof = generate_merkle_proof(tree, 0)
        self.assertEqual(proof, [])
        self.assertTrue(verify_merkle_proof(one[0], proof, root))

    def test_bad_index_raises(self):
        with self.assertRaises(IndexError):
            generate_merkle_proof(self.tree, 99)


if __name__ == "__main__":
    unittest.main()