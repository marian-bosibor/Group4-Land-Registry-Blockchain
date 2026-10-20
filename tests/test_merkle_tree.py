import unittest

from src.merkle_tree import (
    hash_record,
    hash_pair,
    build_merkle_tree,
    get_merkle_root,
    load_records
)


class TestMerkleTree(unittest.TestCase):

    def setUp(self):
        self.records = load_records("data/land_records.json")

    def test_eight_records(self):
        """
        The tree should contain 8 leaf hashes.
        """
        tree = build_merkle_tree(self.records)

        self.assertEqual(len(tree[0]), 8)

    def test_merkle_root_exists(self):
        """
        The Merkle Root should be a 64-character SHA-256 hash.
        """
        root = get_merkle_root(self.records)

        self.assertIsInstance(root, str)
        self.assertEqual(len(root), 64)

    def test_hash_record(self):
        """
        A record should produce a SHA-256 hash.
        """
        hashed = hash_record(self.records[0])

        self.assertEqual(len(hashed), 64)

    def test_hash_pair(self):
        """
        Combining two hashes should produce another SHA-256 hash.
        """
        hash1 = hash_record(self.records[0])
        hash2 = hash_record(self.records[1])

        parent = hash_pair(hash1, hash2)

        self.assertEqual(len(parent), 64)

    def test_odd_number_of_records(self):
        """
        The tree should handle an odd number of records
        by duplicating the last hash.
        """
        odd_records = self.records[:7]

        tree = build_merkle_tree(odd_records)

        # The original leaf level still contains 7 records
        self.assertEqual(len(tree[0]), 7)

        # The odd last hash is duplicated, producing 4 parent hashes
        self.assertEqual(len(tree[1]), 4)

        # The tree must eventually produce one Merkle Root
        self.assertEqual(len(tree[-1]), 1)


if __name__ == "__main__":
    unittest.main()
