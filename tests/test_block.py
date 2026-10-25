import unittest

from src.block import Block, create_genesis_block, create_next_block, GENESIS_PREVIOUS_HASH, is_coinbase
from src.coinbase import CoinbaseTransaction
from src.demo_chain import build_demo_chain
from src.script import execute_script
from src.signing import signing_digest, unlocking_script_for, locking_script_for
from src.transactions import Transaction, TransactionInput, TransactionOutput

# Difficulty
D = 2  

class TestBlock(unittest.TestCase):

    def setUp(self):
        self.chain, self.utxo, self.parties, self.transfer = build_demo_chain(D, verbose=False)

    # success cases
    def test_chain_has_four_blocks(self):
        self.assertEqual([b.height for b in self.chain], [0, 1, 2, 3])

    def test_genesis_has_placeholder_previous_hash(self):
        self.assertEqual(self.chain[0].previous_hash, GENESIS_PREVIOUS_HASH)

    def test_blocks_are_linked(self):
        for prev, cur in zip(self.chain, self.chain[1:]):
            self.assertEqual(cur.previous_hash, prev.block_hash)

    def test_every_block_meets_difficulty(self):
        for b in self.chain:
            self.assertTrue(b.block_hash.startswith("0" * D))

    def test_mining_records_attempts(self):
        for b in self.chain:
            self.assertEqual(b.mining_attempts, b.nonce + 1)

    def test_every_block_starts_with_one_coinbase(self):
        for b in self.chain:
            self.assertTrue(is_coinbase(b.transactions[0]))
            self.assertFalse(any(is_coinbase(t) for t in b.transactions[1:]))

    def test_valid_blocks_pass_validation(self):
        for b in self.chain:
            ok, problems = b.validate()
            self.assertTrue(ok, problems)

    def test_block_two_contains_the_real_transfer(self):
        self.assertIs(self.chain[2].transactions[1], self.transfer)

    def test_transfer_inside_chain_still_satisfies_its_script(self):
        seller_output = TransactionOutput(50, self.parties["seller"]["address"])
        ok = execute_script(unlocking_script_for(self.transfer, 0), locking_script_for(seller_output),
                            signing_digest(self.transfer))
        self.assertTrue(ok)

    def test_coinbase_in_block_two_collects_the_fee(self):
        self.assertEqual(self.chain[2].transactions[0].outputs[0].amount, 51)

    def test_balances(self):
        p = self.parties
        self.assertEqual(self.utxo.balance(p["seller"]["address"]), 0)
        self.assertEqual(self.utxo.balance(p["buyer"]["address"]), 49)

    def test_hash_and_merkle_root_are_deterministic(self):
        b = self.chain[2]
        self.assertEqual(b.calculate_hash(), b.block_hash)
        self.assertEqual(b.calculate_merkle_root(), b.merkle_root)

    def test_rebuilding_gives_identical_chain(self):
        again, _, _, _ = build_demo_chain(D, verbose=False)
        self.assertEqual([b.block_hash for b in again], [b.block_hash for b in self.chain])

    # failure cases
    def test_changed_amount_breaks_merkle_root(self):
        block = self.chain[2]
        stored_before = self.transfer.transaction_id
        self.transfer.outputs[0].amount = 1000
        self.assertEqual(self.transfer.transaction_id, stored_before)    
        ok, problems = block.validate()
        self.assertFalse(ok)                                             
        self.assertTrue(any("Merkle root" in p for p in problems))

    def test_changed_recipient_breaks_merkle_root(self):
        self.transfer.outputs[0].address = "THIEF-ADDRESS"
        ok, problems = self.chain[2].validate()
        self.assertFalse(ok)
        self.assertTrue(any("Merkle root" in p for p in problems))

    def test_changed_nonce_breaks_hash(self):
        self.chain[1].nonce += 1
        ok, problems = self.chain[1].validate()
        self.assertFalse(ok)
        self.assertTrue(any("recomputed header hash" in p for p in problems))

    def test_remined_block_no_longer_matches_next_block(self):
        self.transfer.outputs[0].amount = 1000
        self.chain[2].mine(verbose=False)                                 
        self.assertTrue(self.chain[2].validate()[0])                      
        self.assertNotEqual(self.chain[3].previous_hash, self.chain[2].block_hash)   

    def test_unmined_block_fails_difficulty(self):
        b = Block(1, "a" * 64, [CoinbaseTransaction("M", 1, 50)], 4, "M")
        b.block_hash = b.calculate_hash()
        ok, problems = b.validate()
        self.assertFalse(ok)
        self.assertTrue(any("difficulty" in p for p in problems))

    def test_missing_coinbase_detected(self):
        tx = Transaction(inputs=[TransactionInput("a" * 64, 0)], outputs=[TransactionOutput(1, "X")])
        b = Block(1, "a" * 64, [tx], 1, "M")
        b.mine(verbose=False)
        ok, problems = b.validate()
        self.assertFalse(ok)
        self.assertTrue(any("not a coinbase" in p for p in problems))

    def test_second_coinbase_detected(self):
        b = Block(1, "a" * 64, [CoinbaseTransaction("M", 1, 50), CoinbaseTransaction("N", 1, 50)], 1, "M")
        b.mine(verbose=False)
        ok, problems = b.validate()
        self.assertFalse(ok)
        self.assertTrue(any("after the first position" in p for p in problems))


if __name__ == "__main__":
    unittest.main()