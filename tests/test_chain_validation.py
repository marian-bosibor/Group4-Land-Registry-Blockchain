import copy
import unittest

from src.chain_validation import validate_chain
from src.coinbase import CoinbaseTransaction
from src.demo_chain import build_demo_chain, make_party
from src.signing import sign_input
from src.tamper_demo import remine_from
from src.transactions import Transaction, TransactionInput, TransactionOutput

D = 2  # difficulty used in tests (fast)
T = 2  # block holding the land-title transfer in the group's demo chain


def names(result, block=None):
    return {(c.block, c.name) for c in result.failures if block is None or c.block == block}


class ChainValidationTests(unittest.TestCase):
    def setUp(self):
        built = build_demo_chain(D, verbose=False)
        self.honest, _utxo, self.parties, self.transfer = built
        self.chain = copy.deepcopy(self.honest)
        self.attacker = make_party("attacker")

    def validate(self, chain=None):
        return validate_chain(chain or self.chain, min_difficulty=D)

    def signed_transfer(self, spend_txid, index, pays_amount, to_address, signer=None):
        tx = Transaction(inputs=[TransactionInput(spend_txid, index)],
                         outputs=[TransactionOutput(pays_amount, to_address)])
        sign_input(tx, 0, (signer or self.parties["seller"])["private_key"])
        tx.transaction_id = tx.calculate_id()
        return tx

    # ---- success ------------------------------------------------------------------------
    def test_valid_chain_passes(self):
        r = self.validate()
        self.assertTrue(r.valid, r.failures)
        self.assertEqual(len(self.chain), 4)
        self.assertEqual(self.chain[0].previous_hash, "0" * 64)

    # ---- tampering ----------------------------------------------------------------------
    def test_altered_transaction_caught_by_merkle_root(self):
        self.chain[T].transactions[1].outputs[0].address = self.attacker["address"]
        r = self.validate()
        self.assertEqual((r.first_failure.block, r.first_failure.name), (T, "merkle_root"))
        self.assertNotEqual(self.chain[T].merkle_root, self.chain[T].calculate_merkle_root())
        self.assertNotIn((T, "block_hash"), names(r))  # header untouched, hash still matches

    def test_altered_amount_caught_by_merkle_root(self):
        self.chain[T].transactions[1].outputs[0].amount = 40
        self.assertEqual(self.validate().first_failure.name, "merkle_root")

    def test_fixing_merkle_root_only_breaks_block_hash(self):
        tx = self.chain[T].transactions[1]
        tx.outputs[0].amount = 40
        tx.transaction_id = tx.calculate_id()
        self.chain[T].merkle_root = self.chain[T].calculate_merkle_root()
        self.assertIn((T, "block_hash"), names(self.validate()))

    def test_rehash_without_mining_fails_difficulty(self):
        b = self.chain[T]
        b.transactions[1].outputs[0].amount = 40
        b.merkle_root = b.calculate_merkle_root()
        b.nonce = 0
        while b.calculate_hash().startswith("0" * D):
            b.nonce += 1
        b.block_hash = b.calculate_hash()
        self.assertIn((T, "difficulty"), names(self.validate()))

    def test_remining_only_one_block_breaks_next_link(self):
        self.chain[1].timestamp += 1  # harmless edit that changes block 1's hash
        old = self.chain[1].block_hash
        self.chain[1].mine(verbose=False)
        self.assertNotEqual(old, self.chain[1].block_hash)
        r = self.validate()
        self.assertIn((2, "previous_hash"), names(r))
        self.assertNotIn((1, "block_hash"), names(r))

    def test_full_rewrite_of_signed_transfer_still_fails_on_signature(self):
        tx = self.chain[T].transactions[1]
        tx.outputs[0].address = self.attacker["address"]
        tx.transaction_id = tx.calculate_id()
        remine_from(self.chain, T)
        r = self.validate()
        self.assertIn((T, "scripts"), names(r))
        for blk in range(T, 4):
            self.assertNotIn((blk, "previous_hash"), names(r))
            self.assertNotIn((blk, "merkle_root"), names(r))

    def test_full_rewrite_of_unsigned_coinbase_succeeds_only_after_redoing_work(self):
        cb = self.chain[1].transactions[0]
        cb.outputs[0].address = self.attacker["address"]
        cb.transaction_id = cb.calculate_id()
        self.chain[1].miner_address = self.attacker["address"]
        self.assertFalse(self.validate().valid)
        costs = remine_from(self.chain, 1)
        self.assertTrue(self.validate().valid)
        self.assertEqual(len(costs), 3)  # blocks 1, 2 and 3 all had to be mined again

    # ---- individual rules ---------------------------------------------------------------
    def test_wrong_height(self):
        self.chain[2].height = 7
        remine_from(self.chain, 2)
        self.assertIn((2, "height"), names(self.validate()))

    def test_difficulty_below_network_minimum(self):
        self.chain[3].difficulty = 0
        remine_from(self.chain, 3)
        self.assertIn((3, "difficulty"), names(self.validate()))

    def test_coinbase_overpays(self):
        cb = self.chain[3].transactions[0]
        cb.outputs[0].amount = 1000
        cb.transaction_id = cb.calculate_id()
        remine_from(self.chain, 3)
        self.assertIn((3, "coinbase_amount"), names(self.validate()))

    def test_coinbase_height_must_match_block(self):
        cb = self.chain[3].transactions[0]
        cb.block_height = 99
        cb.transaction_id = cb.calculate_id()
        remine_from(self.chain, 3)
        self.assertIn((3, "coinbase_height"), names(self.validate()))

    def test_second_coinbase_in_block(self):
        self.chain[3].transactions.append(CoinbaseTransaction(self.attacker["address"], 3, 50))
        remine_from(self.chain, 3)
        self.assertIn((3, "coinbase_position"), names(self.validate()))

    def test_missing_coinbase(self):
        self.chain[T].transactions.pop(0)  # leaves only the transfer
        remine_from(self.chain, T)
        self.assertIn((T, "coinbase_position"), names(self.validate()))

    def test_empty_block_does_not_crash_validator(self):
        self.chain[3].transactions = []
        r = self.validate()
        self.assertIn((3, "merkle_root"), names(r))
        self.assertIn((3, "coinbase_position"), names(r))

    def test_double_spend_rejected(self):
        genesis_cb = self.chain[0].transactions[0]
        second = self.signed_transfer(genesis_cb.transaction_id, 0, 49, self.attacker["address"])
        self.chain[3].transactions.append(second)
        remine_from(self.chain, 3)
        r = self.validate()
        self.assertIn((3, "inputs_unspent"), names(r))
        self.assertNotIn((T, "inputs_unspent"), names(r))  # the first, genuine spend is fine

    def test_outputs_exceed_inputs(self):
        genesis_cb = self.chain[0].transactions[0]
        inflate = self.signed_transfer(genesis_cb.transaction_id, 0, 60, self.parties["buyer"]["address"])
        self.chain[T].transactions[1] = inflate
        remine_from(self.chain, T)
        r = self.validate()
        self.assertIn((T, "value_balance"), names(r))
        self.assertNotIn((T, "scripts"), names(r))  # the signature itself was genuine

    def test_spending_output_that_never_existed(self):
        ghost = self.signed_transfer("ab" * 32, 0, 1, self.parties["buyer"]["address"])
        self.chain[T].transactions[1] = ghost
        remine_from(self.chain, T)
        self.assertIn((T, "inputs_unspent"), names(self.validate()))

    def test_missing_signature_is_rejected_not_a_crash(self):
        tx = self.chain[T].transactions[1]
        tx.inputs[0].signature = None
        tx.transaction_id = tx.calculate_id()
        remine_from(self.chain, T)
        r = self.validate()
        self.assertIn((T, "scripts"), names(r))
        self.assertTrue(any("malformed unlocking data" in c.detail for c in r.failures))

    def test_spend_signed_by_wrong_key_rejected_at_equalverify(self):
        genesis_cb = self.chain[0].transactions[0]
        stolen = self.signed_transfer(genesis_cb.transaction_id, 0, 49, self.attacker["address"],
                                      signer=self.attacker)
        self.chain[T].transactions[1] = stolen
        remine_from(self.chain, T)
        r = self.validate()
        self.assertTrue(any(c.name == "scripts" and "OP_EQUALVERIFY" in c.detail for c in r.failures))


if __name__ == "__main__":
    unittest.main()