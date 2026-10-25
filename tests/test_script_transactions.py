"""
Member 4: script validation on REAL transactions (Member 1's Transaction classes).
Run:  python -m pytest tests/test_script_transactions.py -v
"""
from coincurve import PrivateKey

from src.script import execute_script, hash160
from src.script_trace import trace_script
from src.signing import signing_digest, sign_input, unlocking_script_for, locking_script_for
from src.transactions import Transaction, TransactionInput, TransactionOutput


def make_spend(signer=None):
    """The seller owns a 100-unit output. A transaction pays it to the buyer, signed by `signer`
    (the seller by default). Returns (transaction, the output being spent)."""
    seller = PrivateKey()
    seller_pub = seller.public_key.format(compressed=True)
    previous_output = TransactionOutput(100, hash160(seller_pub).hex())      # locked to the seller
    previous_tx = Transaction(outputs=[previous_output])
    tx = Transaction(inputs=[TransactionInput(previous_tx.transaction_id, 0)],
                     outputs=[TransactionOutput(100, "BUYER-ADDRESS")])
    sign_input(tx, 0, signer or seller)
    return tx, previous_output


def run(tx, previous_output):
    unlock, lock = unlocking_script_for(tx, 0), locking_script_for(previous_output)
    message = signing_digest(tx)                  # recomputed from the CURRENT fields every time
    return trace_script(unlock, lock, message), execute_script(unlock, lock, message)


def test_valid_spend_of_a_real_transaction():
    traced, real = run(*make_spend())
    assert traced["ok"] is True and real is True


def test_amount_changed_after_signing_fails_at_checksig():
    tx, previous_output = make_spend()
    tx.outputs[0].amount = 1000                   # tampering after the signature was made
    traced, real = run(tx, previous_output)
    assert traced["failed_at"] == "OP_CHECKSIG" and real is False


def test_recipient_changed_after_signing_fails_at_checksig():
    tx, previous_output = make_spend()
    tx.outputs[0].address = "THIEF-ADDRESS"
    traced, real = run(tx, previous_output)
    assert traced["failed_at"] == "OP_CHECKSIG" and real is False


def test_thief_signing_with_their_own_key_fails_at_equalverify():
    tx, previous_output = make_spend(signer=PrivateKey())         # not the owner of the output
    traced, real = run(tx, previous_output)
    assert traced["failed_at"] == "OP_EQUALVERIFY" and real is False


def test_stored_transaction_id_does_not_follow_changes():
    """FINDING for the report: transaction_id is computed once, in __init__."""
    tx, _ = make_spend()
    stored = tx.transaction_id
    tx.outputs[0].amount = 1000
    assert tx.transaction_id == stored            # unchanged: stale
    assert tx.calculate_id() != stored            # only recalculating shows the change


def test_transaction_id_includes_the_signature():
    """FINDING for the report: the ID covers signature and public_key, so it cannot be what is signed,
    and the same payment signed twice (different signatures) gets different IDs."""
    tx, _ = make_spend()
    unsigned_id = Transaction(inputs=[TransactionInput(tx.inputs[0].previous_txid, 0)],
                              outputs=[TransactionOutput(100, "BUYER-ADDRESS")]).transaction_id
    assert tx.calculate_id() != unsigned_id
