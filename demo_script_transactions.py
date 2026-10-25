"""Traces for REAL transactions. Run from the repo root:  python demo_script_transactions.py"""
from coincurve import PrivateKey
from src.script_trace import trace_script, print_trace
from src.signing import signing_digest, unlocking_script_for, locking_script_for
from tests.test_script_transactions import make_spend


def show(title, tx, previous_output):
    print_trace(title, trace_script(unlocking_script_for(tx, 0), locking_script_for(previous_output),
                                    signing_digest(tx)))

tx, prev = make_spend()
show("REAL TRANSACTION 1  SUCCESSFUL SPEND: seller pays buyer 100", tx, prev)

tx, prev = make_spend()
tx.outputs[0].amount = 1000
show("REAL TRANSACTION 2  AMOUNT CHANGED 100 -> 1000 AFTER SIGNING: caught by OP_CHECKSIG", tx, prev)

tx, prev = make_spend()
tx.outputs[0].address = "THIEF-ADDRESS"
show("REAL TRANSACTION 3  RECIPIENT CHANGED AFTER SIGNING: caught by OP_CHECKSIG", tx, prev)

tx, prev = make_spend(signer=PrivateKey())
show("REAL TRANSACTION 4  THIEF SIGNS WITH THEIR OWN KEY: caught by OP_EQUALVERIFY", tx, prev)
