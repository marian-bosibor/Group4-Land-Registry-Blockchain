"""
Milestone 3 - Member 4: script validation and failure cases.

Every case is a row in CASES: a name, the scripts, the message that was signed, and what we EXPECT
(valid or not, and which opcode should reject it). Two checks run on every row:
  1. the tracer's verdict and failing opcode match the expectation, and
  2. Member 3's real execute_script() gives the same True/False as the tracer.

Run:  python -m pytest tests/test_script_validation.py -v
"""
import pytest
from coincurve import PrivateKey

from src.script import (create_p2pkh_locking_script, create_unlocking_script,
                        execute_script, hash160)
from src.script_trace import trace_script

MESSAGE = b"TRANSFER|LR-001|ADDR_BUYER"          # stands in for the transaction digest


def keys():
    """A fresh demo key pair: (private key object, compressed public key bytes)."""
    private = PrivateKey()
    return private, private.public_key.format(compressed=True)


def good_scripts(private, public, message=MESSAGE):
    """A correct P2PKH lock and unlock for this key and message."""
    lock = create_p2pkh_locking_script(hash160(public))
    unlock = create_unlocking_script(private.sign(message), public)
    return unlock, lock


# ---- cases already written for you ----------------------------------------------------------
def case_valid_spend():
    private, public = keys()
    unlock, lock = good_scripts(private, public)
    return unlock, lock, MESSAGE


def case_wrong_public_key():
    """A thief signs the transaction with THEIR OWN key and presents THEIR public key.
    The signature is genuinely valid for that key, so only the hash check in OP_EQUALVERIFY
    stands between the thief and the owner's land."""
    _, owner_pub = keys()
    thief, thief_pub = keys()
    lock = create_p2pkh_locking_script(hash160(owner_pub))          # locked to the OWNER
    return create_unlocking_script(thief.sign(MESSAGE), thief_pub), lock, MESSAGE


def case_altered_transaction():
    """Signed for one message, then the message changes (e.g. amount or recipient altered)."""
    private, public = keys()
    unlock, lock = good_scripts(private, public)
    return unlock, lock, b"TRANSFER|LR-999|ADDR_BUYER"


def case_malformed_signature():
    """The signature is not even valid DER, so the library raises instead of returning False."""
    private, public = keys()
    unlock, lock = good_scripts(private, public)
    return create_unlocking_script(b"invalid signature", public), lock, MESSAGE

# ---- YOUR CASES (5-8) ------------------------------------------------------------------
def case_signature_from_other_key():
    """Well-formed signature from a DIFFERENT key, but the owner's public key is supplied.
    The hash check passes (it is the owner's key); the signature does not verify against it."""
    owner, owner_pub = keys()
    other, _ = keys()
    lock = create_p2pkh_locking_script(hash160(owner_pub))
    return create_unlocking_script(other.sign(MESSAGE), owner_pub), lock, MESSAGE


def case_missing_signature():
    """Unlocking script holds only the public key. Hash check passes; CHECKSIG finds too few items."""
    private, public = keys()
    _, lock = good_scripts(private, public)
    return [public], lock, MESSAGE


def case_extra_junk_item():
    """[junk, signature, publicKey]: everything verifies, but an extra item is left behind."""
    private, public = keys()
    unlock, lock = good_scripts(private, public)
    return [b"junk"] + unlock, lock, MESSAGE


def case_empty_unlocking_script():
    """Nothing pushed: the first opcode that needs an item (OP_DUP) finds an empty stack."""
    private, public = keys()
    _, lock = good_scripts(private, public)
    return [], lock, MESSAGE

# ---- the table: (name, builder, expected valid?, expected failing opcode) -----------------------

CASES = [
    ("valid spend",                       case_valid_spend,         True,  None),
    ("wrong public key",                  case_wrong_public_key,    False, "OP_EQUALVERIFY"),
    ("altered transaction",               case_altered_transaction, False, "OP_CHECKSIG"),
    ("malformed signature",               case_malformed_signature, False, "OP_CHECKSIG"),
    ("signature from other key",          case_signature_from_other_key, False, "OP_CHECKSIG"),
    ("missing signature",                 case_missing_signature,   False, "OP_CHECKSIG"),
    ("extra junk item",                   case_extra_junk_item,     False, "FINAL_CHECK"),
    ("empty unlocking script",            case_empty_unlocking_script, False, "OP_DUP"),

    # ---- YOUR CASES: write a builder function above for each, then add its row here ---------------
    # 5. Well-formed signature made by a DIFFERENT key, but the correct public key is supplied.
    #    Hint: private.sign(...) with another key, then pair it with the owner's public key.
    # 6. Missing signature: unlocking script holds only the public key (hash still correct).
    #    Hint: trace it by hand first. Which opcode finds the stack too short?
    # 7. Extra junk item left on the stack: unlocking script [junk, signature, publicKey].
    #    Hint: everything verifies, so what rule rejects it at the very end?
    # 8. Empty unlocking script: [].
    #    Hint: which is the very first opcode that needs something on the stack?
]


@pytest.mark.parametrize("name,builder,expect_ok,expect_failed_at", CASES, ids=[c[0] for c in CASES])
def test_case(name, builder, expect_ok, expect_failed_at):
    unlock, lock, message = builder()
    result = trace_script(unlock, lock, message)
    assert result["ok"] is expect_ok
    assert result["failed_at"] == expect_failed_at


@pytest.mark.parametrize("name,builder,expect_ok,expect_failed_at", CASES, ids=[c[0] for c in CASES])
def test_tracer_agrees_with_real_interpreter(name, builder, expect_ok, expect_failed_at):
    """If this ever fails, my tracer and Member 3's execute_script have drifted apart."""
    unlock, lock, message = builder()
    assert trace_script(unlock, lock, message)["ok"] is execute_script(unlock, lock, message)


def test_success_comes_first():
    """Guard against vacuous passing: if the valid spend were broken, every failure test would pass for the wrong reason."""
    unlock, lock, message = case_valid_spend()
    assert execute_script(unlock, lock, message) is True
