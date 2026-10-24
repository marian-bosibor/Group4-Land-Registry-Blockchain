
from coincurve import PrivateKey

from src.script import (
    create_p2pkh_locking_script,
    create_unlocking_script,
    execute_script,
    hash160,
)


def make_message(parcel_id="LR-001", buyer="ADDR_BUYER"):
    return f"TRANSFER|{parcel_id}|{buyer}".encode("utf-8")


def make_scripts(private_key, message):
    public_key = private_key.public_key.format(compressed=True)
    signature = private_key.sign(message)
    locking_script = create_p2pkh_locking_script(hash160(public_key))
    unlocking_script = create_unlocking_script(signature, public_key)
    return unlocking_script, locking_script


def test_valid_signature_and_public_key_succeed():
    private_key = PrivateKey()
    message = make_message()
    unlocking, locking = make_scripts(private_key, message)
    assert execute_script(unlocking, locking, message) is True


def test_altered_transaction_data_fails():
    private_key = PrivateKey()
    message = make_message()
    unlocking, locking = make_scripts(private_key, message)
    altered_message = make_message(parcel_id="LR-999")
    assert execute_script(unlocking, locking, altered_message) is False


def test_wrong_public_key_fails():
    owner_key = PrivateKey()
    wrong_key = PrivateKey()
    message = make_message()
    unlocking, locking = make_scripts(owner_key, message)
    wrong_public_key = wrong_key.public_key.format(compressed=True)
    wrong_unlocking = create_unlocking_script(unlocking[0], wrong_public_key)
    assert execute_script(wrong_unlocking, locking, message) is False


def test_invalid_signature_fails():
    private_key = PrivateKey()
    message = make_message()
    unlocking, locking = make_scripts(private_key, message)
    bad_unlocking = create_unlocking_script(b"invalid signature", unlocking[1])
    assert execute_script(bad_unlocking, locking, message) is False


def test_missing_unlocking_items_fail():
    message = make_message()
    locking = create_p2pkh_locking_script(b"\x00" * 20)
    assert execute_script([], locking, message) is False
    assert execute_script([b"only one item"], locking, message) is False


def test_mismatched_public_key_hash_fails():
    private_key = PrivateKey()
    message = make_message()
    unlocking, _ = make_scripts(private_key, message)
    wrong_locking = create_p2pkh_locking_script(b"\x00" * 20)
    assert execute_script(unlocking, wrong_locking, message) is False


def test_unsupported_opcode_fails():
    private_key = PrivateKey()
    message = make_message()
    unlocking, _ = make_scripts(private_key, message)
    assert execute_script(unlocking, ["OP_UNKNOWN"], message) is False
