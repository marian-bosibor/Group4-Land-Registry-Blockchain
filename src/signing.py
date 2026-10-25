"""
signing.py - Member 4: what gets signed, and how a real Transaction meets the P2PKH scripts.

The brief says: sign a digest of the transaction's inputs and outputs WITHOUT the unlocking
data, so that changing the amount or recipient after signing makes the signature check fail.
Member 1's Transaction.calculate_id() cannot be that digest, because it includes each input's
signature and public_key (a signature cannot sign something that contains itself).

ASSUMPTION (to agree with Members 1 and 3): an output's `address` is the hash160 of the owner's
public key, written in hex (40 characters). Then the locking script is built straight from the
address. Member 1's Participant addresses are currently a SHA-256, which is NOT 20 bytes.
"""
import json

from src.script import create_p2pkh_locking_script, create_unlocking_script


def signing_digest(tx) -> bytes:
    """Canonical bytes of the inputs (reference only) and outputs. coincurve hashes these with SHA-256."""
    data = {
        "inputs": [{"previous_txid": i.previous_txid, "output_index": i.output_index} for i in tx.inputs],
        "outputs": [o.to_dict() for o in tx.outputs],
    }
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_input(tx, index, private_key):
    """Sign the transaction digest and store the signature and public key (hex) on that input."""
    tx_input = tx.inputs[index]
    tx_input.signature = private_key.sign(signing_digest(tx)).hex()
    tx_input.public_key = private_key.public_key.format(compressed=True).hex()


def unlocking_script_for(tx, index):
    """[signature, public key] taken from the input."""
    tx_input = tx.inputs[index]
    return create_unlocking_script(bytes.fromhex(tx_input.signature), bytes.fromhex(tx_input.public_key))


def locking_script_for(previous_output):
    """P2PKH lock for the output being spent (see the ASSUMPTION above)."""
    return create_p2pkh_locking_script(bytes.fromhex(previous_output.address))
