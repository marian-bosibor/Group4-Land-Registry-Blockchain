"""
adapter.py - connects the integration tests to the group's REAL modules.
Interface read from the repo: keys_adapter.py, certificates.py, src/merkle_tree.py.
If a teammate renames a function, this is the only file to change.
"""
import os, sys
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import keys_adapter                       # Member 1 + 2 (key pairs)
import certificates                       # Member 2 (certificates, signatures)
from src import merkle_tree               # Member 3 (tree, root)
from integration import merkle_proof      # PROVISIONAL proof functions (see merkle_proof.py)

TRUSTED_ISSUER = "MOL-CA"
DATA_FILE = os.path.join(ROOT, "data", "land_records.json")

# ---- keys -----------------------------------------------------------------
def generate_keypair(role):                      return keys_adapter.new_keypair(role)

# ---- signatures -----------------------------------------------------------
def sign(private_key_hex, message: bytes):       return certificates.sign_message(private_key_hex, message)
def verify_signature(public_key_hex, message, sig): return certificates.verify_message(public_key_hex, message, sig)

# ---- certificates (verify_* return a tuple: (ok: bool, reason: str)) -------
def issue_certificate(issuer_priv, subject_id, subject_role, subject_pub,
                      not_before="2026-01-01T00:00:00+00:00", not_after="2027-01-01T00:00:00+00:00",
                      issuer_id=TRUSTED_ISSUER, serial=1):
    return certificates.issue_certificate(issuer_id, issuer_priv, subject_id, subject_role,
                                          subject_pub, not_before, not_after, serial)
def verify_certificate(cert, issuer_pub, trusted_issuer=TRUSTED_ISSUER, now=None):
    return certificates.verify_certificate(cert, issuer_pub, trusted_issuer, now)
def verify_signed_message(cert, issuer_pub, message, sig, trusted_issuer=TRUSTED_ISSUER, now=None):
    return certificates.verify_signed_message(cert, issuer_pub, trusted_issuer, message, sig, now)

# ---- Merkle tree (records are dicts) ---------------------------------------
def load_records():                              return merkle_tree.load_records(DATA_FILE)
def merkle_root(records):                        return merkle_tree.get_merkle_root(records)
def build_tree(records):                         return merkle_tree.build_merkle_tree(records)
def get_proof(records, index):                   return merkle_proof.get_merkle_proof(records, index)
def verify_proof(record, proof, root):           return merkle_proof.verify_merkle_proof(record, proof, root)
