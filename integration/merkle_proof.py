"""
PROVISIONAL Merkle proof functions.

The repo's src/merkle_tree.py builds the tree and root but has NO proof generation or
verification, which the Milestone 2 brief requires. These two functions fill the gap for the
integration tests ONLY. They reuse the team's own hash_record / hash_pair / build_merkle_tree,
so they follow the same rules (SHA-256, odd leaf duplicated). Hand to Member 3/4 to adopt or
replace; if they add their own, point adapter.py at theirs.
"""
from src import merkle_tree as mt

def get_merkle_proof(records, index):
    """Return the sibling hashes from leaf to root: list of (side, hash)."""
    levels, proof, idx = mt.build_merkle_tree(records), [], index
    for level in levels[:-1]:
        if len(level) % 2:                       # same odd-leaf rule as build_merkle_tree
            level = level + [level[-1]]
        sibling = idx ^ 1
        proof.append(("right" if idx % 2 == 0 else "left", level[sibling]))
        idx //= 2
    return proof

def verify_merkle_proof(record, proof, root):
    """Recompute the root from one record plus its proof and compare with the known root."""
    current = mt.hash_record(record)
    for side, sibling in proof:
        current = mt.hash_pair(current, sibling) if side == "right" else mt.hash_pair(sibling, current)
    return current == root
