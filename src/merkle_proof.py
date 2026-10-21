"""
Member 4: Merkle proof generation and verification.

Uses Member 3's functions from src/merkle_tree.py. It does NOT build its own tree,
so proofs always match the roots produced by Member 3's code.

Run from the project root:   py -m src.merkle_proof
"""
import math

from src.merkle_tree import (
    hash_record,
    hash_pair,
    build_merkle_tree,
    get_merkle_root,
    load_records,
)


def generate_merkle_proof(tree_levels, leaf_index):
    
    if not 0 <= leaf_index < len(tree_levels[0]):
        raise IndexError("leaf_index is out of range")

    proof = []
    index = leaf_index
    for level in tree_levels[:-1]:            
        if index % 2 == 0:                    
            if index + 1 < len(level):
                sibling = level[index + 1]
            else:
                sibling = level[index]        
            proof.append({"hash": sibling, "position": "right"})
        else:                                 
            proof.append({"hash": level[index - 1], "position": "left"})
        index //= 2
    return proof


def verify_merkle_proof(record, proof, expected_root):
    current = hash_record(record)
    for step in proof:
        if step["position"] == "left":
            current = hash_pair(step["hash"], current)
        else:
            current = hash_pair(current, step["hash"])
    return current == expected_root


def proof_size(proof):
    return len(proof), len(proof) * 32


def _print_proof(proof):
    for number, step in enumerate(proof, start=1):
        print(f"  Step {number}: sibling on the {step['position']:<5} -> {step['hash']}")


if __name__ == "__main__":
    records = load_records("data/land_records.json")
    tree = build_merkle_tree(records)
    root = get_merkle_root(records)

    print("=== MERKLE PROOF DEMONSTRATION ===")
    print(f"Number of records: {len(records)}")
    print(f"Merkle root: {root}")

    # 1. Valid record
    index = 2
    proof = generate_merkle_proof(tree, index)
    print(f"\n[1] VALID RECORD (record {index + 1}: {records[index]['parcel_id']})")
    print("Record:", records[index])
    _print_proof(proof)
    hashes, size_bytes = proof_size(proof)
    print(f"Proof size: {hashes} hashes = {size_bytes} bytes")
    print("Verification result:", verify_merkle_proof(records[index], proof, root))

    # 2. Altered record
    altered = dict(records[index])
    if "new_owner" in altered:
        altered["new_owner"] = "OWNER-FRAUDSTER"
    else:
        altered["owner"] = "OWNER-FRAUDSTER"
    print("\n[2] ALTERED RECORD (same proof, owner changed)")
    print("Altered record:", altered)
    print("Verification result:", verify_merkle_proof(altered, proof, root), "(expected False)")

    # 3. Tampered proof
    bad_proof = [dict(step) for step in proof]
    bad_proof[0]["hash"] = "0" * 64
    print("\n[3] TAMPERED PROOF")
    print("Verification result:", verify_merkle_proof(records[index], bad_proof, root), "(expected False)")

    # 4. Wrong root
    print("\n[4] WRONG ROOT")
    print("Verification result:", verify_merkle_proof(records[index], proof, "f" * 64), "(expected False)")

    # 5. Every record verifies
    all_ok = all(
        verify_merkle_proof(records[i], generate_merkle_proof(tree, i), root)
        for i in range(len(records))
    )
    print(f"\n[5] ALL {len(records)} RECORDS VERIFY:", all_ok)

    # 6. Proof size growth
    print("\n[6] PROOF SIZE GROWTH (hashes = ceil(log2 n))")
    print(f"{'Records':>10} {'Hashes':>8} {'Bytes':>8} {'ceil(log2 n)':>14}")
    for n in [8, 16, 100, 1000, 10000, 100000]:
        sample = [{"parcel_id": f"P-{i}", "transaction": "TEST"} for i in range(n)]
        levels = build_merkle_tree(sample)
        h, b = proof_size(generate_merkle_proof(levels, n - 1))
        print(f"{n:>10} {h:>8} {b:>8} {math.ceil(math.log2(n)):>14}")