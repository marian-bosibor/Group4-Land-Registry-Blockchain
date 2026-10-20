import hashlib
import json


def hash_data(data):
    """
    Generate a SHA-256 hash for the given data.
    """
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def record_to_string(record):
    return json.dumps(
        record,
        sort_keys=True,
        separators=(",", ":")
    )


def hash_record(record):
    """
    Hash a complete land registry record.
    """
    record_string = record_to_string(record)
    return hash_data(record_string)


def hash_pair(left, right):
    """
    Combine two hashes and generate their parent hash.
    """
    return hash_data(left + right)


def build_merkle_tree(records):
    """
    Build the complete Merkle tree from land registry records.

    If a level contains an odd number of hashes,
    the last hash is duplicated.
    """

    if not records:
        raise ValueError("Cannot build a Merkle tree from empty records.")

    # Generate the leaf hashes
    current_level = [hash_record(record) for record in records]

    # Store every level of the tree
    tree_levels = [current_level]

    while len(current_level) > 1:

        # Odd-leaf rule:
        # duplicate the last hash
        if len(current_level) % 2 != 0:
            current_level = current_level + [current_level[-1]]

        next_level = []

        for i in range(0, len(current_level), 2):
            parent_hash = hash_pair(
                current_level[i],
                current_level[i + 1]
            )
            next_level.append(parent_hash)

        current_level = next_level
        tree_levels.append(current_level)

    return tree_levels


def get_merkle_root(records):
    """
    Return the Merkle Root for the given records.
    """
    tree = build_merkle_tree(records)
    return tree[-1][0]


def load_records(filename):
    """
    Load land registry records from a JSON file.
    """
    with open(filename, "r", encoding="utf-8") as file:
        return json.load(file)


if __name__ == "__main__":

    records = load_records("data/land_records.json")

    print("=== LAND REGISTRY MERKLE TREE ===")
    print()
    print(f"Number of records: {len(records)}")
    print("Hash algorithm: SHA-256")
    print("Odd-leaf rule: Duplicate the last hash")
    print()

    tree = build_merkle_tree(records)

    print("Leaf hashes:")
    for index, leaf in enumerate(tree[0], start=1):
        print(f"Record {index}: {leaf}")

    print()
    print("Merkle Root:")
    print(tree[-1][0])
