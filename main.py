
import copy
import json

from crypto_utils import (
    generate_key_pair,
    private_key_to_pem,
    public_key_to_pem,
    key_identifier,
)
from certificates import issue_certificate, verify_certificate
from merkle_tree import (
    build_merkle_tree,
    merkle_root,
    generate_merkle_proof,
    verify_merkle_proof,
)


def main():
    print("=" * 65)
    print("GROUP 4: LAND TITLE REGISTRY - MILESTONE 2")
    print("DEMONSTRATION KEYS ONLY; NO REAL LANDOWNER DATA")
    print("=" * 65)

    # COMPONENT 1: Generate separate keys for two roles.
    authority_private, authority_public = generate_key_pair()
    owner_private, owner_public = generate_key_pair()

    authority_id = "LAND_REGISTRY_AUTHORITY"
    owner_id = "LANDOWNER_001"

    print("\nCOMPONENT 1: KEY GENERATION")

    for role, private_key, public_key in [
        (authority_id, authority_private, authority_public),
        (owner_id, owner_private, owner_public),
    ]:
        print(f"\nRole: {role}")
        print("Private key (DEMONSTRATION ONLY):")
        print(private_key_to_pem(private_key))
        print("Public key:")
        print(public_key_to_pem(public_key))
        print("Derived key identifier:")
        print(key_identifier(public_key))

    # COMPONENT 2: Issue and verify a signed certificate.
    print("\nCOMPONENT 2: CERTIFICATES")

    certificate = issue_certificate(
        subject_identifier=owner_id,
        subject_public_key=owner_public,
        issuer_identifier=authority_id,
        issuer_private_key=authority_private,
    )

    print("\nIssued certificate:")
    print(json.dumps(certificate, indent=2))

    valid_result = verify_certificate(
        certificate,
        authority_public,
        authority_id,
    )
    print("\nOriginal certificate verifies:", valid_result)

    tampered_certificate = copy.deepcopy(certificate)
    tampered_certificate["subject_identifier"] = "LANDOWNER_999"

    tampered_result = verify_certificate(
        tampered_certificate,
        authority_public,
        authority_id,
    )
    print("Tampered certificate verifies:", tampered_result)

    # COMPONENT 3: Nine fictional registry events.
    print("\nCOMPONENT 3: MERKLE TREE")

    records = [
        {
            "event_id": "EVT-001",
            "parcel_id": "LR-001",
            "event_type": "initial_registration",
            "record_version": 1,
        },
        {
            "event_id": "EVT-002",
            "parcel_id": "LR-002",
            "event_type": "initial_registration",
            "record_version": 1,
        },
        {
            "event_id": "EVT-003",
            "parcel_id": "LR-001",
            "event_type": "ownership_transfer",
            "record_version": 2,
        },
        {
            "event_id": "EVT-004",
            "parcel_id": "LR-003",
            "event_type": "caveat_registered",
            "record_version": 1,
        },
        {
            "event_id": "EVT-005",
            "parcel_id": "LR-002",
            "event_type": "ownership_transfer",
            "record_version": 2,
        },
        {
            "event_id": "EVT-006",
            "parcel_id": "LR-004",
            "event_type": "survey_document_updated",
            "record_version": 2,
        },
        {
            "event_id": "EVT-007",
            "parcel_id": "LR-001",
            "event_type": "encumbrance_registered",
            "record_version": 3,
        },
        {
            "event_id": "EVT-008",
            "parcel_id": "LR-005",
            "event_type": "initial_registration",
            "record_version": 1,
        },
        {
            "event_id": "EVT-009",
            "parcel_id": "LR-003",
            "event_type": "caveat_updated",
            "record_version": 2,
        },
    ]

    levels = build_merkle_tree(records)
    root = merkle_root(levels)

    print("Number of records:", len(records))
    print("Number of tree levels:", len(levels))
    print("Number of leaves:", len(levels[0]))
    print("Merkle root:", root)

    selected_index = 2
    selected_record = records[selected_index]
    proof = generate_merkle_proof(levels, selected_index)

    print("\nSelected record:")
    print(json.dumps(selected_record, indent=2))
    print("Merkle proof:")
    print(json.dumps(proof, indent=2))
    print("Proof size (sibling hashes):", len(proof))

    valid_proof = verify_merkle_proof(
        selected_record, proof, root
    )
    print("Original record proof verifies:", valid_proof)

    altered_record = copy.deepcopy(selected_record)
    altered_record["event_type"] = "fraudulent_transfer"

    altered_proof = verify_merkle_proof(
        altered_record, proof, root
    )
    print("Altered record proof verifies:", altered_proof)


if __name__ == "__main__":
    main()