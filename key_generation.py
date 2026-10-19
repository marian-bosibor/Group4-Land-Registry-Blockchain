
"""
CNS 4206 - Milestone 2
Member 1: Cryptographic Key Pair Generation
Case study: Land Title Registry and Transfer
Curve: secp256k1
Library: coincurve
"""

from coincurve import PrivateKey


def generate_key_pair(role):
    """Generate a secp256k1 private/public key pair."""
    private_key = PrivateKey()
    public_key = private_key.public_key

    print(f"\n{'=' * 50}")
    print(f"ROLE: {role}")
    print("=" * 50)

    # Demonstration only. Never expose real private keys.
    print("Private key (DEMO ONLY):")
    print(private_key.to_hex())

    print("\nPublic key:")
    print(public_key.format(compressed=True).hex())

    print("Public key length:", len(public_key.format(compressed=True)), "bytes")

    return private_key, public_key


def main():
    print("CNS 4206 - MILESTONE 2")
    print("LAND TITLE REGISTRY KEY GENERATION")
    print("Elliptic curve: secp256k1")

    registry_private, registry_public = generate_key_pair(
        "Land Registry Official"
    )
    seller_private, seller_public = generate_key_pair(
        "Landowner / Seller"
    )

    message = b"Transfer request for land parcel LR-001"

    # Sign with the seller's private key.
    signature = seller_private.sign(message)

    # Verify using the seller's public key.
    valid = seller_public.verify(signature, message)

    print("\n" + "=" * 50)
    print("DIGITAL SIGNATURE TEST")
    print("=" * 50)
    print("Message:", message.decode())
    print("Signature verified:", valid)

    altered_message = b"Transfer request for land parcel LR-999"
    altered_valid = seller_public.verify(signature, altered_message)

    print("Altered message verified:", altered_valid)
    print(
        "Participants have different public keys:",
        registry_public.format() != seller_public.format()
    )


if __name__ == "__main__":
    main()
