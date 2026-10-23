import hashlib
from coincurve import PrivateKey


class Participant:
    """
    Represents a participant in the blockchain system.

    A participant has:
    - an identifier
    - a name
    - a role
    - a private key
    - a public key
    - a blockchain address
    """

    def __init__(self, participant_id, name, role):
        self.participant_id = participant_id
        self.name = name
        self.role = role

        # Generate a secp256k1 private key
        self.private_key = PrivateKey()

        # Obtain the compressed public key
        self.public_key = self.private_key.public_key.format(
            compressed=True
        )

        # Generate the participant address
        self.address = self.generate_address()

    def generate_address(self):
        """
        Generate an address from the participant's
        compressed public key.
        """
        public_key_hash = hashlib.sha256(
            self.public_key
        ).hexdigest()

        return "ADDR_" + public_key_hash[:40]

    def get_public_key_hex(self):
        """
        Return the compressed public key as hexadecimal.
        """
        return self.public_key.hex()

    def __repr__(self):
        return (
            f"Participant("
            f"id={self.participant_id}, "
            f"name={self.name}, "
            f"role={self.role}, "
            f"address={self.address})"
        )
