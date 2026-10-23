import unittest

from src.participants import Participant


class TestParticipant(unittest.TestCase):

    def test_participant_creation(self):
        participant = Participant(
            "LANDOWNER-001",
            "Alice",
            "landowner"
        )

        self.assertEqual(
            participant.participant_id,
            "LANDOWNER-001"
        )

        self.assertEqual(
            participant.role,
            "landowner"
        )

        self.assertIsNotNone(participant.private_key)
        self.assertIsNotNone(participant.public_key)
        self.assertIsNotNone(participant.address)

    def test_public_key_is_compressed(self):
        participant = Participant(
            "LANDOWNER-001",
            "Alice",
            "landowner"
        )

        # Compressed secp256k1 public keys are 33 bytes
        self.assertEqual(
            len(participant.public_key),
            33
        )

    def test_address_is_deterministic(self):
        participant = Participant(
            "LANDOWNER-001",
            "Alice",
            "landowner"
        )

        expected = (
            "ADDR_" +
            __import__("hashlib")
            .sha256(participant.public_key)
            .hexdigest()[:40]
        )

        self.assertEqual(
            participant.address,
            expected
        )


if __name__ == "__main__":
    unittest.main()
