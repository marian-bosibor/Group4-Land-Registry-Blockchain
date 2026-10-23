import unittest

from src.transactions import (
    Transaction,
    TransactionInput,
    TransactionOutput
)

from src.utxo import UTXO, UTXOSet


class TestUTXO(unittest.TestCase):

    def test_add_and_get_utxo(self):
        utxo_set = UTXOSet()

        utxo = UTXO(
            "TX001",
            0,
            50,
            "ADDR_ALICE"
        )

        utxo_set.add_utxo(utxo)

        self.assertTrue(
            utxo_set.contains("TX001", 0)
        )

        retrieved = utxo_set.get_utxo(
            "TX001",
            0
        )

        self.assertEqual(
            retrieved.amount,
            50
        )

    def test_spend_utxo(self):
        utxo_set = UTXOSet()

        utxo = UTXO(
            "TX001",
            0,
            50,
            "ADDR_ALICE"
        )

        utxo_set.add_utxo(utxo)

        spent = utxo_set.spend_utxo(
            "TX001",
            0
        )

        self.assertEqual(
            spent.amount,
            50
        )

        self.assertFalse(
            utxo_set.contains("TX001", 0)
        )

    def test_successful_transaction_updates_utxos(self):
        utxo_set = UTXOSet()

        # Alice initially owns 50.
        initial_utxo = UTXO(
            "TX001",
            0,
            50,
            "ADDR_ALICE"
        )

        utxo_set.add_utxo(initial_utxo)

        # Alice sends 20 to Bob and receives 30 as change.
        transaction = Transaction(
            inputs=[
                TransactionInput(
                    "TX001",
                    0
                )
            ],
            outputs=[
                TransactionOutput(
                    20,
                    "ADDR_BOB"
                ),
                TransactionOutput(
                    30,
                    "ADDR_ALICE"
                )
            ]
        )

        utxo_set.add_transaction(transaction)

        # Original UTXO has been consumed.
        self.assertFalse(
            utxo_set.contains("TX001", 0)
        )

        # New outputs exist.
        self.assertEqual(
            utxo_set.balance("ADDR_BOB"),
            20
        )

        self.assertEqual(
            utxo_set.balance("ADDR_ALICE"),
            30
        )

    def test_nonexistent_utxo_rejected(self):
        utxo_set = UTXOSet()

        transaction = Transaction(
            inputs=[
                TransactionInput(
                    "DOES_NOT_EXIST",
                    0
                )
            ],
            outputs=[
                TransactionOutput(
                    10,
                    "ADDR_BOB"
                )
            ]
        )

        with self.assertRaises(ValueError):
            utxo_set.add_transaction(transaction)

    def test_double_spend_rejected(self):
        utxo_set = UTXOSet()

        initial_utxo = UTXO(
            "TX001",
            0,
            50,
            "ADDR_ALICE"
        )

        utxo_set.add_utxo(initial_utxo)

        transaction = Transaction(
            inputs=[
                TransactionInput(
                    "TX001",
                    0
                )
            ],
            outputs=[
                TransactionOutput(
                    50,
                    "ADDR_BOB"
                )
            ]
        )

        # First spend succeeds.
        utxo_set.add_transaction(transaction)

        # Attempting to spend TX001:0 again must fail.
        second_transaction = Transaction(
            inputs=[
                TransactionInput(
                    "TX001",
                    0
                )
            ],
            outputs=[
                TransactionOutput(
                    50,
                    "ADDR_CHARLIE"
                )
            ]
        )

        with self.assertRaises(ValueError):
            utxo_set.add_transaction(second_transaction)

    def test_outputs_cannot_exceed_inputs(self):
        utxo_set = UTXOSet()

        initial_utxo = UTXO(
            "TX001",
            0,
            50,
            "ADDR_ALICE"
        )

        utxo_set.add_utxo(initial_utxo)

        transaction = Transaction(
            inputs=[
                TransactionInput(
                    "TX001",
                    0
                )
            ],
            outputs=[
                TransactionOutput(
                    60,
                    "ADDR_BOB"
                )
            ]
        )

        with self.assertRaises(ValueError):
            utxo_set.add_transaction(transaction)


if __name__ == "__main__":
    unittest.main()
