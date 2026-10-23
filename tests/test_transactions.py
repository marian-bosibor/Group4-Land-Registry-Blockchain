import unittest

from src.transactions import (
    Transaction,
    TransactionInput,
    TransactionOutput
)


class TestTransactions(unittest.TestCase):

    def test_transaction_output(self):
        output = TransactionOutput(
            50,
            "ADDR_ALICE"
        )

        self.assertEqual(output.amount, 50)
        self.assertEqual(output.address, "ADDR_ALICE")

    def test_transaction_input(self):
        tx_input = TransactionInput(
            "TX001",
            0
        )

        self.assertEqual(
            tx_input.previous_txid,
            "TX001"
        )

        self.assertEqual(
            tx_input.output_index,
            0
        )

    def test_transaction_creation(self):
        tx_input = TransactionInput(
            "TX001",
            0
        )

        tx_output = TransactionOutput(
            50,
            "ADDR_BOB"
        )

        transaction = Transaction(
            inputs=[tx_input],
            outputs=[tx_output]
        )

        self.assertEqual(
            len(transaction.inputs),
            1
        )

        self.assertEqual(
            len(transaction.outputs),
            1
        )

        self.assertEqual(
            len(transaction.transaction_id),
            64
        )

    def test_transaction_id_is_deterministic(self):
        tx_input = TransactionInput(
            "TX001",
            0
        )

        tx_output = TransactionOutput(
            50,
            "ADDR_BOB"
        )

        tx1 = Transaction(
            inputs=[tx_input],
            outputs=[tx_output]
        )

        tx2 = Transaction(
            inputs=[
                TransactionInput("TX001", 0)
            ],
            outputs=[
                TransactionOutput(50, "ADDR_BOB")
            ]
        )

        self.assertEqual(
            tx1.transaction_id,
            tx2.transaction_id
        )

    def test_negative_output_rejected(self):
        with self.assertRaises(ValueError):
            TransactionOutput(
                -10,
                "ADDR_BOB"
            )


if __name__ == "__main__":
    unittest.main()
