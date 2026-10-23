import hashlib
import json


class TransactionInput:
    """
    References an existing transaction output that is being spent.
    """

    def __init__(
        self,
        previous_txid,
        output_index,
        signature=None,
        public_key=None
    ):
        self.previous_txid = previous_txid
        self.output_index = output_index
        self.signature = signature
        self.public_key = public_key

    def to_dict(self):
        return {
            "previous_txid": self.previous_txid,
            "output_index": self.output_index,
            "signature": self.signature,
            "public_key": self.public_key
        }


class TransactionOutput:
    """
    Represents a new spendable output.
    """

    def __init__(self, amount, address):
        if amount <= 0:
            raise ValueError("Transaction output amount must be positive")

        self.amount = amount
        self.address = address

    def to_dict(self):
        return {
            "amount": self.amount,
            "address": self.address
        }


class Transaction:
    """
    Represents a blockchain transaction.
    """

    def __init__(self, inputs=None, outputs=None):
        self.inputs = inputs or []
        self.outputs = outputs or []

        self.transaction_id = self.calculate_id()

    def calculate_id(self):
        """
        Calculate a deterministic transaction ID from
        the transaction contents.
        """

        data = {
            "inputs": [
                tx_input.to_dict()
                for tx_input in self.inputs
            ],
            "outputs": [
                tx_output.to_dict()
                for tx_output in self.outputs
            ]
        }

        canonical_data = json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":")
        )

        return hashlib.sha256(
            canonical_data.encode()
        ).hexdigest()

    def to_dict(self):
        return {
            "transaction_id": self.transaction_id,
            "inputs": [
                tx_input.to_dict()
                for tx_input in self.inputs
            ],
            "outputs": [
                tx_output.to_dict()
                for tx_output in self.outputs
            ]
        }
