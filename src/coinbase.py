
import hashlib
import json

from src.transactions import Transaction, TransactionOutput
from src.utxo import UTXO, UTXOSet


class CoinbaseTransaction(Transaction):
    """
    Represents a special transaction that creates a block reward.
    Unlike a regular transaction, it has no inputs.
    """

    def __init__(self, miner_address, block_height, block_reward,
                 transaction_fees=0):
        if not isinstance(block_height, int) or isinstance(block_height, bool) or block_height < 0:
            raise ValueError("Block height must be a non-negative integer")

        if block_reward <= 0:
            raise ValueError("Block reward must be positive")

        if transaction_fees < 0:
            raise ValueError("Transaction fees cannot be negative")

        if not isinstance(miner_address, str) or not miner_address.strip():
            raise ValueError("Miner address cannot be empty")

        self.block_height = block_height
        self.block_reward = block_reward
        self.transaction_fees = transaction_fees

        total_reward = block_reward + transaction_fees

        super().__init__(
            inputs=[],
            outputs=[TransactionOutput(total_reward, miner_address)]
        )

        # Recalculate the ID including the block height.
        self.transaction_id = self.calculate_id()

    def calculate_id(self):
        """Create a deterministic ID that includes the block height."""
        data = {
            "type": "coinbase",
            "block_height": self.block_height,
            "inputs": [item.to_dict() for item in self.inputs],
            "outputs": [item.to_dict() for item in self.outputs]
        }

        canonical_data = json.dumps(
            data, sort_keys=True, separators=(",", ":")
        )

        return hashlib.sha256(canonical_data.encode()).hexdigest()

    def to_dict(self):
        data = super().to_dict()
        data["type"] = "coinbase"
        data["block_height"] = self.block_height
        data["block_reward"] = self.block_reward
        data["transaction_fees"] = self.transaction_fees
        return data


def validate_coinbase_transaction(transaction, block_reward,
                                  transaction_fees=0):
    """
    Validate a coinbase transaction without modifying the UTXO set.
    """
    if not isinstance(transaction, CoinbaseTransaction):
        raise ValueError("Transaction must be a coinbase transaction")

    if transaction.inputs:
        raise ValueError("Coinbase transactions cannot have inputs")

    if block_reward <= 0:
        raise ValueError("Block reward must be positive")

    if transaction_fees < 0:
        raise ValueError("Transaction fees cannot be negative")

    if len(transaction.outputs) != 1:
        raise ValueError("Coinbase must have exactly one output")

    output = transaction.outputs[0]

    if not isinstance(output.address, str) or not output.address.strip():
        raise ValueError("Miner address cannot be empty")

    if output.amount != block_reward + transaction_fees:
        raise ValueError("Coinbase amount exceeds or differs from the allowed reward")

    if (
        transaction.block_reward != block_reward
        or transaction.transaction_fees != transaction_fees
    ):
        raise ValueError("Coinbase reward details do not match the expected values")

    return True


def apply_coinbase_transaction(transaction, utxo_set,
                               block_reward, transaction_fees=0):
    """
    Validate a coinbase transaction and add its output to the UTXO set.
    """
    if not isinstance(utxo_set, UTXOSet):
        raise ValueError("A valid UTXOSet is required")

    validate_coinbase_transaction(
        transaction, block_reward, transaction_fees
    )

    for index, output in enumerate(transaction.outputs):
        if utxo_set.contains(transaction.transaction_id, index):
            raise ValueError("Coinbase output already exists in the UTXO set")

    for index, output in enumerate(transaction.outputs):
        utxo_set.add_utxo(
            UTXO(
                transaction.transaction_id,
                index,
                output.amount,
                output.address
            )
        )

    return True
