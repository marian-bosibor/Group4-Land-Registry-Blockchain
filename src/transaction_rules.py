
from src.transactions import Transaction
from src.utxo import UTXOSet


def validate_transaction_rules(transaction, utxo_set):
    """
    Validate a regular transaction without changing the UTXO set.

    Cryptographic signature verification is handled separately.
    """
    if not isinstance(transaction, Transaction):
        raise ValueError("A valid transaction object is required")

    if not isinstance(utxo_set, UTXOSet):
        raise ValueError("A valid UTXOSet is required")

    if not transaction.inputs:
        raise ValueError("A regular transaction must have at least one input")

    if not transaction.outputs:
        raise ValueError("A transaction must have at least one output")

    seen_inputs = set()
    input_total = 0

    for tx_input in transaction.inputs:
        key = (tx_input.previous_txid, tx_input.output_index)

        if key in seen_inputs:
            raise ValueError("Transaction contains a duplicate input")

        seen_inputs.add(key)

        utxo = utxo_set.get_utxo(
            tx_input.previous_txid,
            tx_input.output_index
        )

        if utxo is None:
            raise ValueError(
                "Referenced UTXO does not exist or has already been spent"
            )

        input_total += utxo.amount

    output_total = 0

    for output in transaction.outputs:
        if output.amount <= 0:
            raise ValueError("Transaction output amount must be positive")

        if not isinstance(output.address, str) or not output.address.strip():
            raise ValueError("Transaction output address cannot be empty")

        output_total += output.amount

    if output_total > input_total:
        raise ValueError("Transaction outputs exceed input value")

    return True
