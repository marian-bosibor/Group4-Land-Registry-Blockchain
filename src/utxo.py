class UTXO:
    """
    Represents one unspent transaction output.
    """

    def __init__(self, txid, output_index, amount, address):
        self.txid = txid
        self.output_index = output_index
        self.amount = amount
        self.address = address

    def key(self):
        """
        Unique identifier for this UTXO.
        """
        return (self.txid, self.output_index)

    def to_dict(self):
        return {
            "txid": self.txid,
            "output_index": self.output_index,
            "amount": self.amount,
            "address": self.address
        }


class UTXOSet:
    """
    Maintains the current set of unspent transaction outputs.
    """

    def __init__(self):
        self.utxos = {}

    def add_utxo(self, utxo):
        """
        Add a new UTXO to the set.
        """
        self.utxos[utxo.key()] = utxo

    def get_utxo(self, txid, output_index):
        """
        Retrieve a UTXO using its transaction ID and output index.
        """
        return self.utxos.get((txid, output_index))

    def contains(self, txid, output_index):
        """
        Check whether a UTXO exists and remains unspent.
        """
        return (txid, output_index) in self.utxos

    def spend_utxo(self, txid, output_index):
        """
        Remove a UTXO from the set when it is spent.

        Raises:
            ValueError: if the UTXO does not exist.
        """
        key = (txid, output_index)

        if key not in self.utxos:
            raise ValueError("UTXO does not exist or has already been spent")

        return self.utxos.pop(key)

    def add_transaction(self, transaction):
        """
        Apply a regular transaction to the UTXO set.

        Existing input UTXOs are consumed and new transaction
        outputs are added as UTXOs.

        The transaction must:
        - reference existing UTXOs
        - not spend the same UTXO twice
        - not create more value than it consumes
        """

        if not transaction.inputs:
            raise ValueError(
                "A regular transaction must have at least one input"
            )

        # Check all inputs before modifying the UTXO set.
        input_utxos = []
        seen_inputs = set()

        for tx_input in transaction.inputs:
            key = (
                tx_input.previous_txid,
                tx_input.output_index
            )

            # Detect duplicate inputs inside the same transaction.
            if key in seen_inputs:
                raise ValueError(
                    "Transaction contains a duplicate input"
                )

            seen_inputs.add(key)

            utxo = self.get_utxo(
                tx_input.previous_txid,
                tx_input.output_index
            )

            if utxo is None:
                raise ValueError(
                    "Referenced UTXO does not exist or "
                    "has already been spent"
                )

            input_utxos.append(utxo)

        input_amount = sum(
            utxo.amount for utxo in input_utxos
        )

        output_amount = sum(
            output.amount
            for output in transaction.outputs
        )

        if output_amount > input_amount:
            raise ValueError(
                "Transaction outputs exceed input value"
            )

        # Consume the input UTXOs.
        for utxo in input_utxos:
            self.spend_utxo(
                utxo.txid,
                utxo.output_index
            )

        # Add the new outputs as UTXOs.
        for index, output in enumerate(transaction.outputs):
            new_utxo = UTXO(
                transaction.transaction_id,
                index,
                output.amount,
                output.address
            )

            self.add_utxo(new_utxo)

    def balance(self, address):
        """
        Calculate the total unspent value belonging to an address.
        """
        return sum(
            utxo.amount
            for utxo in self.utxos.values()
            if utxo.address == address
        )

    def all_utxos(self):
        """
        Return all current UTXOs.
        """
        return list(self.utxos.values())
