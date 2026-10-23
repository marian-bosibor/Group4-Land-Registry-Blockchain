
import pytest

from src.transactions import Transaction, TransactionInput, TransactionOutput
from src.utxo import UTXO, UTXOSet
from src.transaction_rules import validate_transaction_rules


def make_utxo_set():
    utxos = UTXOSet()
    utxos.add_utxo(UTXO("previous-tx", 0, 100, "Alice"))
    return utxos


def test_valid_transaction_passes():
    utxos = make_utxo_set()
    tx = Transaction(
        inputs=[TransactionInput("previous-tx", 0)],
        outputs=[TransactionOutput(90, "Bob")]
    )

    assert validate_transaction_rules(tx, utxos) is True


def test_transaction_without_inputs_is_rejected():
    utxos = make_utxo_set()
    tx = Transaction(outputs=[TransactionOutput(10, "Bob")])

    with pytest.raises(ValueError, match="at least one input"):
        validate_transaction_rules(tx, utxos)


def test_transaction_without_outputs_is_rejected():
    utxos = make_utxo_set()
    tx = Transaction(inputs=[TransactionInput("previous-tx", 0)])

    with pytest.raises(ValueError, match="at least one output"):
        validate_transaction_rules(tx, utxos)


def test_duplicate_inputs_are_rejected():
    utxos = make_utxo_set()
    tx = Transaction(
        inputs=[
            TransactionInput("previous-tx", 0),
            TransactionInput("previous-tx", 0)
        ],
        outputs=[TransactionOutput(50, "Bob")]
    )

    with pytest.raises(ValueError, match="duplicate input"):
        validate_transaction_rules(tx, utxos)


def test_missing_utxo_is_rejected():
    utxos = make_utxo_set()
    tx = Transaction(
        inputs=[TransactionInput("unknown-tx", 0)],
        outputs=[TransactionOutput(10, "Bob")]
    )

    with pytest.raises(ValueError, match="UTXO"):
        validate_transaction_rules(tx, utxos)


def test_outputs_cannot_exceed_inputs():
    utxos = make_utxo_set()
    tx = Transaction(
        inputs=[TransactionInput("previous-tx", 0)],
        outputs=[TransactionOutput(101, "Bob")]
    )

    with pytest.raises(ValueError, match="exceed input value"):
        validate_transaction_rules(tx, utxos)


def test_empty_output_address_is_rejected():
    utxos = make_utxo_set()
    tx = Transaction(
        inputs=[TransactionInput("previous-tx", 0)],
        outputs=[TransactionOutput(50, "   ")]
    )

    with pytest.raises(ValueError, match="address"):
        validate_transaction_rules(tx, utxos)


def test_validation_does_not_modify_utxo_set():
    utxos = make_utxo_set()
    tx = Transaction(
        inputs=[TransactionInput("previous-tx", 0)],
        outputs=[TransactionOutput(90, "Bob")]
    )

    validate_transaction_rules(tx, utxos)

    assert utxos.contains("previous-tx", 0)
    assert utxos.balance("Alice") == 100
