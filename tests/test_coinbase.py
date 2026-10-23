
import pytest

from src.coinbase import (
    CoinbaseTransaction,
    validate_coinbase_transaction,
    apply_coinbase_transaction,
)
from src.utxo import UTXOSet


def test_coinbase_has_no_inputs():
    tx = CoinbaseTransaction("miner-A", 1, 50)
    assert tx.inputs == []


def test_coinbase_includes_reward_and_fees():
    tx = CoinbaseTransaction("miner-A", 2, 50, 3)
    assert tx.outputs[0].amount == 53


def test_coinbase_validation_succeeds():
    tx = CoinbaseTransaction("miner-A", 3, 50, 2)
    assert validate_coinbase_transaction(tx, 50, 2) is True


def test_coinbase_rejects_wrong_reward():
    tx = CoinbaseTransaction("miner-A", 4, 50, 2)

    with pytest.raises(ValueError):
        validate_coinbase_transaction(tx, 50, 5)


def test_coinbase_rejects_negative_fees():
    with pytest.raises(ValueError):
        CoinbaseTransaction("miner-A", 5, 50, -1)


def test_coinbase_rejects_empty_miner_address():
    with pytest.raises(ValueError):
        CoinbaseTransaction("", 6, 50)


def test_coinbase_adds_reward_to_utxo_set():
    tx = CoinbaseTransaction("miner-A", 7, 50, 2)
    utxos = UTXOSet()

    apply_coinbase_transaction(tx, utxos, 50, 2)

    assert utxos.balance("miner-A") == 52
    assert utxos.contains(tx.transaction_id, 0)


def test_coinbase_cannot_be_applied_twice():
    tx = CoinbaseTransaction("miner-A", 8, 50)
    utxos = UTXOSet()

    apply_coinbase_transaction(tx, utxos, 50)

    with pytest.raises(ValueError):
        apply_coinbase_transaction(tx, utxos, 50)
