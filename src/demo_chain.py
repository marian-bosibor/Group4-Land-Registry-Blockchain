import hashlib

from coincurve import PrivateKey

from src.block import create_genesis_block, create_next_block, average_attempts
from src.coinbase import CoinbaseTransaction, apply_coinbase_transaction
from src.script import hash160, execute_script
from src.signing import signing_digest, sign_input, unlocking_script_for, locking_script_for
from src.transaction_rules import validate_transaction_rules
from src.transactions import Transaction, TransactionInput, TransactionOutput
from src.utxo import UTXOSet

DIFFICULTY = 3
BLOCK_REWARD = 50
BASE_TIME = 1_700_000_000          


def make_party(name):
    private_key = PrivateKey(hashlib.sha256(f"demo-key-{name}".encode()).digest())
    public_key = private_key.public_key.format(compressed=True)
    return {"name": name, "private_key": private_key, "public_key": public_key,
            "address": hash160(public_key).hex()}


def build_demo_chain(difficulty=DIFFICULTY, verbose=True):
    seller, buyer = make_party("seller"), make_party("buyer")
    miner_a, miner_b = make_party("miner-a"), make_party("miner-b")
    parties = {"seller": seller, "buyer": buyer, "miner_a": miner_a, "miner_b": miner_b}
    utxo = UTXOSet()
    chain = []

    def log(text=""):
        if verbose:
            print(text)

    log("Genesis block: coinbase-like allocation of the Seller's initial output")
    cb0 = CoinbaseTransaction(seller["address"], 0, BLOCK_REWARD)
    apply_coinbase_transaction(cb0, utxo, BLOCK_REWARD, 0)
    chain.append(create_genesis_block(
        cb0, difficulty, seller["address"], timestamp=BASE_TIME,
        note="Genesis: the registry begins; the Seller's initial output stands for a title already held"))

    log("\nBlock 1 (coinbase only):")
    cb1 = CoinbaseTransaction(miner_a["address"], 1, BLOCK_REWARD)
    apply_coinbase_transaction(cb1, utxo, BLOCK_REWARD, 0)
    chain.append(create_next_block(chain[-1], [cb1], difficulty, miner_a["address"],
                                   timestamp=BASE_TIME + 600))

    log("\nBlock 2 (coinbase + Seller -> Buyer land-title transfer):")
    previous = utxo.get_utxo(cb0.transaction_id, 0)           # Seller's output from block 0
    tx = Transaction(inputs=[TransactionInput(cb0.transaction_id, 0)],
                     outputs=[TransactionOutput(previous.amount - 1, buyer["address"])])   
    validate_transaction_rules(tx, utxo)
    sign_input(tx, 0, seller["private_key"])
    ok = execute_script(unlocking_script_for(tx, 0), locking_script_for(previous), signing_digest(tx))
    log(f"  P2PKH script check for the transfer: {ok}")
    if not ok:
        raise RuntimeError("the transfer does not satisfy its locking script")
    tx.transaction_id = tx.calculate_id()      
    fee = previous.amount - sum(o.amount for o in tx.outputs)
    utxo.add_transaction(tx)
    cb2 = CoinbaseTransaction(miner_b["address"], 2, BLOCK_REWARD, fee)
    apply_coinbase_transaction(cb2, utxo, BLOCK_REWARD, fee)
    chain.append(create_next_block(chain[-1], [cb2, tx], difficulty, miner_b["address"],
                                   timestamp=BASE_TIME + 1200))

    log("\nBlock 3 (coinbase only):")
    cb3 = CoinbaseTransaction(miner_a["address"], 3, BLOCK_REWARD)
    apply_coinbase_transaction(cb3, utxo, BLOCK_REWARD, 0)
    chain.append(create_next_block(chain[-1], [cb3], difficulty, miner_a["address"],
                                   timestamp=BASE_TIME + 1800))
    return chain, utxo, parties, tx


if __name__ == "__main__":
    print(f"=== MINING A FOUR-BLOCK CHAIN (difficulty = {DIFFICULTY}) ===\n")
    chain, utxo, parties, transfer = build_demo_chain()

    print("\n=== CHAIN OVERVIEW ===")
    for b in chain:
        print(b.summary())
        print(f"   merkle_root = {b.merkle_root}")
        for position, tx_id in enumerate(b.transaction_ids()):
            kind = "coinbase" if position == 0 else "transfer"
            print(f"   tx[{position}] {kind:<8} {tx_id}")

    print("\n=== LINK CHECK ===")
    for prev, cur in zip(chain, chain[1:]):
        print(f"Block {cur.height}.previous_hash == Block {prev.height}.block_hash:",
              cur.previous_hash == prev.block_hash)

    print("\n=== SINGLE-BLOCK VALIDATION ===")
    for b in chain:
        print(f"Block {b.height}:", b.validate())

    print("\n=== BALANCES AFTER THE CHAIN ===")
    for key in ("seller", "buyer", "miner_a", "miner_b"):
        print(f"{key:<8} {utxo.balance(parties[key]['address'])}")

    print("\n=== MINING DIFFICULTY TABLE (average of 10 runs) ===")
    print(f"{'Difficulty':>10} {'Avg attempts':>14} {'Expected 16^d':>15}")
    for d in [1, 2, 3, 4]:
        avg, _ = average_attempts(d, runs=10)
        print(f"{d:>10} {avg:>14.0f} {16 ** d:>15}")