import hashlib
import json
import time

from src.coinbase import CoinbaseTransaction
from src.merkle_tree import get_merkle_root

GENESIS_PREVIOUS_HASH = "0" * 64


def sha256_hex(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def current_transaction_id(tx):
    """Freshly computed identifier (never the possibly stale stored transaction_id)."""
    return tx.calculate_id()


def is_coinbase(tx):
    return isinstance(tx, CoinbaseTransaction)


class Block:
    def __init__(self, height, previous_hash, transactions, difficulty, miner_address,
                 timestamp=None, note=""):
        self.height = height
        self.timestamp = int(time.time()) if timestamp is None else timestamp
        self.transactions = transactions          
        self.previous_hash = previous_hash
        self.difficulty = difficulty              # number of leading zeros required in the hash
        self.nonce = 0
        self.miner_address = miner_address
        self.note = note                          
        self.merkle_root = self.calculate_merkle_root()
        self.block_hash = None
        self.mining_attempts = None
        self.mining_seconds = None

    # Merkle root 
    def transaction_ids(self):
        return [current_transaction_id(tx) for tx in self.transactions]

    def calculate_merkle_root(self):
        return get_merkle_root(self.transaction_ids())

    #  block hash
    def header(self):
        return {
            "height": self.height,
            "timestamp": self.timestamp,
            "previous_hash": self.previous_hash,
            "merkle_root": self.merkle_root,
            "difficulty": self.difficulty,
            "nonce": self.nonce,
        }

    def calculate_hash(self):
        return sha256_hex(json.dumps(self.header(), sort_keys=True, separators=(",", ":")))

    #  proof of work
    def mine(self, verbose=True):
        """Nonce starts at 0 and increases until the hash begins with `difficulty` zeros."""
        target = "0" * self.difficulty
        self.merkle_root = self.calculate_merkle_root()
        self.nonce = 0
        attempts = 0
        started = time.time()
        while True:
            candidate = self.calculate_hash()
            attempts += 1
            if candidate.startswith(target):
                break
            self.nonce += 1
        self.block_hash = candidate
        self.mining_attempts = attempts
        self.mining_seconds = time.time() - started
        if verbose:
            print(f"  Mined block {self.height}: difficulty={self.difficulty}, nonce={self.nonce}, "
                  f"attempts={attempts}, time={self.mining_seconds:.3f}s")
            print(f"  Hash: {self.block_hash}")
        return self.block_hash

    #  single-block validation
    def validate(self):
     
        problems = []
        if not self.transactions:
            return False, ["block has no transactions"]
        if self.merkle_root != self.calculate_merkle_root():
            problems.append("stored Merkle root does not match the transactions actually present")
        if self.block_hash != self.calculate_hash():
            problems.append("stored hash does not match the recomputed header hash")
        if not (self.block_hash or "").startswith("0" * self.difficulty):
            problems.append("hash does not meet the difficulty")
        if not is_coinbase(self.transactions[0]):
            problems.append("first transaction is not a coinbase")
        if any(is_coinbase(tx) for tx in self.transactions[1:]):
            problems.append("a coinbase transaction appears after the first position")
        return (len(problems) == 0), problems

    def summary(self):
        return (f"Block {self.height} | txs={len(self.transactions)} | nonce={self.nonce} | "
                f"hash={self.block_hash[:16]}... | prev={self.previous_hash[:16]}...")


def create_genesis_block(genesis_coinbase, difficulty, miner_address, timestamp=None, note=""):
  
    block = Block(0, GENESIS_PREVIOUS_HASH, [genesis_coinbase], difficulty, miner_address,
                  timestamp=timestamp, note=note)
    block.mine()
    return block


def create_next_block(previous_block, transactions, difficulty, miner_address, timestamp=None, note=""):
    block = Block(previous_block.height + 1, previous_block.block_hash, transactions,
                  difficulty, miner_address, timestamp=timestamp, note=note)
    block.mine()
    return block


def average_attempts(difficulty, runs=10):
    results = []
    for run in range(runs):
        cb = CoinbaseTransaction("TEST-MINER", run, 50)
        b = Block(run + 1, sha256_hex(f"run-{difficulty}-{run}"), [cb], difficulty,
                  "TEST-MINER", timestamp=run)
        b.mine(verbose=False)
        results.append(b.mining_attempts)
    return sum(results) / len(results), results