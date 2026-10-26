"""
validate_chain(chain) walks the chain from genesis, REBUILDING the unspent-output set as it goes
(it never trusts the UTXO set kept by whoever built the chain), and records every check as
pass/fail instead of stopping at the first problem.

PER BLOCK
    merkle_root        stored Merkle root == root recomputed from the transactions actually present
    block_hash         stored hash == fresh SHA-256 of the header
    difficulty         hash has the required leading zeros AND difficulty >= network minimum
    height             block height == its position in the chain
    previous_hash      equals the hash of the block before it (placeholder for genesis)
    coinbase_position  the first transaction is a coinbase and no other transaction is
PER ORDINARY TRANSACTION
    txid               stored transaction_id == SHA-256 of the transaction's current contents
    inputs_unspent     every input refers to an earlier output that is still unspent (no duplicates)
    scripts            unlocking script, then locking script (taken from the output being spent,
                       never from the spending transaction), succeed - traced by src.script_trace
    value_balance      outputs positive and inputs >= outputs (the difference is the fee)
COINBASE
    txid, coinbase_height, coinbase_miner, coinbase_amount (<= block reward + fees collected)

A transaction that fails any of its checks is NOT applied to the rebuilt UTXO set, as a node would
reject it. "first_failure" is the earliest failed check in the order above.

"""
from dataclasses import dataclass

from src.block import GENESIS_PREVIOUS_HASH, is_coinbase
from src.script_trace import trace_script
from src.signing import locking_script_for, signing_digest, unlocking_script_for
from src.transaction_rules import validate_transaction_rules
from src.utxo import UTXO, UTXOSet

DEFAULT_BLOCK_REWARD = 50  # same constant as src.demo_chain.BLOCK_REWARD

# validate_transaction_rules() raises ValueError with these messages; map them to our check names.
_INPUT_PROBLEMS = ("at least one input", "duplicate input", "does not exist or has already been spent")


@dataclass
class Check:
    block: int
    name: str
    ok: bool
    detail: str


@dataclass
class ValidationResult:
    checks: list

    @property
    def failures(self):
        return [c for c in self.checks if not c.ok]

    @property
    def valid(self):
        return not self.failures

    @property
    def first_failure(self):
        return self.failures[0] if self.failures else None


def _short(x, n=16):
    return str(x or "")[:n] + ".."


def validate_chain(chain, block_reward=DEFAULT_BLOCK_REWARD, min_difficulty=1) -> ValidationResult:
    checks = []
    utxo = UTXOSet()

    def add(i, name, ok, detail):
        checks.append(Check(i, name, bool(ok), detail))

    for i, b in enumerate(chain):
        # ---- block-level checks --------------------------------------------------------
        try:
            root = b.calculate_merkle_root()
        except ValueError:  # a block with no transactions cannot have a Merkle root
            root = None
        add(i, "merkle_root", root is not None and root == b.merkle_root,
            f"stored {_short(b.merkle_root)} vs recomputed {_short(root) if root else 'n/a (block has no transactions)'}")

        recomputed = b.calculate_hash()
        add(i, "block_hash", recomputed == b.block_hash,
            f"stored {_short(b.block_hash)} vs recomputed {_short(recomputed)}")

        meets = (b.block_hash or "").startswith("0" * b.difficulty) and b.difficulty >= min_difficulty
        add(i, "difficulty", meets,
            f"hash {_short(b.block_hash, 10)} needs {b.difficulty} leading zeros (network minimum {min_difficulty})")

        add(i, "height", b.height == i, f"height {b.height}, position {i}")

        expected_prev = GENESIS_PREVIOUS_HASH if i == 0 else chain[i - 1].block_hash
        add(i, "previous_hash", b.previous_hash == expected_prev,
            f"stored {_short(b.previous_hash)} vs expected {_short(expected_prev)}")

        txs = b.transactions
        first_is_cb = bool(txs) and is_coinbase(txs[0])
        extra_cb = [j for j, t in enumerate(txs) if j > 0 and is_coinbase(t)]
        add(i, "coinbase_position", first_is_cb and not extra_cb,
            "first tx is the only coinbase" if first_is_cb and not extra_cb
            else f"first is coinbase: {first_is_cb}; extra coinbases at {extra_cb}")

        # ---- ordinary transactions -----------------------------------------------------
        fees = 0
        for tx in txs:
            if is_coinbase(tx):
                continue
            tag = _short(tx.transaction_id, 8)
            fresh = tx.calculate_id()
            id_ok = fresh == tx.transaction_id
            add(i, "txid", id_ok, f"tx {tag}: stored id {'matches' if id_ok else 'DIFFERS from'} contents")

            # the group's own rule check (existence, duplicates, positive outputs, value balance)
            unspent_ok = balance_ok = True
            unspent_msg = "all inputs refer to earlier unspent outputs"
            try:
                validate_transaction_rules(tx, utxo)
                balance_msg = None
            except ValueError as e:
                msg = str(e)
                if any(p in msg for p in _INPUT_PROBLEMS):
                    unspent_ok, unspent_msg = False, msg
                else:
                    balance_ok, balance_msg = False, msg
            add(i, "inputs_unspent", unspent_ok, f"tx {tag}: {unspent_msg}")

            # scripts: only meaningful when every input exists
            scripts_ok, script_msgs, in_total = True, [], 0
            if unspent_ok:
                for k, tx_in in enumerate(tx.inputs):
                    spent = utxo.get_utxo(tx_in.previous_txid, tx_in.output_index)
                    in_total += spent.amount
                    try:
                        res = trace_script(unlocking_script_for(tx, k), locking_script_for(spent),
                                           signing_digest(tx))
                    except (ValueError, TypeError) as e:  # missing / malformed signature or key
                        scripts_ok = False
                        script_msgs.append(f"input {k}: malformed unlocking data ({type(e).__name__})")
                        continue
                    if not res["ok"]:
                        scripts_ok = False
                        script_msgs.append(f"input {k}: rejected at {res['failed_at']} - {res['reason']}")
                add(i, "scripts", scripts_ok,
                    f"tx {tag}: " + ("unlocking + locking scripts succeed" if scripts_ok else "; ".join(script_msgs)))

                out_total = sum(o.amount for o in tx.outputs)
                add(i, "value_balance", balance_ok,
                    f"tx {tag}: " + (f"inputs {in_total}, outputs {out_total}, fee {in_total - out_total}"
                                     if balance_ok else balance_msg))

            if id_ok and unspent_ok and balance_ok and scripts_ok:
                fees += in_total - sum(o.amount for o in tx.outputs)
                for tx_in in tx.inputs:
                    utxo.spend_utxo(tx_in.previous_txid, tx_in.output_index)
                for n, out in enumerate(tx.outputs):
                    utxo.add_utxo(UTXO(fresh, n, out.amount, out.address))

        # ---- coinbase ------------------------------------------------------------------
        if first_is_cb:
            cb = txs[0]
            id_ok = cb.calculate_id() == cb.transaction_id
            add(i, "txid", id_ok, f"coinbase {_short(cb.transaction_id, 8)}: stored id "
                                  f"{'matches' if id_ok else 'DIFFERS from'} contents")
            add(i, "coinbase_height", cb.block_height == b.height,
                f"coinbase says height {cb.block_height}, block height {b.height}")
            paid_to = cb.outputs[0].address if cb.outputs else None
            add(i, "coinbase_miner", paid_to == b.miner_address and not cb.inputs,
                "coinbase has no inputs and pays the block's miner"
                if paid_to == b.miner_address and not cb.inputs
                else f"coinbase pays {_short(paid_to, 10)}, block miner is {_short(b.miner_address, 10)}"
                     f"{'; coinbase has inputs' if cb.inputs else ''}")
            paid = sum(o.amount for o in cb.outputs)
            allowed = block_reward + fees
            amt_ok = paid <= allowed
            add(i, "coinbase_amount", amt_ok,
                f"pays {paid}, allowed {allowed} (reward {block_reward} + fees {fees})")
            if amt_ok and id_ok:
                for n, out in enumerate(cb.outputs):
                    utxo.add_utxo(UTXO(cb.transaction_id, n, out.amount, out.address))

    return ValidationResult(checks)


def format_report(result: ValidationResult, only_failures=False) -> str:
    lines, current = [], None
    for c in result.checks:
        if only_failures and c.ok:
            continue
        if c.block != current:
            current = c.block
            lines.append(f"Block {c.block}:")
        lines.append(f"  [{'PASS' if c.ok else 'FAIL'}] {c.name:<17} {c.detail}")
    return "\n".join(lines)


def headline(result: ValidationResult) -> str:
    if result.valid:
        return f"CHAIN VALID - all {len(result.checks)} checks passed"
    f = result.first_failure
    return (f"CHAIN INVALID - {len(result.failures)} of {len(result.checks)} checks failed; "
            f"first failure: '{f.name}' in block {f.block}")