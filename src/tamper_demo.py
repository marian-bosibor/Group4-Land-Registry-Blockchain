"""
PART 1  the honest chain validates
PART 2  an attacker alters ONE field of ONE transaction in an early block (the land-title
        transfer): the stored Merkle root and the recomputed root are shown side by side and the
        check that caught it is named
PART 3  the attacker tries to hide the change step by step (fix txid + Merkle root -> fix hash ->
        re-mine -> re-mine every later block) and which check stops each attempt
PART 4  what rewriting history costs: an edit that needs no signature (the coinbase payout) CAN be
        hidden, but only by redoing the proof of work for every later block
Educational only: no network, demonstration keys only.
"""
import copy

from src.chain_validation import format_report, headline, validate_chain
from src.demo_chain import DIFFICULTY, build_demo_chain, make_party


def remine_from(chain, start):
    """The attacker's repair work: from block `start` on, fix each previous-hash link, recompute the
    Merkle root and re-mine. Returns the proof-of-work attempts spent on each block."""
    costs = []
    for i in range(start, len(chain)):
        if i > 0:
            chain[i].previous_hash = chain[i - 1].block_hash
        chain[i].mine(verbose=False)
        costs.append(chain[i].mining_attempts)
    return costs


def transfer_block_index(chain):
    """Index of the block holding the ordinary (land-title transfer) transaction."""
    return next(i for i, b in enumerate(chain) if len(b.transactions) > 1)


def failures_text(result, limit=6):
    lines = [f"      - block {c.block} {c.name}: {c.detail}" for c in result.failures[:limit]]
    if len(result.failures) > limit:
        lines.append(f"      ... and {len(result.failures) - limit} more")
    return "\n".join(lines)


def run(built=None, difficulty=DIFFICULTY):
    """built: an existing build_demo_chain() result, so a bigger demo can use the same chain."""
    chain0, _utxo, parties, _tx = built or build_demo_chain(difficulty, verbose=False)
    attacker = make_party("attacker")
    t = transfer_block_index(chain0)

    print("=" * 72)
    print("PART 1 - THE HONEST CHAIN")
    print("=" * 72)
    r = validate_chain(chain0, min_difficulty=difficulty)
    print(headline(r))
    print("Blocks:", ", ".join(f"#{b.height} {b.block_hash[:10]}.." for b in chain0))

    # ---------------------------------------------------------------- PART 2
    print("\n" + "=" * 72)
    print(f"PART 2 - TAMPERING: redirect the title transfer in block {t}")
    print("=" * 72)
    chain = copy.deepcopy(chain0)
    tx = chain[t].transactions[1]
    before = tx.outputs[0].address
    tx.outputs[0].address = attacker["address"]
    print(f"Field altered : block {t}, transfer transaction, output 0 recipient address")
    print(f"  before      : {before}   (buyer)")
    print(f"  after       : {attacker['address']}   (attacker)")
    r = validate_chain(chain, min_difficulty=difficulty)
    print("\n" + headline(r))
    print(f"\nBlock {t} Merkle root")
    print(f"  stored in header : {chain[t].merkle_root}")
    print(f"  recomputed       : {chain[t].calculate_merkle_root()}")
    print("  -> MISMATCH: the 'merkle_root' check caught the change.")
    h = next(c for c in r.checks if c.block == t and c.name == "block_hash")
    print(f"  (block {t}'s own hash check still says: {'PASS' if h.ok else 'FAIL'} - the header was not "
          "touched, so only the Merkle root exposes the edit)")
    print("\nAll failed checks:")
    print(failures_text(r))
    print("  Note: 'coinbase_amount' fails only as a side effect. The tampered transfer is rejected,\n"
          "  so its fee is no longer collected and the coinbase now claims more than it is owed.")

    # ---------------------------------------------------------------- PART 3
    print("\n" + "=" * 72)
    print("PART 3 - THE ATTACKER TRIES TO HIDE IT")
    print("=" * 72)
    a = copy.deepcopy(chain)
    a[t].transactions[1].transaction_id = a[t].transactions[1].calculate_id()
    a[t].merkle_root = a[t].calculate_merkle_root()
    r = validate_chain(a, min_difficulty=difficulty)
    print(f"Step a) fix the transaction id and the Merkle root in block {t}'s header")
    print(f"   {headline(r)}\n{failures_text(r, 3)}")

    a[t].block_hash = a[t].calculate_hash()
    r = validate_chain(a, min_difficulty=difficulty)
    print(f"\nStep b) also recompute block {t}'s hash, but do no mining")
    print(f"   {headline(r)}\n{failures_text(r, 3)}")

    a[t].mine(verbose=False)
    r = validate_chain(a, min_difficulty=difficulty)
    print(f"\nStep c) re-mine block {t} ({a[t].mining_attempts} attempts) so its header and proof of work are valid")
    print(f"   {headline(r)}\n{failures_text(r, 3)}")

    costs = remine_from(a, t + 1)
    r = validate_chain(a, min_difficulty=difficulty)
    print(f"\nStep d) re-mine every later block too ({sum(costs)} more attempts)")
    print(f"   {headline(r)}\n{failures_text(r, 3)}")
    print("   -> Block headers, hashes and links are now all consistent, yet the chain is still\n"
          "      invalid: the transfer's signature covered the old recipient, and forging a new\n"
          "      one needs the seller's PRIVATE KEY. Proof of work cannot supply that.")

    # ---------------------------------------------------------------- PART 4
    print("\n" + "=" * 72)
    print("PART 4 - WHAT REWRITING HISTORY COSTS")
    print("=" * 72)
    b = copy.deepcopy(chain0)
    cb = b[1].transactions[0]
    cb.outputs[0].address = attacker["address"]
    cb.transaction_id = cb.calculate_id()
    b[1].miner_address = attacker["address"]
    print("Edit: block 1 coinbase payout redirected to the attacker (a coinbase carries no signature).")
    r = validate_chain(b, min_difficulty=difficulty)
    print(f"  Without redoing the work : {headline(r)}")
    costs = remine_from(b, 1)
    r = validate_chain(b, min_difficulty=difficulty)
    print(f"  After re-mining blocks 1-{len(b) - 1}  : {headline(r)}")
    print(f"  Attacker's work          : {costs} attempts per block, {sum(costs)} in total")
    print(f"  Honest network's work    : {[x.mining_attempts for x in chain0[1:]]} attempts for the same blocks")
    print(f"  Expected work per block  : about 16^{difficulty} = {16 ** difficulty} hashes at this toy difficulty;")
    print("  the attacker must also finish before honest miners add the next block, and every")
    print("  extra zero of difficulty multiplies the cost by about 16. Nothing physically stops")
    print("  the edit - it is made expensive and obvious, which is what immutability means here.")


if __name__ == "__main__":
    run()