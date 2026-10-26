import contextlib
import copy
import io
import json

from src import tamper_demo
from src.chain_validation import format_report, headline, validate_chain
from src.demo_chain import DIFFICULTY, build_demo_chain, make_party
from src.script_trace import print_trace, trace_script
from src.signing import locking_script_for, sign_input, signing_digest, unlocking_script_for


def banner(title):
    print("\n" + "=" * 72 + f"\n{title}\n" + "=" * 72)


def main(difficulty=DIFFICULTY):
    mining_log = io.StringIO()
    with contextlib.redirect_stdout(mining_log):  # build_demo_chain logs while it mines
        built = build_demo_chain(difficulty, verbose=True)
    chain, _utxo, parties, transfer = built
    attacker = make_party("attacker")

    banner("1. PARTICIPANTS (address = hash160 of the compressed public key)")
    for name in ("seller", "buyer", "miner_a", "miner_b"):
        p = parties[name]
        print(f"{name:<8} public key {p['public_key'].hex()[:20]}..  address {p['address']}")

    banner("2. TRANSACTIONS")
    print("Genesis coinbase (initial output standing for a title already held by the seller):")
    print(json.dumps(chain[0].transactions[0].to_dict(), indent=2))
    print("\nOrdinary transaction (land-title transfer seller -> buyer, signed with ECDSA):")
    print(json.dumps(transfer.to_dict(), indent=2))

    banner("3. P2PKH SCRIPT EXECUTION (stack after every step)")
    spent_output = chain[0].transactions[0].outputs[0]  # the output the transfer spends
    lock = locking_script_for(spent_output)

    print_trace("SUCCESS: genuine spend by the seller",
                trace_script(unlocking_script_for(transfer, 0), lock, signing_digest(transfer)))

    wrong_key = copy.deepcopy(transfer)
    sign_input(wrong_key, 0, attacker["private_key"])
    print_trace("FAILURE 1: wrong public key (attacker supplies their own key and signature)",
                trace_script(unlocking_script_for(wrong_key, 0), lock, signing_digest(wrong_key)))

    altered = copy.deepcopy(transfer)
    altered.outputs[0].amount = 50
    print_trace("FAILURE 2: transaction altered after signing (output amount 49 -> 50)",
                trace_script(unlocking_script_for(altered, 0), lock, signing_digest(altered)))

    banner("4. MINING (difficulty = leading zeros; Member 5's block code)")
    print(mining_log.getvalue().rstrip())
    for b in chain:
        print(f"block {b.height}: difficulty {b.difficulty}, nonce {b.nonce}, "
              f"attempts {b.mining_attempts}, hash {b.block_hash}")

    banner("5. CHAIN VALIDATION")
    r = validate_chain(chain, min_difficulty=difficulty)
    print(format_report(r))
    print("\n" + headline(r))

    tamper_demo.run(built, difficulty)  # same chain, keys and addresses as sections 1-5


if __name__ == "__main__":
    main()