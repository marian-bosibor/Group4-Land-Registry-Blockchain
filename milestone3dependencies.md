# chain validation: files required from other branches

This branch adds only: src/chain_validation.py, src/tamper_demo.py, src/final_demo.py,
tests/test_chain_validation.py (plus this note).
It needs the following files, which belong to other members' branches and must be merged first:

| Member | Files needed | Used for |
|---|---|---|
| 1 | src/transactions.py, src/utxo.py | transactions, unspent-output set |
| 2 | src/coinbase.py, src/transaction_rules.py | coinbase, transaction rules |
| 3 | src/script.py | P2PKH interpreter |
| 4 | src/signing.py, src/script_trace.py | what is signed, stack traces |
| 5 | src/block.py, src/demo_chain.py | blocks, mining, four-block chain |
| Milestone 2 | src/merkle_tree.py | Merkle root used by blocks |

Merge order: Members 1-4, then Member 5, then this branch.


## How to run (from the project root)
python -m src.final_demo
python -m pytest tests/test_chain_validation.py -v