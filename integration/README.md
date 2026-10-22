# Integration tests (Member 5) - Group 4 Land Registry

Run from the REPO ROOT, with the venv active (Python 3.12/3.13, `pip install coincurve`):

    python -m unittest integration.test_integration -v
    python -m integration.demo

Files: adapter.py (connects to the real modules), merkle_proof.py (PROVISIONAL proof functions -
src/merkle_tree.py has none), test_integration.py (IT-01..IT-20), demo.py (screenshot output).
