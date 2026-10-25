"""Prints the stack traces the report needs. Run from the repo root:  python demo_script_validation.py"""
from tests.test_script_validation import (case_valid_spend, case_wrong_public_key,
                                          case_altered_transaction, case_malformed_signature,
                                          case_signature_from_other_key, case_missing_signature,
                                          case_extra_junk_item, case_empty_unlocking_script)
from src.script_trace import trace_script, print_trace

for title, builder in [
    ("CASE 1  SUCCESSFUL SPEND: correct key, correct signature, unaltered transaction", case_valid_spend),
    ("CASE 2  WRONG PUBLIC KEY (thief signs with their own key): caught by OP_EQUALVERIFY", case_wrong_public_key),
    ("CASE 3  ALTERED TRANSACTION AFTER SIGNING: caught by OP_CHECKSIG", case_altered_transaction),
    ("CASE 4  MALFORMED SIGNATURE: caught by OP_CHECKSIG", case_malformed_signature),
    ("CASE 5  SIGNATURE FROM A DIFFERENT KEY: caught by OP_CHECKSIG", case_signature_from_other_key),
    ("CASE 6  MISSING SIGNATURE: caught by OP_CHECKSIG (stack underflow)", case_missing_signature),
    ("CASE 7  EXTRA JUNK ITEM: caught by the final stack check", case_extra_junk_item),
    ("CASE 8  EMPTY UNLOCKING SCRIPT: caught by OP_DUP (stack underflow)", case_empty_unlocking_script),
]:
    print_trace(title, trace_script(*builder()))
# Add the traces for your own cases here, the same way.
