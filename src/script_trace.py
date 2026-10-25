"""
script_trace.py - Member 4: a TRACING version of the P2PKH interpreter.

Why it exists: src/script.py's execute_script() returns only True/False, so it cannot show
the stack after each opcode or say WHICH opcode rejected a spend. The brief needs both.

This module repeats the same rules as execute_script() (same hash160, same checks, same
order) but records every step. It never replaces Member 3's code: the tests cross-check
that trace_script() and execute_script() always agree.
"""
from coincurve import PublicKey
from src.script import (OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, hash160)


def short(data: bytes) -> str:
    """Readable form of a stack item: first 4 bytes in hex plus its length."""
    h = data.hex()
    return f"<{h}>" if len(data) <= 4 else f"<{h[:8]}..({len(data)}B)>"


def trace_script(unlocking_script, locking_script, message):
    """
    Returns a dict:
      ok        - True only if the spend is valid (same answer as execute_script)
      failed_at - the opcode that rejected it ("OP_EQUALVERIFY", "OP_CHECKSIG", ...), else None
      reason    - plain-English explanation
      steps     - list of (step number, operation, stack after the step)
    """
    steps = []
    stack = []
    current = "START"          # the opcode being executed, so an exception can be blamed on it

    def record(op):
        steps.append((len(steps) + 1, op, [short(x) for x in stack]))

    def fail(op, reason):
        record(f"{op}  -> FAIL")
        return {"ok": False, "failed_at": op, "reason": reason, "steps": steps}

    if not isinstance(message, bytes) or not isinstance(unlocking_script, list) \
            or not isinstance(locking_script, list):
        return fail("INPUT", "message must be bytes and both scripts must be lists")

    try:
        # 1. Unlocking script: push its data onto the stack.
        for i, item in enumerate(unlocking_script, start=1):
            if not isinstance(item, bytes):
                return fail("PUSH", "unlocking script items must be bytes")
            stack.append(item)
            record(f"PUSH unlocking item {i}")

        # 2. Locking script, run over the stack the unlocking script left behind.
        for operation in locking_script:
            current = operation if isinstance(operation, str) else "PUSH <pubKeyHash>"
            if operation == OP_DUP:
                if len(stack) < 1:
                    return fail(OP_DUP, "stack underflow: nothing to duplicate")
                stack.append(stack[-1])
                record(OP_DUP)

            elif operation == OP_HASH160:
                if len(stack) < 1:
                    return fail(OP_HASH160, "stack underflow: nothing to hash")
                stack.append(hash160(stack.pop()))
                record(OP_HASH160)

            elif isinstance(operation, bytes):
                stack.append(operation)
                record("PUSH <pubKeyHash>")

            elif operation == OP_EQUALVERIFY:
                if len(stack) < 2:
                    return fail(OP_EQUALVERIFY, "stack underflow: needs two items")
                first, second = stack.pop(), stack.pop()
                if first != second:
                    return fail(OP_EQUALVERIFY,
                                "hash of the supplied public key does not match the locking script")
                record(OP_EQUALVERIFY)

            elif operation == OP_CHECKSIG:
                if len(stack) < 2:
                    return fail(OP_CHECKSIG, "stack underflow: needs a signature and a public key")
                public_key_bytes, signature = stack.pop(), stack.pop()
                if not PublicKey(public_key_bytes).verify(signature, message):
                    return fail(OP_CHECKSIG, "signature does not match this key and transaction")
                stack.append(b"\x01")
                record(OP_CHECKSIG)

            else:
                return fail("UNKNOWN_OPCODE", f"unsupported operation {operation!r}")

        # 3. Final rule: exactly one TRUE value must remain.
        if len(stack) == 1 and stack[0] == b"\x01":
            return {"ok": True, "failed_at": None, "reason": "valid spend", "steps": steps}
        return fail("FINAL_CHECK", f"stack must end with exactly one TRUE value, found {len(stack)} item(s)")

    except (ValueError, TypeError, IndexError) as exc:
        # Member 3's execute_script catches these and returns False. We report WHICH opcode raised.
        return fail(current, f"malformed input raised {type(exc).__name__}: {exc}")


def print_trace(title, result):
    """Print a trace the way the report needs it: one line per step, stack after each."""
    print("\n" + "=" * 72 + f"\n{title}\n" + "=" * 72)
    for number, op, stack in result["steps"]:
        print(f"{number:>2}. {op:<28} stack: [{', '.join(stack)}]")
    verdict = "ACCEPTED" if result["ok"] else f"REJECTED at {result['failed_at']}"
    print(f"-> {verdict}: {result['reason']}")
