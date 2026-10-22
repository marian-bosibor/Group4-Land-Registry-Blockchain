"""Labelled output for report screenshots.   Run from repo root:  python -m integration.demo"""
from datetime import datetime, timezone
from integration import adapter as A

def banner(t): print("\n" + "=" * 70 + f"\n{t}\n" + "=" * 70)
def forge(r): return {**r, "new_owner": "ATTACKER", "owner": "ATTACKER"}
records = A.load_records()

banner("STEP 1  Key pairs for three roles (DEMONSTRATION KEYS ONLY)")
ca, officer, owner = (A.generate_keypair(r) for r in ("ministry_ca", "registry_official", "landowner"))
for k in (ca, officer, owner):
    print(f"[{k['role']}]  public: {k['public_key'][:30]}...  address: {k['address'][:20]}...")

banner("STEP 2  MOL-CA certifies the registry officer, then a verifier checks it")
cert = A.issue_certificate(ca["private_key"], "officer:REG-0042", "registry_official", officer["public_key"])
print("subject:", cert["subject_id"], "| role:", cert["subject_role"], "| issuer:", cert["issuer_id"])
print("genuine certificate   ->", A.verify_certificate(cert, ca["public_key"]))
bad = dict(cert, subject_public_key=owner["public_key"])
print("public key swapped    ->", A.verify_certificate(bad, ca["public_key"]), " <- expected FAIL")

banner(f"STEP 3  Merkle tree over {len(records)} land records (data/land_records.json)")
root = A.merkle_root(records)
levels = A.build_tree(records)
print("levels (leaves up to root):", [len(l) for l in levels])
print("Merkle root:", root)
proof = A.get_proof(records, 3)
print(f"proof for record 4 ({records[3]['transaction']}): {len(proof)} hashes (8 records -> 3)")
print("genuine record        ->", A.verify_proof(records[3], proof, root))
print("altered record        ->", A.verify_proof(forge(records[3]), proof, root), " <- expected False")

banner("STEP 4  End-to-end: certificate -> signed root -> inclusion proof")
sig = A.sign(officer["private_key"], root.encode())
ok, reason = A.verify_signed_message(cert, ca["public_key"], root.encode(), sig)
print("1+2. certificate valid and root signed by that officer:", ok, "|", reason)
print("3.   record included under the signed root           :", A.verify_proof(records[3], proof, root))
bad_sig = A.sign(owner["private_key"], root.encode())
print("Root signed by the landowner instead of the officer  ->", A.verify_signed_message(cert, ca["public_key"], root.encode(), bad_sig)[1])
late = datetime(2027, 6, 1, tzinfo=timezone.utc)
print("Officer certificate checked after expiry             ->", A.verify_signed_message(cert, ca["public_key"], root.encode(), sig, now=late)[1])

banner("STEP 5  What this does NOT catch")
recs = records[:]; recs[0] = forge(records[0])
froot = A.merkle_root(recs); fsig = A.sign(officer["private_key"], froot.encode())
print("A corrupt but AUTHORISED officer signs a fraudulent record:")
print("  certificate + signature :", A.verify_signed_message(cert, ca["public_key"], froot.encode(), fsig)[0])
print("  inclusion proof         :", A.verify_proof(recs[0], A.get_proof(recs, 0), froot))
print("  -> every check passes. Integrity is guaranteed; truth is not.")
