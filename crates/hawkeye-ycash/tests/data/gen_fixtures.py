"""Generate hawkeye-ycash codec fixtures from the node's Python test framework.

Run: python3 -I crates/hawkeye-ycash/tests/data/gen_fixtures.py <ycash-dd> crates/hawkeye-ycash/tests/data
Uses ycash-dd qa/rpc-tests/test_framework/yellowback_model.serialize_tx_v4 (the v4 serialiser the
devnet's bridge-sim uses) and vault.py's template builders; sighash.json / vault_vectors.json
transactions are taken verbatim from ycash-dd src/test/data.
"""
import hashlib
import json
import os
import random
import struct
import subprocess
import sys
import types

YCASH = os.path.abspath(sys.argv[1])
OUT = os.path.abspath(sys.argv[2])
sys.path.insert(0, os.path.join(YCASH, "qa", "rpc-tests"))
# mininode (imported by vault.py) needs asyncore (gone in Python 3.12) and pyblake2: stub them,
# nothing here touches the network code.
_a = types.ModuleType("asyncore"); _a.dispatcher = object; _a.loop = lambda *x, **k: None
sys.modules["asyncore"] = _a
_pb = types.ModuleType("pyblake2"); _pb.blake2b = hashlib.blake2b; _pb.blake2s = hashlib.blake2s
sys.modules["pyblake2"] = _pb
from test_framework import vault as v              # noqa: E402
from test_framework import yellowback_model as ym  # noqa: E402

rng = random.Random(0x4841574B)  # "HAWK"


def rb(n):
    return bytes(rng.getrandbits(8) for _ in range(n))


def txid_of(raw):
    return ym.hash256(raw)[::-1].hex()


def rtxid():
    return rb(32).hex()


def p2pkh(h20):
    return bytes([0x76, 0xA9, 0x14]) + h20 + bytes([0x88, 0xAC])


def p2pkh_sigscript():
    sig = b"\x30\x44" + rb(68) + b"\x01"
    return v.push(sig) + v.push(b"\x02" + rb(32))


SET_A = rb(32)
OWNER = bytes.fromhex("022144abd3c2b40612b5ec126349833834e2c68d1ace1fc242b3db0b687ee54676")
VP = v.VaultParams(b"WYEC", SET_A, SET_A, 6, 4400, 0, OWNER)
V_SPK = v.vault_script(VP)
RECIP = p2pkh(rb(20))
IP = v.intent_for(VP, RECIP)
I_SPK = v.intent_script(IP)


def memo(nonce):
    """The plan §4.3 HKB1 memo, kind 1, anvil chain id (its fields sum to 73 bytes)."""
    return (b"HKB1" + b"\x01" + struct.pack("<Q", 31337) + rb(20) + struct.pack("<Q", nonce) + rb(32))


cases = []


def add(name, vin, vout, lock=0, expiry=0, note=""):
    raw = ym.serialize_tx_v4(vin, vout, lock, expiry)
    cases.append({"name": name, "hex": raw.hex(), "txid": txid_of(raw), "inputs": len(vin), "outputs": len(vout),
                  "lockTime": lock, "expiryHeight": expiry, "note": note})
    return vin, vout, lock, expiry


dest = b"\x00" * 12 + rb(20)
add("lock", [(rtxid(), 1, b"", 0xFFFFFFFF)],
    [(10 * 10**8, V_SPK), (0, bytes([0x6A]) + v.push(dest)), (5 * 10**8 - 10000, p2pkh(rb(20)))], 0, 240,
    "bridge-sim lock: V + destination OP_RETURN + change, unsigned")
unlock_vin = [(rtxid(), 0, b"", 0xFFFFFFFF), (rtxid(), 3, b"", 0xFFFFFFFF), (rtxid(), 0, b"", 0xFFFFFFFF)]
unlock_vout = [(4 * 10**8, I_SPK), (6 * 10**8, V_SPK), (123456789, p2pkh(rb(20)))]
add("unlock-unsigned", unlock_vin, unlock_vout, 0, 0, "vault_buildunlock shape: template + 2 fee inputs, all unsigned, expiry 0")
signed_vin = [(unlock_vin[0][0], 0, v.vault_unlock_scriptsig([b"\x1f" + rb(64)]), 0xFFFFFFFF),
              (unlock_vin[1][0], 3, p2pkh_sigscript(), 0xFFFFFFFF), (unlock_vin[2][0], 0, p2pkh_sigscript(), 0xFFFFFFFF)]
add("unlock-signed", signed_vin, unlock_vout, 0, 0, "set signature + fee signatures")
half_vin = [(unlock_vin[0][0], 0, v.vault_unlock_scriptsig([b"\x1f" + rb(64)]), 0xFFFFFFFF)] + unlock_vin[1:]
add("unlock-set-signed", half_vin, unlock_vout, 0, 0, "set_signunlock done, fee inputs unsigned")
sel_only_vin = [(unlock_vin[0][0], 0, v.vault_unlock_scriptsig([]), 0xFFFFFFFF)] + unlock_vin[1:]
add("unlock-selector-only", sel_only_vin, unlock_vout, 0, 0, "set_signunlock by a wallet with no member key: scriptSig OP_1 only")
add("release", [(rtxid(), 0, v.intent_release_scriptsig(), 6), (rtxid(), 2, b"", 0xFFFFFFFF)],
    [(4 * 10**8, RECIP), (77777, p2pkh(rb(20)))], 0, 0, "vault_release: selector 1, nSequence = delay")
add("cancel", [(rtxid(), 0, v.intent_cancel_scriptsig([b"\x20" + rb(64)]), 0xFFFFFFFF), (rtxid(), 1, b"", 0xFFFFFFFF)],
    [(4 * 10**8, V_SPK), (55555, p2pkh(rb(20)))], 0, 0, "cancel with one set signature")
add("coinbase", [(None, 0xFFFFFFFF, b"\x03" + rb(3) + rb(8), 0xFFFFFFFF)], [(625000000, p2pkh(rb(20)))], 0, 1234)
add("empty", [], [], 0, 0)
add("many-inputs", [(rtxid(), i, b"", 0xFFFFFFFE) for i in range(260)], [(1, p2pkh(rb(20)))], 7, 9,
    "260 inputs: CompactSize 0xfd")
add("big-scripts", [(rtxid(), 0, rb(300), 0)], [(0, bytes([0x6A]) + rb(252)), (1, rb(253)), (2, rb(70000))], 499999999, 499999999,
    "scripts of 252/253/70000 bytes: CompactSize 1, 3 and 5 bytes")
add("max-values", [(rtxid(), 0xFFFFFFFF, b"", 0)], [(21_000_000 * 10**8, p2pkh(rb(20))), (0, b"")], 0xFFFFFFFF, 0xFFFFFFFF)

inserts = []
for name, base in (("unlock-unsigned", (unlock_vin, unlock_vout)), ("unlock-selector-only", (sel_only_vin, unlock_vout)),
                   ("lock-without-dest", ([(rtxid(), 1, b"", 0xFFFFFFFF)], [(10 * 10**8, V_SPK), (1, p2pkh(rb(20)))]))):
    vin, vout = base
    for dname, data in (("memo", memo(42)), ("data75", rb(75)), ("data76", rb(76)), ("data80", rb(80)), ("data1", rb(1))):
        before = ym.serialize_tx_v4(vin, vout, 0, 0)
        after = ym.serialize_tx_v4(vin, vout + [(0, bytes([0x6A]) + v.push(data))], 0, 0)
        inserts.append({"name": "%s+%s" % (name, dname), "base": before.hex(), "data": data.hex(),
                        "expected": after.hex(), "expectedTxid": txid_of(after)})


# ---- sighash.json: random transactions of every format, shielded parts included -------------
def compact(b, i):
    n = b[i]; i += 1
    if n < 253: return n, i
    if n == 253: return struct.unpack("<H", b[i:i + 2])[0], i + 2
    if n == 254: return struct.unpack("<I", b[i:i + 4])[0], i + 4
    return struct.unpack("<Q", b[i:i + 8])[0], i + 8


def classify(raw):
    """An independent walk of the C++ serialisation (src/primitives/transaction.h) to label each fixture."""
    b = raw
    header = struct.unpack("<I", b[:4])[0]; i = 4
    ow = header >> 31; ver = header & 0x7FFFFFFF; vgid = 0
    if ow: vgid = struct.unpack("<I", b[i:i + 4])[0]; i += 4
    v3 = ow and vgid == 0x03C48270 and ver == 3
    v4 = ow and vgid == 0x892F2085 and ver == 4
    if ow and not (v3 or v4): return None
    n, i = compact(b, i)
    for _ in range(n):
        i += 36; l, i = compact(b, i); i += l + 4
    nout, i = compact(b, i)
    for _ in range(nout):
        i += 8; l, i = compact(b, i); i += l
    i += 4
    if v3 or v4: i += 4
    ns = no = 0
    if v4:
        i += 8
        ns, i = compact(b, i); i += 384 * ns
        no, i = compact(b, i); i += 948 * no
    njs = 0
    if ver >= 2:
        njs, i = compact(b, i)
        i += njs * (1698 if v4 else 1802)
        if njs: i += 96
    if v4 and (ns or no): i += 64
    assert i == len(b), (i, len(b))
    fmt = "sapling-v4" if v4 else "overwinter-v3" if v3 else ("sprout-v%d" % ver if ver < 2 else "sprout-joinsplit")
    return {"format": fmt, "overwintered": bool(ow), "version": ver, "versionGroupId": vgid, "inputs": n, "outputs": nout,
            "spends": ns, "shieldedOutputs": no, "joinSplits": njs}


sig = json.load(open(os.path.join(YCASH, "src/test/data/sighash.json")))[1:]
by = {}
for row in sig:
    raw = bytes.fromhex(row[0])
    c = classify(raw)
    if c is None: continue
    c.update({"hex": raw.hex(), "txid": txid_of(raw)})
    by.setdefault(c["format"], []).append(c)
picked = []
v4 = by.get("sapling-v4", [])
# every v4 with joinsplits, spends or outputs up to a cap, plus a few transparent-only ones
interesting = [c for c in v4 if c["spends"] or c["shieldedOutputs"] or c["joinSplits"]]
plain = [c for c in v4 if not (c["spends"] or c["shieldedOutputs"] or c["joinSplits"])]
interesting.sort(key=lambda c: len(c["hex"]))
picked += interesting[:24] + plain[:4]
for fmt in sorted(by):
    if fmt == "sapling-v4": continue
    lst = sorted(by[fmt], key=lambda c: len(c["hex"]))
    picked += [c for c in lst if not c["joinSplits"]][:3] + [c for c in lst if c["joinSplits"]][:3]
sighash_fx = {"_source": "ycash-dd src/test/data/sighash.json (raw_transaction column), classified by gen_fixtures.py",
              "counts": {k: len(x) for k, x in sorted(by.items())}, "transactions": picked}

vv = json.load(open(os.path.join(YCASH, "src/test/data/vault_vectors.json")))
spends = [{"name": s["name"], "hex": s["tx"], "txid": txid_of(bytes.fromhex(s["tx"])), "nIn": s["nIn"],
           "scriptSig": s["scriptSig"]} for s in vv["spends"]]

rev = subprocess.run(["git", "-C", YCASH, "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
meta = {"generator": "crates/hawkeye-ycash/tests/data/gen_fixtures.py", "ycash-dd": rev}
os.makedirs(OUT, exist_ok=True)
with open(os.path.join(OUT, "v4_transparent.json"), "w") as f:
    json.dump(dict(meta, transactions=cases), f, indent=1)
with open(os.path.join(OUT, "v4_insert_op_return.json"), "w") as f:
    json.dump(dict(meta, cases=inserts), f, indent=1)
with open(os.path.join(OUT, "sighash_txs.json"), "w") as f:
    json.dump(dict(meta, **sighash_fx), f, indent=1)
with open(os.path.join(OUT, "vault_spends.json"), "w") as f:
    json.dump(dict(meta, spends=spends), f, indent=1)
print("v4_transparent %d, inserts %d, sighash %d (of %s), spends %d" % (len(cases), len(inserts), len(picked), sighash_fx["counts"], len(spends)))
