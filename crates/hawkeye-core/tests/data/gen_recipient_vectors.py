#!/usr/bin/env python3
"""Independent derivation of Hawkeye's ycashRecipient (plan §4.2 revision 2) golden vectors.

Written from the plan text alone (no hawkeye-core code): the 22/35-byte field, the three
recipient scripts, recipientHash = SHA256(script), and the Base58Check addresses with the
node's version bytes (ycash-dd cc8c90764, unchanged since d41026209: chainparams.cpp P2PKH/P2SH,
key_io.cpp:23-27 sq/tq/rq).
"""
import hashlib, json, sys

ALPHA = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

def b58(b: bytes) -> str:
    n = int.from_bytes(b, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = ALPHA[r] + out
    pad = 0
    for x in b:
        if x == 0: pad += 1
        else: break
    return "1" * pad + out

def sha256(b): return hashlib.sha256(b).digest()
def b58check(payload: bytes) -> str:
    return b58(payload + sha256(sha256(payload))[:4])

NETS = {
    "mainnet": {"p2pkh": bytes([0x1c, 0x28]), "p2sh": bytes([0x1c, 0x2c]), "pq": bytes([0x4d, 0xd9])},
    "testnet": {"p2pkh": bytes([0x1c, 0x95]), "p2sh": bytes([0x1c, 0x2a]), "pq": bytes([0x4f, 0x61])},
    "regtest": {"p2pkh": bytes([0x1c, 0x95]), "p2sh": bytes([0x1c, 0x2a]), "pq": bytes([0x4c, 0x51])},
}
VERSION = 0x02
KIND = {"p2pkh": 0x00, "p2sh": 0x01, "pqpkh": 0x02}
OP_DUP, OP_HASH160, OP_EQUALVERIFY, OP_CHECKSIG, OP_EQUAL = 0x76, 0xa9, 0x88, 0xac, 0x87
OP_1, OP_CHECKPQSIG = 0x51, 0xc2

def script(kind, scheme, h):
    if kind == "p2pkh": return bytes([OP_DUP, OP_HASH160, 20]) + h + bytes([OP_EQUALVERIFY, OP_CHECKSIG])
    if kind == "p2sh": return bytes([OP_HASH160, 20]) + h + bytes([OP_EQUAL])
    # TX_PQPKH: <keyHash:32> OP_1|OP_2 OP_CHECKPQSIG — the scheme as a script number (OP_n), F-1
    return bytes([32]) + h + bytes([OP_1 + scheme - 1, OP_CHECKPQSIG])

def field(kind, scheme, h):
    b = bytes([VERSION, KIND[kind]])
    if kind == "pqpkh": b += bytes([scheme])
    return b + h

def addresses(kind, scheme, h):
    out = {}
    for net, v in NETS.items():
        if kind == "pqpkh": payload = v["pq"] + bytes([scheme]) + h
        else: payload = v[kind] + h
        out[net] = b58check(payload)
    return out

cases = [
    ("p2pkh", None, bytes([0x5a]) * 20, "P2PKH, hash160 = 20 × 5a (the address tests' hash)"),
    ("p2sh", None, bytes([0x5a]) * 20, "P2SH, same hash160"),
    ("p2pkh", None, bytes([0xab]) * 20, "P2PKH, hash160 = 20 × ab (the former bytes32 test's hash)"),
    ("pqpkh", 1, bytes.fromhex("c554ba62cf5f3a25601f8d6d0e6ff2ce41f3917407402ca623dd83e292e6b258"),
     "PQPKH scheme 1 (SLH-DSA-SHA2-128s), keyHash = the node vector's pqOwner hash"),
    ("pqpkh", 2, bytes([0xff]) * 32, "PQPKH scheme 2 (FN-DSA-512), keyHash = 32 × ff"),
    ("pqpkh", 1, bytes([0x5a]) * 32, "PQPKH scheme 1, keyHash = 32 × 5a (the node's D-Q-21 known-answer hash)"),
    ("pqpkh", 2, bytes([0x5a]) * 32, "PQPKH scheme 2, keyHash = 32 × 5a"),
    ("pqpkh", 1, bytes(32), "PQPKH scheme 1, keyHash = 32 × 00"),
]
valid = []
for kind, scheme, h, note in cases:
    f = field(kind, scheme, h)
    s = script(kind, scheme, h)
    assert len(f) in (22, 35) and len(s) in (25, 23, 35)
    e = {"note": note, "kind": KIND[kind], "kindName": kind.upper(), "hash": h.hex(),
         "bytes": f.hex(), "script": s.hex(), "recipientHash": sha256(s).hex(),
         "addresses": addresses(kind, scheme, h)}
    if scheme is not None: e["scheme"] = scheme
    valid.append(e)

pq1 = bytes.fromhex("c554ba62cf5f3a25601f8d6d0e6ff2ce41f3917407402ca623dd83e292e6b258")
h20 = bytes([0x5a]) * 20
invalid = [
    # a decoder checks the length before the version byte: 32 bytes is no revision-2 length
    {"note": "version 1 (the retired bytes32 form), kind 0", "bytes": (bytes([0x01, 0x00]) + bytes(10) + h20).hex(), "reason": "wrong length"},
    {"note": "version 1 with a 22-byte body", "bytes": (bytes([0x01, 0x00]) + h20).hex(), "reason": "unknown version"},
    {"note": "version 0", "bytes": (bytes([0x00, 0x00]) + h20).hex(), "reason": "unknown version"},
    {"note": "version 3", "bytes": (bytes([0x03, 0x00]) + h20).hex(), "reason": "unknown version"},
    {"note": "kind 3", "bytes": (bytes([0x02, 0x03]) + h20).hex(), "reason": "unknown kind"},
    {"note": "kind 0xff", "bytes": (bytes([0x02, 0xff]) + h20).hex(), "reason": "unknown kind"},
    {"note": "kind 0 with a 35-byte body (a PQ hash under a transparent kind)", "bytes": (bytes([0x02, 0x00, 0x01]) + pq1).hex(), "reason": "wrong length"},
    {"note": "kind 1 with a 35-byte body", "bytes": (bytes([0x02, 0x01, 0x01]) + pq1).hex(), "reason": "wrong length"},
    {"note": "kind 2 with a 22-byte body (hash160 under the PQ kind)", "bytes": (bytes([0x02, 0x02]) + h20).hex(), "reason": "wrong length"},
    {"note": "kind 2, scheme 0", "bytes": (bytes([0x02, 0x02, 0x00]) + pq1).hex(), "reason": "unknown scheme"},
    {"note": "kind 2, scheme 3", "bytes": (bytes([0x02, 0x02, 0x03]) + pq1).hex(), "reason": "unknown scheme"},
    {"note": "kind 2, scheme 0xff", "bytes": (bytes([0x02, 0x02, 0xff]) + pq1).hex(), "reason": "unknown scheme"},
    {"note": "21 bytes (hash160 short by one)", "bytes": (bytes([0x02, 0x00]) + h20[:19]).hex(), "reason": "wrong length"},
    {"note": "23 bytes (hash160 long by one)", "bytes": (bytes([0x02, 0x00]) + h20 + b"\x00").hex(), "reason": "wrong length"},
    {"note": "34 bytes (keyHash short by one)", "bytes": (bytes([0x02, 0x02, 0x01]) + pq1[:31]).hex(), "reason": "wrong length"},
    {"note": "36 bytes (keyHash long by one)", "bytes": (bytes([0x02, 0x02, 0x01]) + pq1 + b"\x00").hex(), "reason": "wrong length"},
    {"note": "32 bytes: an Ethereum address left-padded", "bytes": (bytes(12) + bytes([0x11]) * 20).hex(), "reason": "wrong length"},
    {"note": "empty", "bytes": "", "reason": "wrong length"},
    {"note": "one byte", "bytes": "02", "reason": "wrong length"},
    {"note": "two bytes (a header without a body)", "bytes": "0200", "reason": "wrong length"},
]
scripts_invalid = [
    {"note": "TX_PQPKH with the scheme as the data push 01 01 (quantum spec F-1)", "script": (bytes([32]) + pq1 + bytes([0x01, 0x01, OP_CHECKPQSIG])).hex()},
    {"note": "TX_PQPKH with OP_0 as the scheme", "script": (bytes([32]) + pq1 + bytes([0x00, OP_CHECKPQSIG])).hex()},
    {"note": "TX_PQPKH with OP_3 as the scheme", "script": (bytes([32]) + pq1 + bytes([0x53, OP_CHECKPQSIG])).hex()},
    {"note": "TX_PQPKH with OP_16 as the scheme", "script": (bytes([32]) + pq1 + bytes([0x60, OP_CHECKPQSIG])).hex()},
    {"note": "TX_PQPKH with a 31-byte hash", "script": (bytes([31]) + pq1[:31] + bytes([OP_1, OP_CHECKPQSIG])).hex()},
    {"note": "TX_PQPKH with a 33-byte hash", "script": (bytes([33]) + pq1 + b"\x00" + bytes([OP_1, OP_CHECKPQSIG])).hex()},
    {"note": "TX_PQPKH ending in OP_CHECKSIG", "script": (bytes([32]) + pq1 + bytes([OP_1, OP_CHECKSIG])).hex()},
    {"note": "TX_PQPKH with a trailing byte", "script": (bytes([32]) + pq1 + bytes([OP_1, OP_CHECKPQSIG, 0x00])).hex()},
    {"note": "an OP_RETURN", "script": "6a"},
    {"note": "a P2PKH with a 19-byte hash", "script": (bytes([OP_DUP, OP_HASH160, 19]) + h20[:19] + bytes([OP_EQUALVERIFY, OP_CHECKSIG])).hex()},
    {"note": "a bare OP_CHECKPQSIG", "script": "c2"},
    {"note": "empty", "script": ""},
]
# PQ owner addresses (yb…/yt…/yr…): the same payload under the owner versions is NOT a recipient
OWNER = {"mainnet": bytes([0x56, 0xab]), "testnet": bytes([0x57, 0x1e]), "regtest": bytes([0x57, 0x10])}
owner_addresses = {net: b58check(v + bytes([1]) + pq1) for net, v in OWNER.items()}

out = {
    "version": 2,
    "description": "Hawkeye ycashRecipient revision 2 (docs/hawkeye-bridge-plan.md §4.2, HK-5): field bytes, recipient script, recipientHash = SHA256(script), and the Ycash addresses naming each recipient. Derived independently in Python (tests/data/README.md).",
    "valid": valid,
    "invalid": invalid,
    "scriptsInvalid": scripts_invalid,
    "ownerAddressesNotRecipients": {"note": "the PQ owner address (yb…/yt…/yr…) of the scheme-1 pqOwner key: refused as a burn recipient on every network", "addresses": owner_addresses},
}
json.dump(out, open(sys.argv[1], "w"), indent=2)
open(sys.argv[1], "a").write("\n")
for e in valid: print(e["kindName"], e.get("scheme"), e["bytes"][:12], e["script"][:8], e["recipientHash"][:16], e["addresses"])
print(owner_addresses)
