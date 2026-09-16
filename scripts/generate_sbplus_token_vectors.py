"""PUBLIC TEST SECRETS ONLY. Fixtures for Solidity/Python interoperability.

python -m scripts.generate_sbplus_token_vectors [--check]
No production server imports this module.
"""
import argparse
import json
from pathlib import Path
from scripts.generate_snowblind_vectors import generate, reference_verify
from scripts import generate_frost_vectors as ref
from snowblind import curve as ec, protocol as p, wire as w

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "test/fixtures/sbplus-token.json"


def case(vector):
    key, msg, r = vector["public_key"], bytes.fromhex(vector["message"]), vector["R"]
    sig = bytes.fromhex(vector["signature"])
    assert p.verify(key, msg, sig) and reference_verify(key, msg, sig)
    return dict(publicKey="0x"+key, data="0x"+msg.hex(), signature="0x"+sig.hex(),
                challenge="0x"+p.sh(p.challenge(key, msg, r)),
                challengeInput="0x"+w.canonical([key, msg.hex(), r]).hex())


def fixtures():
    old = json.loads((ROOT / "test/fixtures/frost-secp256k1.json").read_text())
    cases = [case(generate(bytes.fromhex(item["data"][2:]), i+1)) for i, item in enumerate(old["cases"])]
    # Original SB+ fixture is consumed as-is, not replaced by newly generated data.
    existing = json.loads((ROOT / "tests_python/fixtures/sbplus.json").read_text())
    arithmetic = []
    neg_g = (ec.G[0], -ec.G[1] % ec.P)
    neg_h = (ec.H[0], -ec.H[1] % ec.P)
    rows = [(0, 0, 0, ec.G), (1, 0, 1, neg_g), (0, 1, 1, neg_h),
            (1, 1, 1, neg_g), (1, 0, 1, ec.G), (0, 1, 1, ec.H),
            (ec.N-1, ec.N-1, ec.N-1, ec.mul(12345)), (0, 0, 1, ec.H)]
    for a, b, c, q in rows:
        result = ref.add(ref.add(ref.multiply(a), ref.multiply(b, ec.H)), ref.multiply(c, q))
        arithmetic.append(dict(a="0x"+p.sh(a), b="0x"+p.sh(b), c="0x"+p.sh(c),
                               point="0x"+p.ph(q), result="0x"+(ref.encode(result).hex() if result else "")))
    return dict(profile=w.VERSION, H="0x"+p.ph(ec.H), existing=case(existing), cases=cases,
                arithmetic=arithmetic)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    result = fixtures()
    if args.check:
        assert json.loads(OUTPUT.read_text()) == result, "token fixture differs"
        print("SB+ token fixtures and independent verification OK")
    else:
        OUTPUT.write_text(json.dumps(result, indent=2)+"\n", encoding="utf-8")
