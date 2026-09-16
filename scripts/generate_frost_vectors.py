"""Deterministic PUBLIC TEST FIXTURES, not a production signing implementation.

Independent affine secp256k1 arithmetic with Python integers and hashlib.
Implements RFC 9591 Appendix B single-key Schnorr signing for verifier tests;
it does NOT implement distributed FROST signing or safe nonce management.
The fixed seeds/private scalars/nonces here MUST NEVER be used for real assets.
Run with Python 3.10+: python scripts/generate_frost_vectors.py [--check]
"""

import argparse
import hashlib
import json
from pathlib import Path

P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)
DST = b"FROST-secp256k1-SHA256-v1chal"
ROOT = Path(__file__).resolve().parents[1]


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x1, y1 = a
    x2, y2 = b
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    slope = ((3 * x1 * x1) * pow(2 * y1, -1, P) if a == b
             else (y2 - y1) * pow(x2 - x1, -1, P)) % P
    x3 = (slope * slope - x1 - x2) % P
    return x3, (slope * (x1 - x3) - y1) % P


def multiply(k, point=G):
    result = None
    while k:
        if k & 1:
            result = add(result, point)
        point = add(point, point)
        k >>= 1
    return result


def encode(point):
    x, y = point
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def decode(encoded):
    if len(encoded) != 33 or encoded[0] not in (2, 3):
        raise ValueError("invalid encoding")
    x = int.from_bytes(encoded[1:], "big")
    if x >= P:
        raise ValueError("non-canonical x")
    rhs = (x**3 + 7) % P
    y = pow(rhs, (P + 1) // 4, P)
    if y * y % P != rhs:
        raise ValueError("not on curve")
    if y & 1 != encoded[0] & 1:
        y = P - y
    if y >= P:
        raise ValueError("invalid y")
    return x, y


def challenge(message):
    # Generic XMD loop, deliberately independent of Solidity's two-block reduction.
    dst_prime = DST + bytes([len(DST)])
    b0 = hashlib.sha256(bytes(64) + message + (48).to_bytes(2, "big") + b"\0" + dst_prime).digest()
    previous = hashlib.sha256(b0 + b"\1" + dst_prime).digest()
    blocks = [previous]
    for index in range(2, 3):
        previous = hashlib.sha256(bytes(x ^ y for x, y in zip(b0, previous)) + bytes([index]) + dst_prime).digest()
        blocks.append(previous)
    return int.from_bytes(b"".join(blocks)[:48], "big") % N


def verify(pk, message, signature):
    try:
        if len(signature) != 65:
            return False
        public = decode(pk)
        commitment = decode(signature[:33])
        scalar = int.from_bytes(signature[33:], "big")
        if scalar >= N:
            return False
        c = challenge(signature[:33] + pk + message)
        return multiply(scalar) == add(commitment, multiply(c, public))
    except ValueError:
        return False


def scalar(seed):
    return int.from_bytes(hashlib.sha256(seed.encode()).digest(), "big") % (N - 1) + 1


def fixture(secret, nonce, message):
    pk = encode(multiply(secret))
    r = encode(multiply(nonce))
    c = challenge(r + pk + message)
    signature = r + ((nonce + c * secret) % N).to_bytes(32, "big")
    assert verify(pk, message, signature)
    assert not verify(pk, message + b"\x00", signature)
    return dict(publicKey="0x" + pk.hex(), data="0x" + message.hex(),
                signature="0x" + signature.hex(), challenge="0x" + c.to_bytes(32, "big").hex())


def generate():
    # RFC 9591 Appendix E.5, verbatim final public key/message/aggregate signature.
    official = dict(
        publicKey="0x02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4f",
        data="0x74657374",
        signature="0x0205b6d04d3774c8929413e3c76024d54149c372d57aae62574ed74319b5ea14d0c65dde8492a7471437e6c2fe3da49b90d23f642b5c6dbe7e36089f096dd97324",
    )
    pk, msg, sig = (bytes.fromhex(official[k][2:]) for k in ("publicKey", "data", "signature"))
    assert verify(pk, msg, sig), "Python verifier must pass the official RFC vector"
    official["challenge"] = "0x" + challenge(sig[:33] + pk + msg).to_bytes(32, "big").hex()
    alice = (0xA11CE).to_bytes(20, "big")
    bob = (0xB0B).to_bytes(20, "big")
    messages = [alice, alice]
    messages += [alice + bytes((i * 17 + 11) % 256 for i in range(size - 20)) for size in (256, 1024, 4096)]
    messages += [bob + b"another recipient", b"", bytes(19), bytes(20) + b"zero recipient"]
    secret = scalar("PUBLIC TEST KEY - DO NOT USE")
    cases = [fixture(secret, scalar(f"PUBLIC TEST NONCE {i}"), message) for i, message in enumerate(messages)]
    independent = [fixture(scalar(f"key {i}"), scalar(f"nonce {i}"),
                           bytes((j * 7 + i) % 256 for j in range(size)))
                   for i, size in enumerate((0, 1, 20, 31, 32, 33, 55, 56, 63, 64, 65, 127, 128, 129, 255, 257, 1030))]
    # Differential a*G + b*Q results, including infinity and generator/opposite-generator keys.
    arithmetic = []
    for i, (a, b, q) in enumerate([(0, 0, 1), (0, 1, 1), (1, 0, 1), (1, 1, 1),
                                   (1, 1, N - 1), (0, N - 1, 1), (N - 1, 1, 1),
                                   (N - 1, N - 1, N - 1)] +
                                  [(scalar(f"a {i}"), scalar(f"b {i}"), scalar(f"q {i}")) for i in range(8)]):
        point = add(multiply(a), multiply(b, multiply(q)))
        arithmetic.append(dict(a="0x" + a.to_bytes(32, "big").hex(), b="0x" + b.to_bytes(32, "big").hex(),
                               publicKey="0x" + encode(multiply(q)).hex(),
                               result="0x" + (encode(point).hex() if point else "")))
    return dict(source="https://www.rfc-editor.org/rfc/rfc9591.html#appendix-E.5",
                official=official, cases=cases, independent=independent, arithmetic=arithmetic)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Verify fixtures without writing files")
    args = parser.parse_args()
    content = json.dumps(generate(), indent=2) + "\n"
    path = ROOT / "test" / "fixtures" / "frost-secp256k1.json"
    if args.check:
        assert path.read_text(encoding="utf-8") == content, "Fixtures differ; regenerate them"
        print("RFC vector and deterministic fixtures verified")
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        print(f"Wrote {path}")
