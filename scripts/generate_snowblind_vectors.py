"""PUBLIC, deterministic test secrets only. Never import into a server.

Run: python -m scripts.generate_snowblind_vectors [--check]
SB+ transcript fixture, with an independent final-equation check using the old
affine test implementation and a separate XMD implementation below.
"""
import argparse
import hashlib
import json
from pathlib import Path
from scripts import generate_frost_vectors as ref
from snowblind import curve as ec, protocol as p, wire as w

PATH = Path(__file__).resolve().parents[1]/"tests_python/fixtures/sbplus.json"


def reference_verify(pk, message, signature):
    if len(signature) != 97:
        return False
    r = ref.decode(signature[:33])
    z, y = int.from_bytes(signature[33:65], "big"), int.from_bytes(signature[65:], "big")
    # Independently implement the concrete profile's Hsig.
    data = json.dumps([pk, message.hex(), signature[:33].hex()], sort_keys=True,
                      separators=(",", ":"), ensure_ascii=True).encode("ascii")
    dst = b"SBPLUS-secp256k1-SHA256-v1/signature"
    dp = dst+bytes([len(dst)])
    b0 = hashlib.sha256(bytes(64)+data+b"\x00\x30\x00"+dp).digest()
    b1 = hashlib.sha256(b0+b"\x01"+dp).digest()
    b2 = hashlib.sha256(bytes(x ^ y for x, y in zip(b0, b1))+b"\x02"+dp).digest()
    c = int.from_bytes(b1+b2[:16], "big") % ref.N
    # H is fixed by the profile; RFC vectors separately validate its derivation.
    h = ref.decode(bytes.fromhex("03ad14a1f6bf976ca92f697c80b5d05f23349cdce4b57edf6ea420bb8e75163b69"))
    return 0 < y < ref.N and z < ref.N and ref.add(r, ref.multiply(c*y % ref.N, ref.decode(bytes.fromhex(pk)))) == ref.add(ref.multiply(z), ref.multiply(y, h))


def generate(message=b"SB+ reproducible educational vector", seed=0):
    members = [1, 3]
    pk = p.ph(ec.mul(12345))
    shares = {i: (12345+6789*i) % ec.N for i in members}
    sid = [[1, "11"*32], [3, "33"*32]]
    secrets = {i: dict(a=100+i+seed, b=200+i+seed, y=300+i+seed) for i in members}
    commits = {str(i): dict(A=p.ph(ec.mul(s["a"])), B=p.ph(ec.add(ec.mul(s["b"]), ec.mul(s["y"], ec.H))),
                            cm=p.cm(sid, i, p.sh(s["y"]))) for i, s in secrets.items()}
    alpha, beta, r = 501+seed, 502+seed, 503+seed
    rbar, c = p.blind(pk, message, commits, alpha, beta, r)
    cms = {i: v["cm"] for i, v in commits.items()}
    tr = p.transcript(sid, members, c, cms)
    reveals = {str(i): dict(b=p.sh(s["b"]), y=p.sh(s["y"]), ds=w.sign((bytes([i])*32).hex(), tr))
               for i, s in secrets.items()}
    last_input = {i: {k: v[k] for k in ("y", "ds")} for i, v in reveals.items()}
    total_y = sum(v["y"] for v in secrets.values()) % ec.N
    zs = {i: (secrets[i]["a"]+p.sc(c)*total_y*ec.lagrange(i, members)*shares[i]) % ec.N for i in members}
    pair = bytes.fromhex("ab"*32)
    masks = {str(i): p.masked_share(i, members, zs[i], {j: pair for j in members if i != j}, sid, last_input) for i in members}
    recovered = p.recover_shares(members, masks)
    sig = p.unblind(pk, message, members, commits, reveals, recovered, alpha, beta, r, rbar, c)
    assert reference_verify(pk, message, sig)
    return dict(description="PUBLIC TEST SECRETS: SB+ Fig.4/5, custom v1 encoding profile, not an official vector",
                public_key=pk, message=message.hex(), members=members, ssid=sid,
                alpha=p.sh(alpha), beta=p.sh(beta), r=p.sh(r), R=rbar, c=c,
                commitments=commits, reveals=reveals, masked_responses=masks,
                recovered_shares={i: p.sh(z) for i, z in recovered.items()}, signature=sig.hex())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    data = generate()
    if args.check:
        assert json.loads(PATH.read_text()) == data, "fixture differs"
        print("SB+ fixture and independent verification OK")
    else:
        PATH.parent.mkdir(parents=True, exist_ok=True)
        PATH.write_text(json.dumps(data, indent=2)+"\n", encoding="utf-8")
