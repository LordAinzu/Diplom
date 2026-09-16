import json
from pathlib import Path
from scripts.generate_snowblind_vectors import generate, reference_verify
from scripts.generate_sbplus_token_vectors import fixtures
from snowblind import curve as ec, protocol as p


def test_reproducible_vector_and_independent_verifier():
    fixture = json.loads((Path(__file__).parent/"fixtures/sbplus.json").read_text())
    assert generate() == fixture
    pk, msg, sig = fixture["public_key"], bytes.fromhex(fixture["message"]), bytes.fromhex(fixture["signature"])
    assert p.verify(pk, msg, sig) and reference_verify(pk, msg, sig)
    assert not p.verify(p.ph(ec.mul(999)), msg, sig)
    for position in (0, 1, 32, 33, 64, 65, 96):
        altered = bytearray(sig)
        altered[position] ^= 1
        assert not p.verify(pk, msg, bytes(altered))
    assert not p.verify(pk, msg, sig[:65]+bytes(32))
    assert not p.verify(pk, msg, sig[:33]+ec.N.to_bytes(32, "big")+sig[65:])


def test_solidity_fixtures_are_reproducible():
    stored = json.loads((Path(__file__).resolve().parents[1]/"test/fixtures/sbplus-token.json").read_text())
    assert fixtures() == stored
