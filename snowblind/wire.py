"""Versioned canonical transcripts, authenticated envelopes and encryption."""
import hashlib
import json
import secrets
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from Crypto.Hash import keccak

VERSION = "sbplus-demo-v1"


def canonical(value):
    def check(v):
        if v is None or type(v) in (str, bool):
            return
        if type(v) is int and abs(v) < 2**53:
            return
        if isinstance(v, list):
            for x in v:
                check(x)
            return
        if isinstance(v, dict) and all(type(k) is str for k in v):
            for x in v.values():
                check(x)
            return
        raise ValueError("unsupported transcript type; scalars must be hex strings")
    check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def unhex(s, length=None):
    if not isinstance(s, str) or s != s.lower() or len(s) % 2:
        raise ValueError("expected lowercase hex")
    b = bytes.fromhex(s)
    if b.hex() != s or (length is not None and len(b) != length):
        raise ValueError("invalid hex length or encoding")
    return b


def identity_hash(data):
    return keccak.new(digest_bits=256, data=data).hexdigest()


def new_ed():
    return ed25519.Ed25519PrivateKey.generate().private_bytes_raw().hex()


def new_x():
    return x25519.X25519PrivateKey.generate().private_bytes_raw().hex()


def ed_public(private):
    return ed25519.Ed25519PrivateKey.from_private_bytes(unhex(private, 32)).public_key().public_bytes_raw().hex()


def x_public(private):
    return x25519.X25519PrivateKey.from_private_bytes(unhex(private, 32)).public_key().public_bytes_raw().hex()


def sign(private, value):
    return ed25519.Ed25519PrivateKey.from_private_bytes(unhex(private, 32)).sign(canonical(value)).hex()


def check_signature(public, value, signature):
    ed25519.Ed25519PublicKey.from_public_bytes(unhex(public, 32)).verify(unhex(signature, 64), canonical(value))


def envelope(private, group, sender, kind, body):
    value = dict(version=VERSION, group=group, sender=sender, kind=kind, body=body)
    return dict(value=value, signature=sign(private, value))


def open_envelope(packet, public, group, sender, kind):
    value = packet["value"]
    check_signature(public, value, packet["signature"])
    if (value["version"], value["group"], value["sender"], value["kind"]) != (VERSION, group, sender, kind):
        raise ValueError("wrong envelope context")
    return value["body"]


def derive(shared, context):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=canonical([VERSION, context])).derive(shared)


def encrypt(public, plaintext, context):
    ephemeral = x25519.X25519PrivateKey.generate()
    pub = ephemeral.public_key().public_bytes_raw().hex()
    shared = ephemeral.exchange(x25519.X25519PublicKey.from_public_bytes(unhex(public, 32)))
    nonce = secrets.token_bytes(12)
    aad = canonical([VERSION, context, pub])
    cipher = ChaCha20Poly1305(derive(shared, context)).encrypt(nonce, plaintext, aad)
    return dict(ephemeral=pub, nonce=nonce.hex(), ciphertext=cipher.hex())


def decrypt(private, packet, context):
    secret = x25519.X25519PrivateKey.from_private_bytes(unhex(private, 32))
    shared = secret.exchange(x25519.X25519PublicKey.from_public_bytes(unhex(packet["ephemeral"], 32)))
    aad = canonical([VERSION, context, packet["ephemeral"]])
    return ChaCha20Poly1305(derive(shared, context)).decrypt(
        unhex(packet["nonce"], 12), unhex(packet["ciphertext"]), aad)


def pair_key(private, peer_public, group, i, j):
    shared = x25519.X25519PrivateKey.from_private_bytes(unhex(private, 32)).exchange(
        x25519.X25519PublicKey.from_public_bytes(unhex(peer_public, 32)))
    return derive(shared, ["sbplus-pair", group, min(i, j), max(i, j)])


def identity_context(group, request, hashed):
    return ["identity", group, request, hashed]
