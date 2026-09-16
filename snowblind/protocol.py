"""SB Fig. 4 and SB+ Fig. 5 of ePrint 2025/353.

Service signatures are separate from the inner SB transcript signatures.
All secret scalars in persisted state are canonical hex, never JSON numbers.
"""
import hmac
from .curve import N, G, H, add, mul, sum_points, encode, decode, scalar, sb, hash_scalar, lagrange
from .wire import canonical, unhex, check_signature


def sh(k):
    return sb(k).hex()


def sc(s):
    return scalar(unhex(s, 32))


def pt(s):
    return decode(unhex(s, 33))


def ph(p):
    return encode(p).hex()


def cm(sid, i, y):
    return sh(hash_scalar(b"commitment", canonical([sid, i, y])))


def challenge(pk, message, r):
    # Length-delimited canonical structure binds the exact message bytes.
    return hash_scalar(b"signature", canonical([pk, message.hex(), r]))


def transcript(sid, members, c, commitments):
    return ["sb-transcript-v1", sid, members, c, commitments]


def check_reveals(sid, members, c, commitments, reveals, nodes):
    if set(reveals) != {str(i) for i in members} or set(commitments) != set(reveals):
        raise ValueError("incomplete participant set")
    tr = transcript(sid, members, c, commitments)
    for i in members:
        item = reveals[str(i)]
        if sc(item["y"]) == 0 or cm(sid, i, item["y"]) != commitments[str(i)]:
            raise ValueError("invalid commitment opening")
        check_signature(nodes[str(i)]["auth_public"], tr, item["ds"])
    return sum(sc(reveals[str(i)]["y"]) for i in members) % N


def masked_share(i, members, z, pair_keys, sid, last_input):
    """Fig. 5: t separate 32-byte XOR slots, not an additive shortcut."""
    slots = {}
    for j in members:
        slot = bytearray(32)
        for k in members:
            if k != i:
                mask = hmac.digest(pair_keys[k], canonical([sid, j, last_input, members]), "sha256")
                slot = bytearray(a ^ b for a, b in zip(slot, mask))
        if j == i:
            slot = bytearray(a ^ b for a, b in zip(slot, sb(z)))
        slots[str(j)] = bytes(slot).hex()
    return slots


def recover_shares(members, responses):
    expected = {str(i) for i in members}
    if set(responses) != expected:
        raise ValueError("missing final issuer")
    out = {}
    for j in members:
        slot = bytearray(32)
        for i in members:
            if set(responses[str(i)]) != expected:
                raise ValueError("invalid mask slots")
            slot = bytearray(a ^ b for a, b in zip(slot, unhex(responses[str(i)][str(j)], 32)))
        out[str(j)] = scalar(bytes(slot))
    return out


def blind(pk, message, commitments, alpha, beta, r):
    a = sum_points(pt(v["A"]) for v in commitments.values())
    b = sum_points(pt(v["B"]) for v in commitments.values())
    rbar = ph(sum_points([mul(r), mul(alpha*pow(beta, -1, N), a), mul(alpha, b)]))
    return rbar, sh(challenge(pk, message, rbar)*beta % N)


def unblind(pk, message, members, commitments, reveals, shares, alpha, beta, r, rbar, c):
    y = sum(sc(v["y"]) for v in reveals.values()) % N
    b = sum(sc(v["b"]) for v in reveals.values()) % N
    a_point = sum_points(pt(v["A"]) for v in commitments.values())
    b_point = sum_points(pt(v["B"]) for v in commitments.values())
    z = sum(shares.values()) % N
    if b_point != add(mul(b), mul(y, H)) or mul(z) != add(a_point, mul(sc(c)*y, pt(pk))):
        raise ValueError("invalid aggregate response")
    zbar = (r + alpha*z*pow(beta, -1, N) + alpha*b) % N
    signature = unhex(rbar, 33) + sb(zbar) + sb(alpha*y % N)
    if not verify(pk, message, signature):
        raise ValueError("invalid unblinded signature")
    return signature


def verify(pk, message, signature):
    try:
        if len(signature) != 97:
            return False
        r = decode(signature[:33])
        z, y = scalar(signature[33:65]), scalar(signature[65:])
        c = challenge(pk, message, signature[:33].hex())
        return y != 0 and add(r, mul(c*y, pt(pk))) == add(mul(z), mul(y, H))
    except (ValueError, TypeError):
        return False
