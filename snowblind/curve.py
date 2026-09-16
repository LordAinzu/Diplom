"""Readable, variable-time secp256k1 arithmetic and RFC 9380 hash-to-curve.

Not suitable for production secret scalar operations. None is the identity.
"""
import hashlib
import secrets

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    x, y = a
    u, v = b
    if x == u and (y + v) % P == 0:
        return None
    m = ((3*x*x)*pow(2*y, -1, P) if a == b else (v-y)*pow(u-x, -1, P)) % P
    q = (m*m-x-u) % P
    return q, (m*(x-q)-y) % P


def mul(k, point=G):
    k %= N
    result = None
    while k:
        if k & 1:
            result = add(result, point)
        point = add(point, point)
        k >>= 1
    return result


def sum_points(points):
    result = None
    for point in points:
        result = add(result, point)
    return result


def encode(point):
    if point is None:
        raise ValueError("point at infinity")
    return bytes([2 | (point[1] & 1)]) + point[0].to_bytes(32, "big")


def decode(raw):
    if len(raw) != 33 or raw[0] not in (2, 3):
        raise ValueError("invalid SEC1 point")
    x = int.from_bytes(raw[1:], "big")
    if x >= P:
        raise ValueError("noncanonical x")
    rhs = (x**3 + 7) % P
    y = pow(rhs, (P+1)//4, P)
    if y*y % P != rhs:
        raise ValueError("point off curve")
    if y & 1 != raw[0] & 1:
        y = P-y
    return x, y


def scalar(raw):
    if len(raw) != 32 or int.from_bytes(raw, "big") >= N:
        raise ValueError("noncanonical scalar")
    return int.from_bytes(raw, "big")


def sb(k):
    if not 0 <= k < N:
        raise ValueError("scalar out of range")
    return k.to_bytes(32, "big")


def random_scalar():
    return secrets.randbelow(N-1)+1


def xmd(message, dst, length):
    """RFC 9380 5.3.1 expand_message_xmd, SHA-256."""
    if len(dst) > 255 or not 0 < length <= 255*32:
        raise ValueError("unsupported XMD parameters")
    dstp = dst + bytes([len(dst)])
    b0 = hashlib.sha256(bytes(64)+message+length.to_bytes(2, "big")+b"\0"+dstp).digest()
    previous = hashlib.sha256(b0+b"\1"+dstp).digest()
    out = previous
    for i in range(2, (length+31)//32+1):
        previous = hashlib.sha256(bytes(a ^ b for a, b in zip(b0, previous))+bytes([i])+dstp).digest()
        out += previous
    return out[:length]


def hash_scalar(tag, message):
    return int.from_bytes(xmd(message, b"SBPLUS-secp256k1-SHA256-v1/"+tag, 48), "big") % N


# RFC 9380 E.1 coefficients in ascending order.
ISO = [
    [0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa8c7,
     0x7d3d4c80bc321d5b9f315cea7fd44c5d595d2fc0bf63b92dfff1044f17c6581,
     0x534c328d23f234e6e2a413deca25caece4506144037c40314ecbd0b53d9dd262,
     0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa88c],
    [0xd35771193d94918a9ca34ccbb7b640dd86cd409542f8487d9fe6b745781eb49b,
     0xedadc6f64383dc1df7c4b2d51b54225406d36b641f5e41bbc52a56612a8c6d14, 1],
    [0x4bda12f684bda12f684bda12f684bda12f684bda12f684bda12f684b8e38e23c,
     0xc75e0c32d5cb7c0fa9d0a54b12a0a6d5647ab046d686da6fdffc90fc201d71a3,
     0x29a6194691f91a73715209ef6512e576722830a201be2018a765e85a9ecee931,
     0x2f684bda12f684bda12f684bda12f684bda12f684bda12f684bda12f38e38d84],
    [0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffff93b,
     0x7a06534bb8bdb49fd5e9e6632722c2989467c1bfc8e8d978dfb425d2685c2573,
     0x6484aa716545ca2cf3a70c3fa8fe337e0a3d21162f0d6299a7bf8192bfd2a76f, 1],
]


def map_swu(u):
    """RFC 9380 6.6.2, 6.6.3 and E.1 (simple affine formulation)."""
    a = 0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533
    b, z = 1771, -11
    t = (z*z*pow(u, 4, P)+z*u*u) % P
    inv = pow(t, P-2, P)  # inv0(0) = 0
    x = (-b*pow(a, -1, P)*(1+inv)) % P if t else b*pow(z*a, -1, P) % P
    rhs = (x**3+a*x+b) % P
    y = pow(rhs, (P+1)//4, P)
    if y*y % P != rhs:
        x = z*u*u*x % P
        y = pow((x**3+a*x+b) % P, (P+1)//4, P)
    if y & 1 != u & 1:
        y = P-y
    nums = [sum(c*pow(x, i, P) for i, c in enumerate(cs)) % P for cs in ISO]
    if nums[1] == 0 or nums[3] == 0:
        return None
    return nums[0]*pow(nums[1], -1, P) % P, y*nums[2]*pow(nums[3], -1, P) % P


def hash_to_curve(message, dst=b"SBPLUS-v1-H-secp256k1_XMD:SHA-256_SSWU_RO_"):
    uniform = xmd(message, dst, 96)
    return add(*(map_swu(int.from_bytes(uniform[i:i+48], "big") % P) for i in (0, 48)))


H = hash_to_curve(b"independent generator")


def lagrange(i, members):
    result = 1
    for j in members:
        if i != j:
            result = result * j * pow(j-i, -1, N) % N
    return result
