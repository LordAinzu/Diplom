// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice RFC 9591 section 6.5 verification of aggregate FROST Schnorr signatures.
/// @dev Uses SEC1 compressed points, SHA-256 XMD and the exact RFC challenge.
///      This is neither ECDSA nor BIP-340. No signing secrets enter this library.
library FrostSecp256k1 {
    uint256 internal constant P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f;
    uint256 internal constant N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
    uint256 internal constant GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798;
    uint256 internal constant GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8;

    // Jacobian coordinates: affine x = x/z^2, affine y = y/z^3; z = 0 is infinity.
    struct Point {
        uint256 x;
        uint256 y;
        uint256 z;
    }

    /// @dev Rejects infinity, non-canonical field elements and non-curve points.
    ///      secp256k1 has cofactor one, so an additional subgroup test is unnecessary.
    function decodePoint(bytes memory encoded) internal view returns (bool valid, uint256 x, uint256 y) {
        if (encoded.length != 33) return (false, 0, 0);
        uint8 prefix = uint8(encoded[0]);
        if (prefix != 2 && prefix != 3) return (false, 0, 0);
        assembly ("memory-safe") {
            x := mload(add(encoded, 33))
        }
        if (x >= P) return (false, 0, 0);
        uint256 rhs = addmod(mulmod(mulmod(x, x, P), x, P), 7, P);
        // p = 3 mod 4: sqrt(rhs) = rhs^((p+1)/4), if a root exists.
        uint256[6] memory input = [uint256(32), 32, 32, rhs, (P + 1) / 4, P];
        uint256[1] memory output;
        bool success;
        assembly ("memory-safe") {
            success := staticcall(gas(), 5, input, 192, output, 32)
            success := and(success, eq(returndatasize(), 32))
        }
        y = output[0];
        if (!success || y >= P || mulmod(y, y, P) != rhs) return (false, 0, 0);
        if ((y & 1) != (prefix & 1)) y = P - y;
        if (y >= P) return (false, 0, 0);
        return (true, x, y);
    }

    function encodePoint(uint256 x, uint256 y) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes1(uint8(2 + (y & 1))), bytes32(x));
    }

    /// @dev pkX/pkY MUST already have been validated by decodePoint.
    ///      The token validates its fixed key once, during construction.
    function verify(bytes calldata data, bytes calldata signature, uint256 pkX, uint256 pkY)
        internal
        view
        returns (bool)
    {
        if (signature.length != 65) return false;
        uint256 scalar;
        assembly ("memory-safe") {
            scalar := calldataload(add(signature.offset, 33))
        }
        if (scalar >= N) return false;
        (bool valid, uint256 rx, uint256 ry) = decodePoint(signature[:33]);
        if (!valid) return false;
        uint256 c = challenge(abi.encodePacked(signature[:33], encodePoint(pkX, pkY), data));
        // z*G - c*PK = R. Share the 256 doublings for the two scalar multiplications.
        Point memory result = doubleScalarMul(scalar, c, pkX, P - pkY);
        return equalsAffine(result, rx, ry);
    }

    /// @dev RFC 9380 expand_message_xmd(SHA-256), len_in_bytes=48,
    ///      followed by big-endian reduction to the secp256k1 scalar field.
    function challenge(bytes memory input) internal pure returns (uint256) {
        bytes memory dst = bytes("FROST-secp256k1-SHA256-v1chal");
        bytes memory dstPrime = abi.encodePacked(dst, bytes1(uint8(dst.length)));
        bytes32 b0 = sha256(abi.encodePacked(bytes32(0), bytes32(0), input, hex"003000", dstPrime));
        bytes32 b1 = sha256(abi.encodePacked(b0, hex"01", dstPrime));
        bytes32 b2 = sha256(abi.encodePacked(b0 ^ b1, hex"02", dstPrime));
        return addmod(mulmod(uint256(b1), uint256(1) << 128, N), uint256(b2) >> 128, N);
    }

    /// @dev Simultaneous binary multiplication a*G + b*Q with validated affine Q.
    function doubleScalarMul(uint256 a, uint256 b, uint256 qx, uint256 qy) internal pure returns (Point memory result) {
        for (uint256 bit = 256; bit > 0;) {
            unchecked {
                --bit;
            }
            result = doublePoint(result);
            if (((a >> bit) & 1) != 0) result = addAffine(result, GX, GY);
            if (((b >> bit) & 1) != 0) result = addAffine(result, qx, qy);
        }
    }

    function equalsAffine(Point memory point, uint256 x, uint256 y) internal pure returns (bool) {
        if (point.z == 0) return false;
        uint256 zz = mulmod(point.z, point.z, P);
        return point.x == mulmod(x, zz, P) && point.y == mulmod(y, mulmod(zz, point.z, P), P);
    }

    // Jacobian doubling for a=0: S=4XY^2, M=3X^2,
    // X'=M^2-2S, Y'=M(S-X')-8Y^4, Z'=2YZ.
    function doublePoint(Point memory point) internal pure returns (Point memory result) {
        if (point.z == 0 || point.y == 0) return Point(0, 0, 0);
        uint256 yy = mulmod(point.y, point.y, P);
        uint256 s = mulmod(4, mulmod(point.x, yy, P), P);
        uint256 m = mulmod(3, mulmod(point.x, point.x, P), P);
        result.x = sub(mulmod(m, m, P), mulmod(2, s, P));
        result.y = sub(mulmod(m, sub(s, result.x), P), mulmod(8, mulmod(yy, yy, P), P));
        result.z = mulmod(2, mulmod(point.y, point.z, P), P);
    }

    // Mixed Jacobian-affine addition, including equal and opposite points.
    function addAffine(Point memory point, uint256 x, uint256 y) internal pure returns (Point memory result) {
        if (point.z == 0) return Point(x, y, 1);
        uint256 zz = mulmod(point.z, point.z, P);
        uint256 h = sub(mulmod(x, zz, P), point.x);
        uint256 r = sub(mulmod(y, mulmod(zz, point.z, P), P), point.y);
        if (h == 0) return r == 0 ? doublePoint(point) : Point(0, 0, 0);
        uint256 hh = mulmod(h, h, P);
        uint256 hhh = mulmod(h, hh, P);
        uint256 v = mulmod(point.x, hh, P);
        result.x = sub(sub(mulmod(r, r, P), hhh), mulmod(2, v, P));
        result.y = sub(mulmod(r, sub(v, result.x), P), mulmod(point.y, hhh, P));
        result.z = mulmod(point.z, h, P);
    }

    function sub(uint256 a, uint256 b) private pure returns (uint256) {
        return addmod(a, P - b, P);
    }
}
