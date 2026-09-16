// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {FrostSecp256k1 as Curve} from "./FrostSecp256k1.sol";

/// @notice Final Snowblind SB+ verification for the Python sbplus-demo-v1 profile.
/// @dev Signature = SEC1(R) || z || y. This is NOT the RFC 9591 challenge/format.
library SnowblindSecp256k1 {
    // RFC 9380 hash_to_curve("independent generator") with the Python profile DST.
    uint256 internal constant HX = 0xad14a1f6bf976ca92f697c80b5d05f23349cdce4b57edf6ea420bb8e75163b69;
    uint256 internal constant HY = 0xbd71254f0cbd51e735d67d2685d313bb47017cdd409d53b7d9b8106059397be3;
    bytes16 private constant HEX = "0123456789abcdef";

    /// @dev pkX/pkY must be validated once by the caller during construction.
    function verify(bytes calldata data, bytes calldata signature, uint256 pkX, uint256 pkY)
        internal view returns (bool)
    {
        if (signature.length != 97) return false;
        uint256 z;
        uint256 y;
        assembly ("memory-safe") {
            z := calldataload(add(signature.offset, 33))
            y := calldataload(add(signature.offset, 65))
        }
        if (z >= Curve.N || y == 0 || y >= Curve.N) return false;
        (bool valid, uint256 rx, uint256 ry) = Curve.decodePoint(signature[:33]);
        if (!valid) return false;
        uint256 c = challenge(Curve.encodePoint(pkX, pkY), data, signature[:33]);
        // zG + yH - (c*y mod N)PK = R.
        Curve.Point memory result = tripleScalarMul(z, y, mulmod(c, y, Curve.N), pkX, Curve.P - pkY);
        return Curve.equalsAffine(result, rx, ry);
    }

    /// @dev Exact ASCII JSON produced by canonical([pk, message.hex(), r]) in Python.
    ///      All values are lowercase hex, without 0x, whitespace or a newline.
    function challengeInput(bytes memory key, bytes memory data, bytes memory r) internal pure returns (bytes memory) {
        return abi.encodePacked('["', hexLower(key), '","', hexLower(data), '","', hexLower(r), '"]');
    }

    function challenge(bytes memory key, bytes memory data, bytes memory r) internal pure returns (uint256) {
        bytes memory dst = bytes("SBPLUS-secp256k1-SHA256-v1/signature");
        bytes memory dstPrime = abi.encodePacked(dst, bytes1(uint8(dst.length)));
        bytes32 b0 = sha256(abi.encodePacked(bytes32(0), bytes32(0), challengeInput(key, data, r), hex"003000", dstPrime));
        bytes32 b1 = sha256(abi.encodePacked(b0, hex"01", dstPrime));
        bytes32 b2 = sha256(abi.encodePacked(b0 ^ b1, hex"02", dstPrime));
        return addmod(mulmod(uint256(b1), uint256(1) << 128, Curve.N), uint256(b2) >> 128, Curve.N);
    }

    function hexLower(bytes memory value) private pure returns (bytes memory result) {
        result = new bytes(value.length * 2);
        for (uint256 i; i < value.length; ++i) {
            uint8 b = uint8(value[i]);
            result[2 * i] = HEX[b >> 4];
            result[2 * i + 1] = HEX[b & 15];
        }
    }

    /// @dev Joint multiplication aG + bH + cQ, with validated affine Q.
    function tripleScalarMul(uint256 a, uint256 b, uint256 c, uint256 qx, uint256 qy)
        internal pure returns (Curve.Point memory result)
    {
        for (uint256 bit = 256; bit > 0;) {
            unchecked { --bit; }
            result = Curve.doublePoint(result);
            if (((a >> bit) & 1) != 0) result = Curve.addAffine(result, Curve.GX, Curve.GY);
            if (((b >> bit) & 1) != 0) result = Curve.addAffine(result, HX, HY);
            if (((c >> bit) & 1) != 0) result = Curve.addAffine(result, qx, qy);
        }
    }
}
