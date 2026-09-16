// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {FrostRewardToken} from "../src/FrostRewardToken.sol";
import {FrostSecp256k1 as Curve} from "../src/crypto/FrostSecp256k1.sol";
import {SnowblindSecp256k1 as SB} from "../src/crypto/SnowblindSecp256k1.sol";
import {SnowFixtures} from "./FrostRewardToken.t.sol";

contract SnowHarness {
    function input(bytes memory pk, bytes memory data, bytes memory r) external pure returns (bytes memory) {
        return SB.challengeInput(pk, data, r);
    }

    function challenge(bytes memory pk, bytes memory data, bytes memory r) external pure returns (uint256) {
        return SB.challenge(pk, data, r);
    }

    function h() external pure returns (bytes memory) { return Curve.encodePoint(SB.HX, SB.HY); }

    function triple(uint256 a, uint256 b, uint256 c, bytes memory q, bytes memory expected) external view returns (bool) {
        (bool ok, uint256 x, uint256 y) = Curve.decodePoint(q);
        require(ok);
        Curve.Point memory point = SB.tripleScalarMul(a, b, c, x, y);
        if (expected.length == 0) return point.z == 0;
        (ok, x, y) = Curve.decodePoint(expected);
        require(ok);
        return Curve.equalsAffine(point, x, y);
    }
}

contract SnowblindVerifierTest is SnowFixtures {
    SnowHarness private sb;

    function setUp() public override {
        super.setUp();
        sb = new SnowHarness();
    }

    function _r(bytes memory signature) private pure returns (bytes memory r) {
        r = new bytes(33);
        for (uint256 i; i < 33; ++i) r[i] = signature[i];
    }

    function _check(string memory path) private view {
        bytes memory key = _bytes(string.concat(path, ".publicKey"));
        bytes memory data = _bytes(string.concat(path, ".data"));
        bytes memory signature = _bytes(string.concat(path, ".signature"));
        require(keccak256(key) == keccak256(token.groupPublicKey()), "fixture key");
        require(token.verifySignature(data, signature), "Python signature");
        require(!token.verifySignature(bytes.concat(data, hex"00"), signature), "modified message");
        require(keccak256(sb.input(key, data, _r(signature))) == keccak256(_bytes(string.concat(path, ".challengeInput"))), "canonical JSON bytes");
        require(sb.challenge(key, data, _r(signature)) == uint256(vm.parseJsonBytes32(fixtures, string.concat(path, ".challenge"))), "Python challenge");
    }

    function testExistingPythonSBPlusVector() public view { _check(".existing"); }

    function testTokenVectorsSerializationAndChallenge() public view {
        for (uint256 i; i < 9; ++i) _check(string.concat(".cases[", vm.toString(i), "]"));
    }

    function testGeneratorAndTripleArithmetic() public view {
        require(keccak256(sb.h()) == keccak256(_bytes(".H")), "Python hash-to-curve H");
        for (uint256 i; i < 8; ++i) {
            string memory path = string.concat(".arithmetic[", vm.toString(i), "]");
            require(sb.triple(
                uint256(vm.parseJsonBytes32(fixtures, string.concat(path, ".a"))),
                uint256(vm.parseJsonBytes32(fixtures, string.concat(path, ".b"))),
                uint256(vm.parseJsonBytes32(fixtures, string.concat(path, ".c"))),
                _bytes(string.concat(path, ".point")), _bytes(string.concat(path, ".result"))
            ), "independent triple arithmetic including infinity");
        }
    }

    function testMalformedLengthsPrefixesAndLegacyFrost() public view {
        (bytes memory data, bytes memory sig) = _case(0);
        require(!token.verifySignature(data, ""), "empty signature");
        require(!token.verifySignature(data, new bytes(96)), "short");
        require(!token.verifySignature(data, bytes.concat(sig, hex"00")), "long");
        string memory old = vm.readFile("test/fixtures/frost-secp256k1.json");
        bytes memory oldData = vm.parseJsonBytes(old, ".cases[0].data");
        bytes memory oldSig = vm.parseJsonBytes(old, ".cases[0].signature");
        require(!token.verifySignature(oldData, oldSig), "old FROST rejected");
        sig[0] = 0x04;
        require(!token.verifySignature(data, sig), "uncompressed");
        sig[0] = 0x00;
        require(!token.verifySignature(data, sig), "infinity encoding");
    }

    function testOffCurveAndNonCanonicalR() public view {
        (bytes memory data,) = _case(0);
        require(!token.verifySignature(data, abi.encodePacked(hex"02", bytes32(Curve.P), bytes32(uint256(1)), bytes32(uint256(1)))), "x=p");
        require(!token.verifySignature(data, abi.encodePacked(hex"03", bytes32(type(uint256).max), bytes32(uint256(1)), bytes32(uint256(1)))), "x>p");
        require(!token.verifySignature(data, abi.encodePacked(hex"02", bytes32(0), bytes32(uint256(1)), bytes32(uint256(1)))), "off curve");
    }

    function testScalarBoundariesAndIncorrectCanonicalScalars() public view {
        (bytes memory data, bytes memory sig) = _case(0);
        bytes memory r = _r(sig);
        uint256 z;
        uint256 y;
        assembly ("memory-safe") {
            z := mload(add(sig, 65))
            y := mload(add(sig, 97))
        }
        require(!token.verifySignature(data, bytes.concat(r, bytes32(Curve.N), bytes32(y))), "z=n");
        require(!token.verifySignature(data, bytes.concat(r, bytes32(type(uint256).max), bytes32(y))), "z>n");
        require(!token.verifySignature(data, bytes.concat(r, bytes32(0), bytes32(y))), "incorrect z=0");
        require(!token.verifySignature(data, bytes.concat(r, bytes32(Curve.N-1), bytes32(y))), "incorrect z=n-1");
        require(!token.verifySignature(data, bytes.concat(r, bytes32(z), bytes32(0))), "y=0");
        require(!token.verifySignature(data, bytes.concat(r, bytes32(z), bytes32(Curve.N))), "y=n");
        require(!token.verifySignature(data, bytes.concat(r, bytes32(z), bytes32(type(uint256).max))), "y>n");
        require(!token.verifySignature(data, bytes.concat(r, bytes32(z), bytes32(Curve.N-1))), "incorrect y=n-1");
    }

    function testWrongPublicKey() public {
        FrostRewardToken other = new FrostRewardToken(Curve.encodePoint(Curve.GX, Curve.GY));
        (bytes memory data, bytes memory sig) = _case(0);
        require(!other.verifySignature(data, sig), "wrong public key");
    }

    function testFuzzChangedSBPlusSignature(uint16 index, uint8 bit) public view {
        (bytes memory data, bytes memory sig) = _case(0);
        sig[uint256(index) % sig.length] ^= bytes1(uint8(1 << (uint256(bit) % 8)));
        require(!token.verifySignature(data, sig), "mutated signature");
    }

    function testRuntimeFitsEip170() public view {
        require(address(token).code.length <= 24576, "runtime code too large");
    }
}
