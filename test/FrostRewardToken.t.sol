// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {FrostRewardToken} from "../src/FrostRewardToken.sol";
import {FrostSecp256k1 as Frost} from "../src/crypto/FrostSecp256k1.sol";

interface VmFrost {
    function prank(address sender) external;
    function expectRevert(bytes4 reason) external;
    function expectEmit(bool topic1, bool topic2, bool topic3, bool data, address emitter) external;
    function readFile(string calldata path) external view returns (string memory);
    function parseJsonBytes(string calldata json, string calldata key) external pure returns (bytes memory);
    function parseJsonBytes32(string calldata json, string calldata key) external pure returns (bytes32);
    function toString(uint256 value) external pure returns (string memory);
}

contract FrostHarness {
    function verify(bytes calldata key, bytes calldata data, bytes calldata sig) external view returns (bool) {
        (bool ok, uint256 x, uint256 y) = Frost.decodePoint(key);
        return ok && Frost.verify(data, sig, x, y);
    }

    function challenge(bytes memory input) external pure returns (uint256) {
        return Frost.challenge(input);
    }

    function decode(bytes memory key) external view returns (bool, uint256, uint256) {
        return Frost.decodePoint(key);
    }

    function joint(uint256 a, uint256 b, bytes memory q, bytes memory expected) external view returns (bool) {
        (bool ok, uint256 x, uint256 y) = Frost.decodePoint(q);
        require(ok, "fixture key");
        Frost.Point memory result = Frost.doubleScalarMul(a, b, x, y);
        if (expected.length == 0) return result.z == 0;
        (ok, x, y) = Frost.decodePoint(expected);
        require(ok, "fixture result");
        return Frost.equalsAffine(result, x, y);
    }

    function doublePoint(Frost.Point memory point) external pure returns (Frost.Point memory) {
        return Frost.doublePoint(point);
    }

    function addAffine(Frost.Point memory point, uint256 x, uint256 y) external pure returns (Frost.Point memory) {
        return Frost.addAffine(point, x, y);
    }
}

abstract contract FrostFixtures {
    VmFrost internal constant vm = VmFrost(address(uint160(uint256(keccak256("hevm cheat code")))));
    address internal constant ALICE = address(0xA11CE);
    address internal constant BOB = address(0xB0B);
    address internal constant RELAYER = address(0xCA11);
    string internal fixtures;
    FrostRewardToken internal token;
    FrostHarness internal harness;

    function setUp() public virtual {
        fixtures = vm.readFile("test/fixtures/frost-secp256k1.json");
        token = new FrostRewardToken(_bytes(".cases[0].publicKey"));
        harness = new FrostHarness();
    }

    function _bytes(string memory path) internal view returns (bytes memory) {
        return vm.parseJsonBytes(fixtures, path);
    }

    function _case(uint256 index) internal view returns (bytes memory data, bytes memory sig) {
        string memory path = string.concat(".cases[", vm.toString(index), "]");
        return (_bytes(string.concat(path, ".data")), _bytes(string.concat(path, ".signature")));
    }

    function _claim(uint256 index) internal {
        (bytes memory data, bytes memory sig) = _case(index);
        token.claim(data, sig);
    }
}

contract FrostVerifierTest is FrostFixtures {
    function testOfficialRfc9591VectorAndChallenge() public view {
        bytes memory key = _bytes(".official.publicKey");
        bytes memory data = _bytes(".official.data");
        bytes memory sig = _bytes(".official.signature");
        require(harness.verify(key, data, sig), "RFC aggregate signature");
        bytes memory r = new bytes(33);
        for (uint256 i; i < 33; ++i) {
            r[i] = sig[i];
        }
        uint256 expected = uint256(vm.parseJsonBytes32(fixtures, ".official.challenge"));
        require(harness.challenge(bytes.concat(r, key, data)) == expected, "RFC challenge");
    }

    function testIndependentPythonSignaturesAndChallenges() public view {
        for (uint256 i; i < 17; ++i) {
            string memory path = string.concat(".independent[", vm.toString(i), "]");
            bytes memory key = _bytes(string.concat(path, ".publicKey"));
            bytes memory data = _bytes(string.concat(path, ".data"));
            bytes memory sig = _bytes(string.concat(path, ".signature"));
            require(harness.verify(key, data, sig), "independent signature");
            bytes memory r = new bytes(33);
            for (uint256 j; j < 33; ++j) {
                r[j] = sig[j];
            }
            require(
                harness.challenge(bytes.concat(r, key, data))
                    == uint256(vm.parseJsonBytes32(fixtures, string.concat(path, ".challenge"))),
                "independent challenge"
            );
            require(!harness.verify(key, bytes.concat(data, hex"00"), sig), "modified message");
        }
    }

    function testIndependentJointMultiplicationAndInfinityCases() public view {
        for (uint256 i; i < 16; ++i) {
            string memory path = string.concat(".arithmetic[", vm.toString(i), "]");
            uint256 a = uint256(vm.parseJsonBytes32(fixtures, string.concat(path, ".a")));
            uint256 b = uint256(vm.parseJsonBytes32(fixtures, string.concat(path, ".b")));
            require(
                harness.joint(a, b, _bytes(string.concat(path, ".publicKey")), _bytes(string.concat(path, ".result"))),
                "independent point arithmetic"
            );
        }
    }

    function testPointOperationsInNonUnitProjectiveCoordinates() public view {
        uint256 scale = 7;
        Frost.Point memory g = Frost.Point(
            mulmod(Frost.GX, scale * scale, Frost.P), mulmod(Frost.GY, scale * scale * scale, Frost.P), scale
        );
        Frost.Point memory doubled = harness.doublePoint(g);
        Frost.Point memory added = harness.addAffine(g, Frost.GX, Frost.GY);
        require(doubled.x == added.x && doubled.y == added.y && doubled.z == added.z, "equal points double");
        Frost.Point memory opposite = harness.addAffine(g, Frost.GX, Frost.P - Frost.GY);
        require(opposite.z == 0, "opposite points cancel");
        Frost.Point memory identity = harness.doublePoint(Frost.Point(0, 0, 0));
        require(identity.z == 0, "double infinity");
        identity = harness.doublePoint(Frost.Point(1, 0, 1));
        require(identity.z == 0, "zero-y branch");
        Frost.Point memory restored = harness.addAffine(opposite, Frost.GX, Frost.GY);
        require(restored.x == Frost.GX && restored.y == Frost.GY && restored.z == 1, "infinity plus G");
    }

    function testWrongKeyAndChangedRecipientFail() public view {
        (bytes memory data, bytes memory sig) = _case(0);
        require(!harness.verify(_bytes(".official.publicKey"), data, sig), "different key");
        data[19] = bytes1(uint8(data[19]) ^ 1);
        require(!harness.verify(_bytes(".cases[0].publicKey"), data, sig), "different recipient");
    }

    function testFuzzChangedSignatureFails(uint8 index, uint8 bit) public view {
        (bytes memory data, bytes memory sig) = _case(0);
        sig[uint256(index) % sig.length] ^= bytes1(uint8(1 << (uint256(bit) % 8)));
        require(!harness.verify(_bytes(".cases[0].publicKey"), data, sig), "mutated signature accepted");
    }

    function testMalformedSignatureLengthsAndPrefixes() public view {
        (bytes memory data, bytes memory sig) = _case(0);
        require(!harness.verify(_bytes(".cases[0].publicKey"), data, ""), "empty");
        require(!harness.verify(_bytes(".cases[0].publicKey"), data, new bytes(64)), "short");
        require(!harness.verify(_bytes(".cases[0].publicKey"), data, bytes.concat(sig, hex"00")), "long");
        sig[0] = 0x04;
        require(!harness.verify(_bytes(".cases[0].publicKey"), data, sig), "uncompressed prefix");
        sig[0] = 0x00;
        require(!harness.verify(_bytes(".cases[0].publicKey"), data, sig), "infinity encoding");
    }

    function testNonCanonicalAndOffCurveCommitments() public view {
        (bytes memory data,) = _case(0);
        require(!harness.verify(_bytes(".cases[0].publicKey"), data, abi.encodePacked(hex"02", bytes32(Frost.P), bytes32(uint256(1)))), "x=p");
        require(
            !harness.verify(_bytes(".cases[0].publicKey"), data, abi.encodePacked(hex"03", bytes32(type(uint256).max), bytes32(uint256(1)))),
            "x>p"
        );
        // x=0 gives rhs=7, a quadratic non-residue modulo secp256k1's field prime.
        require(!harness.verify(_bytes(".cases[0].publicKey"), data, abi.encodePacked(hex"02", bytes32(0), bytes32(uint256(1)))), "off-curve R");
    }

    function testScalarBoundariesAreNotReduced() public view {
        (bytes memory data, bytes memory sig) = _case(0);
        bytes memory r = new bytes(33);
        for (uint256 i; i < 33; ++i) {
            r[i] = sig[i];
        }
        require(!harness.verify(_bytes(".cases[0].publicKey"), data, bytes.concat(r, bytes32(Frost.N))), "z=n");
        require(!harness.verify(_bytes(".cases[0].publicKey"), data, bytes.concat(r, bytes32(type(uint256).max))), "z>n");
        require(!harness.verify(_bytes(".cases[0].publicKey"), data, bytes.concat(r, bytes32(0))), "wrong zero scalar");
        require(!harness.verify(_bytes(".cases[0].publicKey"), data, bytes.concat(r, bytes32(Frost.N - 1))), "wrong n-1 scalar");
    }

    function testMalformedKeysRejectedAtDeployment() public {
        _badKey("");
        _badKey(new bytes(32));
        _badKey(new bytes(34));
        _badKey(abi.encodePacked(hex"04", bytes32(Frost.GX)));
        _badKey(abi.encodePacked(hex"00", bytes32(0)));
        _badKey(abi.encodePacked(hex"02", bytes32(Frost.P)));
        _badKey(abi.encodePacked(hex"02", bytes32(0)));
        (bool valid,,) = harness.decode(abi.encodePacked(hex"03", bytes32(Frost.GX)));
        require(valid, "odd-y valid point");
    }

    function _badKey(bytes memory key) private {
        vm.expectRevert(FrostRewardToken.InvalidPublicKey.selector);
        new FrostRewardToken(key);
    }
}

abstract contract SnowFixtures is FrostFixtures {
    function setUp() public virtual override {
        fixtures = vm.readFile("test/fixtures/sbplus-token.json");
        token = new FrostRewardToken(_bytes(".cases[0].publicKey"));
    }
}

contract FrostRewardTokenTest is SnowFixtures {
    event Transfer(address indexed from, address indexed to, uint256 value);
    event RewardClaimed(bytes32 indexed dataHash, address indexed recipient, uint256 amount);

    function testMetadataAndFixedKey() public view {
        require(keccak256(bytes(token.name())) == keccak256("Frost Reward"), "name");
        require(keccak256(bytes(token.symbol())) == keccak256("FRT"), "symbol");
        require(token.decimals() == 18 && token.REWARD_AMOUNT() == 1e18, "units");
        require(token.totalSupply() == 0, "initial supply");
        require(keccak256(token.groupPublicKey()) == keccak256(_bytes(".cases[0].publicKey")), "public key");
    }

    function testClaimByRelayerMintsToSignedRecipientAndEmitsEvents() public {
        (bytes memory data, bytes memory sig) = _case(0);
        vm.expectEmit(true, true, false, true, address(token));
        emit Transfer(address(0), ALICE, 1e18);
        vm.expectEmit(true, true, false, true, address(token));
        emit RewardClaimed(keccak256(data), ALICE, 1e18);
        vm.prank(RELAYER);
        token.claim(data, sig);
        require(token.balanceOf(ALICE) == 1e18 && token.balanceOf(RELAYER) == 0, "recipient");
        require(token.totalSupply() == 1e18 && token.usedDataHashes(keccak256(data)), "issued");
        require(token.verifySignature(data, sig), "verification remains valid after redemption");
    }

    function testSameDataCannotBeClaimedWithSameOrNewSignature() public {
        (bytes memory data, bytes memory sig) = _case(0);
        (bytes memory sameData, bytes memory otherSig) = _case(1);
        require(keccak256(data) == keccak256(sameData) && keccak256(sig) != keccak256(otherSig), "fixture");
        require(token.verifySignature(sameData, otherSig), "second signature valid");
        token.claim(data, sig);
        vm.expectRevert(FrostRewardToken.DataAlreadyUsed.selector);
        token.claim(data, sig);
        vm.expectRevert(FrostRewardToken.DataAlreadyUsed.selector);
        vm.prank(BOB);
        token.claim(sameData, otherSig);
        require(token.totalSupply() == 1e18, "single issuance");
    }

    function testDistinctDataAndRecipientsCanClaim() public {
        _claim(0);
        _claim(2);
        _claim(5);
        require(token.totalSupply() == 3e18, "supply");
        require(token.balanceOf(ALICE) == 2e18 && token.balanceOf(BOB) == 1e18, "balances");
    }

    function testInvalidSignatureDoesNotConsumeDataOrMint() public {
        (bytes memory data, bytes memory sig) = _case(0);
        vm.expectRevert(FrostRewardToken.InvalidSignature.selector);
        token.claim(data, hex"00");
        require(!token.usedDataHashes(keccak256(data)) && token.totalSupply() == 0, "atomic failure");
        token.claim(data, sig);
        require(token.balanceOf(ALICE) == 1e18, "valid retry");
    }

    function testSignedShortAndZeroRecipientMessagesCannotClaim() public {
        for (uint256 i = 6; i <= 8; ++i) {
            (bytes memory data, bytes memory sig) = _case(i);
            require(token.verifySignature(data, sig), "signature-only verification");
            vm.expectRevert(i == 8 ? FrostRewardToken.InvalidRecipient.selector : FrostRewardToken.InvalidData.selector);
            token.claim(data, sig);
            require(!token.usedDataHashes(keccak256(data)), "not consumed");
        }
        require(token.totalSupply() == 0, "no mint");
    }

    function testRecipientCannotBeReplacedBySubmitter() public {
        (bytes memory data, bytes memory sig) = _case(0);
        bytes memory stolenData = abi.encodePacked(RELAYER);
        vm.expectRevert(FrostRewardToken.InvalidSignature.selector);
        vm.prank(RELAYER);
        token.claim(stolenData, sig);
        vm.prank(RELAYER);
        token.claim(data, sig);
        require(token.balanceOf(RELAYER) == 0 && token.balanceOf(ALICE) == 1e18, "front-run cannot redirect");
    }

    function testErc20TransferAndAllowance() public {
        _claim(0);
        vm.prank(ALICE);
        require(token.transfer(BOB, 0.25e18), "transfer");
        vm.prank(ALICE);
        require(token.approve(RELAYER, 0.5e18), "approve");
        vm.prank(RELAYER);
        require(token.transferFrom(ALICE, BOB, 0.5e18), "transferFrom");
        require(token.balanceOf(ALICE) == 0.25e18 && token.balanceOf(BOB) == 0.75e18, "balances");
        require(token.allowance(ALICE, RELAYER) == 0 && token.totalSupply() == 1e18, "allowance and supply");
    }

    function testSameKeyOnAnotherDeploymentAllowsAnotherClaim() public {
        // Documents the intentionally absent cross-contract domain binding.
        FrostRewardToken other = new FrostRewardToken(token.groupPublicKey());
        (bytes memory data, bytes memory sig) = _case(0);
        token.claim(data, sig);
        other.claim(data, sig);
        require(token.balanceOf(ALICE) == 1e18 && other.balanceOf(ALICE) == 1e18, "separate redemption domains");
    }
}

contract FrostGasTest is SnowFixtures {
    event log_named_uint(string key, uint256 value);

    function testGas20Bytes() public {
        _measure(0);
    }

    function testGas256Bytes() public {
        _measure(2);
    }

    function testGas1024Bytes() public {
        _measure(3);
    }

    function testGas4096Bytes() public {
        _measure(4);
    }

    function _measure(uint256 index) private {
        (bytes memory data, bytes memory sig) = _case(index);
        uint256 beforeVerify = gasleft();
        bool valid = token.verifySignature(data, sig);
        uint256 verifyGas = beforeVerify - gasleft();
        require(valid, "valid benchmark signature");
        uint256 beforeClaim = gasleft();
        token.claim(data, sig);
        uint256 claimGas = beforeClaim - gasleft();
        emit log_named_uint("data bytes", data.length);
        emit log_named_uint("verify call gas", verifyGas);
        emit log_named_uint("claim call gas", claimGas);
    }
}
