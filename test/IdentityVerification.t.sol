// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IdentityVerification} from "../src/IdentityVerification.sol";

// Minimal Foundry cheatcode interface; no third-party test library is required.
interface Vm {
    function prank(address sender) external;
    function warp(uint256 timestamp) external;
    function expectRevert(bytes4 revertData) external;
    function expectEmit(bool topic1, bool topic2, bool topic3, bool data, address emitter) external;
}

contract IdentityVerificationTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address private constant ADMIN = address(0xA11);
    address private constant ORACLE = address(0xB22);
    address private constant ALICE = address(0xC33);
    address private constant BOB = address(0xD44);
    bytes32 private constant HASH = keccak256("canonical identity fixture");
    uint256 private constant START = 1_800_000_000;
    uint256 private constant TTL = 1 days;
    IdentityVerification private target;

    event IdentityHashUpdated(bytes32 indexed identityHash, bool allowed);
    event VerificationRequested(
        uint256 indexed requestId,
        address indexed requester,
        bytes encryptedIdentity,
        bytes32 identityHash,
        bytes blindedData,
        uint256 expiresAt
    );
    event VerificationCompleted(uint256 indexed requestId, address indexed requester, bool approved, bytes signedData);
    event ExpiredRequestCleared(uint256 indexed requestId, address indexed requester);

    function setUp() public {
        vm.warp(START);
        target = new IdentityVerification(ADMIN, ORACLE, TTL);
        vm.prank(ADMIN);
        target.setIdentityHash(HASH, true);
    }

    function testConstructorRoles() public view {
        require(target.administrator() == ADMIN && target.oracle() == ORACLE, "roles");
        require(target.requestTTL() == TTL, "ttl");
    }

    function testRejectZeroAddresses() public {
        vm.expectRevert(IdentityVerification.ZeroAddress.selector);
        new IdentityVerification(address(0), ORACLE, TTL);
        vm.expectRevert(IdentityVerification.ZeroAddress.selector);
        new IdentityVerification(ADMIN, address(0), TTL);
    }

    function testRejectZeroTTL() public {
        vm.expectRevert(IdentityVerification.InvalidRequestTTL.selector);
        new IdentityVerification(ADMIN, ORACLE, 0);
    }

    function testAdminCanRemoveAndAddHash() public {
        vm.expectEmit(true, false, false, true, address(target));
        emit IdentityHashUpdated(HASH, false);
        vm.prank(ADMIN);
        target.setIdentityHash(HASH, false);
        require(!target.identityHashes(HASH), "removed");
        vm.expectEmit(true, false, false, true, address(target));
        emit IdentityHashUpdated(HASH, true);
        vm.prank(ADMIN);
        target.setIdentityHash(HASH, true);
        require(target.identityHashes(HASH), "added");
    }

    function testFuzzOnlyAdminUpdatesRegistry(address caller) public {
        if (caller == ADMIN) return;
        vm.expectRevert(IdentityVerification.Unauthorized.selector);
        vm.prank(caller);
        target.setIdentityHash(HASH, false);
        vm.expectRevert(IdentityVerification.Unauthorized.selector);
        vm.prank(caller);
        target.setIdentityHash(bytes32(uint256(123)), true);
    }

    function testUnknownHashRejected() public {
        vm.expectRevert(IdentityVerification.UnknownIdentityHash.selector);
        target.requestVerification(hex"01", bytes32(uint256(123)), hex"02");
        require(target.nextRequestId() == 1, "no id consumed");
    }

    function testEmptyInputsRejected() public {
        vm.expectRevert(IdentityVerification.EmptyPayload.selector);
        target.requestVerification("", HASH, hex"02");
        vm.expectRevert(IdentityVerification.EmptyPayload.selector);
        target.requestVerification(hex"01", HASH, "");
        vm.expectRevert(IdentityVerification.EmptyPayload.selector);
        target.requestVerification("", HASH, "");
    }

    function testRequestEventAndSequentialIds() public {
        vm.expectEmit(true, true, false, true, address(target));
        emit VerificationRequested(1, ALICE, hex"010203", HASH, hex"040506", START + TTL);
        vm.prank(ALICE);
        uint256 first = target.requestVerification(hex"010203", HASH, hex"040506");
        uint256 second = _request(ALICE);
        require(first == 1 && second == 2 && target.nextRequestId() == 3, "ids");
        _assertPending(first, ALICE, START + TTL);
        _assertPending(second, ALICE, START + TTL);
    }

    function testFuzzOnlyOracleCanRespond(address caller) public {
        if (caller == ORACLE) return;
        uint256 id = _request(ALICE);
        vm.expectRevert(IdentityVerification.Unauthorized.selector);
        vm.prank(caller);
        target.fulfillVerification(id, true, hex"abcd");
        _assertPending(id, ALICE, START + TTL);
    }

    function testApprovalEmitsResultAndDeletesRequest() public {
        uint256 id = _request(ALICE);
        vm.expectEmit(true, true, false, true, address(target));
        emit VerificationCompleted(id, ALICE, true, hex"aabbcc");
        vm.prank(ORACLE);
        target.fulfillVerification(id, true, hex"aabbcc");
        _assertAbsent(id);
    }

    function testRejectionEmitsResultAndDeletesRequest() public {
        uint256 id = _request(ALICE);
        vm.expectEmit(true, true, false, true, address(target));
        emit VerificationCompleted(id, ALICE, false, "");
        vm.prank(ORACLE);
        target.fulfillVerification(id, false, "");
        _assertAbsent(id);
    }

    function testInvalidResponsesLeavePending() public {
        uint256 id = _request(ALICE);
        vm.expectRevert(IdentityVerification.InvalidSignedData.selector);
        vm.prank(ORACLE);
        target.fulfillVerification(id, true, "");
        vm.expectRevert(IdentityVerification.InvalidSignedData.selector);
        vm.prank(ORACLE);
        target.fulfillVerification(id, false, hex"aa");
        _assertPending(id, ALICE, START + TTL);
    }

    function testFuzzUnknownRequestRejected(uint256 id) public {
        // No requests exist after setUp, including id zero.
        vm.expectRevert(IdentityVerification.UnknownRequest.selector);
        vm.prank(ORACLE);
        target.fulfillVerification(id, false, "");
        vm.expectRevert(IdentityVerification.UnknownRequest.selector);
        target.clearExpiredRequest(id);
        _assertAbsent(id);
    }

    function testFuzzCompletedRequestCannotBeChanged(bool approved, bool secondApproval) public {
        uint256 id = _request(ALICE);
        bytes memory result = approved ? bytes(hex"aabb") : bytes(hex"");
        vm.prank(ORACLE);
        target.fulfillVerification(id, approved, result);
        vm.expectRevert(IdentityVerification.UnknownRequest.selector);
        vm.prank(ORACLE);
        target.fulfillVerification(id, secondApproval, secondApproval ? bytes(hex"ccdd") : bytes(hex""));
        vm.warp(START + TTL);
        vm.expectRevert(IdentityVerification.UnknownRequest.selector);
        target.clearExpiredRequest(id);
        _assertAbsent(id);
    }

    function testResponsesCanArriveOutOfOrder() public {
        uint256 first = _request(ALICE);
        uint256 second = _request(BOB);
        uint256 third = _request(ALICE);
        vm.expectEmit(true, true, false, true, address(target));
        emit VerificationCompleted(third, ALICE, true, hex"33");
        vm.prank(ORACLE);
        target.fulfillVerification(third, true, hex"33");
        vm.expectEmit(true, true, false, true, address(target));
        emit VerificationCompleted(second, BOB, false, "");
        vm.prank(ORACLE);
        target.fulfillVerification(second, false, "");
        _assertPending(first, ALICE, START + TTL);
        vm.expectEmit(true, true, false, true, address(target));
        emit VerificationCompleted(first, ALICE, true, hex"11");
        vm.prank(ORACLE);
        target.fulfillVerification(first, true, hex"11");
        _assertAbsent(first);
        _assertAbsent(second);
        _assertAbsent(third);
    }

    function testRemovingHashDoesNotCancelPendingRequest() public {
        uint256 id = _request(ALICE);
        vm.prank(ADMIN);
        target.setIdentityHash(HASH, false);
        vm.expectRevert(IdentityVerification.UnknownIdentityHash.selector);
        target.requestVerification(hex"01", HASH, hex"02");
        vm.prank(ORACLE);
        target.fulfillVerification(id, true, hex"aa");
        _assertAbsent(id);
    }

    function testResponseImmediatelyBeforeDeadlineSucceeds() public {
        uint256 id = _request(ALICE);
        vm.warp(START + TTL - 1);
        vm.prank(ORACLE);
        target.fulfillVerification(id, true, hex"aa");
        _assertAbsent(id);
    }

    function testCleanupImmediatelyBeforeDeadlineRejected() public {
        uint256 id = _request(ALICE);
        vm.warp(START + TTL - 1);
        vm.expectRevert(IdentityVerification.RequestNotExpired.selector);
        target.clearExpiredRequest(id);
        _assertPending(id, ALICE, START + TTL);
    }

    function testResponseAtDeadlineRejectedAndCleanupAllowed() public {
        uint256 id = _request(ALICE);
        vm.warp(START + TTL);
        vm.expectRevert(IdentityVerification.RequestExpired.selector);
        vm.prank(ORACLE);
        target.fulfillVerification(id, true, hex"aa");
        // Expiration does not itself delete the record.
        _assertPending(id, ALICE, START + TTL);
        vm.expectEmit(true, true, false, true, address(target));
        emit ExpiredRequestCleared(id, ALICE);
        vm.prank(BOB);
        target.clearExpiredRequest(id);
        _assertAbsent(id);
    }

    function testFuzzAnyoneCanClearExpiredRequest(address caller, uint32 delay) public {
        uint256 id = _request(ALICE);
        vm.warp(START + TTL + uint256(delay));
        vm.expectRevert(IdentityVerification.RequestExpired.selector);
        vm.prank(ORACLE);
        target.fulfillVerification(id, false, "");
        vm.expectEmit(true, true, false, true, address(target));
        emit ExpiredRequestCleared(id, ALICE);
        vm.prank(caller);
        target.clearExpiredRequest(id);
        _assertAbsent(id);
        vm.expectRevert(IdentityVerification.UnknownRequest.selector);
        target.clearExpiredRequest(id);
        vm.expectRevert(IdentityVerification.UnknownRequest.selector);
        vm.prank(ORACLE);
        target.fulfillVerification(id, true, hex"aa");
    }

    function testCleanupDoesNotAffectNewerRequestOrReuseIds() public {
        uint256 oldId = _request(ALICE);
        vm.warp(START + TTL / 2);
        uint256 newerId = _request(BOB);
        vm.warp(START + TTL);
        target.clearExpiredRequest(oldId);
        _assertPending(newerId, BOB, START + TTL + TTL / 2);
        vm.prank(ORACLE);
        target.fulfillVerification(newerId, true, hex"bb");
        uint256 nextId = _request(ALICE);
        require(oldId == 1 && newerId == 2 && nextId == 3 && target.nextRequestId() == 4, "no id reuse");
        _assertPending(nextId, ALICE, START + 2 * TTL);
        _assertAbsent(oldId);
        _assertAbsent(newerId);
    }

    function _request(address user) private returns (uint256) {
        vm.prank(user);
        return target.requestVerification(hex"010203", HASH, hex"040506");
    }

    function _assertPending(uint256 id, address user, uint256 deadline) private view {
        (address requester, uint256 expiresAt) = target.getRequest(id);
        require(requester == user, "requester");
        require(expiresAt == deadline, "deadline");
    }

    function _assertAbsent(uint256 id) private {
        vm.expectRevert(IdentityVerification.UnknownRequest.selector);
        target.getRequest(id);
    }
}
