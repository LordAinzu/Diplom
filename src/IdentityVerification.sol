// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice Asynchronous relay between users and a trusted identity/signing oracle.
/// @dev Payloads and results are public. Identity and signature checks happen off-chain.
contract IdentityVerification {
    struct Request {
        address requester;
        uint256 expiresAt;
    }

    error ZeroAddress();
    error Unauthorized();
    error UnknownIdentityHash();
    error EmptyPayload();
    error UnknownRequest();
    error InvalidRequestTTL();
    error RequestExpired();
    error RequestNotExpired();
    error InvalidSignedData();

    address public immutable administrator;
    address public immutable oracle;
    uint256 public immutable requestTTL;
    mapping(bytes32 => bool) public identityHashes;
    mapping(uint256 => Request) private requests;
    uint256 public nextRequestId = 1;

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

    /// @param requestTTL_ Request lifetime in seconds; fixed for this deployment.
    constructor(address administrator_, address oracle_, uint256 requestTTL_) {
        if (administrator_ == address(0) || oracle_ == address(0)) revert ZeroAddress();
        if (requestTTL_ == 0) revert InvalidRequestTTL();
        administrator = administrator_;
        oracle = oracle_;
        requestTTL = requestTTL_;
    }

    function setIdentityHash(bytes32 identityHash, bool allowed) external {
        if (msg.sender != administrator) revert Unauthorized();
        identityHashes[identityHash] = allowed;
        emit IdentityHashUpdated(identityHash, allowed);
    }

    /// @return requestId Correlates this request with a later oracle transaction.
    function requestVerification(bytes calldata encryptedIdentity, bytes32 identityHash, bytes calldata blindedData)
        external
        returns (uint256 requestId)
    {
        if (!identityHashes[identityHash]) revert UnknownIdentityHash();
        if (encryptedIdentity.length == 0 || blindedData.length == 0) revert EmptyPayload();

        requestId = nextRequestId++;
        uint256 expiresAt = block.timestamp + requestTTL;
        requests[requestId] = Request(msg.sender, expiresAt);
        emit VerificationRequested(requestId, msg.sender, encryptedIdentity, identityHash, blindedData, expiresAt);
    }

    /// @dev The configured oracle authenticates the response; the contract does not verify its signature bytes.
    function fulfillVerification(uint256 requestId, bool approved, bytes calldata signedData) external {
        if (msg.sender != oracle) revert Unauthorized();
        Request memory request = requests[requestId];
        if (request.requester == address(0)) revert UnknownRequest();
        if (block.timestamp >= request.expiresAt) revert RequestExpired();
        if (approved ? signedData.length == 0 : signedData.length != 0) revert InvalidSignedData();

        delete requests[requestId];
        emit VerificationCompleted(requestId, request.requester, approved, signedData);
    }

    /// @notice Anyone may clear a request at or after its deadline, paying the transaction gas.
    function clearExpiredRequest(uint256 requestId) external {
        Request memory request = requests[requestId];
        if (request.requester == address(0)) revert UnknownRequest();
        if (block.timestamp < request.expiresAt) revert RequestNotExpired();
        delete requests[requestId];
        emit ExpiredRequestCleared(requestId, request.requester);
    }

    /// @notice Returns an outstanding record, including expired records awaiting explicit cleanup.
    /// @dev Completed/cleared requests are absent; their outcome is available only in events.
    function getRequest(uint256 requestId) external view returns (address requester, uint256 expiresAt) {
        Request storage request = requests[requestId];
        if (request.requester == address(0)) revert UnknownRequest();
        return (request.requester, request.expiresAt);
    }
}
