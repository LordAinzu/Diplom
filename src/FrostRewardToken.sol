// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {FrostSecp256k1} from "./crypto/FrostSecp256k1.sol";

/// @notice Mints one FRT for each distinct message authorized by the fixed FROST group key.
/// @dev data = 20 raw recipient address bytes || arbitrary payload. No prehash or Ethereum prefix.
contract FrostRewardToken is ERC20 {
    error InvalidPublicKey();
    error InvalidData();
    error InvalidRecipient();
    error DataAlreadyUsed();
    error InvalidSignature();

    uint256 public constant REWARD_AMOUNT = 1e18;
    uint256 private immutable publicKeyX;
    uint256 private immutable publicKeyY;
    mapping(bytes32 => bool) public usedDataHashes;

    event RewardClaimed(bytes32 indexed dataHash, address indexed recipient, uint256 amount);

    constructor(bytes memory groupPublicKey_) ERC20("Frost Reward", "FRT") {
        (bool valid, uint256 x, uint256 y) = FrostSecp256k1.decodePoint(groupPublicKey_);
        if (!valid) revert InvalidPublicKey();
        publicKeyX = x;
        publicKeyY = y;
    }

    function groupPublicKey() external view returns (bytes memory) {
        return FrostSecp256k1.encodePoint(publicKeyX, publicKeyY);
    }

    /// @notice Cryptographic validity only: does not enforce recipient or one-time claim rules.
    function verifySignature(bytes calldata data, bytes calldata signature) public view returns (bool) {
        return FrostSecp256k1.verify(data, signature, publicKeyX, publicKeyY);
    }

    /// @notice Anyone can submit a claim, but only the signed recipient receives the tokens.
    function claim(bytes calldata data, bytes calldata signature) external {
        if (data.length < 20) revert InvalidData();
        address recipient = address(bytes20(data[:20]));
        if (recipient == address(0)) revert InvalidRecipient();
        bytes32 dataHash = keccak256(data);
        if (usedDataHashes[dataHash]) revert DataAlreadyUsed();
        if (!verifySignature(data, signature)) revert InvalidSignature();
        usedDataHashes[dataHash] = true;
        _mint(recipient, REWARD_AMOUNT);
        emit RewardClaimed(dataHash, recipient, REWARD_AMOUNT);
    }
}
