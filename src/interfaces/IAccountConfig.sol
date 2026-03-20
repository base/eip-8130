// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Reference interface for the EIP-8130 Account Configuration system contract.
interface IAccountConfig {
    struct InitializeOwner {
        address verifier;
        bytes32 ownerId;
        uint8 scope;
    }

    struct OwnerConfig {
        address verifier;
        uint8 scope;
    }

    struct OwnerChange {
        bytes32 ownerId;
        uint8 changeType;
        bytes configData;
    }

    event OwnerAuthorized(address indexed account, bytes32 indexed ownerId, address verifier, uint8 scope);
    event OwnerRevoked(address indexed account, bytes32 indexed ownerId);
    event AccountCreated(address indexed account, bytes32 userSalt, bytes32 codeHash);
    event SequenceConsumed(address indexed account, bool isMultichain, uint64 sequence);
    event AccountLocked(address indexed account, uint24 unlockDelay);
    event AccountUnlockInitiated(address indexed account, uint40 unlocksAt);

    // Account creation
    function createAccount(bytes32 userSalt, bytes calldata bytecode, InitializeOwner[] calldata initialOwners)
        external
        returns (address);
    function computeAddress(bytes32 userSalt, bytes calldata bytecode, InitializeOwner[] calldata initialOwners)
        external
        view
        returns (address);

    // Direct owner management (msg.sender)
    function authorizeOwner(bytes32 ownerId, address verifier, uint8 scope) external;
    function revokeOwner(bytes32 ownerId) external;

    // Authorized owner changes (any owner with CONFIG scope)
    function applyOwnerChanges(
        address account,
        bool isCrossChain,
        OwnerChange[] calldata ownerChanges,
        bytes calldata authorization
    ) external;
    function getChangeSequence(address account, bool isCrossChain) external view returns (uint64);

    // Account lock (msg.sender based)
    function lock(uint24 unlockDelay) external;
    function initiateUnlock() external;

    // Read functions
    function getOwnerConfig(address account, bytes32 ownerId) external view returns (address verifier, uint8 scope);
    function isOwner(address account, bytes32 ownerId) external view returns (bool);
    function isLocked(address account) external view returns (bool);
    function getLockStatus(address account)
        external
        view
        returns (bool locked, bool hasInitiatedUnlock, uint40 unlocksAt, uint24 unlockDelay);

    // Native verifiers
    function getNativeVerifiers()
        external
        view
        returns (address k1, address p256Raw, address p256WebAuthn, address delegate);
    function getVerifierAddress(uint8 verifierType) external view returns (address);

    // Signature verification
    function verifySignature(address account, bytes32 hash, bytes calldata auth)
        external
        view
        returns (bool valid, bytes32 ownerId, address verifier);
}
