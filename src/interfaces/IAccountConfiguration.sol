// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Reference interface for the EIP-8130 Account Configuration system contract.
interface IAccountConfiguration {
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // STRUCTS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    struct ChangeSequences {
        uint64 multichain; // chain_id 0
        uint64 local; // chain_id == block.chainid
    }

    struct OwnerConfig {
        address verifier;
        uint8 scopes;
        uint8 policyType; // 0x00 = none, 0x01 = gated to stored manager; 0x02-0xFF reserved
    }

    struct Owner {
        bytes32 ownerId;
        OwnerConfig config;
        // Sliced by policyType: empty (0x00); manager[20] || commitment[32] (0x01).
        bytes policyData;
    }

    struct OwnerChange {
        bytes32 ownerId;
        uint8 changeType; // 0x01 = authorizeOwner, 0x02 = revokeOwner
        bytes configData; // OwnerConfig for authorize, empty for revoke
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // EVENTS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    event OwnerAuthorized(
        address indexed account,
        bytes32 indexed ownerId,
        OwnerConfig config,
        address policyManager,
        bytes32 policyCommitment
    );

    event OwnerRevoked(address indexed account, bytes32 indexed ownerId);

    event AccountCreated(address indexed account, bytes32 userSalt, bytes32 codeHash);

    event AccountImported(address indexed account);

    /// @notice Protocol-injected receipt log for successful EIP-8130 delegation updates (not emitted in EVM).
    event DelegationApplied(address indexed account, address target);

    event AccountLocked(address indexed account, uint16 unlockDelay);

    event AccountUnlockInitiated(address indexed account, uint40 unlocksAt);

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // FUNCTIONS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    function createAccount(bytes32 userSalt, bytes calldata bytecode, Owner[] calldata initialOwners)
        external
        returns (address);

    function importAccount(address account, Owner[] calldata initialOwners, bytes calldata signature) external;

    function applySignedOwnerChanges(
        address account,
        uint64 chainId,
        OwnerChange[] calldata ownerChanges,
        bytes calldata auth
    ) external;

    function lock(uint16 unlockDelay) external;

    function initiateUnlock() external;

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // VIEW FUNCTIONS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    function verifySignature(address account, bytes32 hash, bytes calldata signature)
        external
        view
        returns (bool verified);

    function verify(address account, bytes32 hash, bytes calldata auth) external view returns (uint8 scopes);

    // Account creation
    function computeAddress(bytes32 userSalt, bytes calldata bytecode, Owner[] calldata initialOwners)
        external
        view
        returns (address);

    // ----------------------------------------------------------------------------------------------------------------
    // STORAGE VIEWS
    // ----------------------------------------------------------------------------------------------------------------

    function isInitialized(address account) external view returns (bool);

    function isOwner(address account, bytes32 ownerId) external view returns (bool);

    function getOwnerConfig(address account, bytes32 ownerId) external view returns (OwnerConfig memory);

    /// @notice Resolves the policy gate target and signed commitment for an owner:
    ///         0x00 -> (address(0), bytes32(0)); 0x01 -> (manager, commitment).
    function getPolicy(address account, bytes32 ownerId) external view returns (address target, bytes32 commitment);

    function getChangeSequences(address account) external view returns (ChangeSequences memory);

    function isLocked(address account) external view returns (bool);

    function getLockStatus(address account)
        external
        view
        returns (bool locked, bool hasInitiatedUnlock, uint40 unlocksAt, uint16 unlockDelay);
}
