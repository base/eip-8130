// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Reference interface for the EIP-8130 Account Configuration system contract.
interface IAccountConfiguration {
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // STRUCTS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    struct ChangeSequences {
        uint64 multichain; // chain_id 0
        uint64 local; // chain_id == block.chainid; starts at 1 once initialized (created/imported), 0 = uninitialized
    }

    struct ActorConfig {
        address verifier;
        uint8 scope;
        uint48 expiry; // Unix seconds; 0 = no expiry. Actor invalid once block.timestamp > expiry
        uint8 policyType; // 0x00 = none; any non-zero = gated to stored manager (value interpreted by the manager)
    }

    // Minimal actor used for account creation and import (always unrestricted: scope=0x00, policyType=0x00, no expiry).
    struct InitialActor {
        bytes32 actorId;
        address verifier;
    }

    struct Actor {
        bytes32 actorId;
        ActorConfig config;
        // Sliced by policyType: empty (0x00); manager[20] || commitment[32] (non-zero).
        bytes policyData;
    }

    struct ActorChange {
        uint8 changeType; // 0x01 = authorizeActor, 0x02 = revokeActor
        bytes32 actorId;
        bytes data; // operation-specific: ActorConfig || policyData for authorize, empty for revoke
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // EVENTS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    event ActorAuthorized(
        address indexed account,
        bytes32 indexed actorId,
        ActorConfig config,
        address policyManager,
        bytes32 policyCommitment
    );

    event ActorRevoked(address indexed account, bytes32 indexed actorId);

    event AccountCreated(address indexed account, bytes32 userSalt, bytes32 codeHash);

    event AccountImported(address indexed account);

    /// @notice Protocol-injected receipt log for successful EIP-8130 delegation updates (not emitted in EVM).
    event DelegationApplied(address indexed account, address target);

    event AccountLocked(address indexed account, uint16 unlockDelay);

    event AccountUnlockInitiated(address indexed account, uint40 unlocksAt);

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // FUNCTIONS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    function createAccount(bytes32 userSalt, bytes calldata bytecode, InitialActor[] calldata initialActors)
        external
        returns (address);

    function importAccount(address account, InitialActor[] calldata initialActors, bytes calldata signature) external;

    function applySignedActorChanges(
        address account,
        uint64 chainId,
        ActorChange[] calldata actorChanges,
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

    function verifyActor(address account, bytes32 hash, bytes calldata auth) external view returns (uint8 scope);

    // Account creation
    function computeAddress(bytes32 userSalt, bytes calldata bytecode, InitialActor[] calldata initialActors)
        external
        view
        returns (address);

    // ----------------------------------------------------------------------------------------------------------------
    // STORAGE VIEWS
    // ----------------------------------------------------------------------------------------------------------------

    function isActor(address account, bytes32 actorId) external view returns (bool);

    function getActorConfig(address account, bytes32 actorId) external view returns (ActorConfig memory);

    /// @notice Resolves the policy gate target and signed commitment for an actor:
    ///         0x00 -> (address(0), bytes32(0)); non-zero -> (manager, commitment).
    function getPolicy(address account, bytes32 actorId) external view returns (address target, bytes32 commitment);

    function getChangeSequences(address account) external view returns (ChangeSequences memory);

    function isLocked(address account) external view returns (bool);

    function getLockStatus(address account)
        external
        view
        returns (bool locked, bool hasInitiatedUnlock, uint40 unlocksAt, uint16 unlockDelay);
}
