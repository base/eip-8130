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
        address authenticator;
        uint8 scope;
        uint48 expiry; // Unix seconds; 0 = no expiry. Actor invalid once block.timestamp > expiry
        uint8 policyType; // 0x00 = none; any non-zero = gated to stored manager (value interpreted by the manager)
    }

    // Minimal actor used for account creation and import (always unrestricted: scope=0x00, policyType=0x00, no expiry).
    struct InitialActor {
        bytes32 actorId;
        address authenticator;
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

    /// @notice Authenticate `auth` (authenticator(20) || data) over `hash` and return the verified actor's
    ///         authorization surface: scope plus its policy gate (sub-type byte and resolved target).
    /// @return scope The scope of the verified actor (0x00 = unrestricted).
    /// @return policyType The actor's policy sub-type byte (0x00 = none).
    /// @return policyTarget The actor's policy gate target, or address(0) if ungated.
    function authenticateActor(address account, bytes32 hash, bytes calldata auth)
        external
        view
        returns (uint8 scope, uint8 policyType, address policyTarget);

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

    /// @notice Resolves an actor's policy sub-type, gate target, and signed commitment:
    ///         0x00 -> (0x00, address(0), bytes32(0)); non-zero -> (policyType, manager, commitment).
    /// @dev Convenience aggregator for off-chain consumers. On-chain consumers (notably the policy manager
    ///      validating a dispatched 8130 tx) should prefer the single-SLOAD `getPolicyCommitment` /
    ///      `getPolicyManager` accessors below.
    function getPolicy(address account, bytes32 actorId)
        external
        view
        returns (uint8 policyType, address target, bytes32 commitment);

    /// @notice Resolves an actor's signed policy commitment, or bytes32(0) if ungated / no actor.
    /// @dev Single SLOAD. The invariant maintained by _authorizeActor/_revokeActor is that this slot is
    ///      non-zero iff the actor has a non-zero policyType, across both the inline-k1 self and the
    ///      _actorConfig homes (manager/commitment share a single keyspace keyed by actorId). Intended for
    ///      the policy manager's per-tx validation read.
    function getPolicyCommitment(address account, bytes32 actorId) external view returns (bytes32);

    /// @notice Resolves an actor's policy gate target (manager), or address(0) if ungated / no actor.
    /// @dev Single SLOAD. Same invariant as `getPolicyCommitment`.
    function getPolicyManager(address account, bytes32 actorId) external view returns (address);

    function getChangeSequences(address account) external view returns (ChangeSequences memory);

    function isLocked(address account) external view returns (bool);

    function getLockStatus(address account)
        external
        view
        returns (bool locked, bool hasInitiatedUnlock, uint40 unlocksAt, uint16 unlockDelay);
}
