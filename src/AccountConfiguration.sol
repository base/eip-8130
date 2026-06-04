// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IAccountConfiguration} from "./interfaces/IAccountConfiguration.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";

/// @notice Account Configuration system contract for EIP-8130.
///         Manages actor authorization, account creation, change sequencing, and account lock.
contract AccountConfiguration is IAccountConfiguration {
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // STRUCTS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @dev Packed into a single storage slot (23 bytes).
    ///      localSequence > 0 doubles as the account initialized flag.
    struct AccountState {
        uint64 multichainSequence; // 8 bytes
        uint64 localSequence; // 8 bytes – also serves as initialized flag
        uint40 unlocksAt; // 5 bytes
        uint16 unlockDelay; // 2 bytes
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // CONSTANTS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    bytes4 constant ERC1271_SELECTOR = bytes4(keccak256("isValidSignature(bytes32,bytes)"));

    /// @dev Typehash for actor initialization, NOT compliant with EIP-712 to mitigate phishing attacks.
    bytes32 public constant ACTOR_INITIALIZATION_TYPEHASH = keccak256(
        "ActorInitialization(bytes32 salt,Actor[] initialActors)Actor(bytes32 actorId,ActorConfig config,bytes policyData)ActorConfig(address verifier,uint8 scope,uint48 expiry,uint8 policyType)"
    );

    /// @dev Typehash for signed actor changes, NOT compliant with EIP-712 to mitigate phishing attacks.
    bytes32 public constant SIGNED_ACTOR_CHANGES_TYPEHASH = keccak256(
        "SignedActorChanges(address account,uint64 chainId,uint64 sequence,ActorChange[] actorChanges)"
        "ActorChange(uint8 changeType,bytes32 actorId,bytes data)"
    );

    // ----------------------------------------------------------------------------------------------------------------
    // ACTOR CHANGE TYPES
    // ----------------------------------------------------------------------------------------------------------------

    /// @notice Authorize an actor to the account
    uint8 public constant AUTHORIZE_ACTOR = 0x01;

    /// @notice Revoke an actor from the account
    uint8 public constant REVOKE_ACTOR = 0x02;

    // ----------------------------------------------------------------------------------------------------------------
    // ACTOR POLICY TYPES
    // ----------------------------------------------------------------------------------------------------------------

    /// @notice No execution policy; actor is ungated.
    uint8 public constant POLICY_NONE = 0x00;

    /// @notice Canonical non-zero policy type. Any non-zero `policyType` gates the actor to its stored
    ///         manager + commitment (self-enforcement is manager == account); the contract does not interpret
    ///         the specific value, leaving it for the manager to read as a sub-type. `0x01` is the value used
    ///         when no sub-type is needed.
    uint8 public constant POLICY_GATED = 0x01;

    // ----------------------------------------------------------------------------------------------------------------
    // ACTOR ELEVATED SCOPES
    // ----------------------------------------------------------------------------------------------------------------

    /// @notice Actor can sign arbitrary messages with account
    uint8 public constant SCOPE_SIGNER = 0x01;

    /// @notice Actor can initiate transactions with account as sender
    uint8 public constant SCOPE_SENDER = 0x02;

    /// @notice Actor can pay for transactions with account as payer
    uint8 public constant SCOPE_PAYER = 0x04;

    /// @notice Actor can change account actors
    uint8 public constant SCOPE_CHANGE_ACTORS = 0x08;

    /// @dev Verifier namespace: 0=implicit EOA, 1=ecrecover EOA, 2..max-1=custom, max=revoked.
    /// @notice Explicit verifier for native EOA signatures via ecrecover.
    address public constant ECRECOVER_VERIFIER = address(1);

    /// @notice Sentinel verifier written on self-actorId revocation to block implicit re-authorization.
    address public constant REVOKED_VERIFIER = address(type(uint160).max);

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // STORAGE
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Per-actor configuration
    /// @dev Account must be inner-most mapping key to pass ERC-7562 storage access rules for ERC-4337 compatibility.
    mapping(bytes32 actorId => mapping(address account => ActorConfig)) internal _actorConfig;

    /// @notice Per-actor signed policy commitment. Set when policyType != 0x00.
    /// @dev Read only during execution (via getPolicy), never during signature validity checks.
    mapping(bytes32 actorId => mapping(address account => bytes32)) internal _policyCommitment;

    /// @notice Per-actor policy manager address. Set when policyType != 0x00.
    mapping(bytes32 actorId => mapping(address account => address)) internal _policyManager;

    /// @notice Per-account state: sequences, lock status (single slot per account)
    mapping(address account => AccountState) internal _accountState;

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // MODIFIERS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    modifier onlyUnlocked(address account) {
        if (_isLockedSideEffects(account)) revert();
        _;
    }

    modifier nonZero(address account) {
        require(account != address(0));
        _;
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // FUNCTIONS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Deploy a new account with initial actors configured using safe defaults.
    ///         Initial actors are always unrestricted (scope = 0x00).
    function createAccount(bytes32 userSalt, bytes calldata bytecode, Actor[] calldata initialActors)
        external
        returns (address account)
    {
        account = computeAddress(userSalt, bytecode, initialActors);

        // Initialize account actors (reverts naturally on duplicate via _authorizeActor)
        _initializeAccount(account, initialActors);

        // Create account code
        bytes memory deploymentCode = _buildDeploymentCode(bytecode);
        bytes32 deploymentSalt = _computeActorInitializationDigest(userSalt, initialActors);
        assembly {
            pop(create2(0, add(deploymentCode, 0x20), mload(deploymentCode), deploymentSalt))
        }
        emit AccountCreated(account, userSalt, keccak256(bytecode));
    }

    /// @notice Import an existing account to AccountConfiguration management.
    /// @dev Verifies via ERC-1271. Accounts must have bytecode.
    /// @dev Custom hash used to partially mitigate phishing attacks on eth_signTypedData.
    function importAccount(address account, Actor[] calldata initialActors, bytes calldata signature) external {
        require(_accountState[account].localSequence == 0);
        _accountState[account].localSequence = 1;

        bytes32 digest = _computeActorInitializationDigest(bytes32(bytes20(account)), initialActors);
        (bool success, bytes memory result) =
            account.staticcall(abi.encodeWithSelector(ERC1271_SELECTOR, digest, signature));
        require(success && result.length == 32 && abi.decode(result, (bytes4)) == ERC1271_SELECTOR);

        _initializeAccount(account, initialActors);
        emit AccountImported(account);
    }

    /// @notice Apply actor changes (actor management only).
    ///         Direct verification via verifier + actor_config, isValidSignature fallback for migration.
    function applySignedActorChanges(
        address account,
        uint64 chainId,
        ActorChange[] calldata actorChanges,
        bytes calldata auth
    ) external onlyUnlocked(account) {
        require(chainId == 0 || chainId == block.chainid);

        // Increment the corresponding sequence
        uint64 sequence =
            chainId == 0 ? _accountState[account].multichainSequence++ : _accountState[account].localSequence++;

        // Compute digest and verify
        bytes32 digest = _computeSignedActorChangesDigest(account, chainId, sequence, actorChanges);
        uint8 scope = verifyActor(account, digest, auth);

        // Require actor has scope to change actors (scope == 0 means unrestricted)
        require(scope == 0 || scope & SCOPE_CHANGE_ACTORS != 0);

        // Apply actorChanges
        for (uint256 i; i < actorChanges.length; i++) {
            if (actorChanges[i].changeType == AUTHORIZE_ACTOR) {
                (ActorConfig memory newActorConfig, bytes memory policyData) =
                    abi.decode(actorChanges[i].data, (ActorConfig, bytes));
                _authorizeActor(account, actorChanges[i].actorId, newActorConfig, policyData);
            } else if (actorChanges[i].changeType == REVOKE_ACTOR) {
                _revokeActor(account, actorChanges[i].actorId);
            } else {
                revert();
            }
        }
    }

    // ----------------------------------------------------------------------------------------------------------------
    // ACCOUNT LOCKS
    // ----------------------------------------------------------------------------------------------------------------

    /// @notice Lock the account to freeze actor configuration.
    /// @param unlockDelay The delay in seconds before the account can be unlocked (capped at ~18 hours).
    function lock(uint16 unlockDelay) external onlyUnlocked(msg.sender) {
        // Require non-zero unlock delay
        require(unlockDelay > 0);

        AccountState storage config = _accountState[msg.sender];

        config.unlocksAt = type(uint40).max;
        config.unlockDelay = unlockDelay;
        emit AccountLocked(msg.sender, unlockDelay);
    }

    /// @notice Initiate unlock of the account after delay has passed.
    function initiateUnlock() external {
        AccountState storage config = _accountState[msg.sender];

        // Require account is locked and unlock has not been initiated
        require(config.unlocksAt == type(uint40).max);

        config.unlocksAt = uint40(block.timestamp + config.unlockDelay);
        config.unlockDelay = 0;
        emit AccountUnlockInitiated(msg.sender, config.unlocksAt);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // VIEW FUNCTIONS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Verify an account bytes signature in verifier(20) || data format.
    /// @dev Designed for easy account integration with ERC-1271.
    /// @return verified True if the signature is valid.
    function verifySignature(address account, bytes32 hash, bytes calldata signature)
        external
        view
        returns (bool verified)
    {
        uint8 scope = verifyActor(account, hash, signature);
        return scope == 0 || scope & SCOPE_SIGNER != 0;
    }

    /// @notice Verify an account approved a hash using auth in verifier(20) || data format.
    /// @return scope The scope of the verified actor (0x00 = unrestricted).
    function verifyActor(address account, bytes32 hash, bytes calldata auth) public view returns (uint8 scope) {
        require(auth.length >= 20);
        return _verify(account, hash, address(bytes20(auth[:20])), auth[20:]);
    }

    /// @notice Compute the counterfactual address for an account.
    function computeAddress(bytes32 userSalt, bytes calldata bytecode, Actor[] calldata initialActors)
        public
        view
        returns (address)
    {
        bytes32 deploymentSalt = _computeActorInitializationDigest(userSalt, initialActors);
        bytes32 codeHash = keccak256(_buildDeploymentCode(bytecode));
        bytes32 create2Hash = keccak256(abi.encodePacked(bytes1(0xFF), address(this), deploymentSalt, codeHash));
        return address(uint160(uint256(create2Hash)));
    }

    // ----------------------------------------------------------------------------------------------------------------
    // STORAGE VIEWS
    // ----------------------------------------------------------------------------------------------------------------

    function isInitialized(address account) public view returns (bool) {
        return _accountState[account].localSequence > 0;
    }

    function isActor(address account, bytes32 actorId) public view returns (bool) {
        address verifier = _actorConfig[actorId][account].verifier;
        if (verifier >= ECRECOVER_VERIFIER && verifier != REVOKED_VERIFIER) return true;
        // Implicit EOA: self-actorId with truly empty slot
        return verifier == address(0) && actorId == bytes32(bytes20(account));
    }

    function getActorConfig(address account, bytes32 actorId) external view returns (ActorConfig memory) {
        return _actorConfig[actorId][account];
    }

    /// @notice Resolves the policy gate target and signed commitment for an actor.
    /// @dev Enforcement is at execution: this resolves where a policy-bearing actor may call and the commitment a
    ///      target validates presented parameters against. 0x00 -> (0, 0); non-zero -> (manager, commitment).
    function getPolicy(address account, bytes32 actorId) external view returns (address target, bytes32 commitment) {
        if (_actorConfig[actorId][account].policyType == POLICY_NONE) return (address(0), bytes32(0));
        return (_policyManager[actorId][account], _policyCommitment[actorId][account]);
    }

    function getChangeSequences(address account) external view returns (ChangeSequences memory) {
        AccountState storage state = _accountState[account];
        return ChangeSequences({multichain: state.multichainSequence, local: state.localSequence});
    }

    function isLocked(address account) external view returns (bool) {
        return block.timestamp < _accountState[account].unlocksAt;
    }

    function getLockStatus(address account)
        external
        view
        returns (bool locked, bool hasInitiatedUnlock, uint40 unlocksAt, uint16 unlockDelay)
    {
        AccountState storage config = _accountState[account];
        return (
            block.timestamp < config.unlocksAt, // locked if current time is before unlocksAt
            config.unlocksAt != 0 && config.unlocksAt != type(uint40).max, // hasInitiatedUnlock if unlocksAt non-zero and not max
            config.unlocksAt,
            config.unlockDelay
        );
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // INTERNAL FUNCTIONS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Returns true if the account is locked and clears storage if unlocked
    /// @dev Side effects to clear locked state
    function _isLockedSideEffects(address account) internal returns (bool locked) {
        // Early return if account is locked
        uint40 unlocksAt = _accountState[account].unlocksAt;
        if (block.timestamp < unlocksAt) return true;

        // Account is unlocked, clear storage if non-zero
        if (unlocksAt != 0) _accountState[account].unlocksAt = 0;
        return false;
    }

    // ----------------------------------------------------------------------------------------------------------------
    // ACTOR CHANGES
    // ----------------------------------------------------------------------------------------------------------------

    function _initializeAccount(address account, Actor[] calldata initialActors) internal nonZero(account) {
        // Must have at least one initial actor
        require(initialActors.length > 0);

        bytes32 previousActorId;
        for (uint256 i; i < initialActors.length; i++) {
            // Enforce sorting with relative comparison of sequential actor ids
            require(initialActors[i].actorId > previousActorId);
            previousActorId = initialActors[i].actorId;

            _authorizeActor(account, initialActors[i].actorId, initialActors[i].config, initialActors[i].policyData);
        }
    }

    function _authorizeActor(address account, bytes32 actorId, ActorConfig memory config, bytes memory policyData)
        internal
        nonZero(account)
    {
        require(config.verifier >= ECRECOVER_VERIFIER && config.verifier != REVOKED_VERIFIER);
        address existing = _actorConfig[actorId][account].verifier;
        require(existing == address(0) || existing == REVOKED_VERIFIER);

        // A policy-bearing actor must be scope-restricted and may not hold CONFIG scope: the policy gate only
        // covers SENDER-context calls, so a CONFIG-scoped (or unrestricted) key could authorize new, unrestricted
        // actors and escape its policy entirely.
        if (config.policyType != POLICY_NONE) {
            require(config.scope != 0 && config.scope & SCOPE_CHANGE_ACTORS == 0);
        }

        _actorConfig[actorId][account] = config;

        // Slice and store the signed policy by policyType. The commitment is opaque to the protocol.
        (address manager, bytes32 commitment) = _slicePolicy(config.policyType, policyData);
        if (commitment != bytes32(0)) _policyCommitment[actorId][account] = commitment;
        if (manager != address(0)) _policyManager[actorId][account] = manager;

        emit ActorAuthorized(account, actorId, config, manager, commitment);
    }

    /// @dev Validates `policyData` against `policyType` and returns (manager, commitment).
    ///      0x00: empty data -> (0, 0). Any non-zero value: manager[20] || commitment[32] -> (manager, commitment).
    ///      Length mismatches revert. The protocol does not interpret the specific non-zero value; self-enforcement
    ///      is expressed as manager == account.
    function _slicePolicy(uint8 policyType, bytes memory policyData)
        internal
        pure
        returns (address manager, bytes32 commitment)
    {
        if (policyType == POLICY_NONE) {
            require(policyData.length == 0);
        } else {
            require(policyData.length == 52);
            assembly ("memory-safe") {
                manager := shr(96, mload(add(policyData, 0x20)))
                commitment := mload(add(policyData, 0x34))
            }
            require(manager != address(0) && commitment != bytes32(0));
        }
    }

    function _revokeActor(address account, bytes32 actorId) internal nonZero(account) {
        require(isActor(account, actorId));
        if (actorId == bytes32(bytes20(account))) {
            _actorConfig[actorId][account] =
                ActorConfig({verifier: REVOKED_VERIFIER, scope: 0, expiry: 0, policyType: POLICY_NONE});
        } else {
            delete _actorConfig[actorId][account];
        }
        // Policy state is keyed by (account, actorId) and cleared exactly on revoke.
        delete _policyCommitment[actorId][account];
        delete _policyManager[actorId][account];
        emit ActorRevoked(account, actorId);
    }

    function _computeActorInitializationDigest(bytes32 salt, Actor[] calldata initialActors)
        internal
        pure
        returns (bytes32)
    {
        // Hash each actor
        bytes32[] memory initializeActorHashes = new bytes32[](initialActors.length);
        for (uint256 i; i < initialActors.length; i++) {
            initializeActorHashes[i] = keccak256(
                abi.encode(initialActors[i].actorId, initialActors[i].config, keccak256(initialActors[i].policyData))
            );
        }

        // Hash cumulative initialization data
        return
            keccak256(
                abi.encode(ACTOR_INITIALIZATION_TYPEHASH, salt, keccak256(abi.encodePacked(initializeActorHashes)))
            );
    }

    function _computeSignedActorChangesDigest(
        address account,
        uint64 chainId,
        uint64 sequence,
        ActorChange[] calldata actorChanges
    ) internal pure returns (bytes32) {
        // Hash each actor change
        bytes32[] memory actorChangeHashes = new bytes32[](actorChanges.length);
        for (uint256 i; i < actorChanges.length; i++) {
            actorChangeHashes[i] = keccak256(abi.encode(actorChanges[i]));
        }

        // Hash the batch of actor changes
        return keccak256(
            abi.encode(
                SIGNED_ACTOR_CHANGES_TYPEHASH, account, chainId, sequence, keccak256(abi.encodePacked(actorChangeHashes))
            )
        );
    }

    // ----------------------------------------------------------------------------------------------------------------
    // VERIFICATION
    // ----------------------------------------------------------------------------------------------------------------

    function _verify(address account, bytes32 hash, address verifier, bytes calldata data)
        internal
        view
        returns (uint8 scope)
    {
        if (verifier == address(0)) return _verifyImplicitEOA(account, hash, data);
        if (verifier == ECRECOVER_VERIFIER) return _verifyEcrecover(account, hash, data);
        require(verifier != REVOKED_VERIFIER);

        bytes32 actorId = IVerifier(verifier).verify(hash, data);
        require(actorId != bytes32(0));

        ActorConfig memory config = _actorConfig[actorId][account];
        require(config.verifier == verifier);
        // Expiry is read from the same slot; an expired actor fails authentication. 0 = no expiry.
        require(config.expiry == 0 || block.timestamp <= config.expiry);
        return config.scope;
    }

    /// @dev Implicit EOA: native ecrecover, requires self-actorId slot to be empty.
    function _verifyImplicitEOA(address account, bytes32 hash, bytes calldata data) internal view returns (uint8) {
        require(_actorConfig[bytes32(bytes20(account))][account].verifier == address(0));
        address recovered = _recoverSigner(hash, data);
        require(recovered == account);
        return 0;
    }

    /// @dev Explicit EOA actor via native ecrecover verifier (address(1)).
    function _verifyEcrecover(address account, bytes32 hash, bytes calldata data) internal view returns (uint8) {
        address recovered = _recoverSigner(hash, data);
        require(recovered != address(0));

        bytes32 actorId = bytes32(bytes20(recovered));
        ActorConfig memory config = _actorConfig[actorId][account];
        require(config.verifier == ECRECOVER_VERIFIER);
        // Expiry is read from the same slot; an expired actor fails authentication. 0 = no expiry.
        require(config.expiry == 0 || block.timestamp <= config.expiry);
        return config.scope;
    }

    function _recoverSigner(bytes32 hash, bytes calldata data) internal pure returns (address recovered) {
        require(data.length == 65);
        bytes32 r = bytes32(data[:32]);
        bytes32 s = bytes32(data[32:64]);
        return ecrecover(hash, uint8(data[64]), r, s);
    }

    // ----------------------------------------------------------------------------------------------------------------
    // ACCOUNT CREATION
    // ----------------------------------------------------------------------------------------------------------------

    /// @notice Constructs the deployment code for an account in a manner that doesn't immediately run constructor code.
    /// @dev Constructs DEPLOYMENT_HEADER(n) || bytecode. The 14-byte EVM loader
    ///      copies trailing bytecode into memory and returns it.
    function _buildDeploymentCode(bytes calldata bytecode) internal pure returns (bytes memory code) {
        // Bytecode must be less than 65536 bytes
        uint256 n = bytecode.length;
        require(n <= 0xFFFF);

        // Construct the deployment code with 14-byte header then provided bytecode
        code = new bytes(14 + n);
        code[0] = 0x61; //  PUSH2
        code[1] = bytes1(uint8(n >> 8));
        code[2] = bytes1(uint8(n));
        code[3] = 0x60; //  PUSH1
        code[4] = 0x0E; //  14 (offset)
        code[5] = 0x60; //  PUSH1
        code[6] = 0x00; //  0 (mem dest)
        code[7] = 0x39; //  CODECOPY
        code[8] = 0x61; //  PUSH2
        code[9] = bytes1(uint8(n >> 8));
        code[10] = bytes1(uint8(n));
        code[11] = 0x60; // PUSH1
        code[12] = 0x00; // 0 (mem offset)
        code[13] = 0xF3; // RETURN

        // Append the provided bytecode
        for (uint256 i; i < n; i++) {
            code[14 + i] = bytecode[i];
        }
        return code;
    }
}
