// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IVerifier} from "./verifiers/IVerifier.sol";

/// @notice Account Configuration system contract for EIP-8130.
///         Manages owner authorization, account creation, change sequencing, and account lock.
contract AccountConfiguration {
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // STRUCTS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    struct AccountConfig {
        uint64 globalChangeSequence; // chain_id 0
        uint64 localChangeSequence; // chain_id == block.chainid
        uint40 unlocksAt;
        uint24 unlockDelay;
    }

    struct OwnerConfig {
        address verifier;
        uint8 scope; // 0x00 = unrestricted
    }

    struct OwnerChange {
        bytes32 ownerId;
        uint8 changeType; // 0x01 = authorizeOwner, 0x02 = revokeOwner
        bytes configData; // OwnerConfig for authorize, empty for revoke
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // CONSTANTS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @dev Sentinel for the self-ownerId (ownerId == bytes32(bytes20(account))) to distinguish
    ///      "explicitly revoked" from "never registered" (address(0)), which would re-trigger the
    ///      implicit EOA authorization rule. Non-self ownerIds are deleted back to address(0).
    address constant REVOKED = address(type(uint160).max);

    /// @dev ERC-1271 selector for isValidSignature function.
    bytes4 constant ERC1271_IS_VALID_SIGNATURE = bytes4(keccak256("isValidSignature(bytes32,bytes)"));

    /// @dev Typehash for OwnerChangeBatch, NOT compliant with EIP-712 to mitigate phishing attacks.
    bytes32 constant OWNER_CHANGE_BATCH_TYPEHASH = keccak256(
        "OwnerChangeBatch(address account,uint64 chainId,uint64 sequence,OwnerChange[] ownerChanges)"
        "OwnerChange(bytes32 ownerId,uint8 changeType,bytes changeData)"
    );

    // ----------------------------------------------------------------------------------------------------------------
    // OPERATIONS
    // ----------------------------------------------------------------------------------------------------------------

    uint8 constant OP_AUTHORIZE_OWNER = 0x01;
    uint8 constant OP_REVOKE_OWNER = 0x02;

    // ----------------------------------------------------------------------------------------------------------------
    // SCOPES
    // ----------------------------------------------------------------------------------------------------------------

    uint8 constant SCOPE_SIGNATURE = 0x01;
    uint8 constant SCOPE_SENDER = 0x02;
    uint8 constant SCOPE_PAYER = 0x04;
    uint8 constant SCOPE_CONFIG = 0x08;

    // ----------------------------------------------------------------------------------------------------------------
    // NATIVE VERIFIERS
    // ----------------------------------------------------------------------------------------------------------------

    address public immutable K1_VERIFIER; // 0x01
    address public immutable P256_RAW_VERIFIER; // 0x02
    address public immutable P256_WEBAUTHN_VERIFIER; // 0x03
    address public immutable DELEGATE_VERIFIER; // 0x04

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // STORAGE
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    mapping(address account => AccountConfig) internal _accountConfigs;

    /// @dev Account must be inner-most mapping key to pass ERC-7562 storage access rules for ERC-4337 compatibility.
    mapping(bytes32 ownerId => mapping(address account => OwnerConfig)) internal _ownerConfigs;

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // EVENTS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    event AccountCreated(address indexed account, bytes32 userSalt, bytes32 codeHash);
    event OwnerAuthorized(address indexed account, bytes32 indexed ownerId, address verifier, uint8 scope);
    event OwnerRevoked(address indexed account, bytes32 indexed ownerId);
    event SequenceConsumed(address indexed account, bool isMultichain, uint64 sequence);
    event AccountLocked(address indexed account, uint24 unlockDelay);
    event AccountUnlockInitiated(address indexed account, uint40 unlocksAt);

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // MODIFIERS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    modifier onlyUnlocked(address account) {
        uint40 unlocksAt = _accountConfigs[account].unlocksAt;
        if (block.timestamp < unlocksAt) revert();
        // reset lock storage if we have passed unlocksAt
        _accountConfigs[account].unlocksAt = 0;
        _;
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // FUNCTIONS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    constructor(address k1, address p256Raw, address p256WebAuthn, address delegate) {
        K1_VERIFIER = k1;
        P256_RAW_VERIFIER = p256Raw;
        P256_WEBAUTHN_VERIFIER = p256WebAuthn;
        DELEGATE_VERIFIER = delegate;
    }

    /// @notice Deploy a new account with initial owners configured using safe defaults.
    ///         Initial owners are always unrestricted (scope = 0x00).
    function createAccount(bytes32 userSalt, bytes calldata bytecode, AddOwner[] calldata initialOwners)
        external
        returns (address account)
    {
        account = getAddress(userSalt, bytecode, initialOwners);
        if (account.code.length > 0) return account;

        require(initialOwners.length > 0);

        bytes32 previousOwnerId;
        for (uint256 i; i < initialOwners.length; i++) {
            require(initialOwners[i].ownerId > previousOwnerId);
            previousOwnerId = initialOwners[i].ownerId;
            _authorizeOwner(account, initialOwners[i].ownerId, initialOwners[i].verifier, initialOwners[i].scope);
        }

        // Create account
        bytes memory deploymentCode = _buildDeploymentCode(bytecode);
        bytes32 effectiveSalt = _computeEffectiveSalt(userSalt, initialOwners);
        assembly {
            pop(create2(0, add(deploymentCode, 0x20), mload(deploymentCode), effectiveSalt))
        }
        emit AccountCreated(account, userSalt, keccak256(bytecode));
    }

    // ----------------------------------------------------------------------------------------------------------------
    // OWNER CHANGES
    // ----------------------------------------------------------------------------------------------------------------

    /// @notice Authorize an owner to the account.
    function authorizeOwner(bytes32 ownerId, address verifier, uint8 scope) external onlyUnlocked(msg.sender) {
        _authorizeOwner(msg.sender, ownerId, verifier, scope);
    }

    /// @notice Revoke an owner from the account.
    function revokeOwner(bytes32 ownerId) external onlyUnlocked(msg.sender) {
        _revokeOwner(msg.sender, ownerId);
    }

    /// @notice Apply owner changes (owner management only).
    ///         Direct verification via verifier + owner_config, isValidSignature fallback for migration.
    function applyOwnerChanges(
        address account,
        bool isCrossChain,
        OwnerChange[] calldata ownerChanges,
        bytes calldata authorization
    ) external onlyUnlocked(account) {
        // Increment sequence
        uint64 sequence = isCrossChain
            ? _accountConfigs[account].globalChangeSequence++
            : _accountConfigs[account].localChangeSequence++;

        // Compute digest and verify signature
        // Verification only works in context of verifiers so that compute to applying account ownerChanges can be bounded before validating transaction payment
        bytes32 digest =
            _computeOwnerChangeBatchDigest(account, isCrossChain ? 0 : block.chainid, sequence, ownerChanges);
        (bool valid,,) = _verify(account, digest, authorization, SCOPE_CONFIG);
        require(valid);

        // Apply ownerChanges
        for (uint256 i; i < ownerChanges.length; i++) {
            if (ownerChanges[i].changeType == OP_AUTHORIZE_OWNER) {
                OwnerConfig memory config = abi.decode(ownerChanges[i].configData, (OwnerConfig));
                _authorizeOwner(account, ownerChanges[i].ownerId, config.verifier, config.scope);
            } else if (ownerChanges[i].changeType == OP_REVOKE_OWNER) {
                _revokeOwner(account, ownerChanges[i].ownerId);
            } else {
                revert();
            }
        }
        emit SequenceConsumed(account, isCrossChain, sequence);
    }

    // ----------------------------------------------------------------------------------------------------------------
    // ACCOUNT LOCKS
    // ----------------------------------------------------------------------------------------------------------------

    /// @notice Lock the account to freeze owner configuration. Anyone can call; authorization via signature.
    function lock(uint24 unlockDelay) external onlyUnlocked(msg.sender) {
        AccountConfig storage config = _accountConfigs[msg.sender];
        config.unlocksAt = type(uint40).max;
        config.unlockDelay = unlockDelay;
        emit AccountLocked(msg.sender, unlockDelay);
    }

    /// @notice Request to unlock the account. Starts the timelock.
    function initiateUnlock() external {
        AccountConfig storage config = _accountConfigs[msg.sender];
        require(config.unlocksAt == type(uint40).max);
        config.unlocksAt = uint40(block.timestamp + config.unlockDelay);
        config.unlockDelay = 0;
        emit AccountUnlockInitiated(msg.sender, config.unlocksAt);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // VIEW FUNCTIONS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Verify a signature against an account using the type-byte format.
    ///         Checks SIGNATURE scope (0x01). Includes the implicit EOA authorization rule.
    function verifySignature(address account, bytes32 hash, bytes calldata auth)
        external
        view
        returns (bool valid, bytes32 ownerId, address verifier)
    {
        return _verify(account, hash, auth, SCOPE_SIGNATURE);
    }

    /// @notice Compute the counterfactual address for an account.
    function computeAddress(bytes32 userSalt, bytes calldata bytecode, AddOwner[] calldata initialOwners)
        external
        view
        returns (address)
    {
        bytes32 effectiveSalt = _computeEffectiveSalt(userSalt, initialOwners);
        bytes32 codeHash = keccak256(_buildDeploymentCode(bytecode));
        bytes32 create2Hash = keccak256(abi.encodePacked(bytes1(0xFF), address(this), effectiveSalt, codeHash));
        return address(uint160(uint256(create2Hash)));
    }

    // ----------------------------------------------------------------------------------------------------------------
    // STORAGE VIEWS
    // ----------------------------------------------------------------------------------------------------------------

    function isOwner(address account, bytes32 ownerId) external view returns (bool) {
        address verifier = _ownerConfigs[account][ownerId].verifier;
        return verifier != address(0) && verifier != REVOKED;
    }

    function getOwnerConfig(address account, bytes32 ownerId) external view returns (address verifier, uint8 scope) {
        return _getEffectiveOwnerConfig(account, ownerId);
    }

    function getChangeSequence(address account, bool isCrossChain) external view returns (uint64) {
        AccountConfig storage config = _accountConfigs[account];
        return isCrossChain ? config.globalChangeSequence : config.localChangeSequence;
    }

    function isLocked(address account) external view returns (bool) {
        return block.timestamp < _accountConfigs[account].unlocksAt;
    }

    function getLockStatus(address account)
        external
        view
        returns (bool locked, bool hasInitiatedUnlock, uint40 unlocksAt, uint24 unlockDelay)
    {
        AccountConfig storage config = _accountConfigs[account];
        return (
            block.timestamp < config.unlocksAt,
            config.unlocksAt != type(uint40).max,
            config.unlocksAt,
            config.unlockDelay
        );
    }

    // ----------------------------------------------------------------------------------------------------------------
    // NATIVE VERIFIERS
    // ----------------------------------------------------------------------------------------------------------------

    function getNativeVerifiers()
        external
        pure
        returns (address k1, address p256Raw, address p256WebAuthn, address delegate)
    {
        return (K1_VERIFIER, P256_RAW_VERIFIER, P256_WEBAUTHN_VERIFIER, DELEGATE_VERIFIER);
    }

    function getVerifierAddress(uint8 verifierType) public pure returns (address) {
        if (verifierType == 0x01) return K1_VERIFIER;
        if (verifierType == 0x02) return P256_RAW_VERIFIER;
        if (verifierType == 0x03) return P256_WEBAUTHN_VERIFIER;
        if (verifierType == 0x04) return DELEGATE_VERIFIER;
        return address(0);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // INTERNAL FUNCTIONS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @dev Returns the effective verifier and scope for an owner, applying the implicit EOA rule.
    ///      REVOKED sentinel (self-ownerId only) → (address(0), 0).
    ///      Empty slot + implicit EOA eligible → (K1_VERIFIER, 0x00).
    function _getEffectiveOwnerConfig(address account, bytes32 ownerId)
        internal
        view
        returns (address verifier, uint8 scope)
    {
        OwnerConfig storage config = _ownerConfigs[account][ownerId];
        verifier = config.verifier;
        scope = config.scope;
        if (verifier == REVOKED) return (address(0), 0);
        if (verifier == address(0) && ownerId == bytes32(bytes20(account))) return (K1_VERIFIER, 0x00);
    }

    // ----------------------------------------------------------------------------------------------------------------
    // VERIFICATION
    // ----------------------------------------------------------------------------------------------------------------

    /// @dev Core verification with scope context checking.
    ///      Parses verifier type, calls verifier, checks owner_config, and validates scope.
    function _verify(address account, bytes32 hash, bytes calldata auth, uint8 contextBit)
        internal
        view
        returns (bool valid, bytes32 ownerId, address verifier)
    {
        require(auth.length >= 1);
        uint8 verifierType = uint8(auth[0]);
        bytes calldata data;

        if (verifierType == 0x00) {
            require(auth.length >= 21);
            verifier = address(bytes20(auth[1:21]));
            data = auth[21:];
        } else {
            verifier = getVerifierAddress(verifierType);
            data = auth[1:];
        }

        if (verifier == address(0)) return (false, bytes32(0), address(0));

        ownerId = IVerifier(verifier).verify(hash, data);
        if (ownerId == bytes32(0)) return (false, bytes32(0), verifier);

        OwnerConfig storage config = _ownerConfigs[account][ownerId];
        address registeredVerifier = config.verifier;
        uint8 scope = config.scope;

        if (registeredVerifier == verifier) {
            valid = scope == 0x00 || (scope & contextBit) != 0;
        } else if (registeredVerifier == address(0) && ownerId == bytes32(bytes20(account)) && verifier == K1_VERIFIER)
        {
            // Implicit EOA: unrestricted scope (0x00)
            valid = true;
        }
    }

    /// @dev Calls isValidSignature (ERC-1271) on the account for authorization.
    function _requireIsValidSignature(address account, bytes32 digest, bytes calldata signature) internal view {
        require(account.code.length > 0);
        (bool success, bytes memory result) =
            account.staticcall(abi.encodeWithSelector(ERC1271_IS_VALID_SIGNATURE, digest, signature));
        require(success && result.length >= 32);
        require(abi.decode(result, (bytes4)) == ERC1271_IS_VALID_SIGNATURE);
    }

    // ----------------------------------------------------------------------------------------------------------------
    // ACCOUNT CREATION
    // ----------------------------------------------------------------------------------------------------------------

    function _computeEffectiveSalt(bytes32 userSalt, AddOwner[] calldata initialOwners)
        internal
        pure
        returns (bytes32)
    {
        bytes memory ownersPacked;
        for (uint256 i; i < initialOwners.length; i++) {
            ownersPacked = abi.encodePacked(ownersPacked, initialOwners[i]);
        }
        return keccak256(abi.encodePacked(userSalt, keccak256(ownersPacked)));
    }

    /// @dev Constructs DEPLOYMENT_HEADER(n) || bytecode. The 14-byte EVM loader
    ///      copies trailing bytecode into memory and returns it.
    function _buildDeploymentCode(bytes calldata bytecode) internal pure returns (bytes memory) {
        uint256 n = bytecode.length;
        require(n <= 0xFFFF);

        bytes memory code = new bytes(14 + n);

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

        for (uint256 i; i < n; i++) {
            code[14 + i] = bytecode[i];
        }
        return code;
    }

    // ----------------------------------------------------------------------------------------------------------------
    // OWNER CHANGES
    // ----------------------------------------------------------------------------------------------------------------

    function _authorizeOwner(address account, bytes32 ownerId, address verifier, uint8 scope) internal {
        require(verifier != address(0) && verifier != REVOKED);
        address current = _ownerConfigs[account][ownerId].verifier;
        require(current == address(0) || current == REVOKED);
        _ownerConfigs[account][ownerId] = OwnerConfig({verifier: verifier, scope: scope});
        emit OwnerAuthorized(account, ownerId, verifier, scope);
    }

    function _revokeOwner(address account, bytes32 ownerId) internal {
        (address effectiveVerifier,) = _getEffectiveOwnerConfig(account, ownerId);
        require(effectiveVerifier != address(0));
        if (ownerId == bytes32(bytes20(account))) {
            _ownerConfigs[account][ownerId] = OwnerConfig({verifier: REVOKED, scope: 0});
        } else {
            delete _ownerConfigs[account][ownerId];
        }
        emit OwnerRevoked(account, ownerId);
    }

    function _computeOwnerChangeBatchDigest(
        address account,
        uint64 chainId,
        uint64 sequence,
        OwnerChange[] calldata ownerChanges
    ) internal pure returns (bytes32) {
        bytes32[] memory ownerChangeHash = new bytes32[](ownerChanges.length);
        for (uint256 i; i < ownerChanges.length; i++) {
            ownerChangeHash[i] = keccak256(
                abi.encode(ownerChanges[i].ownerId, ownerChanges[i].changeType, keccak256(ownerChanges[i].changeData))
            );
        }
        return keccak256(
            abi.encode(
                OWNER_CHANGE_BATCH_TYPEHASH, account, chainId, sequence, keccak256(abi.encodePacked(ownerChangeHash))
            )
        );
    }
}
