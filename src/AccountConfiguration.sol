// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IAccountConfiguration} from "./interfaces/IAccountConfiguration.sol";
import {IVerifier} from "./interfaces/IVerifier.sol";

/// @notice Account Configuration system contract for EIP-8130.
///         Manages owner authorization, account creation, change sequencing, and account lock.
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

    /// @dev Sentinel for the self-ownerId (ownerId == bytes32(bytes20(account))) to distinguish
    ///      "explicitly revoked" from "never registered" (address(0)).
    address constant REVOKED = address(type(uint160).max);

    /// @dev Typehash for OwnerChangeBatch, NOT compliant with EIP-712 to mitigate phishing attacks.
    bytes32 public constant OWNER_INITIALIZATION_TYPEHASH = keccak256(
        "OwnerInitialization(bytes32 salt,InitializeOwner[] initialOwners)InitializeOwner(bytes32 ownerId,OwnerConfig config)OwnerConfig(address verifier,uint8 scopes)"
    );

    /// @dev Typehash for OwnerChangeBatch, NOT compliant with EIP-712 to mitigate phishing attacks.
    bytes32 public constant OWNER_CHANGE_BATCH_TYPEHASH = keccak256(
        "OwnerChangeBatch(address account,uint64 chainId,uint64 sequence,OwnerChange[] ownerChanges)"
        "OwnerChange(bytes32 ownerId,uint8 changeType,bytes changeData)"
    );

    // ----------------------------------------------------------------------------------------------------------------
    // OWNER CHANGE TYPES
    // ----------------------------------------------------------------------------------------------------------------

    /// @notice Authorize an owner to the account
    uint8 public constant AUTHORIZE_OWNER = 0x01;

    /// @notice Revoke an owner from the account
    uint8 public constant REVOKE_OWNER = 0x02;

    // ----------------------------------------------------------------------------------------------------------------
    // OWNER ELEVATED SCOPES
    // ----------------------------------------------------------------------------------------------------------------

    /// @notice Owner can sign arbitrary messages with account
    uint8 public constant SCOPE_SIGNER = 0x01;

    /// @notice Owner can initiate transactions with account as sender
    uint8 public constant SCOPE_SENDER = 0x02;

    /// @notice Owner can pay for transactions with account as payer
    uint8 public constant SCOPE_PAYER = 0x04;

    /// @notice Owner can change account owners
    uint8 public constant SCOPE_CHANGE_OWNERS = 0x08;

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // STORAGE
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Per-owner configuration
    /// @dev Account must be inner-most mapping key to pass ERC-7562 storage access rules for ERC-4337 compatibility.
    mapping(bytes32 ownerId => mapping(address account => OwnerConfig)) internal _ownerConfig;

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

    /// @notice Deploy a new account with initial owners configured using safe defaults.
    ///         Initial owners are always unrestricted (scope = 0x00).
    function createAccount(bytes32 userSalt, bytes calldata bytecode, InitializeOwner[] calldata initialOwners)
        external
        returns (address account)
    {
        account = computeAddress(userSalt, bytecode, initialOwners);

        // Initialize account owners (reverts naturally on duplicate via _authorizeOwner)
        _initializeAccount(account, initialOwners);

        // Create account code
        bytes memory deploymentCode = _buildDeploymentCode(bytecode);
        bytes32 deploymentSalt = _computeOwnerInitializationDigest(userSalt, initialOwners);
        assembly {
            pop(create2(0, add(deploymentCode, 0x20), mload(deploymentCode), deploymentSalt))
        }
        emit AccountCreated(account, userSalt, keccak256(bytecode));

        // todo: enforce code is initialized to prevent empty implementation uninitialization attacks
    }

    /// @notice Import an existing account to AccountConfigruation management.
    /// @dev Verifies via ERC-1271 implying accounts must have bytecode to be imported.
    /// @dev Custom hash used to partially mitigate phishing attacks on eth_signTypedData.
    function importAccount(address account, InitializeOwner[] calldata initialOwners, bytes calldata signature)
        external
    {
        // Prevent re-import (replay of revoked owners)
        require(_accountState[account].localSequence == 0);
        _accountState[account].localSequence = 1;

        // Verify account signature using ERC-1271
        bytes32 digest = _computeOwnerInitializationDigest(bytes32(bytes20(account)), initialOwners);
        (bool success, bytes memory result) =
            account.staticcall(abi.encodeWithSelector(ERC1271_SELECTOR, digest, signature));
        require(success && result.length == 32 && abi.decode(result, (bytes4)) == ERC1271_SELECTOR);

        // Initialize account owners
        _initializeAccount(account, initialOwners);

        emit AccountImported(account);
    }

    /// @notice Apply owner changes (owner management only).
    ///         Direct verification via verifier + owner_config, isValidSignature fallback for migration.
    function applySignedOwnerChanges(
        address account,
        uint64 chainId,
        OwnerChange[] calldata ownerChanges,
        Verification calldata verification
    ) external onlyUnlocked(account) {
        require(chainId == 0 || chainId == block.chainid);

        // Increment the corresponding sequence
        uint64 sequence =
            chainId == 0 ? _accountState[account].multichainSequence++ : _accountState[account].localSequence++;

        // Compute digest and verify
        bytes32 digest = _computeOwnerChangeBatchDigest(account, chainId, sequence, ownerChanges);
        uint8 scopes = verify(account, digest, verification);

        // Require owner has scope to change owners (scopes == 0 means unrestricted)
        require(scopes == 0 || scopes & SCOPE_CHANGE_OWNERS != 0);

        // Apply ownerChanges
        for (uint256 i; i < ownerChanges.length; i++) {
            if (ownerChanges[i].changeType == AUTHORIZE_OWNER) {
                OwnerConfig memory newOwnerConfig = abi.decode(ownerChanges[i].configData, (OwnerConfig));
                _authorizeOwner(account, ownerChanges[i].ownerId, newOwnerConfig);
            } else if (ownerChanges[i].changeType == REVOKE_OWNER) {
                _revokeOwner(account, ownerChanges[i].ownerId);
            } else {
                revert();
            }
        }
        emit AppliedSignedOwnerChanges(account, sequence);
    }

    // ----------------------------------------------------------------------------------------------------------------
    // ACCOUNT LOCKS
    // ----------------------------------------------------------------------------------------------------------------

    /// @notice Lock the account to freeze owner configuration.
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

    /// @notice Verify an account bytes signature.
    /// @dev Designed for easy account integration with ERC-1271.
    /// @return verified True if the signature is valid.
    function verifySignature(address account, bytes32 hash, bytes calldata signature)
        external
        view
        returns (bool verified)
    {
        uint8 scopes = verify(account, hash, abi.decode(signature, (Verification)));
        return scopes & SCOPE_SIGNER != 0;
    }

    /// @notice Verify an account approved a hash using a verification.
    /// @return scopes The scopes enabled by the verification.
    function verify(address account, bytes32 hash, Verification memory verification)
        public
        view
        returns (uint8 scopes)
    {
        OwnerConfig memory config = _ownerConfig[verification.ownerId][account];

        // Require verifier is not null
        require(config.verifier != address(0));

        // Call verifier and require ownerId is not null (failed verification)
        // todo: consider where to implement 7739 support
        bytes32 ownerId = IVerifier(config.verifier).verify(hash, verification.verifierData);
        require(ownerId != bytes32(0) && ownerId == verification.ownerId);

        return config.scopes;
    }

    /// @notice Compute the counterfactual address for an account.
    function computeAddress(bytes32 userSalt, bytes calldata bytecode, InitializeOwner[] calldata initialOwners)
        public
        view
        returns (address)
    {
        bytes32 deploymentSalt = _computeOwnerInitializationDigest(userSalt, initialOwners);
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

    function isOwner(address account, bytes32 ownerId) public view returns (bool) {
        address verifier = _ownerConfig[ownerId][account].verifier;
        return verifier != address(0) && verifier != REVOKED;
    }

    function getOwnerConfig(address account, bytes32 ownerId) external view returns (OwnerConfig memory) {
        return _ownerConfig[ownerId][account];
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
    // OWNER CHANGES
    // ----------------------------------------------------------------------------------------------------------------

    function _initializeAccount(address account, InitializeOwner[] calldata initialOwners) internal nonZero(account) {
        // Must have at least one initial owner
        require(initialOwners.length > 0);

        bytes32 previousOwnerId;
        for (uint256 i; i < initialOwners.length; i++) {
            // Enforce sorting with relative comparison of sequential owner ids
            require(initialOwners[i].ownerId > previousOwnerId);
            previousOwnerId = initialOwners[i].ownerId;

            _authorizeOwner(account, initialOwners[i].ownerId, initialOwners[i].config);
        }
    }

    function _authorizeOwner(address account, bytes32 ownerId, OwnerConfig memory config) internal nonZero(account) {
        // Must be legitimate verifier
        require(config.verifier != address(0) && config.verifier != REVOKED);

        // Must not already be an owner
        require(!isOwner(account, ownerId));

        _ownerConfig[ownerId][account] = config;
        emit OwnerAuthorized(account, ownerId, config);
    }

    function _revokeOwner(address account, bytes32 ownerId) internal nonZero(account) {
        // Must be an owner
        require(isOwner(account, ownerId));

        _ownerConfig[ownerId][account] = OwnerConfig({verifier: REVOKED, scopes: 0});
        emit OwnerRevoked(account, ownerId);
    }

    function _computeOwnerInitializationDigest(bytes32 salt, InitializeOwner[] calldata initialOwners)
        internal
        pure
        returns (bytes32)
    {
        // Hash each owner
        bytes32[] memory initializeOwnerHashes = new bytes32[](initialOwners.length);
        for (uint256 i; i < initialOwners.length; i++) {
            initializeOwnerHashes[i] = keccak256(abi.encode(initialOwners[i].ownerId, initialOwners[i].config));
        }

        // Hash cumulative initialization data
        return
            keccak256(
                abi.encode(OWNER_INITIALIZATION_TYPEHASH, salt, keccak256(abi.encodePacked(initializeOwnerHashes)))
            );
    }

    function _computeOwnerChangeBatchDigest(
        address account,
        uint64 chainId,
        uint64 sequence,
        OwnerChange[] calldata ownerChanges
    ) internal pure returns (bytes32) {
        // Hash each owner change
        bytes32[] memory ownerChangeHashes = new bytes32[](ownerChanges.length);
        for (uint256 i; i < ownerChanges.length; i++) {
            ownerChangeHashes[i] = keccak256(abi.encode(ownerChanges[i]));
        }

        // Hash the batch of owner changes
        return keccak256(
            abi.encode(
                OWNER_CHANGE_BATCH_TYPEHASH, account, chainId, sequence, keccak256(abi.encodePacked(ownerChangeHashes))
            )
        );
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
