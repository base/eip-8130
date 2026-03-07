// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC1271} from "openzeppelin/interfaces/IERC1271.sol";
import {IAuthVerifier} from "./verifiers/IAuthVerifier.sol";
import {AccountConfigDigest, ConfigOperation} from "./AccountConfigDigest.sol";
import {AccountDeployer, InitialOwner} from "./AccountDeployer.sol";

struct AccountLock {
    bool locked;
    uint32 unlockDelay;
    uint32 unlockRequestedAt;
}

/// @notice Account Configuration system contract for EIP-8130.
///         Manages owner authorization, account creation, change sequencing, and account lock.
///         All authorized owners have equal privileges.
contract AccountConfiguration is AccountConfigDigest, AccountDeployer {
    // ──────────────────────────────────────────────
    //  Constants
    // ──────────────────────────────────────────────

    uint8 constant OP_AUTHORIZE_OWNER = 0x01;
    uint8 constant OP_REVOKE_OWNER = 0x02;

    /// @dev Sentinel value to distinguish "explicitly revoked" from "never registered" (address(0)).
    ///      Needed for the implicit EOA authorization rule.
    address constant REVOKED = address(1);

    bytes32 constant LOCK_TYPEHASH = keccak256("Lock(address account,uint32 unlockDelay)");
    bytes32 constant REQUEST_UNLOCK_TYPEHASH = keccak256("RequestUnlock(address account)");
    bytes32 constant UNLOCK_TYPEHASH = keccak256("Unlock(address account)");

    // ──────────────────────────────────────────────
    //  Reference Verifier Immutables
    // ──────────────────────────────────────────────

    address public immutable K1_VERIFIER; // 0x01
    address public immutable P256_RAW_VERIFIER; // 0x02
    address public immutable P256_WEBAUTHN_VERIFIER; // 0x03
    address public immutable DELEGATE_VERIFIER; // 0x04

    // ──────────────────────────────────────────────
    //  Storage
    // ──────────────────────────────────────────────

    mapping(address account => mapping(bytes32 ownerId => address verifier)) internal _ownerConfigs;
    mapping(address account => AccountLock) internal _accountLocks;

    struct ChangeSequences {
        uint64 multichain; // chain_id 0
        uint64 local; // chain_id == block.chainid
    }

    mapping(address account => ChangeSequences) internal _changeSequences;

    // ──────────────────────────────────────────────
    //  Events
    // ──────────────────────────────────────────────

    event OwnerAuthorized(address indexed account, bytes32 indexed ownerId, address verifier);
    event OwnerRevoked(address indexed account, bytes32 indexed ownerId);
    event AccountCreated(address indexed account, bytes32 userSalt, bytes32 codeHash);
    event ChangeApplied(address indexed account, uint64 sequence);
    event AccountLocked(address indexed account, uint32 unlockDelay);
    event UnlockRequested(address indexed account, uint32 effectiveAt);
    event AccountUnlocked(address indexed account);

    // ──────────────────────────────────────────────
    //  Constructor
    // ──────────────────────────────────────────────

    constructor(address k1, address p256Raw, address p256WebAuthn, address delegate) {
        K1_VERIFIER = k1;
        P256_RAW_VERIFIER = p256Raw;
        P256_WEBAUTHN_VERIFIER = p256WebAuthn;
        DELEGATE_VERIFIER = delegate;
    }

    // ══════════════════════════════════════════════
    //  ACCOUNT CREATION
    // ══════════════════════════════════════════════

    /// @notice Deploy a new account with initial owners configured using safe defaults.
    function createAccount(bytes32 userSalt, bytes calldata bytecode, InitialOwner[] calldata initialOwners)
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
            require(initialOwners[i].verifier != address(0));

            _ownerConfigs[account][initialOwners[i].ownerId] = initialOwners[i].verifier;
            emit OwnerAuthorized(account, initialOwners[i].ownerId, initialOwners[i].verifier);
        }

        _accountLocks[account] = AccountLock(false, 0, 0);

        _deploy(bytecode, initialOwners, userSalt);
        emit AccountCreated(account, userSalt, keccak256(bytecode));
    }

    // ══════════════════════════════════════════════
    //  PORTABLE OWNER CHANGES (EVM path — direct verification + ERC-1271 fallback)
    // ══════════════════════════════════════════════

    /// @notice Apply config change operations (owner management only).
    ///         Direct verification via verifier + owner_config, isValidSignature fallback for migration.
    function applyConfigChange(
        address account,
        uint64 chainId,
        uint64 sequence,
        ConfigOperation[] calldata operations,
        bytes calldata authorizerAuth
    ) external {
        _requireNotLocked(account);

        require(chainId == 0 || chainId == block.chainid);

        require(_getSequence(account, chainId) == sequence);
        _setSequence(account, chainId, sequence + 1);

        bytes32 digest = _computeConfigChangeDigest(account, chainId, sequence, operations);

        _requireValidSignature(account, digest, authorizerAuth);

        for (uint256 i; i < operations.length; i++) {
            _applyOperation(account, operations[i]);
        }
        emit ChangeApplied(account, sequence);
    }

    // ══════════════════════════════════════════════
    //  ACCOUNT LOCK (authorized via account's isValidSignature)
    // ══════════════════════════════════════════════

    /// @notice Lock the account to freeze owner configuration. Anyone can call; authorization via signature.
    function lock(address account, uint32 unlockDelay, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(LOCK_TYPEHASH, account, unlockDelay));
        _requireIsValidSignature(account, digest, signature);

        AccountLock storage l = _accountLocks[account];
        require(!l.locked);
        l.locked = true;
        l.unlockDelay = unlockDelay;
        l.unlockRequestedAt = 0;
        emit AccountLocked(account, unlockDelay);
    }

    /// @notice Request to unlock the account. Starts the timelock.
    function requestUnlock(address account, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(REQUEST_UNLOCK_TYPEHASH, account));
        _requireIsValidSignature(account, digest, signature);

        AccountLock storage l = _accountLocks[account];
        require(l.locked && l.unlockRequestedAt == 0);
        l.unlockRequestedAt = uint32(block.timestamp);
        emit UnlockRequested(account, uint32(block.timestamp) + l.unlockDelay);
    }

    /// @notice Complete the unlock after the timelock has elapsed.
    function unlock(address account, bytes calldata signature) external {
        bytes32 digest = keccak256(abi.encode(UNLOCK_TYPEHASH, account));
        _requireIsValidSignature(account, digest, signature);

        AccountLock storage l = _accountLocks[account];
        require(l.locked && l.unlockRequestedAt != 0);
        require(block.timestamp >= l.unlockRequestedAt + l.unlockDelay);
        l.locked = false;
        l.unlockDelay = 0;
        l.unlockRequestedAt = 0;
        emit AccountUnlocked(account);
    }

    // ══════════════════════════════════════════════
    //  READ FUNCTIONS
    // ══════════════════════════════════════════════

    function isAuthorized(address account, bytes32 ownerId) external view returns (bool) {
        return _getEffectiveVerifier(account, ownerId) != address(0);
    }

    function getOwner(address account, bytes32 ownerId) public view returns (address verifier) {
        return _getEffectiveVerifier(account, ownerId);
    }

    function getLockState(address account)
        public
        view
        returns (bool locked, uint32 unlockDelay, uint32 unlockRequestedAt)
    {
        AccountLock storage l = _accountLocks[account];
        locked = l.locked;
        unlockDelay = l.unlockDelay;
        unlockRequestedAt = l.unlockRequestedAt;
    }

    function getChangeSequence(address account, uint64 chainId) external view returns (uint64) {
        return _getSequence(account, chainId);
    }

    // ══════════════════════════════════════════════
    //  REFERENCE VERIFIERS
    // ══════════════════════════════════════════════

    function getReferenceVerifiers()
        external
        view
        returns (address k1, address p256Raw, address p256WebAuthn, address delegate)
    {
        return (K1_VERIFIER, P256_RAW_VERIFIER, P256_WEBAUTHN_VERIFIER, DELEGATE_VERIFIER);
    }

    function getVerifierAddress(uint8 verifierType) public view returns (address) {
        if (verifierType == 0x01) return K1_VERIFIER;
        if (verifierType == 0x02) return P256_RAW_VERIFIER;
        if (verifierType == 0x03) return P256_WEBAUTHN_VERIFIER;
        if (verifierType == 0x04) return DELEGATE_VERIFIER;
        return address(0);
    }

    // ══════════════════════════════════════════════
    //  TRANSACTION CONTEXT (EIP-1153 transient storage)
    // ══════════════════════════════════════════════

    /// @notice Returns the current AA transaction's gas payer address.
    ///         Only meaningful during AA transaction execution on 8130 chains.
    function getCurrentPayer() public view returns (address payer) {
        bytes32 slot = keccak256("context.payer");
        assembly {
            payer := tload(slot)
        }
    }

    /// @notice Returns the current AA transaction's signer owner info.
    ///         Protocol writes ownerId to transient storage; verifier looked up from persistent storage.
    ///         On non-8130 chains, returns zero values (no protocol writes to transient storage).
    function getCurrentSigner() public view returns (bytes32 ownerId, address verifier) {
        bytes32 signerSlot = keccak256("context.signer");
        assembly {
            ownerId := tload(signerSlot)
        }
        if (ownerId != bytes32(0)) {
            verifier = _getEffectiveVerifier(msg.sender, ownerId);
        }
    }

    // ══════════════════════════════════════════════
    //  SIGNATURE VERIFICATION (type-byte format)
    // ══════════════════════════════════════════════

    /// @notice Verify a signature against an account using the type-byte format.
    ///         Type 0x01-0x04: reference verifier (resolved from immutables).
    ///         Type 0x00: custom verifier (next 20 bytes = contract address).
    ///         Includes the implicit EOA authorization rule.
    function verifySignature(address account, bytes32 hash, bytes calldata auth)
        public
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

        ownerId = IAuthVerifier(verifier).verify(hash, data);
        if (ownerId == bytes32(0)) return (false, bytes32(0), verifier);

        address registeredVerifier = _ownerConfigs[account][ownerId];
        if (registeredVerifier == verifier) {
            valid = true;
        } else if (registeredVerifier == address(0) && ownerId == bytes32(bytes20(account)) && verifier == K1_VERIFIER)
        {
            valid = true;
        }
    }

    // ══════════════════════════════════════════════
    //  INTERNALS
    // ══════════════════════════════════════════════

    /// @dev Two-tier authorization: try verifySignature first (direct verification via owner_config),
    ///      then fall back to isValidSignature (ERC-1271) for migration.
    function _requireValidSignature(address account, bytes32 digest, bytes calldata authorizerAuth) internal view {
        (bool valid,,) = verifySignature(account, digest, authorizerAuth);
        if (valid) return;

        require(account.code.length > 0);
        _requireIsValidSignature(account, digest, authorizerAuth);
    }

    /// @dev Calls isValidSignature (ERC-1271) on the account for authorization.
    function _requireIsValidSignature(address account, bytes32 digest, bytes calldata signature) internal view {
        require(account.code.length > 0);
        (bool success, bytes memory result) =
            account.staticcall(abi.encodeWithSignature("isValidSignature(bytes32,bytes)", digest, signature));
        require(success && result.length >= 32);
        require(abi.decode(result, (bytes4)) == IERC1271.isValidSignature.selector);
    }

    /// @dev Returns the effective verifier for an owner, applying the implicit EOA rule.
    ///      REVOKED sentinel → address(0). Empty slot + implicit EOA eligible → K1_VERIFIER.
    function _getEffectiveVerifier(address account, bytes32 ownerId) internal view returns (address) {
        address v = _ownerConfigs[account][ownerId];
        if (v == REVOKED) return address(0);
        if (v == address(0) && ownerId == bytes32(bytes20(account))) return K1_VERIFIER;
        return v;
    }

    function _getSequence(address account, uint64 chainId) internal view returns (uint64) {
        ChangeSequences storage s = _changeSequences[account];
        return chainId == 0 ? s.multichain : s.local;
    }

    function _setSequence(address account, uint64 chainId, uint64 value) internal {
        ChangeSequences storage s = _changeSequences[account];
        if (chainId == 0) {
            s.multichain = value;
        } else {
            s.local = value;
        }
    }

    function _requireNotLocked(address account) internal view {
        require(!_accountLocks[account].locked);
    }

    function _applyOperation(address account, ConfigOperation calldata op) internal {
        if (op.opType == OP_AUTHORIZE_OWNER) {
            require(op.verifier != address(0) && op.verifier != REVOKED);
            address current = _ownerConfigs[account][op.ownerId];
            require(current == address(0) || current == REVOKED);
            _ownerConfigs[account][op.ownerId] = op.verifier;
            emit OwnerAuthorized(account, op.ownerId, op.verifier);
        } else if (op.opType == OP_REVOKE_OWNER) {
            require(_getEffectiveVerifier(account, op.ownerId) != address(0));
            _ownerConfigs[account][op.ownerId] = REVOKED;
            emit OwnerRevoked(account, op.ownerId);
        } else {
            revert();
        }
    }
}
