// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {InitialOwner} from "../AccountDeployer.sol";
import {ConfigOperation} from "../AccountConfigDigest.sol";

/// @notice Reference interface for the EIP-8130 Account Configuration system contract.
interface IAccountConfig {
    struct Owner {
        address verifier;
        bytes32 ownerId;
        uint8 scope; // 0x00 = unrestricted
    }

    event OwnerAuthorized(address indexed account, bytes32 indexed ownerId, address verifier, uint8 scope);
    event OwnerRevoked(address indexed account, bytes32 indexed ownerId);
    event AccountCreated(address indexed account, bytes32 userSalt, bytes32 codeHash);
    event ChangeApplied(address indexed account, uint64 sequence);
    event AccountLocked(address indexed account, uint32 unlockDelay);
    event UnlockRequested(address indexed account, uint32 effectiveAt);
    event AccountUnlocked(address indexed account);

    // Account creation (factory)
    function createAccount(bytes32 userSalt, bytes calldata bytecode, InitialOwner[] calldata initialOwners)
        external
        returns (address);
    function getAddress(bytes32 userSalt, bytes calldata bytecode, InitialOwner[] calldata initialOwners)
        external
        view
        returns (address);

    // Portable owner changes (direct verification via owner_config, isValidSignature fallback for migration)
    function applyConfigChange(
        address account,
        uint64 chainId,
        uint64 sequence,
        ConfigOperation[] calldata operations,
        bytes calldata authorizerAuth
    ) external;
    function getChangeSequence(address account, uint64 chainId) external view returns (uint64);

    // Account lock (authorized via isValidSignature on the account)
    function lock(address account, uint32 unlockDelay, bytes calldata signature) external;
    function requestUnlock(address account, bytes calldata signature) external;
    function unlock(address account, bytes calldata signature) external;

    // Read functions
    function getOwner(address account, bytes32 ownerId) external view returns (address verifier, uint8 scope);
    function getLockState(address account)
        external
        view
        returns (bool locked, uint32 unlockDelay, uint32 unlockRequestedAt);

    // Native verifiers (immutable, updated only via protocol upgrade)
    function getNativeVerifiers()
        external
        view
        returns (address k1, address p256Raw, address p256WebAuthn, address delegate);
    function getVerifierAddress(uint8 verifierType) external view returns (address);

    // Signature verification (checks SIGNATURE scope bit, includes implicit EOA rule)
    function verifySignature(address account, bytes32 hash, bytes calldata auth)
        external
        view
        returns (bool valid, bytes32 ownerId, address verifier);
}
