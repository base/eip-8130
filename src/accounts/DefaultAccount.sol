// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Receiver} from "solady/accounts/Receiver.sol";

import {AccountConfiguration} from "../AccountConfiguration.sol";

/// @notice A single call in an execution batch.
struct Call {
    /// @dev Address the account calls.
    address target;
    /// @dev Wei forwarded with the call.
    uint256 value;
    /// @dev Calldata passed to `target`.
    bytes data;
}

/// @dev Sentinel `authenticator` value marking an actor as a trusted executor: an address (e.g. a PolicyManager,
///      EntryPoint, or relayer) authorized to drive execution on the account by matching `msg.sender` rather than
///      by verifying a signature. No contract exists at this address; it is hash-derived and deterministic across
///      all chains, so if the protocol ever calls authenticate() on it the call naturally fails.
address constant TRUSTED_EXECUTOR = address(uint160(uint256(keccak256("trustedExecutor"))));

/// @notice Canonical model of the EIP-8130 default account: the behavior every EOA exhibits by default on an
///         EIP-8130 chain, expressed in Solidity. It handles batched execution and ERC-1271 signature validation,
///         and defers all authorization to the AccountConfiguration system contract.
///
///         Caller authorization:
///           - address(this) is always authorized (hardcoded), covering 8130 self-call batches
///           - Trusted executors (PolicyManagers, relayers, EntryPoints) are registered as actors with
///             TRUSTED_EXECUTOR as the authenticator in AccountConfiguration
///
/// @dev Not a deployment target. This describes the default EOA behavior applied natively on an EIP-8130 chain; it
///      is intentionally minimal and is NOT ERC-4337 compatible. An account that wants smart-account features (for
///      example ERC-4337 on a chain without native EIP-8130 support) should delegate or deploy to a purpose-built
///      account, not to this one. If this bytecode is deployed anyway, it MUST sit behind an upgradeable (UUPS)
///      proxy: adopting those features later means swapping in different bytecode, which is only possible if the
///      deployment is upgradeable. See {UpgradeableAccount} for that upgradeable variant.
///
/// @author Coinbase
contract DefaultAccount is Receiver {
    /// @notice The AccountConfiguration system contract that owns this account's authorization state.
    AccountConfiguration public immutable ACCOUNT_CONFIGURATION;

    /// @notice The caller is neither the account itself nor a registered TRUSTED_EXECUTOR actor.
    error UnauthorizedCaller();

    /// @notice An inner call in the executed batch reverted.
    error CallFailed();

    /// @notice Deploys the account implementation bound to an AccountConfiguration instance.
    /// @param accountConfiguration Address of the AccountConfiguration system contract.
    constructor(address accountConfiguration) {
        ACCOUNT_CONFIGURATION = AccountConfiguration(accountConfiguration);
    }

    // ══════════════════════════════════════════════
    //  EXECUTION
    // ══════════════════════════════════════════════

    /// @notice Executes a batch of calls from the account; reverts the entire batch if any call fails.
    ///
    /// @dev Reverts with UnauthorizedCaller when the caller is neither the account nor a TRUSTED_EXECUTOR actor.
    /// @dev Reverts with CallFailed when any inner call reverts.
    ///
    /// @param calls Ordered calls to execute, each as (target, value, data).
    function executeBatch(Call[] calldata calls) external virtual {
        if (!_isAuthorizedCaller(msg.sender)) revert UnauthorizedCaller();
        for (uint256 i; i < calls.length; i++) {
            (bool success,) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            if (!success) revert CallFailed();
        }
    }

    // ══════════════════════════════════════════════
    //  ERC-1271
    // ══════════════════════════════════════════════

    /// @notice Validates an ERC-1271 signature via AccountConfiguration; requires the verified actor to hold
    ///         SIGNER scope or be an unrestricted owner. Never reverts.
    ///
    /// @param hash The digest to authenticate.
    /// @param signature Auth data in `authenticator || data` format.
    ///
    /// @return The ERC-1271 magic value 0x1626ba7e if valid, otherwise 0xffffffff.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view virtual returns (bytes4) {
        return
            ACCOUNT_CONFIGURATION.verifySignature(address(this), hash, signature)
                ? bytes4(0x1626ba7e)
                : bytes4(0xFFFFFFFF);
    }

    // ══════════════════════════════════════════════
    //  VIEW
    // ══════════════════════════════════════════════

    /// @notice Returns whether `caller` may drive execution on this account.
    ///
    /// @param caller Address to check.
    ///
    /// @return True if `caller` is the account itself or a registered TRUSTED_EXECUTOR actor.
    function isAuthorizedCaller(address caller) external view returns (bool) {
        return _isAuthorizedCaller(caller);
    }

    // ══════════════════════════════════════════════
    //  INTERNALS
    // ══════════════════════════════════════════════

    /// @dev Authorized if `caller` is the account itself or holds the TRUSTED_EXECUTOR authenticator.
    function _isAuthorizedCaller(address caller) internal view virtual returns (bool) {
        if (caller == address(this)) return true;
        AccountConfiguration.ActorConfig memory config =
            ACCOUNT_CONFIGURATION.getActorConfig(address(this), bytes32(bytes20(caller)));
        return config.authenticator == TRUSTED_EXECUTOR;
    }
}
