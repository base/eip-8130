// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Receiver} from "solady/accounts/Receiver.sol";
import {LibCall} from "solady/utils/LibCall.sol";

import {Keystore} from "../Keystore.sol";
import {ActorId} from "../libraries/ActorId.sol";
import {Scopes} from "../libraries/Scopes.sol";

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
///         and defers all authorization to the Keystore system contract.
///
///         Caller authorization:
///           - address(this) is always authorized (hardcoded), covering 8130 self-call batches
///           - Trusted executors (PolicyManagers, relayers, EntryPoints) are registered as actors with
///             TRUSTED_EXECUTOR as the authenticator in Keystore
///
/// @dev Not a deployment target. This describes the default EOA behavior applied natively on an EIP-8130 chain; it
///      is intentionally minimal and is NOT ERC-4337 compatible. An account that wants smart-account features (for
///      example ERC-4337 on a chain without native EIP-8130 support) should delegate or deploy to a purpose-built
///      account, not to this one. If this bytecode is deployed anyway, it MUST sit behind an upgradeable (UUPS)
///      proxy: adopting those features later means swapping in different bytecode, which is only possible if the
///      deployment is upgradeable. An upgradeable (UUPS) variant is provided as an unaudited example in a separate
///      repository.
///
/// @author Coinbase
contract DefaultAccount is Receiver {
    /// @notice The Keystore system contract that owns this account's authorization state.
    Keystore public immutable KEYSTORE;

    /// @notice ERC-1271 magic value returned for a valid signature: bytes4(keccak256("isValidSignature(bytes32,bytes)")).
    bytes4 internal constant ERC1271_MAGIC_VALUE = 0x1626ba7e;

    /// @notice ERC-1271 sentinel returned for an invalid signature.
    bytes4 internal constant ERC1271_INVALID = 0xffffffff;

    /// @notice The caller is neither the account itself nor a registered TRUSTED_EXECUTOR actor.
    error UnauthorizedCaller();

    /// @notice Deploys the account implementation bound to an Keystore instance.
    /// @param keystore Address of the Keystore system contract.
    constructor(address keystore) {
        KEYSTORE = Keystore(keystore);
    }

    // ══════════════════════════════════════════════
    //  EXECUTION
    // ══════════════════════════════════════════════

    /// @notice Executes a batch of calls from the account; reverts the entire batch if any call fails.
    ///
    /// @dev Reverts with UnauthorizedCaller when the caller is neither the account nor a TRUSTED_EXECUTOR actor.
    /// @dev Bubbles up the inner call's revert reason verbatim (a reason-less revert propagates as an empty revert).
    ///
    /// @param calls Ordered calls to execute, each as (target, value, data).
    function executeBatch(Call[] calldata calls) external virtual {
        if (!_isAuthorizedCaller(msg.sender)) revert UnauthorizedCaller();
        for (uint256 i; i < calls.length; i++) {
            // Plain `call` (not LibCall.callContract) so value transfers to codeless targets (e.g. EOAs) still succeed.
            (bool success, bytes memory result) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            if (!success) LibCall.bubbleUpRevert(result);
        }
    }

    /// @notice Executes a single call from the account.
    ///
    /// @dev Equivalent to a one-element {executeBatch}. Selector-compatible with the widely deployed
    ///      CoinbaseSmartWallet V1 `execute(address,uint256,bytes)` (0xb61d27f6), so integrations that call that ABI
    ///      directly (e.g. SpendPermissionManager) keep working against this account.
    /// @dev Reverts with UnauthorizedCaller when the caller is neither the account nor a TRUSTED_EXECUTOR actor.
    /// @dev Bubbles up the inner call's revert reason verbatim (a reason-less revert propagates as an empty revert).
    ///
    /// @param target Address the account calls.
    /// @param value Wei forwarded with the call.
    /// @param data Calldata passed to `target`.
    function execute(address target, uint256 value, bytes calldata data) external virtual {
        if (!_isAuthorizedCaller(msg.sender)) revert UnauthorizedCaller();
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) LibCall.bubbleUpRevert(result);
    }

    // ══════════════════════════════════════════════
    //  ERC-1271
    // ══════════════════════════════════════════════

    /// @notice Validates an ERC-1271 signature via Keystore; requires the verified actor to be operational (the
    ///         unrestricted admin, scope == 0x00, or a SENDER actor without POLICY). Never reverts.
    ///
    /// @dev {Keystore.validateSignature} resolves the typed envelope and reverts on any authentication failure; the
    ///      revert is caught and reported as the ERC-1271 failure value. Operational gating lives here (not in the
    ///      Keystore): signing is authorized for any operational actor via {Scopes.isOperator}, keeping the signing
    ///      and execution ({_isAuthorizedCaller}) authorization surfaces aligned.
    ///
    /// @param hash The digest to authenticate.
    /// @param signature Envelope in `sigType(1) || authenticator(20) || data` format.
    ///
    /// @return The ERC-1271 magic value (ERC1271_MAGIC_VALUE) if valid, otherwise ERC1271_INVALID.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view virtual returns (bytes4) {
        try KEYSTORE.validateSignature(address(this), hash, signature) returns (bytes32, uint16 scope) {
            return Scopes.isOperator(scope) ? ERC1271_MAGIC_VALUE : ERC1271_INVALID;
        } catch {
            return ERC1271_INVALID;
        }
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

    /// @dev Authorized if `caller` is the account itself, or holds the TRUSTED_EXECUTOR authenticator with an
    ///      unexpired config AND operational authority. Expiry: 0 means none; a non-zero expiry is enforced so a
    ///      user-set expiry is honored on the execution path. Scope: driving execution requires operational
    ///      authority ({Scopes.isOperator}) — the unrestricted admin (scope == 0x00) or a SENDER actor not gated
    ///      by a policy. A POLICY-gated actor must route every call through its manager, so granting it direct
    ///      executeBatch would bypass that gate; fail closed. Sharing {Scopes.isOperator} keeps the execution and
    ///      signing (ERC-1271) authorization surfaces aligned.
    function _isAuthorizedCaller(address caller) internal view virtual returns (bool) {
        if (caller == address(this)) return true;
        Keystore.ActorConfig memory config = KEYSTORE.getActorConfig(address(this), ActorId.fromAddress(caller));
        if (config.authenticator != TRUSTED_EXECUTOR) return false;
        if (config.expiry != 0 && block.timestamp > config.expiry) return false;
        return Scopes.isOperator(config.scope);
    }
}
