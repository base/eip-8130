// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore} from "../Keystore.sol";
import {Call} from "../interfaces/IExecuteBatch.sol";
import {PolicyBinding, PolicyBindingLib} from "./PolicyBinding.sol";

/// @title Policy
///
/// @notice Manager-agnostic base hook for policies coordinated by any {PolicyManager} the account installs.
///
/// @dev A policy turns an account-authorized binding plus a per-use action (`executionData`) into a wallet-agnostic
///      {Call} plan that the calling manager encodes and forwards to the account. Rather than trust a single
///      hardcoded manager, the policy authenticates every call against the canonical Keystore: it requires the caller
///      to be the manager the account installed for the acting actor, and requires the supplied binding to recompute
///      to that actor's live signed commitment. This lets one deployed policy instance serve every manager (one per
///      account execution ABI) instead of a separate instance per manager.
///
///      A policy MUST validate config in {_onExecute} and MUST NOT store a config hash. Store only mutable execution
///      state (e.g. spend counters), keyed by the authenticated commitment. Because the base authenticates before
///      any hook runs and its only external interaction is a Keystore view read, a policy whose state is keyed by
///      commitment needs no reentrancy guard; a policy that keeps other shared state must add its own.
///
/// @author Coinbase
abstract contract Policy {
    using PolicyBindingLib for PolicyBinding;

    /// @notice The EIP-8130 Keystore used to authenticate that the caller is the account-installed manager.
    Keystore public immutable KEYSTORE;

    /// @notice The binding names a policy other than this contract.
    error PolicyMismatch(address expected, address actual);

    /// @notice The acting actor has no live signed policy commitment (unknown, revoked, or expired).
    error NoActivePolicy(bytes32 actorId);

    /// @notice The caller is not the manager the account installed for the acting actor.
    error UnauthorizedManager(address caller);

    /// @notice The supplied binding does not recompute to the actor's live signed commitment.
    error CommitmentMismatch(bytes32 expected, bytes32 signed);

    /// @notice The current time is outside the binding's `[validAfter, validUntil)` execution window.
    error OutsideValidityWindow(uint40 validAfter, uint40 validUntil, uint256 timestamp);

    /// @notice Deploys the policy bound to a Keystore instance (not to any manager).
    /// @param keystore Address of the EIP-8130 Keystore system contract.
    constructor(address keystore) {
        KEYSTORE = Keystore(keystore);
    }

    /// @notice Authenticate the binding and build the account call and optional post-call.
    ///
    /// @dev Reverts with PolicyMismatch when `binding.policy != address(this)`.
    /// @dev Reverts with NoActivePolicy when the actor has no live signed commitment.
    /// @dev Reverts with UnauthorizedManager when the caller is not the account's installed manager for the actor.
    /// @dev Reverts with CommitmentMismatch when `binding` does not recompute to the signed commitment.
    /// @dev Reverts with OutsideValidityWindow when the current time is outside `[validAfter, validUntil)`.
    /// @dev Implementations MUST revert to refuse execution. An empty `calls` return is treated by the manager as a
    ///      no-op (no account call, no {onPostExecute}, no event).
    ///
    /// @param binding       Full account-authorized binding.
    /// @param actorId       Acting actor whose installed manager and signed commitment authorize this call.
    /// @param executionData Per-use action parameters.
    /// @param caller        Address that invoked the manager.
    ///
    /// @return calls        Wallet-agnostic call plan for the manager to encode and forward to `binding.account`.
    /// @return postCallData Opaque bytes forwarded to {onPostExecute} after the account call (may be empty).
    function onExecute(PolicyBinding calldata binding, bytes32 actorId, bytes calldata executionData, address caller)
        external
        returns (Call[] memory calls, bytes memory postCallData)
    {
        bytes32 commitment = _authenticate(binding, actorId);
        return _onExecute(commitment, binding.account, binding.policyConfig, executionData, caller);
    }

    /// @notice Hook invoked by the manager after a non-empty account call.
    ///
    /// @dev Reverts via {_authenticate} with PolicyMismatch, NoActivePolicy, UnauthorizedManager, CommitmentMismatch,
    ///      or OutsideValidityWindow.
    /// @dev `postCallData` may be empty, so implementations must handle that case. Default is a no-op.
    ///
    /// @param binding      Full account-authorized binding.
    /// @param actorId      Acting actor whose installed manager and signed commitment authorize this call.
    /// @param postCallData Policy-defined post-call payload returned by {onExecute}.
    function onPostExecute(PolicyBinding calldata binding, bytes32 actorId, bytes calldata postCallData) external {
        bytes32 commitment = _authenticate(binding, actorId);
        _onPostExecute(commitment, binding.account, postCallData);
    }

    /// @dev Authenticates the binding against the Keystore and returns its commitment. Order matters: liveness first
    ///      (a revoked/expired actor reads back a zero commitment), then the installed-manager match, then the
    ///      commitment recompute, then the validity window.
    function _authenticate(PolicyBinding calldata binding, bytes32 actorId) internal view returns (bytes32 commitment) {
        if (binding.policy != address(this)) revert PolicyMismatch(address(this), binding.policy);

        (, address manager, bytes32 signed) = KEYSTORE.getActorWithPolicy(binding.account, actorId);
        if (signed == bytes32(0)) revert NoActivePolicy(actorId);
        if (manager != msg.sender) revert UnauthorizedManager(msg.sender);

        commitment = binding.commitment();
        if (signed != commitment) revert CommitmentMismatch(commitment, signed);

        if (
            (binding.validAfter != 0 && block.timestamp < binding.validAfter)
                || (binding.validUntil != 0 && block.timestamp >= binding.validUntil)
        ) {
            revert OutsideValidityWindow(binding.validAfter, binding.validUntil, block.timestamp);
        }
    }

    /// @dev Policy-specific execute logic. Revert to refuse. Validate config here as needed.
    function _onExecute(
        bytes32 commitment,
        address account,
        bytes calldata policyConfig,
        bytes calldata executionData,
        address caller
    ) internal virtual returns (Call[] memory calls, bytes memory postCallData);

    /// @dev Policy-specific post-execute hook. Default no-op; override for post-call checks (e.g. balance deltas).
    function _onPostExecute(bytes32 commitment, address account, bytes calldata postCallData) internal virtual {
        commitment;
        account;
        postCallData;
    }
}
