// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {PolicyBinding} from "../policies/PolicyBinding.sol";

/// @title IPolicy
///
/// @notice Use-time calling surface every EIP-8130 self-executing policy exposes, so external callers (session-key
///         wallet software, subscription providers) integrate against one interface regardless of the account's
///         execution ABI. The wallet-ABI variance is hidden behind the policy's encoding step (default
///         `executeBatch(Call[])` or the binding's `transformer`), so this surface is uniform.
///
/// @dev In this model the policy IS the manager: the account gates a policy-scoped key with
///      `policy_manager = address(policy)`, so the protocol routes the key's calls straight to the policy. The
///      Keystore does not enforce conformance; this is a convention standard (ERC-style) for policies. It is the
///      anchor a future off-chain permission-grant standard points at when telling an app how to exercise a wallet's
///      policy.
///
/// @author Coinbase
interface IPolicy {
    /// @notice Account-acting entrypoint: a policy-gated key transacts and the protocol dispatches as the account.
    ///
    /// @param binding       Full account-authorized binding.
    /// @param executionData Per-use action parameters interpreted by the policy.
    function execute(PolicyBinding calldata binding, bytes calldata executionData) external;

    /// @notice External-caller entrypoint: a party drives a policy the account authorized for it.
    ///
    /// @param binding       Full account-authorized binding.
    /// @param executionData Per-use action parameters interpreted by the policy.
    function executeFor(PolicyBinding calldata binding, bytes calldata executionData) external;

    /// @notice Best-effort cross-account batch of {executeFor}: one external caller, many bindings, one transaction.
    ///
    /// @param bindings      Per-account bindings, parallel to `executionData`.
    /// @param executionData Per-account action parameters, parallel to `bindings`.
    ///
    /// @return results Per-account success flags, parallel to `bindings`.
    function executeForMany(PolicyBinding[] calldata bindings, bytes[] calldata executionData)
        external
        returns (bool[] memory results);

    /// @notice Computes the commitment (binding identifier) for a binding.
    ///
    /// @param binding Full policy binding to hash.
    ///
    /// @return The binding commitment.
    function commitmentOf(PolicyBinding calldata binding) external pure returns (bytes32);
}
