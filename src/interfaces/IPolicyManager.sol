// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {PolicyBinding} from "../policies/PolicyBinding.sol";

/// @title IPolicyManager
///
/// @notice Use-time calling surface every EIP-8130 policy manager exposes, so external callers (session-key wallet
///         software, subscription providers) integrate against one interface regardless of the account's execution
///         ABI. The wallet-ABI variance is hidden behind the manager's encoding step, so this surface is uniform.
///
/// @dev The Keystore does not enforce conformance; this is a convention standard (ERC-style) for managers — the
///      subclasses shipped here, third-party managers, or an account acting as its own manager. It is the anchor a
///      future off-chain permission-grant standard points at when telling an app how to exercise a wallet's policy.
///
/// @author Coinbase
interface IPolicyManager {
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
