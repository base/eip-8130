// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {PolicyManager} from "./PolicyManager.sol";

/// @title Policy
///
/// @notice Minimal base hook interface for policies coordinated by {PolicyManager}.
///
/// @dev A policy turns an account-authorized *commitment* (bound to `policyConfig` via the signed actor change)
///      plus a per-use *action* (`executionData`) into an account call plan. The plan is ABI-encoded calldata that
///      the manager forwards to the account (e.g. `executeBatch`).
///
///      Config delivery: the manager always forwards `policyConfig` to {onExecute} (it MAY be empty). Callers
///      supply the full {PolicyManager.PolicyBinding} at execute; the manager recomputes the commitment and
///      compares it to the live signed commitment in Keystore. That single check authenticates
///      config, validity window, and owning account — so policies MUST NOT store a config hash. There is no
///      separate install step; config validation belongs in {onExecute} (or a helper it calls).
///
///      Mutable execution state (e.g. spend counters) is the exception that belongs in storage, keyed by
///      commitment.
///
///      This is the example/reference shape for an EIP-8130 actor policy (`scope & Scopes.POLICY != 0`): the
///      manager is the single call target a restricted actor may reach, and policies express *what* that actor
///      may do. All hooks are callable only by the configured {PolicyManager}.
abstract contract Policy {
    /// @notice The {PolicyManager} instance authorized to call this policy's hooks.
    PolicyManager public immutable POLICY_MANAGER;

    /// @notice Thrown when a hook is invoked by an address other than {POLICY_MANAGER}.
    error InvalidCaller(address caller, address expected);

    /// @notice Restricts a hook to the configured {PolicyManager}.
    modifier onlyPolicyManager() {
        if (msg.sender != address(POLICY_MANAGER)) revert InvalidCaller(msg.sender, address(POLICY_MANAGER));
        _;
    }

    constructor(address policyManager) {
        POLICY_MANAGER = PolicyManager(policyManager);
    }

    /// @notice Authorize the execution and build the account call and optional post-call.
    ///
    /// @dev MUST revert to refuse execution. `policyConfig` is the binding preimage; the manager has already
    ///      verified it recomputes to the actor's signed commitment. If `accountCallData` is empty, the manager
    ///      treats the call as a no-op (no account call, no {onPostExecute}, no event).
    ///
    /// @param commitment    Identifier of the authorized binding.
    /// @param account       Account the plan will execute against.
    /// @param policyConfig  Policy-defined config bytes (may be empty).
    /// @param executionData Per-use action parameters.
    /// @param caller        The address that invoked the manager.
    ///
    /// @return accountCallData ABI-encoded calldata for the manager to forward to `account` (empty = no-op).
    /// @return postCallData    Opaque bytes forwarded to {onPostExecute} after the account call (may be empty).
    function onExecute(
        bytes32 commitment,
        address account,
        bytes calldata policyConfig,
        bytes calldata executionData,
        address caller
    ) external onlyPolicyManager returns (bytes memory accountCallData, bytes memory postCallData) {
        return _onExecute(commitment, account, policyConfig, executionData, caller);
    }

    /// @notice Hook invoked by the manager after a non-empty account call.
    ///
    /// @dev Called whenever {onExecute} returns non-empty `accountCallData`. `postCallData` may be empty;
    ///      implementations must handle that case. Default is a no-op.
    ///
    /// @param commitment  Identifier of the authorized binding.
    /// @param account     Account associated with the binding.
    /// @param postCallData Policy-defined post-call payload returned by {onExecute}.
    function onPostExecute(bytes32 commitment, address account, bytes calldata postCallData)
        external
        onlyPolicyManager
    {
        _onPostExecute(commitment, account, postCallData);
    }

    /// @dev Policy-specific execute logic. Revert to refuse. Validate config here as needed.
    function _onExecute(
        bytes32 commitment,
        address account,
        bytes calldata policyConfig,
        bytes calldata executionData,
        address caller
    ) internal virtual returns (bytes memory accountCallData, bytes memory postCallData);

    /// @dev Policy-specific post-execute hook. Default no-op; override for post-call checks (e.g. balance deltas).
    function _onPostExecute(bytes32 commitment, address account, bytes calldata postCallData) internal virtual {
        commitment;
        account;
        postCallData;
    }
}
