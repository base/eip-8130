// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {PolicyManager} from "./PolicyManager.sol";

/// @title Policy
///
/// @notice Minimal base hook interface for policies coordinated by {PolicyManager}.
///
/// @dev A policy turns an account-authorized *commitment* (its `policyConfig`, stored at install) plus a
///      per-use *action* (`executionData`, supplied when the session key transacts) into an account call plan.
///      The plan is ABI-encoded calldata that the manager forwards to the account (e.g. `executeBatch`).
///
///      This is the example/reference shape for an EIP-8130 actor policy (`scope & SCOPE_POLICY != 0`): the
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

    /// @notice Hook invoked when the account installs a binding for this policy.
    ///
    /// @dev MUST revert to refuse installation. Implementations parse and store `policyConfig` keyed by
    ///      `commitment` so later executions read committed parameters rather than caller-supplied ones.
    ///
    /// @param commitment Deterministic identifier of the account-authorized binding (the policy commitment).
    /// @param account    Account that authorized the binding.
    /// @param policyConfig Committed, policy-defined configuration bytes (e.g. token + weekly limit, allowed selectors).
    function onInstall(bytes32 commitment, address account, bytes calldata policyConfig) external onlyPolicyManager {
        _onInstall(commitment, account, policyConfig);
    }

    /// @notice Hook invoked when a restricted actor exercises the policy via the manager.
    ///
    /// @dev MUST revert to refuse execution. Returns the account call plan, or empty bytes for a no-op.
    ///      Implementations enforce the committed policy against `executionData` and build the plan.
    ///
    /// @param commitment    Identifier of the installed binding.
    /// @param account       Account the plan will execute against.
    /// @param executionData Per-use action parameters (e.g. transfer recipient + amount, or a target call).
    /// @param caller        The address that invoked the manager (in EIP-8130, the account itself).
    ///
    /// @return accountCallData ABI-encoded calldata for the manager to forward to `account` (empty = no-op).
    function onExecute(bytes32 commitment, address account, bytes calldata executionData, address caller)
        external
        onlyPolicyManager
        returns (bytes memory accountCallData)
    {
        return _onExecute(commitment, account, executionData, caller);
    }

    /// @dev Policy-specific install logic. Revert to refuse.
    function _onInstall(bytes32 commitment, address account, bytes calldata policyConfig) internal virtual;

    /// @dev Policy-specific execute logic. Revert to refuse.
    function _onExecute(bytes32 commitment, address account, bytes calldata executionData, address caller)
        internal
        virtual
        returns (bytes memory accountCallData);
}
