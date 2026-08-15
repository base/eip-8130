// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {PolicyManager} from "./PolicyManager.sol";

/// @title Policy
///
/// @notice Minimal base hook interface for policies coordinated by {PolicyManager}.
///
/// @dev A policy turns an account-authorized commitment plus a per-use action (`executionData`) into an
///      ABI-encoded account call plan that the manager forwards to the account. The manager verifies the
///      supplied `policyConfig` recomputes to the actor's signed commitment before calling {onExecute}, so a
///      policy MUST validate config in {onExecute} and MUST NOT store a config hash. Store only mutable execution
///      state (e.g. spend counters), keyed by commitment. All hooks are callable only by {POLICY_MANAGER}.
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
    /// @dev Reverts with InvalidCaller when the caller is not {POLICY_MANAGER}.
    /// @dev Implementations MUST revert to refuse execution. `policyConfig` is the binding preimage, already
    ///      verified by the manager to recompute to the actor's signed commitment. An empty `accountCallData`
    ///      return is treated as a no-op (no account call, no {onPostExecute}, no event).
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
    /// @dev Reverts with InvalidCaller when the caller is not {POLICY_MANAGER}.
    /// @dev Invoked whenever {onExecute} returns non-empty `accountCallData`; `postCallData` may be empty, so
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
