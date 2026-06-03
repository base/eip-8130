// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Call, DefaultAccount} from "../../accounts/DefaultAccount.sol";
import {Policy} from "./Policy.sol";

/// @title SelectorGatingPolicy
///
/// @notice Example EIP-8130 policy: restrict a key to a single target contract and a fixed set of function
///         selectors (e.g. allow only Morpho `supply`/`withdraw`).
///
/// @dev Stateless beyond the committed allow-set. The committed `policyConfig` is the {Config}; per-use
///      `executionData` is a {Action} carrying the value and full calldata. On execution the policy checks the
///      calldata selector against the committed allow-set and builds an `executeBatch` plan for the target.
contract SelectorGatingPolicy is Policy {
    /// @notice Committed per-binding configuration.
    struct Config {
        /// @dev The only contract this binding may call.
        address target;
        /// @dev Allowed 4-byte function selectors on `target`.
        bytes4[] selectors;
    }

    /// @notice Per-use action: a single call to the committed target.
    struct Action {
        uint256 value;
        bytes data;
    }

    /// @dev Committed target per binding commitment.
    mapping(bytes32 commitment => address target) internal _target;

    /// @dev Committed selector allow-set per binding commitment.
    mapping(bytes32 commitment => mapping(bytes4 selector => bool allowed)) internal _allowed;

    /// @notice Thrown when the action calldata is shorter than a 4-byte selector.
    error MissingSelector();

    /// @notice Thrown when the action selector is not in the committed allow-set.
    error SelectorNotAllowed(bytes4 selector);

    constructor(address policyManager) Policy(policyManager) {}

    /// @notice Returns the committed target for a binding.
    function getTarget(bytes32 commitment) external view returns (address) {
        return _target[commitment];
    }

    /// @notice Returns whether a selector is allowed for a binding.
    function isSelectorAllowed(bytes32 commitment, bytes4 selector) external view returns (bool) {
        return _allowed[commitment][selector];
    }

    function _onInstall(bytes32 commitment, address, bytes calldata policyConfig) internal override {
        Config memory config = abi.decode(policyConfig, (Config));
        _target[commitment] = config.target;
        for (uint256 i; i < config.selectors.length; i++) {
            _allowed[commitment][config.selectors[i]] = true;
        }
    }

    function _onExecute(bytes32 commitment, address, bytes calldata executionData, address)
        internal
        view
        override
        returns (bytes memory accountCallData)
    {
        Action memory action = abi.decode(executionData, (Action));
        bytes memory data = action.data;
        if (data.length < 4) revert MissingSelector();

        bytes4 selector;
        assembly ("memory-safe") {
            selector := mload(add(data, 0x20))
        }
        if (!_allowed[commitment][selector]) revert SelectorNotAllowed(selector);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: _target[commitment], value: action.value, data: action.data});
        return abi.encodeCall(DefaultAccount.executeBatch, (calls));
    }
}
