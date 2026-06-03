// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC20} from "openzeppelin/token/ERC20/IERC20.sol";

import {Call, DefaultAccount} from "../../accounts/DefaultAccount.sol";
import {Policy} from "./Policy.sol";
import {RecurringAllowance} from "./RecurringAllowance.sol";

/// @title ERC20SpendLimitPolicy
///
/// @notice Example EIP-8130 policy: a recurring (e.g. weekly) per-binding ERC-20 spend limit.
///
/// @dev Each installed binding governs one token with one recurring allowance. To grant a key limits on two
///      tokens, install two bindings (two commitments) for the same key; the manager routes each by commitment.
///      The committed `policyConfig` is the {Config}; per-use `executionData` is a {Transfer}. On execution the
///      policy consumes the allowance and builds an `executeBatch` plan that performs the ERC-20 transfer from
///      the account.
contract ERC20SpendLimitPolicy is Policy {
    using RecurringAllowance for RecurringAllowance.State;

    /// @notice Committed per-binding configuration.
    struct Config {
        /// @dev ERC-20 token this binding may spend.
        address token;
        /// @dev Maximum spend per period window.
        uint160 allowance;
        /// @dev Period length in seconds (e.g. 7 days).
        uint40 period;
        /// @dev Window start (seconds, inclusive).
        uint40 start;
        /// @dev Window end (seconds, exclusive).
        uint40 end;
    }

    /// @notice Per-use action: an ERC-20 transfer from the account.
    struct Transfer {
        address to;
        uint256 amount;
    }

    /// @dev Committed config per binding commitment.
    mapping(bytes32 commitment => Config) internal _config;

    /// @dev Recurring spend accounting per binding commitment.
    RecurringAllowance.State internal _allowance;

    /// @notice Thrown when execution data targets a different token than the committed one.
    error UnexpectedToken();

    constructor(address policyManager) Policy(policyManager) {}

    /// @notice Returns the committed config for a binding.
    function getConfig(bytes32 commitment) external view returns (Config memory) {
        return _config[commitment];
    }

    /// @notice Returns current-period usage for a binding.
    function getCurrentPeriod(bytes32 commitment) external view returns (RecurringAllowance.PeriodUsage memory) {
        return _allowance.getCurrentPeriod(commitment, _limit(_config[commitment]));
    }

    function _onInstall(bytes32 commitment, address, bytes calldata policyConfig) internal override {
        _config[commitment] = abi.decode(policyConfig, (Config));
    }

    function _onExecute(bytes32 commitment, address, bytes calldata executionData, address)
        internal
        override
        returns (bytes memory accountCallData)
    {
        Config memory config = _config[commitment];
        Transfer memory transfer = abi.decode(executionData, (Transfer));

        // Consume the recurring allowance; reverts if the period budget would be exceeded.
        _allowance.useLimit(commitment, _limit(config), transfer.amount);

        Call[] memory calls = new Call[](1);
        calls[0] = Call({
            target: config.token, value: 0, data: abi.encodeCall(IERC20.transfer, (transfer.to, transfer.amount))
        });
        return abi.encodeCall(DefaultAccount.executeBatch, (calls));
    }

    function _limit(Config memory config) internal pure returns (RecurringAllowance.Limit memory) {
        return RecurringAllowance.Limit({
            allowance: config.allowance, period: config.period, start: config.start, end: config.end
        });
    }
}
