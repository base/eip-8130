// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @notice A single call in an execution plan: the wallet-agnostic (target, value, data) triple a policy produces and
///         a {PolicyManager} encodes into account-specific calldata.
struct Call {
    /// @dev Address the account calls.
    address target;
    /// @dev Wei forwarded with the call.
    uint256 value;
    /// @dev Calldata passed to `target`.
    bytes data;
}

/// @title IExecuteBatch
///
/// @notice Canonical default account execution ABI: the `executeBatch(Call[])` surface shared by the EIP-8130 default
///         account and common smart wallets (e.g. Coinbase Smart Wallet v2).
///
/// @dev {PolicyManager} references this to derive its default encoding selector. A manager targeting a wallet with a
///      different execution ABI overrides {PolicyManager._encodeCalls} instead of using this.
///
/// @author Coinbase
interface IExecuteBatch {
    /// @notice Executes a batch of calls from the account.
    /// @param calls Ordered calls to execute, each as (target, value, data).
    function executeBatch(Call[] calldata calls) external;
}
