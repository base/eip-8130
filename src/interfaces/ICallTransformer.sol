// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @notice A single call in an execution plan: the wallet-agnostic (target, value, data) triple a policy produces and
///         a transformer (or the manager's default encoding) turns into account-specific calldata.
struct Call {
    /// @dev Address the account calls.
    address target;
    /// @dev Wei forwarded with the call.
    uint256 value;
    /// @dev Calldata passed to `target`.
    bytes data;
}

/// @title ICallTransformer
///
/// @notice Adapter that encodes a policy-produced {Call} plan into the exact calldata for a specific account's
///         execution ABI.
///
/// @dev When a binding pins a transformer, {PolicyManager} staticcalls {transform} to obtain the calldata it forwards
///      to the account; a binding with no transformer uses the manager's default `executeBatch(Call[])` encoding. A
///      transformer is fully trusted by the account that commits to it: the manager forwards its output verbatim, so
///      it can encode any account call, exactly as the account already trusts the policy to produce the plan. It MUST
///      be view (invoked via staticcall) and MUST return non-empty calldata.
///
/// @author Coinbase
interface ICallTransformer {
    /// @notice Encodes `calls` into calldata for `account`'s execution entrypoint.
    ///
    /// @param account Account the encoded calldata will be forwarded to.
    /// @param calls   Wallet-agnostic call plan produced by the policy.
    ///
    /// @return accountCallData Calldata the manager forwards to `account` (MUST be non-empty).
    function transform(address account, Call[] calldata calls) external view returns (bytes memory accountCallData);
}

/// @title IExecuteBatch
///
/// @notice Canonical default account execution ABI: the `executeBatch(Call[])` surface shared by the EIP-8130 default
///         account and common smart wallets (e.g. Coinbase Smart Wallet v2).
///
/// @dev {PolicyManager} references this only to derive the default encoding selector for bindings with no transformer,
///      keeping the manager decoupled from any concrete account implementation.
///
/// @author Coinbase
interface IExecuteBatch {
    /// @notice Executes a batch of calls from the account.
    /// @param calls Ordered calls to execute, each as (target, value, data).
    function executeBatch(Call[] calldata calls) external;
}
