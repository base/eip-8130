// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Call} from "./IExecuteBatch.sol";

/// @title IPolicyCallEncoder
///
/// @notice Transformer that encodes a policy's wallet-agnostic {Call} plan into calldata for a specific account's
///         execution ABI. A {PolicyBinding} may name one via its `transformer` field; when unset (address(0)), the
///         self-executing policy uses its default `executeBatch(Call[])` encoding.
///
/// @dev The policy invokes the encoder with STATICCALL (the function is `view`), so a transformer can produce
///      calldata but can never execute, mutate state, or hold authority. This makes it safe for a transformer to be
///      a shared per-ABI library contract OR the account itself (an account may implement this interface to describe
///      how to drive its own entrypoint). The transformer is bound into the commitment, so the account authorizes
///      exactly which encoder runs for a given binding.
///
/// @author Coinbase
interface IPolicyCallEncoder {
    /// @notice Encodes `calls` into the calldata to forward to `account`'s execution entrypoint.
    ///
    /// @param account Account the calldata will be forwarded to.
    /// @param calls   Wallet-agnostic call plan produced by the policy.
    ///
    /// @return The calldata the policy forwards to `account`.
    function encodeCalls(address account, Call[] calldata calls) external view returns (bytes memory);
}
