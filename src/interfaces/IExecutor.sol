// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Canonical batched-call type for EIP-8130 account execution. Shared across every 8130 account so the
///         protocol (direct dispatch), bundlers, tooling, and PolicyManagers all encode `executeBatch` calldata
///         against one definition, rather than each contract re-declaring a structurally identical struct (which
///         the compiler treats as a distinct, non-interchangeable type).
struct Call {
    address target;
    uint256 value;
    bytes data;
}

/// @notice Minimal execution surface every EIP-8130 account exposes. Declared as an interface so implementations
///         living in other repositories (e.g. Base Account V2) can conform to the exact selector and `Call`
///         layout the protocol and tooling expect, without inheriting any implementation or storage.
interface IExecutor {
    function executeBatch(Call[] calldata calls) external;
}
