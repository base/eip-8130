// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @title IERC7821
///
/// @notice Minimal batch-executor execution ABI defined by ERC-7821.
///
/// @dev Referenced by {ERC7821PolicyManager} to derive the encoding selector for accounts that expose the ERC-7821
///      `execute(bytes32,bytes)` entrypoint rather than the default `executeBatch(Call[])`.
///
/// @author Coinbase
interface IERC7821 {
    /// @notice Executes an encoded batch under the given execution mode.
    /// @param mode          ERC-7821 execution mode identifier.
    /// @param executionData Mode-specific encoded calls (for batch mode, `abi.encode(Call[])`).
    function execute(bytes32 mode, bytes calldata executionData) external payable;
}
