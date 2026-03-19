// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Reference interface for the EIP-8130 Transaction Context precompile at TX_CONTEXT_ADDRESS.
///         Read-only. Gas is charged as a base cost plus 3 gas per 32 bytes of returned data.
///         On non-8130 chains, no code at TX_CONTEXT_ADDRESS; STATICCALL returns zero/default values.
interface ITxContext {
    struct Call {
        address to;
        bytes data;
    }

    function getSender() external view returns (address);
    function getPayer() external view returns (address);
    function getOwnerId() external view returns (bytes32);
    function getCalls() external view returns (Call[][] memory);
    function getMaxCost() external view returns (uint256);
    function getGasLimit() external view returns (uint256);
}
