// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Reference interface for the EIP-8130 Transaction Context precompile at TX_CONTEXT_ADDRESS.
///         Read-only. Gas is charged as a base cost plus 3 gas per 32 bytes of returned data.
///         On non-8130 chains, no code at TX_CONTEXT_ADDRESS; STATICCALL returns zero/default values.
interface ITransactionContext {
    function getTransactionSender() external view returns (address);
    function getTransactionPayer() external view returns (address);
    function getTransactionSenderActorId() external view returns (bytes32);
}
