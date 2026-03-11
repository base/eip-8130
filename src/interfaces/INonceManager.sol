// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Reference interface for the EIP-8130 Nonce Manager precompile at NONCE_MANAGER_ADDRESS.
///         Read-only. The protocol manages nonce storage directly; no state-modifying functions.
interface INonceManager {
    function getNonce(address account, uint192 nonceKey) external view returns (uint64);
}
