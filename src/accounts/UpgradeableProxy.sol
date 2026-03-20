// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @notice Generates runtime bytecode for an ERC-1967 proxy with a hardcoded default
///         implementation. Works immediately on deployment — no initialization required.
///
///         Proxy logic:
///           1. SLOAD the ERC-1967 implementation slot
///           2. If non-zero, delegatecall to that address (upgraded path)
///           3. If zero, delegatecall to the hardcoded default (fresh deployment path)
///
///         93 bytes total. Overhead vs ERC-1167: one SLOAD per call (2100 gas cold, 100 warm).
library UpgradeableProxy {
    function bytecode(address defaultImplementation) internal pure returns (bytes memory) {
        return abi.encodePacked(
            // Phase 1: resolve implementation
            //   PUSH32 ERC1967_SLOT, SLOAD, DUP1, ISZERO
            //   PUSH2 default_label(0x002c), JUMPI
            //   PUSH2 delegate_label(0x0043), JUMP
            hex"7f360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",
            hex"5480156100",
            hex"2c",
            hex"576100",
            hex"4356",
            // default_label: POP, PUSH20 <default>
            hex"5b5073",
            defaultImplementation,
            // delegate_label: delegatecall, return/revert
            hex"5b363d3d373d3d3d363d855af43d82803e903d91605b57fd5bf3"
        );
    }
}
