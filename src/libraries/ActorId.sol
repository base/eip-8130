// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @notice Utilities for deriving actor IDs.
library ActorId {
    /// @dev The actorId for an address-derived actor: `addr` right-aligned into a 32-byte word.
    function fromAddress(address addr) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(addr)));
    }
}
