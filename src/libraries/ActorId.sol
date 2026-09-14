// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @notice Utilities for deriving actor IDs.
library ActorId {
    /// @dev Class tag OR'd into the high bytes of an address-derived actorId to mark the OPERATOR class of a
    ///      delegate account (see DelegateAuthenticator): `0x10 ‖ 11 zero bytes ‖ address`. Address-derived
    ///      admin-class ids have all 12 high bytes zero, so the two classes can never collide.
    bytes32 internal constant OPERATOR_CLASS_TAG = 0x1000000000000000000000000000000000000000000000000000000000000000;

    /// @dev The actorId for an address-derived actor: `addr` right-aligned into a 32-byte word.
    function fromAddress(address addr) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(addr)));
    }

    /// @dev The actorId for the OPERATOR class of a delegate account: {OPERATOR_CLASS_TAG} ‖ `addr`. Returned by
    ///      DelegateAuthenticator when the nested signer is a non-admin operator of `addr`.
    function operatorOfAddress(address addr) internal pure returns (bytes32) {
        return OPERATOR_CLASS_TAG | bytes32(uint256(uint160(addr)));
    }
}
