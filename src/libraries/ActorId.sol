// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @notice Canonical derivation of an actorId from an address-based identity.
///
/// @dev Address-derived actors — an ECDSA/k1 recovered signer, a delegate, an external policy caller, and the
///      implicit self — carry their raw address as the actorId (no hashing, no salt). The address is placed
///      RIGHT-ALIGNED in the 32-byte word, i.e. the ABI `address` layout `bytes32(uint256(uint160(addr)))` (high 12
///      bytes zero). This matches `abi.encode(address)`, an indexed `address` event topic, and the standard
///      `address(uint160(uint256(id)))` round-trip, so off-chain tooling and indexers can correlate an actorId with
///      the address it represents without a bespoke (left-aligned) decode. Defined once here so the self and
///      recovered-signer derivations — which must always agree for the inline k1 self to authenticate — can never
///      drift.
library ActorId {
    /// @dev The actorId for an address-derived actor: `addr` right-aligned into a 32-byte word.
    function fromAddress(address addr) internal pure returns (bytes32) {
        return bytes32(uint256(uint160(addr)));
    }
}
