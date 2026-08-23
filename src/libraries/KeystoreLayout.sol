// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @notice EIP-8130 Keystore actor-record layout (GC-ready).
///
///         Each actor occupies a contiguous 3-word record: `{base, base+1, base+2}`.
///         word0 keeps the existing `actor_config` Solidity packing (authenticator, expiry, scope);
///         the CLEANABLE marker in the reserved region tags a reap-eligible actor record and
///         distinguishes it from the (never-reaped) account-state record.
///
///         word0 packing (low bytes first, matching the `ActorConfig` storage layout):
///           authenticator : bits 0..159
///           expiry        : bits 160..207 (uint48)
///           scope         : bits 208..223 (uint16)
///           reserved      : bits 224..255   <-- CLEANABLE lives here
///
///         CLEANABLE is the low bit of the last byte of word0 (bit 248). That byte is reserved
///         on both the actor record and AccountState (which MUST keep it zero), so a stem-walk
///         reaper can skip account-state without an `(account, actorId)` preimage.
library KeystoreLayout {
    /// @dev Low bit of the last byte of word0. Set on every reap-eligible actor record; never set
    ///      on AccountState (its reserved byte stays zero).
    uint256 internal constant CLEANABLE = uint256(1) << 248;

    /// @dev Base slot salt for the actor-record region. `record(account, actorId) -> {base, base+1, base+2}`.
    bytes32 internal constant ACTOR_RECORD_BASE = keccak256("eip8130.actor.record.v1");

    /// @dev First slot of the 3-word record. The words are contiguous and 4-aligned so a record never
    ///      straddles a 256-slot group, which lets a slot-grouping tree place the whole record in one stem.
    ///      `account` is the first `abi.encode` word so the unaligned hash is `keccak256(account || x)`
    ///      (ERC-7562 associated storage). Ceiling-aligning (not flooring) keeps `{base, base+1, base+2}`
    ///      at `keccak256(account || x) + n` for `n < 4`.
    function recordBase(address account, bytes32 actorId) internal pure returns (bytes32 base) {
        bytes32 h = keccak256(abi.encode(account, actorId, ACTOR_RECORD_BASE));
        base = bytes32((uint256(h) + 3) & ~uint256(3));
    }

    /// @dev Pack word0: existing `ActorConfig` fields plus the CLEANABLE marker.
    function packWord0(address authenticator, uint48 expiry, uint16 scope) internal pure returns (uint256 w0) {
        w0 = uint256(uint160(authenticator)) | (uint256(expiry) << 160) | (uint256(scope) << 208) | CLEANABLE;
    }
}
