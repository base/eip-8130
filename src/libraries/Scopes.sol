// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @notice Canonical EIP-8130 actor scope grants: the named bits of the `uint16` scope bitmask carried in an
///         actor's config.
///
/// @dev Reference vocabulary, not enforcement. AccountConfiguration is deliberately scope-agnostic: it treats
///      `scope == 0` as the admin predicate and interprets only {POLICY} (to slice/store policy data). Every other
///      bit's *meaning* is enforced by whoever reads it — protocol nodes for the transaction paths, account
///      contracts for ERC-1271, policy managers for gating. This library only gives those consumers a shared set of
///      names so the same value is not re-declared as a magic number at each site.
///
///      The assignment is append-only: a value once given a name keeps it, and new grants take the next free bit.
///      That is safe against the immutable AccountConfiguration deployment because unknown bits grant nothing and
///      are stored verbatim (see the EIP's Actor Scope section), so adding a bit here can never change how an
///      already-deployed config behaves. Admin is intentionally absent — it is the *absence* of grants
///      (`scope == 0`), a predicate rather than a pure grant.
///
/// @author Coinbase
library Scopes {
    /// @notice Ungated initiation (`sender_auth`): may originate transactions to any `call.to`.
    uint16 internal constant SENDER = 0x0001;

    /// @notice Gated initiation (`sender_auth`): may originate transactions only to the actor's `policy_manager`.
    ///         The one bit AccountConfiguration itself interprets, to slice and store the actor's policy data.
    uint16 internal constant POLICY = 0x0002;

    /// @notice Permits a restricted actor to use sequenced `nonce_key`s for sender-context transactions.
    uint16 internal constant NONCE = 0x0004;

    /// @notice Self-pay gas: authorizes paying the account's own gas when `payer == sender`.
    uint16 internal constant SELF_PAYER = 0x0008;

    /// @notice Sponsor gas: authorizes acting as `payer_auth` for a different sender (`payer != sender`).
    uint16 internal constant SPONSOR_PAYER = 0x0010;

    /// @notice Manage delegate actors: authorizes authorizing/revoking actors whose
    ///         `authenticator == DELEGATE_AUTHENTICATOR`, without conferring full admin config authority.
    uint16 internal constant DELEGATE = 0x0020;

    // 0x0040..0x8000 (bits 6–15) are spare, reserved for future pure grants.
}
