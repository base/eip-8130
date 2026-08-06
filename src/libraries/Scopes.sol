// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @notice Canonical EIP-8130 actor scope grants: the named bits of the `uint16` scope bitmask carried in an
///         actor's config.
///
/// @dev Reference vocabulary, not enforcement. Keystore is deliberately scope-agnostic: it treats `scope == 0` as
///      the admin predicate and interprets only {POLICY} (to slice/store policy data). Every other bit's *meaning*
///      is enforced by whoever reads it — protocol nodes for the transaction paths, account contracts for ERC-1271,
///      policy managers for gating. This library only gives those consumers a shared set of names so the same value
///      is not re-declared as a magic number at each site.
///
///      Delegation for agent fleets is expressed via the external-policy pattern (an account authorizes a hub as a
///      single POLICY-gated external actor that drives it through a policy manager), so no dedicated delegate grant
///      is defined here.
///
///      The assignment is append-only: a value once given a name keeps it, and new grants take the next free bit.
///      That is safe against the immutable Keystore deployment because unknown bits grant nothing and are stored
///      verbatim (see the EIP's Actor Scope section), so adding a bit here can never change how an already-deployed
///      config behaves. Admin is intentionally absent — it is the *absence* of grants (`scope == 0`), a predicate
///      rather than a pure grant.
///
/// @author Coinbase
library Scopes {
    /// @notice Ungated initiation (`sender_auth`): may originate transactions to any `call.to`.
    uint16 internal constant SENDER = 0x0001;

    /// @notice Gated initiation (`sender_auth`): may originate transactions only to the actor's `policy_manager`.
    ///         The one bit Keystore itself interprets, to slice and store the actor's policy data.
    uint16 internal constant POLICY = 0x0002;

    /// @notice Permits a restricted actor to use sequenced `nonce_key`s for sender-context transactions.
    uint16 internal constant NONCE = 0x0004;

    /// @notice Self-pay gas: authorizes paying the account's own gas when `payer == sender`.
    uint16 internal constant SELF_PAYER = 0x0008;

    /// @notice Sponsor gas: authorizes acting as `payer_auth` for a different sender (`payer != sender`).
    uint16 internal constant SPONSOR_PAYER = 0x0010;

    // 0x0020..0x8000 (bits 5–15) are spare, reserved for future pure grants.

    /// @notice Whether `scope` grants operational authority — the authority to drive execution and to sign
    ///         (ERC-1271) as the account.
    ///
    /// @dev Operational means either the unrestricted admin (`scope == 0`) or a {SENDER} actor that is not gated by
    ///      a policy ({POLICY} unset). A POLICY-gated actor is deliberately not operational: it must route every
    ///      call through its policy manager, so letting it drive execution or vouch a signature would act outside
    ///      that gate. This is the single shared definition consumers use to keep the execution and signing
    ///      authorization surfaces aligned (see DefaultAccount).
    ///
    /// @param scope The actor scope bitmask to test.
    ///
    /// @return True iff `scope` carries operational authority.
    function isOperational(uint16 scope) internal pure returns (bool) {
        return scope == 0 || ((scope & SENDER != 0) && (scope & POLICY == 0));
    }
}
