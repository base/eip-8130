// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @notice Canonical EIP-8130 actor scope grants.
/// @dev Scope assignments are append-only; unknown bits are stored verbatim and grant no authority.
///      Core grants occupy bits 0–2; the optional POLICY and NONCE grants trail them.
///      Keystore stores `scope` verbatim and never interprets these bits; consumers enforce meaning at use time.
///      OPERATOR and POLICY do not combine: OPERATOR may originate to any `call.to`; POLICY-only is gated to the
///      actor's policy manager.
library Scopes {
    /// @notice Ungated initiation (`sender_auth`): may originate transactions to any `call.to`.
    uint16 internal constant OPERATOR = 0x0001;

    /// @notice Self-pay gas: authorizes paying the account's own gas when `payer == sender`.
    uint16 internal constant SELF_PAYER = 0x0002;

    /// @notice Sponsor gas: authorizes acting as `payer_auth` for a different sender (`payer != sender`).
    uint16 internal constant SPONSOR_PAYER = 0x0004;

    /// @notice Gated initiation (`sender_auth`): may originate transactions only to the actor's policy manager.
    ///         Optional grant.
    uint16 internal constant POLICY = 0x0008;

    /// @notice Permits a restricted actor to use sequenced `nonce_key`s for sender-context transactions.
    ///         Optional grant.
    uint16 internal constant NONCE = 0x0010;

    // 0x0020..0x8000 (bits 5–15) are spare, reserved for future pure grants.

    /// @notice Whether `scope` grants operational authority — the authority to drive execution and to sign
    ///         (ERC-1271) as the account.
    ///
    /// @dev Operational means the unrestricted admin (`scope == 0`) or an {OPERATOR} actor. POLICY does not
    ///      suppress OPERATOR: the two grants do not combine, and OPERATOR is the more permissive of the two.
    ///      A POLICY-only actor is deliberately not operational — it must route every call through its policy
    ///      manager. This is the single shared definition consumers use to keep the execution and signing
    ///      authorization surfaces aligned (see DefaultAccount).
    ///
    /// @param scope The actor scope bitmask to test.
    ///
    /// @return True iff `scope` carries operational authority.
    function isOperator(uint16 scope) internal pure returns (bool) {
        return scope == 0 || (scope & OPERATOR != 0);
    }
}
