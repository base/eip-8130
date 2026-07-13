// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../AccountConfiguration.sol";
import {DefaultAccount} from "../DefaultAccount.sol";

struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

/// @notice One independently-signed batch of actor changes, mirroring a single
///         `AccountConfiguration.applySignedActorChanges` call. Multiple sets may be
///         supplied in a UserOperation signature and are applied in order (e.g. a set
///         signed by the current owner, followed by a set signed by a key it just
///         authorized).
struct SignedActorChanges {
    AccountConfiguration.ActorChange[] changes;
    bytes auth;
}

/// @notice Example ERC-4337-compatible account for EIP-8130: {DefaultAccount} plus `validateUserOp`, reproducing
///         the 8130 authorization semantics (scope + policy) so an account works on non-8130 chains via a bundler +
///         EntryPoint, identically to native dispatch.
///
///         The EntryPoint is authorized like any other caller: a revocable TRUSTED_EXECUTOR actor in
///         AccountConfiguration (see {DefaultAccount}). A signed CONFIG change swaps it for a different address at
///         any time, even on non-upgradeable accounts, and supports any EntryPoint version since the account's
///         CREATE2 address never depends on it.
///
///         ERC-7562: authorizing the caller and authenticating the op both read the account's own associated
///         storage in AccountConfiguration, keeping both within the same validation-phase storage category.
///
///         Bootstrapping: the EntryPoint must already be a TRUSTED_EXECUTOR actor before its first call (gated by
///         `_isAuthorizedCaller`). Seed it into the initial actor set at `createAccount` for a counterfactual
///         account's first op to work out of the box; otherwise register it later via a signed actor change.
contract BackwardsCompatible4337Account is DefaultAccount {
    /// @dev Signature discriminator for validation-phase actor changes: when `userOp.signature` starts with this
    ///      32-byte magic, it decodes as `abi.encode(magic, SignedActorChanges[] changeSets, bytes opAuth)` and
    ///      each change set is applied in order (e.g. rotating the controlling key to a P-256 actor) before the op
    ///      is authenticated. Each change is bound to this account + a monotonic sequence and authorized by the
    ///      account's own key, so applying it only ever mutates this account's own config — it never authorizes
    ///      the op itself. The trailing `opAuth` (a plain `authenticator || data` blob) must still sign for this
    ///      exact `userOpHash`, and may come from a key the changes just added/rotated to. A signature without the
    ///      magic prefix is itself treated as the plain `opAuth` blob, preserving the base behaviour.
    bytes32 internal constant SIGNED_ACTOR_CHANGES_MAGIC = keccak256("ERC4337Account.signedActorChanges.v1");

    /// @dev Elevated-scope bitflags, mirroring AccountConfiguration. A scope of 0x00 is an unrestricted owner.
    uint8 internal constant SCOPE_SENDER = 0x01; // may initiate transactions (authorize the op's calls)
    uint8 internal constant SCOPE_SELF_PAYER = 0x08; // may self-pay gas for the account's own op (payer == sender)

    constructor(address accountConfiguration) DefaultAccount(accountConfiguration) {}

    // ══════════════════════════════════════════════
    //  ERC-4337
    // ══════════════════════════════════════════════

    /// @notice Validates a UserOperation signature via the AccountConfiguration system.
    ///         Signature format follows 8130 authenticator conventions (authenticator_type || data),
    ///         and optionally carries signed actor/owner changes applied during validation
    ///         (see {SIGNED_ACTOR_CHANGES_MAGIC}).
    ///
    /// @dev Reverts with UnauthorizedCaller when the caller is neither the account nor a TRUSTED_EXECUTOR actor
    ///      (typically the EntryPoint).
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256 validationData)
    {
        if (!_isAuthorizedCaller(msg.sender)) revert UnauthorizedCaller();

        validationData = _validateSignature(userOp, userOpHash, missingAccountFunds) ? 0 : 1;

        if (missingAccountFunds != 0) {
            assembly {
                pop(call(gas(), caller(), missingAccountFunds, 0, 0, 0, 0))
            }
        }
    }

    /// @notice Validates `userOp` by authenticating it as a plain authenticator blob over `userOpHash` and
    ///         enforcing the verified actor's elevated scope. A signature carrying signed actor/owner changes
    ///         additionally applies them during validation before the op itself is authenticated.
    /// @dev Signed-actor-changes path: each set is applied via `applySignedActorChanges` (empty batch rejected).
    ///      Every slot it writes is keyed by `account`, so under ERC-7562 it's the account's own associated
    ///      storage — allowed by STO-021 for an existing account; only a combined create+change op falls under
    ///      STO-022, requiring the AccountConfiguration factory to be staked.
    ///
    ///      Op authentication (both paths) enforces the verified actor's elevated scope:
    ///        - the actor must be unrestricted (scope 0x00) or hold {SCOPE_SENDER} to authorize the calls;
    ///        - a self-funded op (`missingAccountFunds != 0`) additionally requires {SCOPE_SELF_PAYER}.
    ///      This reduced 4337 bridge does not replicate the native-dispatch policy-target gate: a SCOPE_POLICY
    ///      actor without SCOPE_SENDER is rejected here by construction (see {_authorize}), and this repo does not
    ///      implement protocol-side lane/exclusivity checks for actors that combine SCOPE_POLICY with SCOPE_SENDER.
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        internal
        returns (bool)
    {
        bytes calldata signature = userOp.signature;
        bytes memory opAuth = signature;

        if (signature.length >= 32 && bytes32(signature[:32]) == SIGNED_ACTOR_CHANGES_MAGIC) {
            SignedActorChanges[] memory changeSets;
            (, changeSets, opAuth) = abi.decode(signature, (bytes32, SignedActorChanges[], bytes));

            if (changeSets.length == 0) return false;

            // Each set is bound to address(this) + a monotonic sequence (see SIGNED_ACTOR_CHANGES_MAGIC above),
            // so it only ever mutates this account's own config.
            for (uint256 i; i < changeSets.length; i++) {
                try ACCOUNT_CONFIGURATION.applySignedActorChanges(
                    address(this), uint64(block.chainid), changeSets[i].changes, changeSets[i].auth
                ) {}
                catch {
                    return false;
                }
            }
        }

        // Applying changes never authorizes the op; `opAuth` must still sign for this `userOpHash`.
        (bool valid, uint8 scope) = _authenticate(userOpHash, opAuth);
        if (!valid) return false;

        // Authentication only proves WHO signed; authorization decides whether that actor may drive THIS op.
        return _authorize(scope, missingAccountFunds);
    }

    /// @notice Authenticates `auth` over `hash` via AccountConfiguration, resolving the signing actor's scope.
    ///         This answers only "who signed", never "may they do this" — see {_authorize}.
    /// @return valid True if `auth` is a valid signature from a live actor of this account.
    /// @return scope The verified actor's scope (0x00 = unrestricted owner).
    function _authenticate(bytes32 hash, bytes memory auth) internal view returns (bool valid, uint8 scope) {
        // policyTarget is a protocol-side / policy-manager concern this reduced 4337 bridge does not replicate:
        // a SCOPE_POLICY actor is rejected below by the SCOPE_SENDER check (see {_authorize}), since this repo
        // does not implement protocol-side lane/exclusivity checks.
        try ACCOUNT_CONFIGURATION.authenticateActor(address(this), hash, auth) returns (uint8 s, address) {
            return (true, s);
        } catch {
            return (false, 0);
        }
    }

    /// @notice Decides whether an already-authenticated actor may drive this UserOperation, from its scope.
    ///         Split out from {_authenticate} so the two concerns — who signed vs. what they may do — are
    ///         independently reviewable and overridable.
    /// @dev Enforces:
    ///        - scope 0x00 is an unrestricted owner; any other actor must hold {SCOPE_SENDER} to authorize the calls;
    ///        - a self-funded op (`missingAccountFunds != 0`) additionally requires {SCOPE_SELF_PAYER}.
    ///      A SCOPE_POLICY actor without SCOPE_SENDER fails the check below by construction — this reduced 4337
    ///      bridge does not give policy-gated actors special call-target enforcement (that is native-dispatch,
    ///      protocol-side behavior out of scope for this repo). An actor combining SCOPE_POLICY | SCOPE_SENDER is
    ///      authorized here exactly like any other SENDER-scoped actor.
    /// @param scope The verified actor's scope (0x00 = unrestricted owner).
    /// @param missingAccountFunds The prefund the account owes the EntryPoint; non-zero means a self-funded op.
    function _authorize(uint8 scope, uint256 missingAccountFunds) internal view virtual returns (bool) {
        // scope 0x00 = unrestricted owner; otherwise the actor must explicitly hold the required scopes.
        if (scope != 0) {
            if (scope & SCOPE_SENDER == 0) return false;
            if (missingAccountFunds != 0 && scope & SCOPE_SELF_PAYER == 0) return false;
        }
        return true;
    }
}
