// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Receiver} from "solady/accounts/Receiver.sol";

import {AccountConfiguration} from "../AccountConfiguration.sol";
import {IAccountConfiguration} from "../interfaces/IAccountConfiguration.sol";

struct Call {
    address target;
    uint256 value;
    bytes data;
}

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
    IAccountConfiguration.ActorChange[] changes;
    bytes auth;
}

/// @notice Universal ERC-4337 + EIP-8130 account implementation.
///         Deployed behind ERC-1167 minimal proxy (45 bytes, deterministic pattern).
///
///         Designed to be THE permanent wallet — users never upgrade the implementation.
///         New capabilities are added by authorizing callers (PolicyManager, etc.)
///         and registering actors/authenticators via the AccountConfiguration system contract.
///
///         Supports:
///           - EIP-8130 direct dispatch (msg.sender = from, always authorized as self-call)
///           - ERC-4337 via validateUserOp (EntryPoint is always authorized)
///           - Account Policies via authorized caller (add PolicyManager as authorized caller)
///           - ERC-1271 signature validation via AccountConfiguration
///
///         Caller authorization (hardcoded, always authorized):
///           - address(this) — covers 8130 direct dispatch
///           - ENTRY_POINT — covers ERC-4337 on any chain, no setup required
///         Dynamic callers managed via authorizeCaller/revokeCaller (self-call only)
contract ERC4337Account is Receiver {
    AccountConfiguration public immutable ACCOUNT_CONFIGURATION;
    address public immutable ENTRY_POINT;

    mapping(address => bool) internal _authorizedCallers;

    /// @dev Signature discriminator for validation-phase actor changes. When
    ///      `userOp.signature` begins with this 32-byte magic, it is decoded as:
    ///
    ///        abi.encode(
    ///          bytes32 magic,
    ///          SignedActorChanges[] changeSets, // each: (ActorChange[] changes, bytes auth)
    ///          bytes opAuth                     // authenticates this UserOperation over userOpHash
    ///        )
    ///
    ///      Each `SignedActorChanges` set is applied in order during validation (e.g.
    ///      rotating the controlling key to a P-256 actor). Each change is bound to this
    ///      account + a monotonic sequence and authorized by the account's own key, so it
    ///      is safe to apply. Applying the changes only mutates configuration — it does NOT
    ///      authorize the op. The op is still authenticated as usual by `opAuth`, a plain
    ///      authenticator blob (`authenticator || data`) that signs for this exact
    ///      `userOpHash`, and may be produced by a key the changes just added/rotated to.
    ///      Any signature without the magic prefix is itself treated as the plain `opAuth`
    ///      blob signing `userOpHash`, preserving prior behaviour.
    ///
    ///      Wire format:
    ///        abi.encode(bytes32 magic, SignedActorChanges[] changeSets, bytes opAuth)
    bytes32 internal constant SIGNED_ACTOR_CHANGES_MAGIC = keccak256("ERC4337Account.signedActorChanges.v1");

    /// @dev Elevated-scope bitflags, mirroring AccountConfiguration. A scope of 0x00 is an unrestricted owner.
    uint8 internal constant SCOPE_SENDER = 0x02; // may initiate transactions (authorize the op's calls)
    uint8 internal constant SCOPE_PAYER = 0x04; // may spend account funds paying for the op

    event CallerAuthorized(address indexed caller);
    event CallerRevoked(address indexed caller);

    constructor(address accountConfiguration, address entryPoint) {
        ACCOUNT_CONFIGURATION = AccountConfiguration(accountConfiguration);
        ENTRY_POINT = entryPoint;
    }

    // ══════════════════════════════════════════════
    //  CALLER MANAGEMENT (self-call only)
    // ══════════════════════════════════════════════

    function authorizeCaller(address caller) external {
        require(msg.sender == address(this));
        _authorizedCallers[caller] = true;
        emit CallerAuthorized(caller);
    }

    function revokeCaller(address caller) external {
        require(msg.sender == address(this));
        delete _authorizedCallers[caller];
        emit CallerRevoked(caller);
    }

    function isAuthorizedCaller(address caller) external view returns (bool) {
        return _isAuthorizedCaller(caller);
    }

    // ══════════════════════════════════════════════
    //  EXECUTION
    // ══════════════════════════════════════════════

    function executeBatch(Call[] calldata calls) external {
        require(_isAuthorizedCaller(msg.sender));
        for (uint256 i; i < calls.length; i++) {
            (bool success,) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            require(success);
        }
    }

    // ══════════════════════════════════════════════
    //  ERC-4337
    // ══════════════════════════════════════════════

    /// @notice Validates a UserOperation signature via the AccountConfiguration system.
    ///         Signature format follows 8130 authenticator conventions (authenticator_type || data),
    ///         and optionally carries signed actor/owner changes applied during validation
    ///         (see {SIGNED_ACTOR_CHANGES_MAGIC}).
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256 validationData)
    {
        require(_isAuthorizedCaller(msg.sender));

        validationData = _validateSignature(userOp, userOpHash, missingAccountFunds) ? 0 : 1;

        if (missingAccountFunds != 0) {
            assembly {
                pop(call(gas(), caller(), missingAccountFunds, 0, 0, 0, 0))
            }
        }
    }

    /// @notice Validates `userOp` by authenticating it as a plain authenticator blob over `userOpHash` and
    ///         enforcing the verified actor's elevated scope and policy. A signature carrying signed actor/owner
    ///         changes additionally applies them during validation before the op itself is authenticated.
    /// @dev Signed-actor-changes path (signature begins with {SIGNED_ACTOR_CHANGES_MAGIC}): each set is applied
    ///      during validation via `applySignedActorChanges` (which binds the change to THIS account + a monotonic
    ///      sequence and enforces CONFIG scope) and an empty batch is rejected. Because each change is bound to
    ///      `address(this)` and authorized by the account's own key, it is safe to apply and only ever mutates the
    ///      sender's own config. The changes do NOT authorize the op; the trailing `opAuth` blob must still sign
    ///      for this exact `userOpHash` as usual (and may be produced by a key the changes just added/rotated to).
    ///      Applying changes mutates `AccountConfiguration` storage during validation, which violates ERC-7562
    ///      mempool rules unless this account / factory is staked or granted an exception.
    ///
    ///      Op authentication (both paths) enforces the verified actor's elevated scope and policy:
    ///        - the actor must be unrestricted (scope 0x00) or hold {SCOPE_SENDER} to authorize the calls;
    ///        - a self-funded op (`missingAccountFunds != 0`) additionally requires {SCOPE_PAYER};
    ///        - a policy-gated actor (non-zero `policyType`) may only drive calls to its policy target, so
    ///          `userOp.callData` must be an `executeBatch` whose every call targets that address.
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

            // Each set is independently safe to apply: `applySignedActorChanges` binds the change digest to
            // THIS account (`address(this)`) + a monotonic sequence and authenticates it against the account's
            // own CONFIG-scoped actor. So the changes can only ever mutate the sender's config, authorized by
            // the sender's own key — nobody can inject another account's changes here, and the sender (who
            // pays) is always the one whose configuration is changed.
            for (uint256 i; i < changeSets.length; i++) {
                try ACCOUNT_CONFIGURATION.applySignedActorChanges(
                    address(this), uint64(block.chainid), changeSets[i].changes, changeSets[i].auth
                ) {}
                catch {
                    return false;
                }
            }
        }

        // The op is always authenticated by a signature over `userOpHash` (which commits to `callData`):
        // applying changes alone never authorizes the op. On the changes path this is the trailing `opAuth`
        // blob, which may be produced by a key the changes just added/rotated to.
        (bool valid, uint8 scope, address policyTarget) = _authenticate(userOpHash, opAuth);
        if (!valid) return false;

        // scope 0x00 = unrestricted owner; otherwise the actor must explicitly hold the required scopes.
        if (scope != 0) {
            if (scope & SCOPE_SENDER == 0) return false;
            if (missingAccountFunds != 0 && scope & SCOPE_PAYER == 0) return false;
        }

        // A policy-gated actor may only direct the account's calls to its policy target.
        if (policyTarget != address(0) && !_callsTargetOnly(userOp.callData, policyTarget)) return false;

        return true;
    }

    function _authenticate(bytes32 hash, bytes memory auth)
        internal
        view
        returns (bool valid, uint8 scope, address policyTarget)
    {
        // policyType is reserved for future manager-defined semantics; the account gates on scope + target today.
        try ACCOUNT_CONFIGURATION.authenticateActor(address(this), hash, auth) returns (uint8 s, uint8, address p) {
            return (true, s, p);
        } catch {
            return (false, 0, address(0));
        }
    }

    /// @dev True iff `callData` is a non-empty `executeBatch` whose every call targets `policyTarget`.
    ///      Because `userOpHash` commits to `callData`, enforcing this during validation binds the gated
    ///      actor's authorization to calls that stay within its policy target.
    function _callsTargetOnly(bytes calldata callData, address policyTarget) internal pure returns (bool) {
        if (callData.length < 4 || bytes4(callData[:4]) != ERC4337Account.executeBatch.selector) return false;
        Call[] memory calls = abi.decode(callData[4:], (Call[]));
        if (calls.length == 0) return false;
        for (uint256 i; i < calls.length; i++) {
            if (calls[i].target != policyTarget) return false;
        }
        return true;
    }

    // ══════════════════════════════════════════════
    //  ERC-1271
    // ══════════════════════════════════════════════

    /// @notice Signature validation via AccountConfiguration. Requires the verified actor to hold SIGNER
    ///         scope (or be an unrestricted owner); `verifySignature` enforces this and never reverts.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        return
            ACCOUNT_CONFIGURATION.verifySignature(address(this), hash, signature)
                ? bytes4(0x1626ba7e)
                : bytes4(0xFFFFFFFF);
    }

    // ══════════════════════════════════════════════
    //  INTERNALS
    // ══════════════════════════════════════════════

    function _isAuthorizedCaller(address caller) internal view returns (bool) {
        return caller == address(this) || caller == ENTRY_POINT || _authorizedCallers[caller];
    }
}
