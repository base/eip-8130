// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Receiver} from "solady/accounts/Receiver.sol";

import {IAccountConfiguration} from "../../interfaces/IAccountConfiguration.sol";
import {IBootstrap} from "./IBootstrap.sol";

/// @notice Reference implementation for accounts deployed via `SetDelegateFactory`.
///
///         Self-contained bootstrap (no changes to AccountConfiguration required):
///           - `bootstrap` is the account's own entrypoint. It sets a transient (EIP-1153) latch, drives
///             `AccountConfiguration.importAccount` on itself, then clears the latch — all in one call frame.
///           - While the latch is set (i.e. only during that nested `importAccount`), the ERC-1271 callback is in
///             BOOTSTRAP mode and validates the presented digest against the typed actors hash the factory passed
///             in. The latch lives in transient storage, so it is scoped to the bootstrap transaction and cannot
///             leak into normal operation; it is also cleared explicitly once import returns.
///           - In every other context (latch unset) the implementation defers `isValidSignature` to
///             `AccountConfiguration.authenticateActor` for normal operation.
///
///         Why the signature need not be checked in BOOTSTRAP mode: the account has no key. The factory's atomic
///         `SETDELEGATE → bootstrap` sequence makes front-running impossible, and the SETDELEGATE address
///         derivation binds the address to `(factory, salt)` where `salt` already commits to the actor set. The
///         implementation just confirms the import digest AccountConfiguration computed matches the actors the
///         factory primed.
///
///         Minimal reference; production accounts add execution, caller authorization, asset receive hooks, etc.
contract BootstrapAccount is IBootstrap, Receiver {
    IAccountConfiguration public immutable ACCOUNT_CONFIGURATION;

    /// @dev Matches `AccountConfiguration.ACTOR_INITIALIZATION_TYPEHASH`.
    bytes32 internal constant _ACTOR_INITIALIZATION_TYPEHASH = keccak256(
        "ActorInitialization(bytes32 salt,Actor[] initialActors)Actor(bytes32 actorId,ActorConfig config,bytes policyData)ActorConfig(address authenticator,uint8 scope,uint48 expiry,uint8 policyType)"
    );

    bytes4 internal constant _ERC1271_MAGIC = 0x1626ba7e;
    bytes4 internal constant _ERC1271_INVALID = 0xffffffff;

    /// @notice Transient (EIP-1153) bootstrap latch. Non-zero ONLY for the duration of the `bootstrap` call frame
    ///         (i.e. across the nested `importAccount`). When set, it is the typed actors hash that, combined with
    ///         `address(this)`, reconstructs the expected `ActorInitialization` digest. Auto-clears at end of tx and
    ///         is cleared explicitly after import, so the BOOTSTRAP branch is reachable exactly once.
    bytes32 internal transient _bootstrapActorsHash;

    constructor(address accountConfiguration) {
        ACCOUNT_CONFIGURATION = IAccountConfiguration(accountConfiguration);
    }

    // ══════════════════════════════════════════════
    //  BOOTSTRAP
    // ══════════════════════════════════════════════

    /// @notice Atomically prime + self-import. Called by the factory in the same tx frame as `SETDELEGATE`.
    ///         Sets the transient latch, has AccountConfiguration register the actors (whose ERC-1271 callback
    ///         lands on the BOOTSTRAP branch below), then clears the latch. After `importAccount` succeeds the
    ///         account is initialized, so a second call reverts inside `importAccount` and the BOOTSTRAP branch
    ///         is never reachable again.
    /// @param  actorsHash    `keccak256(actorHash_0 || actorHash_1 || ... )`, matching the inner hash of the
    ///                        `ActorInitialization` digest AccountConfiguration computes for the same actor set.
    /// @param  initialActors The actor set to import. MUST match `actorsHash`.
    function bootstrap(bytes32 actorsHash, IAccountConfiguration.InitialActor[] calldata initialActors) external {
        _bootstrapActorsHash = actorsHash;
        ACCOUNT_CONFIGURATION.importAccount(address(this), initialActors, "");
        _bootstrapActorsHash = bytes32(0);
    }

    // ══════════════════════════════════════════════
    //  ERC-1271
    // ══════════════════════════════════════════════

    /// @notice Signature validation.
    ///         BOOTSTRAP mode (transient latch set): the presented `hash` must equal the canonical
    ///         `ActorInitialization` digest reconstructed from the latched actors hash. The `signature` argument
    ///         is ignored; binding comes from the factory's atomic sequence and the address derivation.
    ///         NORMAL mode (latch unset): defer to AccountConfiguration.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view virtual returns (bytes4) {
        bytes32 actorsHash = _bootstrapActorsHash;
        if (actorsHash != bytes32(0)) {
            return hash == _expectedImportDigest(actorsHash) ? _ERC1271_MAGIC : _ERC1271_INVALID;
        }
        // signature is `authenticator(20) || data` per EIP-8130 for the canonical path.
        try ACCOUNT_CONFIGURATION.authenticateActor(address(this), hash, signature) returns (uint8, uint8, address) {
            return _ERC1271_MAGIC;
        } catch {
            return _ERC1271_INVALID;
        }
    }

    /// @notice The digest this account expects in BOOTSTRAP mode for a given actor set. Exposed for off-chain
    ///         tooling; the on-chain check uses the transient latch primed by `bootstrap`.
    function expectedImportDigest(bytes32 actorsHash) external view returns (bytes32) {
        return _expectedImportDigest(actorsHash);
    }

    // ══════════════════════════════════════════════
    //  INTERNALS
    // ══════════════════════════════════════════════

    function _expectedImportDigest(bytes32 actorsHash) internal view returns (bytes32) {
        return keccak256(abi.encode(_ACTOR_INITIALIZATION_TYPEHASH, bytes32(bytes20(address(this))), actorsHash));
    }
}
