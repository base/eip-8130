// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Receiver} from "solady/accounts/Receiver.sol";

import {IAccountConfiguration} from "../../interfaces/IAccountConfiguration.sol";
import {IBootstrap} from "./IBootstrap.sol";

/// @notice Reference implementation for accounts deployed via `SetDelegateFactory`.
///
///         Bootstrap-aware ERC-1271:
///           - While `getChangeSequences(this).local == 0`, the implementation is in BOOTSTRAP mode and validates
///             the presented digest against the typed actors hash primed by the factory in the same tx frame.
///           - After `AccountConfiguration.importAccount` succeeds (local sequence becomes 1), the implementation
///             defers `isValidSignature` to `AccountConfiguration.authenticateActor` for normal operation.
///
///         Bootstrap mode is the only window in which the "signature" need not be checked: the factory's atomic
///         `SETDELEGATE → bootstrap → importAccount` sequence makes front-running impossible, and the SETDELEGATE
///         address derivation binds the address to `(factory, salt)` where `salt` already commits to the actor
///         set. The implementation just confirms the import digest AccountConfiguration computed matches the
///         actors the factory primed.
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

    /// @notice Typed actors hash primed by the factory at bootstrap. Combined with `address(this)` it
    ///         reconstructs the expected `ActorInitialization` digest used by `importAccount`.
    bytes32 public bootstrappedActorsHash;

    /// @notice True once `bootstrap` has been called; prevents re-bootstrap.
    bool public bootstrapped;

    constructor(address accountConfiguration) {
        ACCOUNT_CONFIGURATION = IAccountConfiguration(accountConfiguration);
    }

    // ══════════════════════════════════════════════
    //  BOOTSTRAP
    // ══════════════════════════════════════════════

    /// @notice Prime the implementation with the typed `actorsHash`. Single-use; the factory calls this in
    ///         the same tx frame as `importAccount`. After `importAccount` succeeds, the bootstrap branch is
    ///         no longer taken (AccountConfiguration sequence is non-zero), and re-bootstrap is also blocked.
    /// @param  actorsHash `keccak256(actorHash_0 || actorHash_1 || ... )`, matching the inner hash of the
    ///                    `ActorInitialization` digest AccountConfiguration computes for the same actor set.
    function bootstrap(bytes32 actorsHash) external {
        require(!bootstrapped, "bootstrapped");
        bootstrappedActorsHash = actorsHash;
        bootstrapped = true;
    }

    // ══════════════════════════════════════════════
    //  ERC-1271
    // ══════════════════════════════════════════════

    /// @notice Signature validation.
    ///         BOOTSTRAP mode (sequence == 0): the presented `hash` must equal the canonical
    ///         `ActorInitialization` digest reconstructed from the primed `bootstrappedActorsHash`.
    ///         The `signature` argument is ignored; binding comes from the factory's atomic sequence.
    ///         NORMAL mode (sequence > 0): defer to AccountConfiguration.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view virtual returns (bytes4) {
        if (bootstrapped && ACCOUNT_CONFIGURATION.getChangeSequences(address(this)).local == 0) {
            return hash == _expectedImportDigest() ? _ERC1271_MAGIC : _ERC1271_INVALID;
        }
        // signature is `authenticator(20) || data` per EIP-8130 for the canonical path.
        try ACCOUNT_CONFIGURATION.authenticateActor(address(this), hash, signature) returns (uint8, uint8, address) {
            return _ERC1271_MAGIC;
        } catch {
            return _ERC1271_INVALID;
        }
    }

    /// @notice The digest this account expects in BOOTSTRAP mode. Exposed for off-chain tooling.
    function expectedImportDigest() external view returns (bytes32) {
        return _expectedImportDigest();
    }

    // ══════════════════════════════════════════════
    //  INTERNALS
    // ══════════════════════════════════════════════

    function _expectedImportDigest() internal view returns (bytes32) {
        return
            keccak256(
                abi.encode(_ACTOR_INITIALIZATION_TYPEHASH, bytes32(bytes20(address(this))), bootstrappedActorsHash)
            );
    }
}
