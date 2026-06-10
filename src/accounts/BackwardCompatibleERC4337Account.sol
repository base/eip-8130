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
    ///          IAccountConfiguration.ActorChange[] changes,
    ///          bytes changesAuth,   // authorizes `changes` (owner-signed digest)
    ///          bytes opAuth         // authenticates this UserOperation
    ///        )
    ///
    ///      Each `SignedActorChanges` set is applied in order during validation (e.g.
    ///      rotating the controlling key to a P-256 actor). A non-empty, fully-applied
    ///      batch authorizes the op: each set is signed by an authorized actor over a
    ///      monotonic-sequence digest, so it cannot be forged and is one-time-use. No
    ///      separate op-over-`userOpHash` signature is required — the final signed
    ///      change in the chain is what authorizes the operation. Any other signature is
    ///      treated as a plain authenticator blob (`authenticator || data`), preserving
    ///      prior behaviour.
    ///
    ///      Wire format:
    ///        abi.encode(bytes32 magic, SignedActorChanges[] changeSets)
    bytes32 internal constant SIGNED_ACTOR_CHANGES_MAGIC = keccak256("ERC4337Account.signedActorChanges.v1");

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

        validationData = _validateSignature(userOpHash, userOp.signature) ? 0 : 1;

        if (missingAccountFunds != 0) {
            assembly {
                pop(call(gas(), caller(), missingAccountFunds, 0, 0, 0, 0))
            }
        }
    }

    /// @notice Applies signed actor/owner changes carried by `signature`. When present,
    ///         successfully applying them authorizes this op (no separate op signature).
    /// @dev Changes are applied atomically with this op: if any change auth is invalid or
    ///      its sequence is stale, validation fails and the EntryPoint rolls everything
    ///      back. Each set is signed by an authorized actor over the
    ///      `(account, chainId, sequence, actorChanges)` digest, so it cannot be forged
    ///      and the monotonic sequence makes it one-time-use.
    ///
    ///      An empty change-set batch is rejected (it would otherwise authorize any op).
    ///
    ///      Note: the change digest does not bind `userOpHash`/`callData`, so this path is
    ///      intended for self-bundled (direct `handleOps`) submission. Applying changes
    ///      also mutates `AccountConfiguration` storage during validation, which violates
    ///      ERC-7562 mempool rules unless this account / factory is staked or granted an
    ///      exception.
    function _validateSignature(bytes32 userOpHash, bytes calldata signature) internal returns (bool) {
        if (signature.length >= 32 && bytes32(signature[:32]) == SIGNED_ACTOR_CHANGES_MAGIC) {
            (, SignedActorChanges[] memory changeSets) = abi.decode(signature, (bytes32, SignedActorChanges[]));

            if (changeSets.length == 0) return false;

            for (uint256 i; i < changeSets.length; i++) {
                try ACCOUNT_CONFIGURATION.applySignedActorChanges(
                    address(this), uint64(block.chainid), changeSets[i].changes, changeSets[i].auth
                ) {}
                catch {
                    return false;
                }
            }
            return true;
        }

        return _authenticate(userOpHash, signature);
    }

    function _authenticate(bytes32 hash, bytes memory auth) internal view returns (bool valid) {
        try ACCOUNT_CONFIGURATION.authenticateActor(address(this), hash, auth) returns (uint8) {
            valid = true;
        } catch {
            valid = false;
        }
    }

    // ══════════════════════════════════════════════
    //  ERC-1271
    // ══════════════════════════════════════════════

    /// @notice Signature validation via AccountConfiguration's authenticator infrastructure.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        try ACCOUNT_CONFIGURATION.authenticateActor(address(this), hash, signature) returns (uint8) {
            return bytes4(0x1626ba7e);
        } catch {
            return bytes4(0xFFFFFFFF);
        }
    }

    // ══════════════════════════════════════════════
    //  INTERNALS
    // ══════════════════════════════════════════════

    function _isAuthorizedCaller(address caller) internal view returns (bool) {
        return caller == address(this) || caller == ENTRY_POINT || _authorizedCallers[caller];
    }
}
