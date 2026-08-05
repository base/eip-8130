// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Receiver} from "solady/accounts/Receiver.sol";

import {AccountConfiguration} from "../AccountConfiguration.sol";
import {Scopes} from "../libraries/Scopes.sol";

/// @notice A single call in an execution batch.
struct Call {
    /// @dev Address the account calls.
    address target;
    /// @dev Wei forwarded with the call.
    uint256 value;
    /// @dev Calldata passed to `target`.
    bytes data;
}

/// @dev Sentinel `authenticator` value marking an actor as a trusted executor: an address (e.g. a PolicyManager,
///      EntryPoint, or relayer) authorized to drive execution on the account by matching `msg.sender` rather than
///      by verifying a signature. No contract exists at this address; it is hash-derived and deterministic across
///      all chains, so if the protocol ever calls authenticate() on it the call naturally fails.
address constant TRUSTED_EXECUTOR = address(uint160(uint256(keccak256("trustedExecutor"))));

/// @notice Canonical model of the EIP-8130 default account: the behavior every EOA exhibits by default on an
///         EIP-8130 chain, expressed in Solidity. It handles batched execution and ERC-1271 signature validation,
///         and defers all authorization to the AccountConfiguration system contract.
///
///         Caller authorization:
///           - address(this) is always authorized (hardcoded), covering 8130 self-call batches
///           - Trusted executors (PolicyManagers, relayers, EntryPoints) are registered as actors with
///             TRUSTED_EXECUTOR as the authenticator in AccountConfiguration
///
/// @dev Not a deployment target. This describes the default EOA behavior applied natively on an EIP-8130 chain; it
///      is intentionally minimal and is NOT ERC-4337 compatible. An account that wants smart-account features (for
///      example ERC-4337 on a chain without native EIP-8130 support) should delegate or deploy to a purpose-built
///      account, not to this one. If this bytecode is deployed anyway, it MUST sit behind an upgradeable (UUPS)
///      proxy: adopting those features later means swapping in different bytecode, which is only possible if the
///      deployment is upgradeable. An upgradeable (UUPS) variant is provided as an unaudited example in a separate
///      repository.
///
/// @author Coinbase
contract DefaultAccount is Receiver {
    /// @notice The AccountConfiguration system contract that owns this account's authorization state.
    AccountConfiguration public immutable ACCOUNT_CONFIGURATION;

    /// @dev ERC-1271 magic return value for a valid signature (`isValidSignature(bytes32,bytes)` selector).
    bytes4 private constant ERC1271_MAGIC = 0x1626ba7e;
    bytes4 private constant ERC1271_FAIL = 0xFFFFFFFF;

    /// @dev EIP-712 domain typehash.
    bytes32 private constant _EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @dev keccak256("PersonalSign(bytes prefixed)").
    bytes32 private constant _PERSONAL_SIGN_TYPEHASH =
        0x983e65e5148e570cd828ead231ee759a8d7958721a768f93bc4483ba005c32de;

    /// @dev Account ERC-1271 domain name/version, fixed for all accounts.
    bytes32 private constant _ACCOUNT_DOMAIN_NAME_HASH = keccak256("EIP8130Account");
    bytes32 private constant _ACCOUNT_DOMAIN_VERSION_HASH = keccak256("1");

    /// @notice The caller is neither the account itself nor a registered TRUSTED_EXECUTOR actor.
    error UnauthorizedCaller();

    /// @notice An inner call in the executed batch reverted.
    error CallFailed();

    /// @notice Deploys the account implementation bound to an AccountConfiguration instance.
    /// @param accountConfiguration Address of the AccountConfiguration system contract.
    constructor(address accountConfiguration) {
        ACCOUNT_CONFIGURATION = AccountConfiguration(accountConfiguration);
    }

    // ══════════════════════════════════════════════
    //  EXECUTION
    // ══════════════════════════════════════════════

    /// @notice Executes a batch of calls from the account; reverts the entire batch if any call fails.
    ///
    /// @dev Reverts with UnauthorizedCaller when the caller is neither the account nor a TRUSTED_EXECUTOR actor.
    /// @dev Reverts with CallFailed when any inner call reverts.
    ///
    /// @param calls Ordered calls to execute, each as (target, value, data).
    function executeBatch(Call[] calldata calls) external virtual {
        if (!_isAuthorizedCaller(msg.sender)) revert UnauthorizedCaller();
        for (uint256 i; i < calls.length; i++) {
            (bool success,) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            if (!success) revert CallFailed();
        }
    }

    // ══════════════════════════════════════════════
    //  ERC-1271
    // ══════════════════════════════════════════════

    /// @notice Validates an ERC-1271 signature via AccountConfiguration; requires the verified actor to be
    ///         operational (the unrestricted admin, scope == 0x00, or a SENDER actor without POLICY). Never reverts.
    ///
    /// @dev Authenticates against the account-scoped digest {replaySafeHash}, not the raw `hash`, so a signature is
    ///      bound to this account (EIP-7739 PersonalSign) and cannot replay onto another account sharing the same key.
    ///      `authenticateActor` reverts on any failure, so it is called externally and the revert is caught. Signing
    ///      is not a scope grant: it is authorized for any operational actor — the admin, or a SENDER actor not gated
    ///      by a policy — because it only encodes authority such an actor already holds via calls. A POLICY-bearing
    ///      actor is never operational and cannot sign (a signature would act off its policy gate). This mirrors the
    ///      operational-actor rule in {_isAuthorizedCaller}.
    ///
    /// @param hash The digest to authenticate.
    /// @param signature Auth data in `authenticator || data` format.
    ///
    /// @return The ERC-1271 magic value 0x1626ba7e if valid, otherwise 0xffffffff.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view virtual returns (bytes4) {
        bytes32 digest = replaySafeHash(hash);
        try ACCOUNT_CONFIGURATION.authenticateActor(address(this), digest, signature) returns (
            bytes32, uint16 scope, address
        ) {
            bool operational = scope == 0 || ((scope & Scopes.SENDER != 0) && (scope & Scopes.POLICY == 0));
            return operational ? ERC1271_MAGIC : ERC1271_FAIL;
        } catch {
            return ERC1271_FAIL;
        }
    }

    /// @notice Account-scoped digest to sign for `hash` to be accepted by this account's ERC-1271 check
    ///         ({isValidSignature}): `hash` wrapped in an EIP-712 domain with verifyingContract = this account and the
    ///         current chainId (EIP-7739 PersonalSign; TypedDataSign is not implemented). This is not a grant, so it
    ///         needs no scope bit.
    ///
    /// @param hash Raw message digest.
    ///
    /// @return The digest to sign.
    function replaySafeHash(bytes32 hash) public view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(_PERSONAL_SIGN_TYPEHASH, hash));
        return keccak256(abi.encodePacked(hex"1901", _accountDomainSeparator(), structHash));
    }

    // ══════════════════════════════════════════════
    //  VIEW
    // ══════════════════════════════════════════════

    /// @notice Returns whether `caller` may drive execution on this account.
    ///
    /// @param caller Address to check.
    ///
    /// @return True if `caller` is the account itself or a registered TRUSTED_EXECUTOR actor.
    function isAuthorizedCaller(address caller) external view returns (bool) {
        return _isAuthorizedCaller(caller);
    }

    // ══════════════════════════════════════════════
    //  INTERNALS
    // ══════════════════════════════════════════════

    /// @dev Authorized if `caller` is the account itself, or holds the TRUSTED_EXECUTOR authenticator AND operational
    ///      (sender) authority. Expiry is enforced by getActorConfig, which returns the empty config (zero
    ///      authenticator) for an expired actor — so an expired caller fails the TRUSTED_EXECUTOR check below, and a
    ///      user-set expiry is honored on the execution path without a separate comparison here. Scope: driving
    ///      execution requires sender authority — the unrestricted admin (scope == 0x00) or an actor with
    ///      Scopes.SENDER that is not gated by a policy (Scopes.POLICY unset). A POLICY-gated actor must route every
    ///      call through its manager, so granting it direct executeBatch would bypass that gate; fail closed. This
    ///      mirrors the operational-actor definition in {isValidSignature}, keeping the execution and signing
    ///      authorization surfaces aligned.
    function _isAuthorizedCaller(address caller) internal view virtual returns (bool) {
        if (caller == address(this)) return true;
        AccountConfiguration.ActorConfig memory config =
            ACCOUNT_CONFIGURATION.getActorConfig(address(this), bytes32(bytes20(caller)));
        if (config.authenticator != TRUSTED_EXECUTOR) return false;
        uint16 scope = config.scope;
        return scope == 0 || ((scope & Scopes.SENDER != 0) && (scope & Scopes.POLICY == 0));
    }

    /// @dev EIP-712 domain separator for this account's ERC-1271 domain (verifyingContract = this account, current
    ///      chainId).
    function _accountDomainSeparator() internal view returns (bytes32) {
        return keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH,
                _ACCOUNT_DOMAIN_NAME_HASH,
                _ACCOUNT_DOMAIN_VERSION_HASH,
                block.chainid,
                address(this)
            )
        );
    }
}
