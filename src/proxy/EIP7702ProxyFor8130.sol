// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Proxy} from "openzeppelin/proxy/Proxy.sol";
import {ERC1967Utils} from "openzeppelin/proxy/ERC1967/ERC1967Utils.sol";

import {AccountConfiguration} from "../AccountConfiguration.sol";

/// @notice A lean, EIP-8130-native ERC-1967 proxy intended as the EIP-7702 delegation target for EOAs that opt into
///         an EIP-8130 account implementation ({DefaultAccount} by default). It is deployed as a singleton; many EOAs
///         delegate their code to it.
///
///         This proxy adds no authorization of its own beyond a single registry-gated recovery function
///         ({setImplementation}); it never falls back to raw-EOA behavior (no `ecrecover` / EOA-key path), only to
///         whatever the implementation points at, and thereby to {AccountConfiguration}.
///
///         The proxy owns exactly one behavior, {setImplementation}, and forwards everything else (execution and
///         ERC-1271) to the implementation. In particular it does NOT define `isValidSignature`: that forwards to the
///         implementation, which defers to `AccountConfiguration.verifySignature` and applies any account-bound /
///         replay-safe hashing itself. Keeping ERC-1271 in the implementation is what makes this proxy
///         implementation-agnostic; the only implementation-specific element is the {DEFAULT_IMPLEMENTATION} pointer
///         baked in at deploy.
///
///         Two problems are specific to EIP-7702 and motivate this proxy:
///           1. A 7702 authorization sets the EOA's code but not its storage, so a constructor-based ERC-1967 proxy
///              would have an empty implementation slot and nothing to delegate to. {DEFAULT_IMPLEMENTATION} solves
///              this: a fresh delegation runs the default immediately, with no bootstrap call.
///           2. A 7702-delegated EOA keeps mutable bytecode (it can re-delegate), and 7702 preserves storage across
///              re-delegation, so another delegate can corrupt the shared ERC-1967 implementation slot. A UUPS
///              `upgrade` path cannot fix that, because the UUPS logic lives in whatever the slot points at; once it
///              points at foreign/broken code that path is unreachable. {setImplementation}, a first-class proxy
///              function that is never forwarded, is the only code that always runs regardless of the slot, so it is
///              the recovery avenue.
///
///         CREATE2-deployed EIP-8130 accounts do not need this proxy: their bytecode is immutable and has no
///         pointer-corruption vector, so they use a plain minimal proxy (e.g. an ERC-1167 clone) instead.
///
/// @dev Selector reservation: because {setImplementation} is a first-class function on this proxy, its selector is
///      caught here and never forwarded. The implementation must not define a colliding selector, or that function
///      would become unreachable through the proxy.
///
/// @dev Unaudited example. Provided in this repository so the EIP-7702 delegation pattern can be reviewed alongside
///      the accounts it delegates to; not a protocol system contract.
///
/// @author Coinbase
contract EIP7702ProxyFor8130 is Proxy {
    /// @notice The AccountConfiguration system contract used to authenticate {setImplementation} signatures.
    AccountConfiguration public immutable ACCOUNT_CONFIGURATION;

    /// @notice The implementation delegated to when the ERC-1967 slot is unset (a fresh 7702 delegation, or a slot
    ///         zeroed by a prior delegate). Deploy this proxy with the default EIP-8130 account implementation here.
    address public immutable DEFAULT_IMPLEMENTATION;

    /// @notice Expected registry codehash. Non-zero pins the registry (non-8130 chains, where AccountConfiguration is
    ///         an ordinary contract and an attacker could otherwise squat a malicious one at the expected address).
    ///         Zero disables the pin, for 8130 chains where the registry is a protocol system contract trusted by
    ///         construction.
    bytes32 public immutable ACCOUNT_CONFIGURATION_CODEHASH;

    /// @dev Binds a {setImplementation} authorization to (account, fromImplementation, toImplementation). `chainId`
    ///      is omitted so one signature can set the pointer on every chain still at `fromImplementation`
    ///      (compare-and-swap replay protection). There is no `data`/init call, so no dataHash: this proxy only moves
    ///      the pointer.
    bytes32 public constant SET_IMPLEMENTATION_TYPEHASH =
        keccak256("SetImplementation(address account,address fromImplementation,address toImplementation)");

    /// @notice The registry code at the expected address did not match the pinned codehash.
    error RegistryCodehashMismatch();

    /// @notice The default implementation supplied at construction has no deployed code.
    error DefaultImplementationNotDeployed();

    /// @notice The current ERC-1967 slot value does not match the signed `fromImplementation` (compare-and-swap).
    error SetImplementationFromMismatch();

    /// @notice The `setImplementation` signature did not authenticate an unrestricted admin (scope 0) of this account.
    error SetImplementationNotAdmin();

    /// @param accountConfiguration The AccountConfiguration system contract address.
    /// @param defaultImplementation The implementation used when the ERC-1967 slot is unset (the EIP-8130 account).
    /// @param expectedConfigCodehash Non-zero to pin the registry codehash (non-8130 chains); zero to disable.
    constructor(address accountConfiguration, address defaultImplementation, bytes32 expectedConfigCodehash) {
        if (defaultImplementation.code.length == 0) revert DefaultImplementationNotDeployed();
        if (expectedConfigCodehash != bytes32(0) && accountConfiguration.codehash != expectedConfigCodehash) {
            revert RegistryCodehashMismatch();
        }
        ACCOUNT_CONFIGURATION = AccountConfiguration(accountConfiguration);
        DEFAULT_IMPLEMENTATION = defaultImplementation;
        ACCOUNT_CONFIGURATION_CODEHASH = expectedConfigCodehash;
    }

    /// @notice Force-set the ERC-1967 implementation pointer, authorized by a registry admin (scope-0) signature.
    ///
    /// @dev The one behavior this proxy owns. It covers the two states a normal UUPS upgrade cannot reach: pointing a
    ///      fresh delegation at a specific (non-default) implementation, and recovering the pointer after another
    ///      delegate corrupted the shared ERC-1967 slot. Because it is a first-class proxy function it is never
    ///      forwarded, so it runs even when the slot points at foreign or broken code.
    ///
    ///      Authorization defers entirely to the registry: `auth` must authenticate an unrestricted admin (scope 0)
    ///      of THIS account (`address(this)`, i.e. the delegated EOA). There is no `ecrecover`/EOA fallback, so a key
    ///      the registry has revoked cannot set the implementation. Replay protection is compare-and-swap on the
    ///      current pointer: the signature commits to `fromImplementation` and applies only while the slot still
    ///      holds it, so the write spends the signature. `chainId` is omitted (see {SET_IMPLEMENTATION_TYPEHASH}); a
    ///      cross-chain recovery whose corrupted `fromImplementation` differs per chain is simply signed per chain.
    ///
    ///      A fresh slot reads `address(0)` even though the effective implementation is {DEFAULT_IMPLEMENTATION}, so
    ///      the first explicit set signs `fromImplementation = address(0)`. `toImplementation` must have deployed code
    ///      (enforced by `ERC1967Utils.upgradeToAndCall`).
    ///
    /// @param fromImplementation The pointer the signature is bound to; must equal the current ERC-1967 slot value.
    /// @param toImplementation The implementation to point at (must be deployed).
    /// @param auth Registry auth blob (authenticator(20) || data) authenticating a scope-0 admin of this account.
    function setImplementation(address fromImplementation, address toImplementation, bytes calldata auth) external {
        if (ERC1967Utils.getImplementation() != fromImplementation) revert SetImplementationFromMismatch();

        bytes32 digest =
            keccak256(abi.encode(SET_IMPLEMENTATION_TYPEHASH, address(this), fromImplementation, toImplementation));
        (, uint8 scope,) = ACCOUNT_CONFIGURATION.authenticateActor(address(this), digest, auth);
        if (scope != 0) revert SetImplementationNotAdmin();

        // Sets the ERC-1967 slot and emits Upgraded; empty data means no init call (the default account needs none)
        // and `_setImplementation` reverts if `toImplementation` has no code.
        ERC1967Utils.upgradeToAndCall(toImplementation, "");
    }

    /// @notice The implementation the proxy delegates to: the ERC-1967 slot if set, else {DEFAULT_IMPLEMENTATION}.
    ///
    /// @dev A fresh 7702 delegation (empty slot) runs the default immediately, with no bootstrap call and with
    ///      token/ETH receiving through the default's Receiver. A slot zeroed by a prior delegate also falls back to
    ///      the known-good default; a slot set to non-zero garbage is recovered via {setImplementation}.
    function _implementation() internal view override returns (address impl) {
        impl = ERC1967Utils.getImplementation();
        if (impl == address(0)) impl = DEFAULT_IMPLEMENTATION;
    }
}
