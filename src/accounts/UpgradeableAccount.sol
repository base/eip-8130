// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {UUPSUpgradeable} from "solady/utils/UUPSUpgradeable.sol";

import {DefaultAccount} from "./DefaultAccount.sol";

/// @notice UUPS-upgradeable version of {DefaultAccount}: the general-purpose deployed account, holding no
///         ERC-4337 surface by default. executeBatch, isValidSignature, and caller authorization are inherited
///         unchanged; upgrade to a 4337-capable implementation (see {BackwardsCompatible4337Account}) or any
///         future capability as needed.
///
///         Deploy behind an UpgradeableProxy instead of ERC-1167.
///         7702 accounts don't need this — they can re-delegate anytime.
///
///         Upgrades are authorized via upgradeBySignature — a CONFIG-key-signed, relayable upgrade with
///         compare-and-swap replay protection that is safe to broadcast across every chain the account lives on.
///         See {_authorizeUpgrade} for how the signature requirement is enforced on the actual implementation
///         change.
contract UpgradeableAccount is DefaultAccount, UUPSUpgradeable {
    /// @dev AccountConfiguration scope granting authority to change account configuration ("CONFIG"). An account
    ///      gates upgrades on this scope so the same key that manages the account's actors can also manage its
    ///      implementation.
    uint8 internal constant SCOPE_CONFIG = 0x08;

    /// @dev One-shot flag set by {upgradeBySignature} immediately before its internal self-call to
    ///      `upgradeToAndCall`, and consumed by {_authorizeUpgrade} to confirm a CONFIG-scoped signature has
    ///      already authorized this specific upgrade.
    bool private _upgradeAuthorized;

    /// @dev Typehash binding a signed upgrade to (account, from, to, dataHash). chainId is intentionally omitted:
    ///      the same owner signature applies on every chain whose current implementation equals
    ///      `fromImplementation` (compare-and-swap), and is naturally skipped on chains that have diverged.
    bytes32 public constant SIGNED_UPGRADE_TYPEHASH = keccak256(
        "SignedUpgrade(address account,address fromImplementation,address toImplementation,bytes32 dataHash)"
    );

    /// @dev The current implementation does not match the signed `fromImplementation` (compare-and-swap failed).
    error UpgradeFromMismatch();
    /// @dev The authenticated actor may not authorize upgrades (not an unrestricted owner and lacks CONFIG scope).
    error UpgradeUnauthorized();

    constructor(address accountConfiguration) DefaultAccount(accountConfiguration) {}

    /// @dev {upgradeBySignature} is the only place that sets {_upgradeAuthorized}, so satisfying this confirms a
    ///      CONFIG-scoped signature has already authorized the implementation change being applied.
    function _authorizeUpgrade(address) internal override {
        require(_upgradeAuthorized);
        _upgradeAuthorized = false;
    }

    /// @notice Upgrade the implementation using an owner signature, with compare-and-swap replay protection.
    /// @dev Replay protection is state-based, not nonce-based: the signature is bound to `fromImplementation` and
    ///      is only valid while the ERC-1967 slot still holds it. Once applied the slot becomes `toImplementation`,
    ///      so the same signature can no longer be replayed on this chain. Because chainId is not part of the
    ///      digest, one signature upgrades every chain currently at `fromImplementation` and is skipped on any
    ///      chain that has diverged. A fresh account (slot unset, running the hardcoded default) requires
    ///      `fromImplementation == address(0)`. Anyone may submit this call (e.g. a relayer); the signature is what
    ///      proves owner intent.
    ///
    ///      NOTE (deferred for audit/discussion): compare-and-swap is not ABA-proof. If an implementation is
    ///      upgraded away from `fromImplementation` and later restored to it, a previously-used signature for that
    ///      transition becomes replayable. This is only harmful if an owner deliberately downgrades away from a
    ///      malicious/broken implementation and an attacker then forces it back. We accept this for now because
    ///      downgrades are expected to be rare; a forward-only version ratchet or a used-digest guard can close it
    ///      without a deadline if we decide we need to. To be revisited during the security review.
    /// @param fromImplementation Expected current implementation (raw ERC-1967 slot value; address(0) when unset).
    /// @param toImplementation The implementation to upgrade to.
    /// @param data Optional initialization calldata delegatecalled on `toImplementation` (empty to skip).
    /// @param auth Authenticator(20) || authenticator-specific data, authenticated by AccountConfiguration.
    function upgradeBySignature(
        address fromImplementation,
        address toImplementation,
        bytes calldata data,
        bytes calldata auth
    ) external {
        if (_currentImplementation() != fromImplementation) revert UpgradeFromMismatch();

        bytes32 digest = keccak256(
            abi.encode(SIGNED_UPGRADE_TYPEHASH, address(this), fromImplementation, toImplementation, keccak256(data))
        );

        // A CONFIG key authorizes the upgrade: an unrestricted owner (scope 0) or an actor with SCOPE_CONFIG.
        (uint8 scope,,) = ACCOUNT_CONFIGURATION.authenticateActor(address(this), digest, auth);
        if (scope != 0 && scope & SCOPE_CONFIG == 0) revert UpgradeUnauthorized();

        // Reuse Solady's tested upgrade path (proxiableUUID check, Upgraded event, optional init delegatecall).
        // The flag set above is what satisfies _authorizeUpgrade for this call.
        _upgradeAuthorized = true;
        this.upgradeToAndCall(toImplementation, data);
    }

    /// @dev Reads the raw ERC-1967 implementation slot (address(0) when unset on a fresh account).
    function _currentImplementation() internal view returns (address impl) {
        bytes32 slot = _ERC1967_IMPLEMENTATION_SLOT;
        assembly ("memory-safe") {
            impl := sload(slot)
        }
    }
}
