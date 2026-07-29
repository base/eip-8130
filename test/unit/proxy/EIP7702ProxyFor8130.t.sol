// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {DefaultAccount} from "../../../src/accounts/DefaultAccount.sol";
import {EIP7702ProxyFor8130} from "../../../src/proxy/EIP7702ProxyFor8130.sol";

import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

/// @dev An implementation whose ERC-1271 always rejects. Used to prove the proxy adds no `ecrecover`/EOA fallback:
///      even a signature by the account's own key must return the failure value, because the proxy forwards
///      ERC-1271 to the implementation and the implementation's answer stands.
contract RejectingImpl {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return 0xffffffff;
    }
}

/// @notice Exercises {EIP7702ProxyFor8130} as an EIP-7702 delegation target. A 7702 EOA is simulated by
///         `vm.etch`-ing the proxy runtime code onto an EOA address: the proxy code then runs in the EOA's storage
///         context, exactly as under a real `0xef0100 || proxy` delegation, and the EOA's own key is its implicit
///         scope-0 admin in {AccountConfiguration} (the default-EOA self-actor), so no bootstrap import is needed.
contract EIP7702ProxyFor8130Test is AccountConfigurationTest {
    uint256 constant ADMIN_PK = 0xA11CE; // the delegated EOA's key: implicit scope-0 admin of itself
    uint8 constant SCOPE_SENDER = 0x01;

    bytes32 constant ERC1967_IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    bytes32 constant SET_IMPLEMENTATION_TYPEHASH =
        keccak256("SetImplementation(address account,address fromImplementation,address toImplementation)");

    address internal impl; // the default implementation (a DefaultAccount singleton)
    EIP7702ProxyFor8130 internal proxySingleton;

    address payable internal account; // the delegated EOA (vm.addr(ADMIN_PK)) running the proxy code

    function setUp() public override {
        super.setUp();
        impl = defaultAccountImplementation;
        proxySingleton = new EIP7702ProxyFor8130(address(accountConfiguration), impl, bytes32(0));

        // Simulate a 7702 delegation: the EOA runs the singleton proxy's code in its own storage context.
        account = payable(vm.addr(ADMIN_PK));
        vm.etch(account, address(proxySingleton).code);
        vm.deal(account, 10 ether);
    }

    // ─────────────────────────────────────────────────────────────
    //  Fallback delegation: fresh 7702 delegation runs the hardcoded default (no bootstrap call)
    // ─────────────────────────────────────────────────────────────

    /// @notice Verifies a fresh delegation (empty ERC-1967 slot) resolves and runs {DEFAULT_IMPLEMENTATION}.
    /// @dev With the slot unset, _implementation falls back to the default; ERC-1271 forwards there and the EOA's own
    ///      key validates as its implicit scope-0 admin. Signs the account-scoped replaySafeHash; fuzzes the digest.
    function test_fallback_success_freshDelegationUsesDefaultImplementation(bytes32 hash) public view {
        assertEq(_slot(), address(0), "fresh delegation: ERC-1967 slot is unset");
        assertEq(EIP7702ProxyFor8130(account).DEFAULT_IMPLEMENTATION(), impl, "default is the EIP-8130 account impl");

        assertEq(
            DefaultAccount(account)
                .isValidSignature(hash, _buildK1Auth(ADMIN_PK, accountConfiguration.replaySafeHash(account, hash))),
            bytes4(0x1626ba7e),
            "implicit-admin signature validates via the default implementation, with no setImplementation call"
        );
    }

    // ─────────────────────────────────────────────────────────────
    //  setImplementation: registry-gated, compare-and-swap
    // ─────────────────────────────────────────────────────────────

    /// @notice Verifies setImplementation reverts when the signed `fromImplementation` does not match the live slot.
    /// @dev Compare-and-swap guard: checks SetImplementationFromMismatch for any wrong-from pointer. Fuzzes the
    ///      mismatched from-pointer (excluding the real fresh-slot value address(0)).
    function test_setImplementation_revert_casMismatch(address wrongFrom) public {
        vm.assume(wrongFrom != address(0));
        address impl2 = address(new DefaultAccount(address(accountConfiguration)));

        vm.expectRevert(EIP7702ProxyFor8130.SetImplementationFromMismatch.selector);
        EIP7702ProxyFor8130(account).setImplementation(wrongFrom, impl2, _setImplAuth(ADMIN_PK, wrongFrom, impl2));
    }

    /// @notice Verifies setImplementation reverts when the authenticated actor is operational but not an admin.
    /// @dev Checks SetImplementationNotAdmin for a SENDER-only (scope != 0) actor. Fuzzes the non-admin signer key.
    function test_setImplementation_revert_nonAdmin(uint256 senderSeed) public {
        uint256 senderPk = _boundK1Pk(senderSeed);
        vm.assume(vm.addr(senderPk) != account); // not the account's implicit admin
        _registerActor(bytes32(bytes20(vm.addr(senderPk))), k1Authenticator, SCOPE_SENDER);
        address impl2 = address(new DefaultAccount(address(accountConfiguration)));

        vm.expectRevert(EIP7702ProxyFor8130.SetImplementationNotAdmin.selector);
        EIP7702ProxyFor8130(account).setImplementation(address(0), impl2, _setImplAuth(senderPk, address(0), impl2));
    }

    /// @notice Verifies setImplementation reverts when signed by a key that is not a registered actor.
    /// @dev authenticateActor reverts for an unregistered actorId; that bubbles up as a top-level revert. Fuzzes the
    ///      unregistered signer key (excluding the account's own implicit-admin key).
    function test_setImplementation_revert_unregisteredKey(uint256 keySeed) public {
        uint256 pk = _boundK1Pk(keySeed);
        vm.assume(vm.addr(pk) != account);
        address impl2 = address(new DefaultAccount(address(accountConfiguration)));

        vm.expectRevert();
        EIP7702ProxyFor8130(account).setImplementation(address(0), impl2, _setImplAuth(pk, address(0), impl2));
    }

    /// @notice Verifies an admin signature bootstraps the ERC-1967 slot from the fresh (zero) state.
    /// @dev First explicit set signs `fromImplementation == address(0)`; asserts the slot points at the chosen impl.
    function test_setImplementation_success_bootstrapFromZero() public {
        address impl2 = address(new DefaultAccount(address(accountConfiguration)));

        EIP7702ProxyFor8130(account).setImplementation(address(0), impl2, _setImplAuth(ADMIN_PK, address(0), impl2));

        assertEq(_slot(), impl2, "explicit bootstrap sets the ERC-1967 slot to the chosen implementation");
    }

    /// @notice Verifies setImplementation recovers a slot corrupted to a foreign/garbage pointer.
    /// @dev Simulates an intervening delegate leaving garbage in the shared ERC-1967 slot. A normal UUPS upgrade
    ///      cannot recover (its logic lives in whatever the slot points at); the first-class setImplementation can,
    ///      because it is never forwarded. Fuzzes the codeless garbage pointer and the post-recovery digest.
    function test_setImplementation_success_recoversCorruptedPointer(address garbage, bytes32 hash) public {
        vm.assume(garbage != address(0) && garbage != impl && garbage.code.length == 0);
        vm.store(account, ERC1967_IMPLEMENTATION_SLOT, bytes32(uint256(uint160(garbage))));
        assertEq(_slot(), garbage, "precondition: slot corrupted to a foreign pointer");

        EIP7702ProxyFor8130(account).setImplementation(garbage, impl, _setImplAuth(ADMIN_PK, garbage, impl));

        assertEq(_slot(), impl, "setImplementation resets the pointer to a known-good implementation");

        // Forwarding works again after recovery.
        assertEq(
            DefaultAccount(account)
                .isValidSignature(hash, _buildK1Auth(ADMIN_PK, accountConfiguration.replaySafeHash(account, hash))),
            bytes4(0x1626ba7e),
            "account is functional again after pointer recovery"
        );
    }

    // ─────────────────────────────────────────────────────────────
    //  isValidSignature: no ecrecover/EOA fallback (the EIP7702Proxy contrast)
    // ─────────────────────────────────────────────────────────────

    /// @notice Verifies ERC-1271 has no ecrecover/EOA fallback: the implementation's answer is final.
    /// @dev Points the account at an always-rejecting implementation, then presents a raw signature by the account's
    ///      OWN key. `EIP7702Proxy` would return the magic value via its ecrecover fallback; this proxy has none, so
    ///      the rejection stands. Fuzzes the signed digest.
    function test_isValidSignature_success_noEcrecoverFallback(bytes32 hash) public {
        address rejecting = address(new RejectingImpl());
        EIP7702ProxyFor8130(account)
            .setImplementation(address(0), rejecting, _setImplAuth(ADMIN_PK, address(0), rejecting));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ADMIN_PK, hash); // raw ECDSA by the account's own key
        bytes memory rawEoaSig = abi.encodePacked(r, s, v);

        assertEq(
            DefaultAccount(account).isValidSignature(hash, rawEoaSig),
            bytes4(0xffffffff),
            "no ecrecover fallback: the implementation's rejection is final, even for the account's own key"
        );
    }

    // ─────────────────────────────────────────────────────────────
    //  Constructor safety (parity with the account / factory)
    // ─────────────────────────────────────────────────────────────

    /// @notice Verifies the constructor reverts when the default implementation has no deployed code.
    /// @dev Checks DefaultImplementationNotDeployed. Fuzzes the codeless default-implementation address.
    function test_constructor_revert_codelessDefaultImplementation(address undeployed) public {
        vm.assume(undeployed.code.length == 0);
        vm.expectRevert(EIP7702ProxyFor8130.DefaultImplementationNotDeployed.selector);
        new EIP7702ProxyFor8130(address(accountConfiguration), undeployed, bytes32(0));
    }

    /// @notice Verifies the constructor reverts when a non-zero codehash pin does not match the registry code.
    /// @dev Checks RegistryCodehashMismatch. Fuzzes the wrong pinned codehash (excluding zero, which disables the pin,
    ///      and the registry's real codehash).
    function test_constructor_revert_codehashPinMismatch(bytes32 wrongCodehash) public {
        vm.assume(wrongCodehash != bytes32(0) && wrongCodehash != address(accountConfiguration).codehash);
        vm.expectRevert(EIP7702ProxyFor8130.RegistryCodehashMismatch.selector);
        new EIP7702ProxyFor8130(address(accountConfiguration), impl, wrongCodehash);
    }

    /// @notice Verifies the constructor succeeds and stores the pin when the codehash matches the registry code.
    /// @dev Asserts ACCOUNT_CONFIGURATION_CODEHASH is set to the supplied (matching) codehash.
    function test_constructor_success_codehashPinMatches() public {
        bytes32 codehash = address(accountConfiguration).codehash;
        EIP7702ProxyFor8130 pinned = new EIP7702ProxyFor8130(address(accountConfiguration), impl, codehash);
        assertEq(pinned.ACCOUNT_CONFIGURATION_CODEHASH(), codehash);
    }

    // ─────────────────────────────────────────────────────────────
    //  Helpers
    // ─────────────────────────────────────────────────────────────

    function _slot() internal view returns (address) {
        return address(uint160(uint256(vm.load(account, ERC1967_IMPLEMENTATION_SLOT))));
    }

    function _setImplAuth(uint256 pk, address from, address to) internal view returns (bytes memory) {
        bytes32 digest = keccak256(abi.encode(SET_IMPLEMENTATION_TYPEHASH, account, from, to));
        return _buildK1Auth(pk, digest);
    }

    /// @dev Registers an actor on `account`, authorized by the account's implicit scope-0 admin (ADMIN_PK).
    function _registerActor(bytes32 actorId, address authenticator, uint8 scope) internal {
        AccountConfiguration.ActorConfig memory config =
            AccountConfiguration.ActorConfig({authenticator: authenticator, scope: scope, expiry: 0});
        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] =
            AccountConfiguration.ActorChange({changeType: 0x01, actorId: actorId, data: abi.encode(config, bytes(""))});

        uint64 sequence = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), sequence, changes);
        accountConfiguration.applySignedActorChanges(
            account, uint64(block.chainid), changes, _buildK1Auth(ADMIN_PK, digest)
        );
    }
}
