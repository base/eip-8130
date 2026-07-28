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
    //  Fresh delegation is immediately functional via the hardcoded default (no bootstrap call)
    // ─────────────────────────────────────────────────────────────

    function test_freshDelegation_slotEmpty_runsDefaultImplementation() public view {
        assertEq(_slot(), address(0), "fresh delegation: ERC-1967 slot is unset");
        assertEq(EIP7702ProxyFor8130(account).DEFAULT_IMPLEMENTATION(), impl, "default is the EIP-8130 account impl");

        // ERC-1271 forwards to the default impl -> AccountConfiguration; the EOA's own key is its implicit admin.
        // verifySignature applies the account-scoped EIP-7739 wrap, so sign the replaySafeHash digest.
        bytes32 hash = keccak256("hello from a fresh 7702 account");
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

    function test_setImplementation_bootstrapFromZero() public {
        address impl2 = address(new DefaultAccount(address(accountConfiguration)));

        EIP7702ProxyFor8130(account).setImplementation(address(0), impl2, _setImplAuth(ADMIN_PK, address(0), impl2));

        assertEq(_slot(), impl2, "explicit bootstrap sets the ERC-1967 slot to the chosen implementation");
    }

    function test_setImplementation_casMismatchReverts() public {
        address impl2 = address(new DefaultAccount(address(accountConfiguration)));
        address wrongFrom = makeAddr("wrongFrom");

        vm.expectRevert(EIP7702ProxyFor8130.SetImplementationFromMismatch.selector);
        EIP7702ProxyFor8130(account).setImplementation(wrongFrom, impl2, _setImplAuth(ADMIN_PK, wrongFrom, impl2));
    }

    function test_setImplementation_rejectsNonAdmin() public {
        uint256 senderPk = 0x5E9DE2; // SCOPE_SENDER only: operational, but not admin
        _registerActor(bytes32(bytes20(vm.addr(senderPk))), k1Authenticator, SCOPE_SENDER);
        address impl2 = address(new DefaultAccount(address(accountConfiguration)));

        vm.expectRevert(EIP7702ProxyFor8130.SetImplementationNotAdmin.selector);
        EIP7702ProxyFor8130(account).setImplementation(address(0), impl2, _setImplAuth(senderPk, address(0), impl2));
    }

    function test_setImplementation_rejectsUnregisteredKey() public {
        address impl2 = address(new DefaultAccount(address(accountConfiguration)));
        // 0xBEEF is neither the account's own key nor a registered actor: authenticateActor reverts, caught as failure.
        vm.expectRevert();
        EIP7702ProxyFor8130(account).setImplementation(address(0), impl2, _setImplAuth(0xBEEF, address(0), impl2));
    }

    // ─────────────────────────────────────────────────────────────
    //  Recovery: reset a corrupted ERC-1967 pointer (the A->B->A / 7702 slipperiness case)
    // ─────────────────────────────────────────────────────────────

    /// @dev Simulates an intervening delegate leaving a foreign/garbage value in the shared ERC-1967 slot. A normal
    ///      UUPS upgrade cannot recover (its logic lives in whatever the slot points at); the proxy's first-class
    ///      `setImplementation` can, because it is never forwarded.
    function test_setImplementation_recoversCorruptedPointer() public {
        address garbage = makeAddr("foreignWalletImpl"); // codeless: a normal delegatecall through here is broken
        vm.store(account, ERC1967_IMPLEMENTATION_SLOT, bytes32(uint256(uint160(garbage))));
        assertEq(_slot(), garbage, "precondition: slot corrupted to a foreign pointer");

        EIP7702ProxyFor8130(account).setImplementation(garbage, impl, _setImplAuth(ADMIN_PK, garbage, impl));

        assertEq(_slot(), impl, "setImplementation resets the pointer to a known-good implementation");

        // Forwarding works again after recovery.
        bytes32 hash = keccak256("post-recovery");
        assertEq(
            DefaultAccount(account)
                .isValidSignature(hash, _buildK1Auth(ADMIN_PK, accountConfiguration.replaySafeHash(account, hash))),
            bytes4(0x1626ba7e),
            "account is functional again after pointer recovery"
        );
    }

    // ─────────────────────────────────────────────────────────────
    //  No ecrecover/EOA fallback: ERC-1271 authority is exactly the registry's (the EIP7702Proxy contrast)
    // ─────────────────────────────────────────────────────────────

    /// @dev Points the account at an implementation whose isValidSignature always rejects, then presents a signature
    ///      by the account's OWN key. `EIP7702Proxy` would return the ERC-1271 magic value here via its `ecrecover`
    ///      fallback (the sig recovers to the account); this proxy has no such fallback, so the implementation's
    ///      rejection stands.
    function test_noEcrecoverFallback_registryIsSoleSignatureAuthority() public {
        address rejecting = address(new RejectingImpl());
        EIP7702ProxyFor8130(account)
            .setImplementation(address(0), rejecting, _setImplAuth(ADMIN_PK, address(0), rejecting));

        bytes32 hash = keccak256("would an EOA fallback accept this?");
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

    function test_constructor_rejectsCodelessDefaultImplementation() public {
        vm.expectRevert(EIP7702ProxyFor8130.DefaultImplementationNotDeployed.selector);
        new EIP7702ProxyFor8130(address(accountConfiguration), makeAddr("undeployed"), bytes32(0));
    }

    function test_constructor_codehashPin_wrongHashReverts() public {
        vm.expectRevert(EIP7702ProxyFor8130.RegistryCodehashMismatch.selector);
        new EIP7702ProxyFor8130(address(accountConfiguration), impl, keccak256("malicious registry"));
    }

    function test_constructor_codehashPin_matchingHashSucceeds() public {
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
