// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Vm} from "forge-std/Vm.sol";

import {IAccountConfiguration} from "../../../../src/interfaces/IAccountConfiguration.sol";
import {BootstrapAccount} from "../../../../src/examples/factory/BootstrapAccount.sol";
import {SetDelegateFactory} from "../../../../src/examples/factory/SetDelegateFactory.sol";
import {AccountConfigurationTest} from "../../../lib/AccountConfigurationTest.sol";

/// @dev Test-only factory: simulates the EIP-7819 SETDELEGATE opcode via `vm.etch`. Production replaces this
///      with the real opcode (see `SetDelegateFactory._setDelegate`).
contract TestableSetDelegateFactory is SetDelegateFactory {
    Vm internal constant _vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function _setDelegate(bytes32 salt, address target) internal override returns (address account) {
        account = computeAddress(salt);
        bytes memory existing = account.code;
        require(
            existing.length == 0 || (existing.length >= 3 && bytes3(existing) == bytes3(0xef0100)),
            "SETDELEGATE: not a delegation"
        );
        _vm.etch(account, abi.encodePacked(hex"ef0100", target));
        // EIP-7819 step 9 also bumps nonce to 1 if zero; the simulation omits this — not needed for the import flow.
    }
}

contract SetDelegateFactoryTest is AccountConfigurationTest {
    TestableSetDelegateFactory internal factory;
    BootstrapAccount internal implementation;

    function setUp() public override {
        super.setUp();
        factory = new TestableSetDelegateFactory();
        implementation = new BootstrapAccount(address(accountConfiguration));
    }

    function _oneActor(uint256 pk) internal view returns (IAccountConfiguration.InitialActor[] memory actors) {
        actors = new IAccountConfiguration.InitialActor[](1);
        actors[0] = IAccountConfiguration.InitialActor({
            actorId: bytes32(bytes20(vm.addr(pk))), authenticator: address(k1Authenticator)
        });
    }

    function test_deploy_atomic() public {
        uint256 pk = 700;
        IAccountConfiguration.InitialActor[] memory actors = _oneActor(pk);
        bytes32 userSalt = bytes32(uint256(42));

        address expected = factory.computeAccount(actors, userSalt);
        address actual = factory.deploy(actors, address(implementation), userSalt);

        assertEq(actual, expected);

        // Delegation indicator placed.
        bytes memory code = actual.code;
        assertEq(code.length, 23);
        assertEq(bytes3(code), bytes3(0xef0100));
        // Implementation address baked into the indicator.
        address embedded;
        assembly {
            embedded := mload(add(code, 23))
        }
        assertEq(embedded, address(implementation));

        // AccountConfiguration registered the actor; account is initialized.
        assertEq(accountConfiguration.getChangeSequences(actual).local, 1);
        assertTrue(accountConfiguration.isActor(actual, bytes32(bytes20(vm.addr(pk)))));

        // Bootstrap branch is permanently closed: the transient latch was cleared after import, so the import
        // digest no longer auto-validates — isValidSignature now routes to AccountConfiguration (empty sig fails).
        bytes32 importDigest = BootstrapAccount(payable(actual)).expectedImportDigest(factory.actorsHash(actors));
        assertEq(BootstrapAccount(payable(actual)).isValidSignature(importDigest, ""), bytes4(0xffffffff));
    }

    function test_deploy_isDeterministic() public {
        uint256 pk = 700;
        IAccountConfiguration.InitialActor[] memory actors = _oneActor(pk);
        bytes32 userSalt = bytes32(uint256(7));

        address a = factory.deploy(actors, address(implementation), userSalt);
        // Same factory + same userSalt + same actors → same address.
        assertEq(factory.computeAccount(actors, userSalt), a);
    }

    function test_deploy_revertsOnSecondDeploy() public {
        uint256 pk = 700;
        IAccountConfiguration.InitialActor[] memory actors = _oneActor(pk);
        bytes32 userSalt = bytes32(uint256(1));

        factory.deploy(actors, address(implementation), userSalt);

        // Re-deploying the same actors+salt re-enters bootstrap on a now-initialized account; importAccount's
        // one-time guard reverts inside the nested call.
        vm.expectRevert();
        factory.deploy(actors, address(implementation), userSalt);
    }

    function test_differentActors_yieldsDifferentAddress() public view {
        IAccountConfiguration.InitialActor[] memory a = _oneActor(700);
        IAccountConfiguration.InitialActor[] memory b = _oneActor(701);
        bytes32 userSalt = bytes32(uint256(99));

        address addrA = factory.computeAccount(a, userSalt);
        address addrB = factory.computeAccount(b, userSalt);
        assertTrue(addrA != addrB);
    }

    function test_differentFactory_yieldsDifferentAddress() public {
        TestableSetDelegateFactory other = new TestableSetDelegateFactory();

        IAccountConfiguration.InitialActor[] memory actors = _oneActor(700);
        bytes32 userSalt = bytes32(uint256(5));

        address fromFirst = factory.computeAccount(actors, userSalt);
        address fromOther = other.computeAccount(actors, userSalt);
        assertTrue(fromFirst != fromOther);
    }

    function test_upgrade_onlyAccount() public {
        uint256 pk = 700;
        IAccountConfiguration.InitialActor[] memory actors = _oneActor(pk);
        bytes32 userSalt = bytes32(uint256(2));

        address account = factory.deploy(actors, address(implementation), userSalt);
        bytes32 ah = factory.actorsHash(actors);

        BootstrapAccount newImpl = new BootstrapAccount(address(accountConfiguration));

        // EOA cannot upgrade.
        vm.expectRevert();
        factory.upgrade(userSalt, ah, address(newImpl));

        // Account itself (as caller) can upgrade.
        vm.prank(account);
        factory.upgrade(userSalt, ah, address(newImpl));

        bytes memory code = account.code;
        address embedded;
        assembly {
            embedded := mload(add(code, 23))
        }
        assertEq(embedded, address(newImpl));
    }

    function test_postBootstrap_isValidSignature_routesThroughAccountConfig() public {
        // After bootstrap, ERC-1271 defers to AccountConfiguration. A k1 signature over an arbitrary digest
        // from the registered actor authenticates via AccountConfiguration.authenticateActor.
        uint256 pk = 700;
        IAccountConfiguration.InitialActor[] memory actors = _oneActor(pk);
        bytes32 userSalt = bytes32(uint256(3));

        address account = factory.deploy(actors, address(implementation), userSalt);

        bytes32 digest = keccak256("hello");
        bytes memory auth = _buildK1Auth(pk, digest);

        bytes4 magic = BootstrapAccount(payable(account)).isValidSignature(digest, auth);
        assertEq(magic, bytes4(0x1626ba7e));
    }
}
