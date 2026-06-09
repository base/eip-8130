// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {IAccountConfiguration} from "../../../src/interfaces/IAccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract CreateAccountTest is AccountConfigurationTest {
    function _initialActor(bytes32 actorId, address authenticator)
        internal
        pure
        returns (IAccountConfiguration.InitialActor memory)
    {
        return IAccountConfiguration.InitialActor({actorId: actorId, authenticator: authenticator});
    }

    function test_createAccount_singleK1Actor(uint256 pk) public {
        pk = bound(pk, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
        address actor = vm.addr(pk);
        bytes32 actorId = bytes32(bytes20(actor));

        IAccountConfiguration.InitialActor[] memory actors = new IAccountConfiguration.InitialActor[](1);
        actors[0] = _initialActor(actorId, address(k1Authenticator));

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        address account = accountConfiguration.createAccount(bytes32(0), bytecode, actors);

        assertTrue(account != address(0));
        assertTrue(account.code.length > 0);
        assertTrue(accountConfiguration.isActor(account, actorId));
    }

    function test_createAccount_multipleActors() public {
        address actor1 = vm.addr(1);
        address actor2 = vm.addr(2);

        bytes32 actorId1 = bytes32(bytes20(actor1));
        bytes32 actorId2 = bytes32(bytes20(actor2));

        IAccountConfiguration.InitialActor[] memory actors = new IAccountConfiguration.InitialActor[](2);
        if (actorId1 < actorId2) {
            actors[0] = _initialActor(actorId1, address(k1Authenticator));
            actors[1] = _initialActor(actorId2, address(k1Authenticator));
        } else {
            actors[0] = _initialActor(actorId2, address(k1Authenticator));
            actors[1] = _initialActor(actorId1, address(k1Authenticator));
        }

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        address account = accountConfiguration.createAccount(bytes32(0), bytecode, actors);

        assertTrue(account != address(0));
        assertTrue(accountConfiguration.isActor(account, actorId1));
        assertTrue(accountConfiguration.isActor(account, actorId2));
    }

    function test_createAccount_deterministicAddress() public {
        address actor = vm.addr(1);
        bytes32 actorId = bytes32(bytes20(actor));

        IAccountConfiguration.InitialActor[] memory actors = new IAccountConfiguration.InitialActor[](1);
        actors[0] = _initialActor(actorId, address(k1Authenticator));

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        address predicted = accountConfiguration.computeAddress(bytes32(0), bytecode, actors);
        address actual = accountConfiguration.createAccount(bytes32(0), bytecode, actors);

        assertEq(predicted, actual);
    }

    function test_createAccount_revertsOnDuplicate() public {
        address actor = vm.addr(1);
        bytes32 actorId = bytes32(bytes20(actor));

        IAccountConfiguration.InitialActor[] memory actors = new IAccountConfiguration.InitialActor[](1);
        actors[0] = _initialActor(actorId, address(k1Authenticator));

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        accountConfiguration.createAccount(bytes32(0), bytecode, actors);

        vm.expectRevert();
        accountConfiguration.createAccount(bytes32(0), bytecode, actors);
    }

    function test_createAccount_revertsWithUnsortedActors() public {
        address actor1 = vm.addr(1);
        address actor2 = vm.addr(2);

        bytes32 actorId1 = bytes32(bytes20(actor1));
        bytes32 actorId2 = bytes32(bytes20(actor2));

        bytes32 smaller = actorId1 < actorId2 ? actorId1 : actorId2;
        bytes32 larger = actorId1 < actorId2 ? actorId2 : actorId1;

        IAccountConfiguration.InitialActor[] memory actors = new IAccountConfiguration.InitialActor[](2);
        actors[0] = _initialActor(larger, address(k1Authenticator));
        actors[1] = _initialActor(smaller, address(k1Authenticator));

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        vm.expectRevert();
        accountConfiguration.createAccount(bytes32(0), bytecode, actors);
    }

    function test_createAccount_revertsWithNoActors() public {
        IAccountConfiguration.InitialActor[] memory actors = new IAccountConfiguration.InitialActor[](0);
        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);

        vm.expectRevert();
        accountConfiguration.createAccount(bytes32(0), bytecode, actors);
    }

    function test_createAccount_revertsWithZeroAuthenticator() public {
        bytes32 actorId = bytes32(uint256(1));

        IAccountConfiguration.InitialActor[] memory actors = new IAccountConfiguration.InitialActor[](1);
        actors[0] = _initialActor(actorId, address(0));

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        vm.expectRevert();
        accountConfiguration.createAccount(bytes32(0), bytecode, actors);
    }

    function test_createAccount_unrestrictedInitialActor() public {
        address actor = vm.addr(1);
        bytes32 actorId = bytes32(bytes20(actor));

        IAccountConfiguration.InitialActor[] memory actors = new IAccountConfiguration.InitialActor[](1);
        actors[0] = _initialActor(actorId, address(k1Authenticator));

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        address account = accountConfiguration.createAccount(bytes32(0), bytecode, actors);

        IAccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(account, actorId);
        assertEq(cfg.authenticator, address(k1Authenticator));
        assertEq(cfg.scope, 0x00);
        assertEq(cfg.expiry, 0);
        assertEq(cfg.policyType, 0x00);

        // Created accounts are marked initialized (localSequence == 1).
        assertEq(accountConfiguration.getChangeSequences(account).local, 1);

        (bool locked, bool hasInitiatedUnlock, uint40 unlocksAt, uint16 unlockDelay) =
            accountConfiguration.getLockStatus(account);
        assertFalse(locked);
        assertFalse(hasInitiatedUnlock);
        assertEq(unlocksAt, 0);
        assertEq(unlockDelay, 0);
    }

    function test_createAccount_differentSaltsProduceDifferentAddresses() public {
        address actor = vm.addr(1);
        bytes32 actorId = bytes32(bytes20(actor));

        IAccountConfiguration.InitialActor[] memory actors = new IAccountConfiguration.InitialActor[](1);
        actors[0] = _initialActor(actorId, address(k1Authenticator));

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        address addr1 = accountConfiguration.computeAddress(bytes32(uint256(1)), bytecode, actors);
        address addr2 = accountConfiguration.computeAddress(bytes32(uint256(2)), bytecode, actors);

        assertTrue(addr1 != addr2);
    }
}
