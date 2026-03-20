// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract CreateAccountTest is AccountConfigurationTest {
    function test_createAccount_singleK1Owner(uint256 pk) public {
        pk = bound(pk, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
        address owner = vm.addr(pk);
        bytes32 ownerId = bytes32(bytes20(owner));

        AccountConfiguration.InitializeOwner[] memory owners = new AccountConfiguration.InitializeOwner[](1);
        owners[0] = AccountConfiguration.InitializeOwner({ownerId: ownerId, config: AccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scope: 0x00})});

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        address account = accountConfiguration.createAccount(bytes32(0), bytecode, owners);

        assertTrue(account != address(0));
        assertTrue(account.code.length > 0);
        (address verifier,) = accountConfiguration.getOwnerConfig(account, ownerId);
        assertTrue(verifier != address(0));
    }

    function test_createAccount_multipleOwners() public {
        address owner1 = vm.addr(1);
        address owner2 = vm.addr(2);

        bytes32 ownerId1 = bytes32(bytes20(owner1));
        bytes32 ownerId2 = bytes32(bytes20(owner2));

        AccountConfiguration.InitializeOwner[] memory owners = new AccountConfiguration.InitializeOwner[](2);
        if (ownerId1 < ownerId2) {
            owners[0] = AccountConfiguration.InitializeOwner({ownerId: ownerId1, config: AccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scope: 0x00})});
            owners[1] = AccountConfiguration.InitializeOwner({ownerId: ownerId2, config: AccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scope: 0x00})});
        } else {
            owners[0] = AccountConfiguration.InitializeOwner({ownerId: ownerId2, config: AccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scope: 0x00})});
            owners[1] = AccountConfiguration.InitializeOwner({ownerId: ownerId1, config: AccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scope: 0x00})});
        }

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        address account = accountConfiguration.createAccount(bytes32(0), bytecode, owners);

        assertTrue(account != address(0));
        (address v1,) = accountConfiguration.getOwnerConfig(account, ownerId1);
        assertTrue(v1 != address(0));
        (address v2,) = accountConfiguration.getOwnerConfig(account, ownerId2);
        assertTrue(v2 != address(0));
    }

    function test_createAccount_deterministicAddress() public {
        address owner = vm.addr(1);
        bytes32 ownerId = bytes32(bytes20(owner));

        AccountConfiguration.InitializeOwner[] memory owners = new AccountConfiguration.InitializeOwner[](1);
        owners[0] = AccountConfiguration.InitializeOwner({ownerId: ownerId, config: AccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scope: 0x00})});

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        address predicted = accountConfiguration.computeAddress(bytes32(0), bytecode, owners);
        address actual = accountConfiguration.createAccount(bytes32(0), bytecode, owners);

        assertEq(predicted, actual);
    }

    function test_createAccount_idempotent() public {
        address owner = vm.addr(1);
        bytes32 ownerId = bytes32(bytes20(owner));

        AccountConfiguration.InitializeOwner[] memory owners = new AccountConfiguration.InitializeOwner[](1);
        owners[0] = AccountConfiguration.InitializeOwner({ownerId: ownerId, config: AccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scope: 0x00})});

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        address first = accountConfiguration.createAccount(bytes32(0), bytecode, owners);
        address second = accountConfiguration.createAccount(bytes32(0), bytecode, owners);

        assertEq(first, second);
    }

    function test_createAccount_revertsWithUnsortedOwners() public {
        address owner1 = vm.addr(1);
        address owner2 = vm.addr(2);

        bytes32 ownerId1 = bytes32(bytes20(owner1));
        bytes32 ownerId2 = bytes32(bytes20(owner2));

        bytes32 smaller = ownerId1 < ownerId2 ? ownerId1 : ownerId2;
        bytes32 larger = ownerId1 < ownerId2 ? ownerId2 : ownerId1;

        AccountConfiguration.InitializeOwner[] memory owners = new AccountConfiguration.InitializeOwner[](2);
        owners[0] = AccountConfiguration.InitializeOwner({ownerId: larger, config: AccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scope: 0x00})});
        owners[1] = AccountConfiguration.InitializeOwner({ownerId: smaller, config: AccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scope: 0x00})});

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        vm.expectRevert();
        accountConfiguration.createAccount(bytes32(0), bytecode, owners);
    }

    function test_createAccount_revertsWithNoOwners() public {
        AccountConfiguration.InitializeOwner[] memory owners = new AccountConfiguration.InitializeOwner[](0);
        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);

        vm.expectRevert();
        accountConfiguration.createAccount(bytes32(0), bytecode, owners);
    }

    function test_createAccount_revertsWithZeroVerifier() public {
        bytes32 ownerId = bytes32(uint256(1));

        AccountConfiguration.InitializeOwner[] memory owners = new AccountConfiguration.InitializeOwner[](1);
        owners[0] = AccountConfiguration.InitializeOwner({ownerId: ownerId, config: AccountConfiguration.OwnerConfig({verifier: address(0), scope: 0x00})});

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        vm.expectRevert();
        accountConfiguration.createAccount(bytes32(0), bytecode, owners);
    }

    function test_createAccount_initialOwnersHaveSpecifiedScope() public {
        address owner = vm.addr(1);
        bytes32 ownerId = bytes32(bytes20(owner));

        AccountConfiguration.InitializeOwner[] memory owners = new AccountConfiguration.InitializeOwner[](1);
        owners[0] = AccountConfiguration.InitializeOwner({ownerId: ownerId, config: AccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scope: 0x03})});

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        address account = accountConfiguration.createAccount(bytes32(0), bytecode, owners);

        (address verifier, uint8 scope) = accountConfiguration.getOwnerConfig(account, ownerId);
        assertEq(verifier, address(k1Verifier));
        assertEq(scope, 0x03);

        (bool locked, bool hasInitiatedUnlock, uint40 unlocksAt, uint24 unlockDelay) =
            accountConfiguration.getLockStatus(account);
        assertFalse(locked);
        assertFalse(hasInitiatedUnlock);
        assertEq(unlocksAt, 0);
        assertEq(unlockDelay, 0);
    }

    function test_createAccount_differentSaltsProduceDifferentAddresses() public {
        address owner = vm.addr(1);
        bytes32 ownerId = bytes32(bytes20(owner));

        AccountConfiguration.InitializeOwner[] memory owners = new AccountConfiguration.InitializeOwner[](1);
        owners[0] = AccountConfiguration.InitializeOwner({ownerId: ownerId, config: AccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scope: 0x00})});

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        address addr1 = accountConfiguration.computeAddress(bytes32(uint256(1)), bytecode, owners);
        address addr2 = accountConfiguration.computeAddress(bytes32(uint256(2)), bytecode, owners);

        assertTrue(addr1 != addr2);
    }
}
