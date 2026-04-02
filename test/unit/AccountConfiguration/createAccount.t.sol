// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {IAccountConfiguration} from "../../../src/interfaces/IAccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract CreateAccountTest is AccountConfigurationTest {
    function test_createAccount_singleK1Owner(uint256 pk) public {
        pk = bound(pk, 1, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140);
        address owner = vm.addr(pk);
        bytes32 ownerId = bytes32(bytes20(owner));

        IAccountConfiguration.Owner[] memory owners = new IAccountConfiguration.Owner[](1);
        owners[0] = IAccountConfiguration.Owner({
            ownerId: ownerId, config: IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00})
        });

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        address account = accountConfiguration.createAccount(bytes32(0), bytecode, owners);

        assertTrue(account != address(0));
        assertTrue(account.code.length > 0);
        assertTrue(accountConfiguration.isOwner(account, ownerId));
    }

    function test_createAccount_multipleOwners() public {
        address owner1 = vm.addr(1);
        address owner2 = vm.addr(2);

        bytes32 ownerId1 = bytes32(bytes20(owner1));
        bytes32 ownerId2 = bytes32(bytes20(owner2));

        IAccountConfiguration.Owner[] memory owners = new IAccountConfiguration.Owner[](2);
        if (ownerId1 < ownerId2) {
            owners[0] = IAccountConfiguration.Owner({
                ownerId: ownerId1,
                config: IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00})
            });
            owners[1] = IAccountConfiguration.Owner({
                ownerId: ownerId2,
                config: IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00})
            });
        } else {
            owners[0] = IAccountConfiguration.Owner({
                ownerId: ownerId2,
                config: IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00})
            });
            owners[1] = IAccountConfiguration.Owner({
                ownerId: ownerId1,
                config: IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00})
            });
        }

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        address account = accountConfiguration.createAccount(bytes32(0), bytecode, owners);

        assertTrue(account != address(0));
        assertTrue(accountConfiguration.isOwner(account, ownerId1));
        assertTrue(accountConfiguration.isOwner(account, ownerId2));
    }

    function test_createAccount_deterministicAddress() public {
        address owner = vm.addr(1);
        bytes32 ownerId = bytes32(bytes20(owner));

        IAccountConfiguration.Owner[] memory owners = new IAccountConfiguration.Owner[](1);
        owners[0] = IAccountConfiguration.Owner({
            ownerId: ownerId, config: IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00})
        });

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        address predicted = accountConfiguration.computeAddress(bytes32(0), bytecode, owners);
        address actual = accountConfiguration.createAccount(bytes32(0), bytecode, owners);

        assertEq(predicted, actual);
    }

    function test_createAccount_revertsOnDuplicate() public {
        address owner = vm.addr(1);
        bytes32 ownerId = bytes32(bytes20(owner));

        IAccountConfiguration.Owner[] memory owners = new IAccountConfiguration.Owner[](1);
        owners[0] = IAccountConfiguration.Owner({
            ownerId: ownerId, config: IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00})
        });

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        accountConfiguration.createAccount(bytes32(0), bytecode, owners);

        vm.expectRevert();
        accountConfiguration.createAccount(bytes32(0), bytecode, owners);
    }

    function test_createAccount_revertsWithUnsortedOwners() public {
        address owner1 = vm.addr(1);
        address owner2 = vm.addr(2);

        bytes32 ownerId1 = bytes32(bytes20(owner1));
        bytes32 ownerId2 = bytes32(bytes20(owner2));

        bytes32 smaller = ownerId1 < ownerId2 ? ownerId1 : ownerId2;
        bytes32 larger = ownerId1 < ownerId2 ? ownerId2 : ownerId1;

        IAccountConfiguration.Owner[] memory owners = new IAccountConfiguration.Owner[](2);
        owners[0] = IAccountConfiguration.Owner({
            ownerId: larger, config: IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00})
        });
        owners[1] = IAccountConfiguration.Owner({
            ownerId: smaller, config: IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00})
        });

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        vm.expectRevert();
        accountConfiguration.createAccount(bytes32(0), bytecode, owners);
    }

    function test_createAccount_revertsWithNoOwners() public {
        IAccountConfiguration.Owner[] memory owners = new IAccountConfiguration.Owner[](0);
        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);

        vm.expectRevert();
        accountConfiguration.createAccount(bytes32(0), bytecode, owners);
    }

    function test_createAccount_revertsWithZeroVerifier() public {
        bytes32 ownerId = bytes32(uint256(1));

        IAccountConfiguration.Owner[] memory owners = new IAccountConfiguration.Owner[](1);
        owners[0] = IAccountConfiguration.Owner({
            ownerId: ownerId, config: IAccountConfiguration.OwnerConfig({verifier: address(0), scopes: 0x00})
        });

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        vm.expectRevert();
        accountConfiguration.createAccount(bytes32(0), bytecode, owners);
    }

    function test_createAccount_initialOwnersHaveSpecifiedScope() public {
        address owner = vm.addr(1);
        bytes32 ownerId = bytes32(bytes20(owner));

        IAccountConfiguration.Owner[] memory owners = new IAccountConfiguration.Owner[](1);
        owners[0] = IAccountConfiguration.Owner({
            ownerId: ownerId, config: IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x03})
        });

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        address account = accountConfiguration.createAccount(bytes32(0), bytecode, owners);

        IAccountConfiguration.OwnerConfig memory cfg = accountConfiguration.getOwnerConfig(account, ownerId);
        assertEq(cfg.verifier, address(k1Verifier));
        assertEq(cfg.scopes, 0x03);

        (bool locked, bool hasInitiatedUnlock, uint40 unlocksAt, uint16 unlockDelay) =
            accountConfiguration.getLockStatus(account);
        assertFalse(locked);
        assertFalse(hasInitiatedUnlock);
        assertEq(unlocksAt, 0);
        assertEq(unlockDelay, 0);
    }

    function test_createAccount_differentSaltsProduceDifferentAddresses() public {
        address owner = vm.addr(1);
        bytes32 ownerId = bytes32(bytes20(owner));

        IAccountConfiguration.Owner[] memory owners = new IAccountConfiguration.Owner[](1);
        owners[0] = IAccountConfiguration.Owner({
            ownerId: ownerId, config: IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00})
        });

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        address addr1 = accountConfiguration.computeAddress(bytes32(uint256(1)), bytecode, owners);
        address addr2 = accountConfiguration.computeAddress(bytes32(uint256(2)), bytecode, owners);

        assertTrue(addr1 != addr2);
    }
}
