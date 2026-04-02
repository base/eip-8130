// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {IAccountConfiguration} from "../../../src/interfaces/IAccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract AccountLockTest is AccountConfigurationTest {
    uint256 constant OWNER_PK = 300;

    function _lockAccount(address account, uint16 unlockDelay) internal {
        vm.prank(account);
        accountConfiguration.lock(unlockDelay);
    }

    function _initiateUnlock(address account) internal {
        vm.prank(account);
        accountConfiguration.initiateUnlock();
    }

    // ── Lock lifecycle ──

    function test_lockAccount() public {
        (address account,) = _createK1Account(OWNER_PK);

        _lockAccount(account, 1 hours);

        (bool locked, bool hasInitiatedUnlock, uint40 unlocksAt, uint16 unlockDelay) =
            accountConfiguration.getLockStatus(account);
        assertTrue(locked);
        assertFalse(hasInitiatedUnlock);
        assertEq(unlocksAt, type(uint40).max);
        assertEq(unlockDelay, 1 hours);
    }

    function test_requestUnlock() public {
        (address account,) = _createK1Account(OWNER_PK);

        _lockAccount(account, 1 hours);

        vm.warp(1000);
        _initiateUnlock(account);

        (bool locked, bool hasInitiatedUnlock, uint40 unlocksAt,) = accountConfiguration.getLockStatus(account);
        assertTrue(locked);
        assertTrue(hasInitiatedUnlock);
        assertEq(unlocksAt, 1000 + 1 hours);
    }

    function test_unlockAfterDelay() public {
        (address account,) = _createK1Account(OWNER_PK);

        _lockAccount(account, 1 hours);

        vm.warp(1000);
        _initiateUnlock(account);

        vm.warp(1000 + 1 hours);
        assertFalse(accountConfiguration.isLocked(account));
    }

    function test_unlockRevertsBeforeDelay() public {
        (address account,) = _createK1Account(OWNER_PK);

        _lockAccount(account, 1 hours);

        vm.warp(1000);
        _initiateUnlock(account);

        vm.warp(1000 + 30 minutes);
        assertTrue(accountConfiguration.isLocked(account));
    }

    function test_unlockRevertsWithoutRequest() public {
        (address account,) = _createK1Account(OWNER_PK);

        _lockAccount(account, 1 hours);

        vm.warp(block.timestamp + 365 days);
        assertTrue(accountConfiguration.isLocked(account));
    }

    function test_requestUnlockRevertsWhenNotLocked() public {
        (address account,) = _createK1Account(OWNER_PK);

        vm.prank(account);
        vm.expectRevert();
        accountConfiguration.initiateUnlock();
    }

    function test_lockRevertsWhenAlreadyLocked() public {
        (address account,) = _createK1Account(OWNER_PK);

        _lockAccount(account, 1 hours);

        vm.prank(account);
        vm.expectRevert();
        accountConfiguration.lock(2 hours);
    }

    function test_lockedAccountRejectsOwnerChanges() public {
        (address account,) = _createK1Account(OWNER_PK);

        _lockAccount(account, 1 hours);

        IAccountConfiguration.OwnerChange[] memory changes = new IAccountConfiguration.OwnerChange[](1);
        changes[0] = IAccountConfiguration.OwnerChange({
            ownerId: bytes32(bytes20(vm.addr(400))),
            changeType: 0x01,
            configData: abi.encode(IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00}))
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        vm.expectRevert();
        accountConfiguration.applySignedOwnerChanges(account, uint64(block.chainid), changes, auth);
    }

    // ── Full lifecycle ──

    function test_fullLockUnlockCycle() public {
        (address account,) = _createK1Account(OWNER_PK);

        _lockAccount(account, 1 hours);
        (bool locked,,,) = accountConfiguration.getLockStatus(account);
        assertTrue(locked);

        vm.warp(1000);
        _initiateUnlock(account);

        vm.warp(1000 + 1 hours);
        assertFalse(accountConfiguration.isLocked(account));

        IAccountConfiguration.OwnerChange[] memory changes = new IAccountConfiguration.OwnerChange[](1);
        changes[0] = IAccountConfiguration.OwnerChange({
            ownerId: bytes32(bytes20(vm.addr(500))),
            changeType: 0x01,
            configData: abi.encode(IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00}))
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        accountConfiguration.applySignedOwnerChanges(account, uint64(block.chainid), changes, auth);
        assertTrue(accountConfiguration.isOwner(account, bytes32(bytes20(vm.addr(500)))));
    }
}
