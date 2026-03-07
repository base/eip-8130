// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ConfigOperation} from "../../../src/AccountConfigDigest.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract AccountLockTest is AccountConfigurationTest {
    uint256 constant OWNER_PK = 300;

    bytes32 constant LOCK_TYPEHASH = keccak256("Lock(address account,uint32 unlockDelay)");
    bytes32 constant REQUEST_UNLOCK_TYPEHASH = keccak256("RequestUnlock(address account)");
    bytes32 constant UNLOCK_TYPEHASH = keccak256("Unlock(address account)");

    function _lockAccount(address account, uint256 pk, uint32 unlockDelay) internal {
        bytes32 digest = keccak256(abi.encode(LOCK_TYPEHASH, account, unlockDelay));
        bytes memory auth = _buildK1Auth(pk, digest);
        accountConfiguration.lock(account, unlockDelay, auth);
    }

    function _requestUnlock(address account, uint256 pk) internal {
        bytes32 digest = keccak256(abi.encode(REQUEST_UNLOCK_TYPEHASH, account));
        bytes memory auth = _buildK1Auth(pk, digest);
        accountConfiguration.requestUnlock(account, auth);
    }

    function _unlock(address account, uint256 pk) internal {
        bytes32 digest = keccak256(abi.encode(UNLOCK_TYPEHASH, account));
        bytes memory auth = _buildK1Auth(pk, digest);
        accountConfiguration.unlock(account, auth);
    }

    // ── Lock lifecycle ──

    function test_lockAccount() public {
        (address account,) = _createK1Account(OWNER_PK);

        _lockAccount(account, OWNER_PK, 1 hours);

        (bool locked, uint32 unlockDelay, uint32 unlockRequestedAt) = accountConfiguration.getLockState(account);
        assertTrue(locked);
        assertEq(unlockDelay, 1 hours);
        assertEq(unlockRequestedAt, 0);
    }

    function test_requestUnlock() public {
        (address account,) = _createK1Account(OWNER_PK);

        _lockAccount(account, OWNER_PK, 1 hours);

        vm.warp(1000);
        _requestUnlock(account, OWNER_PK);

        (bool locked, uint32 unlockDelay, uint32 unlockRequestedAt) = accountConfiguration.getLockState(account);
        assertTrue(locked);
        assertEq(unlockDelay, 1 hours);
        assertEq(unlockRequestedAt, 1000);
    }

    function test_unlockAfterDelay() public {
        (address account,) = _createK1Account(OWNER_PK);

        _lockAccount(account, OWNER_PK, 1 hours);

        vm.warp(1000);
        _requestUnlock(account, OWNER_PK);

        vm.warp(1000 + 1 hours);
        _unlock(account, OWNER_PK);

        (bool locked,,) = accountConfiguration.getLockState(account);
        assertFalse(locked);
    }

    function test_unlockRevertsBeforeDelay() public {
        (address account,) = _createK1Account(OWNER_PK);

        _lockAccount(account, OWNER_PK, 1 hours);

        vm.warp(1000);
        _requestUnlock(account, OWNER_PK);

        vm.warp(1000 + 30 minutes);
        vm.expectRevert();
        _unlock(account, OWNER_PK);
    }

    function test_unlockRevertsWithoutRequest() public {
        (address account,) = _createK1Account(OWNER_PK);

        _lockAccount(account, OWNER_PK, 1 hours);

        vm.expectRevert();
        _unlock(account, OWNER_PK);
    }

    function test_requestUnlockRevertsWhenNotLocked() public {
        (address account,) = _createK1Account(OWNER_PK);

        vm.expectRevert();
        _requestUnlock(account, OWNER_PK);
    }

    function test_lockRevertsWhenAlreadyLocked() public {
        (address account,) = _createK1Account(OWNER_PK);

        _lockAccount(account, OWNER_PK, 1 hours);

        vm.expectRevert();
        _lockAccount(account, OWNER_PK, 2 hours);
    }

    function test_lockedAccountRejectsOwnerChanges() public {
        (address account,) = _createK1Account(OWNER_PK);

        _lockAccount(account, OWNER_PK, 1 hours);

        ConfigOperation[] memory ops = new ConfigOperation[](1);
        ops[0] = ConfigOperation({opType: 0x01, verifier: address(k1Verifier), ownerId: bytes32(bytes20(vm.addr(400)))});

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeConfigChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        vm.expectRevert();
        accountConfiguration.applyConfigChange(account, chainId, seq, ops, auth);
    }

    function test_lockRevertsWithInvalidSignature() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 digest = keccak256(abi.encode(LOCK_TYPEHASH, account, uint32(1 hours)));
        bytes memory wrongAuth = _buildK1Auth(999, digest);

        vm.expectRevert();
        accountConfiguration.lock(account, 1 hours, wrongAuth);
    }

    // ── Full lifecycle ──

    function test_fullLockUnlockCycle() public {
        (address account,) = _createK1Account(OWNER_PK);

        _lockAccount(account, OWNER_PK, 1 hours);
        (bool locked,,) = accountConfiguration.getLockState(account);
        assertTrue(locked);

        vm.warp(1000);
        _requestUnlock(account, OWNER_PK);

        vm.warp(1000 + 1 hours);
        _unlock(account, OWNER_PK);

        (locked,,) = accountConfiguration.getLockState(account);
        assertFalse(locked);

        ConfigOperation[] memory ops = new ConfigOperation[](1);
        ops[0] = ConfigOperation({opType: 0x01, verifier: address(k1Verifier), ownerId: bytes32(bytes20(vm.addr(500)))});

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeConfigChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        accountConfiguration.applyConfigChange(account, chainId, seq, ops, auth);
        assertTrue(accountConfiguration.isAuthorized(account, bytes32(bytes20(vm.addr(500)))));
    }
}
