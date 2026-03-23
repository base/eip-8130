// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract ApplyConfigChangeOwnerTest is AccountConfigurationTest {
    uint256 constant OWNER_PK = 200;
    uint256 constant NEW_OWNER_PK = 201;

    function test_authorizeOwner() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(NEW_OWNER_PK);
        bytes32 newOwnerId = bytes32(bytes20(newSigner));

        AccountConfiguration.OwnerChange[] memory changes = new AccountConfiguration.OwnerChange[](1);
        changes[0] = AccountConfiguration.OwnerChange({
            ownerId: newOwnerId,
            changeType: 0x01,
            configData: abi.encode(AccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00}))
        });

        bool isCrossChain = false;
        uint64 seq = accountConfiguration.getOwnerChangeSequence(account);
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        accountConfiguration.applyOwnerChanges(account, isCrossChain, changes, auth);

        AccountConfiguration.OwnerConfig memory cfg = accountConfiguration.getOwnerConfig(account, newOwnerId);
        assertTrue(cfg.verifier != address(0));
        assertEq(cfg.verifier, address(k1Verifier));
        assertEq(cfg.scopes, 0x00);
    }

    function test_authorizeOwner_withScope() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(NEW_OWNER_PK);
        bytes32 newOwnerId = bytes32(bytes20(newSigner));

        AccountConfiguration.OwnerChange[] memory changes = new AccountConfiguration.OwnerChange[](1);
        changes[0] = AccountConfiguration.OwnerChange({
            ownerId: newOwnerId,
            changeType: 0x01,
            configData: abi.encode(AccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x04}))
        });

        bool isCrossChain = false;
        uint64 seq = accountConfiguration.getOwnerChangeSequence(account);
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        accountConfiguration.applyOwnerChanges(account, isCrossChain, changes, auth);

        AccountConfiguration.OwnerConfig memory cfg = accountConfiguration.getOwnerConfig(account, newOwnerId);
        assertEq(cfg.verifier, address(k1Verifier));
        assertEq(cfg.scopes, 0x04);
    }

    function test_revokeOwner() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(NEW_OWNER_PK);
        bytes32 newOwnerId = bytes32(bytes20(newSigner));
        _authorizeOwner(account, OWNER_PK, newOwnerId, address(k1Verifier));

        assertTrue(accountConfiguration.isOwner(account, newOwnerId));

        AccountConfiguration.OwnerChange[] memory changes = new AccountConfiguration.OwnerChange[](1);
        changes[0] = AccountConfiguration.OwnerChange({ownerId: newOwnerId, changeType: 0x02, configData: ""});

        bool isCrossChain = false;
        uint64 seq = accountConfiguration.getOwnerChangeSequence(account);
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        accountConfiguration.applyOwnerChanges(account, isCrossChain, changes, auth);

        assertFalse(accountConfiguration.isOwner(account, newOwnerId));
    }

    function test_multipleOperationsInSingleChange() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 owner1 = bytes32(bytes20(vm.addr(300)));
        bytes32 owner2 = bytes32(bytes20(vm.addr(301)));

        AccountConfiguration.OwnerChange[] memory changes = new AccountConfiguration.OwnerChange[](2);
        changes[0] = AccountConfiguration.OwnerChange({
            ownerId: owner1,
            changeType: 0x01,
            configData: abi.encode(AccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00}))
        });
        changes[1] = AccountConfiguration.OwnerChange({
            ownerId: owner2,
            changeType: 0x01,
            configData: abi.encode(AccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00}))
        });

        bool isCrossChain = false;
        uint64 seq = accountConfiguration.getOwnerChangeSequence(account);
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        accountConfiguration.applyOwnerChanges(account, isCrossChain, changes, auth);

        assertTrue(accountConfiguration.isOwner(account, owner1));
        assertTrue(accountConfiguration.isOwner(account, owner2));
    }

    function test_sequenceIncrements() public {
        (address account,) = _createK1Account(OWNER_PK);

        assertEq(accountConfiguration.getOwnerChangeSequence(account), 0);

        _authorizeOwner(account, OWNER_PK, bytes32(bytes20(vm.addr(300))), address(k1Verifier));
        assertEq(accountConfiguration.getOwnerChangeSequence(account), 1);

        _authorizeOwner(account, OWNER_PK, bytes32(bytes20(vm.addr(301))), address(k1Verifier));
        assertEq(accountConfiguration.getOwnerChangeSequence(account), 2);
    }

    function test_revertsWhenLocked() public {
        (address account,) = _createK1Account(OWNER_PK);

        _lockAccount(account);

        AccountConfiguration.OwnerChange[] memory changes = new AccountConfiguration.OwnerChange[](1);
        changes[0] = AccountConfiguration.OwnerChange({
            ownerId: bytes32(bytes20(vm.addr(300))),
            changeType: 0x01,
            configData: abi.encode(AccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00}))
        });

        bool isCrossChain = false;
        uint64 seq = accountConfiguration.getOwnerChangeSequence(account);
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        vm.expectRevert();
        accountConfiguration.applyOwnerChanges(account, isCrossChain, changes, auth);
    }

    function test_anyOwnerCanAuthorize() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 secondOwnerId = bytes32(bytes20(vm.addr(NEW_OWNER_PK)));
        _authorizeOwner(account, OWNER_PK, secondOwnerId, address(k1Verifier));

        bytes32 thirdOwnerId = bytes32(bytes20(vm.addr(302)));
        AccountConfiguration.OwnerChange[] memory changes = new AccountConfiguration.OwnerChange[](1);
        changes[0] = AccountConfiguration.OwnerChange({
            ownerId: thirdOwnerId,
            changeType: 0x01,
            configData: abi.encode(AccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00}))
        });

        bool isCrossChain = false;
        uint64 seq = accountConfiguration.getOwnerChangeSequence(account);
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(NEW_OWNER_PK, digest);

        accountConfiguration.applyOwnerChanges(account, isCrossChain, changes, auth);
        assertTrue(accountConfiguration.isOwner(account, thirdOwnerId));
    }

    function test_scopedOwner_cannotAuthorizeWithoutConfigScope() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(NEW_OWNER_PK);
        bytes32 secondOwnerId = bytes32(bytes20(newSigner));
        _authorizeOwnerWithScope(account, OWNER_PK, secondOwnerId, address(k1Verifier), 0x02);

        bytes32 thirdOwnerId = bytes32(bytes20(vm.addr(302)));
        AccountConfiguration.OwnerChange[] memory changes = new AccountConfiguration.OwnerChange[](1);
        changes[0] = AccountConfiguration.OwnerChange({
            ownerId: thirdOwnerId,
            changeType: 0x01,
            configData: abi.encode(AccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00}))
        });

        bool isCrossChain = false;
        uint64 seq = accountConfiguration.getOwnerChangeSequence(account);
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(NEW_OWNER_PK, digest);

        vm.expectRevert();
        accountConfiguration.applyOwnerChanges(account, isCrossChain, changes, auth);
    }

    function test_scopedOwner_canAuthorizeWithConfigScope() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(NEW_OWNER_PK);
        bytes32 secondOwnerId = bytes32(bytes20(newSigner));
        _authorizeOwnerWithScope(account, OWNER_PK, secondOwnerId, address(k1Verifier), 0x04);

        bytes32 thirdOwnerId = bytes32(bytes20(vm.addr(302)));
        AccountConfiguration.OwnerChange[] memory changes = new AccountConfiguration.OwnerChange[](1);
        changes[0] = AccountConfiguration.OwnerChange({
            ownerId: thirdOwnerId,
            changeType: 0x01,
            configData: abi.encode(AccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00}))
        });

        bool isCrossChain = false;
        uint64 seq = accountConfiguration.getOwnerChangeSequence(account);
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(NEW_OWNER_PK, digest);

        accountConfiguration.applyOwnerChanges(account, isCrossChain, changes, auth);
        assertTrue(accountConfiguration.isOwner(account, thirdOwnerId));
    }

    function test_revertsOnDuplicateOwnerAuthorization() public {
        (address account, bytes32 ownerOwnerId) = _createK1Account(OWNER_PK);

        AccountConfiguration.OwnerChange[] memory changes = new AccountConfiguration.OwnerChange[](1);
        changes[0] = AccountConfiguration.OwnerChange({
            ownerId: ownerOwnerId,
            changeType: 0x01,
            configData: abi.encode(AccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00}))
        });

        bool isCrossChain = false;
        uint64 seq = accountConfiguration.getOwnerChangeSequence(account);
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        vm.expectRevert();
        accountConfiguration.applyOwnerChanges(account, isCrossChain, changes, auth);
    }

    function test_revertsOnRevokingNonExistentOwner() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 nonExistentOwnerId = bytes32(bytes20(vm.addr(999)));

        AccountConfiguration.OwnerChange[] memory changes = new AccountConfiguration.OwnerChange[](1);
        changes[0] = AccountConfiguration.OwnerChange({ownerId: nonExistentOwnerId, changeType: 0x02, configData: ""});

        bool isCrossChain = false;
        uint64 seq = accountConfiguration.getOwnerChangeSequence(account);
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        vm.expectRevert();
        accountConfiguration.applyOwnerChanges(account, isCrossChain, changes, auth);
    }

    function test_revertsWithInvalidSignature() public {
        (address account,) = _createK1Account(OWNER_PK);

        AccountConfiguration.OwnerChange[] memory changes = new AccountConfiguration.OwnerChange[](1);
        changes[0] = AccountConfiguration.OwnerChange({
            ownerId: bytes32(bytes20(vm.addr(300))),
            changeType: 0x01,
            configData: abi.encode(AccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00}))
        });

        bool isCrossChain = false;
        uint64 seq = accountConfiguration.getOwnerChangeSequence(account);
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);

        bytes memory badAuth = _buildK1Auth(999, digest);

        vm.expectRevert();
        accountConfiguration.applyOwnerChanges(account, isCrossChain, changes, badAuth);
    }

    // ── Helpers ──

    function _authorizeOwner(address account, uint256 pk, bytes32 newOwnerId, address verifier) internal {
        _authorizeOwnerWithScope(account, pk, newOwnerId, verifier, 0x00);
    }

    function _authorizeOwnerWithScope(address account, uint256 pk, bytes32 newOwnerId, address verifier, uint8 scope)
        internal
    {
        AccountConfiguration.OwnerChange[] memory changes = new AccountConfiguration.OwnerChange[](1);
        changes[0] = AccountConfiguration.OwnerChange({
            ownerId: newOwnerId,
            changeType: 0x01,
            configData: abi.encode(AccountConfiguration.OwnerConfig({verifier: verifier, scopes: scope}))
        });

        bool isCrossChain = false;
        uint64 seq = accountConfiguration.getOwnerChangeSequence(account);
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(pk, digest);

        accountConfiguration.applyOwnerChanges(account, isCrossChain, changes, auth);
    }

    function _lockAccount(address account) internal {
        vm.prank(account);
        accountConfiguration.lock(1 hours);
    }
}
