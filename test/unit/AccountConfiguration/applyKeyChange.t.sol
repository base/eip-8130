// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ConfigOperation} from "../../../src/AccountConfigDigest.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract ApplyConfigChangeOwnerTest is AccountConfigurationTest {
    uint256 constant OWNER_PK = 200;
    uint256 constant NEW_OWNER_PK = 201;

    function test_authorizeOwner() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(NEW_OWNER_PK);
        bytes32 newOwnerId = bytes32(bytes20(newSigner));

        ConfigOperation[] memory ops = new ConfigOperation[](1);
        ops[0] = ConfigOperation({opType: 0x01, verifier: address(k1Verifier), ownerId: newOwnerId, scope: 0x00});

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeConfigChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        accountConfiguration.applyConfigChange(account, chainId, seq, ops, auth);

        (address verifier, uint8 scope) = accountConfiguration.getOwner(account, newOwnerId);
        assertTrue(verifier != address(0));
        assertEq(verifier, address(k1Verifier));
        assertEq(scope, 0x00);
    }

    function test_authorizeOwner_withScope() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(NEW_OWNER_PK);
        bytes32 newOwnerId = bytes32(bytes20(newSigner));

        ConfigOperation[] memory ops = new ConfigOperation[](1);
        ops[0] = ConfigOperation({opType: 0x01, verifier: address(k1Verifier), ownerId: newOwnerId, scope: 0x04});

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeConfigChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        accountConfiguration.applyConfigChange(account, chainId, seq, ops, auth);

        (address verifier, uint8 scope) = accountConfiguration.getOwner(account, newOwnerId);
        assertEq(verifier, address(k1Verifier));
        assertEq(scope, 0x04);
    }

    function test_revokeOwner() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(NEW_OWNER_PK);
        bytes32 newOwnerId = bytes32(bytes20(newSigner));
        _authorizeOwner(account, OWNER_PK, newOwnerId, address(k1Verifier));

        (address v,) = accountConfiguration.getOwner(account, newOwnerId);
        assertTrue(v != address(0));

        ConfigOperation[] memory ops = new ConfigOperation[](1);
        ops[0] = ConfigOperation({opType: 0x02, verifier: address(0), ownerId: newOwnerId, scope: 0});

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeConfigChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        accountConfiguration.applyConfigChange(account, chainId, seq, ops, auth);

        (address v2,) = accountConfiguration.getOwner(account, newOwnerId);
        assertTrue(v2 == address(0));
    }

    function test_multipleOperationsInSingleChange() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 owner1 = bytes32(bytes20(vm.addr(300)));
        bytes32 owner2 = bytes32(bytes20(vm.addr(301)));

        ConfigOperation[] memory ops = new ConfigOperation[](2);
        ops[0] = ConfigOperation({opType: 0x01, verifier: address(k1Verifier), ownerId: owner1, scope: 0x00});
        ops[1] = ConfigOperation({opType: 0x01, verifier: address(k1Verifier), ownerId: owner2, scope: 0x00});

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeConfigChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        accountConfiguration.applyConfigChange(account, chainId, seq, ops, auth);

        (address v1,) = accountConfiguration.getOwner(account, owner1);
        assertTrue(v1 != address(0));
        (address v2,) = accountConfiguration.getOwner(account, owner2);
        assertTrue(v2 != address(0));
    }

    function test_sequenceIncrements() public {
        (address account,) = _createK1Account(OWNER_PK);

        uint64 chainId = uint64(block.chainid);
        assertEq(accountConfiguration.getChangeSequence(account, chainId), 0);

        _authorizeOwner(account, OWNER_PK, bytes32(bytes20(vm.addr(300))), address(k1Verifier));
        assertEq(accountConfiguration.getChangeSequence(account, chainId), 1);

        _authorizeOwner(account, OWNER_PK, bytes32(bytes20(vm.addr(301))), address(k1Verifier));
        assertEq(accountConfiguration.getChangeSequence(account, chainId), 2);
    }

    function test_revertsOnWrongSequence() public {
        (address account,) = _createK1Account(OWNER_PK);

        ConfigOperation[] memory ops = new ConfigOperation[](1);
        ops[0] = ConfigOperation({
            opType: 0x01, verifier: address(k1Verifier), ownerId: bytes32(bytes20(vm.addr(300))), scope: 0x00
        });

        uint64 chainId = uint64(block.chainid);
        uint64 wrongSeq = 999;
        bytes32 digest = _computeConfigChangeDigest(account, chainId, wrongSeq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        vm.expectRevert();
        accountConfiguration.applyConfigChange(account, chainId, wrongSeq, ops, auth);
    }

    function test_revertsWhenLocked() public {
        (address account,) = _createK1Account(OWNER_PK);

        _lockAccount(account);

        ConfigOperation[] memory ops = new ConfigOperation[](1);
        ops[0] = ConfigOperation({
            opType: 0x01, verifier: address(k1Verifier), ownerId: bytes32(bytes20(vm.addr(300))), scope: 0x00
        });

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeConfigChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        vm.expectRevert();
        accountConfiguration.applyConfigChange(account, chainId, seq, ops, auth);
    }

    function test_anyOwnerCanAuthorize() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 secondOwnerId = bytes32(bytes20(vm.addr(NEW_OWNER_PK)));
        _authorizeOwner(account, OWNER_PK, secondOwnerId, address(k1Verifier));

        bytes32 thirdOwnerId = bytes32(bytes20(vm.addr(302)));
        ConfigOperation[] memory ops = new ConfigOperation[](1);
        ops[0] = ConfigOperation({opType: 0x01, verifier: address(k1Verifier), ownerId: thirdOwnerId, scope: 0x00});

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeConfigChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(NEW_OWNER_PK, digest);

        accountConfiguration.applyConfigChange(account, chainId, seq, ops, auth);
        (address v,) = accountConfiguration.getOwner(account, thirdOwnerId);
        assertTrue(v != address(0));
    }

    function test_scopedOwner_cannotAuthorizeWithoutConfigScope() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(NEW_OWNER_PK);
        bytes32 secondOwnerId = bytes32(bytes20(newSigner));
        // Authorize second owner with SENDER scope only (no CONFIG)
        _authorizeOwnerWithScope(account, OWNER_PK, secondOwnerId, address(k1Verifier), 0x02);

        bytes32 thirdOwnerId = bytes32(bytes20(vm.addr(302)));
        ConfigOperation[] memory ops = new ConfigOperation[](1);
        ops[0] = ConfigOperation({opType: 0x01, verifier: address(k1Verifier), ownerId: thirdOwnerId, scope: 0x00});

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeConfigChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(NEW_OWNER_PK, digest);

        vm.expectRevert();
        accountConfiguration.applyConfigChange(account, chainId, seq, ops, auth);
    }

    function test_scopedOwner_canAuthorizeWithConfigScope() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(NEW_OWNER_PK);
        bytes32 secondOwnerId = bytes32(bytes20(newSigner));
        _authorizeOwnerWithScope(account, OWNER_PK, secondOwnerId, address(k1Verifier), 0x08);

        bytes32 thirdOwnerId = bytes32(bytes20(vm.addr(302)));
        ConfigOperation[] memory ops = new ConfigOperation[](1);
        ops[0] = ConfigOperation({opType: 0x01, verifier: address(k1Verifier), ownerId: thirdOwnerId, scope: 0x00});

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeConfigChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(NEW_OWNER_PK, digest);

        accountConfiguration.applyConfigChange(account, chainId, seq, ops, auth);
        (address v,) = accountConfiguration.getOwner(account, thirdOwnerId);
        assertTrue(v != address(0));
    }

    function test_revertsOnDuplicateOwnerAuthorization() public {
        (address account, bytes32 ownerOwnerId) = _createK1Account(OWNER_PK);

        ConfigOperation[] memory ops = new ConfigOperation[](1);
        ops[0] = ConfigOperation({opType: 0x01, verifier: address(k1Verifier), ownerId: ownerOwnerId, scope: 0x00});

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeConfigChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        vm.expectRevert();
        accountConfiguration.applyConfigChange(account, chainId, seq, ops, auth);
    }

    function test_revertsOnRevokingNonExistentOwner() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 nonExistentOwnerId = bytes32(bytes20(vm.addr(999)));

        ConfigOperation[] memory ops = new ConfigOperation[](1);
        ops[0] = ConfigOperation({opType: 0x02, verifier: address(0), ownerId: nonExistentOwnerId, scope: 0});

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeConfigChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        vm.expectRevert();
        accountConfiguration.applyConfigChange(account, chainId, seq, ops, auth);
    }

    function test_revertsWithInvalidSignature() public {
        (address account,) = _createK1Account(OWNER_PK);

        ConfigOperation[] memory ops = new ConfigOperation[](1);
        ops[0] = ConfigOperation({
            opType: 0x01, verifier: address(k1Verifier), ownerId: bytes32(bytes20(vm.addr(300))), scope: 0x00
        });

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeConfigChangeDigest(account, chainId, seq, ops);

        bytes memory badAuth = _buildK1Auth(999, digest);

        vm.expectRevert();
        accountConfiguration.applyConfigChange(account, chainId, seq, ops, badAuth);
    }

    function test_multichainSequenceChannelsAreIndependent() public {
        (address account,) = _createK1Account(OWNER_PK);

        uint64 localChainId = uint64(block.chainid);
        uint64 multichainId = 0;

        assertEq(accountConfiguration.getChangeSequence(account, localChainId), 0);
        assertEq(accountConfiguration.getChangeSequence(account, multichainId), 0);

        _authorizeOwner(account, OWNER_PK, bytes32(bytes20(vm.addr(300))), address(k1Verifier));

        assertEq(accountConfiguration.getChangeSequence(account, localChainId), 1);
        assertEq(accountConfiguration.getChangeSequence(account, multichainId), 0);
    }

    // ── Helpers ──

    function _authorizeOwner(address account, uint256 pk, bytes32 newOwnerId, address verifier) internal {
        _authorizeOwnerWithScope(account, pk, newOwnerId, verifier, 0x00);
    }

    function _authorizeOwnerWithScope(address account, uint256 pk, bytes32 newOwnerId, address verifier, uint8 scope)
        internal
    {
        ConfigOperation[] memory ops = new ConfigOperation[](1);
        ops[0] = ConfigOperation({opType: 0x01, verifier: verifier, ownerId: newOwnerId, scope: scope});

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeConfigChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(pk, digest);

        accountConfiguration.applyConfigChange(account, chainId, seq, ops, auth);
    }

    function _lockAccount(address account) internal {
        bytes32 lockTypehash = keccak256("Lock(address account,uint32 unlockDelay)");
        bytes32 digest = keccak256(abi.encode(lockTypehash, account, uint32(1 hours)));
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);
        accountConfiguration.lock(account, 1 hours, auth);
    }
}
