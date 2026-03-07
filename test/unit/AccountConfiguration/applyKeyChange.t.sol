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
        ops[0] = ConfigOperation({opType: 0x01, verifier: address(k1Verifier), ownerId: newOwnerId});

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeConfigChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        accountConfiguration.applyConfigChange(account, chainId, seq, ops, auth);

        assertTrue(accountConfiguration.isAuthorized(account, newOwnerId));
        assertEq(accountConfiguration.getOwner(account, newOwnerId), address(k1Verifier));
    }

    function test_revokeOwner() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(NEW_OWNER_PK);
        bytes32 newOwnerId = bytes32(bytes20(newSigner));
        _authorizeOwner(account, OWNER_PK, newOwnerId, address(k1Verifier));

        assertTrue(accountConfiguration.isAuthorized(account, newOwnerId));

        ConfigOperation[] memory ops = new ConfigOperation[](1);
        ops[0] = ConfigOperation({opType: 0x02, verifier: address(0), ownerId: newOwnerId});

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeConfigChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        accountConfiguration.applyConfigChange(account, chainId, seq, ops, auth);

        assertFalse(accountConfiguration.isAuthorized(account, newOwnerId));
    }

    function test_multipleOperationsInSingleChange() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 owner1 = bytes32(bytes20(vm.addr(300)));
        bytes32 owner2 = bytes32(bytes20(vm.addr(301)));

        ConfigOperation[] memory ops = new ConfigOperation[](2);
        ops[0] = ConfigOperation({opType: 0x01, verifier: address(k1Verifier), ownerId: owner1});
        ops[1] = ConfigOperation({opType: 0x01, verifier: address(k1Verifier), ownerId: owner2});

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeConfigChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        accountConfiguration.applyConfigChange(account, chainId, seq, ops, auth);

        assertTrue(accountConfiguration.isAuthorized(account, owner1));
        assertTrue(accountConfiguration.isAuthorized(account, owner2));
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
        ops[0] = ConfigOperation({opType: 0x01, verifier: address(k1Verifier), ownerId: bytes32(bytes20(vm.addr(300)))});

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
        ops[0] = ConfigOperation({opType: 0x01, verifier: address(k1Verifier), ownerId: bytes32(bytes20(vm.addr(300)))});

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
        ops[0] = ConfigOperation({opType: 0x01, verifier: address(k1Verifier), ownerId: thirdOwnerId});

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeConfigChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(NEW_OWNER_PK, digest);

        accountConfiguration.applyConfigChange(account, chainId, seq, ops, auth);
        assertTrue(accountConfiguration.isAuthorized(account, thirdOwnerId));
    }

    function test_revertsOnDuplicateOwnerAuthorization() public {
        (address account, bytes32 ownerOwnerId) = _createK1Account(OWNER_PK);

        ConfigOperation[] memory ops = new ConfigOperation[](1);
        ops[0] = ConfigOperation({opType: 0x01, verifier: address(k1Verifier), ownerId: ownerOwnerId});

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
        ops[0] = ConfigOperation({opType: 0x02, verifier: address(0), ownerId: nonExistentOwnerId});

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
        ops[0] = ConfigOperation({opType: 0x01, verifier: address(k1Verifier), ownerId: bytes32(bytes20(vm.addr(300)))});

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
        ConfigOperation[] memory ops = new ConfigOperation[](1);
        ops[0] = ConfigOperation({opType: 0x01, verifier: verifier, ownerId: newOwnerId});

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
