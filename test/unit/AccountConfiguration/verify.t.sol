// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract VerifyTest is AccountConfigurationTest {
    uint256 constant OWNER_PK = 400;

    function test_verify_validK1() public {
        (address account, bytes32 ownerId) = _createK1Account(OWNER_PK);

        bytes32 hash = keccak256("verify me");
        bytes memory auth = _buildK1Auth(OWNER_PK, hash);

        (bytes32 returnedOwnerId, AccountConfiguration.OwnerConfig memory cfg) =
            accountConfiguration.verify(account, hash, auth);
        assertEq(returnedOwnerId, ownerId);
        assertEq(cfg.verifier, address(k1Verifier));
    }

    function test_verify_wrongSignature() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 hash = keccak256("verify me");
        bytes memory auth = _buildK1Auth(999, hash);

        vm.expectRevert();
        accountConfiguration.verify(account, hash, auth);
    }

    function test_verify_unregisteredOwner() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 hash = keccak256("verify me");
        // Sign with pk 999 (not registered on this account)
        bytes memory auth = _buildK1Auth(999, hash);

        vm.expectRevert();
        accountConfiguration.verify(account, hash, auth);
    }

    function test_verify_revokedOwner() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(401);
        bytes32 newOwnerId = bytes32(bytes20(newSigner));
        _authorizeOwner(account, OWNER_PK, newOwnerId, address(k1Verifier));

        _revokeOwner(account, OWNER_PK, newOwnerId);

        bytes32 hash = keccak256("after revoke");
        bytes memory revokedAuth = _buildK1Auth(401, hash);

        vm.expectRevert();
        accountConfiguration.verify(account, hash, revokedAuth);

        // Original owner should still work
        bytes memory ownerAuth = _buildK1Auth(OWNER_PK, hash);
        (bytes32 returnedId,) = accountConfiguration.verify(account, hash, ownerAuth);
        assertEq(returnedId, bytes32(bytes20(vm.addr(OWNER_PK))));
    }

    function test_verify_differentAccounts() public {
        (address account1,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(1)));
        (address account2,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(2)));

        bytes32 hash = keccak256("cross-account test");
        bytes memory auth = _buildK1Auth(OWNER_PK, hash);

        (bytes32 ownerId1,) = accountConfiguration.verify(account1, hash, auth);
        (bytes32 ownerId2,) = accountConfiguration.verify(account2, hash, auth);

        assertEq(ownerId1, bytes32(bytes20(vm.addr(OWNER_PK))));
        assertEq(ownerId2, bytes32(bytes20(vm.addr(OWNER_PK))));
    }

    function test_getOwnerConfig_returnsVerifierAndScopes() public {
        (address account, bytes32 ownerId) = _createK1Account(OWNER_PK);

        AccountConfiguration.OwnerConfig memory cfg = accountConfiguration.getOwnerConfig(account, ownerId);
        assertEq(cfg.verifier, address(k1Verifier));
        assertEq(cfg.scopes, 0x00);
    }

    function test_getOwnerConfig_returnsZeroForUnknownOwner() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 unknownOwnerId = bytes32(bytes20(vm.addr(999)));
        AccountConfiguration.OwnerConfig memory cfg = accountConfiguration.getOwnerConfig(account, unknownOwnerId);
        assertEq(cfg.verifier, address(0));
        assertEq(cfg.scopes, 0);
    }

    function test_verify_scopedOwner_succeeds() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(401);
        bytes32 newOwnerId = bytes32(bytes20(newSigner));
        _authorizeOwnerWithScope(account, OWNER_PK, newOwnerId, address(k1Verifier), 0x01);

        bytes32 hash = keccak256("scoped verify");
        bytes memory auth = _buildK1Auth(401, hash);

        (bytes32 returnedId, AccountConfiguration.OwnerConfig memory cfg) =
            accountConfiguration.verify(account, hash, auth);
        assertEq(returnedId, newOwnerId);
        assertEq(cfg.scopes, 0x01);
    }

    function test_verify_unrestrictedScope() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(401);
        bytes32 newOwnerId = bytes32(bytes20(newSigner));
        _authorizeOwnerWithScope(account, OWNER_PK, newOwnerId, address(k1Verifier), 0x00);

        bytes32 hash = keccak256("unrestricted");
        bytes memory auth = _buildK1Auth(401, hash);

        (bytes32 returnedId,) = accountConfiguration.verify(account, hash, auth);
        assertEq(returnedId, newOwnerId);
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

    function _revokeOwner(address account, uint256 pk, bytes32 ownerId) internal {
        AccountConfiguration.OwnerChange[] memory changes = new AccountConfiguration.OwnerChange[](1);
        changes[0] = AccountConfiguration.OwnerChange({ownerId: ownerId, changeType: 0x02, configData: ""});

        bool isCrossChain = false;
        uint64 seq = accountConfiguration.getOwnerChangeSequence(account);
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(pk, digest);

        accountConfiguration.applyOwnerChanges(account, isCrossChain, changes, auth);
    }
}
