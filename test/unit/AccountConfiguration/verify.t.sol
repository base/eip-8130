// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract VerifyTest is AccountConfigurationTest {
    uint256 constant OWNER_PK = 400;

    function test_verify_validK1() public {
        (address account, bytes32 ownerId) = _createK1Account(OWNER_PK);

        bytes32 hash = keccak256("verify me");
        AccountConfiguration.Verification memory v = _buildK1Verification(OWNER_PK, hash);

        uint8 scopes = accountConfiguration.verify(account, hash, v);
        assertEq(scopes, uint8(0x00));
        assertEq(v.ownerId, ownerId);
    }

    function test_verify_wrongSignature() public {
        (address account, bytes32 ownerId) = _createK1Account(OWNER_PK);

        bytes32 hash = keccak256("verify me");
        // Sign with pk 999 but claim OWNER_PK's ownerId — verifier returns wrong ownerId
        AccountConfiguration.Verification memory v = AccountConfiguration.Verification({
            ownerId: ownerId,
            verifierData: _signDigest(999, hash)
        });

        vm.expectRevert();
        accountConfiguration.verify(account, hash, v);
    }

    function test_verify_unregisteredOwner() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 hash = keccak256("verify me");
        // Sign with pk 999 (not registered on this account)
        AccountConfiguration.Verification memory v = _buildK1Verification(999, hash);

        vm.expectRevert();
        accountConfiguration.verify(account, hash, v);
    }

    function test_verify_revokedOwner() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(401);
        bytes32 newOwnerId = bytes32(bytes20(newSigner));
        _authorizeOwner(account, OWNER_PK, newOwnerId, address(k1Verifier));

        _revokeOwner(account, OWNER_PK, newOwnerId);

        bytes32 hash = keccak256("after revoke");
        AccountConfiguration.Verification memory revokedV = _buildK1Verification(401, hash);

        vm.expectRevert();
        accountConfiguration.verify(account, hash, revokedV);

        // Original owner should still work
        accountConfiguration.verify(account, hash, _buildK1Verification(OWNER_PK, hash));
    }

    function test_verify_differentAccounts() public {
        (address account1,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(1)));
        (address account2,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(2)));

        bytes32 hash = keccak256("cross-account test");
        AccountConfiguration.Verification memory v = _buildK1Verification(OWNER_PK, hash);

        accountConfiguration.verify(account1, hash, v);
        accountConfiguration.verify(account2, hash, v);
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
        AccountConfiguration.Verification memory v = _buildK1Verification(401, hash);

        uint8 scopes = accountConfiguration.verify(account, hash, v);
        assertEq(v.ownerId, newOwnerId);
        assertEq(scopes, uint8(0x01));
    }

    function test_verify_unrestrictedScope() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(401);
        bytes32 newOwnerId = bytes32(bytes20(newSigner));
        _authorizeOwnerWithScope(account, OWNER_PK, newOwnerId, address(k1Verifier), 0x00);

        bytes32 hash = keccak256("unrestricted");
        AccountConfiguration.Verification memory v = _buildK1Verification(401, hash);

        uint8 scopes = accountConfiguration.verify(account, hash, v);
        assertEq(scopes, uint8(0x00));
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
        AccountConfiguration.Verification memory v = _buildK1Verification(pk, digest);

        accountConfiguration.applySignedOwnerChanges(account, isCrossChain, changes, v);
    }

    function _revokeOwner(address account, uint256 pk, bytes32 ownerId) internal {
        AccountConfiguration.OwnerChange[] memory changes = new AccountConfiguration.OwnerChange[](1);
        changes[0] = AccountConfiguration.OwnerChange({ownerId: ownerId, changeType: 0x02, configData: ""});

        bool isCrossChain = false;
        uint64 seq = accountConfiguration.getOwnerChangeSequence(account);
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        AccountConfiguration.Verification memory v = _buildK1Verification(pk, digest);

        accountConfiguration.applySignedOwnerChanges(account, isCrossChain, changes, v);
    }
}
