// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {IAccountConfiguration} from "../../../src/interfaces/IAccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract VerifyTest is AccountConfigurationTest {
    uint256 constant OWNER_PK = 400;

    function test_verify_validK1() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 hash = keccak256("verify me");
        bytes memory auth = _buildK1Auth(OWNER_PK, hash);

        uint8 scopes = accountConfiguration.verify(account, hash, auth);
        assertEq(scopes, uint8(0x00));
    }

    function test_verify_wrongSignature() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 hash = keccak256("verify me");
        // Sign with pk 999 — verifier recovers wrong address, config mismatch
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
        accountConfiguration.verify(account, hash, _buildK1Auth(OWNER_PK, hash));
    }

    function test_verify_differentAccounts() public {
        (address account1,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(1)));
        (address account2,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(2)));

        bytes32 hash = keccak256("cross-account test");
        bytes memory auth = _buildK1Auth(OWNER_PK, hash);

        accountConfiguration.verify(account1, hash, auth);
        accountConfiguration.verify(account2, hash, auth);
    }

    function test_getOwnerConfig_returnsVerifierAndScopes() public {
        (address account, bytes32 ownerId) = _createK1Account(OWNER_PK);

        IAccountConfiguration.OwnerConfig memory cfg = accountConfiguration.getOwnerConfig(account, ownerId);
        assertEq(cfg.verifier, address(k1Verifier));
        assertEq(cfg.scopes, 0x00);
    }

    function test_getOwnerConfig_returnsZeroForUnknownOwner() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 unknownOwnerId = bytes32(bytes20(vm.addr(999)));
        IAccountConfiguration.OwnerConfig memory cfg = accountConfiguration.getOwnerConfig(account, unknownOwnerId);
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

        uint8 scopes = accountConfiguration.verify(account, hash, auth);
        assertEq(scopes, uint8(0x01));
    }

    function test_verify_unrestrictedScope() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(401);
        bytes32 newOwnerId = bytes32(bytes20(newSigner));
        _authorizeOwnerWithScope(account, OWNER_PK, newOwnerId, address(k1Verifier), 0x00);

        bytes32 hash = keccak256("unrestricted");
        bytes memory auth = _buildK1Auth(401, hash);

        uint8 scopes = accountConfiguration.verify(account, hash, auth);
        assertEq(scopes, uint8(0x00));
    }

    // ── Implicit EOA (registered by default) ──

    function test_verify_implicitEOA() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);

        bytes32 hash = keccak256("implicit eoa verify");
        bytes memory auth = _buildImplicitEOAAuth(eoaPk, hash);

        // No createAccount or importAccount — the EOA is implicitly authorized
        uint8 scopes = accountConfiguration.verify(eoa, hash, auth);
        assertEq(scopes, 0);
    }

    function test_verify_implicitEOA_isOwnerReturnsTrue() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);

        assertTrue(accountConfiguration.isOwner(eoa, bytes32(bytes20(eoa))));
    }

    function test_verify_implicitEOA_nonSelfOwnerIdNotImplicit() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);

        // A random ownerId that isn't bytes32(bytes20(eoa)) should NOT be implicit
        bytes32 randomOwnerId = bytes32(bytes20(vm.addr(999)));
        assertFalse(accountConfiguration.isOwner(eoa, randomOwnerId));
    }

    function test_verify_implicitEOA_revokedBySentinel() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);
        bytes32 selfOwnerId = bytes32(bytes20(eoa));

        // Implicit EOA signs to add a second key
        bytes32 newOwnerId = bytes32(bytes20(vm.addr(501)));
        _implicitAuthorizeOwner(eoa, eoaPk, newOwnerId, address(k1Verifier));

        // Revoke the self-ownerId (writes sentinel) using the new explicit key
        _revokeOwner(eoa, 501, selfOwnerId);

        assertFalse(accountConfiguration.isOwner(eoa, selfOwnerId));

        // Implicit path is now blocked
        bytes32 hash = keccak256("after sentinel");
        vm.expectRevert();
        accountConfiguration.verify(eoa, hash, _buildImplicitEOAAuth(eoaPk, hash));
    }

    function test_verify_explicitEOA_selfOwner() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);
        bytes32 selfOwnerId = bytes32(bytes20(eoa));

        _implicitAuthorizeOwner(eoa, eoaPk, selfOwnerId, accountConfiguration.ECRECOVER_VERIFIER());

        bytes32 hash = keccak256("explicit self-owner");
        uint8 scopes = accountConfiguration.verify(eoa, hash, _buildExplicitEOAAuth(eoaPk, hash));
        assertEq(scopes, 0);

        // Explicit self-owner registration disables implicit auth path.
        vm.expectRevert();
        accountConfiguration.verify(eoa, hash, _buildImplicitEOAAuth(eoaPk, hash));
    }

    function test_verify_explicitEOA_nonSelfOwner() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);

        uint256 bobPk = 501;
        bytes32 bobOwnerId = bytes32(bytes20(vm.addr(bobPk)));
        _implicitAuthorizeOwner(eoa, eoaPk, bobOwnerId, accountConfiguration.ECRECOVER_VERIFIER());

        bytes32 hash = keccak256("explicit non-self owner");
        uint8 scopes = accountConfiguration.verify(eoa, hash, _buildExplicitEOAAuth(bobPk, hash));
        assertEq(scopes, 0);
    }

    function test_verify_explicitEOA_unregisteredFails() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);

        bytes32 hash = keccak256("explicit unregistered");
        vm.expectRevert();
        accountConfiguration.verify(eoa, hash, _buildExplicitEOAAuth(eoaPk, hash));
    }

    function test_verify_revokedVerifierPrefixReverts() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);

        bytes32 hash = keccak256("revoked verifier prefix");
        bytes memory auth = abi.encodePacked(accountConfiguration.REVOKED_VERIFIER());

        vm.expectRevert();
        accountConfiguration.verify(eoa, hash, auth);
    }

    // ── Helpers ──

    function _authorizeOwner(address account, uint256 pk, bytes32 newOwnerId, address verifier) internal {
        _authorizeOwnerWithScope(account, pk, newOwnerId, verifier, 0x00);
    }

    function _authorizeOwnerWithScope(address account, uint256 pk, bytes32 newOwnerId, address verifier, uint8 scope)
        internal
    {
        IAccountConfiguration.OwnerChange[] memory changes = new IAccountConfiguration.OwnerChange[](1);
        changes[0] = IAccountConfiguration.OwnerChange({
            ownerId: newOwnerId,
            changeType: 0x01,
            configData: abi.encode(IAccountConfiguration.OwnerConfig({verifier: verifier, scopes: scope}))
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(pk, digest);

        accountConfiguration.applySignedOwnerChanges(account, uint64(block.chainid), changes, auth);
    }

    function _revokeOwner(address account, uint256 pk, bytes32 ownerId) internal {
        IAccountConfiguration.OwnerChange[] memory changes = new IAccountConfiguration.OwnerChange[](1);
        changes[0] = IAccountConfiguration.OwnerChange({ownerId: ownerId, changeType: 0x02, configData: ""});

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(pk, digest);

        accountConfiguration.applySignedOwnerChanges(account, uint64(block.chainid), changes, auth);
    }

    function _implicitAuthorizeOwner(address account, uint256 pk, bytes32 newOwnerId, address verifier) internal {
        IAccountConfiguration.OwnerChange[] memory changes = new IAccountConfiguration.OwnerChange[](1);
        changes[0] = IAccountConfiguration.OwnerChange({
            ownerId: newOwnerId,
            changeType: 0x01,
            configData: abi.encode(IAccountConfiguration.OwnerConfig({verifier: verifier, scopes: 0x00}))
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildImplicitEOAAuth(pk, digest);

        accountConfiguration.applySignedOwnerChanges(account, uint64(block.chainid), changes, auth);
    }
}
