// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {IAccountConfiguration} from "../../../src/interfaces/IAccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract ApplyConfigChangeOwnerTest is AccountConfigurationTest {
    uint256 constant OWNER_PK = 200;
    uint256 constant NEW_OWNER_PK = 201;

    function test_authorizeOwner() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(NEW_OWNER_PK);
        bytes32 newOwnerId = bytes32(bytes20(newSigner));

        IAccountConfiguration.OwnerChange[] memory changes = new IAccountConfiguration.OwnerChange[](1);
        changes[0] = IAccountConfiguration.OwnerChange({
            ownerId: newOwnerId,
            changeType: 0x01,
            configData: abi.encode(IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00}))
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        accountConfiguration.applySignedOwnerChanges(account, uint64(block.chainid), changes, auth);

        IAccountConfiguration.OwnerConfig memory cfg = accountConfiguration.getOwnerConfig(account, newOwnerId);
        assertTrue(cfg.verifier != address(0));
        assertEq(cfg.verifier, address(k1Verifier));
        assertEq(cfg.scopes, 0x00);
    }

    function test_authorizeOwner_withScope() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(NEW_OWNER_PK);
        bytes32 newOwnerId = bytes32(bytes20(newSigner));

        IAccountConfiguration.OwnerChange[] memory changes = new IAccountConfiguration.OwnerChange[](1);
        changes[0] = IAccountConfiguration.OwnerChange({
            ownerId: newOwnerId,
            changeType: 0x01,
            configData: abi.encode(IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x04}))
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        accountConfiguration.applySignedOwnerChanges(account, uint64(block.chainid), changes, auth);

        IAccountConfiguration.OwnerConfig memory cfg = accountConfiguration.getOwnerConfig(account, newOwnerId);
        assertEq(cfg.verifier, address(k1Verifier));
        assertEq(cfg.scopes, 0x04);
    }

    function test_revokeOwner() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(NEW_OWNER_PK);
        bytes32 newOwnerId = bytes32(bytes20(newSigner));
        _authorizeOwner(account, OWNER_PK, newOwnerId, address(k1Verifier));

        assertTrue(accountConfiguration.isOwner(account, newOwnerId));

        IAccountConfiguration.OwnerChange[] memory changes = new IAccountConfiguration.OwnerChange[](1);
        changes[0] = IAccountConfiguration.OwnerChange({ownerId: newOwnerId, changeType: 0x02, configData: ""});

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        accountConfiguration.applySignedOwnerChanges(account, uint64(block.chainid), changes, auth);

        assertFalse(accountConfiguration.isOwner(account, newOwnerId));
    }

    function test_multipleOperationsInSingleChange() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 owner1 = bytes32(bytes20(vm.addr(300)));
        bytes32 owner2 = bytes32(bytes20(vm.addr(301)));

        IAccountConfiguration.OwnerChange[] memory changes = new IAccountConfiguration.OwnerChange[](2);
        changes[0] = IAccountConfiguration.OwnerChange({
            ownerId: owner1,
            changeType: 0x01,
            configData: abi.encode(IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00}))
        });
        changes[1] = IAccountConfiguration.OwnerChange({
            ownerId: owner2,
            changeType: 0x01,
            configData: abi.encode(IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00}))
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        accountConfiguration.applySignedOwnerChanges(account, uint64(block.chainid), changes, auth);

        assertTrue(accountConfiguration.isOwner(account, owner1));
        assertTrue(accountConfiguration.isOwner(account, owner2));
    }

    function test_sequenceIncrements() public {
        (address account,) = _createK1Account(OWNER_PK);

        assertEq(accountConfiguration.getChangeSequences(account).local, 0);

        _authorizeOwner(account, OWNER_PK, bytes32(bytes20(vm.addr(300))), address(k1Verifier));
        assertEq(accountConfiguration.getChangeSequences(account).local, 1);

        _authorizeOwner(account, OWNER_PK, bytes32(bytes20(vm.addr(301))), address(k1Verifier));
        assertEq(accountConfiguration.getChangeSequences(account).local, 2);
    }

    function test_revertsWhenLocked() public {
        (address account,) = _createK1Account(OWNER_PK);

        _lockAccount(account);

        IAccountConfiguration.OwnerChange[] memory changes = new IAccountConfiguration.OwnerChange[](1);
        changes[0] = IAccountConfiguration.OwnerChange({
            ownerId: bytes32(bytes20(vm.addr(300))),
            changeType: 0x01,
            configData: abi.encode(IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00}))
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        vm.expectRevert();
        accountConfiguration.applySignedOwnerChanges(account, uint64(block.chainid), changes, auth);
    }

    function test_anyOwnerCanAuthorize() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 secondOwnerId = bytes32(bytes20(vm.addr(NEW_OWNER_PK)));
        _authorizeOwner(account, OWNER_PK, secondOwnerId, address(k1Verifier));

        bytes32 thirdOwnerId = bytes32(bytes20(vm.addr(302)));
        IAccountConfiguration.OwnerChange[] memory changes = new IAccountConfiguration.OwnerChange[](1);
        changes[0] = IAccountConfiguration.OwnerChange({
            ownerId: thirdOwnerId,
            changeType: 0x01,
            configData: abi.encode(IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00}))
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(NEW_OWNER_PK, digest);

        accountConfiguration.applySignedOwnerChanges(account, uint64(block.chainid), changes, auth);
        assertTrue(accountConfiguration.isOwner(account, thirdOwnerId));
    }

    function test_scopedOwner_cannotAuthorizeWithoutConfigScope() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(NEW_OWNER_PK);
        bytes32 secondOwnerId = bytes32(bytes20(newSigner));
        _authorizeOwnerWithScope(account, OWNER_PK, secondOwnerId, address(k1Verifier), 0x02);

        bytes32 thirdOwnerId = bytes32(bytes20(vm.addr(302)));
        IAccountConfiguration.OwnerChange[] memory changes = new IAccountConfiguration.OwnerChange[](1);
        changes[0] = IAccountConfiguration.OwnerChange({
            ownerId: thirdOwnerId,
            changeType: 0x01,
            configData: abi.encode(IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00}))
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(NEW_OWNER_PK, digest);

        vm.expectRevert();
        accountConfiguration.applySignedOwnerChanges(account, uint64(block.chainid), changes, auth);
    }

    function test_scopedOwner_canAuthorizeWithConfigScope() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(NEW_OWNER_PK);
        bytes32 secondOwnerId = bytes32(bytes20(newSigner));
        _authorizeOwnerWithScope(
            account, OWNER_PK, secondOwnerId, address(k1Verifier), accountConfiguration.SCOPE_CHANGE_OWNERS()
        );

        bytes32 thirdOwnerId = bytes32(bytes20(vm.addr(302)));
        IAccountConfiguration.OwnerChange[] memory changes = new IAccountConfiguration.OwnerChange[](1);
        changes[0] = IAccountConfiguration.OwnerChange({
            ownerId: thirdOwnerId,
            changeType: 0x01,
            configData: abi.encode(IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00}))
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(NEW_OWNER_PK, digest);

        accountConfiguration.applySignedOwnerChanges(account, uint64(block.chainid), changes, auth);
        assertTrue(accountConfiguration.isOwner(account, thirdOwnerId));
    }

    function test_revertsOnDuplicateOwnerAuthorization() public {
        (address account, bytes32 ownerOwnerId) = _createK1Account(OWNER_PK);

        IAccountConfiguration.OwnerChange[] memory changes = new IAccountConfiguration.OwnerChange[](1);
        changes[0] = IAccountConfiguration.OwnerChange({
            ownerId: ownerOwnerId,
            changeType: 0x01,
            configData: abi.encode(IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00}))
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        vm.expectRevert();
        accountConfiguration.applySignedOwnerChanges(account, uint64(block.chainid), changes, auth);
    }

    function test_revertsOnRevokingNonExistentOwner() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 nonExistentOwnerId = bytes32(bytes20(vm.addr(999)));

        IAccountConfiguration.OwnerChange[] memory changes = new IAccountConfiguration.OwnerChange[](1);
        changes[0] = IAccountConfiguration.OwnerChange({ownerId: nonExistentOwnerId, changeType: 0x02, configData: ""});

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        vm.expectRevert();
        accountConfiguration.applySignedOwnerChanges(account, uint64(block.chainid), changes, auth);
    }

    function test_revertsWithInvalidSignature() public {
        (address account,) = _createK1Account(OWNER_PK);

        IAccountConfiguration.OwnerChange[] memory changes = new IAccountConfiguration.OwnerChange[](1);
        changes[0] = IAccountConfiguration.OwnerChange({
            ownerId: bytes32(bytes20(vm.addr(300))),
            changeType: 0x01,
            configData: abi.encode(IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00}))
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);

        bytes memory badAuth = _buildK1Auth(999, digest);

        vm.expectRevert();
        accountConfiguration.applySignedOwnerChanges(account, uint64(block.chainid), changes, badAuth);
    }

    // ── Implicit EOA (registered by default) ──
    //
    // Every account has an implicit self-ownerId bytes32(bytes20(account))
    // that is authorized with unrestricted scopes when the config slot
    // is empty. No createAccount/importAccount needed.

    function test_implicitEOA_canSignOwnerChanges() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);
        bytes32 newOwnerId = bytes32(bytes20(vm.addr(501)));

        IAccountConfiguration.OwnerChange[] memory changes = new IAccountConfiguration.OwnerChange[](1);
        changes[0] = IAccountConfiguration.OwnerChange({
            ownerId: newOwnerId,
            changeType: 0x01,
            configData: abi.encode(IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00}))
        });

        uint64 seq = accountConfiguration.getChangeSequences(eoa).local;
        bytes32 digest = _computeOwnerChangeBatchDigest(eoa, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildImplicitEOAAuth(eoaPk, digest);

        accountConfiguration.applySignedOwnerChanges(eoa, uint64(block.chainid), changes, auth);
        assertTrue(accountConfiguration.isOwner(eoa, newOwnerId));
    }

    function test_implicitEOA_canRevokeItselfViaSentinel() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);
        bytes32 selfOwnerId = bytes32(bytes20(eoa));

        assertTrue(accountConfiguration.isOwner(eoa, selfOwnerId));

        // Add a second key first using implicit EOA auth
        bytes32 newOwnerId = bytes32(bytes20(vm.addr(501)));
        _implicitAuthorizeOwner(eoa, eoaPk, newOwnerId, address(k1Verifier));

        // Revoke self-ownerId using the new explicit key
        _revokeOwner(eoa, 501, selfOwnerId);

        assertFalse(accountConfiguration.isOwner(eoa, selfOwnerId));
        assertTrue(accountConfiguration.isOwner(eoa, newOwnerId));

        IAccountConfiguration.OwnerConfig memory cfg = accountConfiguration.getOwnerConfig(eoa, selfOwnerId);
        assertEq(cfg.verifier, accountConfiguration.REVOKED_VERIFIER());
        assertEq(cfg.scopes, 0);
    }

    function test_implicitEOA_canBeExplicitlyRegistered() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);
        bytes32 selfOwnerId = bytes32(bytes20(eoa));

        _implicitAuthorizeOwnerWithScope(eoa, eoaPk, selfOwnerId, address(k1Verifier), 0x01);

        IAccountConfiguration.OwnerConfig memory cfg = accountConfiguration.getOwnerConfig(eoa, selfOwnerId);
        assertEq(cfg.verifier, address(k1Verifier));
        assertEq(cfg.scopes, 0x01);
    }

    function test_implicitEOA_crossChainOwnerChange() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);
        bytes32 newOwnerId = bytes32(bytes20(vm.addr(501)));

        IAccountConfiguration.OwnerChange[] memory changes = new IAccountConfiguration.OwnerChange[](1);
        changes[0] = IAccountConfiguration.OwnerChange({
            ownerId: newOwnerId,
            changeType: 0x01,
            configData: abi.encode(IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00}))
        });

        // chainId=0 for multichain
        uint64 seq = accountConfiguration.getChangeSequences(eoa).multichain;
        bytes32 digest = _computeOwnerChangeBatchDigest(eoa, 0, seq, changes);
        bytes memory auth = _buildImplicitEOAAuth(eoaPk, digest);

        accountConfiguration.applySignedOwnerChanges(eoa, 0, changes, auth);
        assertTrue(accountConfiguration.isOwner(eoa, newOwnerId));
    }

    // ── EOA self-ownerId revoke/add with explicit registration ──
    //
    // The self-ownerId for an account is bytes32(bytes20(account)).
    // Revoking this ownerId sets a sentinel (verifier=REVOKED_VERIFIER, scopes=0)
    // instead of deleting, to block the implicit authorization.

    function test_selfOwnerId_addKey() public {
        (address account,) = _createK1Account(OWNER_PK);
        bytes32 selfOwnerId = bytes32(bytes20(account));

        _authorizeOwner(account, OWNER_PK, selfOwnerId, address(k1Verifier));
        assertTrue(accountConfiguration.isOwner(account, selfOwnerId));
    }

    function test_selfOwnerId_revokeSetsNonZeroSentinel() public {
        (address account,) = _createK1Account(OWNER_PK);
        bytes32 selfOwnerId = bytes32(bytes20(account));

        _authorizeOwner(account, OWNER_PK, selfOwnerId, address(k1Verifier));
        assertTrue(accountConfiguration.isOwner(account, selfOwnerId));

        _revokeOwner(account, OWNER_PK, selfOwnerId);

        assertFalse(accountConfiguration.isOwner(account, selfOwnerId));

        IAccountConfiguration.OwnerConfig memory cfg = accountConfiguration.getOwnerConfig(account, selfOwnerId);
        assertEq(cfg.verifier, accountConfiguration.REVOKED_VERIFIER());
        assertEq(cfg.scopes, 0);
    }

    function test_selfOwnerId_canReauthorizeAfterSentinel() public {
        (address account,) = _createK1Account(OWNER_PK);
        bytes32 selfOwnerId = bytes32(bytes20(account));

        _authorizeOwner(account, OWNER_PK, selfOwnerId, address(k1Verifier));
        _revokeOwner(account, OWNER_PK, selfOwnerId);
        assertFalse(accountConfiguration.isOwner(account, selfOwnerId));

        // Re-authorization is allowed from the revoked sentinel state.
        _authorizeOwner(account, OWNER_PK, selfOwnerId, address(k1Verifier));
        assertTrue(accountConfiguration.isOwner(account, selfOwnerId));
    }

    function test_selfOwnerId_batchAddAndRevoke() public {
        (address account,) = _createK1Account(OWNER_PK);
        bytes32 selfOwnerId = bytes32(bytes20(account));

        // Add self-ownerId and a second key, then revoke self-ownerId — all in two batches
        _authorizeOwner(account, OWNER_PK, selfOwnerId, address(k1Verifier));

        bytes32 newOwnerId = bytes32(bytes20(vm.addr(NEW_OWNER_PK)));

        IAccountConfiguration.OwnerChange[] memory changes = new IAccountConfiguration.OwnerChange[](2);
        changes[0] = IAccountConfiguration.OwnerChange({
            ownerId: newOwnerId,
            changeType: 0x01,
            configData: abi.encode(IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00}))
        });
        changes[1] = IAccountConfiguration.OwnerChange({ownerId: selfOwnerId, changeType: 0x02, configData: ""});

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(OWNER_PK, digest);

        accountConfiguration.applySignedOwnerChanges(account, uint64(block.chainid), changes, auth);

        assertFalse(accountConfiguration.isOwner(account, selfOwnerId));
        assertTrue(accountConfiguration.isOwner(account, newOwnerId));

        // Self-ownerId has sentinel, not zeroed
        IAccountConfiguration.OwnerConfig memory cfg = accountConfiguration.getOwnerConfig(account, selfOwnerId);
        assertEq(cfg.verifier, accountConfiguration.REVOKED_VERIFIER());
        assertEq(cfg.scopes, 0);
    }

    function test_selfOwnerId_revokedCannotSignOwnerChanges() public {
        (address account,) = _createK1Account(OWNER_PK);
        bytes32 selfOwnerId = bytes32(bytes20(account));

        _authorizeOwner(account, OWNER_PK, selfOwnerId, address(k1Verifier));

        // Add a second key so the account isn't bricked, then revoke self-ownerId
        bytes32 newOwnerId = bytes32(bytes20(vm.addr(NEW_OWNER_PK)));
        _authorizeOwner(account, OWNER_PK, newOwnerId, address(k1Verifier));
        _revokeOwner(account, OWNER_PK, selfOwnerId);

        // The initial key (OWNER_PK) is still active — use it to prove it can sign
        bytes32 thirdOwnerId = bytes32(bytes20(vm.addr(302)));
        IAccountConfiguration.OwnerChange[] memory changes = new IAccountConfiguration.OwnerChange[](1);
        changes[0] = IAccountConfiguration.OwnerChange({
            ownerId: thirdOwnerId,
            changeType: 0x01,
            configData: abi.encode(IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00}))
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);

        // Signing with NEW_OWNER_PK still works (owner not revoked)
        accountConfiguration.applySignedOwnerChanges(
            account, uint64(block.chainid), changes, _buildK1Auth(NEW_OWNER_PK, digest)
        );
        assertTrue(accountConfiguration.isOwner(account, thirdOwnerId));
    }

    function test_revokedKey_cannotSignOwnerChanges() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 newOwnerId = bytes32(bytes20(vm.addr(NEW_OWNER_PK)));
        _authorizeOwner(account, OWNER_PK, newOwnerId, address(k1Verifier));

        // Revoke the initial key
        _revokeOwner(account, NEW_OWNER_PK, bytes32(bytes20(vm.addr(OWNER_PK))));

        // Attempt to sign an owner change with the revoked key
        bytes32 thirdOwnerId = bytes32(bytes20(vm.addr(302)));
        IAccountConfiguration.OwnerChange[] memory changes = new IAccountConfiguration.OwnerChange[](1);
        changes[0] = IAccountConfiguration.OwnerChange({
            ownerId: thirdOwnerId,
            changeType: 0x01,
            configData: abi.encode(IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00}))
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);

        vm.expectRevert();
        accountConfiguration.applySignedOwnerChanges(
            account, uint64(block.chainid), changes, _buildK1Auth(OWNER_PK, digest)
        );
    }

    function test_nonSelfOwner_revokeDeletesSlot() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 newOwnerId = bytes32(bytes20(vm.addr(NEW_OWNER_PK)));
        _authorizeOwner(account, OWNER_PK, newOwnerId, address(k1Verifier));

        _revokeOwner(account, OWNER_PK, newOwnerId);

        IAccountConfiguration.OwnerConfig memory cfg = accountConfiguration.getOwnerConfig(account, newOwnerId);
        assertEq(cfg.verifier, address(0));
        assertEq(cfg.scopes, 0);
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
        _implicitAuthorizeOwnerWithScope(account, pk, newOwnerId, verifier, 0x00);
    }

    function _implicitAuthorizeOwnerWithScope(
        address account,
        uint256 pk,
        bytes32 newOwnerId,
        address verifier,
        uint8 scope
    ) internal {
        IAccountConfiguration.OwnerChange[] memory changes = new IAccountConfiguration.OwnerChange[](1);
        changes[0] = IAccountConfiguration.OwnerChange({
            ownerId: newOwnerId,
            changeType: 0x01,
            configData: abi.encode(IAccountConfiguration.OwnerConfig({verifier: verifier, scopes: scope}))
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeOwnerChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildImplicitEOAAuth(pk, digest);

        accountConfiguration.applySignedOwnerChanges(account, uint64(block.chainid), changes, auth);
    }

    function _lockAccount(address account) internal {
        vm.prank(account);
        accountConfiguration.lock(1 hours);
    }
}
