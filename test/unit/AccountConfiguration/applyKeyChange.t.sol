// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {IAccountConfiguration} from "../../../src/interfaces/IAccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract ApplyConfigChangeActorTest is AccountConfigurationTest {
    uint256 constant ACTOR_PK = 200;
    uint256 constant NEW_ACTOR_PK = 201;

    function test_authorizeActor() public {
        (address account,) = _createK1Account(ACTOR_PK);

        address newSigner = vm.addr(NEW_ACTOR_PK);
        bytes32 newActorId = bytes32(bytes20(newSigner));

        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({
                    verifier: address(k1Verifier), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(ACTOR_PK, digest);

        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);

        IAccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(account, newActorId);
        assertTrue(cfg.verifier != address(0));
        assertEq(cfg.verifier, address(k1Verifier));
        assertEq(cfg.scope, 0x00);
    }

    function test_authorizeActor_withScope() public {
        (address account,) = _createK1Account(ACTOR_PK);

        address newSigner = vm.addr(NEW_ACTOR_PK);
        bytes32 newActorId = bytes32(bytes20(newSigner));

        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({
                    verifier: address(k1Verifier), scope: 0x04, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(ACTOR_PK, digest);

        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);

        IAccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(account, newActorId);
        assertEq(cfg.verifier, address(k1Verifier));
        assertEq(cfg.scope, 0x04);
    }

    function test_revokeActor() public {
        (address account,) = _createK1Account(ACTOR_PK);

        address newSigner = vm.addr(NEW_ACTOR_PK);
        bytes32 newActorId = bytes32(bytes20(newSigner));
        _authorizeActor(account, ACTOR_PK, newActorId, address(k1Verifier));

        assertTrue(accountConfiguration.isActor(account, newActorId));

        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({actorId: newActorId, changeType: 0x02, data: ""});

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(ACTOR_PK, digest);

        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);

        assertFalse(accountConfiguration.isActor(account, newActorId));
    }

    function test_multipleOperationsInSingleChange() public {
        (address account,) = _createK1Account(ACTOR_PK);

        bytes32 actor1 = bytes32(bytes20(vm.addr(300)));
        bytes32 actor2 = bytes32(bytes20(vm.addr(301)));

        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](2);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: actor1,
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({
                    verifier: address(k1Verifier), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });
        changes[1] = IAccountConfiguration.ActorChange({
            actorId: actor2,
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({
                    verifier: address(k1Verifier), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(ACTOR_PK, digest);

        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);

        assertTrue(accountConfiguration.isActor(account, actor1));
        assertTrue(accountConfiguration.isActor(account, actor2));
    }

    function test_sequenceIncrements() public {
        (address account,) = _createK1Account(ACTOR_PK);

        // createAccount initializes localSequence to 1 (the initialized flag), so the local channel starts at 1.
        assertEq(accountConfiguration.getChangeSequences(account).local, 1);

        _authorizeActor(account, ACTOR_PK, bytes32(bytes20(vm.addr(300))), address(k1Verifier));
        assertEq(accountConfiguration.getChangeSequences(account).local, 2);

        _authorizeActor(account, ACTOR_PK, bytes32(bytes20(vm.addr(301))), address(k1Verifier));
        assertEq(accountConfiguration.getChangeSequences(account).local, 3);
    }

    function test_revertsWhenLocked() public {
        (address account,) = _createK1Account(ACTOR_PK);

        _lockAccount(account);

        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: bytes32(bytes20(vm.addr(300))),
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({
                    verifier: address(k1Verifier), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(ACTOR_PK, digest);

        vm.expectRevert();
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
    }

    function test_anyActorCanAuthorize() public {
        (address account,) = _createK1Account(ACTOR_PK);

        bytes32 secondActorId = bytes32(bytes20(vm.addr(NEW_ACTOR_PK)));
        _authorizeActor(account, ACTOR_PK, secondActorId, address(k1Verifier));

        bytes32 thirdActorId = bytes32(bytes20(vm.addr(302)));
        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: thirdActorId,
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({
                    verifier: address(k1Verifier), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(NEW_ACTOR_PK, digest);

        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
        assertTrue(accountConfiguration.isActor(account, thirdActorId));
    }

    function test_scopedActor_cannotAuthorizeWithoutConfigScope() public {
        (address account,) = _createK1Account(ACTOR_PK);

        address newSigner = vm.addr(NEW_ACTOR_PK);
        bytes32 secondActorId = bytes32(bytes20(newSigner));
        _authorizeActorWithScope(account, ACTOR_PK, secondActorId, address(k1Verifier), 0x02);

        bytes32 thirdActorId = bytes32(bytes20(vm.addr(302)));
        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: thirdActorId,
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({
                    verifier: address(k1Verifier), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(NEW_ACTOR_PK, digest);

        vm.expectRevert();
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
    }

    function test_scopedActor_canAuthorizeWithConfigScope() public {
        (address account,) = _createK1Account(ACTOR_PK);

        address newSigner = vm.addr(NEW_ACTOR_PK);
        bytes32 secondActorId = bytes32(bytes20(newSigner));
        _authorizeActorWithScope(
            account, ACTOR_PK, secondActorId, address(k1Verifier), accountConfiguration.SCOPE_CHANGE_ACTORS()
        );

        bytes32 thirdActorId = bytes32(bytes20(vm.addr(302)));
        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: thirdActorId,
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({
                    verifier: address(k1Verifier), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(NEW_ACTOR_PK, digest);

        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
        assertTrue(accountConfiguration.isActor(account, thirdActorId));
    }

    function test_revertsOnDuplicateActorAuthorization() public {
        (address account, bytes32 actorActorId) = _createK1Account(ACTOR_PK);

        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: actorActorId,
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({
                    verifier: address(k1Verifier), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(ACTOR_PK, digest);

        vm.expectRevert();
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
    }

    function test_revertsOnRevokingNonExistentActor() public {
        (address account,) = _createK1Account(ACTOR_PK);

        bytes32 nonExistentActorId = bytes32(bytes20(vm.addr(999)));

        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({actorId: nonExistentActorId, changeType: 0x02, data: ""});

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(ACTOR_PK, digest);

        vm.expectRevert();
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
    }

    function test_revertsWithInvalidSignature() public {
        (address account,) = _createK1Account(ACTOR_PK);

        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: bytes32(bytes20(vm.addr(300))),
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({
                    verifier: address(k1Verifier), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);

        bytes memory badAuth = _buildK1Auth(999, digest);

        vm.expectRevert();
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, badAuth);
    }

    // ── Implicit EOA (registered by default) ──
    //
    // Every account has an implicit self-actorId bytes32(bytes20(account))
    // that is authorized with unrestricted scope when the config slot
    // is empty. No createAccount/importAccount needed.

    function test_implicitEOA_canSignActorChanges() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);
        bytes32 newActorId = bytes32(bytes20(vm.addr(501)));

        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({
                    verifier: address(k1Verifier), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(eoa).local;
        bytes32 digest = _computeActorChangeBatchDigest(eoa, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildImplicitEOAAuth(eoaPk, digest);

        accountConfiguration.applySignedActorChanges(eoa, uint64(block.chainid), changes, auth);
        assertTrue(accountConfiguration.isActor(eoa, newActorId));
    }

    function test_implicitEOA_canRevokeItselfViaSentinel() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        assertTrue(accountConfiguration.isActor(eoa, selfActorId));

        // Add a second key first using implicit EOA auth
        bytes32 newActorId = bytes32(bytes20(vm.addr(501)));
        _implicitAuthorizeActor(eoa, eoaPk, newActorId, address(k1Verifier));

        // Revoke self-actorId using the new explicit key
        _revokeActor(eoa, 501, selfActorId);

        assertFalse(accountConfiguration.isActor(eoa, selfActorId));
        assertTrue(accountConfiguration.isActor(eoa, newActorId));

        IAccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(eoa, selfActorId);
        assertEq(cfg.verifier, accountConfiguration.REVOKED_VERIFIER());
        assertEq(cfg.scope, 0);
    }

    function test_implicitEOA_canBeExplicitlyRegistered() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        _implicitAuthorizeActorWithScope(eoa, eoaPk, selfActorId, address(k1Verifier), 0x01);

        IAccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(eoa, selfActorId);
        assertEq(cfg.verifier, address(k1Verifier));
        assertEq(cfg.scope, 0x01);
    }

    function test_implicitEOA_crossChainActorChange() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);
        bytes32 newActorId = bytes32(bytes20(vm.addr(501)));

        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({
                    verifier: address(k1Verifier), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        // chainId=0 for multichain
        uint64 seq = accountConfiguration.getChangeSequences(eoa).multichain;
        bytes32 digest = _computeActorChangeBatchDigest(eoa, 0, seq, changes);
        bytes memory auth = _buildImplicitEOAAuth(eoaPk, digest);

        accountConfiguration.applySignedActorChanges(eoa, 0, changes, auth);
        assertTrue(accountConfiguration.isActor(eoa, newActorId));
    }

    // ── EOA self-actorId revoke/add with explicit registration ──
    //
    // The self-actorId for an account is bytes32(bytes20(account)).
    // Revoking this actorId sets a sentinel (verifier=REVOKED_VERIFIER, scope=0)
    // instead of deleting, to block the implicit authorization.

    function test_selfActorId_addKey() public {
        (address account,) = _createK1Account(ACTOR_PK);
        bytes32 selfActorId = bytes32(bytes20(account));

        _authorizeActor(account, ACTOR_PK, selfActorId, address(k1Verifier));
        assertTrue(accountConfiguration.isActor(account, selfActorId));
    }

    function test_selfActorId_revokeSetsNonZeroSentinel() public {
        (address account,) = _createK1Account(ACTOR_PK);
        bytes32 selfActorId = bytes32(bytes20(account));

        _authorizeActor(account, ACTOR_PK, selfActorId, address(k1Verifier));
        assertTrue(accountConfiguration.isActor(account, selfActorId));

        _revokeActor(account, ACTOR_PK, selfActorId);

        assertFalse(accountConfiguration.isActor(account, selfActorId));

        IAccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(account, selfActorId);
        assertEq(cfg.verifier, accountConfiguration.REVOKED_VERIFIER());
        assertEq(cfg.scope, 0);
    }

    function test_selfActorId_canReauthorizeAfterSentinel() public {
        (address account,) = _createK1Account(ACTOR_PK);
        bytes32 selfActorId = bytes32(bytes20(account));

        _authorizeActor(account, ACTOR_PK, selfActorId, address(k1Verifier));
        _revokeActor(account, ACTOR_PK, selfActorId);
        assertFalse(accountConfiguration.isActor(account, selfActorId));

        // Re-authorization is allowed from the revoked sentinel state.
        _authorizeActor(account, ACTOR_PK, selfActorId, address(k1Verifier));
        assertTrue(accountConfiguration.isActor(account, selfActorId));
    }

    function test_selfActorId_batchAddAndRevoke() public {
        (address account,) = _createK1Account(ACTOR_PK);
        bytes32 selfActorId = bytes32(bytes20(account));

        // Add self-actorId and a second key, then revoke self-actorId — all in two batches
        _authorizeActor(account, ACTOR_PK, selfActorId, address(k1Verifier));

        bytes32 newActorId = bytes32(bytes20(vm.addr(NEW_ACTOR_PK)));

        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](2);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({
                    verifier: address(k1Verifier), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });
        changes[1] = IAccountConfiguration.ActorChange({actorId: selfActorId, changeType: 0x02, data: ""});

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(ACTOR_PK, digest);

        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);

        assertFalse(accountConfiguration.isActor(account, selfActorId));
        assertTrue(accountConfiguration.isActor(account, newActorId));

        // Self-actorId has sentinel, not zeroed
        IAccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(account, selfActorId);
        assertEq(cfg.verifier, accountConfiguration.REVOKED_VERIFIER());
        assertEq(cfg.scope, 0);
    }

    function test_selfActorId_revokedCannotSignActorChanges() public {
        (address account,) = _createK1Account(ACTOR_PK);
        bytes32 selfActorId = bytes32(bytes20(account));

        _authorizeActor(account, ACTOR_PK, selfActorId, address(k1Verifier));

        // Add a second key so the account isn't bricked, then revoke self-actorId
        bytes32 newActorId = bytes32(bytes20(vm.addr(NEW_ACTOR_PK)));
        _authorizeActor(account, ACTOR_PK, newActorId, address(k1Verifier));
        _revokeActor(account, ACTOR_PK, selfActorId);

        // The initial key (ACTOR_PK) is still active — use it to prove it can sign
        bytes32 thirdActorId = bytes32(bytes20(vm.addr(302)));
        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: thirdActorId,
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({
                    verifier: address(k1Verifier), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);

        // Signing with NEW_ACTOR_PK still works (actor not revoked)
        accountConfiguration.applySignedActorChanges(
            account, uint64(block.chainid), changes, _buildK1Auth(NEW_ACTOR_PK, digest)
        );
        assertTrue(accountConfiguration.isActor(account, thirdActorId));
    }

    function test_revokedKey_cannotSignActorChanges() public {
        (address account,) = _createK1Account(ACTOR_PK);

        bytes32 newActorId = bytes32(bytes20(vm.addr(NEW_ACTOR_PK)));
        _authorizeActor(account, ACTOR_PK, newActorId, address(k1Verifier));

        // Revoke the initial key
        _revokeActor(account, NEW_ACTOR_PK, bytes32(bytes20(vm.addr(ACTOR_PK))));

        // Attempt to sign an actor change with the revoked key
        bytes32 thirdActorId = bytes32(bytes20(vm.addr(302)));
        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: thirdActorId,
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({
                    verifier: address(k1Verifier), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);

        vm.expectRevert();
        accountConfiguration.applySignedActorChanges(
            account, uint64(block.chainid), changes, _buildK1Auth(ACTOR_PK, digest)
        );
    }

    function test_nonSelfActor_revokeDeletesSlot() public {
        (address account,) = _createK1Account(ACTOR_PK);

        bytes32 newActorId = bytes32(bytes20(vm.addr(NEW_ACTOR_PK)));
        _authorizeActor(account, ACTOR_PK, newActorId, address(k1Verifier));

        _revokeActor(account, ACTOR_PK, newActorId);

        IAccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(account, newActorId);
        assertEq(cfg.verifier, address(0));
        assertEq(cfg.scope, 0);
    }

    // ── Helpers ──

    function _authorizeActor(address account, uint256 pk, bytes32 newActorId, address verifier) internal {
        _authorizeActorWithScope(account, pk, newActorId, verifier, 0x00);
    }

    function _authorizeActorWithScope(address account, uint256 pk, bytes32 newActorId, address verifier, uint8 scope)
        internal
    {
        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({verifier: verifier, scope: scope, expiry: 0, policyType: 0x00}),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(pk, digest);

        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
    }

    function _revokeActor(address account, uint256 pk, bytes32 actorId) internal {
        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({actorId: actorId, changeType: 0x02, data: ""});

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(pk, digest);

        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
    }

    function _implicitAuthorizeActor(address account, uint256 pk, bytes32 newActorId, address verifier) internal {
        _implicitAuthorizeActorWithScope(account, pk, newActorId, verifier, 0x00);
    }

    function _implicitAuthorizeActorWithScope(
        address account,
        uint256 pk,
        bytes32 newActorId,
        address verifier,
        uint8 scope
    ) internal {
        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({verifier: verifier, scope: scope, expiry: 0, policyType: 0x00}),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildImplicitEOAAuth(pk, digest);

        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
    }

    function _lockAccount(address account) internal {
        vm.prank(account);
        accountConfiguration.lock(1 hours);
    }
}
