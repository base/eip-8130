// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract ApplyConfigChangeActorTest is AccountConfigurationTest {
    uint256 constant ACTOR_PK = 200;
    uint256 constant NEW_ACTOR_PK = 201;

    function test_authorizeActor() public {
        (address account,) = _createK1Account(ACTOR_PK);

        address newSigner = vm.addr(NEW_ACTOR_PK);
        bytes32 newActorId = bytes32(bytes20(newSigner));

        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: address(k1Authenticator), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(ACTOR_PK, digest);

        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);

        AccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(account, newActorId);
        assertTrue(cfg.authenticator != address(0));
        assertEq(cfg.authenticator, address(k1Authenticator));
        assertEq(cfg.scope, 0x00);
    }

    function test_authorizeActor_withScope() public {
        (address account,) = _createK1Account(ACTOR_PK);

        address newSigner = vm.addr(NEW_ACTOR_PK);
        bytes32 newActorId = bytes32(bytes20(newSigner));

        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: address(k1Authenticator), scope: 0x04, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(ACTOR_PK, digest);

        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);

        AccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(account, newActorId);
        assertEq(cfg.authenticator, address(k1Authenticator));
        assertEq(cfg.scope, 0x04);
    }

    function test_revokeActor() public {
        (address account,) = _createK1Account(ACTOR_PK);

        address newSigner = vm.addr(NEW_ACTOR_PK);
        bytes32 newActorId = bytes32(bytes20(newSigner));
        _authorizeActor(account, ACTOR_PK, newActorId, address(k1Authenticator));

        assertTrue(accountConfiguration.isActor(account, newActorId));

        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({actorId: newActorId, changeType: 0x02, data: ""});

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

        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](2);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: actor1,
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: address(k1Authenticator), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });
        changes[1] = AccountConfiguration.ActorChange({
            actorId: actor2,
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: address(k1Authenticator), scope: 0x00, expiry: 0, policyType: 0x00
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

        _authorizeActor(account, ACTOR_PK, bytes32(bytes20(vm.addr(300))), address(k1Authenticator));
        assertEq(accountConfiguration.getChangeSequences(account).local, 2);

        _authorizeActor(account, ACTOR_PK, bytes32(bytes20(vm.addr(301))), address(k1Authenticator));
        assertEq(accountConfiguration.getChangeSequences(account).local, 3);
    }

    function test_revertsWhenLocked() public {
        (address account,) = _createK1Account(ACTOR_PK);

        _lockAccount(account);

        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: bytes32(bytes20(vm.addr(300))),
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: address(k1Authenticator), scope: 0x00, expiry: 0, policyType: 0x00
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
        _authorizeActor(account, ACTOR_PK, secondActorId, address(k1Authenticator));

        bytes32 thirdActorId = bytes32(bytes20(vm.addr(302)));
        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: thirdActorId,
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: address(k1Authenticator), scope: 0x00, expiry: 0, policyType: 0x00
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
        _authorizeActorWithScope(account, ACTOR_PK, secondActorId, address(k1Authenticator), 0x02);

        bytes32 thirdActorId = bytes32(bytes20(vm.addr(302)));
        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: thirdActorId,
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: address(k1Authenticator), scope: 0x00, expiry: 0, policyType: 0x00
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
            account, ACTOR_PK, secondActorId, address(k1Authenticator), accountConfiguration.SCOPE_CONFIG()
        );

        bytes32 thirdActorId = bytes32(bytes20(vm.addr(302)));
        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: thirdActorId,
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: address(k1Authenticator), scope: 0x00, expiry: 0, policyType: 0x00
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

    function test_reauthorizeNonSelfActor_upsertsInPlace() public {
        // authorizeActor is an upsert: re-authorizing an already-configured (non-self) actor overwrites its config
        // in place rather than reverting. Here the owner actor is re-scoped from unrestricted (0x00) to CONFIG.
        (address account, bytes32 actorActorId) = _createK1Account(ACTOR_PK);

        uint8 newScope = accountConfiguration.SCOPE_CONFIG();
        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: actorActorId,
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: address(k1Authenticator), scope: newScope, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(ACTOR_PK, digest);

        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);

        AccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(account, actorActorId);
        assertEq(cfg.scope, newScope);
        assertEq(cfg.authenticator, address(k1Authenticator));
    }

    function test_reauthorizeLiveK1Self_rescopesWithoutPriorRevoke() public {
        // Re-authorizing the inline k1 self is now an in-place upsert — no prior revoke required, even when the self
        // is live with a non-trivial scope. (Previously this reverted unless the self was revoked or all-zero.)
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        // First: the implicit owner (all-zero inline, live) scopes the self to CONFIG so it can keep signing.
        uint8 configScope = accountConfiguration.SCOPE_CONFIG();
        _rescopeSelf(eoa, eoaPk, configScope);
        assertEq(accountConfiguration.getActorConfig(eoa, selfActorId).scope, configScope);

        // Second: re-scope the now-live, non-trivially-scoped self again (no revoke in between).
        uint8 newScope = configScope | 0x02; // CONFIG | SENDER
        _rescopeSelf(eoa, eoaPk, newScope);

        AccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(eoa, selfActorId);
        assertEq(cfg.scope, newScope);
        assertEq(cfg.authenticator, accountConfiguration.K1_AUTHENTICATOR());
        assertTrue(accountConfiguration.isActor(eoa, selfActorId));
    }

    function test_revertsOnRevokingNonExistentActor() public {
        (address account,) = _createK1Account(ACTOR_PK);

        bytes32 nonExistentActorId = bytes32(bytes20(vm.addr(999)));

        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({actorId: nonExistentActorId, changeType: 0x02, data: ""});

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(ACTOR_PK, digest);

        vm.expectRevert();
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
    }

    function test_revertsWithInvalidSignature() public {
        (address account,) = _createK1Account(ACTOR_PK);

        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: bytes32(bytes20(vm.addr(300))),
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: address(k1Authenticator), scope: 0x00, expiry: 0, policyType: 0x00
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

        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: address(k1Authenticator), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(eoa).local;
        bytes32 digest = _computeActorChangeBatchDigest(eoa, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(eoaPk, digest);

        accountConfiguration.applySignedActorChanges(eoa, uint64(block.chainid), changes, auth);
        assertTrue(accountConfiguration.isActor(eoa, newActorId));
    }

    function test_implicitEOA_canRevokeItselfViaFlag() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        assertTrue(accountConfiguration.isActor(eoa, selfActorId));

        // Add a second key first using implicit EOA auth
        bytes32 newActorId = bytes32(bytes20(vm.addr(501)));
        _implicitAuthorizeActor(eoa, eoaPk, newActorId, address(k1Authenticator));

        // Revoke self-actorId using the new explicit key (sets the default-EOA revoke flag)
        _revokeActor(eoa, 501, selfActorId);

        assertFalse(accountConfiguration.isActor(eoa, selfActorId));
        assertTrue(accountConfiguration.isActor(eoa, newActorId));

        // A revoked default EOA reports as an all-zero (empty) config — no sentinel.
        AccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(eoa, selfActorId);
        assertEq(cfg.authenticator, address(0));
        assertEq(cfg.scope, 0);
    }

    function test_implicitEOA_liveReportsAsEcrecoverOwner() public view {
        // A live default EOA (no createAccount, flag unset) synthesizes a native ecrecover owner config.
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        AccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(eoa, selfActorId);
        assertEq(cfg.authenticator, accountConfiguration.K1_AUTHENTICATOR());
        assertEq(cfg.scope, 0);
    }

    function test_selfActorId_canScopeViaK1() public {
        // The account's own key can be downgraded to a scoped actor by authorizing the self-actorId as a K1 actor.
        // With a single k1 path the config alone decides the scope, so there is no implicit full-owner escape.
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));
        assertTrue(accountConfiguration.isActor(eoa, selfActorId));

        _implicitAuthorizeActorWithScope(eoa, eoaPk, selfActorId, address(k1Authenticator), 0x02);

        assertTrue(accountConfiguration.isActor(eoa, selfActorId));
        AccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(eoa, selfActorId);
        assertEq(cfg.authenticator, address(k1Authenticator));
        assertEq(cfg.scope, 0x02);

        // The same key now authenticates with its downgraded scope (0x02), never full owner (0x00).
        bytes32 hash = keccak256("scoped self");
        (uint8 scope,,) = accountConfiguration.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));
        assertEq(scope, 0x02);
    }

    function test_selfActorId_doubleAuthorizeReverts() public {
        // Once the self-actorId has an explicit entry it cannot be re-authorized without revoking first.
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        _implicitAuthorizeActorWithScope(eoa, eoaPk, selfActorId, address(k1Authenticator), 0x02);

        // Second authorize for the same actorId reverts (existing entry). Signed by the now-scoped self key.
        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: selfActorId,
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: accountConfiguration.K1_AUTHENTICATOR(), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });
        uint64 seq = accountConfiguration.getChangeSequences(eoa).local;
        bytes32 digest = _computeActorChangeBatchDigest(eoa, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(eoaPk, digest);

        vm.expectRevert();
        accountConfiguration.applySignedActorChanges(eoa, uint64(block.chainid), changes, auth);
    }

    function test_implicitEOA_crossChainActorChange() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);
        bytes32 newActorId = bytes32(bytes20(vm.addr(501)));

        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: address(k1Authenticator), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        // chainId=0 for multichain
        uint64 seq = accountConfiguration.getChangeSequences(eoa).multichain;
        bytes32 digest = _computeActorChangeBatchDigest(eoa, 0, seq, changes);
        bytes memory auth = _buildK1Auth(eoaPk, digest);

        accountConfiguration.applySignedActorChanges(eoa, 0, changes, auth);
        assertTrue(accountConfiguration.isActor(eoa, newActorId));
    }

    // ── Default EOA self-actorId semantics ──
    //
    // The self-actorId for an account is bytes32(bytes20(account)). Without an explicit entry it is the implicit
    // default EOA (full owner), gated by the AccountState flag. It may also be configured as an explicit actor like
    // any other (e.g. to scope the account's own key), which sets the flag and disables the implicit address(0)
    // path. The flag is never cleared, so a managed self-actorId is operated through its explicit entry/prefix.
    // createAccount and importAccount disable the implicit default EOA by default.

    function test_selfActorId_revokedByDefaultOnCreate() public {
        (address account,) = _createK1Account(ACTOR_PK);
        bytes32 selfActorId = bytes32(bytes20(account));

        // createAccount disables the default EOA, so the self-actorId is not a live actor.
        assertFalse(accountConfiguration.isActor(account, selfActorId));

        AccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(account, selfActorId);
        assertEq(cfg.authenticator, address(0));
        assertEq(cfg.scope, 0);
    }

    function test_selfActorId_reEnableOnCreatedAccount() public {
        (address account,) = _createK1Account(ACTOR_PK);
        bytes32 selfActorId = bytes32(bytes20(account));
        assertFalse(accountConfiguration.isActor(account, selfActorId));

        // An owner re-enables the default EOA by authorizing the self-actorId with the canonical owner shape.
        _authorizeActor(account, ACTOR_PK, selfActorId, accountConfiguration.K1_AUTHENTICATOR());

        assertTrue(accountConfiguration.isActor(account, selfActorId));
        AccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(account, selfActorId);
        assertEq(cfg.authenticator, accountConfiguration.K1_AUTHENTICATOR());
        assertEq(cfg.scope, 0);
    }

    function test_selfActorId_revokeThenReEnable() public {
        // An EOA account (not created) starts with a live default EOA.
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));
        assertTrue(accountConfiguration.isActor(eoa, selfActorId));

        // Add a second key, then revoke the default EOA via the flag.
        bytes32 newActorId = bytes32(bytes20(vm.addr(501)));
        _implicitAuthorizeActor(eoa, eoaPk, newActorId, address(k1Authenticator));
        _revokeActor(eoa, 501, selfActorId);
        assertFalse(accountConfiguration.isActor(eoa, selfActorId));

        // The default EOA can no longer authenticate while revoked: its own k1 sig finds no config and the flag
        // disables the implicit full-owner fallback.
        bytes32 hash = keccak256("while revoked");
        vm.expectRevert();
        accountConfiguration.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));

        // Re-enable by authorizing the self-actorId as a native k1 owner using the second key.
        _authorizeActor(eoa, 501, selfActorId, accountConfiguration.K1_AUTHENTICATOR());
        assertTrue(accountConfiguration.isActor(eoa, selfActorId));

        // The own key is a full owner again — now resolved through its explicit self config (the flag stays set, so
        // it is the config, not the implicit fallback, that authorizes it).
        (uint8 scope,,) = accountConfiguration.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));
        assertEq(scope, 0);
    }

    function test_e2e_eoaToPasskeyThenReEnableK1() public {
        // Full lifecycle: use the default EOA, hand the account to a "passkey", then re-enable the K1 key.
        //
        // The new owner is registered through an authenticator (K1 here as a stand-in for a passkey/P256 device
        // key); the revoke-self + re-enable-self mechanics are authenticator-agnostic, so a real passkey owner
        // behaves identically — only changes[0].data.authenticator differs.
        uint256 eoaPk = 500; // the account's own K1 key (the default EOA)
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        uint256 devicePk = 600; // the "passkey" device key
        bytes32 deviceActorId = bytes32(bytes20(vm.addr(devicePk)));

        // ── Phase 0: the default EOA is live and authenticates with its own k1 signature (implicit full owner). ──
        assertTrue(accountConfiguration.isActor(eoa, selfActorId));
        bytes32 h0 = keccak256("phase 0");
        (uint8 scope0,,) = accountConfiguration.authenticateActor(eoa, h0, _buildK1Auth(eoaPk, h0));
        assertEq(scope0, 0);

        // ── Phase 1: in one batch signed by the EOA, add the passkey as a full owner and revoke the default EOA. ──
        AccountConfiguration.ActorChange[] memory switchChanges = new AccountConfiguration.ActorChange[](2);
        switchChanges[0] = AccountConfiguration.ActorChange({
            actorId: deviceActorId,
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: address(k1Authenticator), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });
        switchChanges[1] = AccountConfiguration.ActorChange({actorId: selfActorId, changeType: 0x02, data: ""});

        uint64 seq1 = accountConfiguration.getChangeSequences(eoa).local;
        bytes32 d1 = _computeActorChangeBatchDigest(eoa, uint64(block.chainid), seq1, switchChanges);
        accountConfiguration.applySignedActorChanges(eoa, uint64(block.chainid), switchChanges, _buildK1Auth(eoaPk, d1));

        // The EOA is now disabled; the passkey is the live owner.
        assertFalse(accountConfiguration.isActor(eoa, selfActorId));
        assertTrue(accountConfiguration.isActor(eoa, deviceActorId));

        bytes32 h1 = keccak256("phase 1");
        vm.expectRevert();
        accountConfiguration.authenticateActor(eoa, h1, _buildK1Auth(eoaPk, h1));
        (uint8 scope1,,) = accountConfiguration.authenticateActor(eoa, h1, _buildK1Auth(devicePk, h1));
        assertEq(scope1, 0);

        // ── Phase 2: the passkey re-enables the K1 key by authorizing the self-actorId as a native k1 owner. ──
        AccountConfiguration.ActorChange[] memory reEnable = new AccountConfiguration.ActorChange[](1);
        reEnable[0] = AccountConfiguration.ActorChange({
            actorId: selfActorId,
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: accountConfiguration.K1_AUTHENTICATOR(), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        uint64 seq2 = accountConfiguration.getChangeSequences(eoa).local;
        bytes32 d2 = _computeActorChangeBatchDigest(eoa, uint64(block.chainid), seq2, reEnable);
        accountConfiguration.applySignedActorChanges(eoa, uint64(block.chainid), reEnable, _buildK1Auth(devicePk, d2));

        // The K1 key is a full owner again — now resolved through its explicit self config rather than the
        // implicit fallback (the flag is never cleared), so the same k1 signature authenticates.
        assertTrue(accountConfiguration.isActor(eoa, selfActorId));
        bytes32 h2 = keccak256("phase 2");
        (uint8 scope2,,) = accountConfiguration.authenticateActor(eoa, h2, _buildK1Auth(eoaPk, h2));
        assertEq(scope2, 0);
    }

    function test_selfActorId_batchRevokeViaFlag() public {
        // EOA account: add a key and revoke the default EOA in a single batch signed by the default EOA.
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        bytes32 newActorId = bytes32(bytes20(vm.addr(NEW_ACTOR_PK)));

        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](2);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: address(k1Authenticator), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });
        changes[1] = AccountConfiguration.ActorChange({actorId: selfActorId, changeType: 0x02, data: ""});

        uint64 seq = accountConfiguration.getChangeSequences(eoa).local;
        bytes32 digest = _computeActorChangeBatchDigest(eoa, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(eoaPk, digest);

        accountConfiguration.applySignedActorChanges(eoa, uint64(block.chainid), changes, auth);

        assertFalse(accountConfiguration.isActor(eoa, selfActorId));
        assertTrue(accountConfiguration.isActor(eoa, newActorId));

        // A revoked default EOA reports as an all-zero (empty) config — no sentinel.
        AccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(eoa, selfActorId);
        assertEq(cfg.authenticator, address(0));
        assertEq(cfg.scope, 0);
    }

    function test_selfActorId_revokedCannotSignActorChanges() public {
        // EOA account: default EOA adds a second key, then revokes itself.
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        bytes32 newActorId = bytes32(bytes20(vm.addr(NEW_ACTOR_PK)));
        _implicitAuthorizeActor(eoa, eoaPk, newActorId, address(k1Authenticator));
        _revokeActor(eoa, NEW_ACTOR_PK, selfActorId);

        bytes32 thirdActorId = bytes32(bytes20(vm.addr(302)));
        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: thirdActorId,
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: address(k1Authenticator), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(eoa).local;
        bytes32 digest = _computeActorChangeBatchDigest(eoa, uint64(block.chainid), seq, changes);

        // The revoked default EOA can no longer authenticate.
        vm.expectRevert();
        accountConfiguration.applySignedActorChanges(eoa, uint64(block.chainid), changes, _buildK1Auth(eoaPk, digest));

        // But the still-active second key can sign.
        accountConfiguration.applySignedActorChanges(
            eoa, uint64(block.chainid), changes, _buildK1Auth(NEW_ACTOR_PK, digest)
        );
        assertTrue(accountConfiguration.isActor(eoa, thirdActorId));
    }

    function test_revokedKey_cannotSignActorChanges() public {
        (address account,) = _createK1Account(ACTOR_PK);

        bytes32 newActorId = bytes32(bytes20(vm.addr(NEW_ACTOR_PK)));
        _authorizeActor(account, ACTOR_PK, newActorId, address(k1Authenticator));

        // Revoke the initial key
        _revokeActor(account, NEW_ACTOR_PK, bytes32(bytes20(vm.addr(ACTOR_PK))));

        // Attempt to sign an actor change with the revoked key
        bytes32 thirdActorId = bytes32(bytes20(vm.addr(302)));
        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: thirdActorId,
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: address(k1Authenticator), scope: 0x00, expiry: 0, policyType: 0x00
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
        _authorizeActor(account, ACTOR_PK, newActorId, address(k1Authenticator));

        _revokeActor(account, ACTOR_PK, newActorId);

        AccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(account, newActorId);
        assertEq(cfg.authenticator, address(0));
        assertEq(cfg.scope, 0);
    }

    // ── Helpers ──

    /// @dev Authorize/overwrite the EOA's own inline k1 self-actorId with the given scope, signed by the EOA key.
    function _rescopeSelf(address eoa, uint256 eoaPk, uint8 scope) internal {
        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: bytes32(bytes20(eoa)),
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: accountConfiguration.K1_AUTHENTICATOR(), scope: scope, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });
        uint64 seq = accountConfiguration.getChangeSequences(eoa).local;
        bytes32 digest = _computeActorChangeBatchDigest(eoa, uint64(block.chainid), seq, changes);
        accountConfiguration.applySignedActorChanges(eoa, uint64(block.chainid), changes, _buildK1Auth(eoaPk, digest));
    }

    function _authorizeActor(address account, uint256 pk, bytes32 newActorId, address authenticator) internal {
        _authorizeActorWithScope(account, pk, newActorId, authenticator, 0x00);
    }

    function _authorizeActorWithScope(
        address account,
        uint256 pk,
        bytes32 newActorId,
        address authenticator,
        uint8 scope
    ) internal {
        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: authenticator, scope: scope, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(pk, digest);

        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
    }

    function _revokeActor(address account, uint256 pk, bytes32 actorId) internal {
        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({actorId: actorId, changeType: 0x02, data: ""});

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(pk, digest);

        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
    }

    function _implicitAuthorizeActor(address account, uint256 pk, bytes32 newActorId, address authenticator) internal {
        _implicitAuthorizeActorWithScope(account, pk, newActorId, authenticator, 0x00);
    }

    function _implicitAuthorizeActorWithScope(
        address account,
        uint256 pk,
        bytes32 newActorId,
        address authenticator,
        uint8 scope
    ) internal {
        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: authenticator, scope: scope, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(pk, digest);

        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
    }

    function _lockAccount(address account) internal {
        vm.prank(account);
        accountConfiguration.lock(1 hours);
    }
}
