// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract ApplyConfigChangeActorTest is AccountConfigurationTest {
    /// @notice Authorizing a non-self actor registers it with the given authenticator and unrestricted scope.
    function test_authorizeActor_success_unrestricted(uint256 pk, bytes32 actorId) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        AccountConfiguration.ActorChange[] memory ch = _authorizeChange(actorId, address(k1Authenticator), 0, 0, "");
        _signApply(account, pk, ch);

        AccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(account, actorId);
        assertEq(cfg.authenticator, address(k1Authenticator));
        assertEq(cfg.scope, 0x00);
    }

    /// @notice Authorizing an actor stores the requested non-zero scope verbatim.
    function test_authorizeActor_success_withScope(uint256 pk, bytes32 actorId, uint8 scope) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));
        scope = uint8(bound(uint256(scope), 1, 255));

        AccountConfiguration.ActorChange[] memory ch = _authorizeChange(actorId, address(k1Authenticator), scope, 0, "");
        _signApply(account, pk, ch);

        AccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(account, actorId);
        assertEq(cfg.authenticator, address(k1Authenticator));
        assertEq(cfg.scope, scope);
    }

    /// @notice Revoking a live non-self actor removes it from the account.
    function test_revokeActor_success_removesActor(uint256 pk, bytes32 actorId) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));
        _authorizeActor(account, pk, actorId, address(k1Authenticator));
        assertTrue(accountConfiguration.isActor(account, actorId));

        AccountConfiguration.ActorChange[] memory ch = new AccountConfiguration.ActorChange[](1);
        ch[0] = AccountConfiguration.ActorChange({actorId: actorId, changeType: 0x02, data: ""});
        _signApply(account, pk, ch);

        assertFalse(accountConfiguration.isActor(account, actorId));
    }

    /// @notice A batch of multiple authorize operations applies every element.
    function test_applySignedActorChanges_success_multipleOperations(uint256 pk, bytes32 idA, bytes32 idB) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(idA != ownerId && idA != bytes32(bytes20(account)));
        vm.assume(idB != ownerId && idB != bytes32(bytes20(account)));
        vm.assume(idA != idB);

        AccountConfiguration.ActorChange[] memory ch = new AccountConfiguration.ActorChange[](2);
        ch[0] = _authorizeChange(idA, address(k1Authenticator), 0, 0, "")[0];
        ch[1] = _authorizeChange(idB, address(k1Authenticator), 0, 0, "")[0];
        _signApply(account, pk, ch);

        assertTrue(accountConfiguration.isActor(account, idA));
        assertTrue(accountConfiguration.isActor(account, idB));
    }

    /// @notice Each applied batch increments the account's local change sequence by one.
    /// @dev createAccount initializes localSequence to 1 (the initialized flag), so the local channel starts at 1.
    function test_applySignedActorChanges_success_sequenceIncrements(uint256 pk, bytes32 idA, bytes32 idB) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(idA != ownerId && idA != bytes32(bytes20(account)));
        vm.assume(idB != ownerId && idB != bytes32(bytes20(account)));
        vm.assume(idA != idB);

        assertEq(accountConfiguration.getChangeSequences(account).local, 1);

        _authorizeActor(account, pk, idA, address(k1Authenticator));
        assertEq(accountConfiguration.getChangeSequences(account).local, 2);

        _authorizeActor(account, pk, idB, address(k1Authenticator));
        assertEq(accountConfiguration.getChangeSequences(account).local, 3);
    }

    /// @notice A hard-locked account rejects actor changes.
    /// @dev The onlyUnlocked modifier fires before any authentication work.
    function test_applySignedActorChanges_revert_whenLocked(uint256 pk, bytes32 actorId) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));
        _lockAccount(account);

        AccountConfiguration.ActorChange[] memory ch = _authorizeChange(actorId, address(k1Authenticator), 0, 0, "");
        bytes memory auth = _authOver(account, pk, ch);
        vm.expectRevert(AccountConfiguration.AccountIsLocked.selector);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), ch, auth);
    }

    /// @notice Any authorized unrestricted actor, not only the owner, may authorize further actors.
    function test_applySignedActorChanges_success_anyUnrestrictedActorAuthorizes(
        uint256 ownerPk,
        uint256 actorPk,
        bytes32 targetId
    ) public {
        ownerPk = _boundK1Pk(ownerPk);
        actorPk = _boundK1Pk(actorPk);
        vm.assume(ownerPk != actorPk);
        (address account, bytes32 ownerId) = _createK1Account(ownerPk);
        bytes32 actorId = bytes32(bytes20(vm.addr(actorPk)));
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));
        vm.assume(targetId != ownerId && targetId != actorId && targetId != bytes32(bytes20(account)));

        _authorizeActor(account, ownerPk, actorId, address(k1Authenticator));

        AccountConfiguration.ActorChange[] memory ch = _authorizeChange(targetId, address(k1Authenticator), 0, 0, "");
        _signApply(account, actorPk, ch);
        assertTrue(accountConfiguration.isActor(account, targetId));
    }

    /// @notice An actor whose scope lacks the CONFIG bit cannot authorize actors.
    /// @dev Reverts with UnauthorizedActorChange at the CONFIG-scope gate.
    function test_applySignedActorChanges_revert_scopedActorWithoutConfigScope(
        uint256 ownerPk,
        uint256 actorPk,
        uint8 scope,
        bytes32 targetId
    ) public {
        ownerPk = _boundK1Pk(ownerPk);
        actorPk = _boundK1Pk(actorPk);
        vm.assume(ownerPk != actorPk);
        (address account, bytes32 ownerId) = _createK1Account(ownerPk);
        bytes32 actorId = bytes32(bytes20(vm.addr(actorPk)));
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));
        vm.assume(targetId != ownerId && targetId != actorId && targetId != bytes32(bytes20(account)));
        uint8 config = accountConfiguration.SCOPE_CONFIG();
        scope = uint8(bound(uint256(scope), 1, 255)) & ~config;
        vm.assume(scope != 0);

        _authorizeActorWithScope(account, ownerPk, actorId, address(k1Authenticator), scope);

        AccountConfiguration.ActorChange[] memory ch = _authorizeChange(targetId, address(k1Authenticator), 0, 0, "");
        bytes memory auth = _authOver(account, actorPk, ch);
        vm.expectRevert(AccountConfiguration.UnauthorizedActorChange.selector);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), ch, auth);
    }

    /// @notice An actor whose scope includes the CONFIG bit may authorize actors.
    function test_applySignedActorChanges_success_scopedActorWithConfigScope(
        uint256 ownerPk,
        uint256 actorPk,
        uint8 extra,
        bytes32 targetId
    ) public {
        ownerPk = _boundK1Pk(ownerPk);
        actorPk = _boundK1Pk(actorPk);
        vm.assume(ownerPk != actorPk);
        (address account, bytes32 ownerId) = _createK1Account(ownerPk);
        bytes32 actorId = bytes32(bytes20(vm.addr(actorPk)));
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));
        vm.assume(targetId != ownerId && targetId != actorId && targetId != bytes32(bytes20(account)));
        uint8 scope = accountConfiguration.SCOPE_CONFIG() | (extra & 0x07);

        _authorizeActorWithScope(account, ownerPk, actorId, address(k1Authenticator), scope);

        AccountConfiguration.ActorChange[] memory ch = _authorizeChange(targetId, address(k1Authenticator), 0, 0, "");
        _signApply(account, actorPk, ch);
        assertTrue(accountConfiguration.isActor(account, targetId));
    }

    /// @notice Re-authorizing an already-configured non-self actor upserts its config in place.
    /// @dev The owner actor is re-scoped from unrestricted to CONFIG rather than reverting.
    function test_authorizeActor_success_reauthorizeUpsertsInPlace(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);

        uint8 newScope = accountConfiguration.SCOPE_CONFIG();
        AccountConfiguration.ActorChange[] memory ch =
            _authorizeChange(ownerId, address(k1Authenticator), newScope, 0, "");
        _signApply(account, pk, ch);

        AccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(account, ownerId);
        assertEq(cfg.scope, newScope);
        assertEq(cfg.authenticator, address(k1Authenticator));
    }

    /// @notice Re-authorizing a live inline k1 self is an in-place upsert with no prior revoke.
    /// @dev Even a non-trivially-scoped live self can be re-scoped directly.
    function test_selfActorId_success_reauthorizeLiveSelfRescopes(uint256 eoaPk) public {
        eoaPk = _boundK1Pk(eoaPk);
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        uint8 configScope = accountConfiguration.SCOPE_CONFIG();
        _rescopeSelf(eoa, eoaPk, configScope);
        assertEq(accountConfiguration.getActorConfig(eoa, selfActorId).scope, configScope);

        uint8 newScope = configScope | 0x02; // CONFIG | SENDER
        _rescopeSelf(eoa, eoaPk, newScope);

        AccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(eoa, selfActorId);
        assertEq(cfg.scope, newScope);
        assertEq(cfg.authenticator, accountConfiguration.K1_AUTHENTICATOR());
        assertTrue(accountConfiguration.isActor(eoa, selfActorId));
    }

    /// @notice Revoking an actor that was never authorized reverts.
    function test_revokeActor_revert_nonExistentActor(uint256 pk, bytes32 actorId) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        AccountConfiguration.ActorChange[] memory ch = new AccountConfiguration.ActorChange[](1);
        ch[0] = AccountConfiguration.ActorChange({actorId: actorId, changeType: 0x02, data: ""});
        bytes memory auth = _authOver(account, pk, ch);
        vm.expectRevert();
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), ch, auth);
    }

    /// @notice A batch signed by a key that is not an actor on the account reverts.
    function test_applySignedActorChanges_revert_invalidSignature(uint256 pk, uint256 wrongPk, bytes32 actorId) public {
        pk = _boundK1Pk(pk);
        wrongPk = _boundK1Pk(wrongPk);
        vm.assume(vm.addr(pk) != vm.addr(wrongPk));
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(vm.addr(wrongPk) != account);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        AccountConfiguration.ActorChange[] memory ch = _authorizeChange(actorId, address(k1Authenticator), 0, 0, "");
        bytes memory badAuth = _authOver(account, wrongPk, ch);
        vm.expectRevert();
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), ch, badAuth);
    }

    // ── Implicit EOA (registered by default) ──
    //
    // Every account has an implicit self-actorId bytes32(bytes20(account))
    // that is authorized with unrestricted scope when the config slot
    // is empty. No createAccount/importAccount needed.

    /// @notice A never-created EOA can sign actor changes via its implicit self key.
    function test_applySignedActorChanges_success_implicitEoaSigner(uint256 eoaPk, bytes32 actorId) public {
        eoaPk = _boundK1Pk(eoaPk);
        address eoa = vm.addr(eoaPk);
        vm.assume(actorId != bytes32(bytes20(eoa)));

        _signApply(eoa, eoaPk, _authorizeChange(actorId, address(k1Authenticator), 0, 0, ""));
        assertTrue(accountConfiguration.isActor(eoa, actorId));
    }

    /// @notice The implicit EOA self key can be revoked via the default-EOA flag using another key.
    /// @dev A revoked default EOA reports an all-zero config.
    function test_selfActorId_success_implicitEoaRevokesSelfViaFlag(uint256 eoaPk, uint256 newPk) public {
        eoaPk = _boundK1Pk(eoaPk);
        newPk = _boundK1Pk(newPk);
        vm.assume(eoaPk != newPk);
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));
        bytes32 newActorId = bytes32(bytes20(vm.addr(newPk)));
        vm.assume(newActorId != selfActorId);
        assertTrue(accountConfiguration.isActor(eoa, selfActorId));

        _implicitAuthorizeActor(eoa, eoaPk, newActorId, address(k1Authenticator));
        _revokeActor(eoa, newPk, selfActorId);

        assertFalse(accountConfiguration.isActor(eoa, selfActorId));
        assertTrue(accountConfiguration.isActor(eoa, newActorId));

        AccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(eoa, selfActorId);
        assertEq(cfg.authenticator, address(0));
        assertEq(cfg.scope, 0);
    }

    /// @notice A live default EOA reports a synthesized K1 owner config for its self-actorId.
    function test_selfActorId_success_liveReportsAsK1Owner(uint256 eoaPk) public view {
        eoaPk = _boundK1Pk(eoaPk);
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        AccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(eoa, selfActorId);
        assertEq(cfg.authenticator, accountConfiguration.K1_AUTHENTICATOR());
        assertEq(cfg.scope, 0);
    }

    /// @notice The account's own key can be downgraded to a scoped actor via the self-actorId.
    /// @dev With a single k1 path the config alone decides the scope; there is no implicit full-owner escape.
    function test_selfActorId_success_scopeViaK1(uint256 eoaPk, uint8 scope, bytes32 hash) public {
        eoaPk = _boundK1Pk(eoaPk);
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));
        scope = uint8(bound(uint256(scope), 1, 255));
        assertTrue(accountConfiguration.isActor(eoa, selfActorId));

        _implicitAuthorizeActorWithScope(eoa, eoaPk, selfActorId, address(k1Authenticator), scope);

        assertTrue(accountConfiguration.isActor(eoa, selfActorId));
        AccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(eoa, selfActorId);
        assertEq(cfg.authenticator, address(k1Authenticator));
        assertEq(cfg.scope, scope);

        (uint8 outScope,,) = accountConfiguration.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));
        assertEq(outScope, scope);
    }

    /// @notice A self key scoped without the CONFIG bit can no longer authorize, including re-authorizing itself.
    /// @dev Reverts with UnauthorizedActorChange: the downgraded self fails the CONFIG-scope gate.
    function test_selfActorId_revert_scopedSelfCannotReauthorize(uint256 eoaPk, uint8 scope) public {
        eoaPk = _boundK1Pk(eoaPk);
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));
        uint8 config = accountConfiguration.SCOPE_CONFIG();
        scope = uint8(bound(uint256(scope), 1, 255)) & ~config;
        vm.assume(scope != 0);

        _implicitAuthorizeActorWithScope(eoa, eoaPk, selfActorId, address(k1Authenticator), scope);

        AccountConfiguration.ActorChange[] memory ch =
            _authorizeChange(selfActorId, accountConfiguration.K1_AUTHENTICATOR(), 0, 0, "");
        bytes memory auth = _authOver(eoa, eoaPk, ch);
        vm.expectRevert(AccountConfiguration.UnauthorizedActorChange.selector);
        accountConfiguration.applySignedActorChanges(eoa, uint64(block.chainid), ch, auth);
    }

    /// @notice A never-created EOA can apply a multichain (chainId 0) actor change via its implicit self key.
    function test_applySignedActorChanges_success_multichainImplicitEoa(uint256 eoaPk, bytes32 actorId) public {
        eoaPk = _boundK1Pk(eoaPk);
        address eoa = vm.addr(eoaPk);
        vm.assume(actorId != bytes32(bytes20(eoa)));

        AccountConfiguration.ActorChange[] memory ch = _authorizeChange(actorId, address(k1Authenticator), 0, 0, "");
        uint64 seq = accountConfiguration.getChangeSequences(eoa).multichain;
        bytes32 digest = _computeActorChangeBatchDigest(eoa, 0, seq, ch);
        accountConfiguration.applySignedActorChanges(eoa, 0, ch, _buildK1Auth(eoaPk, digest));
        assertTrue(accountConfiguration.isActor(eoa, actorId));
    }

    // ── Default EOA self-actorId semantics ──
    //
    // The self-actorId for an account is bytes32(bytes20(account)). Without an explicit entry it is the implicit
    // default EOA (full owner), gated by the AccountState flag. It may also be configured as an explicit actor like
    // any other (e.g. to scope the account's own key), which sets the flag and disables the implicit address(0)
    // path. The flag is never cleared, so a managed self-actorId is operated through its explicit entry/prefix.
    // createAccount and importAccount disable the implicit default EOA by default.

    /// @notice createAccount disables the implicit default EOA, so the self-actorId is not a live actor.
    function test_selfActorId_success_revokedByDefaultOnCreate(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        bytes32 selfActorId = bytes32(bytes20(account));

        assertFalse(accountConfiguration.isActor(account, selfActorId));
        AccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(account, selfActorId);
        assertEq(cfg.authenticator, address(0));
        assertEq(cfg.scope, 0);
    }

    /// @notice An owner re-enables the default EOA by authorizing the self-actorId with the owner shape.
    function test_selfActorId_success_reEnableOnCreatedAccount(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        bytes32 selfActorId = bytes32(bytes20(account));
        assertFalse(accountConfiguration.isActor(account, selfActorId));

        _authorizeActor(account, pk, selfActorId, accountConfiguration.K1_AUTHENTICATOR());

        assertTrue(accountConfiguration.isActor(account, selfActorId));
        AccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(account, selfActorId);
        assertEq(cfg.authenticator, accountConfiguration.K1_AUTHENTICATOR());
        assertEq(cfg.scope, 0);
    }

    /// @notice A revoked default EOA can be re-enabled by authorizing the self-actorId as a native k1 owner.
    /// @dev While revoked the own key cannot authenticate; after re-enable it resolves via the explicit self config.
    function test_selfActorId_success_revokeThenReEnable(uint256 eoaPk, uint256 newPk, bytes32 hash) public {
        eoaPk = _boundK1Pk(eoaPk);
        newPk = _boundK1Pk(newPk);
        vm.assume(eoaPk != newPk);
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));
        bytes32 newActorId = bytes32(bytes20(vm.addr(newPk)));
        vm.assume(newActorId != selfActorId);
        assertTrue(accountConfiguration.isActor(eoa, selfActorId));

        _implicitAuthorizeActor(eoa, eoaPk, newActorId, address(k1Authenticator));
        _revokeActor(eoa, newPk, selfActorId);
        assertFalse(accountConfiguration.isActor(eoa, selfActorId));

        vm.expectRevert();
        accountConfiguration.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));

        _authorizeActor(eoa, newPk, selfActorId, accountConfiguration.K1_AUTHENTICATOR());
        assertTrue(accountConfiguration.isActor(eoa, selfActorId));

        (uint8 scope,,) = accountConfiguration.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));
        assertEq(scope, 0);
    }

    /// @notice Full lifecycle: default EOA hands the account to a device key, then re-enables the K1 key.
    /// @dev The revoke-self + re-enable-self mechanics are authenticator-agnostic; K1 stands in for a passkey here.
    function test_selfActorId_success_eoaToPasskeyLifecycle(uint256 eoaPk, uint256 devicePk, bytes32 hash) public {
        eoaPk = _boundK1Pk(eoaPk);
        devicePk = _boundK1Pk(devicePk);
        vm.assume(eoaPk != devicePk);
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));
        bytes32 deviceActorId = bytes32(bytes20(vm.addr(devicePk)));
        vm.assume(deviceActorId != selfActorId);

        // Phase 0: the default EOA is live and authenticates with its own k1 signature.
        assertTrue(accountConfiguration.isActor(eoa, selfActorId));
        (uint8 scope0,,) = accountConfiguration.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));
        assertEq(scope0, 0);

        // Phase 1: in one batch signed by the EOA, add the device key as a full owner and revoke the default EOA.
        AccountConfiguration.ActorChange[] memory switchChanges = new AccountConfiguration.ActorChange[](2);
        switchChanges[0] = _authorizeChange(deviceActorId, address(k1Authenticator), 0, 0, "")[0];
        switchChanges[1] = AccountConfiguration.ActorChange({actorId: selfActorId, changeType: 0x02, data: ""});
        _signApply(eoa, eoaPk, switchChanges);

        assertFalse(accountConfiguration.isActor(eoa, selfActorId));
        assertTrue(accountConfiguration.isActor(eoa, deviceActorId));
        vm.expectRevert();
        accountConfiguration.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));
        (uint8 scope1,,) = accountConfiguration.authenticateActor(eoa, hash, _buildK1Auth(devicePk, hash));
        assertEq(scope1, 0);

        // Phase 2: the device key re-enables the K1 key by authorizing the self-actorId as a native k1 owner.
        AccountConfiguration.ActorChange[] memory reEnable =
            _authorizeChange(selfActorId, accountConfiguration.K1_AUTHENTICATOR(), 0, 0, "");
        _signApply(eoa, devicePk, reEnable);

        assertTrue(accountConfiguration.isActor(eoa, selfActorId));
        (uint8 scope2,,) = accountConfiguration.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));
        assertEq(scope2, 0);
    }

    /// @notice A single batch signed by the default EOA can add a key and revoke the default EOA together.
    function test_selfActorId_success_batchRevokeViaFlag(uint256 eoaPk, uint256 newPk) public {
        eoaPk = _boundK1Pk(eoaPk);
        newPk = _boundK1Pk(newPk);
        vm.assume(eoaPk != newPk);
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));
        bytes32 newActorId = bytes32(bytes20(vm.addr(newPk)));
        vm.assume(newActorId != selfActorId);

        AccountConfiguration.ActorChange[] memory ch = new AccountConfiguration.ActorChange[](2);
        ch[0] = _authorizeChange(newActorId, address(k1Authenticator), 0, 0, "")[0];
        ch[1] = AccountConfiguration.ActorChange({actorId: selfActorId, changeType: 0x02, data: ""});
        _signApply(eoa, eoaPk, ch);

        assertFalse(accountConfiguration.isActor(eoa, selfActorId));
        assertTrue(accountConfiguration.isActor(eoa, newActorId));

        AccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(eoa, selfActorId);
        assertEq(cfg.authenticator, address(0));
        assertEq(cfg.scope, 0);
    }

    /// @notice A revoked default EOA can no longer sign actor changes, but a still-active key can.
    /// @dev The revoked self signature reverts; the second key's signature over the same digest applies.
    function test_selfActorId_revert_revokedCannotSign(uint256 eoaPk, uint256 newPk, bytes32 targetId) public {
        eoaPk = _boundK1Pk(eoaPk);
        newPk = _boundK1Pk(newPk);
        vm.assume(eoaPk != newPk);
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));
        bytes32 newActorId = bytes32(bytes20(vm.addr(newPk)));
        vm.assume(newActorId != selfActorId);
        vm.assume(targetId != selfActorId && targetId != newActorId);

        _implicitAuthorizeActor(eoa, eoaPk, newActorId, address(k1Authenticator));
        _revokeActor(eoa, newPk, selfActorId);

        AccountConfiguration.ActorChange[] memory ch = _authorizeChange(targetId, address(k1Authenticator), 0, 0, "");
        uint64 seq = accountConfiguration.getChangeSequences(eoa).local;
        bytes32 digest = _computeActorChangeBatchDigest(eoa, uint64(block.chainid), seq, ch);

        vm.expectRevert();
        accountConfiguration.applySignedActorChanges(eoa, uint64(block.chainid), ch, _buildK1Auth(eoaPk, digest));

        accountConfiguration.applySignedActorChanges(eoa, uint64(block.chainid), ch, _buildK1Auth(newPk, digest));
        assertTrue(accountConfiguration.isActor(eoa, targetId));
    }

    /// @notice A revoked signer key can no longer authorize actor changes.
    function test_applySignedActorChanges_revert_revokedSignerKey(uint256 ownerPk, uint256 newPk, bytes32 targetId)
        public
    {
        ownerPk = _boundK1Pk(ownerPk);
        newPk = _boundK1Pk(newPk);
        vm.assume(ownerPk != newPk);
        (address account, bytes32 ownerId) = _createK1Account(ownerPk);
        bytes32 newActorId = bytes32(bytes20(vm.addr(newPk)));
        vm.assume(newActorId != ownerId && newActorId != bytes32(bytes20(account)));
        vm.assume(targetId != ownerId && targetId != newActorId && targetId != bytes32(bytes20(account)));

        _authorizeActor(account, ownerPk, newActorId, address(k1Authenticator));
        _revokeActor(account, newPk, ownerId);

        AccountConfiguration.ActorChange[] memory ch = _authorizeChange(targetId, address(k1Authenticator), 0, 0, "");
        bytes memory auth = _authOver(account, ownerPk, ch);
        vm.expectRevert();
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), ch, auth);
    }

    /// @notice Revoking a non-self actor deletes its config slot.
    function test_revokeActor_success_deletesSlot(uint256 pk, bytes32 actorId) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));
        _authorizeActor(account, pk, actorId, address(k1Authenticator));

        _revokeActor(account, pk, actorId);

        AccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(account, actorId);
        assertEq(cfg.authenticator, address(0));
        assertEq(cfg.scope, 0);
    }

    // ── Fuzzed reverts and branch coverage ──

    /// @notice applySignedActorChanges reverts for a chainId that is neither 0 (multichain) nor the current chain.
    /// @dev Exercises the `chainId != 0 && chainId != block.chainid` guard on the actor-change path.
    function test_applySignedActorChanges_revert_invalidChainId(uint256 pk, uint256 badChainId) public {
        pk = _boundK1Pk(pk);
        badChainId = bound(badChainId, 1, type(uint64).max);
        vm.assume(badChainId != block.chainid);
        (address account,) = _createK1Account(pk);

        AccountConfiguration.ActorChange[] memory changes =
            _authorizeChange(bytes32(bytes20(vm.addr(0xBEEF))), address(k1Authenticator), 0, 0, "");
        bytes memory auth = _buildK1Auth(pk, _computeActorChangeBatchDigest(account, uint64(badChainId), 0, changes));

        vm.expectRevert(AccountConfiguration.InvalidChainId.selector);
        accountConfiguration.applySignedActorChanges(account, uint64(badChainId), changes, auth);
    }

    /// @notice Replaying an identical (changes, auth) pair fails once the sequence is consumed.
    /// @dev The replay recomputes the digest at seq+1, so the stale signature recovers a non-actor and reverts.
    function test_applySignedActorChanges_revert_replay(uint256 pk, bytes32 actorId) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        AccountConfiguration.ActorChange[] memory changes =
            _authorizeChange(actorId, address(k1Authenticator), 0, 0, "");
        bytes memory auth = _authOver(account, pk, changes);

        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);

        vm.expectRevert();
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
    }

    /// @notice A changeType outside {authorize, revoke} reverts with UnknownChangeType (after the CONFIG gate).
    function test_applySignedActorChanges_revert_unknownChangeType(uint256 pk, uint8 changeType) public {
        pk = _boundK1Pk(pk);
        vm.assume(changeType != 0x01 && changeType != 0x02);
        (address account,) = _createK1Account(pk);

        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: bytes32(bytes20(vm.addr(0xBEEF))), changeType: changeType, data: ""
        });

        bytes memory auth = _authOver(account, pk, changes);
        vm.expectRevert(AccountConfiguration.UnknownChangeType.selector);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
    }

    /// @notice The CONFIG gate: an authenticated actor may change actors iff scope==0 or scope has the CONFIG bit.
    /// @dev Fuzzes the signer's scope across the whole byte and asserts success/revert on the exact predicate.
    function test_applySignedActorChanges_configGate_acrossScopes(
        uint256 ownerPk,
        uint256 signerPk,
        uint8 signerScope,
        bytes32 targetId
    ) public {
        ownerPk = _boundK1Pk(ownerPk);
        signerPk = _boundK1Pk(signerPk);
        vm.assume(ownerPk != signerPk);
        (address account, bytes32 ownerId) = _createK1Account(ownerPk);
        bytes32 signerId = bytes32(bytes20(vm.addr(signerPk)));
        vm.assume(signerId != ownerId && signerId != bytes32(bytes20(account)));
        vm.assume(targetId != ownerId && targetId != signerId && targetId != bytes32(bytes20(account)));

        uint8 config = accountConfiguration.SCOPE_CONFIG();
        _authorizeActorWithScope(account, ownerPk, signerId, address(k1Authenticator), signerScope);

        AccountConfiguration.ActorChange[] memory ch = _authorizeChange(targetId, address(k1Authenticator), 0, 0, "");
        if (signerScope == 0 || signerScope & config != 0) {
            _signApply(account, signerPk, ch);
            assertTrue(accountConfiguration.isActor(account, targetId));
        } else {
            bytes memory auth = _authOver(account, signerPk, ch);
            vm.expectRevert(AccountConfiguration.UnauthorizedActorChange.selector);
            accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), ch, auth);
        }
    }

    /// @notice Authorizing with a zero authenticator reverts with InvalidAuthenticator.
    function test_authorizeActor_revert_invalidAuthenticator(uint256 pk, bytes32 actorId) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        AccountConfiguration.ActorChange[] memory ch = _authorizeChange(actorId, address(0), 0, 0, "");
        bytes memory auth = _authOver(account, pk, ch);
        vm.expectRevert(AccountConfiguration.InvalidAuthenticator.selector);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), ch, auth);
    }

    /// @notice A policy-bearing actor with scope 0 reverts with InvalidPolicyScope.
    function test_authorizeActor_revert_invalidPolicyScope_zeroScope(uint256 pk, bytes32 actorId) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        AccountConfiguration.ActorChange[] memory ch =
            _authorizeChange(actorId, address(k1Authenticator), 0, 0x01, _validPolicyData());
        bytes memory auth = _authOver(account, pk, ch);
        vm.expectRevert(AccountConfiguration.InvalidPolicyScope.selector);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), ch, auth);
    }

    /// @notice A policy-bearing actor whose scope includes the CONFIG bit reverts with InvalidPolicyScope.
    function test_authorizeActor_revert_invalidPolicyScope_configScope(uint256 pk, bytes32 actorId, uint8 extra)
        public
    {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));
        uint8 scope = accountConfiguration.SCOPE_CONFIG() | (extra & 0x07);

        AccountConfiguration.ActorChange[] memory ch =
            _authorizeChange(actorId, address(k1Authenticator), scope, 0x01, _validPolicyData());
        bytes memory auth = _authOver(account, pk, ch);
        vm.expectRevert(AccountConfiguration.InvalidPolicyScope.selector);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), ch, auth);
    }

    /// @notice policyType==NONE with non-empty policyData reverts with InvalidPolicyData.
    function test_authorizeActor_revert_invalidPolicyData_noneWithData(uint256 pk, bytes32 actorId, bytes memory data)
        public
    {
        pk = _boundK1Pk(pk);
        vm.assume(data.length != 0);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        AccountConfiguration.ActorChange[] memory ch = _authorizeChange(actorId, address(k1Authenticator), 0, 0, data);
        bytes memory auth = _authOver(account, pk, ch);
        vm.expectRevert(AccountConfiguration.InvalidPolicyData.selector);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), ch, auth);
    }

    /// @notice A gated actor whose policyData is not exactly 52 bytes reverts with InvalidPolicyData.
    function test_authorizeActor_revert_invalidPolicyData_gatedWrongLength(
        uint256 pk,
        bytes32 actorId,
        bytes memory data
    ) public {
        pk = _boundK1Pk(pk);
        vm.assume(data.length != 52);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        AccountConfiguration.ActorChange[] memory ch =
            _authorizeChange(actorId, address(k1Authenticator), 0x02, 0x01, data);
        bytes memory auth = _authOver(account, pk, ch);
        vm.expectRevert(AccountConfiguration.InvalidPolicyData.selector);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), ch, auth);
    }

    /// @notice A gated actor with a zero policy manager reverts with InvalidPolicyData.
    function test_authorizeActor_revert_invalidPolicyData_zeroManager(uint256 pk, bytes32 actorId, bytes32 commitment)
        public
    {
        pk = _boundK1Pk(pk);
        vm.assume(commitment != bytes32(0));
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        bytes memory data = abi.encodePacked(bytes20(address(0)), commitment);
        AccountConfiguration.ActorChange[] memory ch =
            _authorizeChange(actorId, address(k1Authenticator), 0x02, 0x01, data);
        bytes memory auth = _authOver(account, pk, ch);
        vm.expectRevert(AccountConfiguration.InvalidPolicyData.selector);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), ch, auth);
    }

    /// @notice A gated actor with a zero policy commitment reverts with InvalidPolicyData.
    function test_authorizeActor_revert_invalidPolicyData_zeroCommitment(uint256 pk, bytes32 actorId, address manager)
        public
    {
        pk = _boundK1Pk(pk);
        vm.assume(manager != address(0));
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        bytes memory data = abi.encodePacked(bytes20(manager), bytes32(0));
        AccountConfiguration.ActorChange[] memory ch =
            _authorizeChange(actorId, address(k1Authenticator), 0x02, 0x01, data);
        bytes memory auth = _authOver(account, pk, ch);
        vm.expectRevert(AccountConfiguration.InvalidPolicyData.selector);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), ch, auth);
    }

    /// @notice Duplicate actorIds within one batch apply sequentially (last operation wins).
    function test_applySignedActorChanges_success_duplicateActorIdInBatch(uint256 pk, bytes32 actorId) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        // [authorize A, revoke A] → A ends not live.
        AccountConfiguration.ActorChange[] memory ch = new AccountConfiguration.ActorChange[](2);
        ch[0] = _authorizeChange(actorId, address(k1Authenticator), 0, 0, "")[0];
        ch[1] = AccountConfiguration.ActorChange({actorId: actorId, changeType: 0x02, data: ""});
        _signApply(account, pk, ch);
        assertFalse(accountConfiguration.isActor(account, actorId));

        // Pre-authorize, then [revoke A, authorize A] → A ends live.
        _authorizeActor(account, pk, actorId, address(k1Authenticator));
        AccountConfiguration.ActorChange[] memory ch2 = new AccountConfiguration.ActorChange[](2);
        ch2[0] = AccountConfiguration.ActorChange({actorId: actorId, changeType: 0x02, data: ""});
        ch2[1] = _authorizeChange(actorId, address(k1Authenticator), 0, 0, "")[0];
        _signApply(account, pk, ch2);
        assertTrue(accountConfiguration.isActor(account, actorId));
    }

    /// @notice A CONFIG-scoped signer may revoke itself mid-batch; the scope gate is evaluated once, pre-loop.
    function test_applySignedActorChanges_success_signerRevokesSelfMidBatch(
        uint256 ownerPk,
        uint256 signerPk,
        bytes32 bId
    ) public {
        ownerPk = _boundK1Pk(ownerPk);
        signerPk = _boundK1Pk(signerPk);
        vm.assume(ownerPk != signerPk);
        (address account, bytes32 ownerId) = _createK1Account(ownerPk);
        bytes32 signerId = bytes32(bytes20(vm.addr(signerPk)));
        vm.assume(signerId != ownerId && signerId != bytes32(bytes20(account)));
        vm.assume(bId != ownerId && bId != signerId && bId != bytes32(bytes20(account)));

        _authorizeActorWithScope(
            account, ownerPk, signerId, address(k1Authenticator), accountConfiguration.SCOPE_CONFIG()
        );

        AccountConfiguration.ActorChange[] memory ch = new AccountConfiguration.ActorChange[](2);
        ch[0] = AccountConfiguration.ActorChange({actorId: signerId, changeType: 0x02, data: ""});
        ch[1] = _authorizeChange(bId, address(k1Authenticator), 0, 0, "")[0];
        _signApply(account, signerPk, ch);

        assertFalse(accountConfiguration.isActor(account, signerId));
        assertTrue(accountConfiguration.isActor(account, bId));
    }

    /// @notice Self-actorId flip: k1 self → non-k1 (p256) self → k1 self; the non-k1 config replaces then is replaced.
    function test_selfActorId_success_flipFlopK1NonK1(uint256 eoaPk, uint256 adminPk) public {
        eoaPk = _boundK1Pk(eoaPk);
        adminPk = _boundK1Pk(adminPk);
        vm.assume(eoaPk != adminPk);
        address eoa = vm.addr(eoaPk);
        bytes32 selfId = bytes32(bytes20(eoa));
        bytes32 adminId = bytes32(bytes20(vm.addr(adminPk)));
        vm.assume(adminId != selfId);

        // Implicit self authorizes an admin with CONFIG scope to drive the flips.
        _implicitAuthorizeActorWithScope(
            eoa, eoaPk, adminId, address(k1Authenticator), accountConfiguration.SCOPE_CONFIG()
        );

        // Flip self → non-k1 (p256): sets the revoke flag, stores the non-k1 self config; k1 self dies.
        _authorizeActorWithScope(eoa, adminPk, selfId, address(p256Authenticator), 0x02);
        assertEq(accountConfiguration.getActorConfig(eoa, selfId).authenticator, address(p256Authenticator));
        bytes32 h = keccak256("flip");
        vm.expectRevert();
        accountConfiguration.authenticateActor(eoa, h, _buildK1Auth(eoaPk, h));

        // Flip self → k1 owner: deletes the non-k1 config, restores inline k1 (flag cleared); k1 self lives again.
        _authorizeActor(eoa, adminPk, selfId, accountConfiguration.K1_AUTHENTICATOR());
        assertEq(
            accountConfiguration.getActorConfig(eoa, selfId).authenticator, accountConfiguration.K1_AUTHENTICATOR()
        );
        (uint8 scope,,) = accountConfiguration.authenticateActor(eoa, h, _buildK1Auth(eoaPk, h));
        assertEq(scope, 0);
    }

    /// @notice A happy-path authorize emits ActorAuthorized once with the correct account and actorId.
    function test_applySignedActorChanges_success_emitsActorAuthorized(uint256 pk, bytes32 actorId) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        AccountConfiguration.ActorChange[] memory ch = _authorizeChange(actorId, address(k1Authenticator), 0, 0, "");
        vm.expectEmit(true, true, false, false, address(accountConfiguration));
        emit AccountConfiguration.ActorAuthorized(account, actorId, "");
        _signApply(account, pk, ch);
    }

    /// @notice A happy-path revoke emits ActorRevoked once with the correct account and actorId.
    function test_applySignedActorChanges_success_emitsActorRevoked(uint256 pk, bytes32 actorId) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));
        _authorizeActor(account, pk, actorId, address(k1Authenticator));

        AccountConfiguration.ActorChange[] memory ch = new AccountConfiguration.ActorChange[](1);
        ch[0] = AccountConfiguration.ActorChange({actorId: actorId, changeType: 0x02, data: ""});
        vm.expectEmit(true, true, false, true, address(accountConfiguration));
        emit AccountConfiguration.ActorRevoked(account, actorId);
        _signApply(account, pk, ch);
    }

    // ── Helpers ──

    /// @dev Build a one-element authorize batch with a full ActorConfig + policyData (expiry fixed at 0).
    function _authorizeChange(bytes32 actorId, address auth, uint8 scope, uint8 policyType, bytes memory policyData)
        internal
        pure
        returns (AccountConfiguration.ActorChange[] memory changes)
    {
        changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: actorId,
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: auth, scope: scope, expiry: 0, policyType: policyType
                }),
                policyData
            )
        });
    }

    /// @dev Owner/actor signature over a batch at the current local sequence.
    function _authOver(address account, uint256 pk, AccountConfiguration.ActorChange[] memory changes)
        internal
        view
        returns (bytes memory)
    {
        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        return _buildK1Auth(pk, _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes));
    }

    /// @dev Sign (with pk) and apply a batch on the local chain.
    function _signApply(address account, uint256 pk, AccountConfiguration.ActorChange[] memory changes) internal {
        accountConfiguration.applySignedActorChanges(
            account, uint64(block.chainid), changes, _authOver(account, pk, changes)
        );
    }

    /// @dev A well-formed 52-byte gated policyData (non-zero manager ‖ non-zero commitment).
    function _validPolicyData() internal pure returns (bytes memory) {
        return abi.encodePacked(bytes20(uint160(0x1234)), bytes32(uint256(0x5678)));
    }

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
