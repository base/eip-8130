// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore} from "../../../src/Keystore.sol";
import {KeystoreTest} from "../../lib/KeystoreTest.sol";

contract ApplyConfigChangeActorTest is KeystoreTest {
    uint16 constant SCOPE_SENDER = 0x01;
    uint16 constant SCOPE_POLICY = 0x02;
    uint16 constant SCOPE_NONCE = 0x04;
    uint16 constant SCOPE_SELF_PAYER = 0x08;
    uint16 constant SCOPE_SPONSOR_PAYER = 0x10;

    /// @notice Authorizing a non-self actor registers it with the given authenticator and unrestricted scope.
    function test_authorizeActor_success_unrestricted(uint256 pk, bytes32 actorId) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        Keystore.ActorChange[] memory ch = _authorizeChange(actorId, address(k1Authenticator), 0, "");
        _signApply(account, pk, ch);

        Keystore.ActorConfig memory cfg = keystore.getActorConfig(account, actorId);
        assertEq(cfg.authenticator, address(k1Authenticator));
        assertEq(cfg.scope, 0x00);
    }

    /// @notice Authorizing an actor stores the requested non-zero scope verbatim.
    /// @dev SCOPE_POLICY is masked out because a policy-bearing scope requires policyData (covered elsewhere).
    function test_authorizeActor_success_withScope(uint256 pk, bytes32 actorId, uint16 scope) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));
        scope = uint16(bound(uint256(scope), 1, 255)) & ~SCOPE_POLICY;
        vm.assume(scope != 0);

        Keystore.ActorChange[] memory ch = _authorizeChange(actorId, address(k1Authenticator), scope, "");
        _signApply(account, pk, ch);

        Keystore.ActorConfig memory cfg = keystore.getActorConfig(account, actorId);
        assertEq(cfg.authenticator, address(k1Authenticator));
        assertEq(cfg.scope, scope);
    }

    /// @notice Revoking a live non-self actor removes it from the account.
    function test_revokeActor_success_removesActor(uint256 pk, bytes32 actorId) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));
        _authorizeActor(account, pk, actorId, address(k1Authenticator));
        assertTrue(_isActor(account, actorId));

        Keystore.ActorChange[] memory ch = new Keystore.ActorChange[](1);
        ch[0] = Keystore.ActorChange({actorId: actorId, changeType: 0x02, data: ""});
        _signApply(account, pk, ch);

        assertFalse(_isActor(account, actorId));
    }

    /// @notice A batch of multiple authorize operations applies every element.
    function test_applySignedActorChanges_success_multipleOperations(uint256 pk, bytes32 idA, bytes32 idB) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(idA != ownerId && idA != bytes32(bytes20(account)));
        vm.assume(idB != ownerId && idB != bytes32(bytes20(account)));
        vm.assume(idA != idB);

        Keystore.ActorChange[] memory ch = new Keystore.ActorChange[](2);
        ch[0] = _authorizeChange(idA, address(k1Authenticator), 0, "")[0];
        ch[1] = _authorizeChange(idB, address(k1Authenticator), 0, "")[0];
        _signApply(account, pk, ch);

        assertTrue(_isActor(account, idA));
        assertTrue(_isActor(account, idB));
    }

    /// @notice Each applied batch increments the account's local change sequence by one.
    /// @dev createAccount initializes localSequence to 1 (the initialized flag), so the local channel starts at 1.
    function test_applySignedActorChanges_success_sequenceIncrements(uint256 pk, bytes32 idA, bytes32 idB) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(idA != ownerId && idA != bytes32(bytes20(account)));
        vm.assume(idB != ownerId && idB != bytes32(bytes20(account)));
        vm.assume(idA != idB);

        assertEq(keystore.getChangeSequences(account).local, 1);

        _authorizeActor(account, pk, idA, address(k1Authenticator));
        assertEq(keystore.getChangeSequences(account).local, 2);

        _authorizeActor(account, pk, idB, address(k1Authenticator));
        assertEq(keystore.getChangeSequences(account).local, 3);
    }

    /// @notice A hard-locked account rejects actor changes.
    /// @dev The onlyUnlocked modifier fires before any authentication work.
    function test_applySignedActorChanges_revert_whenLocked(uint256 pk, bytes32 actorId) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));
        _lockAccount(pk, account);

        Keystore.ActorChange[] memory ch = _authorizeChange(actorId, address(k1Authenticator), 0, "");
        bytes memory auth = _authOver(account, pk, ch);
        vm.expectRevert(Keystore.AccountIsLocked.selector);
        keystore.applySignedActorChanges(account, uint64(block.chainid), ch, auth);
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

        Keystore.ActorChange[] memory ch = _authorizeChange(targetId, address(k1Authenticator), 0, "");
        _signApply(account, actorPk, ch);
        assertTrue(_isActor(account, targetId));
    }

    /// @notice Any scoped (non-zero) actor cannot authorize actors; admin is exactly scope == 0.
    /// @dev Reverts with UnauthorizedActorChange at the scope-0 gate.
    function test_applySignedActorChanges_revert_scopedActorCannotAuthorize(
        uint256 ownerPk,
        uint256 actorPk,
        uint16 scope,
        bytes32 targetId
    ) public {
        ownerPk = _boundK1Pk(ownerPk);
        actorPk = _boundK1Pk(actorPk);
        vm.assume(ownerPk != actorPk);
        (address account, bytes32 ownerId) = _createK1Account(ownerPk);
        bytes32 actorId = bytes32(bytes20(vm.addr(actorPk)));
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));
        vm.assume(targetId != ownerId && targetId != actorId && targetId != bytes32(bytes20(account)));
        scope = uint16(bound(uint256(scope), 1, 255)) & ~SCOPE_POLICY;
        vm.assume(scope != 0);

        _authorizeActorWithScope(account, ownerPk, actorId, address(k1Authenticator), scope);

        Keystore.ActorChange[] memory ch = _authorizeChange(targetId, address(k1Authenticator), 0, "");
        bytes memory auth = _authOver(account, actorPk, ch);
        vm.expectRevert(Keystore.UnauthorizedActorChange.selector);
        keystore.applySignedActorChanges(account, uint64(block.chainid), ch, auth);
    }

    /// @notice Re-authorizing an already-configured non-self actor upserts its config in place.
    /// @dev The owner actor is re-scoped from unrestricted to a scoped key rather than reverting.
    function test_authorizeActor_success_reauthorizeUpsertsInPlace(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);

        uint16 newScope = SCOPE_SENDER;
        Keystore.ActorChange[] memory ch = _authorizeChange(ownerId, address(k1Authenticator), newScope, "");
        _signApply(account, pk, ch);

        Keystore.ActorConfig memory cfg = keystore.getActorConfig(account, ownerId);
        assertEq(cfg.scope, newScope);
        assertEq(cfg.authenticator, address(k1Authenticator));
    }

    /// @notice Re-authorizing a live inline k1 self is an in-place upsert with no prior revoke.
    /// @dev Even a non-trivially-scoped live self can be re-scoped directly.
    function test_selfActorId_success_reauthorizeLiveSelfRescopes(uint256 eoaPk) public {
        eoaPk = _boundK1Pk(eoaPk);
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        // First rescope keeps self at admin scope (0) so the same key retains authority to sign the second change;
        // this materializes an explicit live self config over the implicit default-EOA.
        uint8 firstScope = 0;
        _rescopeSelf(eoa, eoaPk, firstScope);
        assertEq(keystore.getActorConfig(eoa, selfActorId).scope, firstScope);

        // Second admin-signed change rescopes the live self actor in place to a non-admin scope.
        uint16 newScope = SCOPE_SENDER | SCOPE_SELF_PAYER;
        _rescopeSelf(eoa, eoaPk, newScope);

        Keystore.ActorConfig memory cfg = keystore.getActorConfig(eoa, selfActorId);
        assertEq(cfg.scope, newScope);
        assertEq(cfg.authenticator, keystore.K1_AUTHENTICATOR());
        assertTrue(_isActor(eoa, selfActorId));
    }

    /// @notice Revoking an actor that was never authorized reverts.
    function test_revokeActor_revert_nonExistentActor(uint256 pk, bytes32 actorId) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        Keystore.ActorChange[] memory ch = new Keystore.ActorChange[](1);
        ch[0] = Keystore.ActorChange({actorId: actorId, changeType: 0x02, data: ""});
        bytes memory auth = _authOver(account, pk, ch);
        vm.expectRevert();
        keystore.applySignedActorChanges(account, uint64(block.chainid), ch, auth);
    }

    /// @notice A batch signed by a key that is not an actor on the account reverts.
    function test_applySignedActorChanges_revert_invalidSignature(uint256 pk, uint256 wrongPk, bytes32 actorId) public {
        pk = _boundK1Pk(pk);
        wrongPk = _boundK1Pk(wrongPk);
        vm.assume(vm.addr(pk) != vm.addr(wrongPk));
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(vm.addr(wrongPk) != account);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        Keystore.ActorChange[] memory ch = _authorizeChange(actorId, address(k1Authenticator), 0, "");
        bytes memory badAuth = _authOver(account, wrongPk, ch);
        vm.expectRevert();
        keystore.applySignedActorChanges(account, uint64(block.chainid), ch, badAuth);
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

        _signApply(eoa, eoaPk, _authorizeChange(actorId, address(k1Authenticator), 0, ""));
        assertTrue(_isActor(eoa, actorId));
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
        assertTrue(_isActor(eoa, selfActorId));

        _implicitAuthorizeActor(eoa, eoaPk, newActorId, address(k1Authenticator));
        _revokeActor(eoa, newPk, selfActorId);

        assertFalse(_isActor(eoa, selfActorId));
        assertTrue(_isActor(eoa, newActorId));

        Keystore.ActorConfig memory cfg = keystore.getActorConfig(eoa, selfActorId);
        assertEq(cfg.authenticator, address(0));
        assertEq(cfg.scope, 0);
    }

    /// @notice A live default EOA reports a synthesized K1 owner config for its self-actorId.
    function test_selfActorId_success_liveReportsAsK1Owner(uint256 eoaPk) public view {
        eoaPk = _boundK1Pk(eoaPk);
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        Keystore.ActorConfig memory cfg = keystore.getActorConfig(eoa, selfActorId);
        assertEq(cfg.authenticator, keystore.K1_AUTHENTICATOR());
        assertEq(cfg.scope, 0);
    }

    /// @notice The account's own key can be downgraded to a scoped actor via the self-actorId.
    /// @dev With a single k1 path the config alone decides the scope; there is no implicit full-owner escape.
    function test_selfActorId_success_scopeViaK1(uint256 eoaPk, uint16 scope, bytes32 hash) public {
        eoaPk = _boundK1Pk(eoaPk);
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));
        scope = uint16(bound(uint256(scope), 1, 255)) & ~SCOPE_POLICY;
        vm.assume(scope != 0);
        assertTrue(_isActor(eoa, selfActorId));

        _implicitAuthorizeActorWithScope(eoa, eoaPk, selfActorId, address(k1Authenticator), scope);

        assertTrue(_isActor(eoa, selfActorId));
        Keystore.ActorConfig memory cfg = keystore.getActorConfig(eoa, selfActorId);
        assertEq(cfg.authenticator, address(k1Authenticator));
        assertEq(cfg.scope, scope);

        (, uint16 outScope) = keystore.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));
        assertEq(outScope, scope);
    }

    /// @notice A self key scoped to any non-zero scope can no longer authorize, including re-authorizing itself.
    /// @dev Reverts with UnauthorizedActorChange: the downgraded self fails the scope-0 (admin) gate.
    function test_selfActorId_revert_scopedSelfCannotReauthorize(uint256 eoaPk, uint16 scope) public {
        eoaPk = _boundK1Pk(eoaPk);
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));
        scope = uint16(bound(uint256(scope), 1, 255)) & ~SCOPE_POLICY;
        vm.assume(scope != 0);

        _implicitAuthorizeActorWithScope(eoa, eoaPk, selfActorId, address(k1Authenticator), scope);

        Keystore.ActorChange[] memory ch = _authorizeChange(selfActorId, keystore.K1_AUTHENTICATOR(), 0, "");
        bytes memory auth = _authOver(eoa, eoaPk, ch);
        vm.expectRevert(Keystore.UnauthorizedActorChange.selector);
        keystore.applySignedActorChanges(eoa, uint64(block.chainid), ch, auth);
    }

    /// @notice A never-created EOA can apply a multichain (chainId 0) actor change via its implicit self key.
    function test_applySignedActorChanges_success_multichainImplicitEoa(uint256 eoaPk, bytes32 actorId) public {
        eoaPk = _boundK1Pk(eoaPk);
        address eoa = vm.addr(eoaPk);
        vm.assume(actorId != bytes32(bytes20(eoa)));

        Keystore.ActorChange[] memory ch = _authorizeChange(actorId, address(k1Authenticator), 0, "");
        uint64 seq = keystore.getChangeSequences(eoa).multichain;
        bytes32 digest = _computeActorChangeBatchDigest(eoa, 0, seq, ch);
        keystore.applySignedActorChanges(eoa, 0, ch, _buildK1Auth(eoaPk, digest));
        assertTrue(_isActor(eoa, actorId));
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

        assertFalse(_isActor(account, selfActorId));
        Keystore.ActorConfig memory cfg = keystore.getActorConfig(account, selfActorId);
        assertEq(cfg.authenticator, address(0));
        assertEq(cfg.scope, 0);
    }

    /// @notice An owner re-enables the default EOA by authorizing the self-actorId with the owner shape.
    function test_selfActorId_success_reEnableOnCreatedAccount(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        bytes32 selfActorId = bytes32(bytes20(account));
        assertFalse(_isActor(account, selfActorId));

        _authorizeActor(account, pk, selfActorId, keystore.K1_AUTHENTICATOR());

        assertTrue(_isActor(account, selfActorId));
        Keystore.ActorConfig memory cfg = keystore.getActorConfig(account, selfActorId);
        assertEq(cfg.authenticator, keystore.K1_AUTHENTICATOR());
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
        assertTrue(_isActor(eoa, selfActorId));

        _implicitAuthorizeActor(eoa, eoaPk, newActorId, address(k1Authenticator));
        _revokeActor(eoa, newPk, selfActorId);
        assertFalse(_isActor(eoa, selfActorId));

        vm.expectRevert();
        keystore.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));

        _authorizeActor(eoa, newPk, selfActorId, keystore.K1_AUTHENTICATOR());
        assertTrue(_isActor(eoa, selfActorId));

        (, uint16 scope) = keystore.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));
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
        assertTrue(_isActor(eoa, selfActorId));
        (, uint16 scope0) = keystore.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));
        assertEq(scope0, 0);

        // Phase 1: in one batch signed by the EOA, add the device key as a full owner and revoke the default EOA.
        Keystore.ActorChange[] memory switchChanges = new Keystore.ActorChange[](2);
        switchChanges[0] = _authorizeChange(deviceActorId, address(k1Authenticator), 0, "")[0];
        switchChanges[1] = Keystore.ActorChange({actorId: selfActorId, changeType: 0x02, data: ""});
        _signApply(eoa, eoaPk, switchChanges);

        assertFalse(_isActor(eoa, selfActorId));
        assertTrue(_isActor(eoa, deviceActorId));
        vm.expectRevert();
        keystore.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));
        (, uint16 scope1) = keystore.authenticateActor(eoa, hash, _buildK1Auth(devicePk, hash));
        assertEq(scope1, 0);

        // Phase 2: the device key re-enables the K1 key by authorizing the self-actorId as a native k1 owner.
        Keystore.ActorChange[] memory reEnable = _authorizeChange(selfActorId, keystore.K1_AUTHENTICATOR(), 0, "");
        _signApply(eoa, devicePk, reEnable);

        assertTrue(_isActor(eoa, selfActorId));
        (, uint16 scope2) = keystore.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));
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

        Keystore.ActorChange[] memory ch = new Keystore.ActorChange[](2);
        ch[0] = _authorizeChange(newActorId, address(k1Authenticator), 0, "")[0];
        ch[1] = Keystore.ActorChange({actorId: selfActorId, changeType: 0x02, data: ""});
        _signApply(eoa, eoaPk, ch);

        assertFalse(_isActor(eoa, selfActorId));
        assertTrue(_isActor(eoa, newActorId));

        Keystore.ActorConfig memory cfg = keystore.getActorConfig(eoa, selfActorId);
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

        Keystore.ActorChange[] memory ch = _authorizeChange(targetId, address(k1Authenticator), 0, "");
        uint64 seq = keystore.getChangeSequences(eoa).local;
        bytes32 digest = _computeActorChangeBatchDigest(eoa, uint64(block.chainid), seq, ch);

        vm.expectRevert();
        keystore.applySignedActorChanges(eoa, uint64(block.chainid), ch, _buildK1Auth(eoaPk, digest));

        keystore.applySignedActorChanges(eoa, uint64(block.chainid), ch, _buildK1Auth(newPk, digest));
        assertTrue(_isActor(eoa, targetId));
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

        Keystore.ActorChange[] memory ch = _authorizeChange(targetId, address(k1Authenticator), 0, "");
        bytes memory auth = _authOver(account, ownerPk, ch);
        vm.expectRevert();
        keystore.applySignedActorChanges(account, uint64(block.chainid), ch, auth);
    }

    /// @notice Revoking a non-self actor deletes its config slot.
    function test_revokeActor_success_deletesSlot(uint256 pk, bytes32 actorId) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));
        _authorizeActor(account, pk, actorId, address(k1Authenticator));

        _revokeActor(account, pk, actorId);

        Keystore.ActorConfig memory cfg = keystore.getActorConfig(account, actorId);
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

        Keystore.ActorChange[] memory changes =
            _authorizeChange(bytes32(bytes20(vm.addr(0xBEEF))), address(k1Authenticator), 0, "");
        bytes memory auth = _buildK1Auth(pk, _computeActorChangeBatchDigest(account, uint64(badChainId), 0, changes));

        vm.expectRevert(Keystore.InvalidChainId.selector);
        keystore.applySignedActorChanges(account, uint64(badChainId), changes, auth);
    }

    /// @notice Replaying an identical (changes, auth) pair fails once the sequence is consumed.
    /// @dev The replay recomputes the digest at seq+1, so the stale signature recovers a non-actor and reverts.
    function test_applySignedActorChanges_revert_replay(uint256 pk, bytes32 actorId) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        Keystore.ActorChange[] memory changes = _authorizeChange(actorId, address(k1Authenticator), 0, "");
        bytes memory auth = _authOver(account, pk, changes);

        keystore.applySignedActorChanges(account, uint64(block.chainid), changes, auth);

        vm.expectRevert();
        keystore.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
    }

    /// @notice A changeType outside {authorize, revoke} reverts with UnknownChangeType (after the scope-0 gate).
    function test_applySignedActorChanges_revert_unknownChangeType(uint256 pk, uint8 changeType) public {
        pk = _boundK1Pk(pk);
        vm.assume(changeType != 0x01 && changeType != 0x02);
        (address account,) = _createK1Account(pk);

        Keystore.ActorChange[] memory changes = new Keystore.ActorChange[](1);
        changes[0] =
            Keystore.ActorChange({actorId: bytes32(bytes20(vm.addr(0xBEEF))), changeType: changeType, data: ""});

        bytes memory auth = _authOver(account, pk, changes);
        vm.expectRevert(Keystore.UnknownChangeType.selector);
        keystore.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
    }

    /// @notice The admin gate: an authenticated actor may change actors iff its scope == 0.
    /// @dev Fuzzes the signer's scope (SCOPE_POLICY masked out) and asserts success only when scope is 0.
    function test_applySignedActorChanges_adminGate_acrossScopes(
        uint256 ownerPk,
        uint256 signerPk,
        uint16 signerScope,
        bytes32 targetId
    ) public {
        ownerPk = _boundK1Pk(ownerPk);
        signerPk = _boundK1Pk(signerPk);
        vm.assume(ownerPk != signerPk);
        (address account, bytes32 ownerId) = _createK1Account(ownerPk);
        bytes32 signerId = bytes32(bytes20(vm.addr(signerPk)));
        vm.assume(signerId != ownerId && signerId != bytes32(bytes20(account)));
        vm.assume(targetId != ownerId && targetId != signerId && targetId != bytes32(bytes20(account)));

        signerScope = signerScope & ~SCOPE_POLICY;
        _authorizeActorWithScope(account, ownerPk, signerId, address(k1Authenticator), signerScope);

        Keystore.ActorChange[] memory ch = _authorizeChange(targetId, address(k1Authenticator), 0, "");
        if (signerScope == 0) {
            _signApply(account, signerPk, ch);
            assertTrue(_isActor(account, targetId));
        } else {
            bytes memory auth = _authOver(account, signerPk, ch);
            vm.expectRevert(Keystore.UnauthorizedActorChange.selector);
            keystore.applySignedActorChanges(account, uint64(block.chainid), ch, auth);
        }
    }

    /// @notice Authorizing with a zero authenticator reverts with InvalidAuthenticator.
    function test_authorizeActor_revert_invalidAuthenticator(uint256 pk, bytes32 actorId) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        Keystore.ActorChange[] memory ch = _authorizeChange(actorId, address(0), 0, "");
        bytes memory auth = _authOver(account, pk, ch);
        vm.expectRevert(Keystore.InvalidAuthenticator.selector);
        keystore.applySignedActorChanges(account, uint64(block.chainid), ch, auth);
    }

    /// @notice An ungated actor (scope & SCOPE_POLICY == 0) with non-empty policyData reverts with InvalidPolicyData.
    function test_authorizeActor_revert_invalidPolicyData_ungatedWithData(
        uint256 pk,
        bytes32 actorId,
        bytes memory data
    ) public {
        pk = _boundK1Pk(pk);
        vm.assume(data.length != 0);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        Keystore.ActorChange[] memory ch = _authorizeChange(actorId, address(k1Authenticator), 0, data);
        bytes memory auth = _authOver(account, pk, ch);
        vm.expectRevert(Keystore.InvalidPolicyData.selector);
        keystore.applySignedActorChanges(account, uint64(block.chainid), ch, auth);
    }

    /// @notice A gated actor (scope & SCOPE_POLICY) whose policyData is not exactly 52 bytes reverts.
    function test_authorizeActor_revert_invalidPolicyData_gatedWrongLength(
        uint256 pk,
        bytes32 actorId,
        bytes memory data
    ) public {
        pk = _boundK1Pk(pk);
        vm.assume(data.length != 52);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        Keystore.ActorChange[] memory ch = _authorizeChange(actorId, address(k1Authenticator), SCOPE_POLICY, data);
        bytes memory auth = _authOver(account, pk, ch);
        vm.expectRevert(Keystore.InvalidPolicyData.selector);
        keystore.applySignedActorChanges(account, uint64(block.chainid), ch, auth);
    }

    /// @notice A gated actor with a zero manager and zero commitment is valid (relaxed policyData rule).
    /// @dev The 52-byte all-zero policyData is written verbatim; gating is by the SCOPE_POLICY bit.
    function test_authorizeActor_success_gatedZeroManagerAndCommitment(uint256 pk, bytes32 actorId) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        bytes memory data = abi.encodePacked(bytes20(address(0)), bytes32(0));
        Keystore.ActorChange[] memory ch = _authorizeChange(actorId, address(k1Authenticator), SCOPE_POLICY, data);
        _signApply(account, pk, ch);

        Keystore.ActorConfig memory cfg = keystore.getActorConfig(account, actorId);
        assertTrue(cfg.scope & SCOPE_POLICY != 0);
        assertEq(keystore.getPolicyManager(account, actorId), address(0));
        assertEq(keystore.getPolicyCommitment(account, actorId), bytes32(0));
    }

    /// @notice Duplicate actorIds within one batch apply sequentially (last operation wins).
    function test_applySignedActorChanges_success_duplicateActorIdInBatch(uint256 pk, bytes32 actorId) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        // [authorize A, revoke A] → A ends not live.
        Keystore.ActorChange[] memory ch = new Keystore.ActorChange[](2);
        ch[0] = _authorizeChange(actorId, address(k1Authenticator), 0, "")[0];
        ch[1] = Keystore.ActorChange({actorId: actorId, changeType: 0x02, data: ""});
        _signApply(account, pk, ch);
        assertFalse(_isActor(account, actorId));

        // Pre-authorize, then [revoke A, authorize A] → A ends live.
        _authorizeActor(account, pk, actorId, address(k1Authenticator));
        Keystore.ActorChange[] memory ch2 = new Keystore.ActorChange[](2);
        ch2[0] = Keystore.ActorChange({actorId: actorId, changeType: 0x02, data: ""});
        ch2[1] = _authorizeChange(actorId, address(k1Authenticator), 0, "")[0];
        _signApply(account, pk, ch2);
        assertTrue(_isActor(account, actorId));
    }

    /// @notice An unrestricted (scope 0) signer may revoke itself mid-batch; the scope gate is evaluated once,
    ///         pre-loop.
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

        _authorizeActor(account, ownerPk, signerId, address(k1Authenticator));

        Keystore.ActorChange[] memory ch = new Keystore.ActorChange[](2);
        ch[0] = Keystore.ActorChange({actorId: signerId, changeType: 0x02, data: ""});
        ch[1] = _authorizeChange(bId, address(k1Authenticator), 0, "")[0];
        _signApply(account, signerPk, ch);

        assertFalse(_isActor(account, signerId));
        assertTrue(_isActor(account, bId));
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

        // Implicit self authorizes an unrestricted admin (scope 0) to drive the flips.
        _implicitAuthorizeActor(eoa, eoaPk, adminId, address(k1Authenticator));

        // Flip self → non-k1 (p256): sets the revoke flag, stores the non-k1 self config; k1 self dies.
        _authorizeActorWithScope(eoa, adminPk, selfId, address(p256Authenticator), SCOPE_SENDER);
        assertEq(keystore.getActorConfig(eoa, selfId).authenticator, address(p256Authenticator));
        bytes32 h = keccak256("flip");
        vm.expectRevert();
        keystore.authenticateActor(eoa, h, _buildK1Auth(eoaPk, h));

        // Flip self → k1 owner: deletes the non-k1 config, restores inline k1 (flag cleared); k1 self lives again.
        _authorizeActor(eoa, adminPk, selfId, keystore.K1_AUTHENTICATOR());
        assertEq(keystore.getActorConfig(eoa, selfId).authenticator, keystore.K1_AUTHENTICATOR());
        (, uint16 scope) = keystore.authenticateActor(eoa, h, _buildK1Auth(eoaPk, h));
        assertEq(scope, 0);
    }

    /// @notice A happy-path authorize emits ActorAuthorized once with the correct account and actorId.
    function test_applySignedActorChanges_success_emitsActorAuthorized(uint256 pk, bytes32 actorId) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        Keystore.ActorChange[] memory ch = _authorizeChange(actorId, address(k1Authenticator), 0, "");
        vm.expectEmit(true, true, false, false, address(keystore));
        emit Keystore.ActorAuthorized(account, actorId, "");
        _signApply(account, pk, ch);
    }

    /// @notice A happy-path revoke emits ActorRevoked once with the correct account and actorId.
    function test_applySignedActorChanges_success_emitsActorRevoked(uint256 pk, bytes32 actorId) public {
        pk = _boundK1Pk(pk);
        (address account, bytes32 ownerId) = _createK1Account(pk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));
        _authorizeActor(account, pk, actorId, address(k1Authenticator));

        Keystore.ActorChange[] memory ch = new Keystore.ActorChange[](1);
        ch[0] = Keystore.ActorChange({actorId: actorId, changeType: 0x02, data: ""});
        vm.expectEmit(true, true, false, true, address(keystore));
        emit Keystore.ActorRevoked(account, actorId);
        _signApply(account, pk, ch);
    }

    // ── Helpers ──

    /// @dev Build a one-element authorize batch with a full ActorConfig + policyData (expiry fixed at 0).
    function _authorizeChange(bytes32 actorId, address auth, uint16 scope, bytes memory policyData)
        internal
        pure
        returns (Keystore.ActorChange[] memory changes)
    {
        changes = new Keystore.ActorChange[](1);
        changes[0] = Keystore.ActorChange({
            actorId: actorId,
            changeType: 0x01,
            data: abi.encode(Keystore.ActorConfig({authenticator: auth, scope: scope, expiry: 0}), policyData)
        });
    }

    /// @dev Owner/actor signature over a batch at the current local sequence.
    function _authOver(address account, uint256 pk, Keystore.ActorChange[] memory changes)
        internal
        view
        returns (bytes memory)
    {
        uint64 seq = keystore.getChangeSequences(account).local;
        return _buildK1Auth(pk, _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes));
    }

    /// @dev Sign (with pk) and apply a batch on the local chain.
    function _signApply(address account, uint256 pk, Keystore.ActorChange[] memory changes) internal {
        keystore.applySignedActorChanges(account, uint64(block.chainid), changes, _authOver(account, pk, changes));
    }

    /// @dev Authorize/overwrite the EOA's own inline k1 self-actorId with the given scope, signed by the EOA key.
    function _rescopeSelf(address eoa, uint256 eoaPk, uint16 scope) internal {
        Keystore.ActorChange[] memory changes = new Keystore.ActorChange[](1);
        changes[0] = Keystore.ActorChange({
            actorId: bytes32(bytes20(eoa)),
            changeType: 0x01,
            data: abi.encode(
                Keystore.ActorConfig({authenticator: keystore.K1_AUTHENTICATOR(), scope: scope, expiry: 0}), bytes("")
            )
        });
        uint64 seq = keystore.getChangeSequences(eoa).local;
        bytes32 digest = _computeActorChangeBatchDigest(eoa, uint64(block.chainid), seq, changes);
        keystore.applySignedActorChanges(eoa, uint64(block.chainid), changes, _buildK1Auth(eoaPk, digest));
    }

    function _authorizeActor(address account, uint256 pk, bytes32 newActorId, address authenticator) internal {
        _authorizeActorWithScope(account, pk, newActorId, authenticator, 0x00);
    }

    function _authorizeActorWithScope(
        address account,
        uint256 pk,
        bytes32 newActorId,
        address authenticator,
        uint16 scope
    ) internal {
        Keystore.ActorChange[] memory changes = new Keystore.ActorChange[](1);
        changes[0] = Keystore.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(Keystore.ActorConfig({authenticator: authenticator, scope: scope, expiry: 0}), bytes(""))
        });

        uint64 seq = keystore.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(pk, digest);

        keystore.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
    }

    function _revokeActor(address account, uint256 pk, bytes32 actorId) internal {
        Keystore.ActorChange[] memory changes = new Keystore.ActorChange[](1);
        changes[0] = Keystore.ActorChange({actorId: actorId, changeType: 0x02, data: ""});

        uint64 seq = keystore.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(pk, digest);

        keystore.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
    }

    function _implicitAuthorizeActor(address account, uint256 pk, bytes32 newActorId, address authenticator) internal {
        _implicitAuthorizeActorWithScope(account, pk, newActorId, authenticator, 0x00);
    }

    function _implicitAuthorizeActorWithScope(
        address account,
        uint256 pk,
        bytes32 newActorId,
        address authenticator,
        uint16 scope
    ) internal {
        Keystore.ActorChange[] memory changes = new Keystore.ActorChange[](1);
        changes[0] = Keystore.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(Keystore.ActorConfig({authenticator: authenticator, scope: scope, expiry: 0}), bytes(""))
        });

        uint64 seq = keystore.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(pk, digest);

        keystore.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
    }

    /// @dev Hard-lock `account` via the signed lock path, authorized by its admin owner key `pk`.
    function _lockAccount(uint256 pk, address account) internal {
        _signedLock(pk, account, 1 hours);
    }
}
