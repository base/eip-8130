// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore} from "../../../src/Keystore.sol";
import {Scopes} from "../../../src/libraries/Scopes.sol";
import {KeystoreTest} from "../../lib/KeystoreTest.sol";

/// @notice §10 test matrix for the authority / environment ops driven through {applySignedAccountChanges}:
///         AuthorizeActor (sequenced + unsequenced), RevokeActor, IncrementLocalEpoch, the op-ordering fence,
///         and the sequenced-channel replay/saturation edges. Lock/unlock (admin-only),
///         and multichain regression live in applyAccountChange.t.sol.
contract ApplySignedAccountChangesTest is KeystoreTest {
    // Non-self, non-owner actor ids: small distinct constants that never collide with a real (address-derived) actorId
    // used in these tests.
    bytes32 constant ACTOR_A = bytes32(uint256(0xA1));
    bytes32 constant ACTOR_B = bytes32(uint256(0xB2));

    uint16 constant SENDER = Scopes.SENDER;
    uint16 constant NONCE = Scopes.NONCE;

    function setUp() public override {
        super.setUp();
        // A non-zero base timestamp so `expiry <= block.timestamp` comparisons are meaningful.
        vm.warp(1_000_000);
    }

    function _future(uint48 delta) internal view returns (uint48) {
        return uint48(block.timestamp + delta);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // AUTHORIZE — UNSEQUENCED (JIT)
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice An unsequenced grant lands on an empty slot and does not consume the local sequence.
    function test_authorizeUnsequenced_success_happyPath(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        uint64 seqBefore = _localSeqWord(account);

        _applyUnsequenced(
            pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), ""))
        );

        Keystore.ActorConfig memory cfg = keystore.getActorConfig(account, ACTOR_A);
        assertEq(cfg.authenticator, address(k1Authenticator));
        assertEq(cfg.scope, SENDER);
        assertEq(cfg.expiry, _future(1 days));
        // Unsequenced batches never consume the counter.
        assertEq(_localSeqWord(account), seqBefore);
    }

    /// @notice Replaying an unsequenced grant that is still in the future is idempotent — it re-lands the same config
    ///         (no monotonicity gate; a grant is valid while its own expiry has not passed).
    function test_authorizeUnsequenced_success_replayIdempotent(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        uint48 expiry = _future(1 days);
        Keystore.SignedAccountChanges memory s = _signBatch(
            pk,
            account,
            Keystore.AccountChangeChannel.Local,
            _unseqWord(account),
            _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, expiry, ""))
        );
        keystore.applySignedAccountChanges(account, s);
        keystore.applySignedAccountChanges(account, s);

        Keystore.ActorConfig memory cfg = keystore.getActorConfig(account, ACTOR_A);
        assertEq(cfg.scope, SENDER);
        assertEq(cfg.expiry, expiry);
    }

    /// @notice A stale unsequenced (JIT) grant cannot clobber a renewed slot: once its granted expiry has passed the
    ///         replay is skipped (no-op, no revert), so re-authorizing the actor with a fresh expiry and then replaying
    ///         the old grant leaves the renewal intact — the "extend the lease, the old one can't apply overtop"
    ///         property, without needing an epoch bump.
    function test_authorizeUnsequenced_expiredReplay_doesNotClobberRenewal(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);

        uint48 shortExpiry = _future(1 days);
        Keystore.SignedAccountChanges memory oldLease = _signBatch(
            pk,
            account,
            Keystore.AccountChangeChannel.Local,
            _unseqWord(account),
            _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, shortExpiry, ""))
        );
        keystore.applySignedAccountChanges(account, oldLease);
        assertEq(keystore.getActorConfig(account, ACTOR_A).expiry, shortExpiry);

        // Lease lapses, then the actor is renewed with a longer expiry (epoch unchanged).
        vm.warp(uint256(shortExpiry) + 1);
        uint48 longExpiry = _future(365 days);
        _applyUnsequenced(
            pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, longExpiry, ""))
        );
        assertEq(keystore.getActorConfig(account, ACTOR_A).expiry, longExpiry);

        // Replaying the now-expired old lease is skipped: no revert, and the renewal is untouched.
        keystore.applySignedAccountChanges(account, oldLease);
        assertEq(keystore.getActorConfig(account, ACTOR_A).expiry, longExpiry);
    }

    /// @notice An unsequenced batch signed at a stale epoch reverts StaleEpoch.
    function test_authorizeUnsequenced_revert_wrongEpoch(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        // Pre-sign at epoch 0, then bump the epoch out from under it.
        Keystore.SignedAccountChanges memory s = _signBatch(
            pk,
            account,
            Keystore.AccountChangeChannel.Local,
            _unseqWord(account),
            _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), ""))
        );
        _applyUnsequenced(pk, account, _one(_bumpChange())); // epoch 0 -> 1

        vm.expectRevert(Keystore.StaleEpoch.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    /// @notice An unsequenced (JIT) grant whose expiry is not strictly in the future (expiry == now) is skipped, not
    ///         reverted: the batch succeeds but the actor is never written (contrast the sequenced path, which installs
    ///         it inert).
    function test_authorizeUnsequenced_pastExpiry_skippedNotApplied(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);

        // No revert despite the already-expired grant.
        _applyUnsequenced(
            pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, uint48(block.timestamp), ""))
        );

        // Skipped, not installed inert: the slot was never written, so an explicit revoke finds nothing.
        assertFalse(_isActor(account, ACTOR_A));
        Keystore.SignedAccountChanges memory revokeBatch = _unseqBatch(pk, account, _one(_revokeChange(ACTOR_A)));
        vm.expectRevert(Keystore.UnknownActor.selector);
        keystore.applySignedAccountChanges(account, revokeBatch);
    }

    /// @notice Partial application on the unsequenced (JIT) path: an already-expired grant is skipped while its live
    ///         siblings in the same batch still apply (skip is per-change, not whole-batch).
    function test_authorizeUnsequenced_mixedExpiredAndLive_appliesLiveOnly(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);

        Keystore.AccountChange[] memory changes = new Keystore.AccountChange[](2);
        changes[0] = _authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, uint48(block.timestamp), ""); // expired
        changes[1] = _authorizeChange(ACTOR_B, address(k1Authenticator), SENDER, _future(1 days), ""); // live

        _applyUnsequenced(pk, account, changes);

        assertFalse(_isActor(account, ACTOR_A)); // expired -> skipped
        assertTrue(_isActor(account, ACTOR_B)); // live -> applied
    }

    /// @notice An unsequenced grant may request the unbounded (max) expiry.
    function test_authorizeUnsequenced_success_unboundedExpiry(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);

        _applyUnsequenced(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, UNBOUNDED, "")));
        assertEq(keystore.getActorConfig(account, ACTOR_A).expiry, UNBOUNDED);
    }

    /// @notice A grant may use expiry 0, the "no expiry" sentinel: it lands and never lapses.
    function test_authorizeUnsequenced_success_zeroExpiryUnlimited(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);

        _applyUnsequenced(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, 0, "")));
        assertEq(keystore.getActorConfig(account, ACTOR_A).expiry, 0);

        // Never lapses: still authorized far in the future.
        vm.warp(block.timestamp + 3650 days);
        assertTrue(_isActor(account, ACTOR_A));
        assertEq(keystore.getActorConfig(account, ACTOR_A).authenticator, address(k1Authenticator));
    }

    /// @notice An unsequenced upsert may change an occupied slot's scope (last-write-wins, no sequencing gate).
    function test_authorizeUnsequenced_success_scopeChangeOnOccupied(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        _applyUnsequenced(
            pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), ""))
        );

        _applyUnsequenced(
            pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), NONCE, _future(2 days), ""))
        );
        assertEq(keystore.getActorConfig(account, ACTOR_A).scope, NONCE);
        assertEq(keystore.getActorConfig(account, ACTOR_A).expiry, _future(2 days));
    }

    /// @notice Unsequenced upserts are last-write-wins: the final applied grant's expiry stands, regardless of order.
    function test_authorizeUnsequenced_lastWriteWins(uint256 pk) public {
        pk = _boundK1Pk(pk);
        uint48 t1 = _future(1 days);
        uint48 t2 = _future(2 days);

        // Order (T1, T2): ends at T2.
        (address accA,) = _createK1Account(pk);
        _applyUnsequenced(pk, accA, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, t1, "")));
        _applyUnsequenced(pk, accA, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, t2, "")));
        assertEq(keystore.getActorConfig(accA, ACTOR_A).expiry, t2);

        // Order (T2, T1): ends at T1 (last write wins; a shorter expiry is allowed).
        (address accB,) = _createK1AccountWithSalt(pk, bytes32(uint256(1)));
        _applyUnsequenced(pk, accB, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, t2, "")));
        _applyUnsequenced(pk, accB, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, t1, "")));
        assertEq(keystore.getActorConfig(accB, ACTOR_A).expiry, t1);
    }

    /// @notice A different authenticator under the same actorId is not possible (id derives from the authenticator);
    ///         two distinct actorIds land in two independent slots.
    function test_authorize_success_distinctSlots(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);

        _applyUnsequenced(
            pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), ""))
        );
        _applyUnsequenced(
            pk, account, _one(_authorizeChange(ACTOR_B, address(p256Authenticator), SENDER, _future(1 days), ""))
        );

        assertEq(keystore.getActorConfig(account, ACTOR_A).authenticator, address(k1Authenticator));
        assertEq(keystore.getActorConfig(account, ACTOR_B).authenticator, address(p256Authenticator));
    }

    /// @notice AuthorizeActor targeting the zero actorId reverts InvalidActorId: bytes32(0) is not a usable actor
    ///         identifier (every real id is a non-zero hash, or the non-zero self).
    function test_authorize_revert_zeroActorId(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);

        Keystore.SignedAccountChanges memory s = _localBatch(
            pk, account, _one(_authorizeChange(bytes32(0), address(k1Authenticator), SENDER, _future(1 days), ""))
        );
        vm.expectRevert(Keystore.InvalidActorId.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // AUTHORIZE — SEQUENCED
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice A sequenced batch consumes the local sequence (low half) and preserves the epoch.
    function test_authorizeSequenced_success_consumesSequence(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        (uint32 epoch0, uint32 seq0) = _localEpochSeq(account);

        _applyLocal(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), "")));

        (uint32 epoch1, uint32 seq1) = _localEpochSeq(account);
        assertEq(epoch1, epoch0);
        assertEq(seq1, seq0 + 1);
    }

    /// @notice A sequenced reinstall over a lapsed slot (later expiry, same scope) is bump-free.
    function test_authorizeSequenced_success_reinstallOverLapsed(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        uint48 e1 = _future(1 days);
        _applyLocal(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, e1, "")));

        vm.warp(uint256(e1) + 1);
        assertFalse(_isActor(account, ACTOR_A)); // lapsed

        uint48 e2 = _future(1 days);
        _applyLocal(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, e2, "")));
        assertTrue(_isActor(account, ACTOR_A));
        assertEq(keystore.getActorConfig(account, ACTOR_A).expiry, e2);
    }

    /// @notice A sequenced scope widen (adding grant bits) is bump-free.
    function test_authorizeSequenced_success_scopeWidenBumpFree(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        uint48 e = _future(10 days);
        _applyLocal(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, e, "")));

        _applyLocal(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER | NONCE, e, "")));
        assertEq(keystore.getActorConfig(account, ACTOR_A).scope, SENDER | NONCE);
    }

    /// @notice A sequenced expiry raise is bump-free.
    function test_authorizeSequenced_success_expiryRaiseBumpFree(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        _applyLocal(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), "")));

        uint48 higher = _future(5 days);
        _applyLocal(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, higher, "")));
        assertEq(keystore.getActorConfig(account, ACTOR_A).expiry, higher);
    }

    /// @notice A sequenced expiry lowering lands on its own (reduction is not contract-enforced to bump).
    function test_authorizeSequenced_success_expiryLower(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        _applyLocal(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(5 days), "")));

        uint48 lower = _future(1 days);
        _applyLocal(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, lower, "")));
        assertEq(keystore.getActorConfig(account, ACTOR_A).expiry, lower);
    }

    /// @notice A sequenced scope narrowing lands on its own (reduction is not contract-enforced to bump).
    function test_authorizeSequenced_success_scopeNarrow(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        uint48 e = _future(10 days);
        _applyLocal(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER | NONCE, e, "")));

        _applyLocal(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, e, "")));
        assertEq(keystore.getActorConfig(account, ACTOR_A).scope, SENDER);
    }

    /// @notice A sequenced expiry lowering may still be batched with an IncrementLocalEpoch (the durable teardown form).
    function test_authorizeSequenced_success_lowerPlusBump(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        _applyLocal(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(5 days), "")));

        uint48 lower = _future(1 days);
        Keystore.AccountChange[] memory ch = new Keystore.AccountChange[](2);
        ch[0] = _authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, lower, "");
        ch[1] = _bumpChange();
        _applyLocal(pk, account, ch);

        assertEq(keystore.getActorConfig(account, ACTOR_A).expiry, lower);
        (uint32 epoch,) = _localEpochSeq(account);
        assertEq(epoch, 1);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // REVOKE
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice A bare revoke of a live actor lands and clears the slot (reduction is not contract-enforced to bump).
    function test_revoke_success_bareRevokeOfLiveActor(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        _applyLocal(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), "")));

        _applyLocal(pk, account, _one(_revokeChange(ACTOR_A)));
        assertFalse(_isActor(account, ACTOR_A));
    }

    /// @notice Documents the accepted footgun: a bare revoke is NOT durable while a replayable unsequenced grant for
    ///         the same actor is outstanding — replaying it re-installs the actor into the emptied slot. Durable
    ///         teardown requires an IncrementLocalEpoch (see test_revoke_success_revokeBumpThenReplayFails).
    function test_revoke_bareRevokeNotDurable_replayReinstalls(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);

        // An outstanding unsequenced grant for ACTOR_A, captured before it first lands.
        Keystore.SignedAccountChanges memory grant = _signBatch(
            pk,
            account,
            Keystore.AccountChangeChannel.Local,
            _unseqWord(account),
            _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), ""))
        );
        keystore.applySignedAccountChanges(account, grant);
        assertTrue(_isActor(account, ACTOR_A));

        // Bare revoke lands...
        _applyLocal(pk, account, _one(_revokeChange(ACTOR_A)));
        assertFalse(_isActor(account, ACTOR_A));

        // ...but the epoch never moved, so the original grant replays straight back into the emptied slot.
        keystore.applySignedAccountChanges(account, grant);
        assertTrue(_isActor(account, ACTOR_A));
    }

    /// @notice `[revoke, bump]` succeeds; a pre-signed authorize at the old epoch then dies on StaleEpoch.
    function test_revoke_success_revokeBumpThenReplayFails(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        _applyLocal(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), "")));

        // A grant signed at the pre-bump epoch (unsequenced), captured before the revoke+bump lands.
        Keystore.SignedAccountChanges memory oldGrant = _signBatch(
            pk,
            account,
            Keystore.AccountChangeChannel.Local,
            _unseqWord(account),
            _one(_authorizeChange(ACTOR_B, address(k1Authenticator), SENDER, _future(1 days), ""))
        );

        Keystore.AccountChange[] memory ch = new Keystore.AccountChange[](2);
        ch[0] = _revokeChange(ACTOR_A);
        ch[1] = _bumpChange();
        _applyLocal(pk, account, ch);
        assertFalse(_isActor(account, ACTOR_A));

        vm.expectRevert(Keystore.StaleEpoch.selector);
        keystore.applySignedAccountChanges(account, oldGrant);
    }

    /// @notice Revoking an already-lapsed actor is GC-equivalent and lands as a bare single-op batch.
    function test_revoke_success_lapsedActorNoBump(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        uint48 e = _future(1 days);
        _applyLocal(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, e, "")));

        vm.warp(uint256(e) + 1);
        _applyLocal(pk, account, _one(_revokeChange(ACTOR_A))); // no bump needed
        assertFalse(_isActor(account, ACTOR_A));
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // BUMP LOCAL EPOCH
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice An unsequenced solo bump increments the epoch and resets the sequence to 0.
    function test_bump_success_unsequencedSolo(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        // Consume a sequence first so we can observe the reset.
        _applyLocal(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), "")));
        (uint32 epoch0,) = _localEpochSeq(account);

        _applyUnsequenced(pk, account, _one(_bumpChange()));

        (uint32 epoch1, uint32 seq1) = _localEpochSeq(account);
        assertEq(epoch1, epoch0 + 1);
        assertEq(seq1, 0);
    }

    /// @notice An unsequenced bump may be batched with other ops (no solo rule): `[authorize, bump]` lands.
    function test_bump_success_unsequencedNonSolo(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        Keystore.AccountChange[] memory ch = new Keystore.AccountChange[](2);
        ch[0] = _authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), "");
        ch[1] = _bumpChange();

        _applyUnsequenced(pk, account, ch);

        assertTrue(_isActor(account, ACTOR_A));
        (uint32 epoch, uint32 seq) = _localEpochSeq(account);
        assertEq(epoch, 1);
        assertEq(seq, 0);
    }

    /// @notice Two independently signed unsequenced bumps at the same epoch: the first lands, the second dies on
    ///         StaleEpoch.
    function test_bump_success_twoSignedBumpsSecondFails(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        uint64 word = _unseqWord(account);
        Keystore.SignedAccountChanges memory b1 =
            _signBatch(pk, account, Keystore.AccountChangeChannel.Local, word, _one(_bumpChange()));
        Keystore.SignedAccountChanges memory b2 =
            _signBatch(pk, account, Keystore.AccountChangeChannel.Local, word, _one(_bumpChange()));

        keystore.applySignedAccountChanges(account, b1);
        vm.expectRevert(Keystore.StaleEpoch.selector);
        keystore.applySignedAccountChanges(account, b2);
    }

    /// @notice A sequenced batch may interleave an environment op before an authority op: `[bump, authorize]` bumps
    ///         the epoch (resetting the sequence) and then installs the actor in the same batch. There is no
    ///         authority-before-environment ordering constraint (the two op classes commute).
    function test_bump_success_sequencedNonTerminal(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        Keystore.AccountChange[] memory ch = new Keystore.AccountChange[](2);
        ch[0] = _bumpChange();
        ch[1] = _authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), "");

        Keystore.SignedAccountChanges memory s = _localBatch(pk, account, ch);
        keystore.applySignedAccountChanges(account, s);

        (uint32 epoch, uint32 seq) = _localEpochSeq(account);
        assertEq(epoch, 1);
        assertEq(seq, 0);
        assertTrue(_isActor(account, ACTOR_A));
        assertEq(keystore.getActorConfig(account, ACTOR_A).scope, SENDER);
    }

    /// @notice A bump at the terminal epoch (the full uint32 max — the epoch half reserves no sentinel) reverts
    ///         EpochSaturated.
    function test_bump_revert_epochSaturated(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        _forceLocalEpoch(account, type(uint32).max);

        Keystore.SignedAccountChanges memory s = _localBatch(pk, account, _one(_bumpChange()));
        vm.expectRevert(Keystore.EpochSaturated.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    /// @notice A bump does not disturb already-landed actors.
    function test_bump_success_landedActorsUnaffected(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        _applyLocal(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), "")));

        _applyUnsequenced(pk, account, _one(_bumpChange()));

        assertTrue(_isActor(account, ACTOR_A));
        assertEq(keystore.getActorConfig(account, ACTOR_A).scope, SENDER);
    }

    /// @notice Post-bump, an old unsequenced signature on the local channel is invalid (StaleEpoch).
    function test_bump_success_oldLocalSignatureInvalid(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        Keystore.SignedAccountChanges memory stale = _signBatch(
            pk,
            account,
            Keystore.AccountChangeChannel.Local,
            _unseqWord(account),
            _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), ""))
        );
        _applyUnsequenced(pk, account, _one(_bumpChange()));

        vm.expectRevert(Keystore.StaleEpoch.selector);
        keystore.applySignedAccountChanges(account, stale);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // ORDERING / BATCHING
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice `[lock, revoke]` reverts LockChangeMustBeStandalone: a Lock may not share a batch with any other change.
    function test_ordering_revert_lockNotStandalone(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        _applyLocal(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), "")));

        Keystore.AccountChange[] memory ch = new Keystore.AccountChange[](2);
        ch[0] = _lockChange(1 hours);
        ch[1] = _revokeChange(ACTOR_A);

        Keystore.SignedAccountChanges memory s = _localBatch(pk, account, ch);
        vm.expectRevert(Keystore.LockChangeMustBeStandalone.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    /// @notice `[revoke, bump]` succeeds: an authority op and an environment op (epoch increment) still freely share a
    ///         batch — only Lock/Unlock are standalone — and the revoke is retired durably by the bump.
    function test_ordering_success_revokeThenBump(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        _applyLocal(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), "")));

        Keystore.AccountChange[] memory ch = new Keystore.AccountChange[](2);
        ch[0] = _revokeChange(ACTOR_A);
        ch[1] = _bumpChange();
        _applyLocal(pk, account, ch);

        assertFalse(_isActor(account, ACTOR_A));
        (uint32 epoch,) = _localEpochSeq(account);
        assertEq(epoch, 1);
    }

    /// @notice `[unlock, bump]` reverts LockChangeMustBeStandalone: an Unlock may not share a batch with any other
    ///         change, even an environment op. Unlocking then bumping requires two separate signed batches.
    function test_unlock_revert_notStandalone(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        _signedLock(pk, account, 1 hours);

        Keystore.AccountChange[] memory ch = new Keystore.AccountChange[](2);
        ch[0] = _unlockChange();
        ch[1] = _bumpChange();

        Keystore.SignedAccountChanges memory s = _localBatch(pk, account, ch);
        vm.expectRevert(Keystore.LockChangeMustBeStandalone.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // SEQUENCED CHANNEL EDGES
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice A sequenced batch at the terminal local sequence (UNSEQUENCED - 1) reverts SequenceSaturated.
    function test_sequenced_revert_saturationAtMaxMinusOne(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        _forceLocalSequence(account, keystore.UNSEQUENCED() - 1);

        Keystore.SignedAccountChanges memory s = _localBatch(
            pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), ""))
        );
        vm.expectRevert(Keystore.SequenceSaturated.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    /// @notice The sequence advances BEFORE apply, so re-submitting the exact same sequenced batch reverts BadSequence.
    function test_sequenced_revert_replaySameBatch(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        Keystore.SignedAccountChanges memory s = _signBatch(
            pk,
            account,
            Keystore.AccountChangeChannel.Local,
            _localSeqWord(account),
            _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), ""))
        );

        (, uint32 seqSigned) = _localEpochSeq(account);
        keystore.applySignedAccountChanges(account, s);
        // The first apply advanced localSequence past the value the batch was signed at.
        vm.expectRevert(abi.encodeWithSelector(Keystore.BadSequence.selector, uint64(seqSigned + 1), uint64(seqSigned)));
        keystore.applySignedAccountChanges(account, s);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // EVENTS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice A happy-path authorize emits ActorAuthorized(account, actorId, ...).
    function test_authorize_success_emitsActorAuthorized(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);

        vm.expectEmit(true, true, false, false, address(keystore));
        emit Keystore.ActorAuthorized(account, ACTOR_A, "");
        _applyLocal(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), "")));
    }

    /// @notice Right-aligned actorId round-trip. An address-derived actor's id is the address right-aligned
    ///         (ActorId.fromAddress: bytes32(uint256(uint160(addr))), high 12 bytes zero). The emitted ActorAuthorized
    ///         indexed topic therefore decodes back to the address via the standard address(uint160(uint256(id)))
    ///         round-trip that off-chain indexers rely on, and the on-chain k1 derivation resolves the very same id.
    function test_authorize_success_rightAlignedActorIdRoundTrip(uint256 pk, uint256 actorSeed) public {
        pk = _boundK1Pk(pk);
        uint256 actorPk = _boundK1Pk(actorSeed);
        (address account,) = _createK1Account(pk);
        address actorAddr = vm.addr(actorPk);
        vm.assume(actorAddr != account);

        bytes32 actorId = bytes32(uint256(uint160(actorAddr))); // right-aligned, high 12 bytes zero

        // The indexed topic equals the right-aligned id.
        vm.expectEmit(true, true, false, false, address(keystore));
        emit Keystore.ActorAuthorized(account, actorId, "");
        _applyLocal(pk, account, _one(_authorizeChange(actorId, address(k1Authenticator), 0x00, UNBOUNDED, "")));

        // Round-trip: the id decodes back to the address and carries no high bytes.
        assertEq(address(uint160(uint256(actorId))), actorAddr);
        assertEq(uint256(actorId) >> 160, 0);

        // The on-chain k1 derivation (recovered signer -> actorId) agrees with the wallet-side derivation.
        bytes32 hash = keccak256("round-trip");
        (bytes32 resolvedId,) = keystore.authenticateActor(account, hash, _buildK1Auth(actorPk, hash));
        assertEq(resolvedId, actorId);
    }

    /// @notice A `[revoke, bump]` batch emits ActorRevoked(account, actorId).
    function test_revoke_success_emitsActorRevoked(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        _applyLocal(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), "")));

        Keystore.AccountChange[] memory ch = new Keystore.AccountChange[](2);
        ch[0] = _revokeChange(ACTOR_A);
        ch[1] = _bumpChange();

        vm.expectEmit(true, true, false, true, address(keystore));
        emit Keystore.ActorRevoked(account, ACTOR_A);
        _applyLocal(pk, account, ch);
    }
}
