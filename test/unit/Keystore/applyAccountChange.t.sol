// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore} from "../../../src/Keystore.sol";
import {Scopes} from "../../../src/libraries/Scopes.sol";
import {KeystoreTest} from "../../lib/KeystoreTest.sol";

/// @notice §10 test matrix for the account-environment surface driven through {applySignedAccountChanges}: the lock
///         / unlock ops (admin-authorized), the Multichain channel (no epochs, no unsequenced mode), and the
///         split-layout regression checks.
contract AccountEnvironmentTest is KeystoreTest {
    bytes32 constant ACTOR_A = bytes32(uint256(0xA1));
    bytes32 constant ACTOR_B = bytes32(uint256(0xB2));

    uint16 constant SENDER = Scopes.SENDER;

    function setUp() public override {
        super.setUp();
        vm.warp(1_000_000);
    }

    function _future(uint48 delta) internal view returns (uint48) {
        return uint48(block.timestamp + delta);
    }

    function _assumeSafeAccount(address account) internal view {
        vm.assume(account != address(0));
        vm.assume(account != address(keystore));
        vm.assume(account != VM_ADDRESS);
        vm.assume(account != CONSOLE);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // LOCK / UNLOCK
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice A lock op hard-locks the account (delay stored, isLocked true, max-sentinel unlocksAt).
    function test_lock_success_setsHardLock(uint256 pkSeed, uint16 delay) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));

        _signedLock(pk, account, delay);

        (bool locked, bool init, uint48 unlocksAt, uint16 storedDelay) = keystore.getLockStatus(account);
        assertTrue(locked);
        assertFalse(init);
        assertEq(unlocksAt, type(uint48).max);
        assertEq(storedDelay, delay);
        assertTrue(keystore.isLocked(account));
    }

    /// @notice A lock op emits AccountLocked(account, delay).
    function test_lock_success_emitsAccountLocked(uint256 pkSeed, uint16 delay) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));

        vm.expectEmit(true, false, false, true, address(keystore));
        emit Keystore.AccountLocked(account, delay);
        _signedLock(pk, account, delay);
    }

    /// @notice A lock op with a zero unlock delay reverts ZeroUnlockDelay.
    function test_lock_revert_zeroDelay(uint256 pkSeed) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);

        Keystore.SignedAccountChanges memory s = _localBatch(pk, account, _one(_lockChange(0)));
        vm.expectRevert(Keystore.ZeroUnlockDelay.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    /// @notice A second lock while already hard-locked reverts AccountIsLocked.
    function test_lock_revert_whenAlreadyLocked(uint256 pkSeed, uint16 d1, uint16 d2) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);
        d1 = uint16(bound(d1, 1, type(uint16).max));
        d2 = uint16(bound(d2, 1, type(uint16).max));

        _signedLock(pk, account, d1);
        Keystore.SignedAccountChanges memory s = _localBatch(pk, account, _one(_lockChange(d2)));
        vm.expectRevert(Keystore.AccountIsLocked.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    /// @notice `[Lock, Unlock, Lock]` reverts LockChangeMustBeStandalone: the standalone rule rejects the multi-op
    ///         batch on its first (Lock) change. Because a lock transition can never interleave with another change
    ///         in one batch, a lock/unlock desync is structurally impossible.
    function test_lock_revert_lockUnlockLockSameBatch(uint256 pkSeed, uint16 d1, uint16 d2) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);
        d1 = uint16(bound(d1, 1, type(uint16).max));
        d2 = uint16(bound(d2, 1, type(uint16).max));

        Keystore.AccountChange[] memory ch = new Keystore.AccountChange[](3);
        ch[0] = _lockChange(d1);
        ch[1] = _unlockChange();
        ch[2] = _lockChange(d2);

        Keystore.SignedAccountChanges memory s = _localBatch(pk, account, ch);
        vm.expectRevert(Keystore.LockChangeMustBeStandalone.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    /// @notice An unlock on a never-locked account reverts NotLocked.
    function test_unlock_revert_whenNeverLocked(uint256 pkSeed) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);

        Keystore.SignedAccountChanges memory s = _localBatch(pk, account, _one(_unlockChange()));
        vm.expectRevert(Keystore.NotLocked.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    /// @notice An unlock op sets unlocksAt = now + delay, zeroes the stored delay, emits AccountUnlockInitiated.
    function test_unlock_success_initiates(uint256 pkSeed, uint16 delay, uint256 t0) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));
        t0 = bound(t0, block.timestamp, 1e12);

        _signedLock(pk, account, delay);
        vm.warp(t0);

        vm.expectEmit(true, false, false, true, address(keystore));
        emit Keystore.AccountUnlockInitiated(account, uint48(t0 + delay));
        _signedUnlock(pk, account);

        (bool locked, bool init, uint48 unlocksAt, uint16 storedDelay) = keystore.getLockStatus(account);
        assertTrue(locked);
        assertTrue(init);
        assertEq(unlocksAt, uint48(t0 + delay));
        assertEq(storedDelay, 0);
    }

    /// @notice A second unlock after one was already initiated reverts NotLocked.
    function test_unlock_revert_whenAlreadyInitiated(uint256 pkSeed, uint16 delay, uint256 t0) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));
        t0 = bound(t0, block.timestamp, 1e9);

        _signedLock(pk, account, delay);
        vm.warp(t0);
        _signedUnlock(pk, account);

        Keystore.SignedAccountChanges memory s = _localBatch(pk, account, _one(_unlockChange()));
        vm.expectRevert(Keystore.NotLocked.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    /// @notice An account can be re-locked once a prior unlock delay has fully elapsed.
    function test_lock_success_relockAfterUnlockElapsed(uint256 pkSeed, uint16 d1, uint16 d2, uint256 t0) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);
        d1 = uint16(bound(d1, 1, type(uint16).max));
        d2 = uint16(bound(d2, 1, type(uint16).max));
        t0 = bound(t0, block.timestamp, 1e9);

        _signedLock(pk, account, d1);
        vm.warp(t0);
        _signedUnlock(pk, account);
        vm.warp(t0 + d1); // at unlocksAt: unlocked
        assertFalse(keystore.isLocked(account));

        _signedLock(pk, account, d2);
        assertTrue(keystore.isLocked(account));
    }

    /// @notice While locked, an authority op (authorize) reverts AccountIsLocked but an environment op (bump)
    ///         succeeds — the lock freezes the actor set, not the epoch.
    function test_lock_bumpSucceedsAuthorizeFails(uint256 pkSeed) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);

        _signedLock(pk, account, 1 hours);

        // Bump under lock: allowed.
        _applyLocal(pk, account, _one(_bumpChange()));
        (uint32 epoch,) = _localEpochSeq(account);
        assertEq(epoch, 1);

        // Authorize under lock: rejected.
        Keystore.SignedAccountChanges memory s = _localBatch(
            pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), ""))
        );
        vm.expectRevert(Keystore.AccountIsLocked.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    /// @notice After a full unlock cycle elapses, an authority op is accepted again (lazy lock clear).
    function test_lock_success_authorizeAfterFullUnlockCycle(uint256 pkSeed, uint16 delay, uint256 t0) public {
        uint256 pk = _boundK1Pk(pkSeed);
        (address account,) = _createK1Account(pk);
        delay = uint16(bound(delay, 1, type(uint16).max));
        t0 = bound(t0, block.timestamp, 1e9);

        _signedLock(pk, account, delay);
        vm.warp(t0);
        _signedUnlock(pk, account);
        vm.warp(t0 + delay); // unlocked
        assertFalse(keystore.isLocked(account));

        _applyLocal(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), "")));
        assertTrue(_isActor(account, ACTOR_A));
    }

    /// @notice Lock-residue overwrite. A full lock -> initiate-unlock -> elapse cycle leaves FLAG_UNLOCK_INITIATED set
    ///         and a now-elapsed unlocksAt in storage (lock reads never clear them). A fresh Lock over that residue must
    ///         land a CLEAN hard-lock: FLAG_LOCKED set, FLAG_UNLOCK_INITIATED clear (init == false), and lockUnion
    ///         holding the NEW delay rather than the stale timestamp. This pins the load-bearing `& ~FLAG_UNLOCK_INITIATED`
    ///         clear in _applyLock: dropping it would leave a delay-valued union under a set INITIATED flag (the
    ///         union-corruption bug).
    function test_lock_success_overwritesElapsedUnlockResidue(uint256 pkSeed, uint16 d1, uint16 d2, uint256 t0) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);
        d1 = uint16(bound(d1, 1, type(uint16).max));
        d2 = uint16(bound(d2, 1, type(uint16).max));
        t0 = bound(t0, block.timestamp, 1e9);

        // Lock, initiate unlock, and let the delay fully elapse. Storage residue now reads unlocked but still carries
        // FLAG_LOCKED | FLAG_UNLOCK_INITIATED with an elapsed timestamp in lockUnion.
        _signedLock(pk, account, d1);
        vm.warp(t0);
        _signedUnlock(pk, account);
        vm.warp(t0 + d1);
        assertFalse(keystore.isLocked(account));

        // Re-lock over the residue.
        _signedLock(pk, account, d2);

        // Clean hard-lock: INITIATED cleared and the union holds the new delay (surfaced as storedDelay), not the
        // stale timestamp.
        (bool locked, bool init, uint48 unlocksAt, uint16 storedDelay) = keystore.getLockStatus(account);
        assertTrue(locked);
        assertFalse(init);
        assertEq(unlocksAt, type(uint48).max);
        assertEq(storedDelay, d2);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // ADMIN-ONLY LOCK CHANGES
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice A scoped (non-admin) actor cannot initiate an Unlock — every signed change is admin-only
    ///         (UnauthorizedAccountChange).
    function test_lock_revert_scopedActorCannotUnlock(uint256 ownerSeed, uint256 scopedSeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 scopedPk = _boundK1Pk(scopedSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(scopedPk));
        (address account,) = _createK1Account(ownerPk);
        bytes32 scopedId = bytes32(uint256(uint160(vm.addr(scopedPk))));

        _applyLocal(ownerPk, account, _one(_authorizeChange(scopedId, address(k1Authenticator), SENDER, UNBOUNDED, "")));
        _signedLock(ownerPk, account, 1 hours);
        assertTrue(keystore.isLocked(account));

        Keystore.SignedAccountChanges memory s = _localBatch(scopedPk, account, _one(_unlockChange()));
        vm.expectRevert(Keystore.UnauthorizedAccountChange.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // MULTICHAIN CHANNEL
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice A Multichain authorize consumes only the multichain counter and leaves the local word untouched.
    function test_multichain_success_authorize(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        uint64 localBefore = _localSeqWord(account);
        uint64 mcBefore = _multichainSeq(account);

        _applyMultichain(
            pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), ""))
        );

        assertTrue(_isActor(account, ACTOR_A));
        assertEq(_localSeqWord(account), localBefore); // local channel untouched
        assertEq(_multichainSeq(account), mcBefore + 1);
    }

    /// @notice An IncrementLocalEpoch on the Multichain channel reverts ChangeRequiresLocalChannel.
    function test_multichain_revert_bumpRejected(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);

        Keystore.SignedAccountChanges memory s = _multichainBatch(pk, account, _one(_bumpChange()));
        vm.expectRevert(Keystore.ChangeRequiresLocalChannel.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    /// @notice A Lock on the Multichain channel reverts ChangeRequiresLocalChannel.
    function test_multichain_revert_lockRejected(uint256 pk, uint16 delay) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        delay = uint16(bound(delay, 1, type(uint16).max));

        Keystore.SignedAccountChanges memory s = _multichainBatch(pk, account, _one(_lockChange(delay)));
        vm.expectRevert(Keystore.ChangeRequiresLocalChannel.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    /// @notice an Unlock on the Multichain channel reverts ChangeRequiresLocalChannel.
    function test_multichain_revert_unlockRejected(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);

        Keystore.SignedAccountChanges memory s = _multichainBatch(pk, account, _one(_unlockChange()));
        vm.expectRevert(Keystore.ChangeRequiresLocalChannel.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // REGRESSION (split layout / deleted entry points)
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice A freshly created account starts at epoch 0, sequence 1 (the non-zero initialized flag) with a zero
    ///         multichain counter.
    function test_regression_initFlagUnderSplitLayout(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);

        (uint32 epoch, uint32 seq) = _localEpochSeq(account);
        assertEq(epoch, 0);
        assertEq(seq, 1);
        assertEq(keystore.getChangeSequences(account).localSequence, 1);
        assertEq(keystore.getChangeSequences(account).multichain, 0);
    }

    /// @notice The deleted entry points (applySignedActorChanges / applySignedLockChanges) are absent from the ABI —
    ///         a call to their old selector finds no function and reverts.
    function test_regression_deletedEntryPointsAbsent(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);

        (bool ok1,) = address(keystore)
            .call(
                abi.encodeWithSignature(
                    "applySignedLockChanges(address,uint8,uint16,bytes)", account, uint8(1), uint16(3600), bytes("")
                )
            );
        assertFalse(ok1);

        (bool ok2,) = address(keystore)
            .call(
                abi.encodeWithSignature(
                    "applySignedActorChanges(address,uint64,bytes,bytes)", account, uint64(0), bytes(""), bytes("")
                )
            );
        assertFalse(ok2);
    }

    /// @notice Regression: an IncrementLocalEpoch zeroes localSequence, but the account must still read as
    ///         initialized (localEpoch is now non-zero) so the one-time importAccount bootstrap stays closed. Prior
    ///         to the fix, _isInitialized checked localSequence alone, so a post-increment local-only account looked
    ///         uninitialized and importAccount would re-bootstrap on top of the live actor set.
    function test_regression_importBlockedAfterEpochIncrement(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);

        // Increment the epoch: localSequence -> 0, localEpoch -> 1 (both counters no longer trivially non-zero on the
        // sequence half).
        _applyLocal(pk, account, _one(_bumpChange()));
        (uint32 epoch, uint32 seq) = _localEpochSeq(account);
        assertEq(epoch, 1);
        assertEq(seq, 0);

        // importAccount must still reject the account as already initialized. The check fires before the ERC-1271
        // staticcall, so the empty signature is never reached.
        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](1);
        actors[0] = Keystore.InitialActor({
            actorId: bytes32(uint256(uint160(account))), authenticator: address(1), scope: 0, policyData: ""
        });
        vm.expectRevert(Keystore.AlreadyInitialized.selector);
        keystore.importAccount(account, 0, actors, "");
    }

    /// @notice An empty sequenced batch is rejected (EmptyChangeSet) so it cannot consume a sequence doing nothing.
    function test_apply_revert_emptyBatchSequenced(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);

        Keystore.SignedAccountChanges memory s = _localBatch(pk, account, new Keystore.AccountChange[](0));
        vm.expectRevert(Keystore.EmptyChangeSet.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    /// @notice An empty unsequenced batch is rejected (EmptyChangeSet) so it cannot initialize a fresh account without
    ///         altering any configuration.
    function test_apply_revert_emptyBatchUnsequenced(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);

        Keystore.SignedAccountChanges memory s = _unseqBatch(pk, account, new Keystore.AccountChange[](0));
        vm.expectRevert(Keystore.EmptyChangeSet.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    /// @notice A never-bootstrapped EOA acting via its inline k1 self on its first unsequenced batch is marked
    ///         initialized: the batch burns local sequence 0 (0 -> 1), closing the one-time importAccount bootstrap and
    ///         invalidating any outstanding sequenced seq==0 signature. The batch itself remains replayable.
    function test_regression_unsequencedInitBlocksImport(uint256 pk) public {
        pk = _boundK1Pk(pk);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);

        // Uninitialized: both local counters are zero.
        (uint32 epoch0, uint32 seq0) = _localEpochSeq(account);
        assertEq(epoch0, 0);
        assertEq(seq0, 0);

        _applyUnsequenced(
            pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), ""))
        );

        // Sequence 0 burned -> reads initialized; the actor landed.
        (uint32 epoch1, uint32 seq1) = _localEpochSeq(account);
        assertEq(epoch1, 0);
        assertEq(seq1, 1);
        assertTrue(_isActor(account, ACTOR_A));

        // importAccount must now reject the account as already initialized.
        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](1);
        actors[0] = Keystore.InitialActor({
            actorId: bytes32(uint256(uint160(account))), authenticator: address(1), scope: 0, policyData: ""
        });
        vm.expectRevert(Keystore.AlreadyInitialized.selector);
        keystore.importAccount(account, 0, actors, "");
    }

    /// @notice Init asymmetry (fresh-account branch): a never-bootstrapped EOA's first LOCAL unsequenced batch burns
    ///         local sequence 0 -> 1, so any sequenced-at-0 signature it had already produced is now dead (BadSequence).
    ///         This is the side of the asymmetry that the unsequenced-init write creates.
    function test_init_unsequencedFirstBatchKillsSequenceZero(uint256 pk) public {
        pk = _boundK1Pk(pk);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);

        // A sequenced local batch at seq 0, captured while the account is still fresh (epoch 0, seq 0).
        Keystore.SignedAccountChanges memory seqZero = _localBatch(
            pk, account, _one(_authorizeChange(ACTOR_B, address(k1Authenticator), SENDER, _future(1 days), ""))
        );

        // First act is an unsequenced batch: burns local sequence 0 -> 1 (marks initialized).
        _applyUnsequenced(
            pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), ""))
        );
        (, uint32 seq1) = _localEpochSeq(account);
        assertEq(seq1, 1);

        // The pre-signed sequenced-at-0 batch no longer matches the advanced counter.
        vm.expectRevert(Keystore.BadSequence.selector);
        keystore.applySignedAccountChanges(account, seqZero);
    }

    /// @notice Init asymmetry (multichain-active branch): once an EOA has bootstrapped via the Multichain channel it
    ///         already reads initialized, so a later first LOCAL unsequenced batch does NOT burn local sequence 0. The
    ///         local sequenced-at-0 slot stays live and a sequenced-at-0 batch still lands — the opposite of a fresh
    ///         account, pinned deliberately.
    function test_init_multichainActiveKeepsLocalSequenceZero(uint256 pk) public {
        pk = _boundK1Pk(pk);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);

        // Bootstrap via multichain: multichain counter 0 -> 1, local word stays 0/0 (initialized via the multichain
        // term of _isInitialized).
        _applyMultichain(
            pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, _future(1 days), ""))
        );
        (uint32 epoch0, uint32 seq0) = _localEpochSeq(account);
        assertEq(epoch0, 0);
        assertEq(seq0, 0);

        // A local unsequenced batch: the unsequenced-init write is skipped (already initialized), so localSequence
        // stays 0.
        _applyUnsequenced(
            pk, account, _one(_authorizeChange(ACTOR_B, address(k1Authenticator), SENDER, _future(1 days), ""))
        );
        (, uint32 seq1) = _localEpochSeq(account);
        assertEq(seq1, 0);

        // A local sequenced batch at seq 0 therefore still lands (seq 0 == localSequence 0), consuming 0 -> 1.
        bytes32 idC = bytes32(uint256(0xC3));
        _applyLocal(pk, account, _one(_authorizeChange(idC, address(k1Authenticator), SENDER, _future(1 days), "")));
        assertTrue(_isActor(account, idC));
        (, uint32 seq2) = _localEpochSeq(account);
        assertEq(seq2, 1);
    }
}
