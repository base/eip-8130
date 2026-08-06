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

    /// @notice Regression: `[Lock, Unlock, Lock]` in a single batch from the unlocked state must revert on the
    ///         trailing Lock. _applyLock gates on LIVE lock state, so it sees the mid-batch Unlock rather than the
    ///         stale batch-entry snapshot; otherwise the final Lock would corrupt the union (FLAG_UNLOCK_INITIATED
    ///         set over a delay-valued lockUnion, making the account read instantly unlockable).
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
        vm.expectRevert(Keystore.AccountIsLocked.selector);
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
        bytes32 scopedId = bytes32(bytes20(vm.addr(scopedPk)));

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

    /// @notice A BumpLocalEpoch on the Multichain channel reverts EpochOpRequiresLocalChannel.
    function test_multichain_revert_bumpRejected(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);

        Keystore.SignedAccountChanges memory s = _multichainBatch(pk, account, _one(_bumpChange()));
        vm.expectRevert(Keystore.EpochOpRequiresLocalChannel.selector);
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
}
