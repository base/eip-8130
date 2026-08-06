// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore} from "../../../src/Keystore.sol";
import {KeystoreTest} from "../../lib/KeystoreTest.sol";

/// @notice Branch-complete, fuzz-by-default suite for the account lock surface: applySignedLockChanges (op = lock /
///         unlock), isLocked, getLockStatus, the onlyUnlocked modifier and _checkAndClearLock. Lock state changes
///         ONLY through applySignedLockChanges — a relayable, admin-authorized (scope 0) signed call — so lock-side
///         tests use a controllable key: an uninitialized EOA at vm.addr(pk) signs with its inline default-EOA self
///         (scope 0 admin), and anyone (here the test) relays. Tests that must drive an onlyUnlocked-guarded config
///         path (applySignedActorChanges) create a real k1 account so the authenticated actor can change actors.
contract AccountLockTest is KeystoreTest {
    // ── Local fuzz-bound helpers ──

    /// @dev Keep a fuzzed account out of the zero address, the system contract, and the forge-std cheatcode /
    ///      console addresses so it acts as a clean, code-free account.
    function _assumeSafeAccount(address account) internal view {
        vm.assume(account != address(0));
        vm.assume(account != address(keystore));
        vm.assume(account != VM_ADDRESS);
        vm.assume(account != CONSOLE);
    }

    /// @dev A single authorize-actor change granting an unrestricted k1 owner (scope 0, no expiry, no policy).
    function _oneAuthorizeChange(bytes32 actorId) internal view returns (Keystore.ActorChange[] memory changes) {
        changes = new Keystore.ActorChange[](1);
        changes[0] = Keystore.ActorChange({
            changeType: 0x01,
            actorId: actorId,
            data: abi.encode(
                Keystore.ActorConfig({authenticator: address(k1Authenticator), scope: 0x00, expiry: 0}), bytes("")
            )
        });
    }

    /// @dev Authorize a k1 actor (actorId = bytes32(bytes20(newSigner))) with `scope` on `account`, signed by the
    ///      account's admin owner `ownerPk`.
    function _authorizeK1ActorWithScope(address account, uint256 ownerPk, address newSigner, uint16 scope) internal {
        Keystore.ActorChange[] memory changes = new Keystore.ActorChange[](1);
        changes[0] = Keystore.ActorChange({
            changeType: 0x01,
            actorId: bytes32(bytes20(newSigner)),
            data: abi.encode(
                Keystore.ActorConfig({authenticator: address(k1Authenticator), scope: scope, expiry: 0}), bytes("")
            )
        });
        uint64 chainId = uint64(block.chainid);
        uint64 seq = keystore.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, chainId, seq, changes);
        bytes memory auth = _buildK1Auth(ownerPk, digest);
        keystore.applySignedActorChanges(account, chainId, changes, auth);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // REVERTS (source order: authorization -> lock op -> unlock op -> onlyUnlocked on other functions)
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice applySignedLockChanges reverts UnauthorizedLockChange when the signer is a scoped (non-admin) actor.
    /// @dev The owner authorizes a SCOPE_SENDER k1 actor, which then signs a lock op; scope != 0 is rejected after
    ///      authentication, before any lock-state work.
    function test_applySignedLockChanges_revert_whenSignerNotAdmin(uint256 ownerSeed, uint256 scopedSeed, uint16 delay)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 scopedPk = _boundK1Pk(scopedSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(scopedPk));
        delay = uint16(bound(delay, 1, type(uint16).max));
        (address account,) = _createK1Account(ownerPk);
        address scopedSigner = vm.addr(scopedPk);
        vm.assume(scopedSigner != account);

        _authorizeK1ActorWithScope(account, ownerPk, scopedSigner, keystore.SCOPE_SENDER());

        bytes memory auth = _lockAuth(scopedPk, account, delay);
        vm.expectRevert(Keystore.UnauthorizedLockChange.selector);
        keystore.applySignedLockChanges(account, LOCK_OP, delay, auth);
    }

    /// @notice applySignedLockChanges reverts UnknownLockOp for any op other than LOCK_OP / UNLOCK_OP.
    function test_applySignedLockChanges_revert_unknownOp(uint256 pkSeed, uint8 op, uint16 delay) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);
        vm.assume(op != LOCK_OP && op != UNLOCK_OP);

        uint64 seq = keystore.getChangeSequences(account).local;
        bytes32 digest = _computeLockChangeDigest(account, block.chainid, op, delay, seq);
        bytes memory auth = _buildK1Auth(pk, digest);

        vm.expectRevert(Keystore.UnknownLockOp.selector);
        keystore.applySignedLockChanges(account, op, delay, auth);
    }

    /// @notice A lock op (op = 1) with a zero unlock delay reverts ZeroUnlockDelay.
    /// @dev Exercises the `unlockDelay == 0` guard on the lock branch; the unlocked-state check passes (fresh account).
    function test_lock_revert_zeroUnlockDelay(uint256 pkSeed) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);

        bytes memory auth = _lockAuth(pk, account, 0);
        vm.expectRevert(Keystore.ZeroUnlockDelay.selector);
        keystore.applySignedLockChanges(account, LOCK_OP, 0, auth);
    }

    /// @notice A lock op reverts AccountIsLocked when the account is already hard-locked.
    /// @dev Second lock hits _checkAndClearLock with FLAG_LOCKED set and FLAG_UNLOCK_INITIATED clear (hard-locked branch).
    function test_lock_revert_whenAlreadyHardLocked(uint256 pkSeed, uint16 firstDelay, uint16 secondDelay) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);
        firstDelay = uint16(bound(firstDelay, 1, type(uint16).max));
        secondDelay = uint16(bound(secondDelay, 1, type(uint16).max));

        _signedLock(pk, account, firstDelay);

        bytes memory auth = _lockAuth(pk, account, secondDelay);
        vm.expectRevert(Keystore.AccountIsLocked.selector);
        keystore.applySignedLockChanges(account, LOCK_OP, secondDelay, auth);
    }

    /// @notice An unlock op (op = 2) with a non-zero unlock delay reverts InvalidUnlockDelay.
    /// @dev The delay guard fires before the hard-locked-state check, so it trips even on a fresh account.
    function test_unlock_revert_nonZeroUnlockDelay(uint256 pkSeed, uint16 delay) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));

        uint64 seq = keystore.getChangeSequences(account).local;
        bytes32 digest = _computeLockChangeDigest(account, block.chainid, UNLOCK_OP, delay, seq);
        bytes memory auth = _buildK1Auth(pk, digest);

        vm.expectRevert(Keystore.InvalidUnlockDelay.selector);
        keystore.applySignedLockChanges(account, UNLOCK_OP, delay, auth);
    }

    /// @notice An unlock op reverts NotLocked when the account has never been locked (FLAG_LOCKED clear).
    function test_initiateUnlock_revert_whenNeverLocked(uint256 pkSeed) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);

        bytes memory auth = _unlockAuth(pk, account);
        vm.expectRevert(Keystore.NotLocked.selector);
        keystore.applySignedLockChanges(account, UNLOCK_OP, 0, auth);
    }

    /// @notice An unlock op reverts NotLocked once an unlock has already been initiated.
    /// @dev After the first unlock, FLAG_UNLOCK_INITIATED is set, so a second unlock reverts.
    function test_initiateUnlock_revert_whenUnlockAlreadyInitiated(uint256 pkSeed, uint16 delay, uint256 t0) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));
        t0 = bound(t0, 1, 1e9);

        _signedLock(pk, account, delay);
        vm.warp(t0);
        _signedUnlock(pk, account);

        bytes memory auth = _unlockAuth(pk, account);
        vm.expectRevert(Keystore.NotLocked.selector);
        keystore.applySignedLockChanges(account, UNLOCK_OP, 0, auth);
    }

    /// @notice A replayed lock auth fails: the local sequence advanced on the first success, so the signed digest no
    ///         longer matches and authentication fails.
    function test_applySignedLockChanges_revert_whenAuthReplayed(uint256 pkSeed, uint16 delay) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));

        bytes memory auth = _lockAuth(pk, account, delay); // signed over sequence 0
        keystore.applySignedLockChanges(account, LOCK_OP, delay, auth); // sequence 0 -> 1

        vm.expectRevert();
        keystore.applySignedLockChanges(account, LOCK_OP, delay, auth);
    }

    /// @notice A lock auth signed over a sequence other than the account's current one fails to authenticate.
    function test_applySignedLockChanges_revert_whenSequenceWrong(uint256 pkSeed, uint16 delay, uint64 seqOffset)
        public
    {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));
        seqOffset = uint64(bound(seqOffset, 1, type(uint64).max - 1));

        uint64 wrongSeq = keystore.getChangeSequences(account).local + seqOffset;
        bytes32 digest = _computeLockChangeDigest(account, block.chainid, LOCK_OP, delay, wrongSeq);
        bytes memory auth = _buildK1Auth(pk, digest);

        vm.expectRevert();
        keystore.applySignedLockChanges(account, LOCK_OP, delay, auth);
    }

    /// @notice applySignedActorChanges reverts AccountIsLocked while the target account is hard-locked.
    /// @dev Exercises the onlyUnlocked modifier on a config-mutating path; the guard fires before any auth work.
    function test_applySignedActorChanges_revert_whenLocked(uint256 pkSeed, uint16 delay) public {
        uint256 pk = _boundK1Pk(pkSeed);
        delay = uint16(bound(delay, 1, type(uint16).max));
        (address account,) = _createK1Account(pk);

        _signedLock(pk, account, delay);

        Keystore.ActorChange[] memory changes = _oneAuthorizeChange(bytes32(bytes20(vm.addr(pk))));
        uint64 chainId = uint64(block.chainid);
        uint64 seq = keystore.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, chainId, seq, changes);
        bytes memory auth = _buildK1Auth(pk, digest);

        vm.expectRevert(Keystore.AccountIsLocked.selector);
        keystore.applySignedActorChanges(account, chainId, changes, auth);
    }

    /// @notice importAccount reverts AccountIsLocked while the target account is hard-locked.
    /// @dev The onlyUnlocked(account) modifier runs before the import body, so the lock guard is asserted in
    ///      isolation on a second, distinct function (empty initialActors never reached).
    function test_importAccount_revert_whenLocked(uint256 pkSeed, uint16 delay) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));

        _signedLock(pk, account, delay);

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](0);
        vm.expectRevert(Keystore.AccountIsLocked.selector);
        keystore.importAccount(account, block.chainid, actors, "");
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // HAPPY PATHS / BRANCH COVERAGE
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice A lock op hard-locks the account: FLAG_LOCKED set, delay stored in lockUnion.
    /// @dev getLockStatus reports locked, not-yet-initiated, the synthesized max sentinel for unlocksAt and the stored
    ///      delay; isLocked true.
    function test_lock_success_setsHardLockStatus(uint256 pkSeed, uint16 delay) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));

        _signedLock(pk, account, delay);

        (bool locked, bool hasInitiatedUnlock, uint40 unlocksAt, uint16 storedDelay) = keystore.getLockStatus(account);
        assertTrue(locked);
        assertFalse(hasInitiatedUnlock);
        assertEq(unlocksAt, type(uint40).max);
        assertEq(storedDelay, delay);
        assertTrue(keystore.isLocked(account));
    }

    /// @notice A lock op emits AccountLocked(account, unlockDelay) exactly once. Sole assertion of this event.
    function test_lock_success_emitsAccountLocked(uint256 pkSeed, uint16 delay) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));

        bytes memory auth = _lockAuth(pk, account, delay);
        vm.expectEmit(true, false, false, true, address(keystore));
        emit Keystore.AccountLocked(account, delay);
        keystore.applySignedLockChanges(account, LOCK_OP, delay, auth);
    }

    /// @notice An account can be re-locked after a prior unlock delay has fully elapsed.
    /// @dev Drives _checkAndClearLock through its lazy-clear branch (UNLOCK_INITIATED set, block.timestamp >= stored unlocksAt):
    ///      the stale timestamp is cleared to 0 and the fresh lock succeeds, hard-locking again with the new delay.
    function test_lock_success_relockAfterUnlockExpired(
        uint256 pkSeed,
        uint16 firstDelay,
        uint16 secondDelay,
        uint256 t0,
        uint256 extra
    ) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);
        firstDelay = uint16(bound(firstDelay, 1, type(uint16).max));
        secondDelay = uint16(bound(secondDelay, 1, type(uint16).max));
        t0 = bound(t0, 1, 1e9);
        extra = bound(extra, 0, 1e9);

        _signedLock(pk, account, firstDelay);
        vm.warp(t0);
        _signedUnlock(pk, account);

        vm.warp(t0 + firstDelay + extra); // at or past unlocksAt: account is unlocked
        assertFalse(keystore.isLocked(account));

        _signedLock(pk, account, secondDelay);

        (bool locked, bool hasInitiatedUnlock, uint40 unlocksAt, uint16 storedDelay) = keystore.getLockStatus(account);
        assertTrue(locked);
        assertFalse(hasInitiatedUnlock);
        assertEq(unlocksAt, type(uint40).max);
        assertEq(storedDelay, secondDelay);
    }

    /// @notice An unlock op sets unlocksAt = block.timestamp + delay and zeroes the stored delay.
    /// @dev Before the delay elapses the account is still locked but now reports hasInitiatedUnlock; unlockDelay is 0.
    function test_initiateUnlock_success_setsUnlocksAtAndClearsDelay(uint256 pkSeed, uint16 delay, uint256 t0) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));
        t0 = bound(t0, 1, 1e9);

        _signedLock(pk, account, delay);
        vm.warp(t0);
        _signedUnlock(pk, account);

        (bool locked, bool hasInitiatedUnlock, uint40 unlocksAt, uint16 storedDelay) = keystore.getLockStatus(account);
        assertTrue(locked); // block.timestamp (t0) < unlocksAt (t0 + delay)
        assertTrue(hasInitiatedUnlock);
        assertEq(unlocksAt, uint40(t0 + delay));
        assertEq(storedDelay, 0);
        assertTrue(keystore.isLocked(account));
    }

    /// @notice An unlock op emits AccountUnlockInitiated(account, unlocksAt) exactly once. Sole assertion.
    function test_initiateUnlock_success_emitsAccountUnlockInitiated(uint256 pkSeed, uint16 delay, uint256 t0) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));
        t0 = bound(t0, 1, 1e9);

        _signedLock(pk, account, delay);
        vm.warp(t0);

        bytes memory auth = _unlockAuth(pk, account);
        vm.expectEmit(true, false, false, true, address(keystore));
        emit Keystore.AccountUnlockInitiated(account, uint40(t0 + delay));
        keystore.applySignedLockChanges(account, UNLOCK_OP, 0, auth);
    }

    /// @notice isLocked is false for an account that has never been locked (FLAG_LOCKED clear).
    function test_isLocked_success_falseWhenNeverLocked(address account, uint256 ts) public {
        _assumeSafeAccount(account);
        vm.warp(bound(ts, 1, 1e12));
        assertFalse(keystore.isLocked(account));
    }

    /// @notice isLocked stays true for a hard-locked account at any timestamp (FLAG_LOCKED set, no pending unlock —
    ///         hard-lock is timestamp-independent).
    function test_isLocked_success_trueWhileHardLocked(uint256 pkSeed, uint16 delay, uint256 ts) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));

        _signedLock(pk, account, delay);

        vm.warp(bound(ts, 1, 1e12)); // hard-lock ignores the clock: FLAG_LOCKED set with no pending unlock
        assertTrue(keystore.isLocked(account));
    }

    /// @notice isLocked remains true after an unlock is initiated while block.timestamp is strictly before unlocksAt.
    function test_isLocked_success_trueBeforeUnlockDelayElapses(
        uint256 pkSeed,
        uint16 delay,
        uint256 t0,
        uint256 within
    ) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));
        t0 = bound(t0, 1, 1e9);

        _signedLock(pk, account, delay);
        vm.warp(t0);
        _signedUnlock(pk, account);

        vm.warp(bound(within, t0, t0 + delay - 1)); // strictly before unlocksAt == t0 + delay
        assertTrue(keystore.isLocked(account));
    }

    /// @notice isLocked flips to false once block.timestamp reaches or passes unlocksAt after an initiated unlock.
    /// @dev Includes the exact boundary (extra == 0): isLocked is `block.timestamp < unlocksAt`, so == is unlocked.
    function test_isLocked_success_falseAfterUnlockDelayElapses(uint256 pkSeed, uint16 delay, uint256 t0, uint256 extra)
        public
    {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));
        t0 = bound(t0, 1, 1e9);
        extra = bound(extra, 0, 1e9);

        _signedLock(pk, account, delay);
        vm.warp(t0);
        _signedUnlock(pk, account);

        vm.warp(t0 + delay + extra); // at or past unlocksAt
        assertFalse(keystore.isLocked(account));
    }

    /// @notice getLockStatus reports all-clear for a never-locked account: unlocked, not initiated, zeroed fields.
    function test_getLockStatus_success_whenNeverLocked(address account) public view {
        (bool locked, bool hasInitiatedUnlock, uint40 unlocksAt, uint16 unlockDelay) = keystore.getLockStatus(account);
        assertFalse(locked);
        assertFalse(hasInitiatedUnlock);
        assertEq(unlocksAt, 0);
        assertEq(unlockDelay, 0);
    }

    /// @notice getLockStatus after the delay elapses (with no intervening onlyUnlocked call) still surfaces the
    ///         initiated-unlock state: unlocked, but hasInitiatedUnlock true and unlocksAt unchanged.
    /// @dev getLockStatus is a pure view: it never runs _checkAndClearLock, so the lock flags/union are not cleared and
    ///      the FLAG_UNLOCK_INITIATED branch reports hasInitiatedUnlock true even though the account is now unlocked.
    function test_getLockStatus_success_afterUnlockElapsedNotCleared(
        uint256 pkSeed,
        uint16 delay,
        uint256 t0,
        uint256 extra
    ) public {
        uint256 pk = _boundK1Pk(pkSeed);
        address account = vm.addr(pk);
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));
        t0 = bound(t0, 1, 1e9);
        extra = bound(extra, 0, 1e9);

        _signedLock(pk, account, delay);
        vm.warp(t0);
        _signedUnlock(pk, account);

        vm.warp(t0 + delay + extra); // past unlocksAt, but no onlyUnlocked call to clear it

        (bool locked, bool hasInitiatedUnlock, uint40 unlocksAt, uint16 storedDelay) = keystore.getLockStatus(account);
        assertFalse(locked);
        assertTrue(hasInitiatedUnlock);
        assertEq(unlocksAt, uint40(t0 + delay));
        assertEq(storedDelay, 0);
    }

    /// @notice Full lock -> initiate-unlock -> warp-past -> config change cycle: once the delay elapses,
    ///         _checkAndClearLock lets an onlyUnlocked config change through and the new actor is authorized.
    /// @dev Drives the expiry-clear branch of _checkAndClearLock on the real applySignedActorChanges path.
    function test_applySignedActorChanges_success_afterFullUnlockCycle(
        uint256 pkSeed,
        uint256 newActorSeed,
        uint16 delay,
        uint256 t0,
        uint256 extra
    ) public {
        uint256 pk = _boundK1Pk(pkSeed);
        delay = uint16(bound(delay, 1, type(uint16).max));
        t0 = bound(t0, 1, 1e9);
        extra = bound(extra, 0, 1e9);
        (address account,) = _createK1Account(pk);

        address newActor = address(uint160(bound(newActorSeed, 1, type(uint160).max)));
        vm.assume(newActor != account);
        vm.assume(newActor != vm.addr(pk));
        bytes32 newActorId = bytes32(bytes20(newActor));

        _signedLock(pk, account, delay);
        vm.warp(t0);
        _signedUnlock(pk, account);
        vm.warp(t0 + delay + extra); // at or past unlocksAt: unlocked
        assertFalse(keystore.isLocked(account));

        Keystore.ActorChange[] memory changes = _oneAuthorizeChange(newActorId);
        uint64 chainId = uint64(block.chainid);
        uint64 seq = keystore.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, chainId, seq, changes);
        bytes memory auth = _buildK1Auth(pk, digest);

        keystore.applySignedActorChanges(account, chainId, changes, auth);

        assertTrue(_isActor(account, newActorId));
        // The onlyUnlocked prelude cleared the stale unlock timestamp back to 0.
        (,, uint40 unlocksAt,) = keystore.getLockStatus(account);
        assertEq(unlocksAt, 0);
    }

    /// @notice applySignedActorChanges still reverts AccountIsLocked after an unlock is initiated but before its delay
    ///         elapses: config stays frozen for the whole notice window, not just while hard-locked.
    /// @dev Drives the pending-unlock branch of _checkAndClearLock (FLAG_UNLOCK_INITIATED set, block.timestamp <
    ///      stored unlocksAt) on the real onlyUnlocked-guarded config path — distinct from the hard-locked branch.
    function test_applySignedActorChanges_revert_whileUnlockPending(
        uint256 pkSeed,
        uint16 delay,
        uint256 t0,
        uint256 within
    ) public {
        uint256 pk = _boundK1Pk(pkSeed);
        delay = uint16(bound(delay, 1, type(uint16).max));
        t0 = bound(t0, 1, 1e9);
        (address account,) = _createK1Account(pk);

        _signedLock(pk, account, delay);
        vm.warp(t0);
        _signedUnlock(pk, account);
        vm.warp(bound(within, t0, t0 + delay - 1)); // strictly before unlocksAt == t0 + delay: still frozen

        Keystore.ActorChange[] memory changes = _oneAuthorizeChange(bytes32(bytes20(vm.addr(pk))));
        uint64 chainId = uint64(block.chainid);
        uint64 seq = keystore.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, chainId, seq, changes);
        bytes memory auth = _buildK1Auth(pk, digest);

        vm.expectRevert(Keystore.AccountIsLocked.selector);
        keystore.applySignedActorChanges(account, chainId, changes, auth);
    }
}
