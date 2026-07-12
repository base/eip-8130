// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

/// @notice Branch-complete, fuzz-by-default suite for the account lock surface: lock(uint16), initiateUnlock(),
///         isLocked, getLockStatus, the onlyUnlocked modifier and _checkAndClearLock. lock/initiateUnlock act on
///         msg.sender, so the account is pranked as itself; lock() is callable by any address as itself, so most
///         lock-side tests prank an arbitrary fuzzed address. Tests that must drive an onlyUnlocked-guarded config
///         path (applySignedActorChanges) create a real k1 account so the authenticated actor can change actors.
contract AccountLockTest is AccountConfigurationTest {
    // ── Local fuzz-bound helpers ──

    /// @dev Keep a fuzzed msg.sender out of the zero address, the system contract, and the forge-std cheatcode /
    ///      console addresses so vm.prank drives a clean, code-free account acting as itself.
    function _assumeSafeAccount(address account) internal view {
        vm.assume(account != address(0));
        vm.assume(account != address(accountConfiguration));
        vm.assume(account != VM_ADDRESS);
        vm.assume(account != CONSOLE);
    }

    function _lockAccount(address account, uint16 unlockDelay) internal {
        vm.prank(account);
        accountConfiguration.lock(unlockDelay);
    }

    function _initiateUnlock(address account) internal {
        vm.prank(account);
        accountConfiguration.initiateUnlock();
    }

    /// @dev A single authorize-actor change granting an unrestricted k1 owner (scope 0, no expiry, no policy).
    function _oneAuthorizeChange(bytes32 actorId)
        internal
        view
        returns (AccountConfiguration.ActorChange[] memory changes)
    {
        changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            changeType: 0x01,
            actorId: actorId,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: address(k1Authenticator), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // REVERTS (source order: lock -> initiateUnlock -> onlyUnlocked on other functions)
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice lock(0) reverts ZeroUnlockDelay for any account acting as itself.
    /// @dev Exercises the `unlockDelay == 0` guard in lock(); the onlyUnlocked prelude passes (fresh, unlocksAt == 0).
    function test_lock_revert_zeroUnlockDelay(address account) public {
        _assumeSafeAccount(account);

        vm.prank(account);
        vm.expectRevert(AccountConfiguration.ZeroUnlockDelay.selector);
        accountConfiguration.lock(0);
    }

    /// @notice lock() reverts AccountIsLocked when the account is already hard-locked.
    /// @dev Second lock hits onlyUnlocked -> _checkAndClearLock with unlocksAt == type(uint40).max (locked branch).
    function test_lock_revert_whenAlreadyHardLocked(address account, uint16 firstDelay, uint16 secondDelay) public {
        _assumeSafeAccount(account);
        firstDelay = uint16(bound(firstDelay, 1, type(uint16).max));
        secondDelay = uint16(bound(secondDelay, 1, type(uint16).max));

        _lockAccount(account, firstDelay);

        vm.prank(account);
        vm.expectRevert(AccountConfiguration.AccountIsLocked.selector);
        accountConfiguration.lock(secondDelay);
    }

    /// @notice initiateUnlock() reverts NotLocked when the account has never been locked (unlocksAt == 0).
    /// @dev The `unlocksAt != type(uint40).max` guard fires on a fresh account whose unlocksAt is 0.
    function test_initiateUnlock_revert_whenNeverLocked(address account) public {
        _assumeSafeAccount(account);

        vm.prank(account);
        vm.expectRevert(AccountConfiguration.NotLocked.selector);
        accountConfiguration.initiateUnlock();
    }

    /// @notice initiateUnlock() reverts NotLocked once an unlock has already been initiated.
    /// @dev After initiateUnlock, unlocksAt is a finite timestamp (!= max), so a second initiateUnlock reverts.
    function test_initiateUnlock_revert_whenUnlockAlreadyInitiated(address account, uint16 delay, uint256 t0) public {
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));
        t0 = bound(t0, 1, 1e9);

        _lockAccount(account, delay);
        vm.warp(t0);
        _initiateUnlock(account);

        vm.prank(account);
        vm.expectRevert(AccountConfiguration.NotLocked.selector);
        accountConfiguration.initiateUnlock();
    }

    /// @notice applySignedActorChanges reverts AccountIsLocked while the target account is hard-locked.
    /// @dev Exercises the onlyUnlocked modifier on a config-mutating path; the guard fires before any auth work.
    function test_applySignedActorChanges_revert_whenLocked(uint256 pkSeed, uint16 delay) public {
        uint256 pk = _boundK1Pk(pkSeed);
        delay = uint16(bound(delay, 1, type(uint16).max));
        (address account,) = _createK1Account(pk);

        _lockAccount(account, delay);

        AccountConfiguration.ActorChange[] memory changes = _oneAuthorizeChange(bytes32(bytes20(vm.addr(pk))));
        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, chainId, seq, changes);
        bytes memory auth = _buildK1Auth(pk, digest);

        vm.expectRevert(AccountConfiguration.AccountIsLocked.selector);
        accountConfiguration.applySignedActorChanges(account, chainId, changes, auth);
    }

    /// @notice importAccount reverts AccountIsLocked while the target account is hard-locked.
    /// @dev The onlyUnlocked(account) modifier runs before the import body, so the lock guard is asserted in
    ///      isolation on a second, distinct function (empty initialActors never reached).
    function test_importAccount_revert_whenLocked(address account, uint16 delay) public {
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));

        _lockAccount(account, delay);

        AccountConfiguration.InitialActor[] memory actors = new AccountConfiguration.InitialActor[](0);
        vm.expectRevert(AccountConfiguration.AccountIsLocked.selector);
        accountConfiguration.importAccount(account, block.chainid, actors, "");
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // HAPPY PATHS / BRANCH COVERAGE
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice lock() hard-locks the account: unlocksAt == type(uint40).max and the delay is stored.
    /// @dev getLockStatus reports locked, not-yet-initiated, sentinel unlocksAt and the stored delay; isLocked true.
    function test_lock_success_setsHardLockStatus(address account, uint16 delay) public {
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));

        _lockAccount(account, delay);

        (bool locked, bool hasInitiatedUnlock, uint40 unlocksAt, uint16 storedDelay) =
            accountConfiguration.getLockStatus(account);
        assertTrue(locked);
        assertFalse(hasInitiatedUnlock);
        assertEq(unlocksAt, type(uint40).max);
        assertEq(storedDelay, delay);
        assertTrue(accountConfiguration.isLocked(account));
    }

    /// @notice lock() emits AccountLocked(account, unlockDelay) exactly once. Sole assertion of this event.
    function test_lock_success_emitsAccountLocked(address account, uint16 delay) public {
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));

        vm.expectEmit(true, false, false, true, address(accountConfiguration));
        emit AccountConfiguration.AccountLocked(account, delay);
        vm.prank(account);
        accountConfiguration.lock(delay);
    }

    /// @notice An account can be re-locked after a prior unlock delay has fully elapsed.
    /// @dev Drives _checkAndClearLock through its expiry-clear branch (block.timestamp >= unlocksAt, unlocksAt != 0):
    ///      the stale timestamp is cleared to 0 and the fresh lock succeeds, hard-locking again with the new delay.
    function test_lock_success_relockAfterUnlockExpired(
        address account,
        uint16 firstDelay,
        uint16 secondDelay,
        uint256 t0,
        uint256 extra
    ) public {
        _assumeSafeAccount(account);
        firstDelay = uint16(bound(firstDelay, 1, type(uint16).max));
        secondDelay = uint16(bound(secondDelay, 1, type(uint16).max));
        t0 = bound(t0, 1, 1e9);
        extra = bound(extra, 0, 1e9);

        _lockAccount(account, firstDelay);
        vm.warp(t0);
        _initiateUnlock(account);

        vm.warp(t0 + firstDelay + extra); // at or past unlocksAt: account is unlocked
        assertFalse(accountConfiguration.isLocked(account));

        _lockAccount(account, secondDelay);

        (bool locked, bool hasInitiatedUnlock, uint40 unlocksAt, uint16 storedDelay) =
            accountConfiguration.getLockStatus(account);
        assertTrue(locked);
        assertFalse(hasInitiatedUnlock);
        assertEq(unlocksAt, type(uint40).max);
        assertEq(storedDelay, secondDelay);
    }

    /// @notice initiateUnlock() sets unlocksAt = block.timestamp + delay and zeroes the stored delay.
    /// @dev Before the delay elapses the account is still locked but now reports hasInitiatedUnlock; unlockDelay is 0.
    function test_initiateUnlock_success_setsUnlocksAtAndClearsDelay(address account, uint16 delay, uint256 t0) public {
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));
        t0 = bound(t0, 1, 1e9);

        _lockAccount(account, delay);
        vm.warp(t0);
        _initiateUnlock(account);

        (bool locked, bool hasInitiatedUnlock, uint40 unlocksAt, uint16 storedDelay) =
            accountConfiguration.getLockStatus(account);
        assertTrue(locked); // block.timestamp (t0) < unlocksAt (t0 + delay)
        assertTrue(hasInitiatedUnlock);
        assertEq(unlocksAt, uint40(t0 + delay));
        assertEq(storedDelay, 0);
        assertTrue(accountConfiguration.isLocked(account));
    }

    /// @notice initiateUnlock() emits AccountUnlockInitiated(account, unlocksAt) exactly once. Sole assertion.
    function test_initiateUnlock_success_emitsAccountUnlockInitiated(address account, uint16 delay, uint256 t0) public {
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));
        t0 = bound(t0, 1, 1e9);

        _lockAccount(account, delay);
        vm.warp(t0);

        vm.expectEmit(true, false, false, true, address(accountConfiguration));
        emit AccountConfiguration.AccountUnlockInitiated(account, uint40(t0 + delay));
        vm.prank(account);
        accountConfiguration.initiateUnlock();
    }

    /// @notice isLocked is false for an account that has never been locked (unlocksAt == 0).
    function test_isLocked_success_falseWhenNeverLocked(address account, uint256 ts) public {
        _assumeSafeAccount(account);
        vm.warp(bound(ts, 1, 1e12));
        assertFalse(accountConfiguration.isLocked(account));
    }

    /// @notice isLocked stays true for a hard-locked account at any reachable timestamp (unlocksAt == max sentinel).
    function test_isLocked_success_trueWhileHardLocked(address account, uint16 delay, uint256 ts) public {
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));

        _lockAccount(account, delay);

        vm.warp(bound(ts, 1, 1e12)); // any timestamp below the uint40 sentinel keeps block.timestamp < unlocksAt
        assertTrue(accountConfiguration.isLocked(account));
    }

    /// @notice isLocked remains true after initiateUnlock while block.timestamp is strictly before unlocksAt.
    function test_isLocked_success_trueBeforeUnlockDelayElapses(
        address account,
        uint16 delay,
        uint256 t0,
        uint256 within
    ) public {
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));
        t0 = bound(t0, 1, 1e9);

        _lockAccount(account, delay);
        vm.warp(t0);
        _initiateUnlock(account);

        vm.warp(bound(within, t0, t0 + delay - 1)); // strictly before unlocksAt == t0 + delay
        assertTrue(accountConfiguration.isLocked(account));
    }

    /// @notice isLocked flips to false once block.timestamp reaches or passes unlocksAt after an initiated unlock.
    /// @dev Includes the exact boundary (extra == 0): isLocked is `block.timestamp < unlocksAt`, so == is unlocked.
    function test_isLocked_success_falseAfterUnlockDelayElapses(
        address account,
        uint16 delay,
        uint256 t0,
        uint256 extra
    ) public {
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));
        t0 = bound(t0, 1, 1e9);
        extra = bound(extra, 0, 1e9);

        _lockAccount(account, delay);
        vm.warp(t0);
        _initiateUnlock(account);

        vm.warp(t0 + delay + extra); // at or past unlocksAt
        assertFalse(accountConfiguration.isLocked(account));
    }

    /// @notice getLockStatus reports all-clear for a never-locked account: unlocked, not initiated, zeroed fields.
    function test_getLockStatus_success_whenNeverLocked(address account) public view {
        (bool locked, bool hasInitiatedUnlock, uint40 unlocksAt, uint16 unlockDelay) =
            accountConfiguration.getLockStatus(account);
        assertFalse(locked);
        assertFalse(hasInitiatedUnlock);
        assertEq(unlocksAt, 0);
        assertEq(unlockDelay, 0);
    }

    /// @notice getLockStatus after the delay elapses (with no intervening onlyUnlocked call) still surfaces the
    ///         initiated-unlock state: unlocked, but hasInitiatedUnlock true and unlocksAt unchanged.
    /// @dev getLockStatus is a pure view: it never runs _checkAndClearLock, so the finite unlocksAt is not zeroed and
    ///      the hasInitiatedUnlock branch (unlocksAt != 0 && != max) reports true even though the account is unlocked.
    function test_getLockStatus_success_afterUnlockElapsedNotCleared(
        address account,
        uint16 delay,
        uint256 t0,
        uint256 extra
    ) public {
        _assumeSafeAccount(account);
        delay = uint16(bound(delay, 1, type(uint16).max));
        t0 = bound(t0, 1, 1e9);
        extra = bound(extra, 0, 1e9);

        _lockAccount(account, delay);
        vm.warp(t0);
        _initiateUnlock(account);

        vm.warp(t0 + delay + extra); // past unlocksAt, but no onlyUnlocked call to clear it

        (bool locked, bool hasInitiatedUnlock, uint40 unlocksAt, uint16 storedDelay) =
            accountConfiguration.getLockStatus(account);
        assertFalse(locked);
        assertTrue(hasInitiatedUnlock);
        assertEq(unlocksAt, uint40(t0 + delay));
        assertEq(storedDelay, 0);
    }

    /// @notice Full lock -> initiateUnlock -> warp-past -> config change cycle: once the delay elapses,
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

        _lockAccount(account, delay);
        vm.warp(t0);
        _initiateUnlock(account);
        vm.warp(t0 + delay + extra); // at or past unlocksAt: unlocked
        assertFalse(accountConfiguration.isLocked(account));

        AccountConfiguration.ActorChange[] memory changes = _oneAuthorizeChange(newActorId);
        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, chainId, seq, changes);
        bytes memory auth = _buildK1Auth(pk, digest);

        accountConfiguration.applySignedActorChanges(account, chainId, changes, auth);

        assertTrue(accountConfiguration.isActor(account, newActorId));
        // The onlyUnlocked prelude cleared the stale unlock timestamp back to 0.
        (,, uint40 unlocksAt,) = accountConfiguration.getLockStatus(account);
        assertEq(unlocksAt, 0);
    }
}
