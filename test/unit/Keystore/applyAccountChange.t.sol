// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore} from "../../../src/Keystore.sol";
import {Scopes} from "../../../src/libraries/Scopes.sol";
import {KeystoreTest} from "../../lib/KeystoreTest.sol";

/// @notice §10 test matrix for the account-environment surface driven through {applySignedAccountChanges}: the
///         Multichain channel (no epochs, no unsequenced mode) and the split-layout regression checks. STRAWMAN
///         (pre-PPS): the account-wide lock/unlock ops were removed from Keystore (payer-tier freezing now lives in
///         the account implementation), so their tests were removed here; see CanonicalHighRatePayerAccount tests.
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

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // MULTICHAIN — EXPIRY (channel-aware install-inert)
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice A Multichain AuthorizeActor whose granted expiry is already in the past does NOT revert: like any
    ///         sequenced batch it installs the actor inert and consumes the multichain sequence, so the slot stays
    ///         replayable for a chain catching up. The actor is present (revocable) but not live.
    function test_multichain_authorize_expiredInstallsInert(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        uint64 mcBefore = _multichainSeq(account);

        // Strictly-past expiry: an unsequenced (JIT) batch would skip this, but a sequenced batch (Local or
        // Multichain) installs it inert.
        uint48 pastExpiry = uint48(block.timestamp - 1);
        _applyMultichain(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, pastExpiry, "")));

        // Sequence consumed (no revert), yet the actor is not live (getActorConfig is expiry-aware).
        assertEq(_multichainSeq(account), mcBefore + 1);
        assertFalse(_isActor(account, ACTOR_A));

        // It is nonetheless present: STRAWMAN (pre-PPS) an installed-expired grant is stored pending-revoke, so an
        // explicit revoke reverts AlreadyRevoking (an EMPTY slot would revert UnknownActor) — proving the slot was
        // written rather than skipped.
        Keystore.SignedAccountChanges memory s = _localBatch(pk, account, _one(_revokeChange(ACTOR_A)));
        vm.expectRevert(Keystore.AlreadyRevoking.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    /// @notice New-chain catch-up: a chain onboarded late replays the full multichain history in order. Historical
    ///         expiring grants (already expired at replay time) install inert and advance the counter instead of
    ///         bricking it, so the final still-live grant lands and the chain converges. This is the core reason the
    ///         Multichain channel does not fail-fast on expiry.
    function test_multichain_authorize_expiredHistoryReplaysToLiveGrant(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);

        // Onboarding "in year 3": every past yearly renewal is already expired; only the current grant is live.
        uint48 expiredOld = uint48(block.timestamp - 2);
        uint48 expiredMid = uint48(block.timestamp - 1);
        uint48 liveNow = _future(365 days);

        // seq 0 and seq 1: historical (expired) operator grants — inert, but each consumes its slot.
        _applyMultichain(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, expiredOld, "")));
        assertFalse(_isActor(account, ACTOR_A));
        _applyMultichain(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, expiredMid, "")));
        assertFalse(_isActor(account, ACTOR_A));

        // seq 2: the current renewal is still live -> the operator is now authorized, converged with chains that
        // applied the same history earlier.
        _applyMultichain(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, liveNow, "")));

        assertTrue(_isActor(account, ACTOR_A));
        assertEq(keystore.getActorConfig(account, ACTOR_A).revokeDelayOrExpiry, liveNow);
        assertEq(_multichainSeq(account), 3); // all three slots consumed, gap-free
    }

    /// @notice Self-actor edge: an expired non-k1 self grant on the Multichain channel is handled like any other —
    ///         installed inert (no revert) and consuming the sequence — so replay stays convergent. As with any non-k1
    ///         self grant it also disables the inline k1 self (mutual exclusion); here that self is simply dead on
    ///         arrival, matching the state a chain that applied it while live reaches once it expires.
    function test_multichain_authorize_expiredSelfInstallsInert(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        bytes32 selfActorId = bytes32(uint256(uint160(account)));
        uint64 mcBefore = _multichainSeq(account);

        // Signed by the (still-live at auth time) k1 self; installs an already-expired non-k1 self.
        uint48 pastExpiry = uint48(block.timestamp - 1);
        _applyMultichain(
            pk, account, _one(_authorizeChange(selfActorId, address(p256Authenticator), SENDER, pastExpiry, ""))
        );

        // No revert; slot consumed. The non-k1 self is present but not live (expired).
        assertEq(_multichainSeq(account), mcBefore + 1);
        assertFalse(_isActor(account, selfActorId));
    }

    /// @notice A SEQUENCED local AuthorizeActor with an already-past expiry installs inert (like Multichain), not
    ///         reverts: a sequenced batch is single-consume and cannot be replayed, so the expiry-bound-replay concern
    ///         does not apply. The fail-fast is reserved for the replayable unsequenced (JIT) path (see
    ///         test_authorizeUnsequenced_revert_pastExpiry in applyKeyChange.t.sol).
    function test_local_sequenced_authorize_pastExpiry_installsInert(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        uint64 seqBefore = _localSeqWord(account);

        uint48 pastExpiry = uint48(block.timestamp - 1);
        _applyLocal(pk, account, _one(_authorizeChange(ACTOR_A, address(k1Authenticator), SENDER, pastExpiry, "")));

        // Sequence consumed (no revert); the actor is present but not live.
        assertEq(_localSeqWord(account), seqBefore + 1);
        assertFalse(_isActor(account, ACTOR_A));
        // Present: STRAWMAN (pre-PPS) the installed-expired grant is pending-revoke, so an explicit revoke reverts
        // AlreadyRevoking (an EMPTY slot would revert UnknownActor).
        Keystore.SignedAccountChanges memory s = _localBatch(pk, account, _one(_revokeChange(ACTOR_A)));
        vm.expectRevert(Keystore.AlreadyRevoking.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    /// @notice A Multichain IncrementLocalEpoch bumps the local epoch (resetting the local sequence) and consumes the
    ///         multichain counter, retiring outstanding unlanded local signatures without a Local batch.
    function test_multichain_success_bump(uint256 pk) public {
        pk = _boundK1Pk(pk);
        (address account,) = _createK1Account(pk);
        (uint32 epochBefore,) = _localEpochSeq(account);
        uint64 mcBefore = _multichainSeq(account);

        _applyMultichain(pk, account, _one(_bumpChange()));

        (uint32 epochAfter, uint32 seqAfter) = _localEpochSeq(account);
        assertEq(epochAfter, epochBefore + 1);
        assertEq(seqAfter, 0); // local sequence reset by the epoch bump
        assertEq(_multichainSeq(account), mcBefore + 1);
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
        vm.expectRevert(abi.encodeWithSelector(Keystore.BadSequence.selector, uint64(seq1), uint64(0)));
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
