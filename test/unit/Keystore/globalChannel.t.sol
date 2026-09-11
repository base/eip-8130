// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {KeystoreTest} from "../../lib/KeystoreTest.sol";
import {Keystore} from "../../../src/Keystore.sol";
import {Scopes} from "../../../src/libraries/Scopes.sol";

/// @notice Tests for the symmetric two-track sequencing model. The Multichain (global / all-chains) channel now
///         mirrors the Local (this-chain) channel: it carries its own epoch and both sequenced and unsequenced (JIT)
///         modes. `IncrementEpoch` targets the epoch of the channel it rides on. The two tracks are independent, so
///         this-chain activity never advances or desyncs the global counter.
contract GlobalChannelTest is KeystoreTest {
    uint256 constant ADMIN_PK = 0xA11CE;
    address account;

    bytes32 constant ACTOR_A = bytes32(uint256(0xA1));
    bytes32 constant ACTOR_B = bytes32(uint256(0xB2));
    bytes32 constant ACTOR_C = bytes32(uint256(0xC3));

    function setUp() public override {
        super.setUp();
        (account,) = _createK1Account(ADMIN_PK);
    }

    // ── Global JIT (reusable, no counter) ──

    function test_globalJit_consumesNoCounter() public {
        (uint32 gEpoch0, uint32 gSeq0) = _globalEpochSeq(account);

        _applyGlobalUnsequenced(
            ADMIN_PK, account, _one(_authorizeChange(ACTOR_A, k1Authenticator, Scopes.OPERATOR, UNBOUNDED, ""))
        );
        assertTrue(_isActor(account, ACTOR_A));

        (uint32 gEpoch1, uint32 gSeq1) = _globalEpochSeq(account);
        assertEq(gEpoch1, gEpoch0);
        assertEq(gSeq1, gSeq0); // JIT consumes no global counter
    }

    function test_globalJit_isReplayable() public {
        Keystore.SignedAccountChanges memory jit = _globalUnseqBatch(
            ADMIN_PK, account, _one(_authorizeChange(ACTOR_A, k1Authenticator, Scopes.OPERATOR, UNBOUNDED, ""))
        );
        keystore.applySignedAccountChanges(account, jit);
        assertTrue(_isActor(account, ACTOR_A));

        // Durably clear the actor, then replay the SAME reusable grant: it re-installs (not consumed).
        _applyLocal(ADMIN_PK, account, _one(_revokeChange(ACTOR_A)));
        assertFalse(_isActor(account, ACTOR_A));

        keystore.applySignedAccountChanges(account, jit);
        assertTrue(_isActor(account, ACTOR_A));
    }

    function test_globalJit_retiredByGlobalEpochBump() public {
        Keystore.SignedAccountChanges memory jit = _globalUnseqBatch(
            ADMIN_PK, account, _one(_authorizeChange(ACTOR_A, k1Authenticator, Scopes.OPERATOR, UNBOUNDED, ""))
        );
        keystore.applySignedAccountChanges(account, jit);
        _applyLocal(ADMIN_PK, account, _one(_revokeChange(ACTOR_A)));

        // Bump the GLOBAL epoch (one signed Multichain IncrementEpoch, landed per chain) retires the reusable grant.
        _applyMultichain(ADMIN_PK, account, _one(_bumpChange()));

        vm.expectRevert(Keystore.StaleEpoch.selector);
        keystore.applySignedAccountChanges(account, jit);
    }

    // ── Global epoch ──

    function test_globalEpochBump_resetsGlobalSequenceOnly() public {
        // Advance the global counter once so the reset is observable.
        _applyMultichain(
            ADMIN_PK, account, _one(_authorizeChange(ACTOR_A, k1Authenticator, Scopes.OPERATOR, UNBOUNDED, ""))
        );
        (, uint32 gSeqBefore) = _globalEpochSeq(account);
        assertEq(gSeqBefore, 1);

        _applyMultichain(ADMIN_PK, account, _one(_bumpChange()));

        (uint32 gEpoch, uint32 gSeq) = _globalEpochSeq(account);
        assertEq(gEpoch, 1);
        assertEq(gSeq, 0);
    }

    function test_globalEpoch_staleReverts() public {
        Keystore.SignedAccountChanges memory s = _multichainBatch(
            ADMIN_PK, account, _one(_authorizeChange(ACTOR_A, k1Authenticator, Scopes.OPERATOR, UNBOUNDED, ""))
        );
        _applyMultichain(ADMIN_PK, account, _one(_bumpChange())); // globalEpoch 0 -> 1

        vm.expectRevert(Keystore.StaleEpoch.selector);
        keystore.applySignedAccountChanges(account, s); // committed global epoch 0, now stale
    }

    function test_globalEpoch_saturated() public {
        // Force globalEpoch to its terminal value (globalSequence stays 0).
        _forceGlobalWord(account, uint64(type(uint32).max) << 32);

        Keystore.SignedAccountChanges memory s = _multichainBatch(ADMIN_PK, account, _one(_bumpChange()));
        vm.expectRevert(Keystore.EpochSaturated.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    // ── Track independence (the load-bearing property for global one-shot) ──

    /// @notice A pre-signed global one-shot batch (e.g. "install this admin on every chain") still applies after
    ///         arbitrary LOCAL activity: this-chain ops advance only the local track, never the global counter, so
    ///         the global sequenced batch does not desync across chains.
    function test_globalSequenced_survivesLocalActivity() public {
        // Pre-sign a global sequenced batch at the current global sequence (0).
        Keystore.SignedAccountChanges memory globalBatch = _multichainBatch(
            ADMIN_PK, account, _one(_authorizeChange(ACTOR_A, k1Authenticator, Scopes.OPERATOR, UNBOUNDED, ""))
        );

        // A bunch of LOCAL activity: sequenced adds and a local epoch bump. None touches the global track.
        _applyLocal(ADMIN_PK, account, _one(_authorizeChange(ACTOR_B, k1Authenticator, Scopes.OPERATOR, UNBOUNDED, "")));
        _applyLocal(ADMIN_PK, account, _one(_bumpChange())); // local epoch bump
        _applyLocal(ADMIN_PK, account, _one(_authorizeChange(ACTOR_C, k1Authenticator, Scopes.OPERATOR, UNBOUNDED, "")));

        (uint32 gEpoch, uint32 gSeq) = _globalEpochSeq(account);
        assertEq(gEpoch, 0);
        assertEq(gSeq, 0); // global track untouched by all the local activity

        // The pre-signed global batch still lands.
        keystore.applySignedAccountChanges(account, globalBatch);
        assertTrue(_isActor(account, ACTOR_A));
    }

    /// @notice A local epoch bump does not retire outstanding GLOBAL grants (and vice versa) — the epochs are
    ///         independent revocation generations.
    function test_localEpochBump_doesNotRetireGlobalGrants() public {
        Keystore.SignedAccountChanges memory jit = _globalUnseqBatch(
            ADMIN_PK, account, _one(_authorizeChange(ACTOR_A, k1Authenticator, Scopes.OPERATOR, UNBOUNDED, ""))
        );
        keystore.applySignedAccountChanges(account, jit);
        _applyLocal(ADMIN_PK, account, _one(_revokeChange(ACTOR_A)));

        // Bump the LOCAL epoch: the global JIT grant is on the other track and stays valid.
        _applyLocal(ADMIN_PK, account, _one(_bumpChange()));

        keystore.applySignedAccountChanges(account, jit);
        assertTrue(_isActor(account, ACTOR_A));
    }
}
