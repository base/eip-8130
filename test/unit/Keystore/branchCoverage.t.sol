// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore} from "../../../src/Keystore.sol";
import {KeystoreTest} from "../../lib/KeystoreTest.sol";

/// @notice Targeted tests closing the remaining reachable branches in {Keystore}: the zero-account guard, the
///         revoke-unknown-actor guard, the environment-op payload-length guards, the expired inline-self read, the
///         elapsed-unlock lock-status read, and the policy-slice length guards. Grouped here rather than scattered
///         across the behavioral suites because each is a defensive edge rather than a feature.
contract KeystoreBranchCoverageTest is KeystoreTest {
    uint256 constant OWNER_PK = 0xB0B;

    // ── nonZeroAccount modifier ──

    /// @notice The zero address is rejected before any signature work (modifier runs first).
    function test_applySignedAccountChanges_revert_zeroAccount() public {
        Keystore.SignedAccountChanges memory s = Keystore.SignedAccountChanges({
            channel: Keystore.AccountChangeChannel.Local,
            sequence: 0,
            changes: new Keystore.AccountChange[](0),
            signature: ""
        });
        vm.expectRevert(Keystore.ZeroAccount.selector);
        keystore.applySignedAccountChanges(address(0), s);
    }

    // ── RevokeActor ──

    /// @notice Revoking an actorId that was never authorized reverts UnknownActor.
    function test_revoke_revert_unknownActor() public {
        (address account,) = _createK1Account(OWNER_PK);
        bytes32 ghost = bytes32(uint256(0xDEAD));
        Keystore.SignedAccountChanges memory s = _localBatch(OWNER_PK, account, _one(_revokeChange(ghost)));
        vm.expectRevert(Keystore.UnknownActor.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    // ── Environment-op payload guards ──

    /// @notice IncrementLocalEpoch carries an empty payload; a non-empty one reverts InvalidChangePayload.
    function test_incrementLocalEpoch_revert_nonEmptyPayload() public {
        (address account,) = _createK1Account(OWNER_PK);
        Keystore.AccountChange memory change =
            Keystore.AccountChange({changeType: Keystore.ChangeType.IncrementLocalEpoch, payload: hex"01"});
        Keystore.SignedAccountChanges memory s = _localBatch(OWNER_PK, account, _one(change));
        vm.expectRevert(Keystore.InvalidChangePayload.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    /// @notice Unlock carries an empty payload; a non-empty one reverts InvalidChangePayload (checked before state).
    function test_unlock_revert_nonEmptyPayload() public {
        (address account,) = _createK1Account(OWNER_PK);
        Keystore.AccountChange memory change =
            Keystore.AccountChange({changeType: Keystore.ChangeType.Unlock, payload: hex"01"});
        Keystore.SignedAccountChanges memory s = _localBatch(OWNER_PK, account, _one(change));
        vm.expectRevert(Keystore.InvalidChangePayload.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    // ── getActorConfig: expired inline self ──

    /// @notice getActorConfig returns the empty config for the inline self once its granted expiry has elapsed.
    function test_getActorConfig_success_selfExpiredReturnsEmpty() public {
        (address account,) = _createK1Account(OWNER_PK);
        bytes32 selfId = bytes32(uint256(uint160(account)));

        // Re-enable the inline self with a bounded expiry (createAccount revokes the default EOA).
        uint48 expiry = uint48(block.timestamp + 1 hours);
        _applyLocal(OWNER_PK, account, _one(_authorizeChange(selfId, k1Authenticator, 0, expiry, "")));

        // Live before expiry.
        assertEq(keystore.getActorConfig(account, selfId).authenticator, k1Authenticator);

        vm.warp(block.timestamp + 2 hours);

        // Expired: the self path returns the empty config rather than the stale slot.
        assertEq(keystore.getActorConfig(account, selfId).authenticator, address(0));
    }

    // ── getLockStatus: elapsed pending unlock ──

    /// @notice Once a pending unlock's timestamp has elapsed, getLockStatus reports the clean unlocked state.
    function test_getLockStatus_success_elapsedUnlockReportsUnlocked() public {
        (address account,) = _createK1Account(OWNER_PK);

        _signedLock(OWNER_PK, account, 100);
        _signedUnlock(OWNER_PK, account); // initiates: unlocksAt = now + 100

        (bool lockedBefore, bool initiatedBefore,,) = keystore.getLockStatus(account);
        assertTrue(lockedBefore);
        assertTrue(initiatedBefore);

        vm.warp(block.timestamp + 101);

        (bool locked, bool initiated, uint48 unlocksAt, uint16 delay) = keystore.getLockStatus(account);
        assertFalse(locked);
        assertFalse(initiated);
        assertEq(unlocksAt, 0);
        assertEq(delay, 0);
    }

    // ── Multichain sequence saturation ──

    /// @notice A Multichain batch at the terminal counter (type(uint64).max) reverts SequenceSaturated.
    function test_multichain_revert_sequenceSaturated() public {
        (address account,) = _createK1Account(OWNER_PK);

        // Force the multichain counter (low 64 bits of the packed AccountState slot at base-slot 3) to its max.
        bytes32 slot = keccak256(abi.encode(account, uint256(3)));
        uint256 cur = uint256(vm.load(address(keystore), slot));
        uint256 updated = (cur & ~uint256(type(uint64).max)) | uint256(type(uint64).max);
        vm.store(address(keystore), slot, bytes32(updated));

        Keystore.AccountChange memory change = _authorizeChange(bytes32(uint256(1)), k1Authenticator, 0, UNBOUNDED, "");
        Keystore.SignedAccountChanges memory s = _multichainBatch(OWNER_PK, account, _one(change));
        vm.expectRevert(Keystore.SequenceSaturated.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    // ── _slicePolicy length guards ──

    /// @notice An ungated actor (scope without POLICY) must carry no policy data.
    function test_authorize_revert_ungatedActorWithPolicyData() public {
        (address account,) = _createK1Account(OWNER_PK);
        bytes32 actorId = bytes32(uint256(0xA11CE));
        Keystore.AccountChange memory change = _authorizeChange(actorId, k1Authenticator, 0, UNBOUNDED, hex"01");
        Keystore.SignedAccountChanges memory s = _localBatch(OWNER_PK, account, _one(change));
        vm.expectRevert(Keystore.InvalidPolicyData.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    /// @notice A policy-gated actor must carry exactly 52 bytes (manager(20) || commitment(32)) of policy data.
    function test_authorize_revert_policyActorWrongLengthData() public {
        (address account,) = _createK1Account(OWNER_PK);
        bytes32 actorId = bytes32(uint256(0xA11CE));
        // Scopes.POLICY == 0x02; 5 bytes is neither empty nor the required 52.
        Keystore.AccountChange memory change =
            _authorizeChange(actorId, k1Authenticator, 0x02, UNBOUNDED, hex"0102030405");
        Keystore.SignedAccountChanges memory s = _localBatch(OWNER_PK, account, _one(change));
        vm.expectRevert(Keystore.InvalidPolicyData.selector);
        keystore.applySignedAccountChanges(account, s);
    }

    /// @notice A policy-gated actor with the exact 52-byte policy data authorizes successfully.
    function test_authorize_success_policyActorValidData() public {
        (address account,) = _createK1Account(OWNER_PK);
        bytes32 actorId = bytes32(uint256(0xA11CE));
        address policyManager = address(0xCAFE);
        bytes32 commitment = keccak256("commitment");
        bytes memory policyData = abi.encodePacked(policyManager, commitment); // 20 + 32 = 52 bytes
        _applyLocal(OWNER_PK, account, _one(_authorizeChange(actorId, k1Authenticator, 0x02, UNBOUNDED, policyData)));

        assertEq(keystore.getActorConfig(account, actorId).authenticator, k1Authenticator);
        assertEq(keystore.getPolicyManager(account, actorId), policyManager);
        assertEq(keystore.getPolicyCommitment(account, actorId), commitment);
    }
}
