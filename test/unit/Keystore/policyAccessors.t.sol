// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore} from "../../../src/Keystore.sol";
import {Scopes} from "../../../src/libraries/Scopes.sol";
import {KeystoreTest} from "../../lib/KeystoreTest.sol";

/// @notice Fully-fuzzed unit tests for the policy accessors on `Keystore`:
///           - `getPolicy(account, actorId)`           — off-chain aggregate: (manager, commitment)
///           - `getPolicyCommitment(account, actorId)` — single-SLOAD hot-path read
///           - `getPolicyManager(account, actorId)`    — single-SLOAD hot-path read (the resolved policy target)
///
///         All are `view`; there are no events to assert. Every test fuzzes its inputs (managers, commitments,
///         actorIds, keys, scopes). Gating is determined by the SCOPE_POLICY bit, never by "slot non-zero": a
///         policy-bearing actor's policyData is exactly 52 bytes (manager(20) || commitment(32)) and is written
///         verbatim, even when a field is zero. Tests bound manager/commitment to non-zero only so the written
///         value is distinguishable from the ungated (unwritten, zero) case.
contract PolicyAccessorsTest is KeystoreTest {
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // getPolicy — explicit (non-self) actor home  (stored.authenticator != 0)
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice A gated non-self actor: getPolicy returns (manager, commitment) and the aggregate agrees with the
    ///         granular accessors. Covers the explicit-actor home.
    function test_getPolicy_success_explicitGatedActor(
        uint256 rootSeed,
        bytes32 actorId,
        uint8 scopeSeed,
        uint256 managerSeed,
        uint256 commitmentSeed
    ) public {
        uint256 rootPk = _boundK1Pk(rootSeed);
        (address account,) = _createK1Account(rootPk);
        actorId = _boundExplicitActorId(account, rootPk, actorId);

        uint16 scope = _boundGatedScope(scopeSeed);
        address manager = _boundNonZeroAddress(managerSeed);
        bytes32 commitment = _boundNonZeroWord(commitmentSeed);

        _authorizePolicyActor(account, rootPk, actorId, scope, manager, commitment);

        (address outManager, bytes32 outCommitment) = keystore.getPolicy(account, actorId);
        assertEq(outManager, manager);
        assertEq(outCommitment, commitment);
        // Aggregate agrees with the single-SLOAD granular accessors.
        assertEq(outManager, keystore.getPolicyManager(account, actorId));
        assertEq(outCommitment, keystore.getPolicyCommitment(account, actorId));
    }

    /// @notice A non-self actor authorized ungated (scope & SCOPE_POLICY == 0): getPolicy returns (0, 0). Covers
    ///         the explicit-actor home with no policy slots written.
    function test_getPolicy_success_ungatedExplicitActor_returnsNone(uint256 rootSeed, bytes32 actorId) public {
        uint256 rootPk = _boundK1Pk(rootSeed);
        (address account,) = _createK1Account(rootPk);
        actorId = _boundExplicitActorId(account, rootPk, actorId);

        _authorizeUngatedActor(account, rootPk, actorId, address(k1Authenticator));

        (address outManager, bytes32 outCommitment) = keystore.getPolicy(account, actorId);
        assertEq(outManager, address(0));
        assertEq(outCommitment, bytes32(0));
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // getPolicy — inline-k1-self home  (else-if actorId == self && !revoked)
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    //
    // The inline-k1 self stores scope/expiry in AccountState, but manager/commitment live in the shared
    // actorId-keyed keyspace — so the accessors must resolve identically to the explicit-actor home.

    /// @notice A gated inline-k1 self: getPolicy returns (manager, commitment) and agrees with the granular
    ///         accessors. Covers the inline-self home.
    function test_getPolicy_success_inlineSelfGatedActor(
        uint256 eoaSeed,
        uint8 scopeSeed,
        uint256 managerSeed,
        uint256 commitmentSeed
    ) public {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        uint16 scope = _boundGatedScope(scopeSeed);
        address manager = _boundNonZeroAddress(managerSeed);
        bytes32 commitment = _boundNonZeroWord(commitmentSeed);

        _authorizeInlineSelfWithPolicy(eoa, eoaPk, scope, manager, commitment);

        (address outManager, bytes32 outCommitment) = keystore.getPolicy(eoa, selfActorId);
        assertEq(outManager, manager);
        assertEq(outCommitment, commitment);
        assertEq(outManager, keystore.getPolicyManager(eoa, selfActorId));
        assertEq(outCommitment, keystore.getPolicyCommitment(eoa, selfActorId));
    }

    /// @notice A fresh EOA's implicit self (full owner, ungated): getPolicy returns (0, 0). Covers the inline-self
    ///         home (else-if true, no _actorConfig, not revoked) with no policy slots written.
    function test_getPolicy_success_inlineSelfUngated_returnsNone(uint256 eoaSeed) public view {
        address eoa = vm.addr(_boundK1Pk(eoaSeed));
        bytes32 selfActorId = bytes32(bytes20(eoa));

        (address outManager, bytes32 outCommitment) = keystore.getPolicy(eoa, selfActorId);
        assertEq(outManager, address(0));
        assertEq(outCommitment, bytes32(0));
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // getPolicy — else branch  (unknown actor / revoked self)
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice An unknown (never-authorized, non-self) actor: getPolicy returns (0, 0) over empty state.
    function test_getPolicy_success_unknownActor_returnsNone(address account, bytes32 actorId) public view {
        vm.assume(actorId != bytes32(bytes20(account))); // stay off the inline-self else-if

        (address outManager, bytes32 outCommitment) = keystore.getPolicy(account, actorId);
        assertEq(outManager, address(0));
        assertEq(outCommitment, bytes32(0));
    }

    /// @notice A gated inline self that is then revoked: getPolicy returns (0, 0). The revoke clears the shared
    ///         (actorId-keyed) policy slots.
    function test_getPolicy_success_revokedInlineSelf_returnsNone(
        uint256 eoaSeed,
        uint256 ownerSeed,
        uint8 scopeSeed,
        uint256 managerSeed,
        uint256 commitmentSeed
    ) public {
        (address eoa, uint256 ownerPk) = _seedGatedInlineSelfWithSpareOwner(
            eoaSeed, ownerSeed, scopeSeed, managerSeed, commitmentSeed
        );
        bytes32 selfActorId = bytes32(bytes20(eoa));

        // Revoke the (downgraded) self via the spare unrestricted owner; the policy-scoped self cannot sign config.
        _revokeActor(eoa, ownerPk, selfActorId);

        (address outManager, bytes32 outCommitment) = keystore.getPolicy(eoa, selfActorId);
        assertEq(outManager, address(0));
        assertEq(outCommitment, bytes32(0));
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // getPolicyManager / getPolicyCommitment — single-SLOAD granular reads
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    function test_getPolicyManager_success_explicitGatedActor(
        uint256 rootSeed,
        bytes32 actorId,
        uint8 scopeSeed,
        uint256 managerSeed,
        uint256 commitmentSeed
    ) public {
        uint256 rootPk = _boundK1Pk(rootSeed);
        (address account,) = _createK1Account(rootPk);
        actorId = _boundExplicitActorId(account, rootPk, actorId);

        address manager = _boundNonZeroAddress(managerSeed);
        _authorizePolicyActor(
            account, rootPk, actorId, _boundGatedScope(scopeSeed), manager, _boundNonZeroWord(commitmentSeed)
        );

        assertEq(keystore.getPolicyManager(account, actorId), manager);
    }

    function test_getPolicyCommitment_success_explicitGatedActor(
        uint256 rootSeed,
        bytes32 actorId,
        uint8 scopeSeed,
        uint256 managerSeed,
        uint256 commitmentSeed
    ) public {
        uint256 rootPk = _boundK1Pk(rootSeed);
        (address account,) = _createK1Account(rootPk);
        actorId = _boundExplicitActorId(account, rootPk, actorId);

        bytes32 commitment = _boundNonZeroWord(commitmentSeed);
        _authorizePolicyActor(
            account, rootPk, actorId, _boundGatedScope(scopeSeed), _boundNonZeroAddress(managerSeed), commitment
        );

        assertEq(keystore.getPolicyCommitment(account, actorId), commitment);
    }

    function test_getPolicyManager_success_inlineSelfGatedActor(
        uint256 eoaSeed,
        uint8 scopeSeed,
        uint256 managerSeed,
        uint256 commitmentSeed
    ) public {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        address manager = _boundNonZeroAddress(managerSeed);
        _authorizeInlineSelfWithPolicy(
            eoa, eoaPk, _boundGatedScope(scopeSeed), manager, _boundNonZeroWord(commitmentSeed)
        );

        assertEq(keystore.getPolicyManager(eoa, selfActorId), manager);
    }

    function test_getPolicyCommitment_success_inlineSelfGatedActor(
        uint256 eoaSeed,
        uint8 scopeSeed,
        uint256 managerSeed,
        uint256 commitmentSeed
    ) public {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        bytes32 commitment = _boundNonZeroWord(commitmentSeed);
        _authorizeInlineSelfWithPolicy(
            eoa, eoaPk, _boundGatedScope(scopeSeed), _boundNonZeroAddress(managerSeed), commitment
        );

        assertEq(keystore.getPolicyCommitment(eoa, selfActorId), commitment);
    }

    /// @notice An ungated actor never has manager/commitment written (per `_authorizeActor`'s SCOPE_POLICY-gated
    ///         writes), so both granular accessors return zero.
    function test_getPolicyManager_success_ungatedActor_returnsZero(uint256 rootSeed, bytes32 actorId) public {
        uint256 rootPk = _boundK1Pk(rootSeed);
        (address account,) = _createK1Account(rootPk);
        actorId = _boundExplicitActorId(account, rootPk, actorId);

        _authorizeUngatedActor(account, rootPk, actorId, address(k1Authenticator));

        assertEq(keystore.getPolicyManager(account, actorId), address(0));
    }

    function test_getPolicyCommitment_success_ungatedActor_returnsZero(uint256 rootSeed, bytes32 actorId) public {
        uint256 rootPk = _boundK1Pk(rootSeed);
        (address account,) = _createK1Account(rootPk);
        actorId = _boundExplicitActorId(account, rootPk, actorId);

        _authorizeUngatedActor(account, rootPk, actorId, address(k1Authenticator));

        assertEq(keystore.getPolicyCommitment(account, actorId), bytes32(0));
    }

    /// @notice An unknown actor's granular slots are empty: both accessors return zero over untouched state.
    function test_getPolicyManager_success_unknownActor_returnsZero(address account, bytes32 actorId) public view {
        assertEq(keystore.getPolicyManager(account, actorId), address(0));
    }

    function test_getPolicyCommitment_success_unknownActor_returnsZero(address account, bytes32 actorId) public view {
        assertEq(keystore.getPolicyCommitment(account, actorId), bytes32(0));
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // Lifecycle — invariant: policy slots written iff scope & SCOPE_POLICY
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Revoking an explicit gated actor clears both policy slots (`_revokeActor` deletes them).
    function test_getPolicyAccessors_success_clearedOnRevoke(
        uint256 rootSeed,
        bytes32 actorId,
        uint8 scopeSeed,
        uint256 managerSeed,
        uint256 commitmentSeed
    ) public {
        uint256 rootPk = _boundK1Pk(rootSeed);
        (address account,) = _createK1Account(rootPk);
        actorId = _boundExplicitActorId(account, rootPk, actorId);

        address manager = _boundNonZeroAddress(managerSeed);
        bytes32 commitment = _boundNonZeroWord(commitmentSeed);
        _authorizePolicyActor(account, rootPk, actorId, _boundGatedScope(scopeSeed), manager, commitment);

        // Live first.
        assertEq(keystore.getPolicyManager(account, actorId), manager);
        assertEq(keystore.getPolicyCommitment(account, actorId), commitment);

        _revokeActor(account, rootPk, actorId);

        assertEq(keystore.getPolicyManager(account, actorId), address(0));
        assertEq(keystore.getPolicyCommitment(account, actorId), bytes32(0));
    }

    /// @notice Revoking a gated inline self clears the shared (actorId-keyed) policy slots too.
    function test_getPolicyAccessors_success_clearedOnInlineSelfRevoke(
        uint256 eoaSeed,
        uint256 ownerSeed,
        uint8 scopeSeed,
        uint256 managerSeed,
        uint256 commitmentSeed
    ) public {
        (address eoa, uint256 ownerPk) =
            _seedGatedInlineSelfWithSpareOwner(eoaSeed, ownerSeed, scopeSeed, managerSeed, commitmentSeed);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        // Live first.
        assertTrue(keystore.getPolicyManager(eoa, selfActorId) != address(0));
        assertTrue(keystore.getPolicyCommitment(eoa, selfActorId) != bytes32(0));

        _revokeActor(eoa, ownerPk, selfActorId);

        assertEq(keystore.getPolicyManager(eoa, selfActorId), address(0));
        assertEq(keystore.getPolicyCommitment(eoa, selfActorId), bytes32(0));
    }

    /// @notice Re-authorizing a gated actor down to an ungated scope clears both policy slots (no stale leak) and
    ///         the config's scope falls to zero.
    function test_getPolicyAccessors_success_clearedOnReauthorizeToNone(
        uint256 rootSeed,
        bytes32 actorId,
        uint8 scopeSeed,
        uint256 managerSeed,
        uint256 commitmentSeed
    ) public {
        uint256 rootPk = _boundK1Pk(rootSeed);
        (address account,) = _createK1Account(rootPk);
        actorId = _boundExplicitActorId(account, rootPk, actorId);

        _authorizePolicyActor(
            account,
            rootPk,
            actorId,
            _boundGatedScope(scopeSeed),
            _boundNonZeroAddress(managerSeed),
            _boundNonZeroWord(commitmentSeed)
        );

        // Overwrite the same actor as ungated (scope & SCOPE_POLICY == 0).
        _authorizeUngatedActor(account, rootPk, actorId, address(k1Authenticator));

        assertEq(keystore.getPolicyManager(account, actorId), address(0));
        assertEq(keystore.getPolicyCommitment(account, actorId), bytes32(0));
        Keystore.ActorConfig memory cfg = keystore.getActorConfig(account, actorId);
        assertEq(cfg.scope, uint8(0x00));
    }

    /// @notice Re-authorizing a gated actor to a *different* (manager, commitment) replaces rather than merges.
    function test_getPolicyAccessors_success_updatedOnReauthorizeToNewManager(
        uint256 rootSeed,
        bytes32 actorId,
        uint8 scopeSeed,
        uint256 managerSeed,
        uint256 commitmentSeed,
        uint256 newManagerSeed,
        uint256 newCommitmentSeed
    ) public {
        uint256 rootPk = _boundK1Pk(rootSeed);
        (address account,) = _createK1Account(rootPk);
        actorId = _boundExplicitActorId(account, rootPk, actorId);

        uint16 scope = _boundGatedScope(scopeSeed);
        address manager = _boundNonZeroAddress(managerSeed);
        bytes32 commitment = _boundNonZeroWord(commitmentSeed);
        address newManager = _boundNonZeroAddress(newManagerSeed);
        bytes32 newCommitment = _boundNonZeroWord(newCommitmentSeed);
        // Make the update observable.
        vm.assume(newManager != manager);
        vm.assume(newCommitment != commitment);

        _authorizePolicyActor(account, rootPk, actorId, scope, manager, commitment);
        _authorizePolicyActor(account, rootPk, actorId, scope, newManager, newCommitment);

        assertEq(keystore.getPolicyManager(account, actorId), newManager);
        assertEq(keystore.getPolicyCommitment(account, actorId), newCommitment);
    }

    /// @notice A gated actor may legitimately carry a zero manager and/or zero commitment: the relaxed policyData
    ///         rule writes both slots verbatim. Gating is by the SCOPE_POLICY bit, not slot non-zero.
    function test_getPolicyAccessors_success_gatedWithZeroManagerAndCommitment(uint256 rootSeed, bytes32 actorId)
        public
    {
        uint256 rootPk = _boundK1Pk(rootSeed);
        (address account,) = _createK1Account(rootPk);
        actorId = _boundExplicitActorId(account, rootPk, actorId);

        _authorizePolicyActor(account, rootPk, actorId, Scopes.POLICY, address(0), bytes32(0));

        // Slots are zero, yet the actor is gated by the SCOPE_POLICY bit.
        assertEq(keystore.getPolicyManager(account, actorId), address(0));
        assertEq(keystore.getPolicyCommitment(account, actorId), bytes32(0));
        Keystore.ActorConfig memory cfg = keystore.getActorConfig(account, actorId);
        assertTrue(cfg.scope & Scopes.POLICY != 0);
    }

    /// @notice This contract does not reject scope combinations: an actor may carry SCOPE_POLICY alongside any
    ///         other scope bits — use-time exclusivity is protocol-side, not enforced here.
    function test_authorizePolicyActor_allowsAnyScopeCombination(
        uint256 rootSeed,
        uint256 managerSeed,
        uint256 commitmentSeed
    ) public {
        uint256 rootPk = _boundK1Pk(rootSeed);
        (address account,) = _createK1Account(rootPk);
        address manager = _boundNonZeroAddress(managerSeed);
        bytes32 commitment = _boundNonZeroWord(commitmentSeed);

        uint16[4] memory otherScopes = [uint16(0), Scopes.SELF_PAYER, Scopes.SPONSOR_PAYER, Scopes.NONCE];
        for (uint256 i; i < otherScopes.length; i++) {
            // Policy actors are keyed by actorId only; no signing key is needed, so a distinct address-shaped id
            // avoids the vm.addr curve-order bound on an unbounded rootPk + i.
            bytes32 actorId = bytes32(bytes20(address(uint160(1000 + i))));
            uint16 scope = otherScopes[i] | Scopes.POLICY;
            _authorizePolicyActor(account, rootPk, actorId, scope, manager, commitment);

            assertEq(keystore.getPolicyManager(account, actorId), manager);
            assertEq(keystore.getPolicyCommitment(account, actorId), commitment);
        }
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // Isolation — correct (account, actorId) mapping-key derivation
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Two distinct actors on the same account keep independent (manager, commitment): no cross-actor leak.
    function test_getPolicyAccessors_success_isolatedAcrossActors(
        uint256 rootSeed,
        bytes32 actorA,
        bytes32 actorB,
        uint8 scopeSeed,
        uint256 managerSeedA,
        uint256 commitmentSeedA,
        uint256 managerSeedB,
        uint256 commitmentSeedB
    ) public {
        uint256 rootPk = _boundK1Pk(rootSeed);
        (address account,) = _createK1Account(rootPk);
        actorA = _boundExplicitActorId(account, rootPk, actorA);
        actorB = _boundExplicitActorId(account, rootPk, actorB);
        vm.assume(actorA != actorB);

        uint16 scope = _boundGatedScope(scopeSeed);
        address managerA = _boundNonZeroAddress(managerSeedA);
        bytes32 commitmentA = _boundNonZeroWord(commitmentSeedA);
        address managerB = _boundNonZeroAddress(managerSeedB);
        bytes32 commitmentB = _boundNonZeroWord(commitmentSeedB);

        _authorizePolicyActor(account, rootPk, actorA, scope, managerA, commitmentA);
        _authorizePolicyActor(account, rootPk, actorB, scope, managerB, commitmentB);

        assertEq(keystore.getPolicyManager(account, actorA), managerA);
        assertEq(keystore.getPolicyCommitment(account, actorA), commitmentA);
        assertEq(keystore.getPolicyManager(account, actorB), managerB);
        assertEq(keystore.getPolicyCommitment(account, actorB), commitmentB);
    }

    /// @notice The same actorId across two distinct accounts resolves to distinct (manager, commitment) — the inner
    ///         mapping is keyed by account, so nothing leaks across accounts.
    function test_getPolicyAccessors_success_isolatedAcrossAccounts(
        uint256 rootSeed,
        bytes32 saltA,
        bytes32 saltB,
        bytes32 sharedActorId,
        uint8 scopeSeed,
        uint256 managerSeedA,
        uint256 commitmentSeedA,
        uint256 managerSeedB,
        uint256 commitmentSeedB
    ) public {
        vm.assume(saltA != saltB);
        uint256 rootPk = _boundK1Pk(rootSeed);
        (address accountA,) = _createK1AccountWithSalt(rootPk, saltA);
        (address accountB,) = _createK1AccountWithSalt(rootPk, saltB);
        bytes32 rootActorId = bytes32(bytes20(vm.addr(rootPk)));
        // Keep the shared actorId a non-self, non-owner explicit actor on both accounts.
        vm.assume(sharedActorId != rootActorId);
        vm.assume(sharedActorId != bytes32(bytes20(accountA)));
        vm.assume(sharedActorId != bytes32(bytes20(accountB)));

        uint16 scope = _boundGatedScope(scopeSeed);
        address managerA = _boundNonZeroAddress(managerSeedA);
        bytes32 commitmentA = _boundNonZeroWord(commitmentSeedA);
        address managerB = _boundNonZeroAddress(managerSeedB);
        bytes32 commitmentB = _boundNonZeroWord(commitmentSeedB);

        _authorizePolicyActor(accountA, rootPk, sharedActorId, scope, managerA, commitmentA);
        _authorizePolicyActor(accountB, rootPk, sharedActorId, scope, managerB, commitmentB);

        assertEq(keystore.getPolicyManager(accountA, sharedActorId), managerA);
        assertEq(keystore.getPolicyCommitment(accountA, sharedActorId), commitmentA);
        assertEq(keystore.getPolicyManager(accountB, sharedActorId), managerB);
        assertEq(keystore.getPolicyCommitment(accountB, sharedActorId), commitmentB);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // policyTarget — resolved via getPolicyManager (an execution-time read, not an authenticateActor return)
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    //
    // authenticateActor returns (actorId, scope); the policy manager is resolved separately via getPolicyManager
    // (address(0) when unwritten). These tests authenticate to confirm the actor is live, then read the manager.

    /// @notice A gated non-self actor authenticates; getPolicyManager resolves to the stored manager.
    function test_policyTarget_success_gatedExplicitActor_returnsManager(
        uint256 rootSeed,
        uint256 sessionSeed,
        uint8 scopeSeed,
        uint256 managerSeed,
        uint256 commitmentSeed,
        bytes32 hash
    ) public {
        uint256 rootPk = _boundK1Pk(rootSeed);
        uint256 sessionPk = _boundK1Pk(sessionSeed);
        vm.assume(vm.addr(rootPk) != vm.addr(sessionPk));

        (address account,) = _createK1Account(rootPk);
        vm.assume(vm.addr(sessionPk) != account); // stay off the inline-self path
        bytes32 sessionActorId = bytes32(bytes20(vm.addr(sessionPk)));

        address manager = _boundNonZeroAddress(managerSeed);
        _authorizePolicyActor(
            account, rootPk, sessionActorId, _boundGatedScope(scopeSeed), manager, _boundNonZeroWord(commitmentSeed)
        );

        (, uint16 outScope) = keystore.authenticateActor(account, hash, _buildK1Auth(sessionPk, hash));
        assertTrue(outScope & Scopes.POLICY != 0);
        assertEq(keystore.getPolicyManager(account, sessionActorId), manager);
    }

    /// @notice An ungated non-self actor authenticates; getPolicyManager is address(0) (no manager slot written).
    function test_policyTarget_success_ungatedActor_returnsZero(uint256 rootSeed, uint256 sessionSeed, bytes32 hash)
        public
    {
        uint256 rootPk = _boundK1Pk(rootSeed);
        uint256 sessionPk = _boundK1Pk(sessionSeed);
        vm.assume(vm.addr(rootPk) != vm.addr(sessionPk));

        (address account,) = _createK1Account(rootPk);
        vm.assume(vm.addr(sessionPk) != account);
        bytes32 sessionActorId = bytes32(bytes20(vm.addr(sessionPk)));

        _authorizeUngatedActor(account, rootPk, sessionActorId, address(k1Authenticator));

        keystore.authenticateActor(account, hash, _buildK1Auth(sessionPk, hash));
        assertEq(keystore.getPolicyManager(account, sessionActorId), address(0));
    }

    /// @notice A gated inline self authenticates; getPolicyManager resolves to the stored manager via the inline home.
    function test_policyTarget_success_inlineSelfGated_returnsManager(
        uint256 eoaSeed,
        uint8 scopeSeed,
        uint256 managerSeed,
        uint256 commitmentSeed,
        bytes32 hash
    ) public {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        address manager = _boundNonZeroAddress(managerSeed);
        _authorizeInlineSelfWithPolicy(
            eoa, eoaPk, _boundGatedScope(scopeSeed), manager, _boundNonZeroWord(commitmentSeed)
        );

        keystore.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));
        assertEq(keystore.getPolicyManager(eoa, selfActorId), manager);
    }

    /// @notice A fresh EOA (implicit full owner, ungated) authenticates; getPolicyManager is address(0) over
    ///         untouched state.
    function test_policyTarget_success_inlineSelfFullOwner_returnsZero(uint256 eoaSeed, bytes32 hash) public view {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        address eoa = vm.addr(eoaPk);

        (, uint16 outScope) = keystore.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));
        assertEq(outScope, uint16(0x00));
        assertEq(keystore.getPolicyManager(eoa, bytes32(bytes20(eoa))), address(0));
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // Fuzz-input bounding helpers
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @dev A policy-bearing actor's scope: always carries Scopes.POLICY, with arbitrary other bits mixed in.
    function _boundGatedScope(uint8 seed) internal pure returns (uint16) {
        return uint16(seed) | Scopes.POLICY;
    }

    /// @dev A non-zero policy manager address (so a written slot is distinguishable from an unwritten one).
    function _boundNonZeroAddress(uint256 seed) internal pure returns (address) {
        return address(uint160(bound(seed, 1, type(uint160).max)));
    }

    /// @dev A non-zero policy commitment word (so a written slot is distinguishable from an unwritten one).
    function _boundNonZeroWord(uint256 seed) internal pure returns (bytes32) {
        return bytes32(bound(seed, 1, type(uint256).max));
    }

    /// @dev Constrain a fuzzed actorId to a non-self, non-owner explicit-actor key on `account`: distinct from the
    ///      self-actorId (which would route to the inline-self home) and from the root owner's actorId (which would
    ///      overwrite the owner). actorId is otherwise an opaque bytes32 the protocol does not format-check.
    function _boundExplicitActorId(address account, uint256 rootPk, bytes32 actorId) internal pure returns (bytes32) {
        vm.assume(actorId != bytes32(bytes20(account)));
        vm.assume(actorId != bytes32(bytes20(vm.addr(rootPk))));
        return actorId;
    }

    /// @dev Seed a gated inline-k1 self plus a spare unrestricted owner able to sign a later self-revoke. Returns
    ///      (eoa, spareOwnerPk). The self is downgraded to a policy scope (admin is exactly scope == 0) and thus
    ///      cannot sign config changes, so the spare owner is what revokes it.
    function _seedGatedInlineSelfWithSpareOwner(
        uint256 eoaSeed,
        uint256 ownerSeed,
        uint8 scopeSeed,
        uint256 managerSeed,
        uint256 commitmentSeed
    ) internal returns (address eoa, uint256 ownerPk) {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        ownerPk = _boundK1Pk(ownerSeed);
        vm.assume(vm.addr(eoaPk) != vm.addr(ownerPk));
        eoa = vm.addr(eoaPk);
        bytes32 ownerActorId = bytes32(bytes20(vm.addr(ownerPk)));
        vm.assume(ownerActorId != bytes32(bytes20(eoa)));

        // Pre-authorize the spare unrestricted owner (signed by the still-full-owner self).
        _authorizeUngatedActor(eoa, eoaPk, ownerActorId, address(k1Authenticator));

        // Downgrade the self to a gated policy actor (signed by the still-full-owner self).
        _authorizeInlineSelfWithPolicy(
            eoa,
            eoaPk,
            _boundGatedScope(scopeSeed),
            _boundNonZeroAddress(managerSeed),
            _boundNonZeroWord(commitmentSeed)
        );
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // Actor-change helpers (signed applySignedActorChanges wrappers)
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @dev Authorize a non-self actor with a gated policy bound to (manager, commitment), signed by the root owner.
    ///      `scope` must carry SCOPE_POLICY.
    function _authorizePolicyActor(
        address account,
        uint256 rootPk,
        bytes32 actorId,
        uint16 scope,
        address policyManager,
        bytes32 commitment
    ) internal {
        Keystore.ActorConfig memory cfg =
            Keystore.ActorConfig({authenticator: address(k1Authenticator), scope: scope, expiry: 0});
        bytes memory policyData = abi.encodePacked(policyManager, commitment);

        Keystore.ActorChange[] memory changes = new Keystore.ActorChange[](1);
        changes[0] = Keystore.ActorChange({
            actorId: actorId, changeType: Keystore.ActorChangeType.Authorize, data: abi.encode(cfg, policyData)
        });

        uint64 seq = keystore.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        keystore.applySignedActorChanges(account, uint64(block.chainid), changes, _buildK1Auth(rootPk, digest));
    }

    /// @dev Authorize the EOA's self-actorId as a scoped k1 actor carrying a gated policy. The EOA is not
    ///      createAccount'd, so the implicit default-EOA owner signs the change; the authorization lives in the
    ///      inline-k1 self home (`_accountState`) with (manager, commitment) in the shared actorId-keyed keyspace.
    function _authorizeInlineSelfWithPolicy(
        address eoa,
        uint256 eoaPk,
        uint16 scope,
        address policyManager,
        bytes32 commitment
    ) internal {
        bytes32 selfActorId = bytes32(bytes20(eoa));
        Keystore.ActorConfig memory cfg =
            Keystore.ActorConfig({authenticator: keystore.K1_AUTHENTICATOR(), scope: scope, expiry: 0});
        bytes memory policyData = abi.encodePacked(policyManager, commitment);

        Keystore.ActorChange[] memory changes = new Keystore.ActorChange[](1);
        changes[0] = Keystore.ActorChange({
            actorId: selfActorId, changeType: Keystore.ActorChangeType.Authorize, data: abi.encode(cfg, policyData)
        });

        uint64 seq = keystore.getChangeSequences(eoa).local;
        bytes32 digest = _computeActorChangeBatchDigest(eoa, uint64(block.chainid), seq, changes);
        keystore.applySignedActorChanges(eoa, uint64(block.chainid), changes, _buildK1Auth(eoaPk, digest));
    }

    /// @dev Authorize an ungated (scope 0) actor under `authenticator`, signed by `pk`.
    function _authorizeUngatedActor(address account, uint256 pk, bytes32 newActorId, address authenticator) internal {
        Keystore.ActorChange[] memory changes = new Keystore.ActorChange[](1);
        changes[0] = Keystore.ActorChange({
            actorId: newActorId,
            changeType: Keystore.ActorChangeType.Authorize,
            data: abi.encode(Keystore.ActorConfig({authenticator: authenticator, scope: 0x00, expiry: 0}), bytes(""))
        });
        uint64 seq = keystore.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        keystore.applySignedActorChanges(account, uint64(block.chainid), changes, _buildK1Auth(pk, digest));
    }

    /// @dev Revoke `actorId` from `account`, signed by `pk`.
    function _revokeActor(address account, uint256 pk, bytes32 actorId) internal {
        Keystore.ActorChange[] memory changes = new Keystore.ActorChange[](1);
        changes[0] = Keystore.ActorChange({actorId: actorId, changeType: Keystore.ActorChangeType.Revoke, data: ""});
        uint64 seq = keystore.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        keystore.applySignedActorChanges(account, uint64(block.chainid), changes, _buildK1Auth(pk, digest));
    }
}
