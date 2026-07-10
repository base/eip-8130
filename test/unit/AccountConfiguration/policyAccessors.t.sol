// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

/// @notice Unit tests for the granular policy accessors `getPolicyCommitment` and `getPolicyManager`, plus
///         regression coverage for the `getPolicy` aggregate. The granular accessors are the single-SLOAD reads
///         intended for the per-tx validation hot path of a policy manager invoked by the protocol-dispatched
///         8130 tx; the aggregate is the convenience read for off-chain consumers.
contract PolicyAccessorsTest is AccountConfigurationTest {
    uint256 internal constant ROOT_PK = 200;
    uint256 internal constant SESSION_PK = 201;
    uint256 internal constant EOA_PK = 500;

    uint8 internal constant SCOPE_SENDER = 0x02;
    uint8 internal constant AUTHORIZE_ACTOR = 0x01;
    uint8 internal constant REVOKE_ACTOR = 0x02;

    address internal constant DUMMY_MANAGER = address(0xCAFE);
    bytes32 internal constant DUMMY_COMMITMENT = bytes32(uint256(0xC0FFEE));

    // ── Explicit-actor home (non-self actor with policy) ──

    function test_getPolicyCommitment_explicitActor_returnsCommitment() public {
        (address account,) = _createK1Account(ROOT_PK);
        bytes32 sessionActorId = bytes32(bytes20(vm.addr(SESSION_PK)));
        _authorizePolicyActor(account, ROOT_PK, sessionActorId, DUMMY_MANAGER, DUMMY_COMMITMENT);

        assertEq(accountConfiguration.getPolicyCommitment(account, sessionActorId), DUMMY_COMMITMENT);
    }

    function test_getPolicyManager_explicitActor_returnsManager() public {
        (address account,) = _createK1Account(ROOT_PK);
        bytes32 sessionActorId = bytes32(bytes20(vm.addr(SESSION_PK)));
        _authorizePolicyActor(account, ROOT_PK, sessionActorId, DUMMY_MANAGER, DUMMY_COMMITMENT);

        assertEq(accountConfiguration.getPolicyManager(account, sessionActorId), DUMMY_MANAGER);
    }

    function test_getPolicy_explicitActor_aggregateMatchesGranular() public {
        (address account,) = _createK1Account(ROOT_PK);
        bytes32 sessionActorId = bytes32(bytes20(vm.addr(SESSION_PK)));
        _authorizePolicyActor(account, ROOT_PK, sessionActorId, DUMMY_MANAGER, DUMMY_COMMITMENT);

        (address target, bytes32 commitment) = accountConfiguration.getPolicy(account, sessionActorId);
        assertEq(target, accountConfiguration.getPolicyManager(account, sessionActorId));
        assertEq(commitment, accountConfiguration.getPolicyCommitment(account, sessionActorId));
    }

    // ── Inline-k1 self home (self-actorId K1 with policy) ──
    //
    // The inline-k1 self lives in AccountState (scope/expiry), but the policy *manager* and
    // *commitment* are keyed by actorId in the shared keyspace — so the granular accessors must work
    // identically to the explicit-actor home. This branch is the one `getPolicy` reaches via its `else if`.

    function test_getPolicyCommitment_inlineSelf_returnsCommitment() public {
        address eoa = vm.addr(EOA_PK);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        _authorizeInlineSelfWithPolicy(eoa, EOA_PK, DUMMY_MANAGER, DUMMY_COMMITMENT);

        assertEq(accountConfiguration.getPolicyCommitment(eoa, selfActorId), DUMMY_COMMITMENT);
    }

    function test_getPolicyManager_inlineSelf_returnsManager() public {
        address eoa = vm.addr(EOA_PK);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        _authorizeInlineSelfWithPolicy(eoa, EOA_PK, DUMMY_MANAGER, DUMMY_COMMITMENT);

        assertEq(accountConfiguration.getPolicyManager(eoa, selfActorId), DUMMY_MANAGER);
    }

    function test_getPolicy_inlineSelf_aggregateMatchesGranular() public {
        address eoa = vm.addr(EOA_PK);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        _authorizeInlineSelfWithPolicy(eoa, EOA_PK, DUMMY_MANAGER, DUMMY_COMMITMENT);

        (address target, bytes32 commitment) = accountConfiguration.getPolicy(eoa, selfActorId);
        assertEq(target, accountConfiguration.getPolicyManager(eoa, selfActorId));
        assertEq(commitment, accountConfiguration.getPolicyCommitment(eoa, selfActorId));
    }

    // ── Zero cases (invariant: zero accessor return iff no policy) ──

    function test_getPolicyAccessors_ungatedActor_returnsZero() public {
        // An actor whose scope lacks SCOPE_POLICY never has manager/commitment set (per _authorizeActor's
        // conditional writes), so the accessors must return zero for it.
        (address account,) = _createK1Account(ROOT_PK);
        bytes32 newActorId = bytes32(bytes20(vm.addr(SESSION_PK)));
        _authorizeUngatedActor(account, ROOT_PK, newActorId, address(k1Authenticator));

        assertEq(accountConfiguration.getPolicyCommitment(account, newActorId), bytes32(0));
        assertEq(accountConfiguration.getPolicyManager(account, newActorId), address(0));
    }

    function test_getPolicyAccessors_unknownActor_returnsZero() public {
        (address account,) = _createK1Account(ROOT_PK);
        bytes32 unknownActorId = bytes32(bytes20(vm.addr(999)));

        assertEq(accountConfiguration.getPolicyCommitment(account, unknownActorId), bytes32(0));
        assertEq(accountConfiguration.getPolicyManager(account, unknownActorId), address(0));
    }

    function test_getPolicyAccessors_clearedOnRevoke() public {
        (address account,) = _createK1Account(ROOT_PK);
        bytes32 sessionActorId = bytes32(bytes20(vm.addr(SESSION_PK)));
        _authorizePolicyActor(account, ROOT_PK, sessionActorId, DUMMY_MANAGER, DUMMY_COMMITMENT);

        // Live first.
        assertEq(accountConfiguration.getPolicyCommitment(account, sessionActorId), DUMMY_COMMITMENT);
        assertEq(accountConfiguration.getPolicyManager(account, sessionActorId), DUMMY_MANAGER);

        // Revoke clears both slots in _revokeActor.
        _revokeActor(account, ROOT_PK, sessionActorId);

        assertEq(accountConfiguration.getPolicyCommitment(account, sessionActorId), bytes32(0));
        assertEq(accountConfiguration.getPolicyManager(account, sessionActorId), address(0));
    }

    function test_getPolicyAccessors_clearedOnInlineSelfRevoke() public {
        // Inline self with a policy → revoke → granular accessors return zero. Verifies the cleanup applies to
        // the shared (actorId-keyed) keyspace from the inline-self home too.
        address eoa = vm.addr(EOA_PK);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        // Pre-authorize a separate unrestricted-owner key. Once we downgrade the self-actorId to
        // SCOPE_SENDER + policy below, admin is exactly scope == 0, so it can't sign the revoke.
        bytes32 ownerActorId = bytes32(bytes20(vm.addr(SESSION_PK)));
        _authorizeUngatedActor(eoa, EOA_PK, ownerActorId, address(k1Authenticator));

        _authorizeInlineSelfWithPolicy(eoa, EOA_PK, DUMMY_MANAGER, DUMMY_COMMITMENT);
        assertEq(accountConfiguration.getPolicyCommitment(eoa, selfActorId), DUMMY_COMMITMENT);

        // Revoke self via the unrestricted owner key — the downgraded self can no longer authorize changes.
        _revokeActor(eoa, SESSION_PK, selfActorId);

        assertEq(accountConfiguration.getPolicyCommitment(eoa, selfActorId), bytes32(0));
        assertEq(accountConfiguration.getPolicyManager(eoa, selfActorId), address(0));
    }

    function test_getPolicyAccessors_clearedOnReauthorizeToNone() public {
        // Upsert path: re-authorizing a policy-bearing actor down to a scope without SCOPE_POLICY must clear both
        // policy slots, so no stale (manager, commitment) leaks and the "commitment non-zero iff SCOPE_POLICY set"
        // invariant holds.
        (address account,) = _createK1Account(ROOT_PK);
        bytes32 sessionActorId = bytes32(bytes20(vm.addr(SESSION_PK)));

        _authorizePolicyActor(account, ROOT_PK, sessionActorId, DUMMY_MANAGER, DUMMY_COMMITMENT);
        assertEq(accountConfiguration.getPolicyCommitment(account, sessionActorId), DUMMY_COMMITMENT);
        assertEq(accountConfiguration.getPolicyManager(account, sessionActorId), DUMMY_MANAGER);

        // Overwrite the same actor as ungated (scope without SCOPE_POLICY).
        _authorizeUngatedActor(account, ROOT_PK, sessionActorId, address(k1Authenticator));

        assertEq(accountConfiguration.getPolicyCommitment(account, sessionActorId), bytes32(0));
        assertEq(accountConfiguration.getPolicyManager(account, sessionActorId), address(0));
        AccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(account, sessionActorId);
        assertEq(cfg.scope, 0x00);
    }

    function test_getPolicyAccessors_updatedOnReauthorizeToNewManager() public {
        // Upsert to a *different* (manager, commitment) must replace, not merge.
        (address account,) = _createK1Account(ROOT_PK);
        bytes32 sessionActorId = bytes32(bytes20(vm.addr(SESSION_PK)));

        _authorizePolicyActor(account, ROOT_PK, sessionActorId, DUMMY_MANAGER, DUMMY_COMMITMENT);

        address newManager = address(0xBEEF);
        bytes32 newCommitment = bytes32(uint256(0xD00D));
        _authorizePolicyActor(account, ROOT_PK, sessionActorId, newManager, newCommitment);

        assertEq(accountConfiguration.getPolicyManager(account, sessionActorId), newManager);
        assertEq(accountConfiguration.getPolicyCommitment(account, sessionActorId), newCommitment);
    }

    function test_authorizePolicyActor_allowsAnyScopeCombination() public {
        // This contract does not reject scope combinations: an actor may carry SCOPE_POLICY alongside any other
        // scope bits (or none) — use-time exclusivity between SCOPE_POLICY and other capabilities is protocol-side,
        // not enforced here.
        (address account,) = _createK1Account(ROOT_PK);

        uint8[4] memory otherScopes = [
            uint8(0),
            accountConfiguration.SCOPE_SIGNER(),
            accountConfiguration.SCOPE_PAYER(),
            accountConfiguration.SCOPE_NONCE()
        ];
        for (uint256 i; i < otherScopes.length; i++) {
            bytes32 actorId = bytes32(bytes20(vm.addr(SESSION_PK + i + 1)));
            uint8 scope = otherScopes[i] | accountConfiguration.SCOPE_POLICY();
            AccountConfiguration.ActorConfig memory cfg =
                AccountConfiguration.ActorConfig({authenticator: address(k1Authenticator), scope: scope, expiry: 0});
            AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
            changes[0] = AccountConfiguration.ActorChange({
                actorId: actorId,
                changeType: AUTHORIZE_ACTOR,
                data: abi.encode(cfg, abi.encodePacked(DUMMY_MANAGER, DUMMY_COMMITMENT))
            });
            uint64 seq = accountConfiguration.getChangeSequences(account).local;
            bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
            accountConfiguration.applySignedActorChanges(
                account, uint64(block.chainid), changes, _buildK1Auth(ROOT_PK, digest)
            );

            assertEq(accountConfiguration.getPolicyManager(account, actorId), DUMMY_MANAGER);
            assertEq(accountConfiguration.getPolicyCommitment(account, actorId), DUMMY_COMMITMENT);
        }
    }

    // ── Isolation (correct mapping key derivation) ──

    function test_getPolicyAccessors_isolatedAcrossActors() public {
        (address account,) = _createK1Account(ROOT_PK);
        bytes32 actorA = bytes32(bytes20(vm.addr(SESSION_PK)));
        bytes32 actorB = bytes32(bytes20(vm.addr(SESSION_PK + 1)));

        address managerA = address(0xAAAA);
        address managerB = address(0xBBBB);
        bytes32 commitmentA = bytes32(uint256(0xA));
        bytes32 commitmentB = bytes32(uint256(0xB));

        _authorizePolicyActor(account, ROOT_PK, actorA, managerA, commitmentA);
        _authorizePolicyActor(account, ROOT_PK, actorB, managerB, commitmentB);

        assertEq(accountConfiguration.getPolicyCommitment(account, actorA), commitmentA);
        assertEq(accountConfiguration.getPolicyManager(account, actorA), managerA);
        assertEq(accountConfiguration.getPolicyCommitment(account, actorB), commitmentB);
        assertEq(accountConfiguration.getPolicyManager(account, actorB), managerB);
    }

    function test_getPolicyAccessors_isolatedAcrossAccounts() public {
        // Same actorId across two distinct accounts must yield distinct commitments — verifies the
        // `(account, actorId)` argument convention resolves the correct nested mapping slot (the inner
        // mapping is keyed by account, not the outer actorId mapping alone).
        (address accountA,) = _createK1AccountWithSalt(ROOT_PK, bytes32(uint256(1)));
        (address accountB,) = _createK1AccountWithSalt(ROOT_PK, bytes32(uint256(2)));

        bytes32 sharedActorId = bytes32(bytes20(vm.addr(SESSION_PK)));

        address managerA = address(0xAAAA);
        address managerB = address(0xBBBB);
        bytes32 commitmentA = bytes32(uint256(0xA));
        bytes32 commitmentB = bytes32(uint256(0xB));

        _authorizePolicyActor(accountA, ROOT_PK, sharedActorId, managerA, commitmentA);
        _authorizePolicyActor(accountB, ROOT_PK, sharedActorId, managerB, commitmentB);

        assertEq(accountConfiguration.getPolicyCommitment(accountA, sharedActorId), commitmentA);
        assertEq(accountConfiguration.getPolicyManager(accountA, sharedActorId), managerA);
        assertEq(accountConfiguration.getPolicyCommitment(accountB, sharedActorId), commitmentB);
        assertEq(accountConfiguration.getPolicyManager(accountB, sharedActorId), managerB);
    }

    // ── Helpers ──

    /// @dev Authorize a non-self actor with a SCOPE_POLICY-gated policy bound to (manager, commitment).
    ///      Signed by the root key, which is the unrestricted-owner k1 actor installed by `_createK1Account`.
    function _authorizePolicyActor(
        address account,
        uint256 rootPk,
        bytes32 actorId,
        address policyManager,
        bytes32 commitment
    ) internal {
        AccountConfiguration.ActorConfig memory cfg = AccountConfiguration.ActorConfig({
            authenticator: address(k1Authenticator), scope: accountConfiguration.SCOPE_POLICY(), expiry: 0
        });
        bytes memory policyData = abi.encodePacked(policyManager, commitment);

        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: actorId, changeType: AUTHORIZE_ACTOR, data: abi.encode(cfg, policyData)
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        accountConfiguration.applySignedActorChanges(
            account, uint64(block.chainid), changes, _buildK1Auth(rootPk, digest)
        );
    }

    /// @dev Authorize the EOA's self-actorId as a scoped k1 actor carrying a policy. The EOA is not
    ///      createAccount'd, so the implicit default-EOA owner (all-zero inline) signs the change; the resulting
    ///      authorization lives in the inline-k1 self home (`_accountState`), with (manager, commitment) in the
    ///      shared actorId-keyed keyspace.
    function _authorizeInlineSelfWithPolicy(address eoa, uint256 eoaPk, address policyManager, bytes32 commitment)
        internal
    {
        bytes32 selfActorId = bytes32(bytes20(eoa));
        AccountConfiguration.ActorConfig memory cfg = AccountConfiguration.ActorConfig({
            authenticator: accountConfiguration.K1_AUTHENTICATOR(),
            scope: accountConfiguration.SCOPE_POLICY(),
            expiry: 0
        });
        bytes memory policyData = abi.encodePacked(policyManager, commitment);

        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: selfActorId, changeType: AUTHORIZE_ACTOR, data: abi.encode(cfg, policyData)
        });

        uint64 seq = accountConfiguration.getChangeSequences(eoa).local;
        bytes32 digest = _computeActorChangeBatchDigest(eoa, uint64(block.chainid), seq, changes);
        accountConfiguration.applySignedActorChanges(eoa, uint64(block.chainid), changes, _buildK1Auth(eoaPk, digest));
    }

    function _authorizeUngatedActor(address account, uint256 pk, bytes32 newActorId, address authenticator) internal {
        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: AUTHORIZE_ACTOR,
            data: abi.encode(
                AccountConfiguration.ActorConfig({authenticator: authenticator, scope: 0x00, expiry: 0}), bytes("")
            )
        });
        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, _buildK1Auth(pk, digest));
    }

    function _revokeActor(address account, uint256 pk, bytes32 actorId) internal {
        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({actorId: actorId, changeType: REVOKE_ACTOR, data: ""});
        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, _buildK1Auth(pk, digest));
    }
}
