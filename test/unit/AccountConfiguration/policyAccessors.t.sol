// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {IAccountConfiguration} from "../../../src/interfaces/IAccountConfiguration.sol";
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
    uint8 internal constant POLICY_GATED = 0x01;
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

        (uint8 policyType, address target, bytes32 commitment) = accountConfiguration.getPolicy(account, sessionActorId);
        assertEq(policyType, POLICY_GATED);
        assertEq(target, accountConfiguration.getPolicyManager(account, sessionActorId));
        assertEq(commitment, accountConfiguration.getPolicyCommitment(account, sessionActorId));
    }

    // ── Inline-k1 self home (self-actorId K1 with policy) ──
    //
    // The inline-k1 self lives in AccountState (scope/policyType/expiry), but the policy *manager* and
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

        (uint8 policyType, address target, bytes32 commitment) = accountConfiguration.getPolicy(eoa, selfActorId);
        assertEq(policyType, POLICY_GATED);
        assertEq(target, accountConfiguration.getPolicyManager(eoa, selfActorId));
        assertEq(commitment, accountConfiguration.getPolicyCommitment(eoa, selfActorId));
    }

    // ── Zero cases (invariant: zero accessor return iff no policy) ──

    function test_getPolicyAccessors_ungatedActor_returnsZero() public {
        // An actor with policyType == POLICY_NONE never has manager/commitment set (per _authorizeActor's
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
        // SCOPE_SENDER + policy below, it no longer carries SCOPE_CHANGE_ACTORS and can't sign the revoke.
        bytes32 ownerActorId = bytes32(bytes20(vm.addr(SESSION_PK)));
        _authorizeUngatedActor(eoa, EOA_PK, ownerActorId, address(k1Authenticator));

        _authorizeInlineSelfWithPolicy(eoa, EOA_PK, DUMMY_MANAGER, DUMMY_COMMITMENT);
        assertEq(accountConfiguration.getPolicyCommitment(eoa, selfActorId), DUMMY_COMMITMENT);

        // Revoke self via the unrestricted owner key — the downgraded self can no longer authorize changes.
        _revokeActor(eoa, SESSION_PK, selfActorId);

        assertEq(accountConfiguration.getPolicyCommitment(eoa, selfActorId), bytes32(0));
        assertEq(accountConfiguration.getPolicyManager(eoa, selfActorId), address(0));
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

    /// @dev Authorize a non-self actor with a gated (policyType=POLICY_GATED) policy bound to (manager, commitment).
    ///      Signed by the root key, which is the unrestricted-owner k1 actor installed by `_createK1Account`.
    function _authorizePolicyActor(
        address account,
        uint256 rootPk,
        bytes32 actorId,
        address policyManager,
        bytes32 commitment
    ) internal {
        IAccountConfiguration.ActorConfig memory cfg = IAccountConfiguration.ActorConfig({
            authenticator: address(k1Authenticator), scope: SCOPE_SENDER, expiry: 0, policyType: POLICY_GATED
        });
        bytes memory policyData = abi.encodePacked(policyManager, commitment);

        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
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
        IAccountConfiguration.ActorConfig memory cfg = IAccountConfiguration.ActorConfig({
            authenticator: accountConfiguration.K1_AUTHENTICATOR(),
            scope: SCOPE_SENDER,
            expiry: 0,
            policyType: POLICY_GATED
        });
        bytes memory policyData = abi.encodePacked(policyManager, commitment);

        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: selfActorId, changeType: AUTHORIZE_ACTOR, data: abi.encode(cfg, policyData)
        });

        uint64 seq = accountConfiguration.getChangeSequences(eoa).local;
        bytes32 digest = _computeActorChangeBatchDigest(eoa, uint64(block.chainid), seq, changes);
        accountConfiguration.applySignedActorChanges(eoa, uint64(block.chainid), changes, _buildK1Auth(eoaPk, digest));
    }

    function _authorizeUngatedActor(address account, uint256 pk, bytes32 newActorId, address authenticator) internal {
        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: AUTHORIZE_ACTOR,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({
                    authenticator: authenticator, scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });
        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, _buildK1Auth(pk, digest));
    }

    function _revokeActor(address account, uint256 pk, bytes32 actorId) internal {
        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({actorId: actorId, changeType: REVOKE_ACTOR, data: ""});
        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, _buildK1Auth(pk, digest));
    }
}
