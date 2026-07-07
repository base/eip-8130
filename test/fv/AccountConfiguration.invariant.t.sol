// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";

import {AccountConfigurationHarness} from "./AccountConfigurationHarness.sol";
import {AccountConfigurationHandler} from "./AccountConfigurationHandler.sol";
import {DefaultAccount} from "../../src/accounts/DefaultAccount.sol";

/// @notice Layer 1 of the verification stack: stateful invariant (fuzz) testing.
///
/// These invariants encode the security-critical guarantees that {AccountConfiguration} currently states only in
/// prose comments. The handler drives the contract through long randomized sequences of validly-signed operations;
/// after every step Foundry re-checks each `invariant_*` below. A single counterexample sequence fails the run.
contract AccountConfigurationInvariantTest is Test {
    uint8 constant SCOPE_CONFIG = 0x08;

    AccountConfigurationHarness internal cfg;
    AccountConfigurationHandler internal handler;
    address internal K1;

    function setUp() public {
        cfg = new AccountConfigurationHarness();
        K1 = cfg.K1_AUTHENTICATOR();
        address impl = address(new DefaultAccount(address(cfg)));
        handler = new AccountConfigurationHandler(cfg, impl);

        // Only fuzz the state-mutating handler actions (not its view getters).
        bytes4[] memory selectors = new bytes4[](7);
        selectors[0] = handler.handler_createAccount.selector;
        selectors[1] = handler.handler_authorize.selector;
        selectors[2] = handler.handler_revoke.selector;
        selectors[3] = handler.handler_lock.selector;
        selectors[4] = handler.handler_initiateUnlock.selector;
        selectors[5] = handler.handler_warp.selector;
        selectors[6] = handler.handler_createAccountBadCode.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        targetContract(address(handler));
    }

    /// @notice INV-1: The inline-k1 self and the non-k1 self are never simultaneously live, and whenever the inline
    ///         self is live its `_actorConfig` self home is empty (and never holds a stray K1 selector). This is the
    ///         mutual-exclusion guarantee `_authorizeActor` / `_revokeActor` claim in prose.
    function invariant_selfHomesMutuallyExclusive() public view {
        uint256 n = handler.accountsLength();
        for (uint256 i; i < n; i++) {
            address account = handler.accounts(i);
            bool inlineLive = cfg.h_inlineSelfLive(account);
            bool nonK1Live = cfg.h_nonK1SelfLive(account);
            assertFalse(inlineLive && nonK1Live, "both self homes live");

            address rawSelfAuth = cfg.h_actorConfigAuthenticator(account, cfg.h_selfActorId(account));
            if (inlineLive) {
                assertEq(rawSelfAuth, address(0), "inline self live but _actorConfig self home populated");
            }
            // The k1 self never lives in _actorConfig (it is inline-only), so the raw self home is never a K1 selector.
            assertTrue(rawSelfAuth != K1, "K1 selector leaked into _actorConfig self home");
        }
    }

    /// @notice INV-2: Across both homes, `_policyCommitment` and `_policyManager` are non-zero *iff* the actor's
    ///         effective `policyType` is non-zero. No stale policy state may leak past a revoke or a downgrade to
    ///         POLICY_NONE. This is the invariant `getPolicyCommitment` / `getPolicyManager` rely on.
    function invariant_policySlotsIffPolicyType() public view {
        uint256 n = handler.pairsLength();
        for (uint256 i; i < n; i++) {
            (address account, bytes32 actorId) = handler.pairAt(i);
            (bool live, uint8 policyType,) = _effective(account, actorId);

            bool hasPolicy = live && policyType != 0;
            bool commitmentSet = cfg.h_policyCommitment(account, actorId) != bytes32(0);
            bool managerSet = cfg.h_policyManager(account, actorId) != address(0);

            assertEq(commitmentSet, hasPolicy, "commitment set != has policy");
            assertEq(managerSet, hasPolicy, "manager set != has policy");
        }
    }

    /// @notice INV-3: Any live policy-bearing actor is scope-restricted and never holds CONFIG (change-actors) scope.
    ///         Otherwise a gated key could authorize fresh unrestricted actors and escape its own policy — the exact
    ///         escalation `_authorizeActor` guards against.
    function invariant_policyActorCannotChangeActors() public view {
        uint256 n = handler.pairsLength();
        for (uint256 i; i < n; i++) {
            (address account, bytes32 actorId) = handler.pairAt(i);
            (bool live, uint8 policyType, uint8 scope) = _effective(account, actorId);
            if (live && policyType != 0) {
                assertTrue(scope != 0, "policy actor has scope 0");
                assertEq(scope & SCOPE_CONFIG, 0, "policy actor holds CONFIG scope");
            }
        }
    }

    /// @notice INV-4: Per-account change sequences are monotonically non-decreasing. Any observed regression would
    ///         open a signed-change replay window; the handler flips this flag if it ever sees one.
    function invariant_sequencesMonotonic() public view {
        assertTrue(handler.sequenceMonotonicityHeld(), "sequence regressed");
    }

    /// @notice INV-5: A created account is permanently initialized (localSequence >= 1), which is what blocks
    ///         re-initialization via createAccount/importAccount.
    function invariant_createdAccountsStayInitialized() public view {
        uint256 n = handler.accountsLength();
        for (uint256 i; i < n; i++) {
            address account = handler.accounts(i);
            assertGe(cfg.getChangeSequences(account).local, 1, "created account de-initialized");
        }
    }

    /// @notice INV-6: A successfully created account always has deployed code, and a createAccount whose deployment
    ///         failed leaves no state and no code behind. This is the "no orphaned config" guarantee enforced by the
    ///         CREATE2 return-value check; the pre-fix contract (swallowed CREATE2 result) would violate it.
    function invariant_noOrphanedAccountState() public view {
        uint256 n = handler.accountsLength();
        for (uint256 i; i < n; i++) {
            address account = handler.accounts(i);
            assertGt(account.code.length, 0, "created account has no code");
        }

        uint256 f = handler.failedCreationsLength();
        for (uint256 i; i < f; i++) {
            address ghost = handler.failedCreations(i);
            assertEq(ghost.code.length, 0, "failed creation left code");
            assertEq(cfg.getChangeSequences(ghost).local, 0, "failed creation left local sequence");
            assertEq(cfg.getChangeSequences(ghost).multichain, 0, "failed creation left multichain sequence");
        }
    }

    // ── Helpers ──

    /// @dev Resolve an actor's effective liveness, policyType and scope, mirroring the contract's home routing:
    ///      a populated `_actorConfig` entry wins; otherwise the inline-k1 self applies to the self-actorId when
    ///      live; otherwise the actor is not live.
    function _effective(address account, bytes32 actorId)
        internal
        view
        returns (bool live, uint8 policyType, uint8 scope)
    {
        address rawAuth = cfg.h_actorConfigAuthenticator(account, actorId);
        if (rawAuth != address(0)) {
            return (true, cfg.h_actorConfigPolicyType(account, actorId), cfg.h_actorConfigScope(account, actorId));
        }
        if (actorId == cfg.h_selfActorId(account) && cfg.h_inlineSelfLive(account)) {
            return (true, cfg.h_inlineSelfPolicyType(account), cfg.h_inlineSelfScope(account));
        }
        return (false, 0, 0);
    }
}
