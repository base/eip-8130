// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";

import {AccountConfiguration} from "../../src/AccountConfiguration.sol";
import {AccountConfigurationHarness} from "./AccountConfigurationHarness.sol";

/// @notice Layer 2 of the verification stack: symbolic verification with Halmos.
///
/// Each `check_*` function is explored by Halmos over the *entire* symbolic input domain (all scopes, expiries,
/// policy bytes, actor ids, ...) rather than sampled fuzz values, so a passing check is a bounded formal proof that
/// no input violates the asserted property. We drive the internal state-machine units directly via the harness's
/// `sym_*` wrappers, which lets Halmos reason about the storage transitions without having to model `ecrecover`
/// (the signature gate on the public change path).
///
/// Run with:  halmos --match-contract AccountConfigurationSymbolicTest
contract AccountConfigurationSymbolicTest is Test {
    AccountConfigurationHarness internal cfg;
    address internal K1;
    address internal constant NON_K1 = address(0xA11CE);
    uint8 internal constant SCOPE_CONFIG = 0x08;

    function setUp() public {
        cfg = new AccountConfigurationHarness();
        K1 = cfg.K1_AUTHENTICATOR();
    }

    // ── _slicePolicy: exact, total parsing ──

    /// @notice POLICY_NONE with empty data yields the zero policy; any non-empty data reverts.
    function check_slicePolicy_none(bytes calldata data) external view {
        if (data.length == 0) {
            (address m, bytes32 c) = cfg.sym_slicePolicy(0, data);
            assert(m == address(0));
            assert(c == bytes32(0));
        } else {
            try cfg.sym_slicePolicy(0, data) returns (address, bytes32) {
                assert(false); // non-empty data under POLICY_NONE must revert
            } catch {}
        }
    }

    /// @notice A gated policy blob of exactly `manager(20) || commitment(32)` parses back byte-for-byte, for every
    ///         non-zero manager and commitment.
    function check_slicePolicy_parsesExactly(bytes32 mgrSeed, bytes32 commitment) external view {
        address manager = address(uint160(uint256(mgrSeed)));
        vm.assume(manager != address(0));
        vm.assume(commitment != bytes32(0));

        bytes memory data = abi.encodePacked(manager, commitment);
        (address gotM, bytes32 gotC) = cfg.sym_slicePolicy(1, data);
        assert(gotM == manager);
        assert(gotC == commitment);
    }

    // ── _authorizeActor: storage round-trip + policy invariant (non-self actor) ──

    /// @notice For every scope/expiry, authorizing an ungated non-self k1 actor stores exactly those fields and
    ///         leaves the policy slots empty (the "commitment iff policyType" invariant, ungated direction).
    function check_authorize_ungated_roundTrip(address account, bytes20 rawActor, uint8 scope, uint48 expiry) external {
        vm.assume(account != address(0));
        vm.assume(bytes32(rawActor) != bytes32(bytes20(account))); // non-self

        bytes32 actorId = bytes32(rawActor);
        AccountConfiguration.ActorConfig memory config =
            AccountConfiguration.ActorConfig({authenticator: K1, scope: scope, expiry: expiry, policyType: 0});

        cfg.sym_authorizeActor(account, actorId, config, "");

        AccountConfiguration.ActorConfig memory got = cfg.getActorConfig(account, actorId);
        assert(got.authenticator == K1);
        assert(got.scope == scope);
        assert(got.expiry == expiry);
        assert(got.policyType == 0);
        assert(cfg.getPolicyCommitment(account, actorId) == bytes32(0));
        assert(cfg.getPolicyManager(account, actorId) == address(0));
    }

    /// @notice A gated actor can only be authorized when it is scope-restricted and lacks change-actors scope;
    ///         when it is authorized, both policy slots become non-zero and the policyType is stored.
    function check_authorize_gated_setsPolicyAndGuardsScope(
        address account,
        bytes20 rawActor,
        uint8 scope,
        bytes32 commitment
    ) external {
        vm.assume(account != address(0));
        vm.assume(bytes32(rawActor) != bytes32(bytes20(account)));
        vm.assume(commitment != bytes32(0));

        bytes32 actorId = bytes32(rawActor);
        address manager = address(0xBEEF);
        AccountConfiguration.ActorConfig memory config =
            AccountConfiguration.ActorConfig({authenticator: K1, scope: scope, expiry: 0, policyType: 1});
        bytes memory policyData = abi.encodePacked(manager, commitment);

        bool legalScope = scope != 0 && scope & SCOPE_CONFIG == 0;

        try cfg.sym_authorizeActor(account, actorId, config, policyData) {
            // Success implies the scope was legal, and the policy slots are now populated.
            assert(legalScope);
            assert(cfg.getPolicyCommitment(account, actorId) == commitment);
            assert(cfg.getPolicyManager(account, actorId) == manager);
            AccountConfiguration.ActorConfig memory got = cfg.getActorConfig(account, actorId);
            assert(got.policyType == 1);
        } catch {
            // A revert implies the scope was illegal for a gated actor.
            assert(!legalScope);
        }
    }

    // ── _revokeActor: total cleanup ──

    /// @notice Revoking a previously-gated non-self actor clears its config and both policy slots.
    function check_revoke_clearsEverything(address account, bytes20 rawActor, bytes32 commitment) external {
        vm.assume(account != address(0));
        vm.assume(bytes32(rawActor) != bytes32(bytes20(account)));
        vm.assume(commitment != bytes32(0));

        bytes32 actorId = bytes32(rawActor);
        AccountConfiguration.ActorConfig memory config = AccountConfiguration.ActorConfig({
            authenticator: K1,
            scope: 0x02, // SCOPE_SENDER: legal for a gated actor
            expiry: 0,
            policyType: 1
        });
        cfg.sym_authorizeActor(account, actorId, config, abi.encodePacked(address(0xBEEF), commitment));

        cfg.sym_revokeActor(account, actorId);

        assert(!cfg.isActor(account, actorId));
        assert(cfg.getPolicyCommitment(account, actorId) == bytes32(0));
        assert(cfg.getPolicyManager(account, actorId) == address(0));
    }

    // ── Self-home mutual exclusion (the core, hardest invariant) ──

    /// @notice Authorizing the self-actorId as a k1 actor and then as a non-k1 actor (and vice-versa) never leaves
    ///         both self homes live — proved symbolically over the account address and both self scopes.
    function check_selfHomes_neverBothLive(address account, uint8 scopeA, uint8 scopeB) external {
        vm.assume(account != address(0));
        bytes32 self = bytes32(bytes20(account));

        // Authorize the k1 self (inline home).
        cfg.sym_authorizeActor(
            account,
            self,
            AccountConfiguration.ActorConfig({authenticator: K1, scope: scopeA, expiry: 0, policyType: 0}),
            ""
        );
        assert(!(cfg.h_inlineSelfLive(account) && cfg.h_nonK1SelfLive(account)));

        // Now authorize a non-k1 self: inline must switch off, non-k1 home on.
        cfg.sym_authorizeActor(
            account,
            self,
            AccountConfiguration.ActorConfig({authenticator: NON_K1, scope: scopeB, expiry: 0, policyType: 0}),
            ""
        );
        assert(!(cfg.h_inlineSelfLive(account) && cfg.h_nonK1SelfLive(account)));
        assert(!cfg.h_inlineSelfLive(account));
        assert(cfg.h_nonK1SelfLive(account));

        // Switch back to the k1 self: non-k1 home cleared, inline live again.
        cfg.sym_authorizeActor(
            account,
            self,
            AccountConfiguration.ActorConfig({authenticator: K1, scope: scopeA, expiry: 0, policyType: 0}),
            ""
        );
        assert(!(cfg.h_inlineSelfLive(account) && cfg.h_nonK1SelfLive(account)));
        assert(cfg.h_inlineSelfLive(account));
        assert(!cfg.h_nonK1SelfLive(account));
        assert(cfg.h_actorConfigAuthenticator(account, self) == address(0));
    }
}
