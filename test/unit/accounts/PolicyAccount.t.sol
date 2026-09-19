// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore} from "../../../src/Keystore.sol";
import {Call} from "../../../src/interfaces/IExecuteBatch.sol";
import {ITransactionContext, TX_CONTEXT_ADDRESS} from "../../../src/interfaces/ITransactionContext.sol";
import {Scopes} from "../../../src/libraries/Scopes.sol";

import {PolicyAccount} from "../../../src/accounts/PolicyAccount.sol";
import {Policy} from "../../../src/policies/Policy.sol";
import {PolicyBinding} from "../../../src/policies/PolicyBinding.sol";
import {SessionPolicy} from "../../../src/policies/SessionPolicy.sol";

import {KeystoreTest} from "../../lib/KeystoreTest.sol";

/// @notice Exploration coverage for Option D (account is its own policy manager). See {PolicyAccount}. Only the
///         account-acting (session-key) path is modeled.
contract PolicyAccountTest is KeystoreTest {
    PolicyAccount internal account;
    SessionPolicy internal policy;

    address internal target = address(0x7A46E7);
    uint256 internal constant ROOT_PK = 0xA11CE;
    uint16 internal constant SCOPE_POLICY = Scopes.POLICY;

    function setUp() public override {
        super.setUp();
        vm.warp(1_700_000_000);
        policy = new SessionPolicy(address(keystore));
        account = PolicyAccount(payable(_createAccount()));
    }

    /// @notice Happy path: a dispatched policy key runs its policy and the account executes the plan natively.
    /// @dev Asserts the action's target is called; the policy self-authenticates the account as its own manager.
    function test_executeForPolicy_success_runsPolicyPlanNatively() public {
        (bytes32 actorId, PolicyBinding memory binding) = _install(1);
        _mockActingActor(actorId);
        vm.expectCall(target, "");
        vm.prank(address(account));
        account.executeForPolicy(binding, _action());
    }

    /// @notice Demonstrates why Option D is load-bearing on protocol selector-gating: a self-call to executeBatch is
    ///         unconditionally authorized, so if the gate routed a policy key here (address-only gating) it would be
    ///         root. A policy key dispatched as the account looks exactly like this `vm.prank(address(account))`.
    function test_executeBatch_selfCallBypass_isRoot() public {
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: target, value: 0, data: ""});
        vm.expectCall(target, "");
        vm.prank(address(account));
        account.executeBatch(calls);
    }

    /// @notice executeForPolicy reverts when the acting actor has no live policy binding on this account.
    /// @dev The reused shared {Policy} self-auth fails first with NoActivePolicy.
    function test_executeForPolicy_revert_noActingPolicy() public {
        bytes32 actorId = _sessionActorId(99);
        _mockActingActor(actorId);
        vm.expectRevert(abi.encodeWithSelector(Policy.NoActivePolicy.selector, actorId));
        vm.prank(address(account));
        account.executeForPolicy(_binding(99), _action());
    }

    // ── Helpers ──

    function _action() internal view returns (bytes memory) {
        return abi.encode(SessionPolicy.Action({target: target, value: 0, data: ""}));
    }

    function _config() internal view returns (bytes memory) {
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = SessionPolicy.CallScope({target: target, selectors: new bytes4[](0)});
        return abi.encode(SessionPolicy.Config({tokenLimits: new SessionPolicy.TokenLimit[](0), callScopes: scopes}));
    }

    function _binding(uint256 salt) internal view returns (PolicyBinding memory) {
        return PolicyBinding({
            account: address(account),
            policy: address(policy),
            policyConfig: _config(),
            validAfter: 0,
            validUntil: 0,
            salt: salt
        });
    }

    function _sessionActorId(uint256 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode("session-key", salt));
    }

    function _commitmentOf(PolicyBinding memory b) internal pure returns (bytes32) {
        return keccak256(abi.encode(b.account, b.policy, keccak256(b.policyConfig), b.validAfter, b.validUntil, b.salt));
    }

    /// @dev Authorizes a policy session actor whose `policy_manager` is the account itself (Option D).
    function _install(uint256 salt) internal returns (bytes32 actorId, PolicyBinding memory binding) {
        binding = _binding(salt);
        actorId = _sessionActorId(salt);
        _applyLocal(
            ROOT_PK,
            address(account),
            _one(
                _authorizeChange(
                    actorId,
                    address(k1Authenticator),
                    SCOPE_POLICY,
                    UNBOUNDED,
                    abi.encodePacked(address(account), _commitmentOf(binding))
                )
            )
        );
    }

    function _mockActingActor(bytes32 actorId) internal {
        vm.mockCall(
            TX_CONTEXT_ADDRESS,
            abi.encodeWithSelector(ITransactionContext.getTransactionSenderActorId.selector),
            abi.encode(actorId)
        );
    }

    function _createAccount() internal returns (address) {
        Keystore.InitialActor memory root = Keystore.InitialActor({
            actorId: bytes32(uint256(uint160(vm.addr(ROOT_PK)))),
            authenticator: address(k1Authenticator),
            scope: 0,
            policyData: ""
        });
        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](1);
        actors[0] = root;
        address impl = address(new PolicyAccount(address(keystore)));
        return keystore.createAccount(bytes32(0), _computeERC1167Bytecode(impl), actors);
    }
}
