// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {ReentrancyGuard} from "openzeppelin/utils/ReentrancyGuard.sol";
import {Keystore} from "../../../src/Keystore.sol";
import {DefaultAccount} from "../../../src/accounts/DefaultAccount.sol";
import {NativePolicyAccount} from "../../../src/accounts/NativePolicyAccount.sol";
import {Call} from "../../../src/interfaces/IExecuteBatch.sol";
import {ITransactionContext, TX_CONTEXT_ADDRESS} from "../../../src/interfaces/ITransactionContext.sol";
import {Scopes} from "../../../src/libraries/Scopes.sol";
import {Policy} from "../../../src/policies/Policy.sol";
import {PolicyBinding, PolicyBindingLib} from "../../../src/policies/PolicyBinding.sol";
import {EXTERNAL_POLICY_AUTHENTICATOR} from "../../../src/policies/PolicyManager.sol";
import {SessionPolicy} from "../../../src/policies/SessionPolicy.sol";
import {RecurringAllowance} from "../../../src/policies/RecurringAllowance.sol";
import {KeystoreTest} from "../../lib/KeystoreTest.sol";

contract NativePolicyTarget {
    address public lastCaller;
    uint256 public value;

    function set(uint256 v) external payable {
        lastCaller = msg.sender;
        value = v;
    }

    function fail() external pure {
        revert("target failure");
    }
}

/// @dev Extensions guard public functions once; conditional internal calls use the shared execution safeguards.
contract ConditionalPolicyAccount is NativePolicyAccount {
    uint256 public fallbackCount;

    constructor(address keystore) NativePolicyAccount(keystore) {}

    function conditional(Call calldata primary, Call calldata recovery) external onlyOperationalActor nonReentrant {
        (bool success,) = _tryExecuteCall(primary);
        if (!success) {
            ++fallbackCount;
            _executeCall(recovery);
        }
    }

    function operationalProbe() external view onlyOperationalActor {}

    function adminProbe() external view onlyAdminActor {}

    function selfProbe() external view {
        require(msg.sender == address(this));
    }
}

/// @dev Test-only policy: return the supplied plan, but still use the shared Policy binding authentication.
///      Deliberately NOT a safe policy to install in production: the holder can choose any calls.
contract NativePlanPolicy is Policy {
    uint256 public executions;
    uint256 public posts;
    address public lastCaller;
    bool public failPost;

    constructor(address keystore) Policy(keystore) {}

    function setFailPost(bool fail_) external {
        failPost = fail_;
    }

    function _onExecute(bytes32, address, bytes calldata, bytes calldata data, address caller)
        internal
        override
        returns (Call[] memory, bytes memory)
    {
        ++executions;
        lastCaller = caller;
        return (abi.decode(data, (Call[])), hex"abcd");
    }

    function _onPostExecute(bytes32, address, bytes calldata data) internal override {
        require(keccak256(data) == keccak256(hex"abcd"));
        require(!failPost, "post failure");
        ++posts;
    }
}

contract NativeReentrantPolicy is Policy {
    constructor(address keystore) Policy(keystore) {}

    function _onExecute(bytes32, address account, bytes calldata, bytes calldata, address)
        internal
        override
        returns (Call[] memory, bytes memory)
    {
        PolicyBinding memory binding;
        binding.account = account;
        NativePolicyAccount(payable(account)).executeFor(binding, "");
        return (new Call[](0), "");
    }
}

contract NativeReentrantTarget {
    function reenter(address account, PolicyBinding calldata binding) external {
        NativePolicyAccount(payable(account)).executeFor(binding, "");
    }
}

contract NativePolicyAccountTest is KeystoreTest {
    using PolicyBindingLib for PolicyBinding;

    uint256 internal constant ROOT_PK = 0xA11CE;
    uint256 internal constant KEY_PK = 0xB0B;
    address internal constant RUNNER = address(0xCAFE);
    address internal constant RECIPIENT = address(0xBEEF);

    ConditionalPolicyAccount internal account;
    NativePolicyTarget internal target;
    NativePlanPolicy internal policy;
    PolicyBinding internal binding;
    bytes32 internal rootId;
    bytes32 internal keyId;
    bytes32 internal runnerId;

    function setUp() public override {
        super.setUp();
        vm.warp(1_700_000_000);
        defaultAccountImplementation = address(new ConditionalPolicyAccount(address(keystore)));
        (address a, bytes32 root) = _createK1Account(ROOT_PK);
        account = ConditionalPolicyAccount(payable(a));
        rootId = root;
        keyId = bytes32(uint256(uint160(vm.addr(KEY_PK))));
        runnerId = bytes32(uint256(uint160(RUNNER)));
        target = new NativePolicyTarget();
        policy = new NativePlanPolicy(address(keystore));
        binding = PolicyBinding(a, address(policy), "", 0, 0, 1);
        _install(keyId, k1Authenticator, Scopes.POLICY, UNBOUNDED, a, binding);
        _install(runnerId, EXTERNAL_POLICY_AUTHENTICATOR, Scopes.POLICY, UNBOUNDED, a, binding);
        vm.deal(a, 10 ether);
        _context(a, keyId);
    }

    function test_session_executesAsAccount_withoutManagerActor() public {
        assertFalse(_isActor(address(account), bytes32(uint256(uint160(address(policy))))));
        _session(_plan(address(target), 1 ether, abi.encodeCall(target.set, (42))));
        assertEq(target.lastCaller(), address(account));
        assertEq(target.value(), 42);
        assertEq(address(target).balance, 1 ether);
        assertEq(policy.lastCaller(), address(account));
        assertEq(policy.posts(), 1);
    }

    function test_external_ignoresTransactionActorAndOrigin() public {
        _context(address(0xDEAD), rootId);
        vm.prank(RUNNER, address(0xBAD));
        account.executeFor(binding, _plan(address(target), 0, abi.encodeCall(target.set, (7))));
        assertEq(target.lastCaller(), address(account));
        assertEq(policy.lastCaller(), RUNNER);
    }

    function test_external_worksWithout8130Context() public {
        vm.clearMockedCalls();
        vm.prank(RUNNER);
        account.executeFor(binding, _plan(address(target), 0, abi.encodeCall(target.set, (7))));
        assertEq(target.value(), 7);
    }

    function test_session_rejectsDirectExecuteAndBatch() public {
        vm.expectRevert(DefaultAccount.UnauthorizedCaller.selector);
        vm.prank(address(account));
        account.execute(address(target), 0, abi.encodeCall(target.set, (1)));
        Call[] memory calls = _calls(address(target), 0, abi.encodeCall(target.set, (1)));
        vm.expectRevert(DefaultAccount.UnauthorizedCaller.selector);
        vm.prank(address(account));
        account.executeBatch(calls);
    }

    function test_session_rejectsOperationalAndAdminFunctions() public {
        Call memory action = Call(address(target), 0, abi.encodeCall(target.set, (1)));
        vm.expectRevert(DefaultAccount.UnauthorizedCaller.selector);
        vm.prank(address(account));
        account.conditional(action, action);
        vm.expectRevert(DefaultAccount.UnauthorizedCaller.selector);
        vm.prank(address(account));
        account.adminProbe();
    }

    function test_policyPlan_cannotLaunderSelfCallIntoOperationalAuthority() public {
        _expectSessionRevert(
            DefaultAccount.UnauthorizedCaller.selector,
            _plan(address(account), 0, abi.encodeCall(account.operationalProbe, ()))
        );
        assertEq(policy.executions(), 0);
    }

    function test_externalPlan_cannotLaunderSelfCallIntoOperationalAuthority() public {
        _context(RUNNER, rootId);
        vm.expectRevert(DefaultAccount.UnauthorizedCaller.selector);
        vm.prank(RUNNER);
        account.executeFor(binding, _plan(address(account), 0, abi.encodeCall(account.operationalProbe, ())));
    }

    function test_operator_runsConditionalRecovery_butNotAdminFunctions() public {
        _authorizeActorWithScope(address(account), ROOT_PK, keyId, k1Authenticator, Scopes.OPERATOR);
        vm.prank(address(account));
        account.conditional(
            Call(address(target), 0, abi.encodeCall(target.fail, ())),
            Call(address(target), 1 ether, abi.encodeCall(target.set, (9)))
        );
        assertEq(account.fallbackCount(), 1);
        assertEq(target.lastCaller(), address(account));
        assertEq(target.value(), 9);
        vm.expectRevert(DefaultAccount.UnauthorizedCaller.selector);
        vm.prank(address(account));
        account.adminProbe();
    }

    function test_admin_runsConditionalSuccessAndAdminFunctions() public {
        _context(address(account), rootId);
        vm.prank(address(account));
        account.conditional(
            Call(address(target), 0, abi.encodeCall(target.set, (3))),
            Call(address(target), 0, abi.encodeCall(target.set, (4)))
        );
        assertEq(target.value(), 3);
        assertEq(account.fallbackCount(), 0);
        vm.prank(address(account));
        account.adminProbe();
    }

    function test_directOperationalCaller_keepsK1Boundary() public {
        _context(address(0xDEAD), keyId);
        vm.prank(vm.addr(ROOT_PK));
        account.execute(address(target), 0, abi.encodeCall(target.set, (5)));
        assertEq(target.value(), 5);
        _authorizeActor(address(account), ROOT_PK, keyId, address(delegateAuthenticator));
        vm.expectRevert(DefaultAccount.UnauthorizedCaller.selector);
        vm.prank(vm.addr(KEY_PK));
        account.operationalProbe();
    }

    function test_session_requiresSelfCaller_notJustMatchingContext() public {
        vm.expectRevert(DefaultAccount.UnauthorizedCaller.selector);
        account.execute(binding, abi.encode(new Call[](0)));
    }

    function test_session_failsClosedWithoutContext() public {
        vm.clearMockedCalls();
        _expectSessionRevert(DefaultAccount.UnauthorizedCaller.selector, abi.encode(new Call[](0)));
    }

    function test_session_failsClosedForMalformedActorContext() public {
        vm.mockCall(TX_CONTEXT_ADDRESS, abi.encodeCall(ITransactionContext.getTransactionSenderActorId, ()), hex"01");
        _expectSessionRevert(DefaultAccount.UnauthorizedCaller.selector, abi.encode(new Call[](0)));
    }

    function test_session_failsClosedForWrongAccountContext() public {
        _context(address(0xDEAD), keyId);
        _expectSessionRevert(DefaultAccount.UnauthorizedCaller.selector, abi.encode(new Call[](0)));
    }

    function test_session_failsClosedForZeroActorContext() public {
        _context(address(account), bytes32(0));
        _expectSessionRevert(DefaultAccount.UnauthorizedCaller.selector, abi.encode(new Call[](0)));
    }

    function test_session_rejectsExpiredAndRevokedActor() public {
        _install(keyId, k1Authenticator, Scopes.POLICY, uint48(block.timestamp + 1), address(account), binding);
        vm.warp(block.timestamp + 2);
        _expectSessionRevert(
            abi.encodeWithSelector(NativePolicyAccount.InvalidPolicyActor.selector, keyId), abi.encode(new Call[](0))
        );
        _revokeActor(address(account), ROOT_PK, keyId);
        _expectSessionRevert(
            abi.encodeWithSelector(NativePolicyAccount.InvalidPolicyActor.selector, keyId), abi.encode(new Call[](0))
        );
    }

    function test_revokedOperationalActor_zeroScopeDoesNotMeanAdmin() public {
        _revokeActor(address(account), ROOT_PK, keyId);
        vm.expectRevert(DefaultAccount.UnauthorizedCaller.selector);
        vm.prank(address(account));
        account.operationalProbe();
        vm.expectRevert(DefaultAccount.UnauthorizedCaller.selector);
        vm.prank(address(account));
        account.adminProbe();
    }

    function test_external_rejectsUnregisteredRunner() public {
        vm.expectRevert(
            abi.encodeWithSelector(NativePolicyAccount.InvalidPolicyActor.selector, bytes32(uint256(0xBAD)))
        );
        vm.prank(address(0xBAD));
        account.executeFor(binding, abi.encode(new Call[](0)));
    }

    function test_external_rejectsSigningActor() public {
        vm.expectRevert(abi.encodeWithSelector(NativePolicyAccount.InvalidPolicyActor.selector, keyId));
        vm.prank(vm.addr(KEY_PK));
        account.executeFor(binding, abi.encode(new Call[](0)));
    }

    function test_external_rejectsExpiredAndRevokedRunner() public {
        _install(
            runnerId,
            EXTERNAL_POLICY_AUTHENTICATOR,
            Scopes.POLICY,
            uint48(block.timestamp + 1),
            address(account),
            binding
        );
        vm.warp(block.timestamp + 2);
        vm.expectRevert(abi.encodeWithSelector(NativePolicyAccount.InvalidPolicyActor.selector, runnerId));
        vm.prank(RUNNER);
        account.executeFor(binding, abi.encode(new Call[](0)));
        _revokeActor(address(account), ROOT_PK, runnerId);
        vm.expectRevert(abi.encodeWithSelector(NativePolicyAccount.InvalidPolicyActor.selector, runnerId));
        vm.prank(RUNNER);
        account.executeFor(binding, abi.encode(new Call[](0)));
    }

    function test_session_rejectsExternalActorEvenWithForgedProtocolContext() public {
        _install(runnerId, EXTERNAL_POLICY_AUTHENTICATOR, Scopes.POLICY, UNBOUNDED, address(account), binding);
        _context(address(account), runnerId);
        _expectSessionRevert(
            abi.encodeWithSelector(NativePolicyAccount.InvalidPolicyActor.selector, runnerId), abi.encode(new Call[](0))
        );
    }

    function test_policy_rejectsWrongManager() public {
        _install(keyId, k1Authenticator, Scopes.POLICY, UNBOUNDED, address(0xBAD), binding);
        _expectSessionRevert(
            abi.encodeWithSelector(NativePolicyAccount.NoActivePolicy.selector, keyId), abi.encode(new Call[](0))
        );
    }

    function test_policy_rejectsWrongAccount() public {
        binding.account = address(0xBAD);
        _expectSessionRevert(NativePolicyAccount.InvalidBindingAccount.selector, abi.encode(new Call[](0)));
    }

    function test_policy_rejectsSubstitutedPolicyBeforeCallingIt() public {
        NativePlanPolicy malicious = new NativePlanPolicy(address(keystore));
        binding.policy = address(malicious);
        _expectSessionRevert(NativePolicyAccount.BindingCommitmentMismatch.selector, abi.encode(new Call[](0)));
        assertEq(malicious.executions(), 0);
    }

    function testFuzz_policy_rejectsChangedConfig(bytes calldata config) public {
        vm.assume(config.length > 0);
        binding.policyConfig = config;
        _expectSessionRevert(NativePolicyAccount.BindingCommitmentMismatch.selector, abi.encode(new Call[](0)));
    }

    function test_policy_enforcesBindingWindow() public {
        binding.validAfter = uint40(block.timestamp + 10);
        binding.validUntil = uint40(block.timestamp + 20);
        _install(keyId, k1Authenticator, Scopes.POLICY, UNBOUNDED, address(account), binding);
        _expectSessionRevert(NativePolicyAccount.OutsideValidityWindow.selector, abi.encode(new Call[](0)));
        vm.warp(binding.validAfter);
        _session(abi.encode(new Call[](0)));
        vm.warp(binding.validUntil);
        _expectSessionRevert(NativePolicyAccount.OutsideValidityWindow.selector, abi.encode(new Call[](0)));
    }

    function test_emptyPlan_skipsPostHook() public {
        _session(abi.encode(new Call[](0)));
        assertEq(policy.executions(), 1);
        assertEq(policy.posts(), 0);
    }

    function test_failedCall_rollsBackPlanAndPolicyAccounting() public {
        Call[] memory calls = new Call[](2);
        calls[0] = Call(address(target), 1 ether, abi.encodeCall(target.set, (1)));
        calls[1] = Call(address(target), 0, abi.encodeCall(target.fail, ()));
        _expectSessionRevert(abi.encodeWithSignature("Error(string)", "target failure"), abi.encode(calls));
        assertEq(policy.executions(), 0);
        assertEq(target.value(), 0);
        assertEq(address(target).balance, 0);
    }

    function test_failedPost_rollsBackExecutionAndPolicyAccounting() public {
        policy.setFailPost(true);
        _expectSessionRevert(
            abi.encodeWithSignature("Error(string)", "post failure"),
            _plan(address(target), 1 ether, abi.encodeCall(target.set, (1)))
        );
        assertEq(policy.executions(), 0);
        assertEq(target.value(), 0);
        assertEq(address(target).balance, 0);
    }

    function test_policyHook_cannotReenterExternalEntry() public {
        binding.policy = address(new NativeReentrantPolicy(address(keystore)));
        _install(keyId, k1Authenticator, Scopes.POLICY, UNBOUNDED, address(account), binding);
        _expectSessionRevert(ReentrancyGuard.ReentrancyGuardReentrantCall.selector, "");
    }

    function test_executionTarget_cannotReenterExternalEntry() public {
        NativeReentrantTarget reentrant = new NativeReentrantTarget();
        _expectSessionRevert(
            ReentrancyGuard.ReentrancyGuardReentrantCall.selector,
            _plan(address(reentrant), 0, abi.encodeCall(reentrant.reenter, (address(account), binding)))
        );
    }

    function test_policyPlan_cannotReenterSessionEntry() public {
        _expectSessionRevert(
            ReentrancyGuard.ReentrancyGuardReentrantCall.selector,
            _plan(
                address(account),
                0,
                abi.encodeWithSignature(
                    "execute((address,address,bytes,uint40,uint40,uint256),bytes)", binding, bytes("")
                )
            )
        );
    }

    function test_lock_appliesToPolicyAndOperationalValueTransfers() public {
        _signedLock(ROOT_PK, address(account), 1 hours);
        _expectSessionRevert(
            NativePolicyAccount.AccountLocked.selector, _plan(address(target), 1 ether, abi.encodeCall(target.set, (1)))
        );
        _context(address(account), rootId);
        vm.expectRevert(NativePolicyAccount.AccountLocked.selector);
        vm.prank(address(account));
        account.execute(address(target), 1 ether, abi.encodeCall(target.set, (1)));
        _context(address(account), keyId);
        _session(_plan(address(target), 0, abi.encodeCall(target.set, (2))));
        assertEq(target.value(), 2);
    }

    function testFuzz_scopeDistinguishesOperationalAndPolicy(uint16 scope) public {
        _install(keyId, k1Authenticator, scope, UNBOUNDED, address(account), binding);
        bool operational = scope == 0 || (scope & Scopes.OPERATOR != 0);
        if (!operational) vm.expectRevert(DefaultAccount.UnauthorizedCaller.selector);
        vm.prank(address(account));
        account.operationalProbe();
        if (operational || scope & Scopes.POLICY == 0) {
            vm.expectRevert(abi.encodeWithSelector(NativePolicyAccount.InvalidPolicyActor.selector, keyId));
        }
        _session(abi.encode(new Call[](0)));
    }

    function test_sharedSessionPolicy_subscriptionBudgetAndNextPeriod() public {
        SessionPolicy shared = new SessionPolicy(address(keystore));
        SessionPolicy.TokenLimit[] memory limits = new SessionPolicy.TokenLimit[](1);
        address[] memory recipients = new address[](1);
        recipients[0] = RECIPIENT;
        limits[0] = SessionPolicy.TokenLimit(address(0), 1 ether, 30 days, recipients);
        SessionPolicy.CallScope[] memory scopes = new SessionPolicy.CallScope[](1);
        scopes[0] = SessionPolicy.CallScope(RECIPIENT, new bytes4[](0));
        binding.policy = address(shared);
        binding.policyConfig = abi.encode(SessionPolicy.Config(limits, scopes));
        _install(runnerId, EXTERNAL_POLICY_AUTHENTICATOR, Scopes.POLICY, UNBOUNDED, address(account), binding);
        bytes memory action = abi.encode(SessionPolicy.Action(RECIPIENT, 1 ether, ""));
        vm.prank(RUNNER);
        account.executeFor(binding, action);
        assertEq(RECIPIENT.balance, 1 ether);
        vm.expectRevert(abi.encodeWithSelector(RecurringAllowance.ExceededAllowance.selector, 2 ether, 1 ether));
        vm.prank(RUNNER);
        account.executeFor(binding, action);
        vm.warp(block.timestamp + 30 days);
        vm.prank(RUNNER);
        account.executeFor(binding, action);
        assertEq(RECIPIENT.balance, 2 ether);
    }

    /// @dev Warm-state budgeting only. Context is a Foundry mock, NOT a priced client precompile.
    ///      The two probes exclude execution/guard costs; their delta estimates the extra authority lookup.
    function test_gas_warmOperationalAuthorization() public {
        _authorizeActorWithScope(address(account), ROOT_PK, keyId, k1Authenticator, Scopes.OPERATOR);
        keystore.getActorConfig(address(account), keyId);
        _context(address(account), keyId);
        vm.prank(address(account));
        account.operationalProbe(); // Warm code, config and both mocked context getter addresses.
        vm.prank(address(account));
        account.selfProbe();

        vm.prank(address(account));
        uint256 start = gasleft();
        account.operationalProbe();
        uint256 operationalGas = start - gasleft();
        vm.prank(address(account));
        start = gasleft();
        account.selfProbe();
        uint256 selfGas = start - gasleft();
        emit log_named_uint("warm operational probe (mock context)", operationalGas);
        emit log_named_uint("warm self-only probe", selfGas);
        emit log_named_uint("extra warm authority check (mock context)", operationalGas - selfGas);
    }

    function test_gas_warmPolicyExecution() public {
        // Explicitly warm all actor/policy metadata. No claim that config warmth implies adjacent-slot warmth.
        keystore.getActorWithPolicy(address(account), keyId);
        _session(_plan(address(target), 0, abi.encodeCall(target.set, (1))));
        bytes memory data = _plan(address(target), 0, abi.encodeCall(target.set, (2)));
        vm.prank(address(account));
        uint256 start = gasleft();
        account.execute(binding, data);
        emit log_named_uint("warm policy repeat, dirty counters (mock context)", start - gasleft());
    }

    function _install(
        bytes32 actorId,
        address auth,
        uint16 scope,
        uint48 expiry,
        address manager,
        PolicyBinding memory b
    ) internal {
        _applyLocal(
            ROOT_PK,
            address(account),
            _one(_authorizeChange(actorId, auth, scope, expiry, abi.encodePacked(manager, account.commitmentOf(b))))
        );
    }

    function _context(address sender, bytes32 actorId) internal {
        vm.mockCall(
            TX_CONTEXT_ADDRESS, abi.encodeCall(ITransactionContext.getTransactionSender, ()), abi.encode(sender)
        );
        vm.mockCall(
            TX_CONTEXT_ADDRESS, abi.encodeCall(ITransactionContext.getTransactionSenderActorId, ()), abi.encode(actorId)
        );
    }

    function _session(bytes memory data) internal {
        vm.prank(address(account));
        account.execute(binding, data);
    }

    function _expectSessionRevert(bytes memory reason, bytes memory data) internal {
        vm.expectRevert(reason);
        _session(data);
    }

    function _expectSessionRevert(bytes4 selector, bytes memory data) internal {
        vm.expectRevert(selector);
        _session(data);
    }

    function _calls(address to, uint256 value, bytes memory data) internal pure returns (Call[] memory calls) {
        calls = new Call[](1);
        calls[0] = Call(to, value, data);
    }

    function _plan(address to, uint256 value, bytes memory data) internal pure returns (bytes memory) {
        return abi.encode(_calls(to, value, data));
    }
}
