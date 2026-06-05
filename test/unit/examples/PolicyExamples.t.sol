// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IAccountConfiguration} from "../../../src/interfaces/IAccountConfiguration.sol";
import {DefaultAccount, Call, EXTERNAL_CALLER_VERIFIER} from "../../../src/accounts/DefaultAccount.sol";

import {PolicyManager} from "../../../src/examples/policies/PolicyManager.sol";
import {ERC20SpendLimitPolicy} from "../../../src/examples/policies/ERC20SpendLimitPolicy.sol";
import {SelectorGatingPolicy} from "../../../src/examples/policies/SelectorGatingPolicy.sol";
import {RecurringAllowance} from "../../../src/examples/policies/RecurringAllowance.sol";

import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract MockERC20 {
    mapping(address account => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

contract MockTarget {
    uint256 public value;

    function setValue(uint256 v) external {
        value = v;
    }

    function forbidden(uint256 v) external {
        value = v;
    }
}

/// @notice End-to-end example of the EIP-8130 policy flow (non-zero `policyType`): a session key is gated to a single
///         {PolicyManager} target, which enforces example policies (recurring ERC-20 limit; selector gating)
///         and drives the account as an execution-enabled actor.
contract PolicyExamplesTest is AccountConfigurationTest {
    PolicyManager internal manager;
    ERC20SpendLimitPolicy internal spendPolicy;
    SelectorGatingPolicy internal gatePolicy;
    MockERC20 internal token;
    MockTarget internal target;

    address internal account;
    address internal bob = address(0xB0B);
    address internal stranger = address(0xBAD);

    uint256 internal constant ROOT_PK = 0xA11CE;

    uint8 internal constant SCOPE_SENDER = 0x02;
    uint8 internal constant POLICY_GATED = 0x01;
    uint8 internal constant AUTHORIZE_ACTOR = 0x01;
    uint8 internal constant REVOKE_ACTOR = 0x02;

    uint40 internal constant WEEK = 7 days;

    function setUp() public override {
        super.setUp();
        vm.warp(1_700_000_000);

        manager = new PolicyManager(address(accountConfiguration));
        spendPolicy = new ERC20SpendLimitPolicy(address(manager));
        gatePolicy = new SelectorGatingPolicy(address(manager));
        token = new MockERC20();
        target = new MockTarget();

        account = _createAccountWithRootAndManager();
        token.mint(account, 1000e18);
    }

    // ── ERC-20 recurring spend limit ──

    function test_erc20SpendLimit_withinAllowance() public {
        bytes32 actorId = _installSpendLimit(500e18, 1);

        vm.prank(account);
        manager.execute(actorId, address(spendPolicy), abi.encode(ERC20SpendLimitPolicy.Transfer(bob, 300e18)));

        assertEq(token.balanceOf(bob), 300e18);
        assertEq(token.balanceOf(account), 700e18);
    }

    function test_erc20SpendLimit_revertsWhenPeriodExceeded() public {
        bytes32 actorId = _installSpendLimit(500e18, 1);

        vm.prank(account);
        manager.execute(actorId, address(spendPolicy), abi.encode(ERC20SpendLimitPolicy.Transfer(bob, 300e18)));

        vm.expectRevert(abi.encodeWithSelector(RecurringAllowance.ExceededAllowance.selector, 600e18, 500e18));
        vm.prank(account);
        manager.execute(actorId, address(spendPolicy), abi.encode(ERC20SpendLimitPolicy.Transfer(bob, 300e18)));
    }

    function test_erc20SpendLimit_resetsNextPeriod() public {
        bytes32 actorId = _installSpendLimit(500e18, 1);

        vm.prank(account);
        manager.execute(actorId, address(spendPolicy), abi.encode(ERC20SpendLimitPolicy.Transfer(bob, 500e18)));

        // Next period: the budget refreshes.
        vm.warp(block.timestamp + WEEK + 1);
        vm.prank(account);
        manager.execute(actorId, address(spendPolicy), abi.encode(ERC20SpendLimitPolicy.Transfer(bob, 400e18)));

        assertEq(token.balanceOf(bob), 900e18);
    }

    // ── Selector gating ──

    function test_selectorGating_allowsCommittedSelector() public {
        bytes32 actorId = _installSelectorGate();

        vm.prank(account);
        manager.execute(
            actorId,
            address(gatePolicy),
            abi.encode(SelectorGatingPolicy.Action(0, abi.encodeCall(MockTarget.setValue, (42))))
        );

        assertEq(target.value(), 42);
    }

    function test_selectorGating_revertsUncommittedSelector() public {
        bytes32 actorId = _installSelectorGate();

        bytes memory badCall = abi.encodeCall(MockTarget.forbidden, (99));
        vm.expectRevert(
            abi.encodeWithSelector(SelectorGatingPolicy.SelectorNotAllowed.selector, MockTarget.forbidden.selector)
        );
        vm.prank(account);
        manager.execute(actorId, address(gatePolicy), abi.encode(SelectorGatingPolicy.Action(0, badCall)));
    }

    // ── Authorization boundary ──

    function test_execute_revertsForUnauthorizedCaller() public {
        bytes32 actorId = _installSpendLimit(500e18, 1);

        // A stranger has no policy for this actorId, so getPolicy resolves to nothing.
        vm.expectRevert(
            abi.encodeWithSelector(PolicyManager.CommitmentNotAuthorized.selector, actorId, address(0), bytes32(0))
        );
        vm.prank(stranger);
        manager.execute(actorId, address(spendPolicy), abi.encode(ERC20SpendLimitPolicy.Transfer(bob, 1)));
    }

    function test_execute_revertsAfterRevoke() public {
        bytes32 actorId = _installSpendLimit(500e18, 1);
        _revokePolicyActor(actorId);

        // Revoke cleared the policy slots; the per-call getPolicy check now resolves to nothing.
        vm.expectRevert(
            abi.encodeWithSelector(PolicyManager.CommitmentNotAuthorized.selector, actorId, address(0), bytes32(0))
        );
        vm.prank(account);
        manager.execute(actorId, address(spendPolicy), abi.encode(ERC20SpendLimitPolicy.Transfer(bob, 1)));
    }

    function test_install_revertsForNonAccountCaller() public {
        PolicyManager.PolicyBinding memory binding = _spendBinding(500e18, 1);
        vm.expectRevert(abi.encodeWithSelector(PolicyManager.UnauthorizedAccount.selector, stranger, account));
        vm.prank(stranger);
        manager.install(bytes32(0), binding);
    }

    function test_install_revertsWhenCommitmentNotAuthorized() public {
        // Binding is well-formed, but the account never authorized an actor committing to it.
        PolicyManager.PolicyBinding memory binding = _spendBinding(500e18, 7);
        bytes32 actorId = _sessionActorId(7);

        vm.expectRevert(
            abi.encodeWithSelector(PolicyManager.CommitmentNotAuthorized.selector, actorId, address(0), bytes32(0))
        );
        vm.prank(account);
        manager.install(actorId, binding);
    }

    function test_getPolicy_resolvesManagerAndCommitment() public {
        PolicyManager.PolicyBinding memory binding = _spendBinding(500e18, 9);
        bytes32 commitment = manager.commitmentOf(binding);
        bytes32 actorId = _sessionActorId(9);
        _authorizePolicyActor(actorId, commitment);

        (address target_, bytes32 signed) = accountConfiguration.getPolicy(account, actorId);
        assertEq(target_, address(manager));
        assertEq(signed, commitment);
    }

    // ── Helpers ──

    /// @dev Account with a K1 root actor (can authorize actors) and the manager as an execution-enabled actor.
    function _createAccountWithRootAndManager() internal returns (address) {
        IAccountConfiguration.InitialActor memory root = IAccountConfiguration.InitialActor({
            actorId: bytes32(bytes20(vm.addr(ROOT_PK))), verifier: address(k1Verifier)
        });
        IAccountConfiguration.InitialActor memory mgr = IAccountConfiguration.InitialActor({
            actorId: bytes32(bytes20(address(manager))), verifier: EXTERNAL_CALLER_VERIFIER
        });

        IAccountConfiguration.InitialActor[] memory actors = new IAccountConfiguration.InitialActor[](2);
        (actors[0], actors[1]) = root.actorId < mgr.actorId ? (root, mgr) : (mgr, root);

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        return accountConfiguration.createAccount(bytes32(0), bytecode, actors);
    }

    /// @dev Root actor authorizes `actorId` as a session key gated to the manager (policyType 0x01), committing to
    ///      `commitment`. This writes `policy_manager`/`policy_commitment` that the manager reads back per call.
    function _authorizePolicyActor(bytes32 actorId, bytes32 commitment) internal {
        IAccountConfiguration.ActorConfig memory cfg = IAccountConfiguration.ActorConfig({
            verifier: address(k1Verifier), scope: SCOPE_SENDER, expiry: 0, policyType: POLICY_GATED
        });
        bytes memory policyData = abi.encodePacked(address(manager), commitment);

        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: actorId, changeType: AUTHORIZE_ACTOR, data: abi.encode(cfg, policyData)
        });

        uint64 chainId = uint64(block.chainid);
        uint64 sequence = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, chainId, sequence, changes);
        accountConfiguration.applySignedActorChanges(account, chainId, changes, _buildK1Auth(ROOT_PK, digest));
    }

    function _revokePolicyActor(bytes32 actorId) internal {
        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({actorId: actorId, changeType: REVOKE_ACTOR, data: ""});

        uint64 chainId = uint64(block.chainid);
        uint64 sequence = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, chainId, sequence, changes);
        accountConfiguration.applySignedActorChanges(account, chainId, changes, _buildK1Auth(ROOT_PK, digest));
    }

    function _sessionActorId(uint256 salt) internal pure returns (bytes32) {
        return keccak256(abi.encode("session-key", salt));
    }

    function _spendBinding(uint160 allowance, uint256 salt) internal view returns (PolicyManager.PolicyBinding memory) {
        ERC20SpendLimitPolicy.Config memory config = ERC20SpendLimitPolicy.Config({
            token: address(token),
            allowance: allowance,
            period: WEEK,
            start: uint40(block.timestamp),
            end: uint40(block.timestamp + 365 days)
        });
        return PolicyManager.PolicyBinding({
            account: account,
            policy: address(spendPolicy),
            policyConfig: abi.encode(config),
            validAfter: 0,
            validUntil: 0,
            salt: salt
        });
    }

    function _installSpendLimit(uint160 allowance, uint256 salt) internal returns (bytes32 actorId) {
        PolicyManager.PolicyBinding memory binding = _spendBinding(allowance, salt);
        actorId = _sessionActorId(salt);
        _authorizePolicyActor(actorId, manager.commitmentOf(binding));
        vm.prank(account);
        manager.install(actorId, binding);
    }

    function _installSelectorGate() internal returns (bytes32 actorId) {
        bytes4[] memory selectors = new bytes4[](1);
        selectors[0] = MockTarget.setValue.selector;
        SelectorGatingPolicy.Config memory config =
            SelectorGatingPolicy.Config({target: address(target), selectors: selectors});
        PolicyManager.PolicyBinding memory binding = PolicyManager.PolicyBinding({
            account: account,
            policy: address(gatePolicy),
            policyConfig: abi.encode(config),
            validAfter: 0,
            validUntil: 0,
            salt: 2
        });
        actorId = _sessionActorId(2);
        _authorizePolicyActor(actorId, manager.commitmentOf(binding));
        vm.prank(account);
        manager.install(actorId, binding);
    }
}
