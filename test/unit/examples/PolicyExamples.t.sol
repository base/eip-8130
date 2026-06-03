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

/// @notice End-to-end example of the EIP-8130 `policyType = 0x02` flow: a session key is gated to a single
///         {PolicyManager} target, which enforces example policies (recurring ERC-20 limit; selector gating)
///         and drives the account as an execution-enabled owner.
contract PolicyExamplesTest is AccountConfigurationTest {
    PolicyManager internal manager;
    ERC20SpendLimitPolicy internal spendPolicy;
    SelectorGatingPolicy internal gatePolicy;
    MockERC20 internal token;
    MockTarget internal target;

    address internal account;
    address internal bob = address(0xB0B);
    address internal stranger = address(0xBAD);

    uint40 internal constant WEEK = 7 days;

    function setUp() public override {
        super.setUp();
        vm.warp(1_700_000_000);

        manager = new PolicyManager();
        spendPolicy = new ERC20SpendLimitPolicy(address(manager));
        gatePolicy = new SelectorGatingPolicy(address(manager));
        token = new MockERC20();
        target = new MockTarget();

        account = _createAccountWithManagerOwner(address(manager));
        token.mint(account, 1000e18);
    }

    // ── ERC-20 recurring spend limit ──

    function test_erc20SpendLimit_withinAllowance() public {
        bytes32 commitment = _installSpendLimit(500e18, 1);

        vm.prank(account);
        manager.execute(address(spendPolicy), commitment, abi.encode(ERC20SpendLimitPolicy.Transfer(bob, 300e18)));

        assertEq(token.balanceOf(bob), 300e18);
        assertEq(token.balanceOf(account), 700e18);
    }

    function test_erc20SpendLimit_revertsWhenPeriodExceeded() public {
        bytes32 commitment = _installSpendLimit(500e18, 1);

        vm.prank(account);
        manager.execute(address(spendPolicy), commitment, abi.encode(ERC20SpendLimitPolicy.Transfer(bob, 300e18)));

        vm.expectRevert(abi.encodeWithSelector(RecurringAllowance.ExceededAllowance.selector, 600e18, 500e18));
        vm.prank(account);
        manager.execute(address(spendPolicy), commitment, abi.encode(ERC20SpendLimitPolicy.Transfer(bob, 300e18)));
    }

    function test_erc20SpendLimit_resetsNextPeriod() public {
        bytes32 commitment = _installSpendLimit(500e18, 1);

        vm.prank(account);
        manager.execute(address(spendPolicy), commitment, abi.encode(ERC20SpendLimitPolicy.Transfer(bob, 500e18)));

        // Next period: the budget refreshes.
        vm.warp(block.timestamp + WEEK + 1);
        vm.prank(account);
        manager.execute(address(spendPolicy), commitment, abi.encode(ERC20SpendLimitPolicy.Transfer(bob, 400e18)));

        assertEq(token.balanceOf(bob), 900e18);
    }

    // ── Selector gating ──

    function test_selectorGating_allowsCommittedSelector() public {
        bytes32 commitment = _installSelectorGate();

        vm.prank(account);
        manager.execute(
            address(gatePolicy),
            commitment,
            abi.encode(SelectorGatingPolicy.Action(0, abi.encodeCall(MockTarget.setValue, (42))))
        );

        assertEq(target.value(), 42);
    }

    function test_selectorGating_revertsUncommittedSelector() public {
        bytes32 commitment = _installSelectorGate();

        bytes memory badCall = abi.encodeCall(MockTarget.forbidden, (99));
        vm.expectRevert(
            abi.encodeWithSelector(SelectorGatingPolicy.SelectorNotAllowed.selector, MockTarget.forbidden.selector)
        );
        vm.prank(account);
        manager.execute(address(gatePolicy), commitment, abi.encode(SelectorGatingPolicy.Action(0, badCall)));
    }

    // ── Authorization boundary ──

    function test_execute_revertsForNonAccountCaller() public {
        bytes32 commitment = _installSpendLimit(500e18, 1);

        vm.expectRevert(abi.encodeWithSelector(PolicyManager.UnauthorizedAccount.selector, stranger, account));
        vm.prank(stranger);
        manager.execute(address(spendPolicy), commitment, abi.encode(ERC20SpendLimitPolicy.Transfer(bob, 1)));
    }

    function test_install_revertsForNonAccountCaller() public {
        PolicyManager.PolicyBinding memory binding = _spendBinding(500e18, 1);
        vm.expectRevert(abi.encodeWithSelector(PolicyManager.UnauthorizedAccount.selector, stranger, account));
        vm.prank(stranger);
        manager.install(binding);
    }

    // ── Helpers ──

    function _createAccountWithManagerOwner(address policyManager) internal returns (address) {
        IAccountConfiguration.Owner[] memory owners = new IAccountConfiguration.Owner[](1);
        owners[0] = IAccountConfiguration.Owner({
            ownerId: bytes32(bytes20(policyManager)),
            config: IAccountConfiguration.OwnerConfig({verifier: EXTERNAL_CALLER_VERIFIER, scopes: 0x00})
        });
        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        return accountConfiguration.createAccount(bytes32(0), bytecode, owners);
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

    function _installSpendLimit(uint160 allowance, uint256 salt) internal returns (bytes32 commitment) {
        PolicyManager.PolicyBinding memory binding = _spendBinding(allowance, salt);
        vm.prank(account);
        commitment = manager.install(binding);
    }

    function _installSelectorGate() internal returns (bytes32 commitment) {
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
        vm.prank(account);
        commitment = manager.install(binding);
    }
}
