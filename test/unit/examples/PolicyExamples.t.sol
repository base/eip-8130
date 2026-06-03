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

    uint256 internal constant ROOT_PK = 0xA11CE;

    uint8 internal constant SCOPE_SENDER = 0x02;
    uint8 internal constant POLICY_GATED = 0x01;
    uint8 internal constant AUTHORIZE_OWNER = 0x01;
    uint8 internal constant REVOKE_OWNER = 0x02;

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
        bytes32 ownerId = _installSpendLimit(500e18, 1);

        vm.prank(account);
        manager.execute(ownerId, address(spendPolicy), abi.encode(ERC20SpendLimitPolicy.Transfer(bob, 300e18)));

        assertEq(token.balanceOf(bob), 300e18);
        assertEq(token.balanceOf(account), 700e18);
    }

    function test_erc20SpendLimit_revertsWhenPeriodExceeded() public {
        bytes32 ownerId = _installSpendLimit(500e18, 1);

        vm.prank(account);
        manager.execute(ownerId, address(spendPolicy), abi.encode(ERC20SpendLimitPolicy.Transfer(bob, 300e18)));

        vm.expectRevert(abi.encodeWithSelector(RecurringAllowance.ExceededAllowance.selector, 600e18, 500e18));
        vm.prank(account);
        manager.execute(ownerId, address(spendPolicy), abi.encode(ERC20SpendLimitPolicy.Transfer(bob, 300e18)));
    }

    function test_erc20SpendLimit_resetsNextPeriod() public {
        bytes32 ownerId = _installSpendLimit(500e18, 1);

        vm.prank(account);
        manager.execute(ownerId, address(spendPolicy), abi.encode(ERC20SpendLimitPolicy.Transfer(bob, 500e18)));

        // Next period: the budget refreshes.
        vm.warp(block.timestamp + WEEK + 1);
        vm.prank(account);
        manager.execute(ownerId, address(spendPolicy), abi.encode(ERC20SpendLimitPolicy.Transfer(bob, 400e18)));

        assertEq(token.balanceOf(bob), 900e18);
    }

    // ── Selector gating ──

    function test_selectorGating_allowsCommittedSelector() public {
        bytes32 ownerId = _installSelectorGate();

        vm.prank(account);
        manager.execute(
            ownerId,
            address(gatePolicy),
            abi.encode(SelectorGatingPolicy.Action(0, abi.encodeCall(MockTarget.setValue, (42))))
        );

        assertEq(target.value(), 42);
    }

    function test_selectorGating_revertsUncommittedSelector() public {
        bytes32 ownerId = _installSelectorGate();

        bytes memory badCall = abi.encodeCall(MockTarget.forbidden, (99));
        vm.expectRevert(
            abi.encodeWithSelector(SelectorGatingPolicy.SelectorNotAllowed.selector, MockTarget.forbidden.selector)
        );
        vm.prank(account);
        manager.execute(ownerId, address(gatePolicy), abi.encode(SelectorGatingPolicy.Action(0, badCall)));
    }

    // ── Authorization boundary ──

    function test_execute_revertsForUnauthorizedCaller() public {
        bytes32 ownerId = _installSpendLimit(500e18, 1);

        // A stranger has no policy for this ownerId, so getPolicy resolves to nothing.
        vm.expectRevert(
            abi.encodeWithSelector(PolicyManager.CommitmentNotAuthorized.selector, ownerId, address(0), bytes32(0))
        );
        vm.prank(stranger);
        manager.execute(ownerId, address(spendPolicy), abi.encode(ERC20SpendLimitPolicy.Transfer(bob, 1)));
    }

    function test_execute_revertsAfterRevoke() public {
        bytes32 ownerId = _installSpendLimit(500e18, 1);
        _revokePolicyOwner(ownerId);

        // Revoke cleared the policy slots; the per-call getPolicy check now resolves to nothing.
        vm.expectRevert(
            abi.encodeWithSelector(PolicyManager.CommitmentNotAuthorized.selector, ownerId, address(0), bytes32(0))
        );
        vm.prank(account);
        manager.execute(ownerId, address(spendPolicy), abi.encode(ERC20SpendLimitPolicy.Transfer(bob, 1)));
    }

    function test_install_revertsForNonAccountCaller() public {
        PolicyManager.PolicyBinding memory binding = _spendBinding(500e18, 1);
        vm.expectRevert(abi.encodeWithSelector(PolicyManager.UnauthorizedAccount.selector, stranger, account));
        vm.prank(stranger);
        manager.install(bytes32(0), binding);
    }

    function test_install_revertsWhenCommitmentNotAuthorized() public {
        // Binding is well-formed, but the account never authorized an owner committing to it.
        PolicyManager.PolicyBinding memory binding = _spendBinding(500e18, 7);
        bytes32 ownerId = _sessionOwnerId(7);

        vm.expectRevert(
            abi.encodeWithSelector(PolicyManager.CommitmentNotAuthorized.selector, ownerId, address(0), bytes32(0))
        );
        vm.prank(account);
        manager.install(ownerId, binding);
    }

    function test_getPolicy_resolvesManagerAndCommitment() public {
        PolicyManager.PolicyBinding memory binding = _spendBinding(500e18, 9);
        bytes32 commitment = manager.commitmentOf(binding);
        bytes32 ownerId = _sessionOwnerId(9);
        _authorizePolicyOwner(ownerId, commitment);

        (address target_, bytes32 signed) = accountConfiguration.getPolicy(account, ownerId);
        assertEq(target_, address(manager));
        assertEq(signed, commitment);
    }

    // ── Helpers ──

    /// @dev Account with a K1 root owner (can authorize owners) and the manager as an execution-enabled owner.
    function _createAccountWithRootAndManager() internal returns (address) {
        IAccountConfiguration.Owner memory root = IAccountConfiguration.Owner({
            ownerId: bytes32(bytes20(vm.addr(ROOT_PK))),
            config: IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00, policyType: 0x00}),
            policyData: ""
        });
        IAccountConfiguration.Owner memory mgr = IAccountConfiguration.Owner({
            ownerId: bytes32(bytes20(address(manager))),
            config: IAccountConfiguration.OwnerConfig({
                verifier: EXTERNAL_CALLER_VERIFIER,
                scopes: 0x00,
                policyType: 0x00
            }),
            policyData: ""
        });

        IAccountConfiguration.Owner[] memory owners = new IAccountConfiguration.Owner[](2);
        (owners[0], owners[1]) = root.ownerId < mgr.ownerId ? (root, mgr) : (mgr, root);

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        return accountConfiguration.createAccount(bytes32(0), bytecode, owners);
    }

    /// @dev Root owner authorizes `ownerId` as a session key gated to the manager (policyType 0x01), committing to
    ///      `commitment`. This writes `policy_manager`/`policy_commitment` that the manager reads back per call.
    function _authorizePolicyOwner(bytes32 ownerId, bytes32 commitment) internal {
        IAccountConfiguration.OwnerConfig memory cfg = IAccountConfiguration.OwnerConfig({
            verifier: address(k1Verifier),
            scopes: SCOPE_SENDER,
            policyType: POLICY_GATED
        });
        bytes memory policyData = abi.encodePacked(address(manager), commitment);

        IAccountConfiguration.OwnerChange[] memory changes = new IAccountConfiguration.OwnerChange[](1);
        changes[0] = IAccountConfiguration.OwnerChange({
            ownerId: ownerId,
            changeType: AUTHORIZE_OWNER,
            configData: abi.encode(cfg, policyData)
        });

        uint64 chainId = uint64(block.chainid);
        uint64 sequence = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeOwnerChangeBatchDigest(account, chainId, sequence, changes);
        accountConfiguration.applySignedOwnerChanges(account, chainId, changes, _buildK1Auth(ROOT_PK, digest));
    }

    function _revokePolicyOwner(bytes32 ownerId) internal {
        IAccountConfiguration.OwnerChange[] memory changes = new IAccountConfiguration.OwnerChange[](1);
        changes[0] = IAccountConfiguration.OwnerChange({ownerId: ownerId, changeType: REVOKE_OWNER, configData: ""});

        uint64 chainId = uint64(block.chainid);
        uint64 sequence = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeOwnerChangeBatchDigest(account, chainId, sequence, changes);
        accountConfiguration.applySignedOwnerChanges(account, chainId, changes, _buildK1Auth(ROOT_PK, digest));
    }

    function _sessionOwnerId(uint256 salt) internal pure returns (bytes32) {
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

    function _installSpendLimit(uint160 allowance, uint256 salt) internal returns (bytes32 ownerId) {
        PolicyManager.PolicyBinding memory binding = _spendBinding(allowance, salt);
        ownerId = _sessionOwnerId(salt);
        _authorizePolicyOwner(ownerId, manager.commitmentOf(binding));
        vm.prank(account);
        manager.install(ownerId, binding);
    }

    function _installSelectorGate() internal returns (bytes32 ownerId) {
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
        ownerId = _sessionOwnerId(2);
        _authorizePolicyOwner(ownerId, manager.commitmentOf(binding));
        vm.prank(account);
        manager.install(ownerId, binding);
    }
}
