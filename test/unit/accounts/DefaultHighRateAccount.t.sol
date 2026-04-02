// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {DefaultHighRateAccount} from "../../../src/accounts/DefaultHighRateAccount.sol";
import {Call} from "../../../src/accounts/DefaultAccount.sol";
import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {IAccountConfiguration} from "../../../src/interfaces/IAccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract HighRateMockTarget {
    uint256 public value;

    function setValue(uint256 v) external payable {
        value = v;
    }

    function reverting() external pure {
        revert("boom");
    }
}

contract DefaultHighRateAccountTest is AccountConfigurationTest {
    uint256 constant OWNER_PK = 100;
    HighRateMockTarget public target;
    address public highRateImplementation;

    function setUp() public override {
        super.setUp();
        target = new HighRateMockTarget();
        highRateImplementation = address(new DefaultHighRateAccount(address(accountConfiguration)));
    }

    function _createHighRateK1Account(uint256 pk) internal returns (address account, bytes32 ownerId) {
        address signer = vm.addr(pk);
        ownerId = bytes32(bytes20(signer));

        IAccountConfiguration.Owner[] memory owners = new IAccountConfiguration.Owner[](1);
        owners[0] = IAccountConfiguration.Owner({
            ownerId: ownerId, config: IAccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scopes: 0x00})
        });

        bytes memory bytecode = _computeERC1167Bytecode(highRateImplementation);
        account = accountConfiguration.createAccount(bytes32(uint256(0xbeef)), bytecode, owners);
    }

    function _lockAccount(address account, uint16 unlockDelay) internal {
        vm.prank(account);
        accountConfiguration.lock(unlockDelay);
    }

    function _singleCall(address t, uint256 v, bytes memory d) internal pure returns (Call[] memory calls) {
        calls = new Call[](1);
        calls[0] = Call(t, v, d);
    }

    // ── executeBatch ──

    function test_executeBatch_success() public {
        (address account,) = _createHighRateK1Account(OWNER_PK);

        vm.prank(account);
        DefaultHighRateAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(HighRateMockTarget.setValue, (42))));

        assertEq(target.value(), 42);
    }

    function test_executeBatch_withETHValue() public {
        (address account,) = _createHighRateK1Account(OWNER_PK);
        vm.deal(account, 1 ether);

        vm.prank(account);
        DefaultHighRateAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0.5 ether, abi.encodeCall(HighRateMockTarget.setValue, (1))));

        assertEq(address(target).balance, 0.5 ether);
    }

    function test_executeBatch_multipleCalls() public {
        (address account,) = _createHighRateK1Account(OWNER_PK);
        HighRateMockTarget target2 = new HighRateMockTarget();

        Call[] memory calls = new Call[](2);
        calls[0] = Call(address(target), 0, abi.encodeCall(HighRateMockTarget.setValue, (10)));
        calls[1] = Call(address(target2), 0, abi.encodeCall(HighRateMockTarget.setValue, (20)));

        vm.prank(account);
        DefaultHighRateAccount(payable(account)).executeBatch(calls);

        assertEq(target.value(), 10);
        assertEq(target2.value(), 20);
    }

    function test_executeBatch_revertsFromNonSelf() public {
        (address account,) = _createHighRateK1Account(OWNER_PK);

        vm.prank(address(0xdead));
        vm.expectRevert();
        DefaultHighRateAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(HighRateMockTarget.setValue, (1))));
    }

    function test_executeBatch_revertsOnFailedCall() public {
        (address account,) = _createHighRateK1Account(OWNER_PK);

        vm.prank(account);
        vm.expectRevert();
        DefaultHighRateAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(HighRateMockTarget.reverting, ())));
    }

    function test_executeBatch_blocksETHWhenLocked() public {
        (address account,) = _createHighRateK1Account(OWNER_PK);
        vm.deal(account, 1 ether);

        _lockAccount(account, 1 hours);

        vm.prank(account);
        vm.expectRevert();
        DefaultHighRateAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0.1 ether, abi.encodeCall(HighRateMockTarget.setValue, (1))));
    }

    function test_executeBatch_allowsZeroValueCallsWhenLocked() public {
        (address account,) = _createHighRateK1Account(OWNER_PK);

        _lockAccount(account, 1 hours);

        vm.prank(account);
        DefaultHighRateAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(HighRateMockTarget.setValue, (99))));

        assertEq(target.value(), 99);
    }

    function test_executeBatch_allowsETHWhenUnlocked() public {
        (address account,) = _createHighRateK1Account(OWNER_PK);
        vm.deal(account, 1 ether);

        vm.prank(account);
        DefaultHighRateAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0.5 ether, abi.encodeCall(HighRateMockTarget.setValue, (1))));

        assertEq(address(target).balance, 0.5 ether);
    }

    // ── isValidSignature ──

    function test_isValidSignature_validK1() public {
        (address account,) = _createHighRateK1Account(OWNER_PK);

        bytes32 hash = keccak256("validate me");
        bytes memory authData = _buildK1Auth(OWNER_PK, hash);

        bytes4 result = DefaultHighRateAccount(payable(account)).isValidSignature(hash, authData);
        assertEq(result, bytes4(0x1626ba7e));
    }

    function test_isValidSignature_invalidSignature() public {
        (address account,) = _createHighRateK1Account(OWNER_PK);

        bytes32 hash = keccak256("validate me");
        bytes memory authData = _buildK1Auth(999, hash);

        bytes4 result = DefaultHighRateAccount(payable(account)).isValidSignature(hash, authData);
        assertEq(result, bytes4(0xFFFFFFFF));
    }
}
