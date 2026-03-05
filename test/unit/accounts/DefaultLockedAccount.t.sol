// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountOperation} from "../../../src/AccountConfigDigest.sol";
import {DefaultAccount} from "../../../src/accounts/DefaultAccount.sol";
import {DefaultHighThroughputAccount} from "../../../src/accounts/DefaultHighThroughputAccount.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract MockTarget {
    uint256 public value;

    function setValue(uint256 v) external payable {
        value = v;
    }
}

contract DefaultLockedAccountTest is AccountConfigurationTest {
    uint256 constant OWNER_PK = 100;
    MockTarget public target;

    function setUp() public override {
        super.setUp();
        defaultAccountImplementation = address(new DefaultHighThroughputAccount(address(accountConfiguration)));
        target = new MockTarget();
    }

    function test_executeBatch_blocksETHWhenLocked() public {
        (address account, bytes32 keyId) = _createK1Account(OWNER_PK);
        vm.deal(account, 1 ether);

        _lockAccount(account, OWNER_PK, keyId);

        (bool locked,,) = accountConfiguration.getAccountPolicy(account);
        assertTrue(locked);

        DefaultAccount.Call[] memory calls = new DefaultAccount.Call[](1);
        calls[0] = DefaultAccount.Call({
            target: address(target), data: abi.encodeCall(MockTarget.setValue, (1)), value: 0.1 ether
        });

        vm.prank(account);
        vm.expectRevert();
        DefaultAccount(payable(account)).executeBatch(calls);
    }

    function test_executeBatch_allowsZeroValueCallsWhenLocked() public {
        (address account, bytes32 keyId) = _createK1Account(OWNER_PK);

        _lockAccount(account, OWNER_PK, keyId);

        DefaultAccount.Call[] memory calls = new DefaultAccount.Call[](1);
        calls[0] =
            DefaultAccount.Call({target: address(target), data: abi.encodeCall(MockTarget.setValue, (99)), value: 0});

        vm.prank(account);
        DefaultAccount(payable(account)).executeBatch(calls);

        assertEq(target.value(), 99);
    }

    function test_executeBatch_allowsETHWhenUnlocked() public {
        (address account,) = _createK1Account(OWNER_PK);
        vm.deal(account, 1 ether);

        DefaultAccount.Call[] memory calls = new DefaultAccount.Call[](1);
        calls[0] = DefaultAccount.Call({
            target: address(target), data: abi.encodeCall(MockTarget.setValue, (1)), value: 0.5 ether
        });

        vm.prank(account);
        DefaultAccount(payable(account)).executeBatch(calls);

        assertEq(address(target).balance, 0.5 ether);
    }

    function _lockAccount(address account, uint256 pk, bytes32 keyId) internal {
        AccountOperation[] memory ops = new AccountOperation[](1);
        ops[0] = AccountOperation({
            opType: 0x03, // OP_SET_ACCOUNT_POLICY
            flags: 0x01, // POLICY_LOCKED
            unlockDelay: 1 hours
        });

        uint64 chainId = uint64(block.chainid);
        uint64 sequence = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeAccountChangeDigest(account, chainId, sequence, ops);
        bytes memory auth = _buildK1Auth(pk, digest);

        accountConfiguration.applyAccountChange(account, chainId, sequence, ops, auth);
    }
}
