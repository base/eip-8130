// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {DefaultAccount, Call} from "../../../src/accounts/DefaultAccount.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract MockTarget {
    uint256 public value;

    function setValue(uint256 v) external payable {
        value = v;
    }

    function reverting() external pure {
        revert("boom");
    }
}

contract DefaultAccountTest is AccountConfigurationTest {
    uint256 constant OWNER_PK = 100;
    MockTarget public target;

    function setUp() public override {
        super.setUp();
        target = new MockTarget();
    }

    function _singleCall(address t, uint256 v, bytes memory d) internal pure returns (Call[] memory calls) {
        calls = new Call[](1);
        calls[0] = Call(t, v, d);
    }

    // ── Caller management ──

    function test_selfIsAlwaysAuthorized() public {
        (address account,) = _createK1Account(OWNER_PK);
        assertTrue(DefaultAccount(payable(account)).isAuthorizedCaller(account));
    }

    function test_authorizeCaller_success() public {
        (address account,) = _createK1Account(OWNER_PK);
        address policyManager = address(0xBBBB);

        vm.prank(account);
        DefaultAccount(payable(account)).authorizeCaller(policyManager);

        assertTrue(DefaultAccount(payable(account)).isAuthorizedCaller(policyManager));
    }

    function test_authorizeCaller_revertsFromNonSelf() public {
        (address account,) = _createK1Account(OWNER_PK);

        vm.prank(address(0xdead));
        vm.expectRevert();
        DefaultAccount(payable(account)).authorizeCaller(address(0xBBBB));
    }

    function test_revokeCaller_success() public {
        (address account,) = _createK1Account(OWNER_PK);
        address policyManager = address(0xBBBB);

        vm.prank(account);
        DefaultAccount(payable(account)).authorizeCaller(policyManager);

        vm.prank(account);
        DefaultAccount(payable(account)).revokeCaller(policyManager);

        assertFalse(DefaultAccount(payable(account)).isAuthorizedCaller(policyManager));
    }

    // ── executeBatch ──

    function test_executeBatch_success() public {
        (address account,) = _createK1Account(OWNER_PK);

        vm.prank(account);
        DefaultAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.setValue, (42))));

        assertEq(target.value(), 42);
    }

    function test_executeBatch_withETHValue() public {
        (address account,) = _createK1Account(OWNER_PK);
        vm.deal(account, 1 ether);

        vm.prank(account);
        DefaultAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0.5 ether, abi.encodeCall(MockTarget.setValue, (1))));

        assertEq(address(target).balance, 0.5 ether);
    }

    function test_executeBatch_multipleCalls() public {
        (address account,) = _createK1Account(OWNER_PK);
        MockTarget target2 = new MockTarget();

        Call[] memory calls = new Call[](2);
        calls[0] = Call(address(target), 0, abi.encodeCall(MockTarget.setValue, (10)));
        calls[1] = Call(address(target2), 0, abi.encodeCall(MockTarget.setValue, (20)));

        vm.prank(account);
        DefaultAccount(payable(account)).executeBatch(calls);

        assertEq(target.value(), 10);
        assertEq(target2.value(), 20);
    }

    function test_executeBatch_fromAuthorizedCaller() public {
        (address account,) = _createK1Account(OWNER_PK);
        address policyManager = address(0xBBBB);

        vm.prank(account);
        DefaultAccount(payable(account)).authorizeCaller(policyManager);

        vm.prank(policyManager);
        DefaultAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.setValue, (77))));

        assertEq(target.value(), 77);
    }

    function test_executeBatch_revertsFromUnauthorizedCaller() public {
        (address account,) = _createK1Account(OWNER_PK);

        vm.prank(address(0xdead));
        vm.expectRevert();
        DefaultAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.setValue, (1))));
    }

    function test_executeBatch_revertsOnFailedCall() public {
        (address account,) = _createK1Account(OWNER_PK);

        vm.prank(account);
        vm.expectRevert();
        DefaultAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.reverting, ())));
    }

    // ── isValidSignature ──

    function test_isValidSignature_validK1() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 hash = keccak256("validate me");
        bytes memory sig = _signDigest(OWNER_PK, hash);
        bytes memory authData = abi.encodePacked(uint8(0x01), sig);

        bytes4 result = DefaultAccount(payable(account)).isValidSignature(hash, authData);
        assertEq(result, bytes4(0x1626ba7e));
    }

    function test_isValidSignature_invalidSignature() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 hash = keccak256("validate me");
        bytes memory wrongSig = _signDigest(999, hash);
        bytes memory authData = abi.encodePacked(uint8(0x01), wrongSig);

        bytes4 result = DefaultAccount(payable(account)).isValidSignature(hash, authData);
        assertEq(result, bytes4(0xFFFFFFFF));
    }

    function test_isValidSignature_unknownOwnerId() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 hash = keccak256("validate me");
        bytes memory sig = _signDigest(999, hash);
        bytes memory authData = abi.encodePacked(uint8(0x01), sig);

        bytes4 result = DefaultAccount(payable(account)).isValidSignature(hash, authData);
        assertEq(result, bytes4(0xFFFFFFFF));
    }
}
