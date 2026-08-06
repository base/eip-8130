// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {CanonicalHighRatePayerAccount} from "../../../src/accounts/CanonicalHighRatePayerAccount.sol";
import {Call, DefaultAccount} from "../../../src/accounts/DefaultAccount.sol";
import {Keystore} from "../../../src/Keystore.sol";
import {KeystoreTest} from "../../lib/KeystoreTest.sol";

contract HighRatePayerMockTarget {
    uint256 public value;

    function setValue(uint256 v) external payable {
        value = v;
    }

    function reverting() external pure {
        revert("boom");
    }
}

contract CanonicalHighRatePayerAccountTest is KeystoreTest {
    uint256 constant ACTOR_PK = 100;
    HighRatePayerMockTarget public target;
    address public highRatePayerImplementation;

    function setUp() public override {
        super.setUp();
        target = new HighRatePayerMockTarget();
        highRatePayerImplementation = address(new CanonicalHighRatePayerAccount(address(keystore)));
    }

    function _createHighRatePayerK1Account(uint256 pk) internal returns (address account, bytes32 actorId) {
        address signer = vm.addr(pk);
        actorId = bytes32(bytes20(signer));

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](1);
        actors[0] = Keystore.InitialActor({
            actorId: actorId, authenticator: address(k1Authenticator), scope: 0, policyData: ""
        });

        // ERC-1167 clone of CanonicalHighRatePayerAccount — the fixed delegation required for high-rate paying.
        bytes memory bytecode = _computeERC1167Bytecode(highRatePayerImplementation);
        account = keystore.createAccount(bytes32(uint256(0xbeef)), bytecode, actors);
    }

    /// @dev Hard-lock `account` via the signed lock path, authorized by its admin owner key `pk`.
    function _lockAccount(uint256 pk, address account, uint16 unlockDelay) internal {
        _signedLock(pk, account, unlockDelay);
    }

    function _singleCall(address t, uint256 v, bytes memory d) internal pure returns (Call[] memory calls) {
        calls = new Call[](1);
        calls[0] = Call(t, v, d);
    }

    // ── executeBatch ──

    function test_executeBatch_success() public {
        (address account,) = _createHighRatePayerK1Account(ACTOR_PK);

        vm.prank(account);
        CanonicalHighRatePayerAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(HighRatePayerMockTarget.setValue, (42))));

        assertEq(target.value(), 42);
    }

    function test_executeBatch_withETHValue() public {
        (address account,) = _createHighRatePayerK1Account(ACTOR_PK);
        vm.deal(account, 1 ether);

        vm.prank(account);
        CanonicalHighRatePayerAccount(payable(account))
            .executeBatch(
                _singleCall(address(target), 0.5 ether, abi.encodeCall(HighRatePayerMockTarget.setValue, (1)))
            );

        assertEq(address(target).balance, 0.5 ether);
    }

    function test_executeBatch_multipleCalls() public {
        (address account,) = _createHighRatePayerK1Account(ACTOR_PK);
        HighRatePayerMockTarget target2 = new HighRatePayerMockTarget();

        Call[] memory calls = new Call[](2);
        calls[0] = Call(address(target), 0, abi.encodeCall(HighRatePayerMockTarget.setValue, (10)));
        calls[1] = Call(address(target2), 0, abi.encodeCall(HighRatePayerMockTarget.setValue, (20)));

        vm.prank(account);
        CanonicalHighRatePayerAccount(payable(account)).executeBatch(calls);

        assertEq(target.value(), 10);
        assertEq(target2.value(), 20);
    }

    function test_executeBatch_revertsFromNonSelf() public {
        (address account,) = _createHighRatePayerK1Account(ACTOR_PK);

        vm.prank(address(0xdead));
        vm.expectRevert(DefaultAccount.UnauthorizedCaller.selector);
        CanonicalHighRatePayerAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(HighRatePayerMockTarget.setValue, (1))));
    }

    function test_executeBatch_revertsOnFailedCall() public {
        (address account,) = _createHighRatePayerK1Account(ACTOR_PK);

        vm.prank(account);
        vm.expectRevert(DefaultAccount.CallFailed.selector);
        CanonicalHighRatePayerAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(HighRatePayerMockTarget.reverting, ())));
    }

    function test_executeBatch_blocksETHWhenLocked() public {
        (address account,) = _createHighRatePayerK1Account(ACTOR_PK);
        vm.deal(account, 1 ether);

        _lockAccount(ACTOR_PK, account, 1 hours);

        vm.prank(account);
        vm.expectRevert(CanonicalHighRatePayerAccount.AccountLocked.selector);
        CanonicalHighRatePayerAccount(payable(account))
            .executeBatch(
                _singleCall(address(target), 0.1 ether, abi.encodeCall(HighRatePayerMockTarget.setValue, (1)))
            );
    }

    function test_executeBatch_allowsZeroValueCallsWhenLocked() public {
        (address account,) = _createHighRatePayerK1Account(ACTOR_PK);

        _lockAccount(ACTOR_PK, account, 1 hours);

        vm.prank(account);
        CanonicalHighRatePayerAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(HighRatePayerMockTarget.setValue, (99))));

        assertEq(target.value(), 99);
    }

    function test_executeBatch_allowsETHWhenUnlocked() public {
        (address account,) = _createHighRatePayerK1Account(ACTOR_PK);
        vm.deal(account, 1 ether);

        vm.prank(account);
        CanonicalHighRatePayerAccount(payable(account))
            .executeBatch(
                _singleCall(address(target), 0.5 ether, abi.encodeCall(HighRatePayerMockTarget.setValue, (1)))
            );

        assertEq(address(target).balance, 0.5 ether);
    }

    // ── execute ──

    function test_execute_success() public {
        (address account,) = _createHighRatePayerK1Account(ACTOR_PK);

        vm.prank(account);
        CanonicalHighRatePayerAccount(payable(account))
            .execute(address(target), 0, abi.encodeCall(HighRatePayerMockTarget.setValue, (42)));

        assertEq(target.value(), 42);
    }

    function test_execute_withETHValue() public {
        (address account,) = _createHighRatePayerK1Account(ACTOR_PK);
        vm.deal(account, 1 ether);

        vm.prank(account);
        CanonicalHighRatePayerAccount(payable(account))
            .execute(address(target), 0.5 ether, abi.encodeCall(HighRatePayerMockTarget.setValue, (1)));

        assertEq(address(target).balance, 0.5 ether);
    }

    function test_execute_revertsFromNonSelf() public {
        (address account,) = _createHighRatePayerK1Account(ACTOR_PK);

        vm.prank(address(0xdead));
        vm.expectRevert(DefaultAccount.UnauthorizedCaller.selector);
        CanonicalHighRatePayerAccount(payable(account))
            .execute(address(target), 0, abi.encodeCall(HighRatePayerMockTarget.setValue, (1)));
    }

    function test_execute_revertsOnFailedCall() public {
        (address account,) = _createHighRatePayerK1Account(ACTOR_PK);

        vm.prank(account);
        vm.expectRevert(DefaultAccount.CallFailed.selector);
        CanonicalHighRatePayerAccount(payable(account))
            .execute(address(target), 0, abi.encodeCall(HighRatePayerMockTarget.reverting, ()));
    }

    function test_execute_blocksETHWhenLocked() public {
        (address account,) = _createHighRatePayerK1Account(ACTOR_PK);
        vm.deal(account, 1 ether);

        _lockAccount(ACTOR_PK, account, 1 hours);

        vm.prank(account);
        vm.expectRevert(CanonicalHighRatePayerAccount.AccountLocked.selector);
        CanonicalHighRatePayerAccount(payable(account))
            .execute(address(target), 0.1 ether, abi.encodeCall(HighRatePayerMockTarget.setValue, (1)));
    }

    function test_execute_allowsZeroValueCallsWhenLocked() public {
        (address account,) = _createHighRatePayerK1Account(ACTOR_PK);

        _lockAccount(ACTOR_PK, account, 1 hours);

        vm.prank(account);
        CanonicalHighRatePayerAccount(payable(account))
            .execute(address(target), 0, abi.encodeCall(HighRatePayerMockTarget.setValue, (99)));

        assertEq(target.value(), 99);
    }

    // ── isValidSignature ──

    function test_isValidSignature_validK1() public {
        (address account,) = _createHighRatePayerK1Account(ACTOR_PK);

        bytes32 hash = keccak256("validate me");
        // verifySignature applies the account-scoped EIP-7739 wrap, so sign the replaySafeHash digest.
        bytes memory authData = _buildK1Auth(ACTOR_PK, keystore.replaySafeHash(account, hash));

        bytes4 result = CanonicalHighRatePayerAccount(payable(account)).isValidSignature(hash, authData);
        assertEq(result, bytes4(0x1626ba7e));
    }

    function test_isValidSignature_invalidSignature() public {
        (address account,) = _createHighRatePayerK1Account(ACTOR_PK);

        bytes32 hash = keccak256("validate me");
        bytes memory authData = _buildK1Auth(999, hash);

        bytes4 result = CanonicalHighRatePayerAccount(payable(account)).isValidSignature(hash, authData);
        assertEq(result, bytes4(0xFFFFFFFF));
    }
}
