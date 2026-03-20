// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ERC4337Account, Call, PackedUserOperation} from "../../../src/accounts/BackwardCompatibleERC4337Account.sol";
import {InitialOwner} from "../../../src/AccountDeployer.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";
import {IVerifier} from "../../../src/verifiers/IVerifier.sol";

contract MockTarget {
    uint256 public value;

    function setValue(uint256 v) external payable {
        value = v;
    }

    function reverting() external pure {
        revert("boom");
    }
}

contract ERC4337AccountTest is AccountConfigurationTest {
    uint256 constant OWNER_PK = 100;
    address constant ENTRY_POINT = address(0xEEEE);
    MockTarget public target;
    address public erc4337Implementation;

    function setUp() public override {
        super.setUp();
        target = new MockTarget();
        erc4337Implementation = address(new ERC4337Account(address(accountConfiguration), ENTRY_POINT));
    }

    function _create4337Account(uint256 pk) internal returns (address account, bytes32 ownerId) {
        address signer = vm.addr(pk);
        ownerId = bytes32(bytes20(signer));

        InitialOwner[] memory owners = new InitialOwner[](1);
        owners[0] = InitialOwner({verifier: address(k1Verifier), ownerId: ownerId, scope: 0x00});

        bytes memory bytecode = _computeERC1167Bytecode(erc4337Implementation);
        account = accountConfiguration.createAccount(bytes32(0), bytecode, owners);
    }

    function _singleCall(address t, uint256 v, bytes memory d) internal pure returns (Call[] memory calls) {
        calls = new Call[](1);
        calls[0] = Call(t, v, d);
    }

    function _buildUserOp(address account, bytes memory signature) internal pure returns (PackedUserOperation memory) {
        return PackedUserOperation({
            sender: account,
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: signature
        });
    }

    // ── EntryPoint is always authorized ──

    function test_entryPointIsAlwaysAuthorized() public {
        (address account,) = _create4337Account(OWNER_PK);
        assertTrue(ERC4337Account(payable(account)).isAuthorizedCaller(ENTRY_POINT));
    }

    function test_selfIsAlwaysAuthorized() public {
        (address account,) = _create4337Account(OWNER_PK);
        assertTrue(ERC4337Account(payable(account)).isAuthorizedCaller(account));
    }

    // ── Caller management ──

    function test_authorizeCaller_success() public {
        (address account,) = _create4337Account(OWNER_PK);
        address policyManager = address(0xBBBB);

        vm.prank(account);
        ERC4337Account(payable(account)).authorizeCaller(policyManager);

        assertTrue(ERC4337Account(payable(account)).isAuthorizedCaller(policyManager));
    }

    function test_authorizeCaller_revertsFromNonSelf() public {
        (address account,) = _create4337Account(OWNER_PK);

        vm.prank(address(0xdead));
        vm.expectRevert();
        ERC4337Account(payable(account)).authorizeCaller(address(0xBBBB));
    }

    function test_revokeCaller_success() public {
        (address account,) = _create4337Account(OWNER_PK);
        address policyManager = address(0xBBBB);

        vm.prank(account);
        ERC4337Account(payable(account)).authorizeCaller(policyManager);

        vm.prank(account);
        ERC4337Account(payable(account)).revokeCaller(policyManager);

        assertFalse(ERC4337Account(payable(account)).isAuthorizedCaller(policyManager));
    }

    // ── executeBatch ──

    function test_executeBatch_success() public {
        (address account,) = _create4337Account(OWNER_PK);

        vm.prank(account);
        ERC4337Account(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.setValue, (42))));

        assertEq(target.value(), 42);
    }

    function test_executeBatch_withETHValue() public {
        (address account,) = _create4337Account(OWNER_PK);
        vm.deal(account, 1 ether);

        vm.prank(account);
        ERC4337Account(payable(account))
            .executeBatch(_singleCall(address(target), 0.5 ether, abi.encodeCall(MockTarget.setValue, (1))));

        assertEq(address(target).balance, 0.5 ether);
    }

    function test_executeBatch_fromEntryPoint() public {
        (address account,) = _create4337Account(OWNER_PK);

        vm.prank(ENTRY_POINT);
        ERC4337Account(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.setValue, (77))));

        assertEq(target.value(), 77);
    }

    function test_executeBatch_revertsFromUnauthorizedCaller() public {
        (address account,) = _create4337Account(OWNER_PK);

        vm.prank(address(0xdead));
        vm.expectRevert();
        ERC4337Account(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.setValue, (1))));
    }

    function test_executeBatch_revertsOnFailedCall() public {
        (address account,) = _create4337Account(OWNER_PK);

        vm.prank(account);
        vm.expectRevert();
        ERC4337Account(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.reverting, ())));
    }

    // ── validateUserOp ──

    function test_validateUserOp_validSignature() public {
        (address account,) = _create4337Account(OWNER_PK);

        bytes32 userOpHash = keccak256("user-op");
        bytes memory sig = _signDigest(OWNER_PK, userOpHash);
        bytes memory authData = abi.encodePacked(uint8(0x01), sig);

        PackedUserOperation memory userOp = _buildUserOp(account, authData);

        vm.prank(ENTRY_POINT);
        uint256 validationData = ERC4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0);

        assertEq(validationData, 0);
    }

    function test_validateUserOp_invalidSignature() public {
        (address account,) = _create4337Account(OWNER_PK);

        bytes32 userOpHash = keccak256("user-op");
        bytes memory wrongSig = _signDigest(999, userOpHash);
        bytes memory authData = abi.encodePacked(uint8(0x01), wrongSig);

        PackedUserOperation memory userOp = _buildUserOp(account, authData);

        vm.prank(ENTRY_POINT);
        uint256 validationData = ERC4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0);

        assertEq(validationData, 1);
    }

    function test_validateUserOp_revertsFromUnauthorizedCaller() public {
        (address account,) = _create4337Account(OWNER_PK);

        bytes32 userOpHash = keccak256("user-op");
        bytes memory sig = _signDigest(OWNER_PK, userOpHash);
        bytes memory authData = abi.encodePacked(uint8(0x01), sig);

        PackedUserOperation memory userOp = _buildUserOp(account, authData);

        vm.prank(address(0xdead));
        vm.expectRevert();
        ERC4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0);
    }

    function test_validateUserOp_paysPrefund() public {
        (address account,) = _create4337Account(OWNER_PK);
        vm.deal(account, 1 ether);

        bytes32 userOpHash = keccak256("user-op");
        bytes memory sig = _signDigest(OWNER_PK, userOpHash);
        bytes memory authData = abi.encodePacked(uint8(0x01), sig);

        PackedUserOperation memory userOp = _buildUserOp(account, authData);

        uint256 prefund = 0.1 ether;
        uint256 epBalanceBefore = ENTRY_POINT.balance;

        vm.prank(ENTRY_POINT);
        ERC4337Account(payable(account)).validateUserOp(userOp, userOpHash, prefund);

        assertEq(ENTRY_POINT.balance - epBalanceBefore, prefund);
    }

    // ── isValidSignature ──

    function test_isValidSignature_validK1() public {
        (address account,) = _create4337Account(OWNER_PK);

        bytes32 hash = keccak256("validate me");
        bytes memory sig = _signDigest(OWNER_PK, hash);
        bytes memory authData = abi.encodePacked(uint8(0x01), sig);

        bytes4 result = ERC4337Account(payable(account)).isValidSignature(hash, authData);
        assertEq(result, bytes4(0x1626ba7e));
    }

    function test_isValidSignature_invalidSignature() public {
        (address account,) = _create4337Account(OWNER_PK);

        bytes32 hash = keccak256("validate me");
        bytes memory wrongSig = _signDigest(999, hash);
        bytes memory authData = abi.encodePacked(uint8(0x01), wrongSig);

        bytes4 result = ERC4337Account(payable(account)).isValidSignature(hash, authData);
        assertEq(result, bytes4(0xFFFFFFFF));
    }
}
