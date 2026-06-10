// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {
    ERC4337Account,
    Call,
    PackedUserOperation,
    SignedActorChanges
} from "../../../src/accounts/BackwardCompatibleERC4337Account.sol";
import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {IAccountConfiguration} from "../../../src/interfaces/IAccountConfiguration.sol";
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

contract ERC4337AccountTest is AccountConfigurationTest {
    uint256 constant ACTOR_PK = 100;
    address constant ENTRY_POINT = address(0xEEEE);
    MockTarget public target;
    address public erc4337Implementation;

    function setUp() public override {
        super.setUp();
        target = new MockTarget();
        erc4337Implementation = address(new ERC4337Account(address(accountConfiguration), ENTRY_POINT));
    }

    function _create4337Account(uint256 pk) internal returns (address account, bytes32 actorId) {
        address signer = vm.addr(pk);
        actorId = bytes32(bytes20(signer));

        IAccountConfiguration.InitialActor[] memory actors = new IAccountConfiguration.InitialActor[](1);
        actors[0] = IAccountConfiguration.InitialActor({actorId: actorId, authenticator: address(k1Authenticator)});

        bytes memory bytecode = _computeERC1167Bytecode(erc4337Implementation);
        account = accountConfiguration.createAccount(bytes32(0), bytecode, actors);
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
        (address account,) = _create4337Account(ACTOR_PK);
        assertTrue(ERC4337Account(payable(account)).isAuthorizedCaller(ENTRY_POINT));
    }

    function test_selfIsAlwaysAuthorized() public {
        (address account,) = _create4337Account(ACTOR_PK);
        assertTrue(ERC4337Account(payable(account)).isAuthorizedCaller(account));
    }

    // ── Caller management ──

    function test_authorizeCaller_success() public {
        (address account,) = _create4337Account(ACTOR_PK);
        address policyManager = address(0xBBBB);

        vm.prank(account);
        ERC4337Account(payable(account)).authorizeCaller(policyManager);

        assertTrue(ERC4337Account(payable(account)).isAuthorizedCaller(policyManager));
    }

    function test_authorizeCaller_revertsFromNonSelf() public {
        (address account,) = _create4337Account(ACTOR_PK);

        vm.prank(address(0xdead));
        vm.expectRevert();
        ERC4337Account(payable(account)).authorizeCaller(address(0xBBBB));
    }

    function test_revokeCaller_success() public {
        (address account,) = _create4337Account(ACTOR_PK);
        address policyManager = address(0xBBBB);

        vm.prank(account);
        ERC4337Account(payable(account)).authorizeCaller(policyManager);

        vm.prank(account);
        ERC4337Account(payable(account)).revokeCaller(policyManager);

        assertFalse(ERC4337Account(payable(account)).isAuthorizedCaller(policyManager));
    }

    // ── executeBatch ──

    function test_executeBatch_success() public {
        (address account,) = _create4337Account(ACTOR_PK);

        vm.prank(account);
        ERC4337Account(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.setValue, (42))));

        assertEq(target.value(), 42);
    }

    function test_executeBatch_withETHValue() public {
        (address account,) = _create4337Account(ACTOR_PK);
        vm.deal(account, 1 ether);

        vm.prank(account);
        ERC4337Account(payable(account))
            .executeBatch(_singleCall(address(target), 0.5 ether, abi.encodeCall(MockTarget.setValue, (1))));

        assertEq(address(target).balance, 0.5 ether);
    }

    function test_executeBatch_fromEntryPoint() public {
        (address account,) = _create4337Account(ACTOR_PK);

        vm.prank(ENTRY_POINT);
        ERC4337Account(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.setValue, (77))));

        assertEq(target.value(), 77);
    }

    function test_executeBatch_revertsFromUnauthorizedCaller() public {
        (address account,) = _create4337Account(ACTOR_PK);

        vm.prank(address(0xdead));
        vm.expectRevert();
        ERC4337Account(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.setValue, (1))));
    }

    function test_executeBatch_revertsOnFailedCall() public {
        (address account,) = _create4337Account(ACTOR_PK);

        vm.prank(account);
        vm.expectRevert();
        ERC4337Account(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(MockTarget.reverting, ())));
    }

    // ── validateUserOp ──

    function test_validateUserOp_validSignature() public {
        (address account,) = _create4337Account(ACTOR_PK);

        bytes32 userOpHash = keccak256("user-op");
        bytes memory authData = _buildK1Auth(ACTOR_PK, userOpHash);

        PackedUserOperation memory userOp = _buildUserOp(account, authData);

        vm.prank(ENTRY_POINT);
        uint256 validationData = ERC4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0);

        assertEq(validationData, 0);
    }

    function test_validateUserOp_invalidSignature() public {
        (address account,) = _create4337Account(ACTOR_PK);

        bytes32 userOpHash = keccak256("user-op");
        bytes memory authData = _buildK1Auth(999, userOpHash);

        PackedUserOperation memory userOp = _buildUserOp(account, authData);

        vm.prank(ENTRY_POINT);
        uint256 validationData = ERC4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0);

        assertEq(validationData, 1);
    }

    function test_validateUserOp_revertsFromUnauthorizedCaller() public {
        (address account,) = _create4337Account(ACTOR_PK);

        bytes32 userOpHash = keccak256("user-op");
        bytes memory authData = _buildK1Auth(ACTOR_PK, userOpHash);

        PackedUserOperation memory userOp = _buildUserOp(account, authData);

        vm.prank(address(0xdead));
        vm.expectRevert();
        ERC4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0);
    }

    function test_validateUserOp_paysPrefund() public {
        (address account,) = _create4337Account(ACTOR_PK);
        vm.deal(account, 1 ether);

        bytes32 userOpHash = keccak256("user-op");
        bytes memory authData = _buildK1Auth(ACTOR_PK, userOpHash);

        PackedUserOperation memory userOp = _buildUserOp(account, authData);

        uint256 prefund = 0.1 ether;
        uint256 epBalanceBefore = ENTRY_POINT.balance;

        vm.prank(ENTRY_POINT);
        ERC4337Account(payable(account)).validateUserOp(userOp, userOpHash, prefund);

        assertEq(ENTRY_POINT.balance - epBalanceBefore, prefund);
    }

    // ── validateUserOp: validation-phase actor changes ──

    bytes32 constant SIGNED_ACTOR_CHANGES_MAGIC = keccak256("ERC4337Account.signedActorChanges.v1");

    function _authorizeK1ActorChange(uint256 newPk)
        internal
        view
        returns (IAccountConfiguration.ActorChange[] memory changes, bytes32 newActorId)
    {
        newActorId = bytes32(bytes20(vm.addr(newPk)));
        changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({
                    authenticator: address(k1Authenticator), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });
    }

    function _signedSet(
        address account,
        uint64 seq,
        uint256 signerPk,
        IAccountConfiguration.ActorChange[] memory changes
    ) internal view returns (SignedActorChanges memory) {
        bytes32 changeDigest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        return SignedActorChanges({changes: changes, auth: _buildK1Auth(signerPk, changeDigest)});
    }

    /// @notice A single UserOperation can rotate/add a key during validation and be
    ///         authenticated by that brand-new key.
    function test_validateUserOp_appliesSignedActorChanges() public {
        (address account,) = _create4337Account(ACTOR_PK);

        uint256 newPk = 101;
        (IAccountConfiguration.ActorChange[] memory changes, bytes32 newActorId) = _authorizeK1ActorChange(newPk);

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        SignedActorChanges[] memory changeSets = new SignedActorChanges[](1);
        changeSets[0] = _signedSet(account, seq, ACTOR_PK, changes);

        // Authenticate the op with the *new* actor — proving it is usable within the
        // same op it was added in.
        bytes32 userOpHash = keccak256("rotate-and-go");
        bytes memory opAuth = _buildK1Auth(newPk, userOpHash);

        bytes memory signature = abi.encode(SIGNED_ACTOR_CHANGES_MAGIC, changeSets, opAuth);
        PackedUserOperation memory userOp = _buildUserOp(account, signature);

        vm.prank(ENTRY_POINT);
        uint256 validationData = ERC4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0);

        assertEq(validationData, 0);
        assertTrue(accountConfiguration.isActor(account, newActorId));
    }

    /// @notice Multiple independently-signed change sets are applied in order: the
    ///         owner authorizes key B, then key B (now active) authorizes key C, all in
    ///         one op authenticated by key C.
    function test_validateUserOp_appliesMultipleSignedActorChangeSets() public {
        (address account,) = _create4337Account(ACTOR_PK);

        uint256 pkB = 101;
        uint256 pkC = 102;
        (IAccountConfiguration.ActorChange[] memory changesB, bytes32 actorB) = _authorizeK1ActorChange(pkB);
        (IAccountConfiguration.ActorChange[] memory changesC, bytes32 actorC) = _authorizeK1ActorChange(pkC);

        // Sequences increment per applied set.
        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        SignedActorChanges[] memory changeSets = new SignedActorChanges[](2);
        changeSets[0] = _signedSet(account, seq, ACTOR_PK, changesB); // signed by owner
        changeSets[1] = _signedSet(account, seq + 1, pkB, changesC); // signed by B (active after set 0)

        bytes32 userOpHash = keccak256("chain-of-rotations");
        bytes memory opAuth = _buildK1Auth(pkC, userOpHash);

        bytes memory signature = abi.encode(SIGNED_ACTOR_CHANGES_MAGIC, changeSets, opAuth);
        PackedUserOperation memory userOp = _buildUserOp(account, signature);

        vm.prank(ENTRY_POINT);
        uint256 validationData = ERC4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0);

        assertEq(validationData, 0);
        assertTrue(accountConfiguration.isActor(account, actorB));
        assertTrue(accountConfiguration.isActor(account, actorC));
    }

    /// @notice An invalid change authorization fails validation and applies nothing.
    function test_validateUserOp_signedActorChanges_invalidChangeAuthFails() public {
        (address account,) = _create4337Account(ACTOR_PK);

        uint256 newPk = 101;
        (IAccountConfiguration.ActorChange[] memory changes, bytes32 newActorId) = _authorizeK1ActorChange(newPk);

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        SignedActorChanges[] memory changeSets = new SignedActorChanges[](1);
        // Signed by a non-owner key → change auth is invalid.
        changeSets[0] = _signedSet(account, seq, 999, changes);

        bytes32 userOpHash = keccak256("op");
        bytes memory opAuth = _buildK1Auth(ACTOR_PK, userOpHash);

        bytes memory signature = abi.encode(SIGNED_ACTOR_CHANGES_MAGIC, changeSets, opAuth);
        PackedUserOperation memory userOp = _buildUserOp(account, signature);

        vm.prank(ENTRY_POINT);
        uint256 validationData = ERC4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0);

        assertEq(validationData, 1);
        assertFalse(accountConfiguration.isActor(account, newActorId));
    }

    // ── isValidSignature ──

    function test_isValidSignature_validK1() public {
        (address account,) = _create4337Account(ACTOR_PK);

        bytes32 hash = keccak256("validate me");
        bytes memory authData = _buildK1Auth(ACTOR_PK, hash);

        bytes4 result = ERC4337Account(payable(account)).isValidSignature(hash, authData);
        assertEq(result, bytes4(0x1626ba7e));
    }

    function test_isValidSignature_invalidSignature() public {
        (address account,) = _create4337Account(ACTOR_PK);

        bytes32 hash = keccak256("validate me");
        bytes memory authData = _buildK1Auth(999, hash);

        bytes4 result = ERC4337Account(payable(account)).isValidSignature(hash, authData);
        assertEq(result, bytes4(0xFFFFFFFF));
    }
}
