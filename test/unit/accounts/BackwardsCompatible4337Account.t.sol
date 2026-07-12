// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {DefaultAccount, Call, TRUSTED_EXECUTOR} from "../../../src/accounts/DefaultAccount.sol";
import {
    BackwardsCompatible4337Account,
    PackedUserOperation,
    SignedActorChanges
} from "../../../src/accounts/example/BackwardsCompatible4337Account.sol";
import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract UserOpMockTarget {
    uint256 public value;

    function setValue(uint256 v) external payable {
        value = v;
    }

    function reverting() external pure {
        revert("boom");
    }
}

/// @notice ERC-4337 conformance suite for {BackwardsCompatible4337Account}. The EntryPoint is authorized as a
///         config-driven TRUSTED_EXECUTOR actor (seeded into the initial actor set at creation), so it is revocable
///         and version-agnostic — the single opinionated 4337 model for the repo.
contract BackwardsCompatible4337AccountTest is AccountConfigurationTest {
    uint256 constant ACTOR_PK = 100;

    uint8 constant SCOPE_SIGNER = 0x01;
    uint8 constant SCOPE_SENDER = 0x02;
    uint8 constant SCOPE_PAYER = 0x04;

    bytes32 constant SIGNED_ACTOR_CHANGES_MAGIC = keccak256("ERC4337Account.signedActorChanges.v1");

    UserOpMockTarget public target;
    address public impl;

    function setUp() public virtual override {
        super.setUp();
        target = new UserOpMockTarget();
        impl = address(new BackwardsCompatible4337Account(address(accountConfiguration)));
    }

    /// @dev Create an account from `impl` with `pk` as the unrestricted owner, seeding the EntryPoint as a
    ///      TRUSTED_EXECUTOR actor so it is an authorized caller from the account's first op (the config-driven
    ///      model has no hardcoded EntryPoint). Returns (account, ownerActorId).
    function _create4337Account(uint256 pk) internal returns (address account, bytes32 actorId) {
        actorId = bytes32(bytes20(vm.addr(pk)));
        AccountConfiguration.InitialActor memory owner =
            AccountConfiguration.InitialActor({actorId: actorId, authenticator: address(k1Authenticator)});
        AccountConfiguration.InitialActor memory ep = AccountConfiguration.InitialActor({
            actorId: bytes32(bytes20(ENTRY_POINT)), authenticator: TRUSTED_EXECUTOR
        });

        AccountConfiguration.InitialActor[] memory actors = new AccountConfiguration.InitialActor[](2);
        (actors[0], actors[1]) = owner.actorId < ep.actorId ? (owner, ep) : (ep, owner);
        account = accountConfiguration.createAccount(bytes32(0), _computeERC1167Bytecode(impl), actors);
    }

    // ── Shared helpers ──

    function _singleCall(address t, uint256 v, bytes memory d) internal pure returns (Call[] memory calls) {
        calls = new Call[](1);
        calls[0] = Call(t, v, d);
    }

    function _buildUserOp(address account, bytes memory signature) internal pure returns (PackedUserOperation memory) {
        return _buildUserOp(account, "", signature);
    }

    function _buildUserOp(address account, bytes memory callData, bytes memory signature)
        internal
        pure
        returns (PackedUserOperation memory)
    {
        return PackedUserOperation({
            sender: account,
            nonce: 0,
            initCode: "",
            callData: callData,
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: signature
        });
    }

    function _executeBatchCallData(address t, uint256 v, bytes memory d) internal pure returns (bytes memory) {
        return abi.encodeCall(DefaultAccount.executeBatch, (_singleCall(t, v, d)));
    }

    /// @dev Authorizes a new K1 actor on `account` with the given scope/policy, signed by the unrestricted owner
    ///      (`ownerPk`) via `applySignedActorChanges`. Returns the new actor's id.
    function _authorizeScopedActor(
        address account,
        uint256 ownerPk,
        uint256 newPk,
        uint8 scope,
        uint8 policyType,
        address policyManager,
        bytes32 commitment
    ) internal returns (bytes32 newActorId) {
        newActorId = bytes32(bytes20(vm.addr(newPk)));
        bytes memory policyData = policyType == 0 ? bytes("") : abi.encodePacked(policyManager, commitment);

        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: address(k1Authenticator), scope: scope, expiry: 0, policyType: policyType
                }),
                policyData
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        accountConfiguration.applySignedActorChanges(
            account, uint64(block.chainid), changes, _buildK1Auth(ownerPk, digest)
        );
    }

    function _authorizeK1ActorChange(uint256 newPk)
        internal
        view
        returns (AccountConfiguration.ActorChange[] memory changes, bytes32 newActorId)
    {
        newActorId = bytes32(bytes20(vm.addr(newPk)));
        changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
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
        AccountConfiguration.ActorChange[] memory changes
    ) internal view returns (SignedActorChanges memory) {
        bytes32 changeDigest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        return SignedActorChanges({changes: changes, auth: _buildK1Auth(signerPk, changeDigest)});
    }

    // ── Always-authorized callers ──

    function test_entryPointIsAuthorized() public {
        (address account,) = _create4337Account(ACTOR_PK);
        assertTrue(DefaultAccount(payable(account)).isAuthorizedCaller(ENTRY_POINT));
    }

    function test_selfIsAlwaysAuthorized() public {
        (address account,) = _create4337Account(ACTOR_PK);
        assertTrue(DefaultAccount(payable(account)).isAuthorizedCaller(account));
    }

    function test_unknownCallerNotAuthorized() public {
        (address account,) = _create4337Account(ACTOR_PK);
        assertFalse(DefaultAccount(payable(account)).isAuthorizedCaller(address(0xdead)));
    }

    // ── Trusted-executor actor (relayer / PolicyManager registered via AccountConfiguration) ──

    function test_trustedExecutorActorIsAuthorized() public {
        (address account,) = _create4337Account(ACTOR_PK);
        address relayer = address(0xBEEF);

        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: bytes32(bytes20(relayer)),
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: TRUSTED_EXECUTOR, scope: SCOPE_SENDER, expiry: 0, policyType: 0
                }),
                bytes("")
            )
        });
        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        accountConfiguration.applySignedActorChanges(
            account, uint64(block.chainid), changes, _buildK1Auth(ACTOR_PK, digest)
        );

        assertTrue(DefaultAccount(payable(account)).isAuthorizedCaller(relayer));

        vm.prank(relayer);
        DefaultAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(UserOpMockTarget.setValue, (7))));
        assertEq(target.value(), 7);
    }

    // ── executeBatch from EntryPoint ──

    function test_executeBatch_fromEntryPoint() public {
        (address account,) = _create4337Account(ACTOR_PK);

        vm.prank(ENTRY_POINT);
        DefaultAccount(payable(account))
            .executeBatch(_singleCall(address(target), 0, abi.encodeCall(UserOpMockTarget.setValue, (77))));

        assertEq(target.value(), 77);
    }

    // ── validateUserOp ──

    function test_validateUserOp_validSignature() public {
        (address account,) = _create4337Account(ACTOR_PK);

        bytes32 userOpHash = keccak256("user-op");
        PackedUserOperation memory userOp = _buildUserOp(account, _buildK1Auth(ACTOR_PK, userOpHash));

        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0), 0);
    }

    function test_validateUserOp_invalidSignature() public {
        (address account,) = _create4337Account(ACTOR_PK);

        bytes32 userOpHash = keccak256("user-op");
        PackedUserOperation memory userOp = _buildUserOp(account, _buildK1Auth(999, userOpHash));

        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0), 1);
    }

    function test_validateUserOp_revertsFromUnauthorizedCaller() public {
        (address account,) = _create4337Account(ACTOR_PK);

        bytes32 userOpHash = keccak256("user-op");
        PackedUserOperation memory userOp = _buildUserOp(account, _buildK1Auth(ACTOR_PK, userOpHash));

        vm.prank(address(0xdead));
        vm.expectRevert(DefaultAccount.UnauthorizedCaller.selector);
        BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0);
    }

    function test_validateUserOp_paysPrefund() public {
        (address account,) = _create4337Account(ACTOR_PK);
        vm.deal(account, 1 ether);

        bytes32 userOpHash = keccak256("user-op");
        PackedUserOperation memory userOp = _buildUserOp(account, _buildK1Auth(ACTOR_PK, userOpHash));

        uint256 prefund = 0.1 ether;
        uint256 epBalanceBefore = ENTRY_POINT.balance;

        vm.prank(ENTRY_POINT);
        BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, prefund);

        assertEq(ENTRY_POINT.balance - epBalanceBefore, prefund);
    }

    // ── validateUserOp: validation-phase actor changes ──

    /// @notice A single UserOperation can rotate/add a key during validation; the op is then authenticated as
    ///         usual by `opAuth` — produced here by the brand-new key.
    function test_validateUserOp_appliesSignedActorChanges() public {
        (address account,) = _create4337Account(ACTOR_PK);

        uint256 newPk = 101;
        (AccountConfiguration.ActorChange[] memory changes, bytes32 newActorId) = _authorizeK1ActorChange(newPk);

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        SignedActorChanges[] memory changeSets = new SignedActorChanges[](1);
        changeSets[0] = _signedSet(account, seq, ACTOR_PK, changes);

        bytes32 userOpHash = keccak256("rotate-and-go");
        bytes memory opAuth = _buildK1Auth(newPk, userOpHash);
        bytes memory signature = abi.encode(SIGNED_ACTOR_CHANGES_MAGIC, changeSets, opAuth);
        PackedUserOperation memory userOp = _buildUserOp(account, signature);

        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0), 0);
        assertTrue(accountConfiguration.isActor(account, newActorId));
    }

    /// @notice Multiple independently-signed change sets are applied in order: the owner authorizes key B, then
    ///         key B (now active) authorizes key C, all in one op. The op is then authenticated by C's `opAuth`.
    function test_validateUserOp_appliesMultipleSignedActorChangeSets() public {
        (address account,) = _create4337Account(ACTOR_PK);

        uint256 pkB = 101;
        uint256 pkC = 102;
        (AccountConfiguration.ActorChange[] memory changesB, bytes32 actorB) = _authorizeK1ActorChange(pkB);
        (AccountConfiguration.ActorChange[] memory changesC, bytes32 actorC) = _authorizeK1ActorChange(pkC);

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        SignedActorChanges[] memory changeSets = new SignedActorChanges[](2);
        changeSets[0] = _signedSet(account, seq, ACTOR_PK, changesB); // signed by owner
        changeSets[1] = _signedSet(account, seq + 1, pkB, changesC); // signed by B (active after set 0)

        bytes32 userOpHash = keccak256("chain-of-rotations");
        bytes memory opAuth = _buildK1Auth(pkC, userOpHash); // op signed by C (active after set 1)
        bytes memory signature = abi.encode(SIGNED_ACTOR_CHANGES_MAGIC, changeSets, opAuth);
        PackedUserOperation memory userOp = _buildUserOp(account, signature);

        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0), 0);
        assertTrue(accountConfiguration.isActor(account, actorB));
        assertTrue(accountConfiguration.isActor(account, actorC));
    }

    /// @notice Applying changes does NOT authorize the op: a valid change set with an `opAuth` that does not sign
    ///         this userOpHash fails validation.
    function test_validateUserOp_signedActorChanges_requiresOpAuth() public {
        (address account,) = _create4337Account(ACTOR_PK);

        uint256 newPk = 101;
        (AccountConfiguration.ActorChange[] memory changes,) = _authorizeK1ActorChange(newPk);

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        SignedActorChanges[] memory changeSets = new SignedActorChanges[](1);
        changeSets[0] = _signedSet(account, seq, ACTOR_PK, changes);

        bytes32 userOpHash = keccak256("rotate-but-no-op-auth");
        bytes memory opAuth = _buildK1Auth(999, userOpHash); // unauthorized key
        bytes memory signature = abi.encode(SIGNED_ACTOR_CHANGES_MAGIC, changeSets, opAuth);
        PackedUserOperation memory userOp = _buildUserOp(account, signature);

        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0), 1);
    }

    /// @notice An invalid change authorization fails validation and applies nothing.
    function test_validateUserOp_signedActorChanges_invalidChangeAuthFails() public {
        (address account,) = _create4337Account(ACTOR_PK);

        uint256 newPk = 101;
        (AccountConfiguration.ActorChange[] memory changes, bytes32 newActorId) = _authorizeK1ActorChange(newPk);

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        SignedActorChanges[] memory changeSets = new SignedActorChanges[](1);
        changeSets[0] = _signedSet(account, seq, 999, changes); // signed by a non-owner key

        bytes32 userOpHash = keccak256("op");
        bytes memory opAuth = _buildK1Auth(ACTOR_PK, userOpHash);
        bytes memory signature = abi.encode(SIGNED_ACTOR_CHANGES_MAGIC, changeSets, opAuth);
        PackedUserOperation memory userOp = _buildUserOp(account, signature);

        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0), 1);
        assertFalse(accountConfiguration.isActor(account, newActorId));
    }

    /// @notice An empty change-set batch is rejected (it must not authorize any op).
    function test_validateUserOp_signedActorChanges_emptyBatchFails() public {
        (address account,) = _create4337Account(ACTOR_PK);

        SignedActorChanges[] memory changeSets = new SignedActorChanges[](0);
        bytes32 userOpHash = keccak256("op");
        bytes memory opAuth = _buildK1Auth(ACTOR_PK, userOpHash);
        bytes memory signature = abi.encode(SIGNED_ACTOR_CHANGES_MAGIC, changeSets, opAuth);
        PackedUserOperation memory userOp = _buildUserOp(account, signature);

        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0), 1);
    }

    // ── SIGNER scope (ERC-1271) ──

    function test_isValidSignature_requiresSignerScope() public {
        (address account,) = _create4337Account(ACTOR_PK);
        uint256 senderOnlyPk = 201;
        _authorizeScopedActor(account, ACTOR_PK, senderOnlyPk, SCOPE_SENDER, 0, address(0), bytes32(0));

        bytes32 hash = keccak256("sign me");
        bytes memory authData = _buildK1Auth(senderOnlyPk, hash);

        // A SENDER-only actor lacks SIGNER scope, so ERC-1271 validation must fail.
        assertEq(DefaultAccount(payable(account)).isValidSignature(hash, authData), bytes4(0xFFFFFFFF));
    }

    function test_isValidSignature_signerScopeSucceeds() public {
        (address account,) = _create4337Account(ACTOR_PK);
        uint256 signerPk = 202;
        _authorizeScopedActor(account, ACTOR_PK, signerPk, SCOPE_SIGNER, 0, address(0), bytes32(0));

        bytes32 hash = keccak256("sign me");
        bytes memory authData = _buildK1Auth(signerPk, hash);

        assertEq(DefaultAccount(payable(account)).isValidSignature(hash, authData), bytes4(0x1626ba7e));
    }

    // ── SENDER scope (validateUserOp) ──

    function test_validateUserOp_senderScopeAuthorizes() public {
        (address account,) = _create4337Account(ACTOR_PK);
        uint256 senderPk = 203;
        _authorizeScopedActor(account, ACTOR_PK, senderPk, SCOPE_SENDER, 0, address(0), bytes32(0));

        bytes32 userOpHash = keccak256("op");
        PackedUserOperation memory userOp = _buildUserOp(account, _buildK1Auth(senderPk, userOpHash));

        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0), 0);
    }

    function test_validateUserOp_requiresSenderScope() public {
        (address account,) = _create4337Account(ACTOR_PK);
        uint256 signerOnlyPk = 204;
        _authorizeScopedActor(account, ACTOR_PK, signerOnlyPk, SCOPE_SIGNER, 0, address(0), bytes32(0));

        bytes32 userOpHash = keccak256("op");
        PackedUserOperation memory userOp = _buildUserOp(account, _buildK1Auth(signerOnlyPk, userOpHash));

        // A SIGNER-only actor cannot initiate transactions: no SENDER scope.
        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0), 1);
    }

    // ── PAYER scope (self-funded ops) ──

    function test_validateUserOp_selfFundedRequiresPayerScope() public {
        (address account,) = _create4337Account(ACTOR_PK);
        vm.deal(account, 1 ether);
        uint256 senderOnlyPk = 205;
        _authorizeScopedActor(account, ACTOR_PK, senderOnlyPk, SCOPE_SENDER, 0, address(0), bytes32(0));

        bytes32 userOpHash = keccak256("op");
        PackedUserOperation memory userOp = _buildUserOp(account, _buildK1Auth(senderOnlyPk, userOpHash));

        // SENDER but not PAYER: cannot authorize spending the account's funds on gas.
        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0.1 ether), 1);
    }

    function test_validateUserOp_senderPayerScope_selfFundedSucceeds() public {
        (address account,) = _create4337Account(ACTOR_PK);
        vm.deal(account, 1 ether);
        uint256 pk = 206;
        _authorizeScopedActor(account, ACTOR_PK, pk, SCOPE_SENDER | SCOPE_PAYER, 0, address(0), bytes32(0));

        bytes32 userOpHash = keccak256("op");
        PackedUserOperation memory userOp = _buildUserOp(account, _buildK1Auth(pk, userOpHash));

        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0.1 ether), 0);
    }

    // ── Policy gating (calls confined to policy target) ──

    function test_validateUserOp_policyGated_allowsCallsToPolicyTarget() public {
        (address account,) = _create4337Account(ACTOR_PK);
        address policyManager = address(0xB0B);
        uint256 pk = 207;
        _authorizeScopedActor(account, ACTOR_PK, pk, SCOPE_SENDER, 0x01, policyManager, keccak256("commit"));

        bytes memory callData = _executeBatchCallData(policyManager, 0, abi.encodeCall(UserOpMockTarget.setValue, (1)));
        bytes32 userOpHash = keccak256(abi.encode("op", callData));
        PackedUserOperation memory userOp = _buildUserOp(account, callData, _buildK1Auth(pk, userOpHash));

        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0), 0);
    }

    function test_validateUserOp_policyGated_rejectsCallsToOtherTarget() public {
        (address account,) = _create4337Account(ACTOR_PK);
        address policyManager = address(0xB0B);
        uint256 pk = 208;
        _authorizeScopedActor(account, ACTOR_PK, pk, SCOPE_SENDER, 0x01, policyManager, keccak256("commit"));

        // Call targets the MockTarget directly, escaping the actor's policy gate.
        bytes memory callData =
            _executeBatchCallData(address(target), 0, abi.encodeCall(UserOpMockTarget.setValue, (1)));
        bytes32 userOpHash = keccak256(abi.encode("op", callData));
        PackedUserOperation memory userOp = _buildUserOp(account, callData, _buildK1Auth(pk, userOpHash));

        vm.prank(ENTRY_POINT);
        assertEq(BackwardsCompatible4337Account(payable(account)).validateUserOp(userOp, userOpHash, 0), 1);
    }
}
