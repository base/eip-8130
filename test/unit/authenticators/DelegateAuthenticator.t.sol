// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore} from "../../../src/Keystore.sol";
import {DelegateAuthenticator} from "../../../src/authenticators/DelegateAuthenticator.sol";
import {DefaultAccount} from "../../../src/accounts/DefaultAccount.sol";
import {ActorId} from "../../../src/libraries/ActorId.sol";
import {Scopes} from "../../../src/libraries/Scopes.sol";
import {KeystoreTest} from "../../lib/KeystoreTest.sol";

/// @notice Fuzzed, branch-complete test suite for DelegateAuthenticator.authenticate.
///
///         Source data layout: delegate_address(20) ‖ nested_authenticator(20) ‖ nested_data.
///         Guards, in source-execution order, each reverting with a custom error:
///           1. InvalidDataLength       — data.length < 40
///           2. RecursiveDelegation     — nestedAuthenticator == address(this) (blocks 1-hop recursion)
///           3. InvalidNestedSignature  — the nested auth does not validate on `delegate`, or validates to an actor
///                                        that is neither admin nor operator
///         On success the returned actorId encodes the nested signer's CLASS on the delegate account:
///           - admin (scope 0x00)              → ActorId.fromAddress(delegate)
///           - operator (Scopes.isOperator)    → ActorId.operatorOfAddress(delegate)
///         The registering account picks the class it trusts by which actorId it authorizes; the class is decided
///         by the nested signer's stored scope, never by anything the signer declares.
contract DelegateAuthenticatorTest is KeystoreTest {
    uint16 constant SCOPE_OPERATOR = Scopes.OPERATOR;
    uint16 constant SCOPE_POLICY = Scopes.POLICY;
    uint16 constant SCOPE_NONCE = Scopes.NONCE;
    uint16 constant SCOPE_SELF_PAYER = Scopes.SELF_PAYER;
    uint16 constant SCOPE_SPONSOR_PAYER = Scopes.SPONSOR_PAYER;

    // ── Guard 1: require(data.length >= 40) ──

    /// @dev Any data shorter than 40 bytes reverts before the delegate/nested slices are read.
    ///      Fuzzes the full [0,39] length range (including the 39-byte boundary) and the byte content.
    function test_authenticate_revert_dataTooShort(bytes32 hash, uint256 lenSeed, uint256 fillSeed) public {
        uint256 len = bound(lenSeed, 0, 39);
        bytes memory data = new bytes(len);
        for (uint256 i; i < len; i++) {
            data[i] = bytes1(uint8(uint256(keccak256(abi.encode(fillSeed, i)))));
        }

        vm.expectRevert(DelegateAuthenticator.InvalidDataLength.selector);
        delegateAuthenticator.authenticate(hash, data);
    }

    // ── Guard 2: require(nestedAuthenticator != address(this)) — 1-hop recursion block ──

    /// @dev A nested authenticator equal to the DelegateAuthenticator itself is rejected regardless of
    ///      delegate address or trailing nested data (data is >= 40 bytes so guard 1 passes first).
    function test_authenticate_revert_selfNestedAuthenticator(address delegate, bytes32 hash, bytes calldata tail)
        public
    {
        address self = address(delegateAuthenticator);
        bytes memory data = abi.encodePacked(delegate, self, tail);
        assertGe(data.length, 40);

        vm.expectRevert(DelegateAuthenticator.RecursiveDelegation.selector);
        delegateAuthenticator.authenticate(hash, data);
    }

    // ── Guard 3: nested actor must be admin or operator on `delegate` (authenticateActor + class check) ──

    /// @dev A well-formed k1 nested auth whose recovered signer is not an actor on the delegate account
    ///      makes authenticateActor revert (caught) so the delegate vouch reverts InvalidNestedSignature.
    function test_authenticate_revert_invalidNestedSignature(uint256 ownerSeed, uint256 wrongSeed, bytes32 hash)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 wrongPk = _boundK1Pk(wrongSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(wrongPk));

        (address delegateAccount,) = _createK1Account(ownerPk);

        // Signature by a key that is not authorized on the delegate account.
        bytes memory nestedAuth = abi.encodePacked(k1Authenticator, _signDigest(wrongPk, hash));
        bytes memory data = abi.encodePacked(delegateAccount, nestedAuth);

        vm.expectRevert(DelegateAuthenticator.InvalidNestedSignature.selector);
        delegateAuthenticator.authenticate(hash, data);
    }

    /// @dev The nested signature is valid for account A's owner, but the delegate passed is account B, where
    ///      that signer is not an actor. Confirms the delegate address scopes verification: authenticateActor
    ///      reverts (caught) and guard 3 reverts InvalidNestedSignature.
    function test_authenticate_revert_delegateMismatch(uint256 ownerASeed, uint256 ownerBSeed, bytes32 hash) public {
        uint256 ownerAPk = _boundK1Pk(ownerASeed);
        uint256 ownerBPk = _boundK1Pk(ownerBSeed);
        vm.assume(vm.addr(ownerAPk) != vm.addr(ownerBPk));

        (address accountA,) = _createK1AccountWithSalt(ownerAPk, bytes32(uint256(1)));
        (address accountB,) = _createK1AccountWithSalt(ownerBPk, bytes32(uint256(2)));
        vm.assume(accountA != accountB);

        // Valid owner-A signature, but delegate = account B (owner A is not an actor on B).
        bytes memory nestedAuth = abi.encodePacked(k1Authenticator, _signDigest(ownerAPk, hash));
        bytes memory data = abi.encodePacked(accountB, nestedAuth);

        vm.expectRevert(DelegateAuthenticator.InvalidNestedSignature.selector);
        delegateAuthenticator.authenticate(hash, data);
    }

    /// @dev A nested signer that is a live actor on the delegate account but holds a non-zero scope WITHOUT the
    ///      OPERATOR bit (payer-only, NONCE-only, ...) is neither admin nor operator, so the vouch reverts.
    function test_authenticate_revert_nestedSignerNotOperational(
        uint256 ownerSeed,
        uint256 signerSeed,
        uint8 scopeSeed,
        bytes32 hash
    ) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 signerPk = _boundK1Pk(signerSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(signerPk));

        // Non-zero, no OPERATOR, no POLICY (so no policyData is needed at authorization time).
        uint16 scope = uint16(bound(uint256(scopeSeed), 1, 255)) & ~SCOPE_POLICY & ~SCOPE_OPERATOR;
        vm.assume(scope != 0);

        (address delegateAccount,) = _createK1Account(ownerPk);
        _authorizeScopedK1Actor(delegateAccount, ownerPk, signerPk, scope);

        bytes memory nestedAuth = abi.encodePacked(k1Authenticator, _signDigest(signerPk, hash));
        bytes memory data = abi.encodePacked(delegateAccount, nestedAuth);

        vm.expectRevert(DelegateAuthenticator.InvalidNestedSignature.selector);
        delegateAuthenticator.authenticate(hash, data);
    }

    /// @dev An OPERATOR nested actor on the delegate account CAN satisfy the account's ERC-1271 (it is operational)
    ///      and CAN vouch — but only as the OPERATOR class: the returned actorId is operatorOfAddress(delegate), never
    ///      the admin-class fromAddress(delegate). An account that registered only the admin-class id therefore does
    ///      not accept it (Keystore's actorId binding fails on the unregistered id).
    function test_authenticate_success_operatorResolvesToOperatorClass(
        uint256 ownerSeed,
        uint256 signerSeed,
        bytes32 hash
    ) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 signerPk = _boundK1Pk(signerSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(signerPk));

        (address delegateAccount,) = _createK1Account(ownerPk);
        vm.assume(vm.addr(signerPk) != delegateAccount);
        _authorizeScopedK1Actor(delegateAccount, ownerPk, signerPk, SCOPE_OPERATOR);

        bytes memory nestedAuth = abi.encodePacked(k1Authenticator, _signDigest(signerPk, hash));

        bytes memory wrappedAuth =
            _wrapLocal(_buildK1Auth(signerPk, keystore.replaySafeHash(delegateAccount, block.chainid, hash)));
        assertEq(DefaultAccount(payable(delegateAccount)).isValidSignature(hash, wrappedAuth), bytes4(0x1626ba7e));

        bytes memory data = abi.encodePacked(delegateAccount, nestedAuth);
        bytes32 actorId = delegateAuthenticator.authenticate(hash, data);
        assertEq(actorId, ActorId.operatorOfAddress(delegateAccount));
        assertTrue(actorId != ActorId.fromAddress(delegateAccount));
    }

    /// @dev OPERATOR combined with other grants (payer bits, NONCE) is still the operator class.
    function test_authenticate_success_operatorWithExtraBitsIsOperatorClass(
        uint256 ownerSeed,
        uint256 signerSeed,
        uint8 extraSeed,
        bytes32 hash
    ) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 signerPk = _boundK1Pk(signerSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(signerPk));
        uint16 scope = SCOPE_OPERATOR | (uint16(extraSeed) & ~SCOPE_POLICY);

        (address delegateAccount,) = _createK1Account(ownerPk);
        _authorizeScopedK1Actor(delegateAccount, ownerPk, signerPk, scope);

        bytes memory data =
            abi.encodePacked(delegateAccount, abi.encodePacked(k1Authenticator, _signDigest(signerPk, hash)));
        assertEq(delegateAuthenticator.authenticate(hash, data), ActorId.operatorOfAddress(delegateAccount));
    }

    /// @dev End to end through Keystore: account A registers ONLY the admin-class delegate id for B. B's operator
    ///      vouches → operator-class id → A has no such actor → AuthenticatorMismatch. Registering the operator-class
    ///      id on A makes the same signature authenticate with the scope A chose for it.
    function test_authenticate_success_registeringAccountChoosesClass(
        uint256 ownerASeed,
        uint256 ownerBSeed,
        uint256 opBSeed,
        bytes32 hash
    ) public {
        uint256 ownerAPk = _boundK1Pk(ownerASeed);
        uint256 ownerBPk = _boundK1Pk(ownerBSeed);
        uint256 opBPk = _boundK1Pk(opBSeed);
        vm.assume(vm.addr(ownerAPk) != vm.addr(ownerBPk) && vm.addr(ownerBPk) != vm.addr(opBPk));
        vm.assume(vm.addr(ownerAPk) != vm.addr(opBPk));

        (address accountA,) = _createK1AccountWithSalt(ownerAPk, bytes32(uint256(1)));
        (address accountB,) = _createK1AccountWithSalt(ownerBPk, bytes32(uint256(2)));
        vm.assume(accountA != accountB && vm.addr(opBPk) != accountB);
        _authorizeScopedK1Actor(accountB, ownerBPk, opBPk, SCOPE_OPERATOR);

        // A trusts B's ADMIN class only.
        _authorizeActorWithScope(accountA, ownerAPk, ActorId.fromAddress(accountB), address(delegateAuthenticator), 0);

        bytes memory opAuth = abi.encodePacked(
            address(delegateAuthenticator), accountB, abi.encodePacked(k1Authenticator, _signDigest(opBPk, hash))
        );
        vm.expectRevert(Keystore.AuthenticatorMismatch.selector);
        keystore.authenticateActor(accountA, hash, opAuth);

        // B's admin still authenticates as the admin-class actor on A.
        bytes memory adminAuth = abi.encodePacked(
            address(delegateAuthenticator), accountB, abi.encodePacked(k1Authenticator, _signDigest(ownerBPk, hash))
        );
        (bytes32 gotId, uint16 gotScope) = keystore.authenticateActor(accountA, hash, adminAuth);
        assertEq(gotId, ActorId.fromAddress(accountB));
        assertEq(gotScope, 0);

        // Now A also trusts B's OPERATOR class, as an OPERATOR on A.
        _authorizeActorWithScope(
            accountA, ownerAPk, ActorId.operatorOfAddress(accountB), address(delegateAuthenticator), SCOPE_OPERATOR
        );
        (gotId, gotScope) = keystore.authenticateActor(accountA, hash, opAuth);
        assertEq(gotId, ActorId.operatorOfAddress(accountB));
        assertEq(gotScope, SCOPE_OPERATOR);
    }

    // ── Happy paths ──

    /// @dev An unrestricted (scope 0x00) initial owner is admin, so the delegate vouch succeeds;
    ///      authenticate returns the admin-class actorId = ActorId.fromAddress(delegate).
    function test_authenticate_success_unrestrictedNestedSigner(uint256 ownerSeed, bytes32 hash) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        (address delegateAccount,) = _createK1Account(ownerPk);

        bytes memory nestedAuth = abi.encodePacked(k1Authenticator, _signDigest(ownerPk, hash));
        bytes memory data = abi.encodePacked(delegateAccount, nestedAuth);

        bytes32 actorId = delegateAuthenticator.authenticate(hash, data);
        assertEq(actorId, bytes32(uint256(uint160(delegateAccount))));
    }

    /// @dev The SCOPE_SPONSOR_PAYER bit does not grant signing: a nested actor holding only it is neither admin nor
    ///      operator (and cannot produce a valid ERC-1271 signature), so the delegate vouch reverts.
    function test_authenticate_revert_sponsorPayerBitCannotSign(uint256 ownerSeed, uint256 signerSeed, bytes32 hash)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 signerPk = _boundK1Pk(signerSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(signerPk));

        (address delegateAccount,) = _createK1Account(ownerPk);
        _authorizeScopedK1Actor(delegateAccount, ownerPk, signerPk, SCOPE_SPONSOR_PAYER);

        bytes memory nestedAuth = abi.encodePacked(k1Authenticator, _signDigest(signerPk, hash));
        bytes memory data = abi.encodePacked(delegateAccount, nestedAuth);

        vm.expectRevert(DelegateAuthenticator.InvalidNestedSignature.selector);
        delegateAuthenticator.authenticate(hash, data);
    }

    // ── Helpers ──

    /// @dev Authorizes a new K1 actor (`newPk`) with `scope` on `account`, signed by the unrestricted owner
    ///      (`ownerPk`). Granted UNBOUNDED (the new "no expiry") on a sequenced local batch via the harness helper.
    function _authorizeScopedK1Actor(address account, uint256 ownerPk, uint256 newPk, uint16 scope) internal {
        _authorizeActorWithScope(
            account, ownerPk, bytes32(uint256(uint160(vm.addr(newPk)))), address(k1Authenticator), scope
        );
    }
}
