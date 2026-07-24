// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {DelegateAuthenticator} from "../../../src/authenticators/DelegateAuthenticator.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

/// @notice Fuzzed, branch-complete test suite for DelegateAuthenticator.authenticate.
///
///         Source data layout: delegate_address(20) ‖ nested_authenticator(20) ‖ nested_data.
///         Guards, in source-execution order, each reverting with a custom error:
///           1. InvalidDataLength       — data.length < 40
///           2. RecursiveDelegation     — nestedAuthenticator == address(this) (blocks 1-hop recursion)
///           3. InvalidNestedSignature  — the nested auth does not resolve to the admin actor on `delegate`
///         On success returns actorId = bytes32(bytes20(delegate)).
///
///         The delegate vouch requires the nested auth to resolve to the ADMIN actor on `delegate` (scope ==
///         0x00). This admin-only requirement is enforced independently of verifySignature (via authenticateActor
///         + an explicit scope == 0 check): verifySignature is now operational (a SENDER-without-POLICY key can
///         sign), but such a key must NOT be able to vouch as a delegate, so a non-admin nested actor reverts.
contract DelegateAuthenticatorTest is AccountConfigurationTest {
    uint8 constant SCOPE_SENDER = 0x01;
    uint8 constant SCOPE_POLICY = 0x02;
    uint8 constant SCOPE_NONCE = 0x04;
    uint8 constant SCOPE_SELF_PAYER = 0x08;
    uint8 constant SCOPE_SPONSOR_PAYER = 0x10;
    uint8 constant AUTHORIZE_ACTOR = 0x01;

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

    // ── Guard 3: nested actor must be admin (authenticateActor + scope == 0, decoupled from verifySignature) ──

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

    /// @dev A nested signer that is a live actor on the delegate account but holds any non-zero (non-admin) scope
    ///      is rejected: the delegate vouch requires admin (scope == 0x00) and guard 3 reverts.
    function test_authenticate_revert_nestedSignerIsScoped(
        uint256 ownerSeed,
        uint256 signerSeed,
        uint8 scopeSeed,
        bytes32 hash
    ) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 signerPk = _boundK1Pk(signerSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(signerPk));

        // Any non-zero scope → non-admin → the delegate vouch must revert. Clear POLICY so the scoped actor
        // needs no policyData at authorization time.
        uint8 scope = uint8(bound(uint256(scopeSeed), 1, 255)) & ~SCOPE_POLICY;
        vm.assume(scope != 0);

        (address delegateAccount,) = _createK1Account(ownerPk);
        _authorizeScopedK1Actor(delegateAccount, ownerPk, signerPk, scope);

        bytes memory nestedAuth = abi.encodePacked(k1Authenticator, _signDigest(signerPk, hash));
        bytes memory data = abi.encodePacked(delegateAccount, nestedAuth);

        vm.expectRevert(DelegateAuthenticator.InvalidNestedSignature.selector);
        delegateAuthenticator.authenticate(hash, data);
    }

    /// @dev Regression guard for the operational/admin decoupling: a SENDER-without-POLICY nested actor on the
    ///      delegate account CAN verifySignature (it is operational), yet it MUST NOT satisfy the delegate vouch,
    ///      which stays admin-only. Asserts verifySignature is true for the same actor, then that the vouch reverts.
    function test_authenticate_revert_operationalSenderCannotVouch(uint256 ownerSeed, uint256 signerSeed, bytes32 hash)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 signerPk = _boundK1Pk(signerSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(signerPk));

        (address delegateAccount,) = _createK1Account(ownerPk);
        vm.assume(vm.addr(signerPk) != delegateAccount);
        _authorizeScopedK1Actor(delegateAccount, ownerPk, signerPk, SCOPE_SENDER);

        bytes memory nestedAuth = abi.encodePacked(k1Authenticator, _signDigest(signerPk, hash));

        // verifySignature wraps: sign replaySafeHash. (nestedAuth, over the raw hash, is for the vouch below.)
        bytes memory wrappedAuth = abi.encodePacked(
            k1Authenticator, _signDigest(signerPk, accountConfiguration.replaySafeHash(delegateAccount, hash))
        );
        assertTrue(accountConfiguration.verifySignature(delegateAccount, hash, wrappedAuth));

        // But it cannot vouch as a delegate — the nested check stays admin-only.
        bytes memory data = abi.encodePacked(delegateAccount, nestedAuth);
        vm.expectRevert(DelegateAuthenticator.InvalidNestedSignature.selector);
        delegateAuthenticator.authenticate(hash, data);
    }

    // ── Happy paths ──

    /// @dev An unrestricted (scope 0x00) initial owner is admin, so the delegate vouch succeeds;
    ///      authenticate returns actorId = bytes32(bytes20(delegate)).
    function test_authenticate_success_unrestrictedNestedSigner(uint256 ownerSeed, bytes32 hash) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        (address delegateAccount,) = _createK1Account(ownerPk);

        bytes memory nestedAuth = abi.encodePacked(k1Authenticator, _signDigest(ownerPk, hash));
        bytes memory data = abi.encodePacked(delegateAccount, nestedAuth);

        bytes32 actorId = delegateAuthenticator.authenticate(hash, data);
        assertEq(actorId, bytes32(bytes20(delegateAccount)));
    }

    /// @dev The former SIGNER bit (0x10, now SCOPE_SPONSOR_PAYER) no longer grants signing: a nested actor holding
    ///      it is non-admin (and non-operational), so the delegate vouch reverts.
    function test_authenticate_revert_formerSignerBitCannotSign(uint256 ownerSeed, uint256 signerSeed, bytes32 hash)
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

    /// @dev Authorizes a new K1 actor (`newPk`) with `scope` on `account`, signed by the unrestricted
    ///      owner (`ownerPk`) via applySignedActorChanges on the local chain.
    function _authorizeScopedK1Actor(address account, uint256 ownerPk, uint256 newPk, uint8 scope) internal {
        AccountConfiguration.ActorConfig memory config =
            AccountConfiguration.ActorConfig({authenticator: address(k1Authenticator), scope: scope, expiry: 0});

        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            changeType: AUTHORIZE_ACTOR, actorId: bytes32(bytes20(vm.addr(newPk))), data: abi.encode(config, bytes(""))
        });

        uint64 chainId = uint64(block.chainid);
        uint64 sequence = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, chainId, sequence, changes);
        accountConfiguration.applySignedActorChanges(account, chainId, changes, _buildK1Auth(ownerPk, digest));
    }
}
