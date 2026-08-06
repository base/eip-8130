// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore} from "../../../src/Keystore.sol";
import {KeystoreTest} from "../../lib/KeystoreTest.sol";

/// @notice Fuzzed, branch-complete suite for the authentication paths of Keystore:
///         authenticateActor -> _authenticate -> {_authenticateK1, IAuthenticator} -> _recoverSigner, plus the
///         verifySignature / getActorConfig / getPolicy views that read the same actor resolution.
///
///         Source-order revert coverage (as declared / hit through authenticateActor):
///           1. InvalidAuthLength      authenticateActor: auth.length < 20
///           2. AuthenticationFailed   _authenticate: non-K1 IAuthenticator returns bytes32(0)
///           3. AuthenticatorMismatch  _authenticate (non-K1) / _authenticateK1: stored authenticator != presented
///           4. ActorExpired           inline self (_authenticateK1), non-self K1, and non-self non-K1 paths
///           5. DefaultEoaRevoked      _authenticateK1: recovered == account with the revoke flag set
///           6. InvalidSignature       _recoverSigner: bad length / high-s / non-canonical v / zero recovery
///
///         The authentication functions are `view` and emit no events, so there are no event assertions here;
///         events (ActorAuthorized / ActorRevoked) belong to the applyKeyChange suite that drives the config writes.
contract AuthenticateTest is KeystoreTest {
    uint16 constant SCOPE_SENDER = 0x01;
    uint16 constant SCOPE_POLICY = 0x02;
    uint16 constant SCOPE_NONCE = 0x04;
    uint16 constant SCOPE_SELF_PAYER = 0x08;
    uint16 constant SCOPE_SPONSOR_PAYER = 0x10;

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // REVERTS (source order)
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    // ── 1. InvalidAuthLength: authenticateActor, auth.length < 20 ──

    /// @notice Any auth blob shorter than the 20-byte authenticator prefix reverts before slicing the selector.
    /// @dev Fuzzes the full [0,19] length range and byte content plus the account/hash; hits the length guard.
    function test_authenticateActor_revert_invalidAuthLength(
        address account,
        bytes32 hash,
        uint256 lenSeed,
        uint256 fillSeed
    ) public {
        uint256 len = bound(lenSeed, 0, 19);
        bytes memory auth = new bytes(len);
        for (uint256 i; i < len; ++i) {
            auth[i] = bytes1(uint8(uint256(keccak256(abi.encode(fillSeed, i)))));
        }

        vm.expectRevert(Keystore.InvalidAuthLength.selector);
        keystore.authenticateActor(account, hash, auth);
    }

    // ── 2. AuthenticationFailed: non-K1 IAuthenticator returns bytes32(0) ──

    /// @notice A well-formed P-256 blob whose signature is over a different hash resolves actorId 0 and reverts.
    /// @dev The P256Authenticator returns bytes32(0) on a failed verify (never reverts on a well-formed sig), so
    ///      _authenticate hits `revert AuthenticationFailed`. Reverts before any account SLOAD, so account is free.
    function test_authenticateActor_revert_authenticationFailed_p256(
        address account,
        uint256 pkSeed,
        bytes32 hash,
        bytes32 wrongHash
    ) public {
        vm.assume(hash != wrongHash);
        uint256 pk = _boundP256Pk(pkSeed);
        bytes memory auth = abi.encodePacked(address(p256Authenticator), _p256SignData(pk, hash));

        vm.expectRevert(Keystore.AuthenticationFailed.selector);
        keystore.authenticateActor(account, wrongHash, auth);
    }

    /// @notice A valid WebAuthn assertion presented against a different hash also resolves actorId 0 and reverts.
    /// @dev Same AuthenticationFailed branch through a distinct IAuthenticator (challenge != abi.encode(wrongHash)).
    function test_authenticateActor_revert_authenticationFailed_webAuthn(
        address account,
        uint256 pkSeed,
        bytes32 hash,
        bytes32 wrongHash
    ) public {
        vm.assume(hash != wrongHash);
        uint256 pk = _boundP256Pk(pkSeed);
        bytes memory auth = abi.encodePacked(address(webAuthnAuthenticator), _webauthnSignData(pk, hash));

        vm.expectRevert(Keystore.AuthenticationFailed.selector);
        keystore.authenticateActor(account, wrongHash, auth);
    }

    // ── 3. AuthenticatorMismatch: stored actor authenticator != presented ──

    /// @notice A K1 signature recovering to a key that is neither the account nor a registered actor mismatches.
    /// @dev _authenticateK1: recovered != account, `_actorConfig[actorId].authenticator == 0 != K1` -> mismatch.
    function test_authenticateActor_revert_authenticatorMismatch_k1Unregistered(
        uint256 ownerSeed,
        uint256 strangerSeed,
        bytes32 hash
    ) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 strangerPk = _boundK1Pk(strangerSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(strangerPk));

        (address account,) = _createK1Account(ownerPk);
        // A CREATE2 account can never equal a recoverable EOA, so the stranger takes the non-self K1 actor branch.
        vm.assume(vm.addr(strangerPk) != account);

        vm.expectRevert(Keystore.AuthenticatorMismatch.selector);
        keystore.authenticateActor(account, hash, _buildK1Auth(strangerPk, hash));
    }

    /// @notice A valid P-256 signature for a key that was never authorized on the account mismatches.
    /// @dev _authenticate (non-K1): actorId resolves, but `_actorConfig[actorId].authenticator == 0 != p256`.
    function test_authenticateActor_revert_authenticatorMismatch_p256Unregistered(
        address account,
        uint256 pkSeed,
        bytes32 hash
    ) public {
        uint256 pk = _boundP256Pk(pkSeed);
        bytes memory auth = abi.encodePacked(address(p256Authenticator), _p256SignData(pk, hash));

        vm.expectRevert(Keystore.AuthenticatorMismatch.selector);
        keystore.authenticateActor(account, hash, auth);
    }

    /// @notice A key registered under the P-256 authenticator, presented via the WebAuthn authenticator, mismatches.
    /// @dev Both authenticators derive actorId = keccak256(x‖y), so the actorId resolves but the stored authenticator
    ///      (p256) differs from the presented one (webAuthn).
    function test_authenticateActor_revert_authenticatorMismatch_crossAuthenticator(
        uint256 ownerSeed,
        uint256 pkSeed,
        bytes32 hash
    ) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 pk = _boundP256Pk(pkSeed);

        (address account,) = _createK1Account(ownerPk);
        _authorizeActorWithScope(account, ownerPk, _p256ActorId(pk), address(p256Authenticator), 0x00);

        // Present the same key through WebAuthn: actorId matches, presented authenticator does not.
        bytes memory auth = abi.encodePacked(address(webAuthnAuthenticator), _webauthnSignData(pk, hash));

        vm.expectRevert(Keystore.AuthenticatorMismatch.selector);
        keystore.authenticateActor(account, hash, auth);
    }

    /// @notice After a K1 actor is revoked its config is cleared, so re-presenting its signature mismatches.
    /// @dev Revoke deletes `_actorConfig[actorId]`, leaving authenticator == 0 != K1 on the non-self K1 path.
    function test_authenticateActor_revert_authenticatorMismatch_revokedActor(
        uint256 ownerSeed,
        uint256 actorSeed,
        bytes32 hash
    ) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 actorPk = _boundK1Pk(actorSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(actorPk));

        (address account,) = _createK1Account(ownerPk);
        bytes32 actorId = bytes32(bytes20(vm.addr(actorPk)));
        _authorizeActorWithScope(account, ownerPk, actorId, address(k1Authenticator), 0x00);
        _revokeActor(account, ownerPk, actorId);

        vm.expectRevert(Keystore.AuthenticatorMismatch.selector);
        keystore.authenticateActor(account, hash, _buildK1Auth(actorPk, hash));
    }

    // ── 4. ActorExpired: inline self, non-self K1, and non-self non-K1 ──

    /// @notice The inline self key expires: once block.timestamp passes defaultEOAExpiry the self path reverts.
    /// @dev _authenticateK1 inline-self branch (recovered == account, flag unset) hits the expiry guard.
    function test_authenticateActor_revert_actorExpired_inlineSelf(
        uint256 eoaSeed,
        uint48 expirySeed,
        uint256 warpSeed,
        bytes32 hash
    ) public {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        uint48 expiry = uint48(bound(uint256(expirySeed), 1, uint256(type(uint48).max) - 1));
        // Authorize the self-actorId as a scoped-0 K1 actor carrying an expiry (re-enables the inline self).
        _authorizeActorWithExpiry(eoa, eoaPk, selfActorId, address(k1Authenticator), expiry);

        vm.warp(uint256(expiry) + bound(warpSeed, 1, 1_000_000));
        vm.expectRevert(Keystore.ActorExpired.selector);
        keystore.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));
    }

    /// @notice A non-self K1 session actor expires and can no longer authenticate.
    /// @dev _authenticateK1 non-self branch (config.expiry != 0 && block.timestamp > expiry).
    function test_authenticateActor_revert_actorExpired_nonSelfK1(
        uint256 ownerSeed,
        uint256 sessionSeed,
        uint48 expirySeed,
        uint256 warpSeed,
        bytes32 hash
    ) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 sessionPk = _boundK1Pk(sessionSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(sessionPk));

        (address account,) = _createK1Account(ownerPk);
        bytes32 sessionActorId = bytes32(bytes20(vm.addr(sessionPk)));
        uint48 expiry = uint48(bound(uint256(expirySeed), 1, uint256(type(uint48).max) - 1));
        _authorizeActorWithExpiry(account, ownerPk, sessionActorId, address(k1Authenticator), expiry);

        vm.warp(uint256(expiry) + bound(warpSeed, 1, 1_000_000));
        vm.expectRevert(Keystore.ActorExpired.selector);
        keystore.authenticateActor(account, hash, _buildK1Auth(sessionPk, hash));
    }

    /// @notice A non-self P-256 actor expires and can no longer authenticate.
    /// @dev _authenticate (non-K1) expiry guard: exercises the ActorExpired branch outside the K1 path.
    function test_authenticateActor_revert_actorExpired_nonSelfP256(
        uint256 ownerSeed,
        uint256 pkSeed,
        uint48 expirySeed,
        uint256 warpSeed,
        bytes32 hash
    ) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 pk = _boundP256Pk(pkSeed);

        (address account,) = _createK1Account(ownerPk);
        uint48 expiry = uint48(bound(uint256(expirySeed), 1, uint256(type(uint48).max) - 1));
        _authorizeActorWithExpiry(account, ownerPk, _p256ActorId(pk), address(p256Authenticator), expiry);

        vm.warp(uint256(expiry) + bound(warpSeed, 1, 1_000_000));
        bytes memory auth = abi.encodePacked(address(p256Authenticator), _p256SignData(pk, hash));

        vm.expectRevert(Keystore.ActorExpired.selector);
        keystore.authenticateActor(account, hash, auth);
    }

    // ── 5. DefaultEoaRevoked: recovered == account with the revoke flag set ──

    /// @notice After the self-actorId is revoked, the account's own K1 key can no longer authenticate.
    /// @dev Revoking the self-actorId sets FLAG_REVOKE_DEFAULT_EOA; _authenticateK1 reverts on the flag check.
    function test_authenticateActor_revert_defaultEoaRevoked_afterSelfRevoke(uint256 eoaSeed, bytes32 hash) public {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        // The implicit self (unrestricted) signs a batch revoking its own self-actorId; auth precedes the revoke.
        _revokeActor(eoa, eoaPk, selfActorId);

        vm.expectRevert(Keystore.DefaultEoaRevoked.selector);
        keystore.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));
    }

    /// @notice Authorizing the self-actorId to a non-K1 authenticator disables the inline K1 self (mutual exclusion).
    /// @dev The non-K1 self path sets FLAG_REVOKE_DEFAULT_EOA, so a subsequent self K1 signature is DefaultEoaRevoked.
    function test_authenticateActor_revert_defaultEoaRevoked_afterNonK1SelfAuthorize(uint256 eoaSeed, bytes32 hash)
        public
    {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        // Implicit self authorizes itself to a non-K1 authenticator (P256), flipping the mutual-exclusion flag.
        _authorizeActorWithScope(eoa, eoaPk, selfActorId, address(p256Authenticator), 0x00);

        vm.expectRevert(Keystore.DefaultEoaRevoked.selector);
        keystore.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));
    }

    // ── 6. InvalidSignature: _recoverSigner (length / high-s / v / zero recovery) ──

    /// @notice A K1 auth whose signature payload is not exactly 65 bytes reverts on the length guard.
    /// @dev _recoverSigner: `data.length != 65`; data == auth[20:], so the auth blob is K1(20) ‖ <len != 65>.
    function test_authenticateActor_revert_invalidSignature_badLength(
        address account,
        bytes32 hash,
        uint256 lenSeed,
        uint256 fillSeed
    ) public {
        uint256 len = bound(lenSeed, 0, 200);
        vm.assume(len != 65);
        bytes memory data = new bytes(len);
        for (uint256 i; i < len; ++i) {
            data[i] = bytes1(uint8(uint256(keccak256(abi.encode(fillSeed, i)))));
        }
        bytes memory auth = abi.encodePacked(k1Authenticator, data);

        vm.expectRevert(Keystore.InvalidSignature.selector);
        keystore.authenticateActor(account, hash, auth);
    }

    /// @notice The high-s (EIP-2 malleable) twin of a canonical signature is rejected.
    /// @dev _recoverSigner: `s > SECP256K1_HALF_ORDER`. vm.sign returns low-s, so n - s is always high-s; v flipped
    ///      to model the malleability attack that recovers the same address.
    function test_authenticateActor_revert_invalidSignature_highS(uint256 eoaSeed, bytes32 hash) public {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        address eoa = vm.addr(eoaPk);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(eoaPk, hash);
        bytes32 highS = bytes32(SECP256K1_ORDER - uint256(s));
        uint8 flippedV = v == 27 ? 28 : 27;
        bytes memory auth = abi.encodePacked(k1Authenticator, r, highS, flippedV);

        vm.expectRevert(Keystore.InvalidSignature.selector);
        keystore.authenticateActor(eoa, hash, auth);
    }

    /// @notice A recovery id outside {27, 28} is rejected even with a canonical low-s signature.
    /// @dev _recoverSigner: `v != 27 && v != 28`. Low-s keeps the high-s guard from firing first.
    function test_authenticateActor_revert_invalidSignature_badV(uint256 eoaSeed, bytes32 hash, uint8 vSeed) public {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        address eoa = vm.addr(eoaPk);
        vm.assume(vSeed != 27 && vSeed != 28);

        (, bytes32 r, bytes32 s) = vm.sign(eoaPk, hash);
        bytes memory auth = abi.encodePacked(k1Authenticator, r, s, vSeed);

        vm.expectRevert(Keystore.InvalidSignature.selector);
        keystore.authenticateActor(eoa, hash, auth);
    }

    /// @notice A signature that ecrecovers to address(0) (r == 0) is rejected as a zero recovery.
    /// @dev _recoverSigner passes length/high-s/v guards (s low, v = 27) but r == 0 -> ecrecover == 0 ->
    ///      _authenticateK1 reverts on `recovered == address(0)`.
    function test_authenticateActor_revert_invalidSignature_zeroRecovery(address account, bytes32 hash, uint256 sSeed)
        public
    {
        uint256 s = bound(sSeed, 1, (SECP256K1_ORDER - 1) / 2); // canonical low-s so only the r == 0 guard bites
        bytes memory auth = abi.encodePacked(k1Authenticator, bytes32(0), bytes32(s), uint8(27));

        vm.expectRevert(Keystore.InvalidSignature.selector);
        keystore.authenticateActor(account, hash, auth);
    }

    // ── Unknown authenticator: a selector with no deployed code cannot resolve an actor ──

    /// @notice A non-K1 authenticator address with no deployed code reverts (empty returndata fails the decode).
    /// @dev Exercises the external-call branch of _authenticate against a codeless authenticator.
    function test_authenticateActor_revert_unknownAuthenticatorNoCode(
        address account,
        address authenticator,
        bytes32 hash,
        bytes calldata data
    ) public {
        vm.assume(uint160(authenticator) > uint160(k1Authenticator)); // not the K1 branch, not address(0)
        vm.assume(authenticator.code.length == 0);
        bytes memory auth = abi.encodePacked(authenticator, data);

        vm.expectRevert();
        keystore.authenticateActor(account, hash, auth);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // HAPPY / BRANCH
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice A never-created EOA authenticates via the implicit self key as a full owner (all-zero inline config).
    /// @dev _authenticateK1 inline-self branch: recovered == account, flag unset, expiry 0 -> scope 0.
    function test_authenticateActor_success_implicitEoaSelf(uint256 eoaSeed, bytes32 hash) public view {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        address eoa = vm.addr(eoaPk);

        (, uint16 scope) = keystore.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));

        assertEq(scope, uint16(0x00));
    }

    /// @notice A registered non-self K1 owner (scope 0) authenticates on a created account.
    /// @dev _authenticateK1 non-self branch: config.authenticator == K1, expiry 0 -> returns the stored scope.
    function test_authenticateActor_success_registeredK1Actor(uint256 ownerSeed, uint256 actorSeed, bytes32 hash)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 actorPk = _boundK1Pk(actorSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(actorPk));

        (address account,) = _createK1Account(ownerPk);
        vm.assume(vm.addr(actorPk) != account);
        _authorizeActorWithScope(account, ownerPk, bytes32(bytes20(vm.addr(actorPk))), address(k1Authenticator), 0x00);

        (, uint16 scope) = keystore.authenticateActor(account, hash, _buildK1Auth(actorPk, hash));
        assertEq(scope, uint8(0x00));
    }

    /// @notice A registered P-256 actor authenticates via the non-K1 authenticator path.
    /// @dev _authenticate (non-K1) success: IAuthenticator resolves actorId, config.authenticator == p256. The
    ///      SCOPE_POLICY bit is cleared so no policyData is required at authorize time.
    function test_authenticateActor_success_p256Actor(uint256 ownerSeed, uint256 pkSeed, uint8 scopeSeed, bytes32 hash)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 pk = _boundP256Pk(pkSeed);
        uint16 scope = uint16(bound(uint256(scopeSeed), 0, 255)) & ~SCOPE_POLICY;

        (address account,) = _createK1Account(ownerPk);
        _authorizeActorWithScope(account, ownerPk, _p256ActorId(pk), address(p256Authenticator), scope);

        bytes memory auth = abi.encodePacked(address(p256Authenticator), _p256SignData(pk, hash));
        (, uint16 outScope) = keystore.authenticateActor(account, hash, auth);
        assertEq(outScope, scope);
    }

    /// @notice A registered WebAuthn actor authenticates via the non-K1 authenticator path.
    /// @dev Same non-K1 success branch through the WebAuthn authenticator; actorId = keccak256(x‖y).
    function test_authenticateActor_success_webAuthnActor(
        uint256 ownerSeed,
        uint256 pkSeed,
        uint8 scopeSeed,
        bytes32 hash
    ) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 pk = _boundP256Pk(pkSeed);
        uint16 scope = uint16(bound(uint256(scopeSeed), 0, 255)) & ~SCOPE_POLICY;

        (address account,) = _createK1Account(ownerPk);
        _authorizeActorWithScope(account, ownerPk, _p256ActorId(pk), address(webAuthnAuthenticator), scope);

        bytes memory auth = abi.encodePacked(address(webAuthnAuthenticator), _webauthnSignData(pk, hash));
        (, uint16 outScope) = keystore.authenticateActor(account, hash, auth);
        assertEq(outScope, scope);
    }

    /// @notice A scoped K1 actor authenticates and surfaces exactly its stored scope.
    /// @dev Fuzzes the scope space (minus SCOPE_POLICY, which requires policyData) to prove passthrough of the
    ///      scope byte (no SIGNER special-casing).
    function test_authenticateActor_success_scopedActorReturnsScope(
        uint256 ownerSeed,
        uint256 actorSeed,
        uint8 scopeSeed,
        bytes32 hash
    ) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 actorPk = _boundK1Pk(actorSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(actorPk));
        uint16 scope = uint16(bound(uint256(scopeSeed), 1, 255)) & ~SCOPE_POLICY;

        (address account,) = _createK1Account(ownerPk);
        vm.assume(vm.addr(actorPk) != account);
        _authorizeActorWithScope(account, ownerPk, bytes32(bytes20(vm.addr(actorPk))), address(k1Authenticator), scope);

        (, uint16 outScope) = keystore.authenticateActor(account, hash, _buildK1Auth(actorPk, hash));
        assertEq(outScope, scope);
    }

    /// @notice An explicitly registered unrestricted (scope 0) non-self K1 actor authenticates as a full owner.
    /// @dev Distinguishes the explicit scope-0 upsert from the implicit-self path; both resolve to scope 0.
    function test_authenticateActor_success_unrestrictedScope(uint256 ownerSeed, uint256 actorSeed, bytes32 hash)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 actorPk = _boundK1Pk(actorSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(actorPk));

        (address account,) = _createK1Account(ownerPk);
        vm.assume(vm.addr(actorPk) != account);
        _authorizeActorWithScope(account, ownerPk, bytes32(bytes20(vm.addr(actorPk))), address(k1Authenticator), 0x00);

        (, uint16 scope) = keystore.authenticateActor(account, hash, _buildK1Auth(actorPk, hash));
        assertEq(scope, uint8(0x00));
    }

    /// @notice A zero-expiry actor never expires, even far in the future.
    /// @dev expiry == 0 short-circuits the expiry guard on the non-self K1 path regardless of warp.
    function test_authenticateActor_success_zeroExpiryNeverExpires(
        uint256 ownerSeed,
        uint256 sessionSeed,
        uint256 warpSeed,
        bytes32 hash
    ) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 sessionPk = _boundK1Pk(sessionSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(sessionPk));

        (address account,) = _createK1Account(ownerPk);
        vm.assume(vm.addr(sessionPk) != account);
        _authorizeActorWithExpiry(account, ownerPk, bytes32(bytes20(vm.addr(sessionPk))), address(k1Authenticator), 0);

        vm.warp(block.timestamp + bound(warpSeed, 1, 3650 days));
        (, uint16 scope) = keystore.authenticateActor(account, hash, _buildK1Auth(sessionPk, hash));
        assertEq(scope, uint8(0x00));
    }

    /// @notice An actor at exactly its expiry timestamp is still valid (guard is strict `>`).
    /// @dev Warps to block.timestamp == expiry on the non-self K1 path and expects success.
    function test_authenticateActor_success_atExpiryBoundary(
        uint256 ownerSeed,
        uint256 sessionSeed,
        uint48 expirySeed,
        bytes32 hash
    ) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 sessionPk = _boundK1Pk(sessionSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(sessionPk));

        (address account,) = _createK1Account(ownerPk);
        vm.assume(vm.addr(sessionPk) != account);
        uint48 expiry = uint48(bound(uint256(expirySeed), block.timestamp + 1, uint256(type(uint48).max)));
        _authorizeActorWithExpiry(
            account, ownerPk, bytes32(bytes20(vm.addr(sessionPk))), address(k1Authenticator), expiry
        );

        vm.warp(expiry);
        (, uint16 scope) = keystore.authenticateActor(account, hash, _buildK1Auth(sessionPk, hash));
        assertEq(scope, uint8(0x00));
    }

    /// @notice A policy-gated actor surfaces its scope; the policy target is resolved separately via getPolicyManager.
    /// @dev authenticateActor returns (actorId, scope) only; the manager is an execution-time read (getPolicyManager).
    function test_authenticateActor_success_gatedActorReturnsScope(
        uint256 ownerSeed,
        uint256 sessionSeed,
        uint8 scopeSeed,
        address manager,
        bytes32 commitment,
        bytes32 hash
    ) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 sessionPk = _boundK1Pk(sessionSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(sessionPk));
        vm.assume(manager != address(0));
        vm.assume(commitment != bytes32(0));
        // A policy-bearing actor's scope carries SCOPE_POLICY; other bits are arbitrary.
        uint16 scope = uint16(scopeSeed) | SCOPE_POLICY;

        (address account,) = _createK1Account(ownerPk);
        vm.assume(vm.addr(sessionPk) != account);
        bytes32 sessionActorId = bytes32(bytes20(vm.addr(sessionPk)));
        _authorizeGatedActor(account, ownerPk, sessionActorId, scope, manager, commitment);

        (, uint16 outScope) = keystore.authenticateActor(account, hash, _buildK1Auth(sessionPk, hash));

        assertEq(outScope, scope);
        assertEq(keystore.getPolicyManager(account, sessionActorId), manager);
    }

    /// @notice An ungated actor authenticates and returns only its scope (no policy manager slot written).
    /// @dev getPolicyManager is address(0) for an ungated actor.
    function test_authenticateActor_success_ungatedActorReturnsScope(uint256 eoaSeed, bytes32 hash) public view {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        address eoa = vm.addr(eoaPk);

        (, uint16 scope) = keystore.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));

        assertEq(scope, uint16(0x00));
        assertEq(keystore.getPolicyManager(eoa, bytes32(bytes20(eoa))), address(0));
    }

    /// @notice Scoping the account's own key downgrades it: the inline self returns the reduced scope, never owner.
    /// @dev There is a single K1 path, so the config alone decides the scope — no implicit full-owner escape.
    function test_authenticateActor_success_selfScopedDowngrade(uint256 eoaSeed, uint8 scopeSeed, bytes32 hash) public {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));
        uint16 scope = uint16(bound(uint256(scopeSeed), 1, 255)) & ~SCOPE_POLICY;
        vm.assume(scope != 0);

        _authorizeActorWithScope(eoa, eoaPk, selfActorId, address(k1Authenticator), scope);

        (, uint16 outScope) = keystore.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));
        assertEq(outScope, scope);
    }

    /// @notice A second explicit K1 owner (non-self actorId) registered on an EOA authenticates independently.
    /// @dev Non-self K1 branch on an EIP-7702-style EOA that still has its implicit self live.
    function test_authenticateActor_success_explicitNonSelfEoaActor(uint256 eoaSeed, uint256 bobSeed, bytes32 hash)
        public
    {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        uint256 bobPk = _boundK1Pk(bobSeed);
        address eoa = vm.addr(eoaPk);
        vm.assume(vm.addr(bobPk) != eoa);

        _implicitAuthorizeActor(eoa, eoaPk, bytes32(bytes20(vm.addr(bobPk))), address(k1Authenticator));

        (, uint16 scope) = keystore.authenticateActor(eoa, hash, _buildK1Auth(bobPk, hash));
        assertEq(scope, uint8(0x00));
    }

    /// @notice The same owner key authenticates on two distinct accounts derived from different salts.
    /// @dev Confirms actor resolution is keyed per-account; a valid owner sig is not cross-account fungible by luck.
    function test_authenticateActor_success_crossAccount(uint256 ownerSeed, bytes32 saltA, bytes32 saltB, bytes32 hash)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        vm.assume(saltA != saltB);

        (address accountA,) = _createK1AccountWithSalt(ownerPk, saltA);
        (address accountB,) = _createK1AccountWithSalt(ownerPk, saltB);
        vm.assume(accountA != accountB);

        bytes memory auth = _buildK1Auth(ownerPk, hash);
        (, uint16 scopeA) = keystore.authenticateActor(accountA, hash, auth);
        (, uint16 scopeB) = keystore.authenticateActor(accountB, hash, auth);
        assertEq(scopeA, uint16(0x00));
        assertEq(scopeB, uint16(0x00));
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // actorId — surfaced as the first return of authenticateActor
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    //
    // Off-8130 consumers (e.g. an ERC-4337 account) need the resolved actorId to drive getPolicyCommitment without
    // re-invoking the authenticator — parity with the tx-context precompile on an 8130 chain.

    /// @notice The inline-self k1 path returns actorId == bytes32(bytes20(account)).
    function test_authenticateActor_success_returnsActorId_inlineSelf(uint256 eoaSeed, bytes32 hash) public view {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        address eoa = vm.addr(eoaPk);

        (bytes32 actorId,) = keystore.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));
        assertEq(actorId, bytes32(bytes20(eoa)));
    }

    /// @notice A non-self k1 actor returns actorId == bytes32(bytes20(signer)).
    function test_authenticateActor_success_returnsActorId_nonSelfK1(uint256 ownerSeed, uint256 actorSeed, bytes32 hash)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 actorPk = _boundK1Pk(actorSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(actorPk));

        (address account,) = _createK1Account(ownerPk);
        vm.assume(vm.addr(actorPk) != account);
        bytes32 expectedActorId = bytes32(bytes20(vm.addr(actorPk)));
        _authorizeActorWithScope(account, ownerPk, expectedActorId, address(k1Authenticator), 0x00);

        (bytes32 actorId,) = keystore.authenticateActor(account, hash, _buildK1Auth(actorPk, hash));
        assertEq(actorId, expectedActorId);
    }

    /// @notice A non-k1 (P-256) actor returns the actorId resolved by its authenticator.
    function test_authenticateActor_success_returnsActorId_nonK1(uint256 ownerSeed, uint256 pkSeed, bytes32 hash)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 pk = _boundP256Pk(pkSeed);

        (address account,) = _createK1Account(ownerPk);
        bytes32 expectedActorId = _p256ActorId(pk);
        _authorizeActorWithScope(account, ownerPk, expectedActorId, address(p256Authenticator), 0x00);

        bytes memory auth = abi.encodePacked(address(p256Authenticator), _p256SignData(pk, hash));
        (bytes32 actorId,) = keystore.authenticateActor(account, hash, auth);
        assertEq(actorId, expectedActorId);
    }

    /// @notice A non-k1 WebAuthn actor returns the actorId resolved by its authenticator (second non-k1 path).
    function test_authenticateActor_success_returnsActorId_webAuthn(uint256 ownerSeed, uint256 pkSeed, bytes32 hash)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 pk = _boundP256Pk(pkSeed);

        (address account,) = _createK1Account(ownerPk);
        bytes32 expectedActorId = _p256ActorId(pk);
        _authorizeActorWithScope(account, ownerPk, expectedActorId, address(webAuthnAuthenticator), 0x00);

        bytes memory auth = abi.encodePacked(address(webAuthnAuthenticator), _webauthnSignData(pk, hash));
        (bytes32 actorId,) = keystore.authenticateActor(account, hash, auth);
        assertEq(actorId, expectedActorId);
    }

    /// @notice actorId is returned unchanged alongside a non-zero (fuzzed) scope — identity is independent of scope.
    function test_authenticateActor_success_returnsActorId_scopedActor(
        uint256 ownerSeed,
        uint256 actorSeed,
        uint8 scopeSeed,
        bytes32 hash
    ) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 actorPk = _boundK1Pk(actorSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(actorPk));
        uint16 scope = uint16(bound(uint256(scopeSeed), 1, 255)) & ~SCOPE_POLICY;

        (address account,) = _createK1Account(ownerPk);
        vm.assume(vm.addr(actorPk) != account);
        bytes32 expectedActorId = bytes32(bytes20(vm.addr(actorPk)));
        _authorizeActorWithScope(account, ownerPk, expectedActorId, address(k1Authenticator), scope);

        (bytes32 actorId, uint16 outScope) = keystore.authenticateActor(account, hash, _buildK1Auth(actorPk, hash));
        assertEq(actorId, expectedActorId);
        assertEq(outScope, scope);
    }

    /// @notice A scoped (downgraded) inline self still returns actorId == bytes32(bytes20(account)).
    function test_authenticateActor_success_returnsActorId_scopedInlineSelf(
        uint256 eoaSeed,
        uint8 scopeSeed,
        bytes32 hash
    ) public {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));
        uint16 scope = uint16(bound(uint256(scopeSeed), 1, 255)) & ~SCOPE_POLICY;

        _authorizeActorWithScope(eoa, eoaPk, selfActorId, address(k1Authenticator), scope);

        (bytes32 actorId, uint16 outScope) = keystore.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));
        assertEq(actorId, selfActorId);
        assertEq(outScope, scope);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // verifySignature (operational authority)
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice verifySignature returns true for any operational actor: the admin (scope == 0x00) or a SENDER actor
    ///         without POLICY. Payer-only / nonce-only (non-SENDER) scopes are not operational and verify false.
    /// @dev Fuzzes the (POLICY-cleared) scope space and asserts the boolean equals the operational predicate
    ///      `scope == 0 || (scope & SCOPE_SENDER != 0)`, proving ERC-1271 signing is operational — not admin-only,
    ///      and with no dedicated SIGNER grant.
    function test_verifySignature_success_operationalAcrossScopes(
        uint256 ownerSeed,
        uint256 actorSeed,
        uint8 scopeSeed,
        bytes32 hash
    ) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 actorPk = _boundK1Pk(actorSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(actorPk));
        uint16 scope = uint16(bound(uint256(scopeSeed), 0, 255)) & ~SCOPE_POLICY;

        (address account,) = _createK1Account(ownerPk);
        vm.assume(vm.addr(actorPk) != account);
        _authorizeActorWithScope(account, ownerPk, bytes32(bytes20(vm.addr(actorPk))), address(k1Authenticator), scope);

        bool expected = scope == 0 || (scope & SCOPE_SENDER != 0);
        // verifySignature applies the account-scoped EIP-7739 wrap.
        bytes memory auth = _buildK1Auth(actorPk, keystore.replaySafeHash(account, hash));
        assertEq(keystore.verifySignature(account, hash, auth), expected);
    }

    /// @notice A SENDER actor without POLICY is operational and verifies true via verifySignature.
    /// @dev Positive guard for the operational-authority path: signing is authority a SENDER key already holds via
    ///      calls, so it does not require the admin scope. Covers SENDER alone and SENDER combined with the
    ///      SELF_PAYER / NONCE capability bits (still no POLICY).
    function test_verifySignature_success_trueForSenderWithoutPolicy(uint256 ownerSeed, uint256 actorSeed, bytes32 hash)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 actorPk = _boundK1Pk(actorSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(actorPk));

        (address account,) = _createK1Account(ownerPk);
        vm.assume(vm.addr(actorPk) != account);
        bytes32 actorId = bytes32(bytes20(vm.addr(actorPk)));
        // verifySignature applies the account-scoped EIP-7739 wrap; replaySafeHash(account, hash) is scope-independent.
        bytes memory auth = _buildK1Auth(actorPk, keystore.replaySafeHash(account, hash));

        _authorizeActorWithScope(account, ownerPk, actorId, address(k1Authenticator), SCOPE_SENDER);
        assertTrue(keystore.verifySignature(account, hash, auth));

        _authorizeActorWithScope(account, ownerPk, actorId, address(k1Authenticator), SCOPE_SENDER | SCOPE_SELF_PAYER);
        assertTrue(keystore.verifySignature(account, hash, auth));

        _authorizeActorWithScope(account, ownerPk, actorId, address(k1Authenticator), SCOPE_SENDER | SCOPE_NONCE);
        assertTrue(keystore.verifySignature(account, hash, auth));
    }

    /// @notice A non-SENDER capability-only actor (SELF_PAYER-only, SPONSOR_PAYER-only, NONCE-only) is NOT
    ///         operational and verifies false.
    /// @dev Negative guard: only admin or SENDER-without-POLICY are operational.
    function test_verifySignature_success_falseForNonSenderScopes(uint256 ownerSeed, uint256 actorSeed, bytes32 hash)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 actorPk = _boundK1Pk(actorSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(actorPk));

        (address account,) = _createK1Account(ownerPk);
        vm.assume(vm.addr(actorPk) != account);
        bytes32 actorId = bytes32(bytes20(vm.addr(actorPk)));

        _authorizeActorWithScope(account, ownerPk, actorId, address(k1Authenticator), SCOPE_SELF_PAYER);
        assertFalse(keystore.verifySignature(account, hash, _buildK1Auth(actorPk, hash)));

        _authorizeActorWithScope(account, ownerPk, actorId, address(k1Authenticator), SCOPE_SPONSOR_PAYER);
        assertFalse(keystore.verifySignature(account, hash, _buildK1Auth(actorPk, hash)));

        _authorizeActorWithScope(account, ownerPk, actorId, address(k1Authenticator), SCOPE_NONCE);
        assertFalse(keystore.verifySignature(account, hash, _buildK1Auth(actorPk, hash)));
    }

    /// @notice A policy-bearing actor is NEVER a valid ERC-1271 signer (a POLICY actor is not operational).
    /// @dev verifySignature must return false for a scoped SCOPE_POLICY actor.
    function test_verifySignature_success_falseForPolicyActor(
        uint256 ownerSeed,
        uint256 sessionSeed,
        address manager,
        bytes32 commitment,
        bytes32 hash
    ) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 sessionPk = _boundK1Pk(sessionSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(sessionPk));
        vm.assume(manager != address(0));
        vm.assume(commitment != bytes32(0));

        (address account,) = _createK1Account(ownerPk);
        vm.assume(vm.addr(sessionPk) != account);
        bytes32 sessionActorId = bytes32(bytes20(vm.addr(sessionPk)));
        _authorizeGatedActor(account, ownerPk, sessionActorId, SCOPE_POLICY, manager, commitment);
        assertFalse(keystore.verifySignature(account, hash, _buildK1Auth(sessionPk, hash)));

        // SENDER | POLICY is still not operational: the POLICY bit disqualifies it even though SENDER is set.
        _authorizeGatedActor(account, ownerPk, sessionActorId, SCOPE_SENDER | SCOPE_POLICY, manager, commitment);
        assertFalse(keystore.verifySignature(account, hash, _buildK1Auth(sessionPk, hash)));
    }

    /// @notice verifySignature returns false when authentication fails outright (unregistered signer).
    /// @dev authenticateActor reverts (AuthenticatorMismatch) and the try/catch collapses it to false.
    function test_verifySignature_success_falseOnUnauthenticated(uint256 ownerSeed, uint256 strangerSeed, bytes32 hash)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 strangerPk = _boundK1Pk(strangerSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(strangerPk));

        (address account,) = _createK1Account(ownerPk);
        vm.assume(vm.addr(strangerPk) != account);

        assertFalse(keystore.verifySignature(account, hash, _buildK1Auth(strangerPk, hash)));
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // getPolicy / getActorConfig / isActor (actor-resolution views)
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice getPolicy resolves a gated actor's manager and signed commitment.
    /// @dev Returns (manager, commitment) from the policy keyspace when scope & SCOPE_POLICY is set.
    function test_getPolicy_success_gatedActor(
        uint256 ownerSeed,
        uint256 sessionSeed,
        uint8 scopeSeed,
        address manager,
        bytes32 commitment
    ) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 sessionPk = _boundK1Pk(sessionSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(sessionPk));
        vm.assume(manager != address(0));
        vm.assume(commitment != bytes32(0));
        uint16 scope = uint16(scopeSeed) | SCOPE_POLICY;

        (address account,) = _createK1Account(ownerPk);
        bytes32 sessionActorId = bytes32(bytes20(vm.addr(sessionPk)));
        _authorizeGatedActor(account, ownerPk, sessionActorId, scope, manager, commitment);

        (address outTarget, bytes32 outCommitment) = keystore.getPolicy(account, sessionActorId);
        assertEq(outTarget, manager);
        assertEq(outCommitment, commitment);
    }

    /// @notice getPolicy returns the zero policy for an ungated actor.
    /// @dev No policy slots written for scope & SCOPE_POLICY == 0 -> (address(0), bytes32(0)).
    function test_getPolicy_success_ungatedActor(uint256 ownerSeed, uint256 actorSeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 actorPk = _boundK1Pk(actorSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(actorPk));

        (address account,) = _createK1Account(ownerPk);
        vm.assume(vm.addr(actorPk) != account);
        bytes32 actorId = bytes32(bytes20(vm.addr(actorPk)));
        _authorizeActorWithScope(account, ownerPk, actorId, address(k1Authenticator), 0x00);

        (address target, bytes32 commitment) = keystore.getPolicy(account, actorId);
        assertEq(target, address(0));
        assertEq(commitment, bytes32(0));
    }

    /// @notice getActorConfig returns a registered actor's authenticator and scope verbatim.
    /// @dev The initial owner is stored with the K1 authenticator and scope 0.
    function test_getActorConfig_success_returnsAuthenticatorAndScope(uint256 ownerSeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        (address account, bytes32 actorId) = _createK1Account(ownerPk);

        Keystore.ActorConfig memory cfg = keystore.getActorConfig(account, actorId);
        assertEq(cfg.authenticator, address(k1Authenticator));
        assertEq(cfg.scope, uint8(0x00));
    }

    /// @notice getActorConfig returns the empty config for an unknown actor.
    /// @dev No _actorConfig entry and not the (live) self-actorId -> all-zero config.
    function test_getActorConfig_success_returnsZeroForUnknownActor(uint256 ownerSeed, bytes32 unknownActorId) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        (address account, bytes32 actorId) = _createK1Account(ownerPk);
        vm.assume(unknownActorId != actorId);
        vm.assume(unknownActorId != bytes32(bytes20(account)));

        Keystore.ActorConfig memory cfg = keystore.getActorConfig(account, unknownActorId);
        assertEq(cfg.authenticator, address(0));
        assertEq(cfg.scope, uint8(0x00));
    }

    /// @notice isActor reports the implicit self-actorId of a never-created EOA as live.
    /// @dev No _actorConfig entry, actorId == self, flag unset -> true.
    function test_isActor_success_implicitEoaTrue(uint256 eoaSeed) public view {
        address eoa = vm.addr(_boundK1Pk(eoaSeed));
        assertTrue(_isActor(eoa, bytes32(bytes20(eoa))));
    }

    /// @notice isActor reports a non-self actorId on a never-created EOA as not live.
    /// @dev A random actorId != bytes32(bytes20(eoa)) has no inline home and no _actorConfig entry -> false.
    function test_isActor_success_nonSelfActorIdNotImplicit(uint256 eoaSeed, bytes32 randomActorId) public view {
        address eoa = vm.addr(_boundK1Pk(eoaSeed));
        vm.assume(randomActorId != bytes32(bytes20(eoa)));
        assertFalse(_isActor(eoa, randomActorId));
    }

    /// @notice isActor reports the self-actorId as not live after the self key has been revoked.
    /// @dev Revoking the self-actorId sets the revoke flag, so the inline self no longer counts as an actor.
    function test_isActor_success_falseAfterSelfRevoke(uint256 eoaSeed) public {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        _revokeActor(eoa, eoaPk, selfActorId);

        assertFalse(_isActor(eoa, selfActorId));
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // HELPERS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @dev Authorize `newActorId` under `authenticator` with `scope` (no expiry, no policy), signed by `pk`.
    ///      For the self-actorId with the K1 authenticator this drives the inline-self home; for any other
    ///      authenticator on the self-actorId it drives the mutually-exclusive non-K1 self home. `scope` must not
    ///      carry SCOPE_POLICY (no policyData is provided).
    function _authorizeActorWithScope(
        address account,
        uint256 pk,
        bytes32 newActorId,
        address authenticator,
        uint16 scope
    ) internal {
        Keystore.ActorChange[] memory changes = new Keystore.ActorChange[](1);
        changes[0] = Keystore.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(Keystore.ActorConfig({authenticator: authenticator, scope: scope, expiry: 0}), bytes(""))
        });

        uint64 seq = keystore.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        keystore.applySignedActorChanges(account, uint64(block.chainid), changes, _buildK1Auth(pk, digest));
    }

    /// @dev Authorize `newActorId` under `authenticator` with the given `expiry` (scope 0, no policy), signed by `pk`.
    function _authorizeActorWithExpiry(
        address account,
        uint256 pk,
        bytes32 newActorId,
        address authenticator,
        uint48 expiry
    ) internal {
        Keystore.ActorChange[] memory changes = new Keystore.ActorChange[](1);
        changes[0] = Keystore.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                Keystore.ActorConfig({authenticator: authenticator, scope: 0x00, expiry: expiry}), bytes("")
            )
        });

        uint64 seq = keystore.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        keystore.applySignedActorChanges(account, uint64(block.chainid), changes, _buildK1Auth(pk, digest));
    }

    /// @dev Authorize `newActorId` under `authenticator` as an unrestricted owner (scope 0), signed by `pk`.
    function _implicitAuthorizeActor(address account, uint256 pk, bytes32 newActorId, address authenticator) internal {
        _authorizeActorWithScope(account, pk, newActorId, authenticator, 0x00);
    }

    /// @dev Revoke `actorId` from `account`, signed by `pk`.
    function _revokeActor(address account, uint256 pk, bytes32 actorId) internal {
        Keystore.ActorChange[] memory changes = new Keystore.ActorChange[](1);
        changes[0] = Keystore.ActorChange({actorId: actorId, changeType: 0x02, data: ""});

        uint64 seq = keystore.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        keystore.applySignedActorChanges(account, uint64(block.chainid), changes, _buildK1Auth(pk, digest));
    }

    /// @dev Authorize a K1 policy-gated actor: manager[20] || commitment[32] policy data, signed by the owner `pk`.
    ///      `scope` must carry SCOPE_POLICY.
    function _authorizeGatedActor(
        address account,
        uint256 ownerPk,
        bytes32 newActorId,
        uint16 scope,
        address policyManager,
        bytes32 commitment
    ) internal {
        Keystore.ActorChange[] memory changes = new Keystore.ActorChange[](1);
        changes[0] = Keystore.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                Keystore.ActorConfig({authenticator: address(k1Authenticator), scope: scope, expiry: 0}),
                abi.encodePacked(policyManager, commitment)
            )
        });

        uint64 seq = keystore.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        keystore.applySignedActorChanges(account, uint64(block.chainid), changes, _buildK1Auth(ownerPk, digest));
    }
}
