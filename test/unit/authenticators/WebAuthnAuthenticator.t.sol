// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Base64} from "openzeppelin/utils/Base64.sol";
import {Math} from "openzeppelin/utils/math/Math.sol";
import {P256} from "openzeppelin/utils/cryptography/P256.sol";
import {WebAuthn} from "openzeppelin/utils/cryptography/WebAuthn.sol";

import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

/// @notice WebAuthnAuthenticator tests. The authenticator decodes abi.encode(WebAuthnAuth, x, y), derives
///         actorId = keccak256(x‖y), and calls WebAuthn.verify(challenge: abi.encode(hash), auth, x, y,
///         requireUV: false). It returns bytes32(0) on any verification failure and reverts only when the calldata
///         cannot be abi-decoded into the expected tuple.
contract WebAuthnAuthenticatorTest is AccountConfigurationTest {
    // ── revert: undecodable calldata ──

    /// @notice Reverts when calldata is too short to abi-decode into (WebAuthnAuth, bytes32, bytes32).
    /// @dev The authenticator does not wrap abi.decode; malformed input propagates as a revert.
    function test_authenticate_revert_truncatedData(uint256 len) public {
        len = bound(len, 0, 95); // top-level head needs 3 words (offset + x + y); < 96 cannot decode
        bytes memory data = new bytes(len);
        vm.expectRevert();
        p256WebAuthnAuthenticate(keccak256("h"), data);
    }

    // ── success: valid assertion returns actorId ──

    /// @notice A valid WebAuthn assertion over `hash` returns keccak256(x‖y).
    /// @dev Fuzzes key and message; User-Present set, low-s normalized.
    function test_authenticate_success_validReturnsActorId(uint256 pk, bytes32 hash) public view {
        pk = _boundP256Pk(pk);
        bytes memory data = _webauthnSignData(pk, hash);

        bytes32 actorId = webAuthnAuthenticator.authenticate(hash, data);

        assertEq(actorId, _p256ActorId(pk));
        assertTrue(actorId != bytes32(0));
    }

    /// @notice actorId is exactly keccak256(x‖y) of the credential public key.
    /// @dev A change to this derivation would rebind every existing credential's identity.
    function test_authenticate_success_actorIdIsKeccakOfPubKey(uint256 pk, bytes32 hash) public view {
        pk = _boundP256Pk(pk);
        (bytes32 x, bytes32 y) = _p256PubKey(pk);

        assertEq(
            webAuthnAuthenticator.authenticate(hash, _webauthnSignData(pk, hash)), keccak256(abi.encodePacked(x, y))
        );
    }

    /// @notice Distinct credentials produce distinct actorIds.
    /// @dev Guards against actorId collisions across credentials.
    function test_authenticate_success_distinctKeysDistinctActorIds(uint256 pk1, uint256 pk2, bytes32 hash)
        public
        view
    {
        pk1 = _boundP256Pk(pk1);
        pk2 = _boundP256Pk(pk2);
        vm.assume(pk1 != pk2);

        bytes32 id1 = webAuthnAuthenticator.authenticate(hash, _webauthnSignData(pk1, hash));
        bytes32 id2 = webAuthnAuthenticator.authenticate(hash, _webauthnSignData(pk2, hash));

        assertTrue(id1 != id2);
    }

    /// @notice A User-Verified assertion also authenticates (authenticator sets requireUV = false).
    /// @dev UP|UV must succeed given requireUV is false.
    function test_authenticate_success_userVerifiedAlsoAuthenticates(uint256 pk, bytes32 hash) public view {
        pk = _boundP256Pk(pk);
        bytes memory data = _webauthnSignData(pk, hash, WebAuthn.AUTH_DATA_FLAGS_UP | WebAuthn.AUTH_DATA_FLAGS_UV);

        assertEq(webAuthnAuthenticator.authenticate(hash, data), _p256ActorId(pk));
    }

    /// @notice Backup-eligible + backed-up assertion authenticates (BE=1, BS=1 is a valid state).
    /// @dev Confirms the BE/BS consistency check permits the fully-backed-up state.
    function test_authenticate_success_backupEligibleAndStateAuthenticates(uint256 pk, bytes32 hash) public view {
        pk = _boundP256Pk(pk);
        bytes1 flags = WebAuthn.AUTH_DATA_FLAGS_UP | WebAuthn.AUTH_DATA_FLAGS_BE | WebAuthn.AUTH_DATA_FLAGS_BS;
        bytes memory data = _webauthnSignData(pk, hash, flags);

        assertEq(webAuthnAuthenticator.authenticate(hash, data), _p256ActorId(pk));
    }

    // ── success: verification failures return bytes32(0) ──

    /// @notice Returns zero when the challenge in clientDataJSON does not match the authenticated hash.
    /// @dev Assertion is built for `hash` but verified against `wrongHash`; challenge check must fail.
    function test_authenticate_success_wrongHashReturnsZero(uint256 pk, bytes32 hash, bytes32 wrongHash) public view {
        pk = _boundP256Pk(pk);
        vm.assume(hash != wrongHash);
        bytes memory data = _webauthnSignData(pk, hash);

        assertEq(webAuthnAuthenticator.authenticate(wrongHash, data), bytes32(0));
    }

    /// @notice Returns zero when the User-Present bit is not set.
    /// @dev UP is mandatory even when requireUV is false.
    function test_authenticate_success_userPresentNotSetReturnsZero(uint256 pk, bytes32 hash) public view {
        pk = _boundP256Pk(pk);
        // Only UV set (no UP).
        bytes memory data = _webauthnSignData(pk, hash, WebAuthn.AUTH_DATA_FLAGS_UV);

        assertEq(webAuthnAuthenticator.authenticate(hash, data), bytes32(0));
    }

    /// @notice Returns zero when backed-up (BS=1) without backup-eligibility (BE=0).
    /// @dev BE/BS consistency: BS=1 requires BE=1.
    function test_authenticate_success_backupStateWithoutEligibilityReturnsZero(uint256 pk, bytes32 hash) public view {
        pk = _boundP256Pk(pk);
        bytes memory data = _webauthnSignData(pk, hash, WebAuthn.AUTH_DATA_FLAGS_UP | WebAuthn.AUTH_DATA_FLAGS_BS);

        assertEq(webAuthnAuthenticator.authenticate(hash, data), bytes32(0));
    }

    /// @notice Returns zero when clientDataJSON type is not "webauthn.get".
    /// @dev A "webauthn.create" ceremony must not authenticate an assertion.
    function test_authenticate_success_wrongTypeReturnsZero(uint256 pk, bytes32 hash) public view {
        pk = _boundP256Pk(pk);
        (bytes32 x, bytes32 y) = _p256PubKey(pk);
        bytes memory authData = _webauthnAuthenticatorData(WebAuthn.AUTH_DATA_FLAGS_UP);
        string memory clientDataJSON =
            string.concat('{"type":"webauthn.create","challenge":"', Base64.encodeURL(abi.encode(hash)), '"}');

        bytes32 msgHash = sha256(abi.encodePacked(authData, sha256(bytes(clientDataJSON))));
        (bytes32 r, bytes32 s) = vm.signP256(pk, msgHash);
        s = bytes32(Math.min(uint256(s), P256.N - uint256(s)));

        WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
            r: r,
            s: s,
            challengeIndex: 25, // shifted by 2 vs "webauthn.get" prefix; type check fails first regardless
            typeIndex: 1,
            authenticatorData: authData,
            clientDataJSON: clientDataJSON
        });

        assertEq(webAuthnAuthenticator.authenticate(hash, abi.encode(auth, x, y)), bytes32(0));
    }

    /// @notice Returns zero for a high-s (malleable) signature.
    /// @dev WebAuthn.verify delegates to P256.verify, which rejects s > n/2.
    function test_authenticate_success_highSReturnsZero(uint256 pk, bytes32 hash) public view {
        pk = _boundP256Pk(pk);
        (bytes32 x, bytes32 y) = _p256PubKey(pk);
        bytes memory authData = _webauthnAuthenticatorData(WebAuthn.AUTH_DATA_FLAGS_UP);
        string memory clientDataJSON = _webauthnClientDataJSON(abi.encode(hash));

        bytes32 msgHash = sha256(abi.encodePacked(authData, sha256(bytes(clientDataJSON))));
        (bytes32 r, bytes32 s) = vm.signP256(pk, msgHash);
        uint256 lowS = Math.min(uint256(s), P256.N - uint256(s));

        WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
            r: r,
            s: bytes32(P256.N - lowS), // high-s
            challengeIndex: 23,
            typeIndex: 1,
            authenticatorData: authData,
            clientDataJSON: clientDataJSON
        });

        assertEq(webAuthnAuthenticator.authenticate(hash, abi.encode(auth, x, y)), bytes32(0));
    }

    /// @notice Returns zero when a valid signature is paired with a different public key.
    /// @dev Signature binds to the supplied credential key; substituting a foreign key must fail.
    function test_authenticate_success_wrongPubKeyReturnsZero(uint256 pk, uint256 pk2, bytes32 hash) public view {
        pk = _boundP256Pk(pk);
        pk2 = _boundP256Pk(pk2);
        vm.assume(pk != pk2);

        bytes memory authData = _webauthnAuthenticatorData(WebAuthn.AUTH_DATA_FLAGS_UP);
        string memory clientDataJSON = _webauthnClientDataJSON(abi.encode(hash));
        bytes32 msgHash = sha256(abi.encodePacked(authData, sha256(bytes(clientDataJSON))));
        (bytes32 r, bytes32 s) = vm.signP256(pk, msgHash);
        s = bytes32(Math.min(uint256(s), P256.N - uint256(s)));
        (bytes32 x2, bytes32 y2) = _p256PubKey(pk2);

        WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
            r: r, s: s, challengeIndex: 23, typeIndex: 1, authenticatorData: authData, clientDataJSON: clientDataJSON
        });

        assertEq(webAuthnAuthenticator.authenticate(hash, abi.encode(auth, x2, y2)), bytes32(0));
    }

    /// @notice Returns zero when authenticatorData is too short (<= 36 bytes).
    /// @dev verify checks the length before indexing the flags byte; short data fails cleanly without reverting.
    function test_authenticate_success_shortAuthenticatorDataReturnsZero(uint256 pk, bytes32 hash) public view {
        pk = _boundP256Pk(pk);
        (bytes32 x, bytes32 y) = _p256PubKey(pk);
        bytes memory authData = new bytes(36); // one byte short of the 37-byte minimum
        string memory clientDataJSON = _webauthnClientDataJSON(abi.encode(hash));
        bytes32 msgHash = sha256(abi.encodePacked(authData, sha256(bytes(clientDataJSON))));
        (bytes32 r, bytes32 s) = vm.signP256(pk, msgHash);
        s = bytes32(Math.min(uint256(s), P256.N - uint256(s)));

        WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
            r: r, s: s, challengeIndex: 23, typeIndex: 1, authenticatorData: authData, clientDataJSON: clientDataJSON
        });

        assertEq(webAuthnAuthenticator.authenticate(hash, abi.encode(auth, x, y)), bytes32(0));
    }

    /// @notice Returns zero for the zero public key (0,0); never leaks keccak256(0,0) as an actorId.
    /// @dev (0,0) is the uninitialized-key value; accepting it would let an unset credential authenticate.
    function test_authenticate_success_zeroPubKeyReturnsZero(uint256 pk, bytes32 hash) public view {
        pk = _boundP256Pk(pk);
        bytes memory authData = _webauthnAuthenticatorData(WebAuthn.AUTH_DATA_FLAGS_UP);
        string memory clientDataJSON = _webauthnClientDataJSON(abi.encode(hash));
        bytes32 msgHash = sha256(abi.encodePacked(authData, sha256(bytes(clientDataJSON))));
        (bytes32 r, bytes32 s) = vm.signP256(pk, msgHash);
        s = bytes32(Math.min(uint256(s), P256.N - uint256(s)));

        WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
            r: r, s: s, challengeIndex: 23, typeIndex: 1, authenticatorData: authData, clientDataJSON: clientDataJSON
        });

        bytes32 actorId = webAuthnAuthenticator.authenticate(hash, abi.encode(auth, bytes32(0), bytes32(0)));
        assertEq(actorId, bytes32(0));
        assertTrue(actorId != keccak256(abi.encodePacked(bytes32(0), bytes32(0))));
    }

    /// @notice Returns zero when typeIndex is tampered out of bounds.
    /// @dev typeIndex/challengeIndex are caller-supplied and NOT signed material; a garbage index must not
    ///      produce a false accept (and must not revert).
    function test_authenticate_success_tamperedTypeIndexReturnsZero(uint256 pk, bytes32 hash) public view {
        pk = _boundP256Pk(pk);
        (bytes32 x, bytes32 y) = _p256PubKey(pk);
        bytes memory authData = _webauthnAuthenticatorData(WebAuthn.AUTH_DATA_FLAGS_UP);
        string memory clientDataJSON = _webauthnClientDataJSON(abi.encode(hash));
        bytes32 msgHash = sha256(abi.encodePacked(authData, sha256(bytes(clientDataJSON))));
        (bytes32 r, bytes32 s) = vm.signP256(pk, msgHash);
        s = bytes32(Math.min(uint256(s), P256.N - uint256(s)));

        WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
            r: r,
            s: s,
            challengeIndex: 23,
            typeIndex: type(uint256).max,
            authenticatorData: authData,
            clientDataJSON: clientDataJSON
        });

        assertEq(webAuthnAuthenticator.authenticate(hash, abi.encode(auth, x, y)), bytes32(0));
    }

    /// @notice Returns zero when challengeIndex is tampered out of bounds.
    /// @dev An overflowing challengeIndex slice must yield a mismatch, not a revert.
    function test_authenticate_success_tamperedChallengeIndexReturnsZero(uint256 pk, bytes32 hash) public view {
        pk = _boundP256Pk(pk);
        (bytes32 x, bytes32 y) = _p256PubKey(pk);
        bytes memory authData = _webauthnAuthenticatorData(WebAuthn.AUTH_DATA_FLAGS_UP);
        string memory clientDataJSON = _webauthnClientDataJSON(abi.encode(hash));
        bytes32 msgHash = sha256(abi.encodePacked(authData, sha256(bytes(clientDataJSON))));
        (bytes32 r, bytes32 s) = vm.signP256(pk, msgHash);
        s = bytes32(Math.min(uint256(s), P256.N - uint256(s)));

        WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
            r: r,
            s: s,
            challengeIndex: type(uint256).max,
            typeIndex: 1,
            authenticatorData: authData,
            clientDataJSON: clientDataJSON
        });

        assertEq(webAuthnAuthenticator.authenticate(hash, abi.encode(auth, x, y)), bytes32(0));
    }

    /// @dev Forwards to webAuthnAuthenticator.authenticate; used by the truncated-data revert test.
    function p256WebAuthnAuthenticate(bytes32 hash, bytes memory data) internal view returns (bytes32) {
        return webAuthnAuthenticator.authenticate(hash, data);
    }
}
