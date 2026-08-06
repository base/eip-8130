// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Math} from "openzeppelin/utils/math/Math.sol";
import {P256} from "openzeppelin/utils/cryptography/P256.sol";

import {P256Authenticator} from "../../../src/authenticators/P256Authenticator.sol";
import {KeystoreTest} from "../../lib/KeystoreTest.sol";

/// @notice P256Authenticator tests. Data layout: r(32) ‖ s(32) ‖ x(32) ‖ y(32) ‖ preHash(1) = 129 bytes.
///         The authenticator reverts on wrong length, returns actorId = keccak256(x‖y) on a valid signature, and
///         returns bytes32(0) on any verification failure (it never reverts on a bad-but-well-formed signature).
contract P256AuthenticatorTest is KeystoreTest {
    // ── revert: length guard (InvalidDataLength) ──

    /// @notice Reverts for any calldata whose length is not exactly 129 bytes.
    /// @dev Fuzz confirms no length other than 129 is accepted; reverts with InvalidDataLength.
    function test_authenticate_revert_wrongDataLength(bytes memory data) public {
        vm.assume(data.length != 129);
        vm.expectRevert(P256Authenticator.InvalidDataLength.selector);
        p256Authenticator.authenticate(keccak256("h"), data);
    }

    /// @notice Reverts at exactly one byte short (128).
    /// @dev Boundary below the required length.
    function test_authenticate_revert_length128(uint256 pk, bytes32 hash) public {
        pk = _boundP256Pk(pk);
        bytes memory data = _p256SignData(pk, hash);
        bytes memory short = new bytes(128);
        for (uint256 i; i < 128; ++i) {
            short[i] = data[i];
        }
        vm.expectRevert(P256Authenticator.InvalidDataLength.selector);
        p256Authenticator.authenticate(hash, short);
    }

    /// @notice Reverts at exactly one byte long (130).
    /// @dev Boundary above the required length.
    function test_authenticate_revert_length130(uint256 pk, bytes32 hash) public {
        pk = _boundP256Pk(pk);
        bytes memory data = abi.encodePacked(_p256SignData(pk, hash), uint8(0));
        assertEq(data.length, 130);
        vm.expectRevert(P256Authenticator.InvalidDataLength.selector);
        p256Authenticator.authenticate(hash, data);
    }

    // ── success: valid signature returns actorId ──

    /// @notice A valid P-256 signature over `hash` returns keccak256(x‖y).
    /// @dev Fuzzes the key and the message; low-s normalized so OZ P256.verify accepts.
    function test_authenticate_success_validSignatureReturnsActorId(uint256 pk, bytes32 hash) public view {
        pk = _boundP256Pk(pk);
        bytes memory data = _p256SignData(pk, hash);

        bytes32 actorId = p256Authenticator.authenticate(hash, data);

        assertEq(actorId, _p256ActorId(pk));
        assertTrue(actorId != bytes32(0));
    }

    /// @notice actorId is exactly keccak256(x‖y) of the signing key.
    /// @dev A change to this derivation would rebind every existing P-256 actor's identity.
    function test_authenticate_success_actorIdIsKeccakOfPubKey(uint256 pk, bytes32 hash) public view {
        pk = _boundP256Pk(pk);
        (bytes32 x, bytes32 y) = _p256PubKey(pk);
        bytes memory data = _p256SignData(pk, hash);

        assertEq(p256Authenticator.authenticate(hash, data), keccak256(abi.encodePacked(x, y)));
    }

    /// @notice Distinct keys produce distinct actorIds for the same message.
    /// @dev Guards against actorId collisions across keys.
    function test_authenticate_success_distinctKeysDistinctActorIds(uint256 pk1, uint256 pk2, bytes32 hash)
        public
        view
    {
        pk1 = _boundP256Pk(pk1);
        pk2 = _boundP256Pk(pk2);
        vm.assume(pk1 != pk2);

        bytes32 id1 = p256Authenticator.authenticate(hash, _p256SignData(pk1, hash));
        bytes32 id2 = p256Authenticator.authenticate(hash, _p256SignData(pk2, hash));

        assertTrue(id1 != id2);
    }

    /// @notice The trailing preHash byte is not validated; any value still authenticates.
    /// @dev Documents that data[128] is inert in this implementation.
    function test_authenticate_success_preHashByteIgnored(uint256 pk, bytes32 hash, uint8 preByte) public view {
        pk = _boundP256Pk(pk);
        (bytes32 x, bytes32 y) = _p256PubKey(pk);
        (bytes32 r, bytes32 s) = vm.signP256(pk, hash);
        s = bytes32(Math.min(uint256(s), P256.N - uint256(s)));
        bytes memory data = abi.encodePacked(r, s, x, y, preByte);

        assertEq(p256Authenticator.authenticate(hash, data), _p256ActorId(pk));
    }

    // ── success: verification failures return bytes32(0) (no revert) ──

    /// @notice Returns zero when the signature is over a different hash.
    /// @dev Signature bound to message: verifying a different hash must fail.
    function test_authenticate_success_wrongHashReturnsZero(uint256 pk, bytes32 hash, bytes32 wrongHash) public view {
        pk = _boundP256Pk(pk);
        vm.assume(hash != wrongHash);
        bytes memory data = _p256SignData(pk, hash);

        assertEq(p256Authenticator.authenticate(wrongHash, data), bytes32(0));
    }

    /// @notice Returns zero for a high-s (malleable) signature.
    /// @dev OZ P256.verify rejects s > n/2; a mirrored signature must not authenticate.
    function test_authenticate_success_highSReturnsZero(uint256 pk, bytes32 hash) public view {
        pk = _boundP256Pk(pk);
        bytes memory data = _p256SignDataHighS(pk, hash);

        assertEq(p256Authenticator.authenticate(hash, data), bytes32(0));
    }

    /// @notice Returns zero when s == 0.
    /// @dev Degenerate scalar must be rejected by the verifier.
    function test_authenticate_success_zeroSReturnsZero(uint256 pk, bytes32 hash) public view {
        pk = _boundP256Pk(pk);
        (bytes32 x, bytes32 y) = _p256PubKey(pk);
        (bytes32 r,) = vm.signP256(pk, hash);
        bytes memory data = abi.encodePacked(r, bytes32(0), x, y, uint8(0));

        assertEq(p256Authenticator.authenticate(hash, data), bytes32(0));
    }

    /// @notice Returns zero when r == 0.
    /// @dev Degenerate scalar must be rejected by the verifier.
    function test_authenticate_success_zeroRReturnsZero(uint256 pk, bytes32 hash) public view {
        pk = _boundP256Pk(pk);
        (bytes32 x, bytes32 y) = _p256PubKey(pk);
        (, bytes32 s) = vm.signP256(pk, hash);
        s = bytes32(Math.min(uint256(s), P256.N - uint256(s)));
        bytes memory data = abi.encodePacked(bytes32(0), s, x, y, uint8(0));

        assertEq(p256Authenticator.authenticate(hash, data), bytes32(0));
    }

    /// @notice Returns zero when r or s equals the curve order n.
    /// @dev Out-of-range scalars must be rejected.
    function test_authenticate_success_scalarEqualsOrderReturnsZero(uint256 pk, bytes32 hash) public view {
        pk = _boundP256Pk(pk);
        (bytes32 x, bytes32 y) = _p256PubKey(pk);

        bytes memory rEqN = abi.encodePacked(bytes32(P256.N), bytes32(uint256(1)), x, y, uint8(0));
        assertEq(p256Authenticator.authenticate(hash, rEqN), bytes32(0));

        bytes memory sEqN = abi.encodePacked(bytes32(uint256(1)), bytes32(P256.N), x, y, uint8(0));
        assertEq(p256Authenticator.authenticate(hash, sEqN), bytes32(0));
    }

    /// @notice Returns zero when the signature is valid but paired with a different public key.
    /// @dev The verifier binds signature to the supplied key; substituting a foreign key must fail.
    function test_authenticate_success_wrongPubKeyReturnsZero(uint256 pk, uint256 pk2, bytes32 hash) public view {
        pk = _boundP256Pk(pk);
        pk2 = _boundP256Pk(pk2);
        vm.assume(pk != pk2);

        (bytes32 r, bytes32 s) = vm.signP256(pk, hash);
        s = bytes32(Math.min(uint256(s), P256.N - uint256(s)));
        (bytes32 x2, bytes32 y2) = _p256PubKey(pk2);
        bytes memory data = abi.encodePacked(r, s, x2, y2, uint8(0));

        assertEq(p256Authenticator.authenticate(hash, data), bytes32(0));
    }

    /// @notice Returns zero for a public key that is not a point on the P-256 curve.
    /// @dev Off-curve keys must never authenticate.
    function test_authenticate_success_offCurvePubKeyReturnsZero(uint256 pk, bytes32 hash, bytes32 badX, bytes32 badY)
        public
        view
    {
        pk = _boundP256Pk(pk);
        // Exclude the (astronomically unlikely) case that (badX, badY) is actually on-curve for this signature.
        (bytes32 r, bytes32 s) = vm.signP256(pk, hash);
        s = bytes32(Math.min(uint256(s), P256.N - uint256(s)));
        bytes memory data = abi.encodePacked(r, s, badX, badY, uint8(0));

        assertEq(p256Authenticator.authenticate(hash, data), bytes32(0));
    }

    /// @notice Returns zero for the zero public key (0,0) and never leaks keccak256(0,0) as an actorId.
    /// @dev (0,0) is the uninitialized-key value; accepting it would let an unset credential authenticate.
    function test_authenticate_success_zeroPubKeyReturnsZero(bytes32 hash, bytes32 r, bytes32 s) public view {
        bytes memory data = abi.encodePacked(r, s, bytes32(0), bytes32(0), uint8(0));

        bytes32 actorId = p256Authenticator.authenticate(hash, data);
        assertEq(actorId, bytes32(0));
        assertTrue(actorId != keccak256(abi.encodePacked(bytes32(0), bytes32(0))));
    }

    /// @notice Returns zero for out-of-field public-key coordinates (x = y = 2^256-1).
    /// @dev Exercises the verifier's public-key range validation.
    function test_authenticate_success_maxCoordsReturnZero(uint256 pk, bytes32 hash) public view {
        pk = _boundP256Pk(pk);
        (bytes32 r, bytes32 s) = vm.signP256(pk, hash);
        s = bytes32(Math.min(uint256(s), P256.N - uint256(s)));
        bytes memory data = abi.encodePacked(r, s, bytes32(type(uint256).max), bytes32(type(uint256).max), uint8(0));

        assertEq(p256Authenticator.authenticate(hash, data), bytes32(0));
    }

    /// @notice Returns zero for an all-zero 129-byte blob (r = s = x = y = 0).
    /// @dev Length is valid so no revert; every scalar/coordinate is degenerate.
    function test_authenticate_success_allZeroBlobReturnsZero(bytes32 hash) public view {
        bytes memory data = new bytes(129);
        assertEq(p256Authenticator.authenticate(hash, data), bytes32(0));
    }

    /// @notice Returns zero when s is just above the low-s cutoff (n/2 + 1).
    /// @dev Tightens the malleability boundary beyond the high-s mirror; s just over n/2 must be rejected.
    function test_authenticate_success_sJustAboveHalfOrderReturnsZero(uint256 pk, bytes32 hash) public view {
        pk = _boundP256Pk(pk);
        (bytes32 x, bytes32 y) = _p256PubKey(pk);
        bytes memory data = abi.encodePacked(bytes32(uint256(1)), bytes32(P256.N / 2 + 1), x, y, uint8(0));

        assertEq(p256Authenticator.authenticate(hash, data), bytes32(0));
    }

    /// @notice Returns zero when r or s exceeds the curve order n.
    /// @dev Out-of-range scalars (> n, not just == n) must be rejected.
    function test_authenticate_success_scalarAboveOrderReturnsZero(uint256 pk, bytes32 hash) public view {
        pk = _boundP256Pk(pk);
        (bytes32 x, bytes32 y) = _p256PubKey(pk);

        bytes memory rHi = abi.encodePacked(bytes32(P256.N + 1), bytes32(uint256(1)), x, y, uint8(0));
        assertEq(p256Authenticator.authenticate(hash, rHi), bytes32(0));

        bytes memory sHi = abi.encodePacked(bytes32(uint256(1)), bytes32(P256.N + 1), x, y, uint8(0));
        assertEq(p256Authenticator.authenticate(hash, sHi), bytes32(0));
    }
}
