// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";

import {Base64} from "openzeppelin/utils/Base64.sol";
import {Math} from "openzeppelin/utils/math/Math.sol";
import {P256} from "openzeppelin/utils/cryptography/P256.sol";
import {WebAuthn} from "openzeppelin/utils/cryptography/WebAuthn.sol";

import {Keystore} from "../../src/Keystore.sol";
import {DefaultAccount} from "../../src/accounts/DefaultAccount.sol";
import {DelegateAuthenticator} from "../../src/authenticators/DelegateAuthenticator.sol";
import {IAuthenticator} from "../../src/interfaces/IAuthenticator.sol";
import {P256Authenticator} from "../../src/authenticators/P256Authenticator.sol";
import {WebAuthnAuthenticator} from "../../src/authenticators/WebAuthnAuthenticator.sol";

contract KeystoreTest is Test {
    Keystore public keystore;
    // The single canonical secp256k1 authenticator (internal ecrecover). Not a deployed contract — it's the
    // K1_AUTHENTICATOR sentinel (address(1)); k1 auth blobs are K1_AUTHENTICATOR(20) || r‖s‖v.
    address public k1Authenticator;
    IAuthenticator public p256Authenticator;
    IAuthenticator public webAuthnAuthenticator;
    IAuthenticator public delegateAuthenticator;
    address public defaultAccountImplementation;

    /// @dev Test EntryPoint address; tests register it as a TRUSTED_EXECUTOR actor in the initial actor set.
    address public constant ENTRY_POINT = address(0xEEEE);

    // SECP256K1_ORDER (curve order n) is inherited from forge-std; _boundK1Pk bounds fuzzed keys to [1, n-1].

    bytes32 constant SIGNED_ACTOR_CHANGES_TYPEHASH = keccak256(
        "SignedActorChanges(address account,uint256 chainId,uint64 sequence,ActorChange[] actorChanges)"
        "ActorChange(uint8 changeType,bytes32 actorId,bytes data)"
    );

    bytes32 constant ACTORCHANGE_TYPEHASH = keccak256("ActorChange(uint8 changeType,bytes32 actorId,bytes data)");

    bytes32 constant LOCK_CHANGE_TYPEHASH =
        keccak256("SignedLockChange(address account,uint256 chainId,uint8 op,uint16 unlockDelay,uint64 sequence)");

    uint8 constant LOCK_OP = 0x01;
    uint8 constant UNLOCK_OP = 0x02;

    function setUp() public virtual {
        keystore = new Keystore();
        k1Authenticator = keystore.K1_AUTHENTICATOR();
        p256Authenticator = IAuthenticator(new P256Authenticator());
        webAuthnAuthenticator = IAuthenticator(new WebAuthnAuthenticator());
        delegateAuthenticator = IAuthenticator(new DelegateAuthenticator(address(keystore)));
        defaultAccountImplementation = address(new DefaultAccount(address(keystore)));
    }

    // ── Bytecode helpers ──

    function _computeERC1167Bytecode(address implementation) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"363d3d373d3d3d363d73", implementation, hex"5af43d82803e903d91602b57fd5bf3");
    }

    // ── Account creation helpers ──

    function _createK1Account(uint256 pk) internal returns (address account, bytes32 actorId) {
        address signer = vm.addr(pk);
        actorId = bytes32(bytes20(signer));

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](1);
        actors[0] = Keystore.InitialActor({
            actorId: actorId, authenticator: address(k1Authenticator), scope: 0, policyData: ""
        });

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        account = keystore.createAccount(bytes32(0), bytecode, actors);
    }

    function _createK1AccountWithSalt(uint256 pk, bytes32 salt) internal returns (address account, bytes32 actorId) {
        address signer = vm.addr(pk);
        actorId = bytes32(bytes20(signer));

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](1);
        actors[0] = Keystore.InitialActor({
            actorId: actorId, authenticator: address(k1Authenticator), scope: 0, policyData: ""
        });

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        account = keystore.createAccount(salt, bytecode, actors);
    }

    // ── K1 signature helpers ──

    function _signDigest(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Build a canonical K1 auth blob: K1_AUTHENTICATOR(20) || r‖s‖v.
    function _buildK1Auth(uint256 pk, bytes32 digest) internal view returns (bytes memory) {
        bytes memory sig = _signDigest(pk, digest);
        return abi.encodePacked(k1Authenticator, sig);
    }

    // ── Canonical digest computation ──

    function _computeActorChangeBatchDigest(
        address account,
        uint256 chainId,
        uint64 sequence,
        Keystore.ActorChange[] memory actorChanges
    ) internal pure returns (bytes32) {
        bytes32[] memory actorChangeHash = new bytes32[](actorChanges.length);
        for (uint256 i; i < actorChanges.length; i++) {
            actorChangeHash[i] = keccak256(
                abi.encode(
                    ACTORCHANGE_TYPEHASH,
                    actorChanges[i].changeType,
                    actorChanges[i].actorId,
                    keccak256(actorChanges[i].data)
                )
            );
        }
        return keccak256(
            abi.encode(
                SIGNED_ACTOR_CHANGES_TYPEHASH, account, chainId, sequence, keccak256(abi.encodePacked(actorChangeHash))
            )
        );
    }

    // ── Signed lock-change helpers ──
    //
    // Lock state changes go through applySignedLockChanges: a relayable, admin-authorized (scope 0) signed call.
    // These helpers drive it for an account controlled by `pk` — either the account's inline default-EOA self (an
    // uninitialized EOA at vm.addr(pk)) or a k1 admin actor whose actorId is bytes32(bytes20(vm.addr(pk))).

    function _computeLockChangeDigest(address account, uint256 chainId, uint8 op, uint16 unlockDelay, uint64 sequence)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(LOCK_CHANGE_TYPEHASH, account, chainId, op, unlockDelay, sequence));
    }

    /// @dev Admin auth blob for a lock op (op = 1) at the account's current local sequence.
    function _lockAuth(uint256 pk, address account, uint16 unlockDelay) internal view returns (bytes memory) {
        uint64 seq = keystore.getChangeSequences(account).local;
        bytes32 digest = _computeLockChangeDigest(account, block.chainid, LOCK_OP, unlockDelay, seq);
        return _buildK1Auth(pk, digest);
    }

    /// @dev Admin auth blob for an unlock op (op = 2) at the account's current local sequence.
    function _unlockAuth(uint256 pk, address account) internal view returns (bytes memory) {
        uint64 seq = keystore.getChangeSequences(account).local;
        bytes32 digest = _computeLockChangeDigest(account, block.chainid, UNLOCK_OP, 0, seq);
        return _buildK1Auth(pk, digest);
    }

    /// @dev Relay a signed lock op (op = 1) authorized by `pk`.
    function _signedLock(uint256 pk, address account, uint16 unlockDelay) internal {
        keystore.applySignedLockChanges(account, LOCK_OP, unlockDelay, _lockAuth(pk, account, unlockDelay));
    }

    /// @dev Relay a signed unlock op (op = 2) authorized by `pk`.
    function _signedUnlock(uint256 pk, address account) internal {
        keystore.applySignedLockChanges(account, UNLOCK_OP, 0, _unlockAuth(pk, account));
    }

    // ── Fuzzed key bounding ──

    /// @dev Bound a fuzzed seed to a valid secp256k1 private key in [1, n-1].
    function _boundK1Pk(uint256 seed) internal pure returns (uint256) {
        return bound(seed, 1, SECP256K1_ORDER - 1);
    }

    /// @dev Bound a fuzzed seed to a valid secp256r1 (P-256) private key in [1, n-1].
    function _boundP256Pk(uint256 seed) internal pure returns (uint256) {
        return bound(seed, 1, P256.N - 1);
    }

    // ── P-256 helpers (raw P256Authenticator: r‖s‖x‖y‖preHash = 129 bytes) ──

    /// @dev P-256 public key coordinates for `pk`.
    function _p256PubKey(uint256 pk) internal view returns (bytes32 x, bytes32 y) {
        (uint256 ux, uint256 uy) = vm.publicKeyP256(pk);
        (x, y) = (bytes32(ux), bytes32(uy));
    }

    /// @dev actorId for a P-256 / WebAuthn key = keccak256(x ‖ y).
    function _p256ActorId(uint256 pk) internal view returns (bytes32) {
        (bytes32 x, bytes32 y) = _p256PubKey(pk);
        return keccak256(abi.encodePacked(x, y));
    }

    /// @dev Valid P256Authenticator data. s is normalized low-s so OZ P256.verify (which rejects high-s) accepts.
    function _p256SignData(uint256 pk, bytes32 hash) internal view returns (bytes memory) {
        (bytes32 x, bytes32 y) = _p256PubKey(pk);
        (bytes32 r, bytes32 s) = vm.signP256(pk, hash);
        s = bytes32(Math.min(uint256(s), P256.N - uint256(s)));
        return abi.encodePacked(r, s, x, y, uint8(0));
    }

    /// @dev Malleable (high-s) variant of a valid P256 signature: s' = n - lowS > n/2. Must be rejected.
    function _p256SignDataHighS(uint256 pk, bytes32 hash) internal view returns (bytes memory) {
        (bytes32 x, bytes32 y) = _p256PubKey(pk);
        (bytes32 r, bytes32 s) = vm.signP256(pk, hash);
        uint256 lowS = Math.min(uint256(s), P256.N - uint256(s));
        return abi.encodePacked(r, bytes32(P256.N - lowS), x, y, uint8(0));
    }

    // ── WebAuthn helpers (WebAuthnAuthenticator: abi.encode(WebAuthnAuth, x, y)) ──
    //
    // The WebAuthnAuthenticator calls WebAuthn.verify(challenge: abi.encode(hash), auth, x, y, requireUV: false).
    // clientDataJSON prefix `{"type":"webauthn.get","challenge":"` fixes typeIndex = 1, challengeIndex = 23.

    /// @dev Encoded authenticatorData: 32-byte rpIdHash ‖ 1-byte flags ‖ 4-byte counter (37 bytes, > 36 minimum).
    function _webauthnAuthenticatorData(bytes1 flags) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes32(0), flags, bytes4(0));
    }

    function _webauthnClientDataJSON(bytes memory challenge) internal pure returns (string memory) {
        return string.concat('{"type":"webauthn.get","challenge":"', Base64.encodeURL(challenge), '"}');
    }

    /// @dev Valid WebAuthnAuthenticator data with User-Present set (requireUV is false in the authenticator).
    function _webauthnSignData(uint256 pk, bytes32 hash) internal view returns (bytes memory) {
        return _webauthnSignData(pk, hash, WebAuthn.AUTH_DATA_FLAGS_UP);
    }

    /// @dev WebAuthnAuthenticator data with caller-chosen authenticator-data flags.
    function _webauthnSignData(uint256 pk, bytes32 hash, bytes1 flags) internal view returns (bytes memory) {
        (bytes32 x, bytes32 y) = _p256PubKey(pk);
        bytes memory authenticatorData = _webauthnAuthenticatorData(flags);
        string memory clientDataJSON = _webauthnClientDataJSON(abi.encode(hash));

        bytes32 msgHash = sha256(abi.encodePacked(authenticatorData, sha256(bytes(clientDataJSON))));
        (bytes32 r, bytes32 s) = vm.signP256(pk, msgHash);
        s = bytes32(Math.min(uint256(s), P256.N - uint256(s)));

        WebAuthn.WebAuthnAuth memory auth = WebAuthn.WebAuthnAuth({
            r: r,
            s: s,
            challengeIndex: 23,
            typeIndex: 1,
            authenticatorData: authenticatorData,
            clientDataJSON: clientDataJSON
        });
        return abi.encode(auth, x, y);
    }
}
