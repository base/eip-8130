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

    bytes32 constant SIGNED_ACCOUNT_CHANGES_TYPEHASH = keccak256(
        "SignedAccountChanges(address account,uint256 chainId,uint64 sequence,AccountChange[] changes)"
        "AccountChange(uint8 changeType,bytes payload)"
    );

    bytes32 constant ACCOUNT_CHANGE_TYPEHASH = keccak256("AccountChange(uint8 changeType,bytes payload)");

    /// @dev Unbounded expiry sentinel: an unbounded (never-expiring) grant is expressed as this value and is only
    ///      permitted on a sequenced batch. Convenience helpers that stand in for the old "no expiry" actors grant
    ///      this so they never trip the ExpiredChange fence (a signed grant always self-expires).
    uint48 constant UNBOUNDED = type(uint48).max;

    function setUp() public virtual {
        keystore = new Keystore();
        k1Authenticator = keystore.K1_AUTHENTICATOR();
        p256Authenticator = IAuthenticator(new P256Authenticator());
        webAuthnAuthenticator = IAuthenticator(new WebAuthnAuthenticator());
        delegateAuthenticator = IAuthenticator(new DelegateAuthenticator(address(keystore)));
        defaultAccountImplementation = address(new DefaultAccount(address(keystore)));
    }

    // ── Actor liveness helper ──

    /// @dev Liveness check via the public getActorConfig (authenticator != 0). Expiry-aware: getActorConfig resolves
    ///      an expired, revoked, or disabled actor to the all-zero config.
    function _isActor(address account, bytes32 actorId) internal view returns (bool) {
        return keystore.getActorConfig(account, actorId).authenticator != address(0);
    }

    // ── Bytecode helpers ──

    function _computeERC1167Bytecode(address implementation) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"363d3d373d3d3d363d73", implementation, hex"5af43d82803e903d91602b57fd5bf3");
    }

    // ── Account creation helpers ──

    function _createK1Account(uint256 pk) internal returns (address account, bytes32 actorId) {
        address signer = vm.addr(pk);
        actorId = bytes32(uint256(uint160(signer)));

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](1);
        actors[0] = Keystore.InitialActor({
            actorId: actorId, authenticator: address(k1Authenticator), scope: 0, policyData: ""
        });

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        account = keystore.createAccount(bytes32(0), bytecode, actors);
    }

    function _createK1AccountWithSalt(uint256 pk, bytes32 salt) internal returns (address account, bytes32 actorId) {
        address signer = vm.addr(pk);
        actorId = bytes32(uint256(uint160(signer)));

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

    // ── Sequence-word helpers ──

    /// @dev The account's current local sequence WORD (localEpoch(32) || localSequence(32)) for a sequenced batch.
    function _localSeqWord(address account) internal view returns (uint64) {
        Keystore.ChangeSequences memory cs = keystore.getChangeSequences(account);
        return (uint64(cs.localEpoch) << 32) | uint64(cs.localSequence);
    }

    /// @dev An unsequenced (JIT) local sequence word at the account's current epoch: epoch || UNSEQUENCED.
    function _unseqWord(address account) internal view returns (uint64) {
        return (uint64(keystore.getChangeSequences(account).localEpoch) << 32) | uint64(keystore.UNSEQUENCED());
    }

    /// @dev The account's current multichain sequence.
    function _multichainSeq(address account) internal view returns (uint64) {
        return keystore.getChangeSequences(account).multichain;
    }

    /// @dev The account's current local epoch and local sequence (split), for terse test assertions.
    function _localEpochSeq(address account) internal view returns (uint32 epoch, uint32 sequence) {
        Keystore.ChangeSequences memory cs = keystore.getChangeSequences(account);
        return (cs.localEpoch, cs.localSequence);
    }

    // ── Change builders ──

    function _authorizeChange(bytes32 actorId, address auth, uint16 scope, uint48 expiry, bytes memory policyData)
        internal
        pure
        returns (Keystore.AccountChange memory)
    {
        return Keystore.AccountChange({
            changeType: Keystore.ChangeType.AuthorizeActor,
            payload: abi.encode(
                actorId, Keystore.ActorConfig({authenticator: auth, scope: scope, expiry: expiry}), policyData
            )
        });
    }

    function _revokeChange(bytes32 actorId) internal pure returns (Keystore.AccountChange memory) {
        return Keystore.AccountChange({changeType: Keystore.ChangeType.RevokeActor, payload: abi.encode(actorId)});
    }

    function _bumpChange() internal pure returns (Keystore.AccountChange memory) {
        return Keystore.AccountChange({changeType: Keystore.ChangeType.IncrementLocalEpoch, payload: ""});
    }

    function _lockChange(uint16 unlockDelay) internal pure returns (Keystore.AccountChange memory) {
        return Keystore.AccountChange({changeType: Keystore.ChangeType.Lock, payload: abi.encode(unlockDelay)});
    }

    function _unlockChange() internal pure returns (Keystore.AccountChange memory) {
        return Keystore.AccountChange({changeType: Keystore.ChangeType.Unlock, payload: ""});
    }

    /// @dev Wrap a single change into a one-element array.
    function _one(Keystore.AccountChange memory c) internal pure returns (Keystore.AccountChange[] memory arr) {
        arr = new Keystore.AccountChange[](1);
        arr[0] = c;
    }

    // ── Canonical digest computation (mirrors Keystore._changesDigest) ──

    function _changesDigest(
        address account,
        Keystore.AccountChangeChannel channel,
        uint64 sequence,
        Keystore.AccountChange[] memory changes
    ) internal view returns (bytes32) {
        uint256 chainId = channel == Keystore.AccountChangeChannel.Multichain ? 0 : block.chainid;
        bytes32[] memory changeHashes = new bytes32[](changes.length);
        for (uint256 i; i < changes.length; i++) {
            changeHashes[i] = keccak256(
                abi.encode(ACCOUNT_CHANGE_TYPEHASH, uint8(changes[i].changeType), keccak256(changes[i].payload))
            );
        }
        return keccak256(
            abi.encode(
                SIGNED_ACCOUNT_CHANGES_TYPEHASH, account, chainId, sequence, keccak256(abi.encodePacked(changeHashes))
            )
        );
    }

    // ── Signed batch construction (K1) ──

    /// @dev Build a fully-signed batch for `channel`/`sequence`, K1-signed by `pk`.
    function _signBatch(
        uint256 pk,
        address account,
        Keystore.AccountChangeChannel channel,
        uint64 sequence,
        Keystore.AccountChange[] memory changes
    ) internal view returns (Keystore.SignedAccountChanges memory) {
        bytes32 digest = _changesDigest(account, channel, sequence, changes);
        return Keystore.SignedAccountChanges({
            channel: channel, sequence: sequence, changes: changes, signature: _buildK1Auth(pk, digest)
        });
    }

    /// @dev Build + relay a sequenced local batch at the account's current sequence word, K1-signed by `pk`.
    function _applyLocal(uint256 pk, address account, Keystore.AccountChange[] memory changes) internal {
        keystore.applySignedAccountChanges(
            account, _signBatch(pk, account, Keystore.AccountChangeChannel.Local, _localSeqWord(account), changes)
        );
    }

    /// @dev Build + relay an unsequenced (JIT) local batch at the account's current epoch, K1-signed by `pk`.
    function _applyUnsequenced(uint256 pk, address account, Keystore.AccountChange[] memory changes) internal {
        keystore.applySignedAccountChanges(
            account, _signBatch(pk, account, Keystore.AccountChangeChannel.Local, _unseqWord(account), changes)
        );
    }

    /// @dev Build + relay a multichain batch at the account's current multichain sequence, K1-signed by `pk`.
    function _applyMultichain(uint256 pk, address account, Keystore.AccountChange[] memory changes) internal {
        keystore.applySignedAccountChanges(
            account, _signBatch(pk, account, Keystore.AccountChangeChannel.Multichain, _multichainSeq(account), changes)
        );
    }

    // ── Pre-built (unrelayed) batches ──
    //
    // These build the fully-signed batch WITHOUT relaying it, so revert tests can construct the batch (which reads
    // the current sequence word via a view staticcall) BEFORE `vm.expectRevert`, then relay it as the single
    // expected-reverting external call. Foundry's strict expectRevert binds to the very next external call, so the
    // sequence-word staticcall must not sit between expectRevert and applySignedAccountChanges.

    function _localBatch(uint256 pk, address account, Keystore.AccountChange[] memory changes)
        internal
        view
        returns (Keystore.SignedAccountChanges memory)
    {
        return _signBatch(pk, account, Keystore.AccountChangeChannel.Local, _localSeqWord(account), changes);
    }

    function _unseqBatch(uint256 pk, address account, Keystore.AccountChange[] memory changes)
        internal
        view
        returns (Keystore.SignedAccountChanges memory)
    {
        return _signBatch(pk, account, Keystore.AccountChangeChannel.Local, _unseqWord(account), changes);
    }

    function _multichainBatch(uint256 pk, address account, Keystore.AccountChange[] memory changes)
        internal
        view
        returns (Keystore.SignedAccountChanges memory)
    {
        return _signBatch(pk, account, Keystore.AccountChangeChannel.Multichain, _multichainSeq(account), changes);
    }

    // ── Back-compat actor helpers (re-implemented on applySignedAccountChanges) ──
    //
    // These preserve the pre-split helper names used across the suite. A signed grant always self-expires, so where
    // the old model used a no-expiry (0) actor these grant UNBOUNDED (type(uint48).max) on a sequenced batch — the
    // same never-expiring behavior, expressed the new way.

    function _authorizeActor(address account, uint256 pk, bytes32 actorId, address authenticator) internal {
        _authorizeActorWithScope(account, pk, actorId, authenticator, 0);
    }

    function _authorizeActorWithScope(address account, uint256 pk, bytes32 actorId, address authenticator, uint16 scope)
        internal
    {
        _applyLocal(pk, account, _one(_authorizeChange(actorId, authenticator, scope, UNBOUNDED, "")));
    }

    function _revokeActor(address account, uint256 pk, bytes32 actorId) internal {
        // A bare (sequenced) revoke lands on its own; durable teardown against outstanding grants is a separate bump.
        _applyLocal(pk, account, _one(_revokeChange(actorId)));
    }

    // Implicit-EOA variants are identical here (the same k1 signer path); kept as named aliases for readability.
    function _implicitAuthorizeActor(address account, uint256 pk, bytes32 actorId, address authenticator) internal {
        _authorizeActor(account, pk, actorId, authenticator);
    }

    function _implicitAuthorizeActorWithScope(
        address account,
        uint256 pk,
        bytes32 actorId,
        address authenticator,
        uint16 scope
    ) internal {
        _authorizeActorWithScope(account, pk, actorId, authenticator, scope);
    }

    // ── Signed lock helpers (re-implemented as environment-op batches) ──

    /// @dev Relay a signed Lock (unlockDelay) authorized by `pk` on the local channel.
    function _signedLock(uint256 pk, address account, uint16 unlockDelay) internal {
        _applyLocal(pk, account, _one(_lockChange(unlockDelay)));
    }

    /// @dev Relay a signed Unlock authorized by `pk` on the local channel.
    function _signedUnlock(uint256 pk, address account) internal {
        _applyLocal(pk, account, _one(_unlockChange()));
    }

    /// @dev Hard-lock `account` via the signed lock path, authorized by its admin owner key `pk`.
    function _lockAccount(uint256 pk, address account) internal {
        _signedLock(pk, account, 1 hours);
    }

    // ── Direct AccountState storage pokes (for saturation edge cases) ──
    //
    // AccountState packs into one slot at base-slot 3 (declaration order: _actorConfig, _policyCommitment,
    // _policyManager, _accountState). multichainSequence occupies bytes[0:8] and localSequence bytes[8:16] of that
    // slot; localSequence's high 32 bits are the epoch, its low 32 bits the sequence.

    function _accountStateSlot(address account) internal pure returns (bytes32) {
        return keccak256(abi.encode(account, uint256(3)));
    }

    /// @dev Overwrite the packed localSequence word (epoch<<32 | seq), preserving every other field in the slot.
    function _forceLocalWord(address account, uint64 word) internal {
        bytes32 slot = _accountStateSlot(account);
        uint256 cur = uint256(vm.load(address(keystore), slot));
        // Clear bytes[8:16] (bits 64..127) and write the new word there.
        uint256 mask = ~(uint256(type(uint64).max) << 64);
        uint256 updated = (cur & mask) | (uint256(word) << 64);
        vm.store(address(keystore), slot, bytes32(updated));
    }

    /// @dev Force the account's local epoch (high 32 bits), keeping the current low sequence.
    function _forceLocalEpoch(address account, uint32 epoch) internal {
        uint32 seq = keystore.getChangeSequences(account).localSequence;
        _forceLocalWord(account, (uint64(epoch) << 32) | uint64(seq));
    }

    /// @dev Force the account's local sequence (low 32 bits), keeping the current epoch.
    function _forceLocalSequence(address account, uint32 seq) internal {
        uint32 epoch = keystore.getChangeSequences(account).localEpoch;
        _forceLocalWord(account, (uint64(epoch) << 32) | uint64(seq));
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
