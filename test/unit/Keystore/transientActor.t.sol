// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {KeystoreTest} from "../../lib/KeystoreTest.sol";
import {Keystore} from "../../../src/Keystore.sol";
import {Scopes} from "../../../src/libraries/Scopes.sol";

/// @notice Tests for the transient (ephemeral) actor tier. A transient actor is installed by the
///         `AuthorizeTransientActor` signed account change — same payload shape as `AuthorizeActor`, authorized by
///         the batch's admin signature and the existing epoch/sequence machinery — and is written to EIP-1153
///         transient storage instead of being persisted. The unified read is persistent-first, transient-fallback,
///         so a transient actor is indistinguishable from a durable one for the rest of the transaction.
///
/// @dev Transient storage persists across external calls within a single test (one transaction), so an install in
///      one batch is resolvable by a later authenticate/read call in the same test.
contract TransientActorTest is KeystoreTest {
    uint256 constant ADMIN_PK = 0xA11CE;
    address account;
    uint256 constant LEAF_PK = 0xBEEF; // P-256 leaf key
    bytes32 leafActorId;

    function setUp() public override {
        super.setUp();
        vm.warp(1_000_000); // move off timestamp 1 so past-expiry values are non-zero (0 = no-expiry sentinel)
        (account,) = _createK1Account(ADMIN_PK);
        leafActorId = _p256ActorId(LEAF_PK);
    }

    /// @dev Install a transient P-256 leaf via an admin-signed local batch.
    function _installTransient(uint16 scope, uint48 expiry, bytes memory policy) internal {
        _applyLocal(
            ADMIN_PK,
            account,
            _one(_authorizeTransientChange(leafActorId, address(p256Authenticator), scope, expiry, policy))
        );
    }

    // ── install + resolution ──

    function test_install_resolvesAsActor() public {
        _installTransient(Scopes.OPERATOR, UNBOUNDED, "");
        Keystore.ActorConfig memory cfg = keystore.getActorConfig(account, leafActorId);
        assertEq(cfg.authenticator, address(p256Authenticator));
        assertEq(cfg.scope, Scopes.OPERATOR);
        assertEq(cfg.expiry, UNBOUNDED);
        assertTrue(_isActor(account, leafActorId));
    }

    function test_install_authenticates() public {
        _installTransient(Scopes.OPERATOR, UNBOUNDED, "");
        bytes32 digest = keccak256("some-op");
        bytes memory auth = abi.encodePacked(address(p256Authenticator), _p256SignData(LEAF_PK, digest));
        (bytes32 gotActorId, uint16 gotScope) = keystore.authenticateActor(account, digest, auth);
        assertEq(gotActorId, leafActorId);
        assertEq(gotScope, Scopes.OPERATOR);
    }

    function test_scopeIsExactlyAsSigned() public {
        // No attenuation: the actor carries exactly the scope the admin signed.
        _installTransient(Scopes.OPERATOR | Scopes.SELF_PAYER, UNBOUNDED, "");
        assertEq(keystore.getActorConfig(account, leafActorId).scope, Scopes.OPERATOR | Scopes.SELF_PAYER);
    }

    function test_notInstalled_doesNotAuthenticate() public {
        bytes32 digest = keccak256("some-op");
        bytes memory auth = abi.encodePacked(address(p256Authenticator), _p256SignData(LEAF_PK, digest));
        vm.expectRevert(Keystore.AuthenticatorMismatch.selector);
        keystore.authenticateActor(account, digest, auth);
    }

    function test_install_viaMultichainChannel() public {
        _applyMultichain(
            ADMIN_PK,
            account,
            _one(_authorizeTransientChange(leafActorId, address(p256Authenticator), Scopes.OPERATOR, UNBOUNDED, ""))
        );
        assertTrue(_isActor(account, leafActorId));
    }

    function test_install_viaUnsequencedBatch() public {
        _applyUnsequenced(
            ADMIN_PK,
            account,
            _one(_authorizeTransientChange(leafActorId, address(p256Authenticator), Scopes.OPERATOR, UNBOUNDED, ""))
        );
        assertTrue(_isActor(account, leafActorId));
    }

    /// @notice The motivating case: a reusable, all-chains install grant. A global (Multichain) JIT batch installs
    ///         the transient actor, consumes no counter, and is replayable on every chain until the global epoch moves.
    function test_install_viaGlobalUnsequenced_reusable() public {
        (, uint32 gSeqBefore) = _globalEpochSeq(account);
        _applyGlobalUnsequenced(
            ADMIN_PK,
            account,
            _one(_authorizeTransientChange(leafActorId, address(p256Authenticator), Scopes.OPERATOR, UNBOUNDED, ""))
        );
        assertTrue(_isActor(account, leafActorId));
        (, uint32 gSeqAfter) = _globalEpochSeq(account);
        assertEq(gSeqAfter, gSeqBefore); // reusable: no global counter burned
    }

    /// @notice A reusable (JIT) install of an already-expired grant is silently skipped, mirroring _applyAuthorize,
    ///         so a lapsed reusable grant cannot keep materializing an inert actor.
    function test_install_jitExpired_skipped() public {
        _applyGlobalUnsequenced(
            ADMIN_PK,
            account,
            _one(
                _authorizeTransientChange(
                    leafActorId, address(p256Authenticator), Scopes.OPERATOR, uint48(block.timestamp - 1), ""
                )
            )
        );
        assertFalse(_isActor(account, leafActorId));
    }

    function test_persistentWins_overTransient() public {
        // A durable actor at the leafActorId is never shadowed or downgraded by a transient install.
        _authorizeActorWithScope(account, ADMIN_PK, leafActorId, address(webAuthnAuthenticator), Scopes.SELF_PAYER);
        _installTransient(Scopes.OPERATOR, UNBOUNDED, "");

        Keystore.ActorConfig memory cfg = keystore.getActorConfig(account, leafActorId);
        assertEq(cfg.authenticator, address(webAuthnAuthenticator));
        assertEq(cfg.scope, Scopes.SELF_PAYER);
    }

    function test_expiredPersistent_shadowsTransient_onEveryRead() public {
        // An OCCUPIED-but-expired durable entry keeps the ephemeral tier shadowed on every surface, exactly as the
        // authentication path does. A transient twin must not resurrect (or re-scope) a lapsed durable actor.
        _applyLocal(
            ADMIN_PK,
            account,
            _one(
                _authorizeChange(
                    leafActorId, address(p256Authenticator), Scopes.SELF_PAYER, uint48(block.timestamp + 10), ""
                )
            )
        );
        vm.warp(block.timestamp + 100);
        _installTransient(0, UNBOUNDED, "");

        // Read surface: empty (expired durable entry wins).
        Keystore.ActorConfig memory cfg = keystore.getActorConfig(account, leafActorId);
        assertEq(cfg.authenticator, address(0));
        assertFalse(_isActor(account, leafActorId));
        (Keystore.ActorConfig memory cfg2, address mgr, bytes32 comm) =
            keystore.getActorWithPolicy(account, leafActorId);
        assertEq(cfg2.authenticator, address(0));
        assertEq(mgr, address(0));
        assertEq(comm, bytes32(0));

        // Authentication surface agrees: ActorExpired, not the transient twin.
        bytes32 digest = keccak256("op");
        bytes memory auth = abi.encodePacked(address(p256Authenticator), _p256SignData(LEAF_PK, digest));
        vm.expectRevert(Keystore.ActorExpired.selector);
        keystore.authenticateActor(account, digest, auth);
    }

    function test_expiredPersistentPolicy_notMixedWithTransientConfig() public {
        // Durable POLICY actor (manager M1) expires; a transient twin (manager M2) is installed. The read must not
        // pair one tier's config with the other tier's policy slots: the durable entry is occupied, so every surface
        // resolves empty.
        address m1 = address(0x1111);
        address m2 = address(0x2222);
        _applyLocal(
            ADMIN_PK,
            account,
            _one(
                _authorizeChange(
                    leafActorId,
                    address(p256Authenticator),
                    Scopes.POLICY,
                    uint48(block.timestamp + 10),
                    abi.encodePacked(m1, bytes32(uint256(1)))
                )
            )
        );
        vm.warp(block.timestamp + 100);
        _installTransient(Scopes.POLICY, UNBOUNDED, abi.encodePacked(m2, bytes32(uint256(2))));

        assertEq(keystore.getPolicyManager(account, leafActorId), address(0));
        assertEq(keystore.getPolicyCommitment(account, leafActorId), bytes32(0));
        (, address mgr, bytes32 comm) = keystore.getActorWithPolicy(account, leafActorId);
        assertEq(mgr, address(0));
        assertEq(comm, bytes32(0));
    }

    function test_revokedPersistent_unshadowsTransient() public {
        // Revoke empties the durable home, so a transient install for the same id is reachable again on both the
        // read and authentication surfaces (consistent occupancy rule).
        _authorizeActorWithScope(account, ADMIN_PK, leafActorId, address(p256Authenticator), Scopes.SELF_PAYER);
        _revokeActor(account, ADMIN_PK, leafActorId);
        _installTransient(Scopes.OPERATOR, UNBOUNDED, "");

        assertEq(keystore.getActorConfig(account, leafActorId).scope, Scopes.OPERATOR);
        bytes32 digest = keccak256("op");
        bytes memory auth = abi.encodePacked(address(p256Authenticator), _p256SignData(LEAF_PK, digest));
        (, uint16 scope) = keystore.authenticateActor(account, digest, auth);
        assertEq(scope, Scopes.OPERATOR);
    }

    // ── policy on a transient actor ──

    function test_transientPolicy_resolves() public {
        address manager = address(0xA9A9A9);
        bytes32 commitment = keccak256("policy-params");
        bytes memory policy = abi.encodePacked(manager, commitment);

        _installTransient(Scopes.POLICY, UNBOUNDED, policy);

        (Keystore.ActorConfig memory cfg, address gotManager, bytes32 gotCommitment) =
            keystore.getActorWithPolicy(account, leafActorId);
        assertEq(cfg.scope, Scopes.POLICY);
        assertEq(gotManager, manager);
        assertEq(gotCommitment, commitment);
        assertEq(keystore.getPolicyManager(account, leafActorId), manager);
        assertEq(keystore.getPolicyCommitment(account, leafActorId), commitment);
    }

    // ── expiry ──

    function test_expiredLeaf_readsInert() public {
        _installTransient(Scopes.OPERATOR, uint48(block.timestamp - 1), "");
        assertFalse(_isActor(account, leafActorId));
        assertEq(keystore.getActorConfig(account, leafActorId).authenticator, address(0));
    }

    function test_liveLeaf_untilExpiry() public {
        _installTransient(Scopes.OPERATOR, uint48(block.timestamp + 1 hours), "");
        assertTrue(_isActor(account, leafActorId));
        vm.warp(block.timestamp + 2 hours);
        assertFalse(_isActor(account, leafActorId));
    }

    // ── reverts ──

    function test_revert_selfActorForbidden() public {
        bytes32 selfId = bytes32(uint256(uint160(account)));
        Keystore.SignedAccountChanges memory batch = _localBatch(
            ADMIN_PK,
            account,
            _one(_authorizeTransientChange(selfId, address(p256Authenticator), Scopes.OPERATOR, UNBOUNDED, ""))
        );
        vm.expectRevert(Keystore.TransientSelfActorForbidden.selector);
        keystore.applySignedAccountChanges(account, batch);
    }

    function test_revert_zeroActorId() public {
        Keystore.SignedAccountChanges memory batch = _localBatch(
            ADMIN_PK,
            account,
            _one(_authorizeTransientChange(bytes32(0), address(p256Authenticator), Scopes.OPERATOR, UNBOUNDED, ""))
        );
        vm.expectRevert(Keystore.InvalidActorId.selector);
        keystore.applySignedAccountChanges(account, batch);
    }

    function test_revert_zeroAuthenticator() public {
        Keystore.SignedAccountChanges memory batch = _localBatch(
            ADMIN_PK, account, _one(_authorizeTransientChange(leafActorId, address(0), Scopes.OPERATOR, UNBOUNDED, ""))
        );
        vm.expectRevert(Keystore.InvalidAuthenticator.selector);
        keystore.applySignedAccountChanges(account, batch);
    }

    function test_revert_badPolicyLength() public {
        Keystore.SignedAccountChanges memory batch = _localBatch(
            ADMIN_PK,
            account,
            _one(
                _authorizeTransientChange(leafActorId, address(p256Authenticator), Scopes.POLICY, UNBOUNDED, hex"1234")
            )
        );
        vm.expectRevert(Keystore.InvalidPolicyData.selector);
        keystore.applySignedAccountChanges(account, batch);
    }

    function test_revert_whenLocked() public {
        _lockAccount(ADMIN_PK, account);
        Keystore.SignedAccountChanges memory batch = _localBatch(
            ADMIN_PK,
            account,
            _one(_authorizeTransientChange(leafActorId, address(p256Authenticator), Scopes.OPERATOR, UNBOUNDED, ""))
        );
        vm.expectRevert(Keystore.AccountIsLocked.selector);
        keystore.applySignedAccountChanges(account, batch);
    }

    function test_revert_nonAdminSigner() public {
        // A scoped (non-admin) actor cannot authorize account changes, including a transient install.
        uint256 scopedPk = 0xC0FFEE;
        bytes32 scopedActorId = bytes32(uint256(uint160(vm.addr(scopedPk))));
        _authorizeActorWithScope(account, ADMIN_PK, scopedActorId, k1Authenticator, Scopes.OPERATOR);

        Keystore.SignedAccountChanges memory batch = _localBatch(
            scopedPk,
            account,
            _one(_authorizeTransientChange(leafActorId, address(p256Authenticator), Scopes.OPERATOR, UNBOUNDED, ""))
        );
        vm.expectRevert(Keystore.UnauthorizedAccountChange.selector);
        keystore.applySignedAccountChanges(account, batch);
    }

    // ── event ──

    function test_emitsTransientActorInstalled() public {
        bytes memory expectedData =
            abi.encodePacked(address(p256Authenticator), UNBOUNDED, uint16(Scopes.OPERATOR), bytes4(0));
        vm.expectEmit(true, true, true, true, address(keystore));
        emit Keystore.TransientActorInstalled(account, leafActorId, expectedData);
        _installTransient(Scopes.OPERATOR, UNBOUNDED, "");
    }
}
