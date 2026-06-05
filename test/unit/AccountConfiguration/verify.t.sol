// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {IAccountConfiguration} from "../../../src/interfaces/IAccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract VerifyTest is AccountConfigurationTest {
    uint256 constant ACTOR_PK = 400;

    function test_verify_validK1() public {
        (address account,) = _createK1Account(ACTOR_PK);

        bytes32 hash = keccak256("verify me");
        bytes memory auth = _buildK1Auth(ACTOR_PK, hash);

        uint8 scope = accountConfiguration.verifyActor(account, hash, auth);
        assertEq(scope, uint8(0x00));
    }

    function test_verify_wrongSignature() public {
        (address account,) = _createK1Account(ACTOR_PK);

        bytes32 hash = keccak256("verify me");
        // Sign with pk 999 — verifier recovers wrong address, config mismatch
        bytes memory auth = _buildK1Auth(999, hash);

        vm.expectRevert();
        accountConfiguration.verifyActor(account, hash, auth);
    }

    function test_verify_unregisteredActor() public {
        (address account,) = _createK1Account(ACTOR_PK);

        bytes32 hash = keccak256("verify me");
        // Sign with pk 999 (not registered on this account)
        bytes memory auth = _buildK1Auth(999, hash);

        vm.expectRevert();
        accountConfiguration.verifyActor(account, hash, auth);
    }

    function test_verify_revokedActor() public {
        (address account,) = _createK1Account(ACTOR_PK);

        address newSigner = vm.addr(401);
        bytes32 newActorId = bytes32(bytes20(newSigner));
        _authorizeActor(account, ACTOR_PK, newActorId, address(k1Verifier));

        _revokeActor(account, ACTOR_PK, newActorId);

        bytes32 hash = keccak256("after revoke");
        bytes memory revokedAuth = _buildK1Auth(401, hash);

        vm.expectRevert();
        accountConfiguration.verifyActor(account, hash, revokedAuth);

        // Original actor should still work
        accountConfiguration.verifyActor(account, hash, _buildK1Auth(ACTOR_PK, hash));
    }

    function test_verify_differentAccounts() public {
        (address account1,) = _createK1AccountWithSalt(ACTOR_PK, bytes32(uint256(1)));
        (address account2,) = _createK1AccountWithSalt(ACTOR_PK, bytes32(uint256(2)));

        bytes32 hash = keccak256("cross-account test");
        bytes memory auth = _buildK1Auth(ACTOR_PK, hash);

        accountConfiguration.verifyActor(account1, hash, auth);
        accountConfiguration.verifyActor(account2, hash, auth);
    }

    function test_verify_expiredActor_reverts() public {
        (address account,) = _createK1Account(ACTOR_PK);

        uint256 sessionPk = 401;
        bytes32 sessionActorId = bytes32(bytes20(vm.addr(sessionPk)));
        uint48 expiry = uint48(block.timestamp + 1 hours);
        _authorizeActorWithExpiry(account, ACTOR_PK, sessionActorId, address(k1Verifier), expiry);

        bytes32 hash = keccak256("expiry test");

        // Before expiry: valid.
        accountConfiguration.verifyActor(account, hash, _buildK1Auth(sessionPk, hash));

        // At expiry boundary (block.timestamp == expiry): still valid.
        vm.warp(expiry);
        accountConfiguration.verifyActor(account, hash, _buildK1Auth(sessionPk, hash));

        // Past expiry: authentication fails.
        vm.warp(uint256(expiry) + 1);
        vm.expectRevert();
        accountConfiguration.verifyActor(account, hash, _buildK1Auth(sessionPk, hash));
    }

    function test_verify_zeroExpiry_neverExpires() public {
        (address account,) = _createK1Account(ACTOR_PK);

        uint256 sessionPk = 401;
        bytes32 sessionActorId = bytes32(bytes20(vm.addr(sessionPk)));
        _authorizeActorWithExpiry(account, ACTOR_PK, sessionActorId, address(k1Verifier), 0);

        bytes32 hash = keccak256("no expiry test");
        vm.warp(block.timestamp + 3650 days);
        accountConfiguration.verifyActor(account, hash, _buildK1Auth(sessionPk, hash));
    }

    function test_getActorConfig_returnsVerifierAndScopes() public {
        (address account, bytes32 actorId) = _createK1Account(ACTOR_PK);

        IAccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(account, actorId);
        assertEq(cfg.verifier, address(k1Verifier));
        assertEq(cfg.scope, 0x00);
    }

    function test_getActorConfig_returnsZeroForUnknownActor() public {
        (address account,) = _createK1Account(ACTOR_PK);

        bytes32 unknownActorId = bytes32(bytes20(vm.addr(999)));
        IAccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(account, unknownActorId);
        assertEq(cfg.verifier, address(0));
        assertEq(cfg.scope, 0);
    }

    function test_verify_scopedActor_succeeds() public {
        (address account,) = _createK1Account(ACTOR_PK);

        address newSigner = vm.addr(401);
        bytes32 newActorId = bytes32(bytes20(newSigner));
        _authorizeActorWithScope(account, ACTOR_PK, newActorId, address(k1Verifier), 0x01);

        bytes32 hash = keccak256("scoped verify");
        bytes memory auth = _buildK1Auth(401, hash);

        uint8 scope = accountConfiguration.verifyActor(account, hash, auth);
        assertEq(scope, uint8(0x01));
    }

    function test_verify_unrestrictedScope() public {
        (address account,) = _createK1Account(ACTOR_PK);

        address newSigner = vm.addr(401);
        bytes32 newActorId = bytes32(bytes20(newSigner));
        _authorizeActorWithScope(account, ACTOR_PK, newActorId, address(k1Verifier), 0x00);

        bytes32 hash = keccak256("unrestricted");
        bytes memory auth = _buildK1Auth(401, hash);

        uint8 scope = accountConfiguration.verifyActor(account, hash, auth);
        assertEq(scope, uint8(0x00));
    }

    // ── Implicit EOA (registered by default) ──

    function test_verify_implicitEOA() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);

        bytes32 hash = keccak256("implicit eoa verify");
        bytes memory auth = _buildImplicitEOAAuth(eoaPk, hash);

        // No createAccount or importAccount — the EOA is implicitly authorized
        uint8 scope = accountConfiguration.verifyActor(eoa, hash, auth);
        assertEq(scope, 0);
    }

    function test_verify_implicitEOA_isActorReturnsTrue() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);

        assertTrue(accountConfiguration.isActor(eoa, bytes32(bytes20(eoa))));
    }

    function test_verify_implicitEOA_nonSelfActorIdNotImplicit() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);

        // A random actorId that isn't bytes32(bytes20(eoa)) should NOT be implicit
        bytes32 randomActorId = bytes32(bytes20(vm.addr(999)));
        assertFalse(accountConfiguration.isActor(eoa, randomActorId));
    }

    function test_verify_implicitEOA_revokedBySentinel() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        // Implicit EOA signs to add a second key
        bytes32 newActorId = bytes32(bytes20(vm.addr(501)));
        _implicitAuthorizeActor(eoa, eoaPk, newActorId, address(k1Verifier));

        // Revoke the self-actorId (writes sentinel) using the new explicit key
        _revokeActor(eoa, 501, selfActorId);

        assertFalse(accountConfiguration.isActor(eoa, selfActorId));

        // Implicit path is now blocked
        bytes32 hash = keccak256("after sentinel");
        vm.expectRevert();
        accountConfiguration.verifyActor(eoa, hash, _buildImplicitEOAAuth(eoaPk, hash));
    }

    function test_verify_explicitEOA_selfActor() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        _implicitAuthorizeActor(eoa, eoaPk, selfActorId, accountConfiguration.ECRECOVER_VERIFIER());

        bytes32 hash = keccak256("explicit self-actor");
        uint8 scope = accountConfiguration.verifyActor(eoa, hash, _buildExplicitEOAAuth(eoaPk, hash));
        assertEq(scope, 0);

        // Explicit self-actor registration disables implicit auth path.
        vm.expectRevert();
        accountConfiguration.verifyActor(eoa, hash, _buildImplicitEOAAuth(eoaPk, hash));
    }

    function test_verify_explicitEOA_nonSelfActor() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);

        uint256 bobPk = 501;
        bytes32 bobActorId = bytes32(bytes20(vm.addr(bobPk)));
        _implicitAuthorizeActor(eoa, eoaPk, bobActorId, accountConfiguration.ECRECOVER_VERIFIER());

        bytes32 hash = keccak256("explicit non-self actor");
        uint8 scope = accountConfiguration.verifyActor(eoa, hash, _buildExplicitEOAAuth(bobPk, hash));
        assertEq(scope, 0);
    }

    function test_verify_explicitEOA_unregisteredFails() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);

        bytes32 hash = keccak256("explicit unregistered");
        vm.expectRevert();
        accountConfiguration.verifyActor(eoa, hash, _buildExplicitEOAAuth(eoaPk, hash));
    }

    function test_verify_revokedVerifierPrefixReverts() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);

        bytes32 hash = keccak256("revoked verifier prefix");
        bytes memory auth = abi.encodePacked(accountConfiguration.REVOKED_VERIFIER());

        vm.expectRevert();
        accountConfiguration.verifyActor(eoa, hash, auth);
    }

    // ── Helpers ──

    function _authorizeActor(address account, uint256 pk, bytes32 newActorId, address verifier) internal {
        _authorizeActorWithScope(account, pk, newActorId, verifier, 0x00);
    }

    function _authorizeActorWithScope(address account, uint256 pk, bytes32 newActorId, address verifier, uint8 scope)
        internal
    {
        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({verifier: verifier, scope: scope, expiry: 0, policyType: 0x00}),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(pk, digest);

        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
    }

    function _authorizeActorWithExpiry(address account, uint256 pk, bytes32 newActorId, address verifier, uint48 expiry)
        internal
    {
        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({verifier: verifier, scope: 0x00, expiry: expiry, policyType: 0x00}),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(pk, digest);

        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
    }

    function _revokeActor(address account, uint256 pk, bytes32 actorId) internal {
        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({actorId: actorId, changeType: 0x02, data: ""});

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(pk, digest);

        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
    }

    function _implicitAuthorizeActor(address account, uint256 pk, bytes32 newActorId, address verifier) internal {
        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({verifier: verifier, scope: 0x00, expiry: 0, policyType: 0x00}),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildImplicitEOAAuth(pk, digest);

        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
    }
}
