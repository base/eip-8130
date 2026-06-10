// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {IAccountConfiguration} from "../../../src/interfaces/IAccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract AuthenticateTest is AccountConfigurationTest {
    uint256 constant ACTOR_PK = 400;

    function test_authenticate_validK1() public {
        (address account,) = _createK1Account(ACTOR_PK);

        bytes32 hash = keccak256("authenticate me");
        bytes memory auth = _buildK1Auth(ACTOR_PK, hash);

        (uint8 scope,,) = accountConfiguration.authenticateActor(account, hash, auth);
        assertEq(scope, uint8(0x00));
    }

    function test_authenticate_wrongSignature() public {
        (address account,) = _createK1Account(ACTOR_PK);

        bytes32 hash = keccak256("authenticate me");
        // Sign with pk 999 — authenticator recovers wrong address, config mismatch
        bytes memory auth = _buildK1Auth(999, hash);

        vm.expectRevert();
        accountConfiguration.authenticateActor(account, hash, auth);
    }

    function test_authenticate_unregisteredActor() public {
        (address account,) = _createK1Account(ACTOR_PK);

        bytes32 hash = keccak256("authenticate me");
        // Sign with pk 999 (not registered on this account)
        bytes memory auth = _buildK1Auth(999, hash);

        vm.expectRevert();
        accountConfiguration.authenticateActor(account, hash, auth);
    }

    function test_authenticate_revokedActor() public {
        (address account,) = _createK1Account(ACTOR_PK);

        address newSigner = vm.addr(401);
        bytes32 newActorId = bytes32(bytes20(newSigner));
        _authorizeActor(account, ACTOR_PK, newActorId, address(k1Authenticator));

        _revokeActor(account, ACTOR_PK, newActorId);

        bytes32 hash = keccak256("after revoke");
        bytes memory revokedAuth = _buildK1Auth(401, hash);

        vm.expectRevert();
        accountConfiguration.authenticateActor(account, hash, revokedAuth);

        // Original actor should still work
        accountConfiguration.authenticateActor(account, hash, _buildK1Auth(ACTOR_PK, hash));
    }

    function test_authenticate_differentAccounts() public {
        (address account1,) = _createK1AccountWithSalt(ACTOR_PK, bytes32(uint256(1)));
        (address account2,) = _createK1AccountWithSalt(ACTOR_PK, bytes32(uint256(2)));

        bytes32 hash = keccak256("cross-account test");
        bytes memory auth = _buildK1Auth(ACTOR_PK, hash);

        accountConfiguration.authenticateActor(account1, hash, auth);
        accountConfiguration.authenticateActor(account2, hash, auth);
    }

    function test_authenticate_expiredActor_reverts() public {
        (address account,) = _createK1Account(ACTOR_PK);

        uint256 sessionPk = 401;
        bytes32 sessionActorId = bytes32(bytes20(vm.addr(sessionPk)));
        uint48 expiry = uint48(block.timestamp + 1 hours);
        _authorizeActorWithExpiry(account, ACTOR_PK, sessionActorId, address(k1Authenticator), expiry);

        bytes32 hash = keccak256("expiry test");

        // Before expiry: valid.
        accountConfiguration.authenticateActor(account, hash, _buildK1Auth(sessionPk, hash));

        // At expiry boundary (block.timestamp == expiry): still valid.
        vm.warp(expiry);
        accountConfiguration.authenticateActor(account, hash, _buildK1Auth(sessionPk, hash));

        // Past expiry: authentication fails.
        vm.warp(uint256(expiry) + 1);
        vm.expectRevert();
        accountConfiguration.authenticateActor(account, hash, _buildK1Auth(sessionPk, hash));
    }

    function test_authenticate_zeroExpiry_neverExpires() public {
        (address account,) = _createK1Account(ACTOR_PK);

        uint256 sessionPk = 401;
        bytes32 sessionActorId = bytes32(bytes20(vm.addr(sessionPk)));
        _authorizeActorWithExpiry(account, ACTOR_PK, sessionActorId, address(k1Authenticator), 0);

        bytes32 hash = keccak256("no expiry test");
        vm.warp(block.timestamp + 3650 days);
        accountConfiguration.authenticateActor(account, hash, _buildK1Auth(sessionPk, hash));
    }

    function test_getActorConfig_returnsAuthenticatorAndScopes() public {
        (address account, bytes32 actorId) = _createK1Account(ACTOR_PK);

        IAccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(account, actorId);
        assertEq(cfg.authenticator, address(k1Authenticator));
        assertEq(cfg.scope, 0x00);
    }

    function test_getActorConfig_returnsZeroForUnknownActor() public {
        (address account,) = _createK1Account(ACTOR_PK);

        bytes32 unknownActorId = bytes32(bytes20(vm.addr(999)));
        IAccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(account, unknownActorId);
        assertEq(cfg.authenticator, address(0));
        assertEq(cfg.scope, 0);
    }

    function test_authenticate_scopedActor_succeeds() public {
        (address account,) = _createK1Account(ACTOR_PK);

        address newSigner = vm.addr(401);
        bytes32 newActorId = bytes32(bytes20(newSigner));
        _authorizeActorWithScope(account, ACTOR_PK, newActorId, address(k1Authenticator), 0x01);

        bytes32 hash = keccak256("scoped authenticate");
        bytes memory auth = _buildK1Auth(401, hash);

        (uint8 scope,,) = accountConfiguration.authenticateActor(account, hash, auth);
        assertEq(scope, uint8(0x01));
    }

    function test_authenticate_unrestrictedScope() public {
        (address account,) = _createK1Account(ACTOR_PK);

        address newSigner = vm.addr(401);
        bytes32 newActorId = bytes32(bytes20(newSigner));
        _authorizeActorWithScope(account, ACTOR_PK, newActorId, address(k1Authenticator), 0x00);

        bytes32 hash = keccak256("unrestricted");
        bytes memory auth = _buildK1Auth(401, hash);

        (uint8 scope,,) = accountConfiguration.authenticateActor(account, hash, auth);
        assertEq(scope, uint8(0x00));
    }

    // ── Implicit EOA (registered by default) ──

    function test_authenticate_implicitEOA() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);

        bytes32 hash = keccak256("implicit eoa authenticate");
        bytes memory auth = _buildImplicitEOAAuth(eoaPk, hash);

        // No createAccount or importAccount — the EOA is implicitly authorized
        (uint8 scope,,) = accountConfiguration.authenticateActor(eoa, hash, auth);
        assertEq(scope, 0);
    }

    function test_authenticate_implicitEOA_isActorReturnsTrue() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);

        assertTrue(accountConfiguration.isActor(eoa, bytes32(bytes20(eoa))));
    }

    function test_authenticate_implicitEOA_nonSelfActorIdNotImplicit() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);

        // A random actorId that isn't bytes32(bytes20(eoa)) should NOT be implicit
        bytes32 randomActorId = bytes32(bytes20(vm.addr(999)));
        assertFalse(accountConfiguration.isActor(eoa, randomActorId));
    }

    function test_authenticate_implicitEOA_revokedBySentinel() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        // Implicit EOA signs to add a second key
        bytes32 newActorId = bytes32(bytes20(vm.addr(501)));
        _implicitAuthorizeActor(eoa, eoaPk, newActorId, address(k1Authenticator));

        // Revoke the self-actorId (writes sentinel) using the new explicit key
        _revokeActor(eoa, 501, selfActorId);

        assertFalse(accountConfiguration.isActor(eoa, selfActorId));

        // Implicit path is now blocked
        bytes32 hash = keccak256("after sentinel");
        vm.expectRevert();
        accountConfiguration.authenticateActor(eoa, hash, _buildImplicitEOAAuth(eoaPk, hash));
    }

    function test_authenticate_explicitEOA_selfActor() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));

        _implicitAuthorizeActor(eoa, eoaPk, selfActorId, accountConfiguration.ECRECOVER_AUTHENTICATOR());

        bytes32 hash = keccak256("explicit self-actor");
        (uint8 scope,,) = accountConfiguration.authenticateActor(eoa, hash, _buildExplicitEOAAuth(eoaPk, hash));
        assertEq(scope, 0);

        // Explicit self-actor registration disables implicit auth path.
        vm.expectRevert();
        accountConfiguration.authenticateActor(eoa, hash, _buildImplicitEOAAuth(eoaPk, hash));
    }

    function test_authenticate_explicitEOA_nonSelfActor() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);

        uint256 bobPk = 501;
        bytes32 bobActorId = bytes32(bytes20(vm.addr(bobPk)));
        _implicitAuthorizeActor(eoa, eoaPk, bobActorId, accountConfiguration.ECRECOVER_AUTHENTICATOR());

        bytes32 hash = keccak256("explicit non-self actor");
        (uint8 scope,,) = accountConfiguration.authenticateActor(eoa, hash, _buildExplicitEOAAuth(bobPk, hash));
        assertEq(scope, 0);
    }

    function test_authenticate_explicitEOA_unregisteredFails() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);

        bytes32 hash = keccak256("explicit unregistered");
        vm.expectRevert();
        accountConfiguration.authenticateActor(eoa, hash, _buildExplicitEOAAuth(eoaPk, hash));
    }

    function test_authenticate_revokedAuthenticatorPrefixReverts() public {
        uint256 eoaPk = 500;
        address eoa = vm.addr(eoaPk);

        bytes32 hash = keccak256("revoked authenticator prefix");
        bytes memory auth = abi.encodePacked(accountConfiguration.REVOKED_AUTHENTICATOR());

        vm.expectRevert();
        accountConfiguration.authenticateActor(eoa, hash, auth);
    }

    // ── Helpers ──

    function _authorizeActor(address account, uint256 pk, bytes32 newActorId, address authenticator) internal {
        _authorizeActorWithScope(account, pk, newActorId, authenticator, 0x00);
    }

    function _authorizeActorWithScope(
        address account,
        uint256 pk,
        bytes32 newActorId,
        address authenticator,
        uint8 scope
    ) internal {
        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({
                    authenticator: authenticator, scope: scope, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildK1Auth(pk, digest);

        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
    }

    function _authorizeActorWithExpiry(
        address account,
        uint256 pk,
        bytes32 newActorId,
        address authenticator,
        uint48 expiry
    ) internal {
        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({
                    authenticator: authenticator, scope: 0x00, expiry: expiry, policyType: 0x00
                }),
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

    function _implicitAuthorizeActor(address account, uint256 pk, bytes32 newActorId, address authenticator) internal {
        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({
                    authenticator: authenticator, scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        bytes memory auth = _buildImplicitEOAAuth(pk, digest);

        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), changes, auth);
    }

    function _authorizeGatedActor(
        address account,
        uint256 ownerPk,
        bytes32 newActorId,
        uint8 scope,
        uint8 policyType,
        address policyManager,
        bytes32 commitment
    ) internal {
        IAccountConfiguration.ActorChange[] memory changes = new IAccountConfiguration.ActorChange[](1);
        changes[0] = IAccountConfiguration.ActorChange({
            actorId: newActorId,
            changeType: 0x01,
            data: abi.encode(
                IAccountConfiguration.ActorConfig({
                    authenticator: address(k1Authenticator), scope: scope, expiry: 0, policyType: policyType
                }),
                abi.encodePacked(policyManager, commitment)
            )
        });

        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, changes);
        accountConfiguration.applySignedActorChanges(
            account, uint64(block.chainid), changes, _buildK1Auth(ownerPk, digest)
        );
    }

    /// @notice authenticate surfaces the actor's full authorization: scope, the reserved policyType byte, and the
    ///         resolved policy target (the manager); the commitment stays an execution-time read.
    function test_authenticate_returnsScopePolicyTypeAndTarget() public {
        (address account,) = _createK1Account(ACTOR_PK);

        uint256 sessionPk = 410;
        bytes32 sessionActorId = bytes32(bytes20(vm.addr(sessionPk)));
        address policyManager = address(0xB0B);
        _authorizeGatedActor(account, ACTOR_PK, sessionActorId, 0x02, 0x01, policyManager, keccak256("commit"));

        bytes32 hash = keccak256("gated authenticate");
        (uint8 scope, uint8 policyType, address policyTarget) =
            accountConfiguration.authenticateActor(account, hash, _buildK1Auth(sessionPk, hash));

        assertEq(scope, uint8(0x02));
        assertEq(policyType, uint8(0x01));
        assertEq(policyTarget, policyManager);
    }

    function test_authenticate_ungatedActorReturnsZeroPolicy() public {
        (address account,) = _createK1Account(ACTOR_PK);

        bytes32 hash = keccak256("ungated authenticate");
        (uint8 scope, uint8 policyType, address policyTarget) =
            accountConfiguration.authenticateActor(account, hash, _buildK1Auth(ACTOR_PK, hash));

        assertEq(scope, uint8(0x00));
        assertEq(policyType, uint8(0x00));
        assertEq(policyTarget, address(0));
    }
}
