// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";
import {Scopes} from "../../../src/libraries/Scopes.sol";

/// @notice Local-channel epoch expiration: the epoch bump, the MAX-sentinel install channel, and the
///         non-admin actor epoch check at authentication.
contract EpochTest is AccountConfigurationTest {
    bytes32 constant EPOCH_BUMP_TYPEHASH = keccak256("SignedEpochBump(address account,uint256 chainId,uint24 epoch)");

    // ── Helpers ──

    /// @dev Admin-signed sequenced authorize of a scoped, optionally-expiring actor (installEpoch stamped from the
    ///      current epoch bound in the sequence).
    function _authorizeScoped(address account, uint256 adminPk, bytes32 actorId, uint16 scope, uint48 expiry) internal {
        AccountConfiguration.ActorChange[] memory ch = _scopedAuthorizeChange(actorId, scope, expiry);
        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, ch);
        accountConfiguration.applySignedActorChanges(
            account, uint64(block.chainid), seq, ch, _buildK1Auth(adminPk, digest)
        );
    }

    function _scopedAuthorizeChange(bytes32 actorId, uint16 scope, uint48 expiry)
        internal
        view
        returns (AccountConfiguration.ActorChange[] memory ch)
    {
        ch = new AccountConfiguration.ActorChange[](1);
        ch[0] = AccountConfiguration.ActorChange({
            actorId: actorId,
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: address(k1Authenticator), expiry: expiry, installEpoch: 0, scope: scope
                }),
                bytes("")
            )
        });
    }

    /// @dev The MAX-sentinel local sequence for `epoch`: epoch bits set, nonce == SEQUENCE_MASK (unordered channel).
    function _maxSentinelSeq(uint24 epoch) internal view returns (uint64) {
        return (uint64(epoch) << uint64(accountConfiguration.EPOCH_SHIFT())) | accountConfiguration.SEQUENCE_MASK();
    }

    function _installViaMaxSentinel(address account, uint256 adminPk, bytes32 actorId, uint16 scope, uint48 expiry)
        internal
    {
        AccountConfiguration.ActorChange[] memory ch = _scopedAuthorizeChange(actorId, scope, expiry);
        uint24 epoch = uint24(accountConfiguration.getChangeSequences(account).local >> 40);
        uint64 seq = _maxSentinelSeq(epoch);
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, ch);
        accountConfiguration.applySignedActorChanges(
            account, uint64(block.chainid), seq, ch, _buildK1Auth(adminPk, digest)
        );
    }

    function _bump(address account, uint256 adminPk, uint24 epoch) internal {
        bytes32 digest = keccak256(abi.encode(EPOCH_BUMP_TYPEHASH, account, block.chainid, epoch));
        accountConfiguration.applySignedEpochBump(account, epoch, _buildK1Auth(adminPk, digest));
    }

    // ── Actor epoch check ──

    /// @notice A non-admin actor authorized at epoch 0 stops authenticating after a bump (ActorEpochRevoked), while
    ///         the admin owner keeps authenticating (admins are exempt from the epoch check).
    function test_epochBump_revokesNonAdminActor_adminSurvives(uint256 ownerPk, uint256 actorPk, bytes32 hash) public {
        ownerPk = _boundK1Pk(ownerPk);
        actorPk = _boundK1Pk(actorPk);
        vm.assume(ownerPk != actorPk);
        (address account, bytes32 ownerId) = _createK1Account(ownerPk);
        bytes32 actorId = bytes32(bytes20(vm.addr(actorPk)));
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        _authorizeScoped(account, ownerPk, actorId, Scopes.SENDER, 0);

        // Live before the bump.
        (, uint16 scope,) = accountConfiguration.authenticateActor(account, hash, _buildK1Auth(actorPk, hash));
        assertEq(scope, Scopes.SENDER);

        _bump(account, ownerPk, 0);

        // The non-admin actor is now epoch-revoked; the admin still authenticates.
        vm.expectRevert(AccountConfiguration.ActorEpochRevoked.selector);
        accountConfiguration.authenticateActor(account, hash, _buildK1Auth(actorPk, hash));

        (, uint16 ownerScope,) = accountConfiguration.authenticateActor(account, hash, _buildK1Auth(ownerPk, hash));
        assertEq(ownerScope, 0);
    }

    /// @notice A non-admin actor authorized after the bump is stamped at the new epoch and authenticates.
    function test_epochBump_actorAuthorizedAtNewEpoch_isLive(uint256 ownerPk, uint256 actorPk, bytes32 hash) public {
        ownerPk = _boundK1Pk(ownerPk);
        actorPk = _boundK1Pk(actorPk);
        vm.assume(ownerPk != actorPk);
        (address account, bytes32 ownerId) = _createK1Account(ownerPk);
        bytes32 actorId = bytes32(bytes20(vm.addr(actorPk)));
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        _bump(account, ownerPk, 0);
        _authorizeScoped(account, ownerPk, actorId, Scopes.SENDER, 0);

        (, uint16 scope,) = accountConfiguration.authenticateActor(account, hash, _buildK1Auth(actorPk, hash));
        assertEq(scope, Scopes.SENDER);

        AccountConfiguration.ActorConfig memory cfg = accountConfiguration.getActorConfig(account, actorId);
        assertEq(cfg.installEpoch, 1);
    }

    /// @notice The inline secp256k1 self is exempt from the epoch check even when scoped (it carries no stamp), so a
    ///         bump driven by a separate admin does not revoke a scoped inline self.
    function test_epochBump_inlineScopedSelf_exempt(uint256 eoaPk, uint256 adminPk, bytes32 hash) public {
        eoaPk = _boundK1Pk(eoaPk);
        adminPk = _boundK1Pk(adminPk);
        vm.assume(eoaPk != adminPk);
        address eoa = vm.addr(eoaPk);
        bytes32 selfActorId = bytes32(bytes20(eoa));
        bytes32 adminId = bytes32(bytes20(vm.addr(adminPk)));
        vm.assume(adminId != selfActorId);

        // A separate k1 admin (signed by the implicit self), then scope the inline self down to SENDER.
        _authorizeScoped(eoa, eoaPk, adminId, 0, 0);
        _authorizeScoped(eoa, eoaPk, selfActorId, Scopes.SENDER, 0);

        // Bump via the separate admin. A stamped non-admin actor at epoch 0 would die; the inline self is exempt.
        _bump(eoa, adminPk, 0);

        (, uint16 scope,) = accountConfiguration.authenticateActor(eoa, hash, _buildK1Auth(eoaPk, hash));
        assertEq(scope, Scopes.SENDER);
    }

    // ── applySignedEpochBump ──

    /// @notice A successful bump advances the epoch, resets the nonce to 0, and emits EpochBumped.
    function test_epochBump_success_advancesEpochResetsNonce(uint256 ownerPk) public {
        ownerPk = _boundK1Pk(ownerPk);
        (address account,) = _createK1Account(ownerPk);

        // Consume a couple of nonces so the reset is observable.
        _authorizeScoped(account, ownerPk, bytes32(uint256(0xA11CE)), Scopes.SENDER, 0);
        assertEq(accountConfiguration.getChangeSequences(account).local & accountConfiguration.SEQUENCE_MASK(), 2);

        vm.expectEmit(true, false, false, true);
        emit AccountConfiguration.EpochBumped(account, 1);
        _bump(account, ownerPk, 0);

        uint64 local = accountConfiguration.getChangeSequences(account).local;
        assertEq(local >> 40, 1); // epoch advanced
        assertEq(local & accountConfiguration.SEQUENCE_MASK(), 0); // nonce reset
    }

    /// @notice A bump bound to a stale epoch reverts EpochMismatch, and a replay of a valid bump self-invalidates.
    function test_epochBump_revert_staleEpoch_andReplay(uint256 ownerPk) public {
        ownerPk = _boundK1Pk(ownerPk);
        (address account,) = _createK1Account(ownerPk);

        // Wrong epoch up front.
        bytes32 wrongDigest = keccak256(abi.encode(EPOCH_BUMP_TYPEHASH, account, block.chainid, uint24(5)));
        vm.expectRevert(AccountConfiguration.EpochMismatch.selector);
        accountConfiguration.applySignedEpochBump(account, 5, _buildK1Auth(ownerPk, wrongDigest));

        // Valid bump, then replay of the same (epoch 0) signature fails once the epoch is 1.
        bytes32 digest = keccak256(abi.encode(EPOCH_BUMP_TYPEHASH, account, block.chainid, uint24(0)));
        bytes memory auth = _buildK1Auth(ownerPk, digest);
        accountConfiguration.applySignedEpochBump(account, 0, auth);

        vm.expectRevert(AccountConfiguration.EpochMismatch.selector);
        accountConfiguration.applySignedEpochBump(account, 0, auth);
    }

    /// @notice Only an admin (scope 0) may bump; a non-admin signer reverts UnauthorizedActorChange.
    function test_epochBump_revert_nonAdminSigner(uint256 ownerPk, uint256 actorPk) public {
        ownerPk = _boundK1Pk(ownerPk);
        actorPk = _boundK1Pk(actorPk);
        vm.assume(ownerPk != actorPk);
        (address account, bytes32 ownerId) = _createK1Account(ownerPk);
        bytes32 actorId = bytes32(bytes20(vm.addr(actorPk)));
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        _authorizeScoped(account, ownerPk, actorId, Scopes.SENDER, 0);

        bytes32 digest = keccak256(abi.encode(EPOCH_BUMP_TYPEHASH, account, block.chainid, uint24(0)));
        vm.expectRevert(AccountConfiguration.UnauthorizedActorChange.selector);
        accountConfiguration.applySignedEpochBump(account, 0, _buildK1Auth(actorPk, digest));
    }

    /// @notice The bump is not gated by lock: it can only remove authority, so it succeeds while the account is locked.
    function test_epochBump_success_whileLocked(uint256 ownerPk) public {
        ownerPk = _boundK1Pk(ownerPk);
        (address account,) = _createK1Account(ownerPk);

        _signedLock(ownerPk, account, 3600);
        assertTrue(accountConfiguration.isLocked(account));

        _bump(account, ownerPk, 0);
        assertEq(accountConfiguration.getChangeSequences(account).local >> 40, 1);
    }

    // ── MAX-sentinel install channel ──

    /// @notice The MAX sentinel installs a scoped, expiring actor without consuming the ordered nonce.
    function test_maxSentinel_success_installsWithoutConsumingNonce(uint256 ownerPk, uint256 actorPk, bytes32 hash)
        public
    {
        ownerPk = _boundK1Pk(ownerPk);
        actorPk = _boundK1Pk(actorPk);
        vm.assume(ownerPk != actorPk);
        (address account, bytes32 ownerId) = _createK1Account(ownerPk);
        bytes32 actorId = bytes32(bytes20(vm.addr(actorPk)));
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        uint64 nonceBefore =
            accountConfiguration.getChangeSequences(account).local & accountConfiguration.SEQUENCE_MASK();
        _installViaMaxSentinel(account, ownerPk, actorId, Scopes.SENDER, uint48(block.timestamp + 1 days));
        uint64 nonceAfter =
            accountConfiguration.getChangeSequences(account).local & accountConfiguration.SEQUENCE_MASK();
        assertEq(nonceAfter, nonceBefore); // non-consuming

        (, uint16 scope,) = accountConfiguration.authenticateActor(account, hash, _buildK1Auth(actorPk, hash));
        assertEq(scope, Scopes.SENDER);
    }

    /// @notice The MAX sentinel is insert-only: it cannot overwrite a live actor.
    function test_maxSentinel_revert_overwriteExisting(uint256 ownerPk, uint256 actorPk) public {
        ownerPk = _boundK1Pk(ownerPk);
        actorPk = _boundK1Pk(actorPk);
        vm.assume(ownerPk != actorPk);
        (address account, bytes32 ownerId) = _createK1Account(ownerPk);
        bytes32 actorId = bytes32(bytes20(vm.addr(actorPk)));
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        _installViaMaxSentinel(account, ownerPk, actorId, Scopes.SENDER, uint48(block.timestamp + 1 days));

        AccountConfiguration.ActorChange[] memory ch =
            _scopedAuthorizeChange(actorId, Scopes.SENDER, uint48(block.timestamp + 2 days));
        uint64 seq = _maxSentinelSeq(0);
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, ch);
        bytes memory auth = _buildK1Auth(ownerPk, digest);
        vm.expectRevert(AccountConfiguration.InvalidMaxSentinelChange.selector);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), seq, ch, auth);
    }

    /// @notice The MAX sentinel rejects an admin (scope 0) actor: it is a non-admin-only install channel.
    function test_maxSentinel_revert_adminActor(uint256 ownerPk, bytes32 actorId) public {
        ownerPk = _boundK1Pk(ownerPk);
        (address account, bytes32 ownerId) = _createK1Account(ownerPk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        AccountConfiguration.ActorChange[] memory ch =
            _scopedAuthorizeChange(actorId, 0, uint48(block.timestamp + 1 days));
        uint64 seq = _maxSentinelSeq(0);
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, ch);
        bytes memory auth = _buildK1Auth(ownerPk, digest);
        vm.expectRevert(AccountConfiguration.InvalidMaxSentinelChange.selector);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), seq, ch, auth);
    }

    /// @notice The MAX sentinel rejects a non-expiring actor (expiry == 0): durable revocation must stay independent.
    function test_maxSentinel_revert_nonExpiringActor(uint256 ownerPk, bytes32 actorId) public {
        ownerPk = _boundK1Pk(ownerPk);
        (address account, bytes32 ownerId) = _createK1Account(ownerPk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        AccountConfiguration.ActorChange[] memory ch = _scopedAuthorizeChange(actorId, Scopes.SENDER, 0);
        uint64 seq = _maxSentinelSeq(0);
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, ch);
        bytes memory auth = _buildK1Auth(ownerPk, digest);
        vm.expectRevert(AccountConfiguration.InvalidMaxSentinelChange.selector);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), seq, ch, auth);
    }

    /// @notice The MAX sentinel rejects a revoke: it is an install-only channel.
    function test_maxSentinel_revert_revokeChange(uint256 ownerPk, uint256 actorPk) public {
        ownerPk = _boundK1Pk(ownerPk);
        actorPk = _boundK1Pk(actorPk);
        vm.assume(ownerPk != actorPk);
        (address account, bytes32 ownerId) = _createK1Account(ownerPk);
        bytes32 actorId = bytes32(bytes20(vm.addr(actorPk)));
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        _authorizeScoped(account, ownerPk, actorId, Scopes.SENDER, 0);

        AccountConfiguration.ActorChange[] memory ch = new AccountConfiguration.ActorChange[](1);
        ch[0] = AccountConfiguration.ActorChange({actorId: actorId, changeType: 0x02, data: ""});
        uint64 seq = _maxSentinelSeq(0);
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, ch);
        bytes memory auth = _buildK1Auth(ownerPk, digest);
        vm.expectRevert(AccountConfiguration.InvalidMaxSentinelChange.selector);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), seq, ch, auth);
    }

    /// @notice A MAX-sentinel actor is revoked by an epoch bump (its installEpoch goes stale), while an ordered
    ///         admin change still applies at the new epoch — the bump kills the pending fleet generation.
    function test_maxSentinel_revokedByBump(uint256 ownerPk, uint256 actorPk, bytes32 hash) public {
        ownerPk = _boundK1Pk(ownerPk);
        actorPk = _boundK1Pk(actorPk);
        vm.assume(ownerPk != actorPk);
        (address account, bytes32 ownerId) = _createK1Account(ownerPk);
        bytes32 actorId = bytes32(bytes20(vm.addr(actorPk)));
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        _installViaMaxSentinel(account, ownerPk, actorId, Scopes.SENDER, uint48(block.timestamp + 1 days));
        _bump(account, ownerPk, 0);

        vm.expectRevert(AccountConfiguration.ActorEpochRevoked.selector);
        accountConfiguration.authenticateActor(account, hash, _buildK1Auth(actorPk, hash));
    }

    // ── sequenced-path epoch binding ──

    /// @notice A sequenced actor change bound to a stale epoch reverts EpochMismatch after a bump.
    function test_sequenced_revert_staleEpochAfterBump(uint256 ownerPk, bytes32 actorId) public {
        ownerPk = _boundK1Pk(ownerPk);
        (address account, bytes32 ownerId) = _createK1Account(ownerPk);
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        // Pre-sign a sequenced change at epoch 0, nonce 1, then bump before relaying it.
        AccountConfiguration.ActorChange[] memory ch = _scopedAuthorizeChange(actorId, Scopes.SENDER, 0);
        uint64 staleSeq = accountConfiguration.getChangeSequences(account).local; // epoch 0, nonce 1
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), staleSeq, ch);
        bytes memory auth = _buildK1Auth(ownerPk, digest);

        _bump(account, ownerPk, 0);

        vm.expectRevert(AccountConfiguration.EpochMismatch.selector);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), staleSeq, ch, auth);
    }
}
