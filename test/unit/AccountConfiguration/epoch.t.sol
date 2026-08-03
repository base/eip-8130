// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";
import {Scopes} from "../../../src/libraries/Scopes.sol";

/// @notice Local-channel epoch: the BUMP_EPOCH change type, the MAX-sentinel install channel, and the epoch's role as
///         a replay guard for install/change *signatures* (checked at the apply path, never at authentication).
contract EpochTest is AccountConfigurationTest {
    // ── Helpers ──

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
                    authenticator: address(k1Authenticator), expiry: expiry, scope: scope
                }),
                bytes("")
            )
        });
    }

    function _bumpChange() internal pure returns (AccountConfiguration.ActorChange memory) {
        return AccountConfiguration.ActorChange({actorId: bytes32(0), changeType: 0x03, data: ""});
    }

    /// @dev The MAX-sentinel local sequence for `epoch`: epoch bits set, nonce == SEQUENCE_MASK (unordered channel).
    function _maxSentinelSeq(uint24 epoch) internal view returns (uint64) {
        return (uint64(epoch) << uint64(accountConfiguration.EPOCH_SHIFT())) | accountConfiguration.SEQUENCE_MASK();
    }

    /// @dev Sign and relay `ch` at an explicit `seq`.
    function _applyAt(address account, uint256 adminPk, uint64 seq, AccountConfiguration.ActorChange[] memory ch)
        internal
    {
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, ch);
        accountConfiguration.applySignedActorChanges(
            account, uint64(block.chainid), seq, ch, _buildK1Auth(adminPk, digest)
        );
    }

    /// @dev Admin-signed sequenced authorize at the account's current local sequence.
    function _authorizeScoped(address account, uint256 adminPk, bytes32 actorId, uint16 scope, uint48 expiry) internal {
        _applyAt(
            account,
            adminPk,
            accountConfiguration.getChangeSequences(account).local,
            _scopedAuthorizeChange(actorId, scope, expiry)
        );
    }

    /// @dev Admin-signed sequenced bump at the account's current local sequence.
    function _bump(address account, uint256 adminPk) internal {
        AccountConfiguration.ActorChange[] memory ch = new AccountConfiguration.ActorChange[](1);
        ch[0] = _bumpChange();
        _applyAt(account, adminPk, accountConfiguration.getChangeSequences(account).local, ch);
    }

    function _epoch(address account) internal view returns (uint64) {
        return accountConfiguration.getChangeSequences(account).local >> 40;
    }

    function _nonce(address account) internal view returns (uint64) {
        return accountConfiguration.getChangeSequences(account).local & accountConfiguration.SEQUENCE_MASK();
    }

    // ── BUMP_EPOCH change type ──

    /// @notice A BUMP_EPOCH change advances the epoch, resets the nonce to 0, and emits EpochBumped.
    function test_bump_success_advancesEpochResetsNonce(uint256 ownerPk) public {
        ownerPk = _boundK1Pk(ownerPk);
        (address account,) = _createK1Account(ownerPk);

        // Consume a nonce so the reset is observable.
        _authorizeScoped(account, ownerPk, bytes32(uint256(0xA11CE)), Scopes.SENDER, 0);
        assertEq(_nonce(account), 2);

        vm.expectEmit(true, false, false, true);
        emit AccountConfiguration.EpochBumped(account, 1);
        _bump(account, ownerPk);

        assertEq(_epoch(account), 1); // epoch advanced
        assertEq(_nonce(account), 0); // nonce reset
    }

    /// @notice A bump batch is single-use: a replay binds the pre-bump epoch and now fails EpochMismatch.
    function test_bump_replay_selfInvalidates(uint256 ownerPk) public {
        ownerPk = _boundK1Pk(ownerPk);
        (address account,) = _createK1Account(ownerPk);

        AccountConfiguration.ActorChange[] memory ch = new AccountConfiguration.ActorChange[](1);
        ch[0] = _bumpChange();
        uint64 seq = accountConfiguration.getChangeSequences(account).local; // epoch 0, nonce 1
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, ch);
        bytes memory auth = _buildK1Auth(ownerPk, digest);

        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), seq, ch, auth);

        vm.expectRevert(AccountConfiguration.EpochMismatch.selector);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), seq, ch, auth);
    }

    /// @notice The epoch is never read at authentication: a live non-admin actor keeps authenticating across a bump.
    ///         A bump cancels pending signatures, not live agents.
    function test_bump_doesNotRevokeLiveActor(uint256 ownerPk, uint256 actorPk, bytes32 hash) public {
        ownerPk = _boundK1Pk(ownerPk);
        actorPk = _boundK1Pk(actorPk);
        vm.assume(ownerPk != actorPk);
        (address account, bytes32 ownerId) = _createK1Account(ownerPk);
        bytes32 actorId = bytes32(bytes20(vm.addr(actorPk)));
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        _authorizeScoped(account, ownerPk, actorId, Scopes.SENDER, 0);
        (, uint16 scope,) = accountConfiguration.authenticateActor(account, hash, _buildK1Auth(actorPk, hash));
        assertEq(scope, Scopes.SENDER);

        _bump(account, ownerPk);

        // Still live after the bump — no auth-time epoch check.
        (, uint16 scopeAfter,) = accountConfiguration.authenticateActor(account, hash, _buildK1Auth(actorPk, hash));
        assertEq(scopeAfter, Scopes.SENDER);
    }

    /// @notice [REVOKE_ACTOR(x), BUMP_EPOCH] in one signed batch: x is revoked AND its install signature is
    ///         permanently dead (a replay of the MAX-sentinel install bound to the old epoch fails EpochMismatch).
    function test_bump_atomicRevokeAndKillInstallSignature(uint256 ownerPk, uint256 actorPk, bytes32 hash) public {
        ownerPk = _boundK1Pk(ownerPk);
        actorPk = _boundK1Pk(actorPk);
        vm.assume(ownerPk != actorPk);
        (address account, bytes32 ownerId) = _createK1Account(ownerPk);
        bytes32 actorId = bytes32(bytes20(vm.addr(actorPk)));
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        // Install x via the MAX sentinel at epoch 0, keeping the reusable install signature to attempt a replay later.
        AccountConfiguration.ActorChange[] memory install =
            _scopedAuthorizeChange(actorId, Scopes.SENDER, uint48(block.timestamp + 365 days));
        uint64 maxSeq = _maxSentinelSeq(0);
        bytes32 installDigest = _computeActorChangeBatchDigest(account, uint64(block.chainid), maxSeq, install);
        bytes memory installAuth = _buildK1Auth(ownerPk, installDigest);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), maxSeq, install, installAuth);

        (, uint16 scope,) = accountConfiguration.authenticateActor(account, hash, _buildK1Auth(actorPk, hash));
        assertEq(scope, Scopes.SENDER);

        // Atomic [revoke(x), bump].
        AccountConfiguration.ActorChange[] memory batch = new AccountConfiguration.ActorChange[](2);
        batch[0] = AccountConfiguration.ActorChange({actorId: actorId, changeType: 0x02, data: ""});
        batch[1] = _bumpChange();
        _applyAt(account, ownerPk, accountConfiguration.getChangeSequences(account).local, batch);

        // x is gone.
        assertEq(_epoch(account), 1);
        vm.expectRevert(AccountConfiguration.AuthenticatorMismatch.selector);
        accountConfiguration.authenticateActor(account, hash, _buildK1Auth(actorPk, hash));

        // And x's original install signature can never re-install it: it binds the old epoch.
        vm.expectRevert(AccountConfiguration.EpochMismatch.selector);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), maxSeq, install, installAuth);
    }

    /// @notice BUMP_EPOCH rejects a non-empty data payload (InvalidBumpChange).
    function test_bump_revert_nonEmptyData(uint256 ownerPk) public {
        ownerPk = _boundK1Pk(ownerPk);
        (address account,) = _createK1Account(ownerPk);

        AccountConfiguration.ActorChange[] memory ch = new AccountConfiguration.ActorChange[](1);
        ch[0] = AccountConfiguration.ActorChange({actorId: bytes32(0), changeType: 0x03, data: hex"00"});
        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, ch);
        bytes memory auth = _buildK1Auth(ownerPk, digest);

        vm.expectRevert(AccountConfiguration.InvalidBumpChange.selector);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), seq, ch, auth);
    }

    /// @notice BUMP_EPOCH is local-channel only: a multichain (chainId 0) bump reverts InvalidBumpChange.
    function test_bump_revert_multichainChannel(uint256 ownerPk) public {
        ownerPk = _boundK1Pk(ownerPk);
        (address account,) = _createK1Account(ownerPk);

        AccountConfiguration.ActorChange[] memory ch = new AccountConfiguration.ActorChange[](1);
        ch[0] = _bumpChange();
        uint64 seq = accountConfiguration.getChangeSequences(account).multichain; // 0
        bytes32 digest = _computeActorChangeBatchDigest(account, 0, seq, ch);
        bytes memory auth = _buildK1Auth(ownerPk, digest);

        vm.expectRevert(AccountConfiguration.InvalidBumpChange.selector);
        accountConfiguration.applySignedActorChanges(account, 0, seq, ch, auth);
    }

    /// @notice BUMP_EPOCH is not permitted on the unordered MAX-sentinel path (InvalidMaxSentinelChange).
    function test_bump_revert_onMaxSentinel(uint256 ownerPk) public {
        ownerPk = _boundK1Pk(ownerPk);
        (address account,) = _createK1Account(ownerPk);

        AccountConfiguration.ActorChange[] memory ch = new AccountConfiguration.ActorChange[](1);
        ch[0] = _bumpChange();
        uint64 seq = _maxSentinelSeq(0);
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, ch);
        bytes memory auth = _buildK1Auth(ownerPk, digest);

        vm.expectRevert(AccountConfiguration.InvalidMaxSentinelChange.selector);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), seq, ch, auth);
    }

    /// @notice Only an admin (scope 0) may apply a batch containing a bump; a non-admin signer reverts.
    function test_bump_revert_nonAdminSigner(uint256 ownerPk, uint256 actorPk) public {
        ownerPk = _boundK1Pk(ownerPk);
        actorPk = _boundK1Pk(actorPk);
        vm.assume(ownerPk != actorPk);
        (address account, bytes32 ownerId) = _createK1Account(ownerPk);
        bytes32 actorId = bytes32(bytes20(vm.addr(actorPk)));
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        _authorizeScoped(account, ownerPk, actorId, Scopes.SENDER, 0);

        AccountConfiguration.ActorChange[] memory ch = new AccountConfiguration.ActorChange[](1);
        ch[0] = _bumpChange();
        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, ch);
        bytes memory auth = _buildK1Auth(actorPk, digest);

        vm.expectRevert(AccountConfiguration.UnauthorizedActorChange.selector);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), seq, ch, auth);
    }

    /// @notice A bump rides the ordered channel, so it obeys the lock: it is rejected while the account is locked.
    function test_bump_revert_whileLocked(uint256 ownerPk) public {
        ownerPk = _boundK1Pk(ownerPk);
        (address account,) = _createK1Account(ownerPk);

        _signedLock(ownerPk, account, 3600);
        assertTrue(accountConfiguration.isLocked(account));

        AccountConfiguration.ActorChange[] memory ch = new AccountConfiguration.ActorChange[](1);
        ch[0] = _bumpChange();
        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, ch);
        bytes memory auth = _buildK1Auth(ownerPk, digest);

        vm.expectRevert(AccountConfiguration.AccountIsLocked.selector);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), seq, ch, auth);
    }

    /// @notice A bump reverts EpochExhausted once the local epoch is already at type(uint24).max.
    function test_bump_revert_epochExhausted(uint256 ownerPk) public {
        ownerPk = _boundK1Pk(ownerPk);
        (address account,) = _createK1Account(ownerPk);

        // Force the local epoch to its maximum via direct storage write, preserving the nonce. _accountState is the
        // 4th declared mapping (slot 3); the whole AccountState struct packs into one slot, with localSequence at
        // bits [64:128).
        bytes32 slot = keccak256(abi.encode(account, uint256(3)));
        uint256 packed = uint256(vm.load(address(accountConfiguration), slot));
        uint64 nonce = uint64(packed >> 64) & accountConfiguration.SEQUENCE_MASK();
        uint64 newLocal = (uint64(type(uint24).max) << 40) | nonce;
        packed = (packed & ~(uint256(type(uint64).max) << 64)) | (uint256(newLocal) << 64);
        vm.store(address(accountConfiguration), slot, bytes32(packed));
        assertEq(_epoch(account), type(uint24).max);

        AccountConfiguration.ActorChange[] memory ch = new AccountConfiguration.ActorChange[](1);
        ch[0] = _bumpChange();
        uint64 seq = accountConfiguration.getChangeSequences(account).local;
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, ch);
        bytes memory auth = _buildK1Auth(ownerPk, digest);

        vm.expectRevert(AccountConfiguration.EpochExhausted.selector);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), seq, ch, auth);
    }

    // ── Sequenced-path epoch binding ──

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

        _bump(account, ownerPk);

        vm.expectRevert(AccountConfiguration.EpochMismatch.selector);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), staleSeq, ch, auth);
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

        uint64 nonceBefore = _nonce(account);
        AccountConfiguration.ActorChange[] memory ch =
            _scopedAuthorizeChange(actorId, Scopes.SENDER, uint48(block.timestamp + 1 days));
        _applyAt(account, ownerPk, _maxSentinelSeq(0), ch);
        assertEq(_nonce(account), nonceBefore); // non-consuming

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

        _applyAt(
            account,
            ownerPk,
            _maxSentinelSeq(0),
            _scopedAuthorizeChange(actorId, Scopes.SENDER, uint48(block.timestamp + 1 days))
        );

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

    /// @notice The MAX sentinel rejects a non-expiring actor (expiry == 0): durable revocation must stay independent
    ///         of the epoch brake, so a perpetual MAX install is disallowed.
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

    /// @notice A MAX-sentinel install signature bound to the old epoch dies after a bump (EpochMismatch), while the
    ///         already-installed live actor is untouched — the bump kills the pending fleet generation's signatures.
    function test_maxSentinel_installSignatureDiesAfterBump(uint256 ownerPk, uint256 actorPk, bytes32 hash) public {
        ownerPk = _boundK1Pk(ownerPk);
        actorPk = _boundK1Pk(actorPk);
        vm.assume(ownerPk != actorPk);
        (address account, bytes32 ownerId) = _createK1Account(ownerPk);
        bytes32 actorId = bytes32(bytes20(vm.addr(actorPk)));
        vm.assume(actorId != ownerId && actorId != bytes32(bytes20(account)));

        // Pre-sign a MAX install at epoch 0 but do not relay it yet.
        AccountConfiguration.ActorChange[] memory ch =
            _scopedAuthorizeChange(actorId, Scopes.SENDER, uint48(block.timestamp + 1 days));
        uint64 seq = _maxSentinelSeq(0);
        bytes32 digest = _computeActorChangeBatchDigest(account, uint64(block.chainid), seq, ch);
        bytes memory auth = _buildK1Auth(ownerPk, digest);

        _bump(account, ownerPk);

        // The pre-signed install now binds a stale epoch.
        vm.expectRevert(AccountConfiguration.EpochMismatch.selector);
        accountConfiguration.applySignedActorChanges(account, uint64(block.chainid), seq, ch, auth);
    }
}
