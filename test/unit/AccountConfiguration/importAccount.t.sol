// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

/// @dev Minimal ERC-1271 wallet that validates an owner ECDSA signature over the presented hash. Returns the
///      0x1626ba7e magic for a valid owner signature and 0xFFFFFFFF otherwise (the wrong-selector branch).
contract MockERC1271Wallet {
    address public immutable owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        if (ECDSA.recover(hash, signature) == owner) return 0x1626ba7e;
        return 0xFFFFFFFF;
    }
}

/// @dev ERC-1271 wallet whose isValidSignature always reverts. Drives the `!success` term of the import
///      signature predicate (staticcall fails).
contract RevertingERC1271Wallet {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        revert("no");
    }
}

/// @dev ERC-1271 wallet that returns non-32-byte returndata (4 bytes here, containing the magic). Drives the
///      `result.length != 32` term even though the leading word would decode to the magic.
contract ShortReturnERC1271Wallet {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        assembly ("memory-safe") {
            mstore(0x00, 0x1626ba7e00000000000000000000000000000000000000000000000000000000)
            return(0x00, 4)
        }
    }
}

/// @dev Fully fuzzed, branch-complete suite for AccountConfiguration.importAccount and the pure digest machinery it
///      drives (_computeImportDigest), plus the _initializeAccount reverts it inherits. Reverts are ordered to
///      mirror importAccount's source control flow (onlyUnlocked → InvalidChainId → AlreadyInitialized →
///      InvalidImportSignature → _initializeAccount reverts); happy/branch paths follow.
contract ImportAccountTest is AccountConfigurationTest {
    // ERC-1271 magic value (matches AccountConfiguration.ERC1271_SELECTOR).
    bytes4 constant ERC1271_MAGIC = 0x1626ba7e;

    // Independent reimplementation of the contract's typed import digest (see _computeImportDigest). The digest
    // retains the full Actor/ActorConfig typehash structure; for imported (always unrestricted) actors the config
    // fields are zero and policyData is empty.
    bytes32 constant ACTOR_INITIALIZATION_TYPEHASH = keccak256(
        "ActorInitialization(bytes32 salt,uint256 chainId,Actor[] initialActors)Actor(bytes32 actorId,ActorConfig config,bytes policyData)ActorConfig(address authenticator,uint8 scope,uint48 expiry,uint8 policyType)"
    );
    bytes32 constant ACTOR_TYPEHASH = keccak256(
        "Actor(bytes32 actorId,ActorConfig config,bytes policyData)ActorConfig(address authenticator,uint8 scope,uint48 expiry,uint8 policyType)"
    );
    bytes32 constant ACTORCONFIG_TYPEHASH =
        keccak256("ActorConfig(address authenticator,uint8 scope,uint48 expiry,uint8 policyType)");

    // ── digest helpers ──

    /// @dev Convenience: bind the digest to the current chain (the common per-chain import).
    function _computeImportDigest(address account, AccountConfiguration.InitialActor[] memory initialActors)
        internal
        view
        returns (bytes32)
    {
        return _computeImportDigest(account, block.chainid, initialActors);
    }

    function _computeImportDigest(
        address account,
        uint256 chainId,
        AccountConfiguration.InitialActor[] memory initialActors
    ) internal pure returns (bytes32) {
        bytes32[] memory actorHashes = new bytes32[](initialActors.length);
        for (uint256 i; i < initialActors.length; i++) {
            bytes32 configHash = keccak256(
                abi.encode(ACTORCONFIG_TYPEHASH, initialActors[i].authenticator, uint8(0), uint48(0), uint8(0))
            );
            actorHashes[i] = keccak256(abi.encode(ACTOR_TYPEHASH, initialActors[i].actorId, configHash, keccak256("")));
        }
        return keccak256(
            abi.encode(
                ACTOR_INITIALIZATION_TYPEHASH,
                bytes32(bytes20(account)),
                chainId,
                keccak256(abi.encodePacked(actorHashes))
            )
        );
    }

    // ── actor-set builders ──

    function _singleUnrestrictedActor(address signer)
        internal
        view
        returns (AccountConfiguration.InitialActor[] memory actors)
    {
        actors = new AccountConfiguration.InitialActor[](1);
        actors[0] = AccountConfiguration.InitialActor({
            actorId: bytes32(bytes20(signer)), authenticator: address(k1Authenticator)
        });
    }

    /// @dev A strictly-ascending k1 actor set of `count` address-shaped actorIds (mirroring a real k1 actorId =
    ///      bytes32(bytes20(signer))). Ascending uint160 base+i maps to ascending bytes32, so no sort is needed.
    function _ascendingK1Actors(uint256 count, uint256 base)
        internal
        view
        returns (AccountConfiguration.InitialActor[] memory actors)
    {
        actors = new AccountConfiguration.InitialActor[](count);
        for (uint256 i; i < count; i++) {
            actors[i] = AccountConfiguration.InitialActor({
                actorId: bytes32(bytes20(address(uint160(base + i)))), authenticator: address(k1Authenticator)
            });
        }
    }

    /// @dev chainId is fuzzed over its two accepted domains: 0 (multichain) or the current chain (local).
    function _acceptedChainId(bool multichain) internal view returns (uint256) {
        return multichain ? 0 : block.chainid;
    }

    /// @dev Deploy a MockERC1271Wallet owned by vm.addr(ownerPk) and return it with a valid import signature over the
    ///      given actors/chainId. The signature is a raw 65-byte r‖s‖v ECDSA blob (what ERC-1271 recover expects).
    function _walletAndSig(uint256 ownerPk, uint256 chainId, AccountConfiguration.InitialActor[] memory actors)
        internal
        returns (MockERC1271Wallet wallet, bytes memory sig)
    {
        wallet = new MockERC1271Wallet(vm.addr(ownerPk));
        bytes32 digest = _computeImportDigest(address(wallet), chainId, actors);
        sig = _signDigest(ownerPk, digest);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // REVERTS (source-execution order)
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Verifies importAccount reverts when the account is hard-locked (onlyUnlocked runs before all else).
    /// @dev lock() sets unlocksAt = type(uint40).max, so the account stays locked regardless of warp; any non-zero
    ///      unlock delay locks it. The onlyUnlocked modifier trips before the chainId/sequence/signature checks.
    function test_importAccount_revert_accountIsLocked(uint256 ownerSeed, uint16 delay, bool multichain) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        vm.assume(delay != 0);

        AccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(vm.addr(ownerPk));
        uint256 chainId = _acceptedChainId(multichain);
        (MockERC1271Wallet wallet, bytes memory sig) = _walletAndSig(ownerPk, chainId, actors);

        vm.prank(address(wallet));
        accountConfiguration.lock(delay);

        vm.expectRevert(AccountConfiguration.AccountIsLocked.selector);
        accountConfiguration.importAccount(address(wallet), chainId, actors, sig);
    }

    /// @notice Verifies importAccount reverts for a chainId that is neither 0 (multichain) nor the current chain.
    /// @dev Exercises the `chainId != 0 && chainId != block.chainid` guard, which runs before any signature work.
    function test_importAccount_revert_invalidChainId(uint256 ownerSeed, uint256 chainIdSeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        vm.assume(chainIdSeed != 0 && chainIdSeed != block.chainid);

        AccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(vm.addr(ownerPk));
        (MockERC1271Wallet wallet, bytes memory sig) = _walletAndSig(ownerPk, chainIdSeed, actors);

        vm.expectRevert(AccountConfiguration.InvalidChainId.selector);
        accountConfiguration.importAccount(address(wallet), chainIdSeed, actors, sig);
    }

    /// @notice Verifies importAccount reverts on an already-created account (localSequence == 1).
    /// @dev A created account is initialized (localSequence doubles as the initialized flag), so the first
    ///      AlreadyInitialized disjunct trips before the signature is ever checked (empty sig suffices).
    function test_importAccount_revert_alreadyInitialized_createdAccount(uint256 pkSeed, bool multichain) public {
        uint256 pk = _boundK1Pk(pkSeed);
        (address account,) = _createK1Account(pk);

        AccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(vm.addr(pk));
        uint256 chainId = _acceptedChainId(multichain);

        vm.expectRevert(AccountConfiguration.AlreadyInitialized.selector);
        accountConfiguration.importAccount(account, chainId, actors, "");
    }

    /// @notice Verifies a second importAccount on the same account reverts (localSequence == 1 after first import).
    /// @dev The re-init guard blocks re-import, which would otherwise re-open a stale key.
    function test_importAccount_revert_alreadyInitialized_reimport(uint256 ownerSeed, bool multichain) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 chainId = _acceptedChainId(multichain);

        AccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(vm.addr(ownerPk));
        (MockERC1271Wallet wallet, bytes memory sig) = _walletAndSig(ownerPk, chainId, actors);

        accountConfiguration.importAccount(address(wallet), chainId, actors, sig);

        vm.expectRevert(AccountConfiguration.AlreadyInitialized.selector);
        accountConfiguration.importAccount(address(wallet), chainId, actors, sig);
    }

    /// @notice Verifies importAccount reverts when the multichain channel is non-zero even though localSequence == 0.
    /// @dev A code-less 8130 EOA can apply a *global* (chainId 0) actor change signed by its implicit default EOA,
    ///      advancing multichainSequence while localSequence stays 0. Import must still be blocked: the gate requires
    ///      *both* sequence channels empty, so this exercises the `|| multichainSequence != 0` disjunct.
    function test_importAccount_revert_alreadyInitialized_afterMultichainChange(uint256 eoaSeed, uint256 deviceSeed)
        public
    {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        uint256 devicePk = _boundK1Pk(deviceSeed);
        address eoa = vm.addr(eoaPk);
        address device = vm.addr(devicePk);
        vm.assume(eoa != device);

        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: bytes32(bytes20(device)),
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: address(k1Authenticator), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });
        uint64 seq = accountConfiguration.getChangeSequences(eoa).multichain;
        bytes32 changeDigest = _computeActorChangeBatchDigest(eoa, 0, seq, changes);
        accountConfiguration.applySignedActorChanges(eoa, 0, changes, _buildK1Auth(eoaPk, changeDigest));

        // Multichain channel advanced; local channel untouched.
        assertEq(accountConfiguration.getChangeSequences(eoa).multichain, 1);
        assertEq(accountConfiguration.getChangeSequences(eoa).local, 0);

        AccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(device);
        bytes32 importDigest = _computeImportDigest(eoa, actors);
        vm.expectRevert(AccountConfiguration.AlreadyInitialized.selector);
        accountConfiguration.importAccount(eoa, uint64(block.chainid), actors, _buildK1Auth(eoaPk, importDigest));
    }

    /// @notice Verifies importAccount reverts when the ERC-1271 signer is wrong (magic value not returned).
    /// @dev Signing with a key other than the wallet owner makes isValidSignature return 0xFFFFFFFF (32-byte
    ///      returndata), tripping the `abi.decode(result,(bytes4)) != ERC1271_SELECTOR` term.
    function test_importAccount_revert_invalidImportSignature_wrongSigner(
        uint256 ownerSeed,
        uint256 wrongSeed,
        bool multichain
    ) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 wrongPk = _boundK1Pk(wrongSeed);
        vm.assume(vm.addr(ownerPk) != vm.addr(wrongPk));

        MockERC1271Wallet wallet = new MockERC1271Wallet(vm.addr(ownerPk));
        AccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(vm.addr(ownerPk));
        uint256 chainId = _acceptedChainId(multichain);
        bytes32 digest = _computeImportDigest(address(wallet), chainId, actors);
        bytes memory sig = _signDigest(wrongPk, digest);

        vm.expectRevert(AccountConfiguration.InvalidImportSignature.selector);
        accountConfiguration.importAccount(address(wallet), chainId, actors, sig);
    }

    /// @notice Verifies importAccount reverts when the account's isValidSignature reverts (staticcall fails).
    /// @dev Exercises the `!success` term of the import signature predicate.
    function test_importAccount_revert_invalidImportSignature_staticcallReverts(uint256 ownerSeed, bool multichain)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        RevertingERC1271Wallet wallet = new RevertingERC1271Wallet();

        AccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(vm.addr(ownerPk));
        uint256 chainId = _acceptedChainId(multichain);
        bytes32 digest = _computeImportDigest(address(wallet), chainId, actors);
        bytes memory sig = _signDigest(ownerPk, digest);

        vm.expectRevert(AccountConfiguration.InvalidImportSignature.selector);
        accountConfiguration.importAccount(address(wallet), chainId, actors, sig);
    }

    /// @notice Verifies importAccount reverts against a code-less account (staticcall returns empty returndata).
    /// @dev A plain EOA has no code, so the staticcall succeeds with zero-length returndata, tripping the
    ///      `result.length != 32` term (the natural "account has no ERC-1271 implementation" case).
    function test_importAccount_revert_invalidImportSignature_noCode(uint256 accountSeed, bool multichain) public {
        uint256 accountPk = _boundK1Pk(accountSeed);
        address account = vm.addr(accountPk);

        AccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(account);
        uint256 chainId = _acceptedChainId(multichain);
        bytes32 digest = _computeImportDigest(account, chainId, actors);
        bytes memory sig = _signDigest(accountPk, digest);

        vm.expectRevert(AccountConfiguration.InvalidImportSignature.selector);
        accountConfiguration.importAccount(account, chainId, actors, sig);
    }

    /// @notice Verifies importAccount reverts when isValidSignature returns non-32-byte returndata.
    /// @dev The wallet returns 4 bytes (the magic word truncated), so the `result.length != 32` term trips before
    ///      any decode, distinguishing the length guard from the selector guard.
    function test_importAccount_revert_invalidImportSignature_wrongReturnLength(uint256 ownerSeed, bool multichain)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        ShortReturnERC1271Wallet wallet = new ShortReturnERC1271Wallet();

        AccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(vm.addr(ownerPk));
        uint256 chainId = _acceptedChainId(multichain);
        bytes32 digest = _computeImportDigest(address(wallet), chainId, actors);
        bytes memory sig = _signDigest(ownerPk, digest);

        vm.expectRevert(AccountConfiguration.InvalidImportSignature.selector);
        accountConfiguration.importAccount(address(wallet), chainId, actors, sig);
    }

    /// @notice Verifies importAccount reverts with NoInitialActors when the actor set is empty.
    /// @dev The signature check (over the empty-actor digest) passes first, so this exercises the _initializeAccount
    ///      `initialActors.length == 0` guard reached only after a valid ERC-1271 signature.
    function test_importAccount_revert_noInitialActors(uint256 ownerSeed, bool multichain) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        AccountConfiguration.InitialActor[] memory actors = new AccountConfiguration.InitialActor[](0);
        uint256 chainId = _acceptedChainId(multichain);
        (MockERC1271Wallet wallet, bytes memory sig) = _walletAndSig(ownerPk, chainId, actors);

        vm.expectRevert(AccountConfiguration.NoInitialActors.selector);
        accountConfiguration.importAccount(address(wallet), chainId, actors, sig);
    }

    /// @notice Verifies importAccount reverts when initial actors are not strictly ascending by actorId.
    /// @dev Exercises the `<` side of the `actorId <= previousActorId` guard in _initializeAccount, reached after a
    ///      valid import signature over the (unsorted) actor set.
    function test_importAccount_revert_actorsNotSorted(uint256 ownerSeed, bytes32 idA, bytes32 idB, bool multichain)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        vm.assume(idA != 0 && idB != 0 && idA != idB);
        bytes32 smaller = idA < idB ? idA : idB;
        bytes32 larger = idA < idB ? idB : idA;

        AccountConfiguration.InitialActor[] memory actors = new AccountConfiguration.InitialActor[](2);
        actors[0] = AccountConfiguration.InitialActor({actorId: larger, authenticator: address(k1Authenticator)});
        actors[1] = AccountConfiguration.InitialActor({actorId: smaller, authenticator: address(k1Authenticator)});

        uint256 chainId = _acceptedChainId(multichain);
        (MockERC1271Wallet wallet, bytes memory sig) = _walletAndSig(ownerPk, chainId, actors);

        vm.expectRevert(AccountConfiguration.ActorsNotSortedOrDuplicate.selector);
        accountConfiguration.importAccount(address(wallet), chainId, actors, sig);
    }

    /// @notice Verifies importAccount reverts when the initial actor set contains a duplicate actorId.
    /// @dev Exercises the `==` side of the `actorId <= previousActorId` guard, again reached only after a valid
    ///      import signature.
    function test_importAccount_revert_actorsDuplicate(uint256 ownerSeed, bytes32 id, bool multichain) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        vm.assume(id != 0);

        AccountConfiguration.InitialActor[] memory actors = new AccountConfiguration.InitialActor[](2);
        actors[0] = AccountConfiguration.InitialActor({actorId: id, authenticator: address(k1Authenticator)});
        actors[1] = AccountConfiguration.InitialActor({actorId: id, authenticator: address(k1Authenticator)});

        uint256 chainId = _acceptedChainId(multichain);
        (MockERC1271Wallet wallet, bytes memory sig) = _walletAndSig(ownerPk, chainId, actors);

        vm.expectRevert(AccountConfiguration.ActorsNotSortedOrDuplicate.selector);
        accountConfiguration.importAccount(address(wallet), chainId, actors, sig);
    }

    /// @notice Verifies importAccount reverts when an initial actor names an authenticator below the K1 sentinel.
    /// @dev _authorizeActor rejects authenticator < K1_AUTHENTICATOR; address(0) is the only such value. Reached
    ///      after a valid import signature over the (address(0)-authenticator) actor set.
    function test_importAccount_revert_invalidAuthenticator(uint256 ownerSeed, bytes32 actorId, bool multichain)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        vm.assume(actorId != 0);

        AccountConfiguration.InitialActor[] memory actors = new AccountConfiguration.InitialActor[](1);
        actors[0] = AccountConfiguration.InitialActor({actorId: actorId, authenticator: address(0)});

        uint256 chainId = _acceptedChainId(multichain);
        (MockERC1271Wallet wallet, bytes memory sig) = _walletAndSig(ownerPk, chainId, actors);

        vm.expectRevert(AccountConfiguration.InvalidAuthenticator.selector);
        accountConfiguration.importAccount(address(wallet), chainId, actors, sig);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // HAPPY / BRANCH PATHS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Verifies a valid local-chain (chainId == block.chainid) import via an ERC-1271 wallet succeeds.
    /// @dev Sets localSequence to 1 and registers the imported actor as live.
    function test_importAccount_success_validSignatureLocalChain(uint256 ownerSeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        AccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(vm.addr(ownerPk));
        (MockERC1271Wallet wallet, bytes memory sig) = _walletAndSig(ownerPk, block.chainid, actors);

        accountConfiguration.importAccount(address(wallet), block.chainid, actors, sig);

        assertEq(accountConfiguration.getChangeSequences(address(wallet)).local, 1);
        assertTrue(accountConfiguration.isActor(address(wallet), bytes32(bytes20(vm.addr(ownerPk)))));
    }

    /// @notice Verifies a chainId == 0 (multichain) import signature authorizes import and still sets localSequence.
    /// @dev The multichain branch of the chainId gate: import is valid on any chain, yet localSequence is set to 1
    ///      (the local initialized flag) while the multichain channel stays 0 — the source always writes local.
    function test_importAccount_success_multichainSignature(uint256 ownerSeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        AccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(vm.addr(ownerPk));
        (MockERC1271Wallet wallet, bytes memory sig) = _walletAndSig(ownerPk, 0, actors);

        accountConfiguration.importAccount(address(wallet), 0, actors, sig);

        assertEq(accountConfiguration.getChangeSequences(address(wallet)).local, 1);
        assertEq(accountConfiguration.getChangeSequences(address(wallet)).multichain, 0);
        assertTrue(accountConfiguration.isActor(address(wallet), bytes32(bytes20(vm.addr(ownerPk)))));
    }

    /// @notice Verifies importAccount emits AccountImported(account) exactly once on the happy path.
    /// @dev The event is asserted here (and only here) per the one-event-per-test convention.
    function test_importAccount_success_emitsAccountImported(uint256 ownerSeed, bool multichain) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        AccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(vm.addr(ownerPk));
        uint256 chainId = _acceptedChainId(multichain);
        (MockERC1271Wallet wallet, bytes memory sig) = _walletAndSig(ownerPk, chainId, actors);

        vm.expectEmit(true, true, true, true, address(accountConfiguration));
        emit AccountConfiguration.AccountImported(address(wallet));
        accountConfiguration.importAccount(address(wallet), chainId, actors, sig);
    }

    /// @notice Verifies FLAG_REVOKE_DEFAULT_EOA is set after import (the implicit default-EOA self key is disabled).
    /// @dev With the flag set and no explicit self actor, the account's own self-actorId is not a live actor.
    function test_importAccount_success_defaultEoaRevokedFlagSet(uint256 ownerSeed, bool multichain) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        AccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(vm.addr(ownerPk));
        uint256 chainId = _acceptedChainId(multichain);
        (MockERC1271Wallet wallet, bytes memory sig) = _walletAndSig(ownerPk, chainId, actors);

        accountConfiguration.importAccount(address(wallet), chainId, actors, sig);

        // The implicit default EOA (self-actorId) is disabled by default on import.
        assertFalse(accountConfiguration.isActor(address(wallet), bytes32(bytes20(address(wallet)))));
        AccountConfiguration.ActorConfig memory selfConfig =
            accountConfiguration.getActorConfig(address(wallet), bytes32(bytes20(address(wallet))));
        assertEq(selfConfig.authenticator, address(0));
    }

    /// @notice Verifies every imported actor is live and registered as an unrestricted k1 owner.
    /// @dev Exercises the multi-actor branch of _computeImportDigest and _initializeAccount: each actor reports via
    ///      isActor and getActorConfig with authenticator == K1, scope 0, no expiry, no policy.
    function test_importAccount_success_importedActorsLive(uint256 ownerSeed, uint256 countSeed, uint256 baseSeed)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 count = bound(countSeed, 1, 8);
        // Keep the ascending block clear of 0 and clear of the low address range that could collide with sentinels.
        uint256 base = bound(baseSeed, 1000, type(uint32).max);

        AccountConfiguration.InitialActor[] memory actors = _ascendingK1Actors(count, base);
        (MockERC1271Wallet wallet, bytes memory sig) = _walletAndSig(ownerPk, block.chainid, actors);

        accountConfiguration.importAccount(address(wallet), block.chainid, actors, sig);

        assertEq(accountConfiguration.getChangeSequences(address(wallet)).local, 1);
        for (uint256 i; i < count; i++) {
            bytes32 actorId = actors[i].actorId;
            assertTrue(accountConfiguration.isActor(address(wallet), actorId));
            AccountConfiguration.ActorConfig memory config =
                accountConfiguration.getActorConfig(address(wallet), actorId);
            assertEq(config.authenticator, address(k1Authenticator));
            assertEq(config.scope, 0);
            assertEq(config.expiry, 0);
            assertEq(config.policyType, 0);
        }
    }

    /// @notice Verifies an EIP-7702 delegated account can be imported (delegate-indicator check removed).
    /// @dev Import is gated solely by the ERC-1271 signature against the delegated account's authorization logic; the
    ///      distinct device actor is registered and the implicit default EOA is disabled by default on import.
    function test_importAccount_success_delegatedAccount(uint256 ownerSeed, uint256 deviceSeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 devicePk = _boundK1Pk(deviceSeed);
        address eoa = vm.addr(ownerPk);
        address device = vm.addr(devicePk);
        vm.assume(eoa != device);

        MockERC1271Wallet impl = new MockERC1271Wallet(eoa);
        // Delegate the EOA's code to the ERC-1271 implementation (code = 0xef0100 || delegate).
        vm.etch(eoa, abi.encodePacked(hex"ef0100", address(impl)));

        AccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(device);
        bytes32 digest = _computeImportDigest(eoa, actors);
        bytes memory sig = _signDigest(ownerPk, digest);

        accountConfiguration.importAccount(eoa, uint64(block.chainid), actors, sig);

        assertEq(accountConfiguration.getChangeSequences(eoa).local, 1);
        assertTrue(accountConfiguration.isActor(eoa, bytes32(bytes20(device))));
        assertFalse(accountConfiguration.isActor(eoa, bytes32(bytes20(eoa))));
    }

    /// @notice Verifies a real EIP-7702 EOA delegated to DefaultAccount can self-import with its own k1 signature.
    /// @dev The implicit full-owner path is the only authenticator available at import time, pinning the ordering
    ///      invariant: the ERC-1271 check runs before the flag is set, and the default EOA is disabled only after
    ///      import succeeds (its own k1 sig then finds no config and the flag disables the full-owner fallback).
    function test_importAccount_success_7702_selfSignDisablesEoa(uint256 eoaSeed, uint256 deviceSeed) public {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        uint256 devicePk = _boundK1Pk(deviceSeed);
        address eoa = vm.addr(eoaPk);
        address device = vm.addr(devicePk);
        vm.assume(eoa != device);
        vm.etch(eoa, abi.encodePacked(hex"ef0100", defaultAccountImplementation));

        AccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(device);
        bytes32 digest = _computeImportDigest(eoa, actors);
        // Canonical k1 auth blob: K1_AUTHENTICATOR || signature, signed by the EOA's own key (the implicit owner).
        accountConfiguration.importAccount(eoa, uint64(block.chainid), actors, _buildK1Auth(eoaPk, digest));

        assertEq(accountConfiguration.getChangeSequences(eoa).local, 1);
        assertTrue(accountConfiguration.isActor(eoa, bytes32(bytes20(device))));
        assertFalse(accountConfiguration.isActor(eoa, bytes32(bytes20(eoa))));

        // The implicit default EOA is disabled after import: its own k1 sig now finds no config.
        bytes32 h = keccak256("post import");
        vm.expectRevert(AccountConfiguration.DefaultEoaRevoked.selector);
        accountConfiguration.authenticateActor(eoa, h, _buildK1Auth(eoaPk, h));
    }

    /// @notice Verifies a live 7702 EOA that lists its self-actorId as an explicit k1 owner keeps its key past import.
    /// @dev Import disables the implicit full-owner fallback (sets the flag), but the same key stays a full owner
    ///      through its explicit self config — lossless, resolved via the explicit config rather than the fallback.
    function test_importAccount_success_7702_keepKeyViaExplicitSelfActor(uint256 eoaSeed) public {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        address eoa = vm.addr(eoaPk);
        vm.etch(eoa, abi.encodePacked(hex"ef0100", defaultAccountImplementation));

        AccountConfiguration.InitialActor[] memory actors = new AccountConfiguration.InitialActor[](1);
        actors[0] = AccountConfiguration.InitialActor({
            actorId: bytes32(bytes20(eoa)), authenticator: accountConfiguration.K1_AUTHENTICATOR()
        });

        bytes32 digest = _computeImportDigest(eoa, actors);
        accountConfiguration.importAccount(eoa, uint64(block.chainid), actors, _buildK1Auth(eoaPk, digest));

        assertEq(accountConfiguration.getChangeSequences(eoa).local, 1);
        // The self-actorId is a live explicit owner.
        assertTrue(accountConfiguration.isActor(eoa, bytes32(bytes20(eoa))));

        // The same key still authenticates as a full owner — now via its explicit self config, not the (disabled)
        // implicit fallback.
        bytes32 h = keccak256("post import");
        (uint8 scope,,) = accountConfiguration.authenticateActor(eoa, h, _buildK1Auth(eoaPk, h));
        assertEq(scope, 0);
    }
}
