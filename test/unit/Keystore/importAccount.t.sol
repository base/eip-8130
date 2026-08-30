// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore} from "../../../src/Keystore.sol";
import {KeystoreTest} from "../../lib/KeystoreTest.sol";

// keccak256("EIP8130.importDigest") — a compile-time constant so tstore/tload can use it.
bytes32 constant IMPORT_DIGEST_TSLOT = 0xb5bf2f05f2eb384fc0dbef99ba1dcfe1b125d5d451d767b1289cf0464eca78c5;

/// @dev Reference-pattern wallet: code chooses the actor set; an empty-sig 1271 confirms the transient digest.
contract ImportableWallet {
    Keystore public immutable KEYSTORE;
    Keystore.InitialActor[] internal _actors;

    constructor(Keystore keystore_, Keystore.InitialActor[] memory actors) {
        KEYSTORE = keystore_;
        for (uint256 i; i < actors.length; i++) {
            _actors.push(actors[i]);
        }
    }

    function getImportActors() public view returns (Keystore.InitialActor[] memory) {
        return _actors;
    }

    function importToKeystore(uint256 chainId) external {
        Keystore.InitialActor[] memory actors = getImportActors();
        bytes32 digest = KEYSTORE.computeImportDigest(address(this), chainId, actors);
        assembly {
            tstore(IMPORT_DIGEST_TSLOT, digest)
        }
        KEYSTORE.importAccount(chainId, "");
        assembly {
            tstore(IMPORT_DIGEST_TSLOT, 0)
        }
    }

    function isValidSignature(bytes32 hash, bytes calldata sig) public view returns (bytes4) {
        if (sig.length == 0 && msg.sender == address(KEYSTORE)) {
            bytes32 expected;
            assembly {
                expected := tload(IMPORT_DIGEST_TSLOT)
            }
            return (expected != 0 && hash == expected) ? this.isValidSignature.selector : bytes4(0);
        }
        return bytes4(0);
    }
}

/// @dev 7702-safe reference wallet: actor set is derived from immutables + `address(this)`, so etching
///      `0xef0100 || impl` onto an EOA still returns a well-formed set (EOA storage is empty).
contract DelegatedImportWallet {
    Keystore public immutable KEYSTORE;
    /// @dev `address(0)` → install the EOA's own k1 self; otherwise a single k1 device actor.
    address public immutable device;

    constructor(Keystore keystore_, address device_) {
        KEYSTORE = keystore_;
        device = device_;
    }

    function getImportActors() public view returns (Keystore.InitialActor[] memory actors) {
        address actor = device == address(0) ? address(this) : device;
        actors = new Keystore.InitialActor[](1);
        actors[0] = Keystore.InitialActor({
            actorId: bytes32(uint256(uint160(actor))), authenticator: address(1), scope: 0, policyData: ""
        });
    }

    function importToKeystore(uint256 chainId) external {
        Keystore.InitialActor[] memory actors = getImportActors();
        bytes32 digest = KEYSTORE.computeImportDigest(address(this), chainId, actors);
        assembly {
            tstore(IMPORT_DIGEST_TSLOT, digest)
        }
        KEYSTORE.importAccount(chainId, "");
        assembly {
            tstore(IMPORT_DIGEST_TSLOT, 0)
        }
    }

    function isValidSignature(bytes32 hash, bytes calldata sig) public view returns (bytes4) {
        if (sig.length == 0 && msg.sender == address(KEYSTORE)) {
            bytes32 expected;
            assembly {
                expected := tload(IMPORT_DIGEST_TSLOT)
            }
            return (expected != 0 && hash == expected) ? this.isValidSignature.selector : bytes4(0);
        }
        return bytes4(0);
    }
}

/// @dev Weiroll-style wallet: `execute()` (and therefore import) is frozen until `lockedUntil`.
contract LockedExecute1271Wallet {
    Keystore public immutable KEYSTORE;
    address public immutable owner;
    uint256 public immutable lockedUntil;
    Keystore.InitialActor[] internal _actors;

    error NotOwner();
    error WalletLocked();

    constructor(Keystore keystore_, address owner_, uint256 lockedUntil_, Keystore.InitialActor[] memory actors) {
        KEYSTORE = keystore_;
        owner = owner_;
        lockedUntil = lockedUntil_;
        for (uint256 i; i < actors.length; i++) {
            _actors.push(actors[i]);
        }
    }

    function getImportActors() public view returns (Keystore.InitialActor[] memory) {
        return _actors;
    }

    function execute(address target, uint256 value, bytes calldata data) external payable returns (bytes memory) {
        if (msg.sender != owner) revert NotOwner();
        if (block.timestamp < lockedUntil) revert WalletLocked();
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(result, 0x20), mload(result))
            }
        }
        return result;
    }

    function importToKeystore(uint256 chainId) external {
        if (msg.sender != address(this)) revert NotOwner();
        Keystore.InitialActor[] memory actors = getImportActors();
        bytes32 digest = KEYSTORE.computeImportDigest(address(this), chainId, actors);
        assembly {
            tstore(IMPORT_DIGEST_TSLOT, digest)
        }
        KEYSTORE.importAccount(chainId, "");
        assembly {
            tstore(IMPORT_DIGEST_TSLOT, 0)
        }
    }

    function isValidSignature(bytes32 hash, bytes calldata sig) public view returns (bytes4) {
        if (sig.length == 0 && msg.sender == address(KEYSTORE)) {
            bytes32 expected;
            assembly {
                expected := tload(IMPORT_DIGEST_TSLOT)
            }
            return (expected != 0 && hash == expected) ? this.isValidSignature.selector : bytes4(0);
        }
        return bytes4(0);
    }
}

/// @dev Plain ERC-1271 wallet with no getImportActors. Models an un-upgraded wallet.
contract PlainERC1271Wallet {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return 0x1626ba7e;
    }
}

/// @dev Fallback returns calldata verbatim — an echo that must fail ABI-decode of InitialActor[], never 1271.
contract EchoFallbackWallet {
    fallback() external {
        assembly {
            calldatacopy(0, 0, calldatasize())
            return(0, calldatasize())
        }
    }
}

/// @dev Fallback returns address(this) right-aligned. Must fail ABI-decode, never reach 1271.
contract AddressEchoWallet {
    fallback() external {
        assembly {
            mstore(0, address())
            return(0, 32)
        }
    }
}

contract EmptyImportActorsWallet {
    function getImportActors() external pure returns (Keystore.InitialActor[] memory) {
        return new Keystore.InitialActor[](0);
    }
}

contract RevertingERC1271ImportWallet {
    Keystore.InitialActor[] internal _actors;

    constructor(Keystore.InitialActor[] memory actors) {
        for (uint256 i; i < actors.length; i++) {
            _actors.push(actors[i]);
        }
    }

    function getImportActors() external view returns (Keystore.InitialActor[] memory) {
        return _actors;
    }

    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        revert("no");
    }
}

contract ShortReturnImportWallet {
    Keystore.InitialActor[] internal _actors;

    constructor(Keystore.InitialActor[] memory actors) {
        for (uint256 i; i < actors.length; i++) {
            _actors.push(actors[i]);
        }
    }

    function getImportActors() external view returns (Keystore.InitialActor[] memory) {
        return _actors;
    }

    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        assembly ("memory-safe") {
            mstore(0x00, 0x1626ba7e00000000000000000000000000000000000000000000000000000000)
            return(0x00, 4)
        }
    }
}

contract DirtyReturnImportWallet {
    Keystore.InitialActor[] internal _actors;

    constructor(Keystore.InitialActor[] memory actors) {
        for (uint256 i; i < actors.length; i++) {
            _actors.push(actors[i]);
        }
    }

    function getImportActors() external view returns (Keystore.InitialActor[] memory) {
        return _actors;
    }

    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes32) {
        return 0x1626ba7effffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    }
}

/// @dev 1271 confirms keccak256("other") rather than the import digest.
contract MismatchDigestWallet {
    Keystore.InitialActor[] internal _actors;

    constructor(Keystore.InitialActor[] memory actors) {
        for (uint256 i; i < actors.length; i++) {
            _actors.push(actors[i]);
        }
    }

    function getImportActors() external view returns (Keystore.InitialActor[] memory) {
        return _actors;
    }

    function isValidSignature(bytes32 hash, bytes calldata) external pure returns (bytes4) {
        return hash == keccak256("other") ? bytes4(0x1626ba7e) : bytes4(0);
    }
}

contract ConstructorImporter {
    constructor(Keystore keystore, uint256 chainId) {
        keystore.importAccount(chainId, "");
    }
}

/// @dev CoinbaseSmartWalletV2-shaped import (see `_import` at CoinbaseSmartWalletV2.sol:457).
///      V1 owners live in storage; {getImportActors} reconstructs them and appends code-baked canonical
///      EntryPoints as TRUSTED_EXECUTOR. Caller-supplied actor sets are gone — that was the sub-root gap.
///      The old `_migrationInProgress` (magic for any hash) is replaced by a hash-bound transient digest.
contract CoinbaseSmartWalletStyle {
    Keystore public immutable KEYSTORE;
    address public immutable PASSKEY_AUTHENTICATOR;
    address public immutable ENTRY_POINT;

    address constant TRUSTED_EXECUTOR = address(uint160(uint256(keccak256("trustedExecutor"))));

    error OnlySelf();
    error NotOwner();

    address public owner;
    Keystore.InitialActor[] internal _v1Owners;
    bytes32 transient _importDigest;

    constructor(
        Keystore keystore_,
        address owner_,
        address passkeyAuthenticator_,
        address entryPoint_,
        Keystore.InitialActor[] memory v1Owners
    ) {
        KEYSTORE = keystore_;
        owner = owner_;
        PASSKEY_AUTHENTICATOR = passkeyAuthenticator_;
        ENTRY_POINT = entryPoint_;
        for (uint256 i; i < v1Owners.length; i++) {
            _v1Owners.push(v1Owners[i]);
        }
    }

    function getImportActors() public view returns (Keystore.InitialActor[] memory actors) {
        actors = new Keystore.InitialActor[](_v1Owners.length + 1);
        for (uint256 i; i < _v1Owners.length; i++) {
            actors[i] = _v1Owners[i];
        }
        actors[_v1Owners.length] = Keystore.InitialActor({
            actorId: bytes32(uint256(uint160(ENTRY_POINT))), authenticator: TRUSTED_EXECUTOR, scope: 0, policyData: ""
        });
        _sortByActorId(actors);
    }

    /// @notice Nominal V1→V2 path: onlySelf, reached as the owner-signed upgrade's `initData` self-call.
    ///         No actor array — Keystore reads {getImportActors}.
    function completeV1Migration() external {
        if (msg.sender != address(this)) revert OnlySelf();
        _import();
    }

    /// @notice Permissionless recovery: reconstructs owners from this account's storage. A third party can
    ///         only import the real V1 owners plus the code-baked EntryPoint.
    function recoverV1Owners() external {
        _import();
    }

    function execute(address target, uint256 value, bytes calldata data) external payable returns (bytes memory) {
        if (msg.sender != owner) revert NotOwner();
        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) {
            assembly ("memory-safe") {
                revert(add(result, 0x20), mload(result))
            }
        }
        return result;
    }

    function isValidSignature(bytes32 hash, bytes calldata) external view returns (bytes4) {
        if (msg.sender == address(KEYSTORE) && _importDigest != 0 && hash == _importDigest) {
            return 0x1626ba7e;
        }
        return 0xffffffff;
    }

    function _import() internal {
        Keystore.InitialActor[] memory actors = getImportActors();
        _importDigest = KEYSTORE.computeImportDigest(address(this), block.chainid, actors);
        KEYSTORE.importAccount(block.chainid, "");
        _importDigest = bytes32(0);
    }

    function _sortByActorId(Keystore.InitialActor[] memory actors) internal pure {
        for (uint256 i; i < actors.length; i++) {
            for (uint256 j = i + 1; j < actors.length; j++) {
                if (uint256(actors[j].actorId) < uint256(actors[i].actorId)) {
                    Keystore.InitialActor memory tmp = actors[i];
                    actors[i] = actors[j];
                    actors[j] = tmp;
                }
            }
        }
    }
}

/// @dev Fully fuzzed, branch-complete suite for Keystore.importAccount. Reverts are ordered to mirror
///      importAccount's source control flow (onlyUnlocked → InvalidChainId → AlreadyInitialized →
///      getImportActors / NoImportActors / _validateInitialActors → InvalidImportSignature); happy/branch paths follow.
contract ImportAccountTest is KeystoreTest {
    bytes4 constant ERC1271_MAGIC = 0x1626ba7e;

    bytes32 constant ACTOR_INITIALIZATION_TYPEHASH = keccak256(
        "ActorInitialization(bytes32 accountId,uint256 chainId,Actor[] initialActors)Actor(bytes32 actorId,ActorConfig config,bytes policyData)ActorConfig(address authenticator,uint48 expiry,uint16 scope)"
    );
    bytes32 constant ACTOR_TYPEHASH = keccak256(
        "Actor(bytes32 actorId,ActorConfig config,bytes policyData)ActorConfig(address authenticator,uint48 expiry,uint16 scope)"
    );
    bytes32 constant ACTOR_CONFIG_TYPEHASH = keccak256("ActorConfig(address authenticator,uint48 expiry,uint16 scope)");

    // ── digest helpers ──

    function _computeImportDigest(address account, Keystore.InitialActor[] memory initialActors)
        internal
        view
        returns (bytes32)
    {
        return _computeImportDigest(account, block.chainid, initialActors);
    }

    function _computeImportDigest(address account, uint256 chainId, Keystore.InitialActor[] memory initialActors)
        internal
        pure
        returns (bytes32)
    {
        bytes32[] memory actorHashes = new bytes32[](initialActors.length);
        for (uint256 i; i < initialActors.length; i++) {
            bytes32 configHash = keccak256(
                abi.encode(ACTOR_CONFIG_TYPEHASH, initialActors[i].authenticator, uint48(0), initialActors[i].scope)
            );
            actorHashes[i] = keccak256(
                abi.encode(ACTOR_TYPEHASH, initialActors[i].actorId, configHash, keccak256(initialActors[i].policyData))
            );
        }
        return keccak256(
            abi.encode(
                ACTOR_INITIALIZATION_TYPEHASH,
                bytes32(uint256(uint160(account))),
                chainId,
                keccak256(abi.encodePacked(actorHashes))
            )
        );
    }

    // ── actor-set builders ──

    function _singleUnrestrictedActor(address signer) internal view returns (Keystore.InitialActor[] memory actors) {
        actors = new Keystore.InitialActor[](1);
        actors[0] = Keystore.InitialActor({
            actorId: bytes32(uint256(uint160(signer))),
            authenticator: address(k1Authenticator),
            scope: 0,
            policyData: ""
        });
    }

    function _ascendingK1Actors(uint256 count, uint256 base)
        internal
        view
        returns (Keystore.InitialActor[] memory actors)
    {
        actors = new Keystore.InitialActor[](count);
        for (uint256 i; i < count; i++) {
            actors[i] = Keystore.InitialActor({
                actorId: bytes32(uint256(uint160(address(uint160(base + i))))),
                authenticator: address(k1Authenticator),
                scope: 0,
                policyData: ""
            });
        }
    }

    function _acceptedChainId(bool multichain) internal view returns (uint256) {
        return multichain ? 0 : block.chainid;
    }

    function _importable(Keystore.InitialActor[] memory actors) internal returns (ImportableWallet) {
        return new ImportableWallet(keystore, actors);
    }

    function _importAs(address account, uint256 chainId, bytes memory sig) internal {
        vm.prank(account);
        keystore.importAccount(chainId, sig);
    }

    function _assertUnimported(address account) internal view {
        assertEq(keystore.getChangeSequences(account).localSequence, 0);
        assertEq(keystore.getChangeSequences(account).multichain, 0);
        assertEq(keystore.getChangeSequences(account).localEpoch, 0);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // REVERTS (source-execution order)
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Verifies importAccount reverts when the account is hard-locked (onlyUnlocked runs before all else).
    function test_importAccount_revert_accountIsLocked(uint256 ownerSeed, uint16 delay, bool multichain) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        vm.assume(delay != 0);
        address account = vm.addr(ownerPk);
        uint256 chainId = _acceptedChainId(multichain);

        _signedLock(ownerPk, account, delay);

        vm.expectRevert(Keystore.AccountIsLocked.selector);
        _importAs(account, chainId, "");
    }

    /// @notice A third party cannot import a wallet: there is no account parameter, so the call attempts to import
    ///         the caller. The test contract has code but no getImportActors, so ABI-decode reverts and the wallet
    ///         is untouched.
    function test_importAccount_revert_callerNotAccount(uint256 ownerSeed, bool multichain) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        ImportableWallet wallet = _importable(_singleUnrestrictedActor(vm.addr(ownerPk)));

        vm.expectRevert();
        keystore.importAccount(_acceptedChainId(multichain), "");
        _assertUnimported(address(wallet));
    }

    /// @notice A wallet that locks `execute()` until `lockedUntil` cannot self-import while that lock is active.
    ///         `importToKeystore` is only reachable through `execute()`, so the existing execution gate still applies.
    function test_importAccount_revert_executeLockedWallet(uint256 ownerSeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        address owner = vm.addr(ownerPk);
        uint256 unlockTime = block.timestamp + 30 days;
        Keystore.InitialActor[] memory actors = _singleUnrestrictedActor(owner);
        LockedExecute1271Wallet wallet = new LockedExecute1271Wallet(keystore, owner, unlockTime, actors);

        bytes memory importCall = abi.encodeCall(LockedExecute1271Wallet.importToKeystore, (block.chainid));

        vm.expectRevert(LockedExecute1271Wallet.WalletLocked.selector);
        vm.prank(owner);
        wallet.execute(address(wallet), 0, importCall);

        _assertUnimported(address(wallet));
    }

    /// @notice After the execution lock expires, the same wallet can self-import through `execute()`.
    function test_importAccount_success_executeUnlockedWallet(uint256 ownerSeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        address owner = vm.addr(ownerPk);
        uint256 unlockTime = block.timestamp + 30 days;
        Keystore.InitialActor[] memory actors = _singleUnrestrictedActor(owner);
        LockedExecute1271Wallet wallet = new LockedExecute1271Wallet(keystore, owner, unlockTime, actors);

        vm.warp(unlockTime);
        vm.prank(owner);
        wallet.execute(address(wallet), 0, abi.encodeCall(LockedExecute1271Wallet.importToKeystore, (block.chainid)));

        assertEq(keystore.getChangeSequences(address(wallet)).localSequence, 1);
        assertTrue(_isActor(address(wallet), bytes32(uint256(uint160(owner)))));
    }

    /// @notice Verifies importAccount reverts for a chainId that is neither 0 nor the current chain.
    function test_importAccount_revert_invalidChainId(uint256 ownerSeed, uint256 chainIdSeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        vm.assume(chainIdSeed != 0 && chainIdSeed != block.chainid);
        ImportableWallet wallet = _importable(_singleUnrestrictedActor(vm.addr(ownerPk)));

        vm.expectRevert(Keystore.InvalidChainId.selector);
        _importAs(address(wallet), chainIdSeed, "");
        _assertUnimported(address(wallet));
    }

    /// @notice Verifies importAccount reverts on an already-created account (localSequence == 1).
    function test_importAccount_revert_alreadyInitialized_createdAccount(uint256 pkSeed, bool multichain) public {
        uint256 pk = _boundK1Pk(pkSeed);
        (address account,) = _createK1Account(pk);

        vm.expectRevert(Keystore.AlreadyInitialized.selector);
        _importAs(account, _acceptedChainId(multichain), "");
    }

    /// @notice Verifies a second importAccount on the same account reverts.
    function test_importAccount_revert_alreadyInitialized_reimport(uint256 ownerSeed, bool multichain) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        uint256 chainId = _acceptedChainId(multichain);
        ImportableWallet wallet = _importable(_singleUnrestrictedActor(vm.addr(ownerPk)));

        wallet.importToKeystore(chainId);

        vm.expectRevert(Keystore.AlreadyInitialized.selector);
        wallet.importToKeystore(chainId);
    }

    /// @notice Verifies importAccount reverts when the multichain channel is non-zero even though localSequence == 0.
    function test_importAccount_revert_alreadyInitialized_afterMultichainChange(uint256 eoaSeed, uint256 deviceSeed)
        public
    {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        uint256 devicePk = _boundK1Pk(deviceSeed);
        address eoa = vm.addr(eoaPk);
        address device = vm.addr(devicePk);
        vm.assume(eoa != device);

        _applyMultichain(
            eoaPk,
            eoa,
            _one(_authorizeChange(bytes32(uint256(uint160(device))), address(k1Authenticator), 0x00, UNBOUNDED, ""))
        );

        assertEq(keystore.getChangeSequences(eoa).multichain, 1);
        assertEq(keystore.getChangeSequences(eoa).localSequence, 0);

        vm.expectRevert(Keystore.AlreadyInitialized.selector);
        _importAs(eoa, uint64(block.chainid), "");
    }

    /// @notice A code-less account (plain EOA) fails at getImportActors: empty returndata cannot ABI-decode as
    ///         InitialActor[].
    function test_importAccount_revert_noCode(uint256 accountSeed, bool multichain) public {
        uint256 accountPk = _boundK1Pk(accountSeed);
        address account = vm.addr(accountPk);

        vm.expectRevert();
        _importAs(account, _acceptedChainId(multichain), "");
        _assertUnimported(account);
    }

    /// @notice Calling importAccount from a constructor fails the same way (runtime code is not yet stored).
    function test_importAccount_revert_fromConstructor() public {
        vm.expectRevert();
        new ConstructorImporter(keystore, block.chainid);
    }

    /// @notice A wallet that returns an empty actor array reverts NoImportActors, before ERC-1271.
    function test_importAccount_revert_noImportActors(bool multichain) public {
        EmptyImportActorsWallet wallet = new EmptyImportActorsWallet();

        vm.expectRevert(Keystore.NoImportActors.selector);
        _importAs(address(wallet), _acceptedChainId(multichain), "");
        _assertUnimported(address(wallet));
    }

    /// @notice A plain 1271 wallet that does not implement getImportActors reverts on ABI-decode of the empty return.
    function test_importAccount_revert_missingGetImportActors(bool multichain) public {
        PlainERC1271Wallet wallet = new PlainERC1271Wallet();

        vm.expectRevert();
        _importAs(address(wallet), _acceptedChainId(multichain), "");
        _assertUnimported(address(wallet));
    }

    /// @notice An echo-fallback that returns calldata reverts on decode and never reaches 1271.
    function test_importAccount_revert_echoFallbackCalldata(bool multichain) public {
        EchoFallbackWallet wallet = new EchoFallbackWallet();

        vm.expectRevert();
        _importAs(address(wallet), _acceptedChainId(multichain), "");
        _assertUnimported(address(wallet));
    }

    /// @notice An echo-fallback that returns address(this) right-aligned reverts on decode and never reaches 1271.
    function test_importAccount_revert_echoFallbackAddress(bool multichain) public {
        AddressEchoWallet wallet = new AddressEchoWallet();

        vm.expectRevert();
        _importAs(address(wallet), _acceptedChainId(multichain), "");
        _assertUnimported(address(wallet));
    }

    /// @notice Unsorted getImportActors output reverts ActorsNotSortedOrDuplicate before 1271.
    function test_importAccount_revert_actorsNotSorted(bytes32 idA, bytes32 idB, bool multichain) public {
        vm.assume(idA != 0 && idB != 0 && idA != idB);
        bytes32 smaller = idA < idB ? idA : idB;
        bytes32 larger = idA < idB ? idB : idA;

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](2);
        actors[0] =
            Keystore.InitialActor({actorId: larger, authenticator: address(k1Authenticator), scope: 0, policyData: ""});
        actors[1] = Keystore.InitialActor({
            actorId: smaller, authenticator: address(k1Authenticator), scope: 0, policyData: ""
        });

        ImportableWallet wallet = _importable(actors);
        vm.expectRevert(Keystore.ActorsNotSortedOrDuplicate.selector);
        _importAs(address(wallet), _acceptedChainId(multichain), "");
        _assertUnimported(address(wallet));
    }

    /// @notice Duplicate actorIds in getImportActors reverts ActorsNotSortedOrDuplicate before 1271.
    function test_importAccount_revert_actorsDuplicate(bytes32 id, bool multichain) public {
        vm.assume(id != 0);

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](2);
        actors[0] =
            Keystore.InitialActor({actorId: id, authenticator: address(k1Authenticator), scope: 0, policyData: ""});
        actors[1] =
            Keystore.InitialActor({actorId: id, authenticator: address(k1Authenticator), scope: 0, policyData: ""});

        ImportableWallet wallet = _importable(actors);
        vm.expectRevert(Keystore.ActorsNotSortedOrDuplicate.selector);
        _importAs(address(wallet), _acceptedChainId(multichain), "");
        _assertUnimported(address(wallet));
    }

    /// @notice A sub-K1 authenticator in getImportActors reverts InvalidAuthenticator before 1271.
    function test_importAccount_revert_invalidAuthenticator(bytes32 actorId, bool multichain) public {
        vm.assume(actorId != 0);

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](1);
        actors[0] = Keystore.InitialActor({actorId: actorId, authenticator: address(0), scope: 0, policyData: ""});

        ImportableWallet wallet = _importable(actors);
        vm.expectRevert(Keystore.InvalidAuthenticator.selector);
        _importAs(address(wallet), _acceptedChainId(multichain), "");
        _assertUnimported(address(wallet));
    }

    /// @notice Malformed policyData in getImportActors reverts InvalidPolicyData before 1271.
    function test_importAccount_revert_invalidPolicyData(bytes32 actorId, bool multichain) public {
        vm.assume(actorId != 0);

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](1);
        actors[0] = Keystore.InitialActor({
            actorId: actorId, authenticator: address(k1Authenticator), scope: 0, policyData: hex"deadbeef"
        });

        ImportableWallet wallet = _importable(actors);
        vm.expectRevert(Keystore.InvalidPolicyData.selector);
        _importAs(address(wallet), _acceptedChainId(multichain), "");
        _assertUnimported(address(wallet));
    }

    /// @notice 1271 confirming a different hash than computeImportDigest reverts InvalidImportSignature.
    function test_importAccount_revert_digestMismatch(uint256 ownerSeed, bool multichain) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        MismatchDigestWallet wallet = new MismatchDigestWallet(_singleUnrestrictedActor(vm.addr(ownerPk)));

        vm.expectRevert(Keystore.InvalidImportSignature.selector);
        _importAs(address(wallet), _acceptedChainId(multichain), "");
        _assertUnimported(address(wallet));
    }

    /// @notice isValidSignature reverting is InvalidImportSignature; account state is rolled back.
    function test_importAccount_revert_invalidImportSignature_staticcallReverts(uint256 ownerSeed, bool multichain)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        RevertingERC1271ImportWallet wallet =
            new RevertingERC1271ImportWallet(_singleUnrestrictedActor(vm.addr(ownerPk)));

        vm.expectRevert(Keystore.InvalidImportSignature.selector);
        _importAs(address(wallet), _acceptedChainId(multichain), "");
        _assertUnimported(address(wallet));
    }

    /// @notice Non-32-byte 1271 returndata is InvalidImportSignature.
    function test_importAccount_revert_invalidImportSignature_wrongReturnLength(uint256 ownerSeed, bool multichain)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        ShortReturnImportWallet wallet = new ShortReturnImportWallet(_singleUnrestrictedActor(vm.addr(ownerPk)));

        vm.expectRevert(Keystore.InvalidImportSignature.selector);
        _importAs(address(wallet), _acceptedChainId(multichain), "");
        _assertUnimported(address(wallet));
    }

    /// @notice A 32-byte response with the magic prefix but dirty padding is InvalidImportSignature.
    function test_importAccount_revert_invalidImportSignature_dirtyReturn(uint256 ownerSeed, bool multichain) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        DirtyReturnImportWallet wallet = new DirtyReturnImportWallet(_singleUnrestrictedActor(vm.addr(ownerPk)));

        vm.expectRevert(Keystore.InvalidImportSignature.selector);
        _importAs(address(wallet), _acceptedChainId(multichain), "");
        _assertUnimported(address(wallet));
    }

    /// @notice 1271 returning a non-magic 32-byte word (wrong selector) is InvalidImportSignature.
    /// @dev The reference wallet's 1271 without a prior tstore returns bytes4(0).
    function test_importAccount_revert_invalidImportSignature_wrongMagic(uint256 ownerSeed, bool multichain) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        ImportableWallet wallet = _importable(_singleUnrestrictedActor(vm.addr(ownerPk)));

        vm.expectRevert(Keystore.InvalidImportSignature.selector);
        _importAs(address(wallet), _acceptedChainId(multichain), "");
        _assertUnimported(address(wallet));
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // HAPPY / BRANCH PATHS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice The public computeImportDigest matches the independent typehash reimplementation and is distinct
    ///         from the signed-change and signed-message typehashes.
    function test_computeImportDigest_matchesAndDistinctTypehash(uint256 ownerSeed, bool multichain) public view {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        address account = address(uint160(uint256(keccak256(abi.encode(ownerPk)))));
        Keystore.InitialActor[] memory actors = _singleUnrestrictedActor(vm.addr(ownerPk));
        uint256 chainId = _acceptedChainId(multichain);

        assertEq(keystore.computeImportDigest(account, chainId, actors), _computeImportDigest(account, chainId, actors));
        assertTrue(keystore.ACTOR_INITIALIZATION_TYPEHASH() != keystore.SIGNED_ACCOUNT_CHANGES_TYPEHASH());
        assertTrue(keystore.ACTOR_INITIALIZATION_TYPEHASH() != keystore.SIGNED_MESSAGE_TYPEHASH());
    }

    /// @notice Happy path: getImportActors + transient-digest 1271 on the local chain.
    function test_importAccount_success_validSignatureLocalChain(uint256 ownerSeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        address owner = vm.addr(ownerPk);
        ImportableWallet wallet = _importable(_singleUnrestrictedActor(owner));

        wallet.importToKeystore(block.chainid);

        assertEq(keystore.getChangeSequences(address(wallet)).localSequence, 1);
        assertTrue(_isActor(address(wallet), bytes32(uint256(uint160(owner)))));
    }

    /// @notice chainId == 0 (multichain) import still sets localSequence and leaves the multichain channel at 0.
    function test_importAccount_success_multichainSignature(uint256 ownerSeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        address owner = vm.addr(ownerPk);
        ImportableWallet wallet = _importable(_singleUnrestrictedActor(owner));

        wallet.importToKeystore(0);

        assertEq(keystore.getChangeSequences(address(wallet)).localSequence, 1);
        assertEq(keystore.getChangeSequences(address(wallet)).multichain, 0);
        assertTrue(_isActor(address(wallet), bytes32(uint256(uint160(owner)))));
    }

    /// @notice importAccount emits AccountImported(account) exactly once on the happy path.
    function test_importAccount_success_emitsAccountImported(uint256 ownerSeed, bool multichain) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        address owner = vm.addr(ownerPk);
        ImportableWallet wallet = _importable(_singleUnrestrictedActor(owner));

        vm.expectEmit(true, false, false, true, address(keystore));
        emit Keystore.AccountImported(address(wallet));
        wallet.importToKeystore(_acceptedChainId(multichain));
    }

    /// @notice FLAG_REVOKE_DEFAULT_EOA is set after import (the implicit default-EOA self key is disabled).
    function test_importAccount_success_defaultEoaRevokedFlagSet(uint256 ownerSeed, bool multichain) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        ImportableWallet wallet = _importable(_singleUnrestrictedActor(vm.addr(ownerPk)));

        wallet.importToKeystore(_acceptedChainId(multichain));

        assertFalse(_isActor(address(wallet), bytes32(uint256(uint160(address(wallet))))));
        Keystore.ActorConfig memory selfConfig =
            keystore.getActorConfig(address(wallet), bytes32(uint256(uint160(address(wallet)))));
        assertEq(selfConfig.authenticator, address(0));
    }

    /// @notice Every imported actor is live with the declared k1 config.
    function test_importAccount_success_importedActorsLive(uint256 countSeed, uint256 baseSeed) public {
        uint256 count = bound(countSeed, 1, 8);
        uint256 base = bound(baseSeed, 1000, type(uint32).max);

        Keystore.InitialActor[] memory actors = _ascendingK1Actors(count, base);
        ImportableWallet wallet = _importable(actors);

        wallet.importToKeystore(block.chainid);

        assertEq(keystore.getChangeSequences(address(wallet)).localSequence, 1);
        for (uint256 i; i < count; i++) {
            bytes32 actorId = actors[i].actorId;
            assertTrue(_isActor(address(wallet), actorId));
            Keystore.ActorConfig memory config = keystore.getActorConfig(address(wallet), actorId);
            assertEq(config.authenticator, address(k1Authenticator));
            assertEq(config.scope, 0);
            assertEq(config.expiry, 0);
        }
    }

    /// @notice An empty `sig` is forwarded as-is; the transient-digest 1271 path accepts it.
    function test_importAccount_success_emptySignature(uint256 ownerSeed, bool multichain) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        ImportableWallet wallet = _importable(_singleUnrestrictedActor(vm.addr(ownerPk)));
        wallet.importToKeystore(_acceptedChainId(multichain));
        assertEq(keystore.getChangeSequences(address(wallet)).localSequence, 1);
    }

    /// @notice A 7702-delegated EOA imports via its delegate's getImportActors (device actor, EOA key disabled).
    function test_importAccount_success_7702_selfSignDisablesEoa(uint256 eoaSeed, uint256 deviceSeed) public {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        uint256 devicePk = _boundK1Pk(deviceSeed);
        address eoa = vm.addr(eoaPk);
        address device = vm.addr(devicePk);
        vm.assume(eoa != device);

        DelegatedImportWallet impl = new DelegatedImportWallet(keystore, device);
        vm.etch(eoa, abi.encodePacked(hex"ef0100", address(impl)));

        vm.prank(eoa);
        DelegatedImportWallet(eoa).importToKeystore(block.chainid);

        assertEq(keystore.getChangeSequences(eoa).localSequence, 1);
        assertTrue(_isActor(eoa, bytes32(uint256(uint160(device)))));
        assertFalse(_isActor(eoa, bytes32(uint256(uint160(eoa)))));

        bytes32 h = keccak256("post import");
        vm.expectRevert(Keystore.DefaultEoaRevoked.selector);
        keystore.authenticateActor(eoa, h, _buildK1Auth(eoaPk, h));
    }

    /// @notice A 7702 EOA whose delegate returns the self-actorId as an explicit k1 owner keeps that key past import.
    function test_importAccount_success_7702_keepKeyViaExplicitSelfActor(uint256 eoaSeed) public {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        address eoa = vm.addr(eoaPk);

        DelegatedImportWallet impl = new DelegatedImportWallet(keystore, address(0));
        vm.etch(eoa, abi.encodePacked(hex"ef0100", address(impl)));

        vm.prank(eoa);
        DelegatedImportWallet(eoa).importToKeystore(block.chainid);

        assertEq(keystore.getChangeSequences(eoa).localSequence, 1);
        assertTrue(_isActor(eoa, bytes32(uint256(uint160(eoa)))));

        bytes32 h = keccak256("post import");
        (, uint16 scope) = keystore.authenticateActor(eoa, h, _buildK1Auth(eoaPk, h));
        assertEq(scope, 0);
    }

    // ── CoinbaseSmartWalletV2-shaped import ──

    function _cswWallet(uint256 ownerPk, uint256 passkeySeed)
        internal
        returns (CoinbaseSmartWalletStyle wallet, address owner, bytes32 passkeyId, address entryPoint)
    {
        owner = vm.addr(ownerPk);
        passkeyId = keccak256(abi.encodePacked("csw-passkey", passkeySeed));
        entryPoint = ENTRY_POINT;
        vm.assume(passkeyId != bytes32(uint256(uint160(owner))));
        vm.assume(passkeyId != bytes32(uint256(uint160(entryPoint))));
        address passkeyAuth = address(uint160(uint256(keccak256("passkeyAuthenticator"))));

        Keystore.InitialActor[] memory v1 = new Keystore.InitialActor[](2);
        v1[0] = Keystore.InitialActor({
            actorId: bytes32(uint256(uint160(owner))), authenticator: address(k1Authenticator), scope: 0, policyData: ""
        });
        v1[1] = Keystore.InitialActor({actorId: passkeyId, authenticator: passkeyAuth, scope: 0, policyData: ""});
        wallet = new CoinbaseSmartWalletStyle(keystore, owner, passkeyAuth, entryPoint, v1);
    }

    /// @notice CSW `recoverV1Owners`: permissionless, but the actor set is reconstructed from storage + code-baked
    ///         EntryPoint. A third party cannot choose a different admin.
    function test_importAccount_success_cswStyle_recoverV1Owners(uint256 ownerSeed, uint256 passkeySeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        (CoinbaseSmartWalletStyle wallet, address owner, bytes32 passkeyId, address entryPoint) =
            _cswWallet(ownerPk, passkeySeed);

        wallet.recoverV1Owners();

        assertEq(keystore.getChangeSequences(address(wallet)).localSequence, 1);
        assertTrue(_isActor(address(wallet), bytes32(uint256(uint160(owner)))));
        assertTrue(_isActor(address(wallet), passkeyId));
        assertTrue(_isActor(address(wallet), bytes32(uint256(uint160(entryPoint)))));
        assertEq(
            keystore.getActorConfig(address(wallet), bytes32(uint256(uint160(entryPoint)))).authenticator,
            address(uint160(uint256(keccak256("trustedExecutor"))))
        );
    }

    /// @notice CSW `completeV1Migration`: onlySelf, reached as the upgrade `initData` self-call through `execute`.
    ///         No actor array is passed — matching the new Keystore signature.
    function test_importAccount_success_cswStyle_completeV1Migration(uint256 ownerSeed, uint256 passkeySeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        (CoinbaseSmartWalletStyle wallet, address owner, bytes32 passkeyId,) = _cswWallet(ownerPk, passkeySeed);

        vm.prank(owner);
        wallet.execute(address(wallet), 0, abi.encodeCall(CoinbaseSmartWalletStyle.completeV1Migration, ()));

        assertEq(keystore.getChangeSequences(address(wallet)).localSequence, 1);
        assertTrue(_isActor(address(wallet), bytes32(uint256(uint160(owner)))));
        assertTrue(_isActor(address(wallet), passkeyId));
    }

    /// @notice A third party cannot call completeV1Migration (OnlySelf). They also cannot import a chosen actor set:
    ///         there is no actors parameter on importAccount.
    function test_importAccount_revert_cswStyle_completeV1Migration_notSelf(uint256 ownerSeed, uint256 passkeySeed)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        (CoinbaseSmartWalletStyle wallet,,,) = _cswWallet(ownerPk, passkeySeed);

        vm.expectRevert(CoinbaseSmartWalletStyle.OnlySelf.selector);
        wallet.completeV1Migration();
        _assertUnimported(address(wallet));
    }
}
