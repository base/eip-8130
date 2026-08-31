// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore} from "../../../src/Keystore.sol";
import {KeystoreTest} from "../../lib/KeystoreTest.sol";

// keccak256("EIP8130.importDigest") — a compile-time constant so tstore/tload can use it.
bytes32 constant IMPORT_DIGEST_TSLOT = 0xb5bf2f05f2eb384fc0dbef99ba1dcfe1b125d5d451d767b1289cf0464eca78c5;

contract ActorStore {
    Keystore.InitialActor[] internal _actors;

    constructor(Keystore.InitialActor[] memory actors) {
        for (uint256 i; i < actors.length; i++) {
            _actors.push(actors[i]);
        }
    }

    function initialActors() public view returns (Keystore.InitialActor[] memory) {
        return _actors;
    }
}

/// @dev Reference wallet: owner-gated import entry, actors from storage, transient confirmation.
contract ImportableWallet is ActorStore {
    Keystore public immutable KEYSTORE;
    address public immutable owner;

    error NotOwner();

    constructor(Keystore keystore_, address owner_, Keystore.InitialActor[] memory actors) ActorStore(actors) {
        KEYSTORE = keystore_;
        owner = owner_;
    }

    function importToKeystore() external {
        if (msg.sender != owner) revert NotOwner();
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

    function confirmKeystoreImport() external view returns (bytes32 digest, Keystore.InitialActor[] memory actors) {
        actors = initialActors();
        assembly {
            digest := tload(IMPORT_DIGEST_TSLOT)
        }
        if (msg.sender != address(KEYSTORE) || digest == 0) return (bytes32(0), actors);
    }

    function _import() internal {
        Keystore.InitialActor[] memory actors = initialActors();
        bytes32 digest = KEYSTORE.computeImportDigest(address(this), actors);
        assembly {
            tstore(IMPORT_DIGEST_TSLOT, digest)
        }
        KEYSTORE.importAccount();
        assembly {
            tstore(IMPORT_DIGEST_TSLOT, 0)
        }
    }
}

/// @dev 7702 delegate: no storage. Actors are derived from `address(this)` so they resolve on the EOA.
contract DelegatedImportWallet {
    Keystore public immutable KEYSTORE;

    constructor(Keystore keystore_) {
        KEYSTORE = keystore_;
    }

    function confirmKeystoreImport() external view returns (bytes32 digest, Keystore.InitialActor[] memory actors) {
        actors = new Keystore.InitialActor[](1);
        actors[0] = Keystore.InitialActor({
            actorId: bytes32(uint256(uint160(address(this)))),
            authenticator: KEYSTORE.K1_AUTHENTICATOR(),
            scope: 0,
            policyData: ""
        });
        if (msg.sender != address(KEYSTORE)) return (bytes32(0), actors);
        digest = KEYSTORE.computeImportDigest(address(this), actors);
    }
}

/// @dev Init-time import: {confirmKeystoreImport} recomputes from {initialActors}; no transient handshake.
contract StatelessImportWallet is ActorStore {
    Keystore public immutable KEYSTORE;

    constructor(Keystore keystore_, Keystore.InitialActor[] memory actors) ActorStore(actors) {
        KEYSTORE = keystore_;
    }

    function importToKeystore() external {
        KEYSTORE.importAccount();
    }

    function confirmKeystoreImport() external view returns (bytes32 digest, Keystore.InitialActor[] memory actors) {
        actors = initialActors();
        if (msg.sender != address(KEYSTORE)) return (bytes32(0), actors);
        digest = KEYSTORE.computeImportDigest(address(this), actors);
    }
}

/// @dev Wallet whose `execute()` (and therefore onlySelf import) is frozen until `lockedUntil`.
contract LockedExecuteWallet is ActorStore {
    Keystore public immutable KEYSTORE;
    address public immutable owner;
    uint256 public immutable lockedUntil;

    error NotOwner();
    error WalletLocked();

    constructor(Keystore keystore_, address owner_, uint256 lockedUntil_, Keystore.InitialActor[] memory actors)
        ActorStore(actors)
    {
        KEYSTORE = keystore_;
        owner = owner_;
        lockedUntil = lockedUntil_;
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

    function importToKeystore() external {
        if (msg.sender != address(this)) revert NotOwner();
        Keystore.InitialActor[] memory actors = initialActors();
        bytes32 digest = KEYSTORE.computeImportDigest(address(this), actors);
        assembly {
            tstore(IMPORT_DIGEST_TSLOT, digest)
        }
        KEYSTORE.importAccount();
        assembly {
            tstore(IMPORT_DIGEST_TSLOT, 0)
        }
    }

    function confirmKeystoreImport() external view returns (bytes32 digest, Keystore.InitialActor[] memory actors) {
        actors = initialActors();
        assembly {
            digest := tload(IMPORT_DIGEST_TSLOT)
        }
        if (msg.sender != address(KEYSTORE) || digest == 0) return (bytes32(0), actors);
    }
}

contract EmptyImportActorsWallet {
    function confirmKeystoreImport() external pure returns (bytes32, Keystore.InitialActor[] memory actors) {
        return (bytes32(0), actors);
    }
}

contract PlainWallet {
    function isValidSignature(bytes32, bytes calldata) external pure returns (bytes4) {
        return 0x1626ba7e;
    }
}

contract EchoFallbackWallet {
    fallback() external {
        assembly {
            calldatacopy(0, 0, calldatasize())
            return(0, calldatasize())
        }
    }
}

contract AddressEchoWallet {
    fallback() external {
        assembly {
            mstore(0, address())
            return(0, 32)
        }
    }
}

contract EchoConfirmWallet is ActorStore {
    constructor(Keystore.InitialActor[] memory actors) ActorStore(actors) {}

    function confirmKeystoreImport() external pure returns (bytes32, Keystore.InitialActor[] memory) {
        assembly {
            calldatacopy(0, 0, calldatasize())
            return(0, calldatasize())
        }
    }
}

contract AddressEchoConfirmWallet is ActorStore {
    constructor(Keystore.InitialActor[] memory actors) ActorStore(actors) {}

    function confirmKeystoreImport() external view returns (bytes32, Keystore.InitialActor[] memory) {
        assembly {
            mstore(0, address())
            return(0, 32)
        }
    }
}

contract ShortReturnConfirmWallet is ActorStore {
    constructor(Keystore.InitialActor[] memory actors) ActorStore(actors) {}

    function confirmKeystoreImport() external pure returns (bytes32, Keystore.InitialActor[] memory) {
        assembly ("memory-safe") {
            mstore(0x00, 1)
            return(0x00, 4)
        }
    }
}

contract DirtyReturnConfirmWallet is ActorStore {
    constructor(Keystore.InitialActor[] memory actors) ActorStore(actors) {}

    function confirmKeystoreImport() external view returns (bytes32, Keystore.InitialActor[] memory actors) {
        return (bytes32(uint256(1)), initialActors());
    }
}

contract RevertingConfirmWallet is ActorStore {
    constructor(Keystore.InitialActor[] memory actors) ActorStore(actors) {}

    function confirmKeystoreImport() external pure returns (bytes32, Keystore.InitialActor[] memory) {
        revert("no");
    }
}

contract MismatchDigestWallet is ActorStore {
    constructor(Keystore.InitialActor[] memory actors) ActorStore(actors) {}

    function confirmKeystoreImport() external view returns (bytes32, Keystore.InitialActor[] memory actors) {
        return (keccak256("other"), initialActors());
    }
}

contract ConstructorImporter {
    constructor(Keystore keystore) {
        keystore.importAccount();
    }
}

/// @dev Existing wallet whose {initialActors} reconstructs owners from storage and appends a code-baked
///      canonical executor. Confirmation recomputes that set (stateless / init-time style).
contract StorageReconstructedWallet {
    Keystore public immutable KEYSTORE;
    address public immutable PASSKEY_AUTHENTICATOR;
    address public immutable ENTRY_POINT;

    address constant TRUSTED_EXECUTOR = address(uint160(uint256(keccak256("trustedExecutor"))));

    error OnlySelf();
    error NotOwner();

    address public owner;
    Keystore.InitialActor[] internal _storedOwners;

    constructor(
        Keystore keystore_,
        address owner_,
        address passkeyAuthenticator_,
        address entryPoint_,
        Keystore.InitialActor[] memory storedOwners
    ) {
        KEYSTORE = keystore_;
        owner = owner_;
        PASSKEY_AUTHENTICATOR = passkeyAuthenticator_;
        ENTRY_POINT = entryPoint_;
        for (uint256 i; i < storedOwners.length; i++) {
            _storedOwners.push(storedOwners[i]);
        }
    }

    function initialActors() public view returns (Keystore.InitialActor[] memory actors) {
        actors = new Keystore.InitialActor[](_storedOwners.length + 1);
        for (uint256 i; i < _storedOwners.length; i++) {
            actors[i] = _storedOwners[i];
        }
        actors[_storedOwners.length] = Keystore.InitialActor({
            actorId: bytes32(uint256(uint160(ENTRY_POINT))), authenticator: TRUSTED_EXECUTOR, scope: 0, policyData: ""
        });
        _sortByActorId(actors);
    }

    function importSelf() external {
        if (msg.sender != address(this)) revert OnlySelf();
        KEYSTORE.importAccount();
    }

    function importPermissionless() external {
        KEYSTORE.importAccount();
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

    function confirmKeystoreImport() external view returns (bytes32 digest, Keystore.InitialActor[] memory actors) {
        actors = initialActors();
        if (msg.sender != address(KEYSTORE)) return (bytes32(0), actors);
        digest = KEYSTORE.computeImportDigest(address(this), actors);
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
///      importAccount's source control flow (onlyUnlocked → AlreadyInitialized → confirmKeystoreImport
///      decode → _validateInitialActors → digest match); happy/branch paths follow.
contract ImportAccountTest is KeystoreTest {
    bytes32 constant ACTOR_INITIALIZATION_TYPEHASH = keccak256(
        "ActorInitialization(bytes32 accountId,Actor[] initialActors)Actor(bytes32 actorId,ActorConfig config,bytes policyData)ActorConfig(address authenticator,uint48 expiry,uint16 scope)"
    );
    bytes32 constant ACTOR_TYPEHASH = keccak256(
        "Actor(bytes32 actorId,ActorConfig config,bytes policyData)ActorConfig(address authenticator,uint48 expiry,uint16 scope)"
    );
    bytes32 constant ACTOR_CONFIG_TYPEHASH = keccak256("ActorConfig(address authenticator,uint48 expiry,uint16 scope)");

    function _computeImportDigest(address account, Keystore.InitialActor[] memory initialActors)
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
                keccak256(abi.encodePacked(actorHashes))
            )
        );
    }

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

    function _importable(address owner, Keystore.InitialActor[] memory actors) internal returns (ImportableWallet) {
        return new ImportableWallet(keystore, owner, actors);
    }

    function _importAs(address account) internal {
        vm.prank(account);
        keystore.importAccount();
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
    function test_importAccount_revert_accountIsLocked(uint256 ownerSeed, uint16 delay) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        vm.assume(delay != 0);
        address account = vm.addr(ownerPk);

        _signedLock(ownerPk, account, delay);

        vm.expectRevert(Keystore.AccountIsLocked.selector);
        _importAs(account);
    }

    /// @notice A third party cannot import a wallet: there is no account parameter, so the call attempts to import
    ///         the caller. The test contract has no confirmKeystoreImport, so confirmation fails and the wallet
    ///         is untouched.
    function test_importAccount_revert_callerNotAccount(uint256 ownerSeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        address owner = vm.addr(ownerPk);
        ImportableWallet wallet = _importable(owner, _singleUnrestrictedActor(owner));

        vm.expectRevert();
        keystore.importAccount();
        _assertUnimported(address(wallet));
    }

    /// @notice A wallet that locks `execute()` until `lockedUntil` cannot self-import while that lock is active.
    function test_importAccount_revert_executeLockedWallet(uint256 ownerSeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        address owner = vm.addr(ownerPk);
        uint256 unlockTime = block.timestamp + 30 days;
        LockedExecuteWallet wallet =
            new LockedExecuteWallet(keystore, owner, unlockTime, _singleUnrestrictedActor(owner));

        vm.expectRevert(LockedExecuteWallet.WalletLocked.selector);
        vm.prank(owner);
        wallet.execute(address(wallet), 0, abi.encodeCall(LockedExecuteWallet.importToKeystore, ()));

        _assertUnimported(address(wallet));
    }

    /// @notice After the execution lock expires, the same wallet can self-import through `execute()`.
    function test_importAccount_success_executeUnlockedWallet(uint256 ownerSeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        address owner = vm.addr(ownerPk);
        uint256 unlockTime = block.timestamp + 30 days;
        LockedExecuteWallet wallet =
            new LockedExecuteWallet(keystore, owner, unlockTime, _singleUnrestrictedActor(owner));

        vm.warp(unlockTime);
        vm.prank(owner);
        wallet.execute(address(wallet), 0, abi.encodeCall(LockedExecuteWallet.importToKeystore, ()));

        assertEq(keystore.getChangeSequences(address(wallet)).localSequence, 1);
        assertTrue(_isActor(address(wallet), bytes32(uint256(uint160(owner)))));
    }

    /// @notice Verifies importAccount reverts on an already-created account (localSequence == 1).
    function test_importAccount_revert_alreadyInitialized_createdAccount(uint256 pkSeed) public {
        uint256 pk = _boundK1Pk(pkSeed);
        (address account,) = _createK1Account(pk);

        vm.expectRevert(Keystore.AlreadyInitialized.selector);
        _importAs(account);
    }

    /// @notice Verifies a second importAccount on the same account reverts.
    function test_importAccount_revert_alreadyInitialized_reimport(uint256 ownerSeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        address owner = vm.addr(ownerPk);
        ImportableWallet wallet = _importable(owner, _singleUnrestrictedActor(owner));

        vm.prank(owner);
        wallet.importToKeystore();

        vm.expectRevert(Keystore.AlreadyInitialized.selector);
        vm.prank(owner);
        wallet.importToKeystore();
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
        _importAs(eoa);
    }

    /// @notice A 7702-delegated EOA imports like any other account if the delegate implements confirmKeystoreImport.
    function test_importAccount_success_7702_delegatedEoa(uint256 eoaSeed) public {
        uint256 eoaPk = _boundK1Pk(eoaSeed);
        address eoa = vm.addr(eoaPk);

        DelegatedImportWallet impl = new DelegatedImportWallet(keystore);
        vm.etch(eoa, abi.encodePacked(hex"ef0100", address(impl)));

        _importAs(eoa);
        assertEq(keystore.getChangeSequences(eoa).localSequence, 1);
        assertTrue(_isActor(eoa, bytes32(uint256(uint160(eoa)))));
    }

    /// @notice A delegated EOA already initialized via signed changes still reverts AlreadyInitialized.
    function test_importAccount_revert_7702_alreadyInitialized(uint256 eoaSeed, uint256 deviceSeed) public {
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

        StatelessImportWallet impl = new StatelessImportWallet(keystore, _singleUnrestrictedActor(eoa));
        vm.etch(eoa, abi.encodePacked(hex"ef0100", address(impl)));

        vm.expectRevert(Keystore.AlreadyInitialized.selector);
        _importAs(eoa);
    }

    /// @notice A code-less account (plain EOA) fails confirmation: empty returndata is not the actor-set digest.
    function test_importAccount_revert_noCode(uint256 accountSeed) public {
        uint256 accountPk = _boundK1Pk(accountSeed);
        address account = vm.addr(accountPk);

        vm.expectRevert();
        _importAs(account);
        _assertUnimported(account);
    }

    /// @notice Calling importAccount from a constructor fails the same way (runtime code is not yet stored).
    function test_importAccount_revert_fromConstructor() public {
        vm.expectRevert();
        new ConstructorImporter(keystore);
    }

    /// @notice An empty actor array from confirmKeystoreImport reverts NoInitialActors.
    function test_importAccount_revert_noInitialActors() public {
        EmptyImportActorsWallet wallet = new EmptyImportActorsWallet();

        vm.expectRevert(Keystore.NoInitialActors.selector);
        _importAs(address(wallet));
        _assertUnimported(address(wallet));
    }

    /// @notice A plain wallet that does not implement confirmKeystoreImport reverts on ABI-decode of the empty return.
    function test_importAccount_revert_missingConfirm() public {
        PlainWallet wallet = new PlainWallet();

        vm.expectRevert();
        _importAs(address(wallet));
        _assertUnimported(address(wallet));
    }

    /// @notice An echo-fallback that returns calldata reverts on decode of confirmKeystoreImport.
    function test_importAccount_revert_echoFallbackCalldata() public {
        EchoFallbackWallet wallet = new EchoFallbackWallet();

        vm.expectRevert();
        _importAs(address(wallet));
        _assertUnimported(address(wallet));
    }

    /// @notice An echo-fallback that returns address(this) reverts on decode of confirmKeystoreImport.
    function test_importAccount_revert_echoFallbackAddress() public {
        AddressEchoWallet wallet = new AddressEchoWallet();

        vm.expectRevert();
        _importAs(address(wallet));
        _assertUnimported(address(wallet));
    }

    /// @notice Unsorted initialActors reverts ActorsNotSortedOrDuplicate before confirmation.
    function test_importAccount_revert_actorsNotSorted(bytes32 idA, bytes32 idB) public {
        vm.assume(idA != 0 && idB != 0 && idA != idB);
        bytes32 smaller = idA < idB ? idA : idB;
        bytes32 larger = idA < idB ? idB : idA;

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](2);
        actors[0] =
            Keystore.InitialActor({actorId: larger, authenticator: address(k1Authenticator), scope: 0, policyData: ""});
        actors[1] = Keystore.InitialActor({
            actorId: smaller, authenticator: address(k1Authenticator), scope: 0, policyData: ""
        });

        ImportableWallet wallet = _importable(vm.addr(1), actors);
        vm.expectRevert(Keystore.ActorsNotSortedOrDuplicate.selector);
        _importAs(address(wallet));
        _assertUnimported(address(wallet));
    }

    /// @notice Duplicate actorIds reverts ActorsNotSortedOrDuplicate before confirmation.
    function test_importAccount_revert_actorsDuplicate(bytes32 id) public {
        vm.assume(id != 0);

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](2);
        actors[0] =
            Keystore.InitialActor({actorId: id, authenticator: address(k1Authenticator), scope: 0, policyData: ""});
        actors[1] =
            Keystore.InitialActor({actorId: id, authenticator: address(k1Authenticator), scope: 0, policyData: ""});

        ImportableWallet wallet = _importable(vm.addr(1), actors);
        vm.expectRevert(Keystore.ActorsNotSortedOrDuplicate.selector);
        _importAs(address(wallet));
        _assertUnimported(address(wallet));
    }

    /// @notice A sub-K1 authenticator reverts InvalidAuthenticator before confirmation.
    function test_importAccount_revert_invalidAuthenticator(bytes32 actorId) public {
        vm.assume(actorId != 0);

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](1);
        actors[0] = Keystore.InitialActor({actorId: actorId, authenticator: address(0), scope: 0, policyData: ""});

        ImportableWallet wallet = _importable(vm.addr(1), actors);
        vm.expectRevert(Keystore.InvalidAuthenticator.selector);
        _importAs(address(wallet));
        _assertUnimported(address(wallet));
    }

    /// @notice Malformed policyData reverts InvalidPolicyData before confirmation.
    function test_importAccount_revert_invalidPolicyData(bytes32 actorId) public {
        vm.assume(actorId != 0);

        Keystore.InitialActor[] memory actors = new Keystore.InitialActor[](1);
        actors[0] = Keystore.InitialActor({
            actorId: actorId, authenticator: address(k1Authenticator), scope: 0, policyData: hex"deadbeef"
        });

        ImportableWallet wallet = _importable(vm.addr(1), actors);
        vm.expectRevert(Keystore.InvalidPolicyData.selector);
        _importAs(address(wallet));
        _assertUnimported(address(wallet));
    }

    function _assertConfirmRejected(address wallet) internal {
        vm.expectRevert(Keystore.ImportNotConfirmed.selector);
        _importAs(wallet);
        _assertUnimported(wallet);
    }

    function _assertConfirmDecodeRejected(address wallet) internal {
        vm.expectRevert();
        _importAs(wallet);
        _assertUnimported(wallet);
    }

    /// @notice confirmKeystoreImport echoing calldata fails ABI-decode.
    function test_importAccount_revert_confirm_echoCalldata(uint256 ownerSeed) public {
        EchoConfirmWallet wallet = new EchoConfirmWallet(_singleUnrestrictedActor(vm.addr(_boundK1Pk(ownerSeed))));
        _assertConfirmDecodeRejected(address(wallet));
    }

    /// @notice confirmKeystoreImport echoing address(this) fails ABI-decode.
    function test_importAccount_revert_confirm_echoAddress(uint256 ownerSeed) public {
        AddressEchoConfirmWallet wallet =
            new AddressEchoConfirmWallet(_singleUnrestrictedActor(vm.addr(_boundK1Pk(ownerSeed))));
        _assertConfirmDecodeRejected(address(wallet));
    }

    /// @notice Non-tuple confirm returndata fails ABI-decode.
    function test_importAccount_revert_confirm_wrongLength(uint256 ownerSeed) public {
        ShortReturnConfirmWallet wallet =
            new ShortReturnConfirmWallet(_singleUnrestrictedActor(vm.addr(_boundK1Pk(ownerSeed))));
        _assertConfirmDecodeRejected(address(wallet));
    }

    /// @notice A 32-byte non-digest word with a valid actor set is ImportNotConfirmed; account state is rolled back.
    function test_importAccount_revert_confirm_dirtyReturn(uint256 ownerSeed) public {
        DirtyReturnConfirmWallet wallet =
            new DirtyReturnConfirmWallet(_singleUnrestrictedActor(vm.addr(_boundK1Pk(ownerSeed))));
        _assertConfirmRejected(address(wallet));
    }

    /// @notice confirmKeystoreImport reverting is ImportNotConfirmed; account state is rolled back.
    function test_importAccount_revert_confirm_reverting(uint256 ownerSeed) public {
        RevertingConfirmWallet wallet =
            new RevertingConfirmWallet(_singleUnrestrictedActor(vm.addr(_boundK1Pk(ownerSeed))));
        _assertConfirmRejected(address(wallet));
    }

    /// @notice Returning a different digest than computeImportDigest of the returned actors is ImportNotConfirmed.
    function test_importAccount_revert_digestMismatch(uint256 ownerSeed) public {
        MismatchDigestWallet wallet = new MismatchDigestWallet(_singleUnrestrictedActor(vm.addr(_boundK1Pk(ownerSeed))));
        _assertConfirmRejected(address(wallet));
    }

    /// @notice Direct importAccount without the transient handshake is ImportNotConfirmed (reference wallet).
    function test_importAccount_revert_confirm_noTransient(uint256 ownerSeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        address owner = vm.addr(ownerPk);
        ImportableWallet wallet = _importable(owner, _singleUnrestrictedActor(owner));
        _assertConfirmRejected(address(wallet));
    }

    /// @notice Owner `execute(keystore, importAccount())` bypasses the tstore handshake → ImportNotConfirmed.
    function test_importAccount_revert_executeKeystoreImport(uint256 ownerSeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        address owner = vm.addr(ownerPk);
        ImportableWallet wallet = _importable(owner, _singleUnrestrictedActor(owner));

        vm.expectRevert(Keystore.ImportNotConfirmed.selector);
        vm.prank(owner);
        wallet.execute(address(keystore), 0, abi.encodeCall(Keystore.importAccount, ()));
        _assertUnimported(address(wallet));
    }

    /// @notice Owner `execute(this, importToKeystore)` cannot satisfy onlyOwner (self-call); import does not run.
    function test_importAccount_revert_executeSelfImportToKeystore(uint256 ownerSeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        address owner = vm.addr(ownerPk);
        ImportableWallet wallet = _importable(owner, _singleUnrestrictedActor(owner));

        vm.expectRevert(ImportableWallet.NotOwner.selector);
        vm.prank(owner);
        wallet.execute(address(wallet), 0, abi.encodeCall(ImportableWallet.importToKeystore, ()));
        _assertUnimported(address(wallet));
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // HAPPY / BRANCH PATHS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice The public computeImportDigest matches the independent typehash reimplementation and is distinct
    ///         from the signed-change and signed-message typehashes.
    function test_computeImportDigest_matchesAndDistinctTypehash(uint256 ownerSeed) public view {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        address account = address(uint160(uint256(keccak256(abi.encode(ownerPk)))));
        Keystore.InitialActor[] memory actors = _singleUnrestrictedActor(vm.addr(ownerPk));

        assertEq(keystore.computeImportDigest(account, actors), _computeImportDigest(account, actors));
        assertTrue(keystore.ACTOR_INITIALIZATION_TYPEHASH() != keystore.SIGNED_ACCOUNT_CHANGES_TYPEHASH());
        assertTrue(keystore.ACTOR_INITIALIZATION_TYPEHASH() != keystore.SIGNED_MESSAGE_TYPEHASH());
    }

    /// @notice Happy path: owner-gated entry + transient confirmation.
    function test_importAccount_success_transient(uint256 ownerSeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        address owner = vm.addr(ownerPk);
        ImportableWallet wallet = _importable(owner, _singleUnrestrictedActor(owner));

        vm.prank(owner);
        wallet.importToKeystore();

        assertEq(keystore.getChangeSequences(address(wallet)).localSequence, 1);
        assertEq(keystore.getChangeSequences(address(wallet)).multichain, 0);
        assertTrue(_isActor(address(wallet), bytes32(uint256(uint160(owner)))));
    }

    /// @notice Stateless confirmation (recompute from initialActors) works without a transient handshake.
    function test_importAccount_success_stateless(uint256 ownerSeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        address owner = vm.addr(ownerPk);
        StatelessImportWallet wallet = new StatelessImportWallet(keystore, _singleUnrestrictedActor(owner));

        wallet.importToKeystore();

        assertEq(keystore.getChangeSequences(address(wallet)).localSequence, 1);
        assertTrue(_isActor(address(wallet), bytes32(uint256(uint160(owner)))));
    }

    /// @notice importAccount emits AccountImported(account) exactly once on the happy path.
    function test_importAccount_success_emitsAccountImported(uint256 ownerSeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        address owner = vm.addr(ownerPk);
        ImportableWallet wallet = _importable(owner, _singleUnrestrictedActor(owner));

        vm.expectEmit(true, false, false, true, address(keystore));
        emit Keystore.AccountImported(address(wallet));
        vm.prank(owner);
        wallet.importToKeystore();
    }

    /// @notice FLAG_REVOKE_DEFAULT_EOA is set after import (the implicit default-EOA self key is disabled).
    function test_importAccount_success_defaultEoaRevokedFlagSet(uint256 ownerSeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        address owner = vm.addr(ownerPk);
        ImportableWallet wallet = _importable(owner, _singleUnrestrictedActor(owner));

        vm.prank(owner);
        wallet.importToKeystore();

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
        address owner = vm.addr(_boundK1Pk(base));
        ImportableWallet wallet = _importable(owner, actors);

        vm.prank(owner);
        wallet.importToKeystore();

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

    /// @notice After a successful transient import, confirmKeystoreImport no longer returns the bound value.
    function test_importAccount_success_transientClearedAfterImport(uint256 ownerSeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        address owner = vm.addr(ownerPk);
        ImportableWallet wallet = _importable(owner, _singleUnrestrictedActor(owner));

        vm.prank(owner);
        wallet.importToKeystore();

        vm.prank(address(keystore));
        (bytes32 digest,) = wallet.confirmKeystoreImport();
        assertEq(digest, bytes32(0));
    }

    // ── Storage-reconstructed existing wallet ──

    function _reconstructedWallet(uint256 ownerPk, uint256 passkeySeed)
        internal
        returns (StorageReconstructedWallet wallet, address owner, bytes32 passkeyId, address entryPoint)
    {
        owner = vm.addr(ownerPk);
        passkeyId = keccak256(abi.encodePacked("passkey", passkeySeed));
        entryPoint = ENTRY_POINT;
        vm.assume(passkeyId != bytes32(uint256(uint160(owner))));
        vm.assume(passkeyId != bytes32(uint256(uint160(entryPoint))));
        address passkeyAuth = address(uint160(uint256(keccak256("passkeyAuthenticator"))));

        Keystore.InitialActor[] memory owners = new Keystore.InitialActor[](2);
        owners[0] = Keystore.InitialActor({
            actorId: bytes32(uint256(uint160(owner))), authenticator: address(k1Authenticator), scope: 0, policyData: ""
        });
        owners[1] = Keystore.InitialActor({actorId: passkeyId, authenticator: passkeyAuth, scope: 0, policyData: ""});
        wallet = new StorageReconstructedWallet(keystore, owner, passkeyAuth, entryPoint, owners);
    }

    /// @notice Permissionless import still installs the storage-reconstructed set plus the code-baked executor.
    function test_importAccount_success_permissionlessReconstructsOwners(uint256 ownerSeed, uint256 passkeySeed)
        public
    {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        (StorageReconstructedWallet wallet, address owner, bytes32 passkeyId, address entryPoint) =
            _reconstructedWallet(ownerPk, passkeySeed);

        wallet.importPermissionless();

        assertEq(keystore.getChangeSequences(address(wallet)).localSequence, 1);
        assertTrue(_isActor(address(wallet), bytes32(uint256(uint160(owner)))));
        assertTrue(_isActor(address(wallet), passkeyId));
        assertTrue(_isActor(address(wallet), bytes32(uint256(uint160(entryPoint)))));
        assertEq(
            keystore.getActorConfig(address(wallet), bytes32(uint256(uint160(entryPoint)))).authenticator,
            address(uint160(uint256(keccak256("trustedExecutor"))))
        );
    }

    /// @notice onlySelf import, reached as an `initData` self-call through `execute`.
    function test_importAccount_success_onlySelfImportViaExecute(uint256 ownerSeed, uint256 passkeySeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        (StorageReconstructedWallet wallet, address owner, bytes32 passkeyId,) =
            _reconstructedWallet(ownerPk, passkeySeed);

        vm.prank(owner);
        wallet.execute(address(wallet), 0, abi.encodeCall(StorageReconstructedWallet.importSelf, ()));

        assertEq(keystore.getChangeSequences(address(wallet)).localSequence, 1);
        assertTrue(_isActor(address(wallet), bytes32(uint256(uint160(owner)))));
        assertTrue(_isActor(address(wallet), passkeyId));
    }

    /// @notice A third party cannot call importSelf (OnlySelf). A chosen actor set that is not the wallet's
    ///         reconstructed digest is ImportNotConfirmed.
    function test_importAccount_revert_onlySelfImport_notSelf(uint256 ownerSeed, uint256 passkeySeed) public {
        uint256 ownerPk = _boundK1Pk(ownerSeed);
        (StorageReconstructedWallet wallet,,,) = _reconstructedWallet(ownerPk, passkeySeed);

        vm.expectRevert(StorageReconstructedWallet.OnlySelf.selector);
        wallet.importSelf();
        _assertUnimported(address(wallet));
    }
}
