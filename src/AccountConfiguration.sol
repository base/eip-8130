// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IAuthenticator} from "./interfaces/IAuthenticator.sol";

/// @notice Account Configuration system contract for EIP-8130.
///         Manages actor authorization, account creation, change sequencing, and account lock. This contract is
///         also the canonical reference for the EIP-8130 Account Configuration ABI: its public structs, events,
///         and function signatures are the spec surface, and there is no separate interface file to keep in sync.
///
/// @author Coinbase
contract AccountConfiguration {
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // STRUCTS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Per-account replay counters for signed changes.
    struct ChangeSequences {
        uint64 multichain; // chain_id 0
        uint64 local; // chain_id == block.chainid; starts at 1 once initialized (created/imported), 0 = uninitialized
    }

    /// @notice An actor's authorization: authenticator, scope, expiry, and policy sub-type.
    struct ActorConfig {
        address authenticator;
        uint8 scope;
        uint48 expiry; // Unix seconds; 0 = no expiry. Actor invalid once block.timestamp > expiry
        uint8 policyType; // 0x00 = none; any non-zero = gated to stored manager (value interpreted by the manager)
    }

    /// @notice Minimal actor for account creation and import (always unrestricted: scope 0x00, no expiry, no policy).
    struct InitialActor {
        bytes32 actorId;
        address authenticator;
    }

    /// @notice A full actor record: identifier, config, and policy data.
    struct Actor {
        bytes32 actorId;
        ActorConfig config;
        // Sliced by policyType: empty (0x00); manager[20] || commitment[32] (non-zero).
        bytes policyData;
    }

    /// @notice A single authorize/revoke operation within a signed batch.
    struct ActorChange {
        uint8 changeType; // 0x01 = authorizeActor, 0x02 = revokeActor
        bytes32 actorId;
        bytes data; // operation-specific: ActorConfig || policyData for authorize, empty for revoke
    }

    /// @notice Per-account packed state: sequences, lock status, and the inline home for the account's k1 self key.
    ///
    /// @dev Packed into a single storage slot (exactly 32 bytes).
    ///      localSequence > 0 doubles as the account initialized flag.
    ///      The defaultEOA* fields are the inline home for the account's own secp256k1 ("self") key — the actor whose
    ///      actorId is bytes32(bytes20(account)). When FLAG_REVOKE_DEFAULT_EOA is unset, a k1 signature recovering to
    ///      the account authenticates with this inline config (all-zero = full owner; non-zero scope/expiry/policy =
    ///      a scoped self key), resolved in a single SLOAD. The separate _actorConfig[self][account] slot is reserved
    ///      for a *non-k1* self authenticator (e.g. a post-quantum verifier returning the self-actorId); the two
    ///      homes are mutually exclusive (see _authorizeActor).
    struct AccountState {
        uint64 multichainSequence; // 8 bytes
        uint64 localSequence; // 8 bytes – also serves as initialized flag
        uint40 unlocksAt; // 5 bytes
        uint16 unlockDelay; // 2 bytes
        uint8 flags; // 1 byte – bitfield; bit 0 = default EOA revoked (see FLAG_REVOKE_DEFAULT_EOA)
        uint8 defaultEOAScope; // 1 byte – inline self k1 scope (0 = full owner)
        uint8 defaultEOAPolicyType; // 1 byte – inline self k1 policy sub-type (0 = none)
        uint48 defaultEOAExpiry; // 6 bytes – inline self k1 expiry (Unix seconds; 0 = no expiry)
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // CONSTANTS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @dev ERC-1271 isValidSignature(bytes32,bytes) selector, which also equals the ERC-1271 magic return value
    ///      (0x1626ba7e); used both to build the import staticcall and to validate its result.
    bytes4 constant ERC1271_SELECTOR = bytes4(keccak256("isValidSignature(bytes32,bytes)"));

    /// @notice Typehash binding an importAccount signature to its salt, chainId, and initial actor set.
    ///
    /// @dev NOT compliant with EIP-712, to mitigate eth_signTypedData phishing. Bound to the current chainId so an
    ///      import signature cannot be replayed on another chain. Initial actors are hashed structurally via
    ///      ACTOR_TYPEHASH / ACTORCONFIG_TYPEHASH below.
    bytes32 public constant ACTOR_INITIALIZATION_TYPEHASH = keccak256(
        "ActorInitialization(bytes32 salt,uint256 chainId,Actor[] initialActors)Actor(bytes32 actorId,ActorConfig config,bytes policyData)ActorConfig(address authenticator,uint8 scope,uint48 expiry,uint8 policyType)"
    );

    /// @notice Typehash used to structurally hash each Actor within an ActorInitialization import digest.
    bytes32 public constant ACTOR_TYPEHASH = keccak256(
        "Actor(bytes32 actorId,ActorConfig config,bytes policyData)ActorConfig(address authenticator,uint8 scope,uint48 expiry,uint8 policyType)"
    );

    /// @notice Typehash used to structurally hash an Actor's ActorConfig within an import digest.
    bytes32 public constant ACTORCONFIG_TYPEHASH =
        keccak256("ActorConfig(address authenticator,uint8 scope,uint48 expiry,uint8 policyType)");

    /// @notice Typehash binding a signed actor-change batch to its account, chainId, and sequence.
    ///
    /// @dev NOT compliant with EIP-712, to mitigate phishing attacks.
    bytes32 public constant SIGNED_ACTOR_CHANGES_TYPEHASH = keccak256(
        "SignedActorChanges(address account,uint256 chainId,uint64 sequence,ActorChange[] actorChanges)"
        "ActorChange(uint8 changeType,bytes32 actorId,bytes data)"
    );

    /// @notice Typehash used to structurally hash each ActorChange within a SignedActorChanges batch.
    bytes32 public constant ACTORCHANGE_TYPEHASH =
        keccak256("ActorChange(uint8 changeType,bytes32 actorId,bytes data)");

    // ----------------------------------------------------------------------------------------------------------------
    // ACTOR CHANGE TYPES
    // ----------------------------------------------------------------------------------------------------------------

    /// @notice Authorize an actor to the account
    uint8 public constant AUTHORIZE_ACTOR = 0x01;

    /// @notice Revoke an actor from the account
    uint8 public constant REVOKE_ACTOR = 0x02;

    // ----------------------------------------------------------------------------------------------------------------
    // ACTOR POLICY TYPES
    // ----------------------------------------------------------------------------------------------------------------

    /// @notice No execution policy; actor is ungated.
    uint8 public constant POLICY_NONE = 0x00;

    /// @notice Canonical non-zero policy type. Any non-zero `policyType` gates the actor to its stored
    ///         manager + commitment (self-enforcement is manager == account); the contract does not interpret
    ///         the specific value, leaving it for the manager to read as a sub-type. `0x01` is the value used
    ///         when no sub-type is needed.
    uint8 public constant POLICY_GATED = 0x01;

    // ----------------------------------------------------------------------------------------------------------------
    // ACTOR ELEVATED SCOPES
    // ----------------------------------------------------------------------------------------------------------------

    /// @notice Actor can sign arbitrary messages with account
    uint8 public constant SCOPE_SIGNER = 0x01;

    /// @notice Actor can initiate transactions with account as sender
    uint8 public constant SCOPE_SENDER = 0x02;

    /// @notice Actor can pay for transactions with account as payer
    uint8 public constant SCOPE_PAYER = 0x04;

    /// @notice Actor can change account configuration (authorize/revoke actors). This is an administrative,
    ///         root-equivalent capability: a config key can authorize brand-new unrestricted owners, so it must be
    ///         treated as being as powerful as full ownership. Policy-bearing actors are barred from holding it
    ///         (see _authorizeActor), since a policy could otherwise be escaped by minting a fresh unrestricted actor.
    uint8 public constant SCOPE_CONFIG = 0x08;

    /// @notice The single secp256k1 authenticator. The default EOA and every k1 actor share this one identity; the
    ///         actor config alone distinguishes a full-owner EOA from a scoped key. Signed with a K1_AUTHENTICATOR
    ///         (20) || r‖s‖v auth blob.
    ///
    /// @dev Authenticator namespace: 1 = the canonical secp256k1 ("K1") verifier (native ecrecover); 2..max = custom
    ///      IAuthenticator contracts. address(0) is reserved as the "no actor configured" storage sentinel and is
    ///      never a valid authenticator selector.
    address public constant K1_AUTHENTICATOR = address(1);

    // ----------------------------------------------------------------------------------------------------------------
    // ACCOUNT STATE FLAGS
    // ----------------------------------------------------------------------------------------------------------------

    /// @notice AccountState.flags bit: when set, the account's secp256k1 ("self") key cannot authenticate — neither
    ///         the implicit full owner nor an inline-scoped self. The self key is a K1_AUTHENTICATOR signature whose
    ///         recovered signer equals the account; when this flag is unset, it authenticates with the inline
    ///         AccountState.defaultEOA* config (all-zero = full owner), resolved in a single SLOAD. The flag is set
    ///         by createAccount/importAccount (self k1 disabled by default — quantum-safe), by revoking the
    ///         self-actorId, and by authorizing the self-actorId to a *non-k1* authenticator (mutual exclusion: the
    ///         k1 self and a non-k1 self are never simultaneously live). Authorizing the self-actorId as a k1 actor
    ///         clears it (re-enabling the inline self, possibly scoped).
    uint8 public constant FLAG_REVOKE_DEFAULT_EOA = 0x01;

    /// @dev secp256k1 half-order (n/2). Per EIP-2, only the lower-half `s` value is accepted to reject signature
    ///      malleability. Equal to (secp256k1n - 1) / 2.
    uint256 internal constant SECP256K1_HALF_ORDER = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // EVENTS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Emitted when an actor is authorized (created or updated).
    ///
    /// @param account The account whose actor was authorized.
    /// @param actorId The authorized actor's identifier.
    /// @param actorData Tightly packed authorization surface mirroring the storage/wire packing:
    ///        authenticator(20) || scope(1) || expiry(6) || policyType(1) = 28 bytes, and, only when
    ///        policyType != 0x00, followed by the resolved policy gate manager(20) || commitment(32). So the
    ///        payload is 28 bytes for an ungated actor and 80 bytes for a policy-gated one.
    event ActorAuthorized(address indexed account, bytes32 indexed actorId, bytes actorData);

    /// @notice Emitted when an actor is revoked from an account.
    ///
    /// @param account The account whose actor was revoked.
    /// @param actorId The revoked actor's identifier.
    event ActorRevoked(address indexed account, bytes32 indexed actorId);

    /// @notice Emitted when a new account is created.
    ///
    /// @param account The created account address.
    /// @param userSalt The caller-chosen salt used in the address derivation.
    /// @param codeHash The keccak256 of the account's deployment bytecode.
    event AccountCreated(address indexed account, bytes32 userSalt, bytes32 codeHash);

    /// @notice Emitted when an existing account is imported into management.
    ///
    /// @param account The imported account address.
    event AccountImported(address indexed account);

    /// @notice Protocol-injected receipt log for successful EIP-8130 delegation updates (not emitted in EVM).
    ///
    /// @param account The account whose delegation was updated.
    /// @param target The delegation target.
    event DelegationApplied(address indexed account, address target);

    /// @notice Emitted when an account is locked.
    ///
    /// @param account The locked account.
    /// @param unlockDelay The configured unlock delay in seconds.
    event AccountLocked(address indexed account, uint16 unlockDelay);

    /// @notice Emitted when an account's unlock is initiated.
    ///
    /// @param account The account whose unlock was initiated.
    /// @param unlocksAt The timestamp at which the account will unlock.
    event AccountUnlockInitiated(address indexed account, uint40 unlocksAt);

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // ERRORS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice An account address argument was the zero address.
    error ZeroAccount();

    /// @notice The account already has EIP-8130 state, so it cannot be created or imported again.
    error AlreadyInitialized();

    /// @notice The operation is not permitted while the account is locked.
    error AccountIsLocked();

    /// @notice The signed chainId is neither 0 (multichain) nor the current chain.
    error InvalidChainId();

    /// @notice The authenticated actor lacks the scope required to change actors.
    error UnauthorizedActorChange();

    /// @notice An ActorChange carried an unrecognized changeType.
    error UnknownChangeType();

    /// @notice The importAccount ERC-1271 signature check did not return the magic value.
    error InvalidImportSignature();

    /// @notice lock() was called with a zero unlock delay.
    error ZeroUnlockDelay();

    /// @notice initiateUnlock() was called when the account was not in the locked (unlocksAt == max) state.
    error NotLocked();

    /// @notice The auth blob is shorter than the 20-byte authenticator selector prefix.
    error InvalidAuthLength();

    /// @notice createAccount/importAccount was called with an empty initialActors set.
    error NoInitialActors();

    /// @notice initialActors are not strictly ascending by actorId (unsorted or duplicated).
    error ActorsNotSortedOrDuplicate();

    /// @notice An actor config named an authenticator below the K1 sentinel (i.e. address(0)).
    error InvalidAuthenticator();

    /// @notice A policy-bearing actor must be scope-restricted and must not hold change-actors scope.
    error InvalidPolicyScope();

    /// @notice The policyData length or embedded manager/commitment did not match the policyType.
    error InvalidPolicyData();

    /// @notice The referenced actor is not currently authorized on the account.
    error UnknownActor();

    /// @notice An authenticator resolved a zero actorId (authentication failed).
    error AuthenticationFailed();

    /// @notice The resolved actor is not bound to the presented authenticator.
    error AuthenticatorMismatch();

    /// @notice The actor's expiry has passed.
    error ActorExpired();

    /// @notice The signature was malformed: bad length, non-canonical v, high-s, or a zero recovery.
    error InvalidSignature();

    /// @notice The account's default (implicit/scoped) EOA key has been revoked.
    error DefaultEoaRevoked();

    /// @notice The provided account bytecode exceeds the maximum encodable length.
    error BytecodeTooLarge();

    /// @notice CREATE2 did not deploy code at the expected account address (e.g. bytecode too large per EIP-170,
    ///      leading 0xEF byte per EIP-3541, or out of gas). Reverting unwinds all state writes so no orphaned
    ///      EIP-8130 configuration is left behind.
    error AccountDeploymentFailed();

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // STORAGE
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Per-actor configuration
    /// @dev Account must be inner-most mapping key to pass ERC-7562 storage access rules for ERC-4337 compatibility.
    mapping(bytes32 actorId => mapping(address account => ActorConfig)) internal _actorConfig;

    /// @notice Per-actor signed policy commitment. Set when policyType != 0x00.
    /// @dev Read only during execution (via getPolicy), never during signature validity checks.
    mapping(bytes32 actorId => mapping(address account => bytes32)) internal _policyCommitment;

    /// @notice Per-actor policy manager address. Set when policyType != 0x00.
    mapping(bytes32 actorId => mapping(address account => address)) internal _policyManager;

    /// @notice Per-account state: sequences, lock status (single slot per account)
    mapping(address account => AccountState) internal _accountState;

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // MODIFIERS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Modifier to check if an account is unlocked.
    /// @dev Reverts with AccountIsLocked when the account is locked.
    modifier onlyUnlocked(address account) {
        if (_checkAndClearLock(account)) revert AccountIsLocked();
        _;
    }

    /// @notice Modifier to check if an account is not the zero address.
    /// @dev Reverts with ZeroAccount when the account is the zero address.
    modifier nonZeroAccount(address account) {
        if (account == address(0)) revert ZeroAccount();
        _;
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // FUNCTIONS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Deploys a new account with its initial actors, which are always registered as unrestricted owners
    ///         (scope 0x00, no expiry, no policy); scoped keys and session-key policies are added afterwards via
    ///         applySignedActorChanges. The implicit default-EOA key is disabled on creation.
    ///
    /// @dev Reverts with BytecodeTooLarge when `bytecode` exceeds the maximum encodable length.
    /// @dev Reverts with AlreadyInitialized when the account already has EIP-8130 state.
    /// @dev Reverts with NoInitialActors when `initialActors` is empty.
    /// @dev Reverts with ActorsNotSortedOrDuplicate when `initialActors` is not strictly ascending by actorId.
    /// @dev Reverts with InvalidAuthenticator when an initial actor names a zero authenticator.
    /// @dev Reverts with AccountDeploymentFailed when CREATE2 does not deploy code at the expected address.
    ///
    /// @param userSalt Caller-chosen salt mixed into the CREATE2 address derivation.
    /// @param bytecode Account deployment bytecode to CREATE2 at the derived address.
    /// @param initialActors Bootstrap owners, strictly ascending by actorId; each becomes an unrestricted owner.
    ///
    /// @return account The deployed account address.
    function createAccount(bytes32 userSalt, bytes calldata bytecode, InitialActor[] calldata initialActors)
        external
        returns (address account)
    {
        account = computeAddress(userSalt, bytecode, initialActors);

        // Block re-initialization of an already-bootstrapped account. localSequence doubles as the initialized flag,
        // so a prior createAccount/import set it to 1; multichainSequence guards an account that established 8130
        // state via a global (chainId 0) change. This must be explicit: now that authorizeActor is an upsert it no
        // longer reverts on a duplicate initial actor, and the create2 below is intentionally swallowed (pop), so a
        // duplicate createAccount would otherwise silently re-initialize.
        if (_accountState[account].localSequence != 0 || _accountState[account].multichainSequence != 0) {
            revert AlreadyInitialized();
        }

        // Mark the account initialized: localSequence doubles as the initialized flag, so setting it to 1 blocks
        // importAccount (which requires localSequence == 0) from running against an already-created account.
        // Created accounts have contract code at a CREATE2 address, so the default EOA path (recovered == account)
        // is unreachable; disable it by default so the account is canonically ECDSA-owner-free (quantum-safe by
        // default). This folds into the same slot write as localSequence, costing no extra SSTORE. Set *before*
        // initializing actors so a self-actorId k1 initial actor can re-enable the inline self (parity with import).
        _accountState[account].localSequence = 1;
        _accountState[account].flags = FLAG_REVOKE_DEFAULT_EOA;

        _initializeAccount(account, initialActors);

        // Create account code at the CREATE2 address derived from the packed actors commitment. The return value
        // MUST be checked: CREATE2 returns address(0) on failure (bytecode too large per EIP-170, a leading 0xEF
        // byte per EIP-3541, or out of gas). On success it returns the deployed address, which equals `account` by
        // construction. Reverting on mismatch unwinds every state write above, so a failed deploy can never leave an
        // initialized-but-codeless account behind.
        bytes memory deploymentCode = _buildDeploymentCode(bytecode);
        bytes32 effectiveSalt = _computeEffectiveSalt(userSalt, initialActors);
        address deployed;
        assembly ("memory-safe") {
            deployed := create2(0, add(deploymentCode, 0x20), mload(deploymentCode), effectiveSalt)
        }
        if (deployed != account) revert AccountDeploymentFailed();
        emit AccountCreated(account, userSalt, keccak256(bytecode));
    }

    /// @notice Imports an existing account (which must have bytecode) into AccountConfiguration management via an
    ///         ERC-1271 signature over a typed import digest. The implicit default-EOA key is disabled after import.
    ///
    /// @dev Uses a custom (non-EIP-712) digest to partially mitigate eth_signTypedData phishing.
    /// @dev Reverts with AccountIsLocked when the account is locked.
    /// @dev Reverts with InvalidChainId when `chainId` is neither 0 (multichain) nor the current chain.
    /// @dev Reverts with AlreadyInitialized when the account already has EIP-8130 state.
    /// @dev Reverts with InvalidImportSignature when the account's ERC-1271 check does not return the magic value.
    /// @dev Reverts with NoInitialActors when `initialActors` is empty.
    /// @dev Reverts with ActorsNotSortedOrDuplicate when `initialActors` is not strictly ascending by actorId.
    /// @dev Reverts with InvalidAuthenticator when an initial actor names a zero authenticator.
    ///
    /// @param account The account being imported.
    /// @param chainId Replay domain of the import signature: 0 = multichain (valid on every chain), otherwise it
    ///        must equal the current chain.
    /// @param initialActors Bootstrap owners, strictly ascending by actorId; each becomes an unrestricted owner.
    /// @param signature ERC-1271 signature the account validates over the import digest.
    function importAccount(
        address account,
        uint256 chainId,
        InitialActor[] calldata initialActors,
        bytes calldata signature
    ) external onlyUnlocked(account) {
        if (chainId != 0 && chainId != block.chainid) revert InvalidChainId();

        // Import is a one-time bootstrap for accounts with no 8130 state yet
        if (_accountState[account].localSequence != 0 || _accountState[account].multichainSequence != 0) {
            revert AlreadyInitialized();
        }
        _accountState[account].localSequence = 1;

        bytes32 digest = _computeImportDigest(account, chainId, initialActors);
        (bool success, bytes memory result) =
            account.staticcall(abi.encodeWithSelector(ERC1271_SELECTOR, digest, signature));
        if (!success || result.length != 32 || abi.decode(result, (bytes4)) != ERC1271_SELECTOR) {
            revert InvalidImportSignature();
        }

        // Disable the implicit default-EOA path (parity with createAccount). Set *after* the ERC-1271 check: for an
        // EIP-7702 delegated EOA its own k1 signature (the implicit full owner) is the only authenticator available
        // at import time, so it must stay live for that check. An owner who wants to keep using the key can include
        // the self-actorId as an explicit k1 actor in initialActors (still a full owner, now via its config), or
        // re-enable it later. Folds into the same slot as localSequence.
        _accountState[account].flags = FLAG_REVOKE_DEFAULT_EOA;

        _initializeAccount(account, initialActors);
        emit AccountImported(account);
    }

    /// @notice Applies a batch of signed actor changes (authorize/revoke) to an account's configuration.
    ///
    /// @dev Authorized when the authenticated actor is unrestricted (scope 0) or holds SCOPE_CONFIG. Replay is
    ///      bound by `chainId` and a monotonic per-account sequence consumed on each call.
    /// @dev Reverts with AccountIsLocked when the account is locked.
    /// @dev Reverts with InvalidChainId when `chainId` is neither 0 (multichain) nor the current chain.
    /// @dev Reverts with InvalidAuthLength, InvalidSignature, AuthenticationFailed, AuthenticatorMismatch,
    ///      ActorExpired, or DefaultEoaRevoked when `auth` fails to authenticate a live actor.
    /// @dev Reverts with UnauthorizedActorChange when the authenticated actor lacks CONFIG scope.
    /// @dev Reverts with UnknownChangeType when a change carries an unrecognized changeType.
    /// @dev Reverts with InvalidAuthenticator, InvalidPolicyScope, or InvalidPolicyData on a malformed authorize.
    /// @dev Reverts with UnknownActor when revoking an actor that is not authorized.
    ///
    /// @param account The account whose configuration is changed.
    /// @param chainId Replay domain: 0 = multichain (valid on every chain), otherwise the current chain.
    /// @param actorChanges Ordered authorize/revoke operations to apply.
    /// @param auth Authenticator(20) || authenticator-specific data authenticating a CONFIG-capable actor.
    function applySignedActorChanges(
        address account,
        uint256 chainId,
        ActorChange[] calldata actorChanges,
        bytes calldata auth
    ) external onlyUnlocked(account) {
        if (chainId != 0 && chainId != block.chainid) revert InvalidChainId();

        // Increment the corresponding sequence
        uint64 sequence =
            chainId == 0 ? _accountState[account].multichainSequence++ : _accountState[account].localSequence++;

        // Compute digest and authenticate
        bytes32 digest = _computeSignedActorChangesDigest(account, chainId, sequence, actorChanges);
        (uint8 scope,,) = authenticateActor(account, digest, auth);

        // Require actor has scope to change actors (scope == 0 means unrestricted)
        if (scope != 0 && scope & SCOPE_CONFIG == 0) revert UnauthorizedActorChange();

        // Apply actorChanges
        for (uint256 i; i < actorChanges.length; i++) {
            if (actorChanges[i].changeType == AUTHORIZE_ACTOR) {
                (ActorConfig memory newActorConfig, bytes memory policyData) =
                    abi.decode(actorChanges[i].data, (ActorConfig, bytes));
                _authorizeActor(account, actorChanges[i].actorId, newActorConfig, policyData);
            } else if (actorChanges[i].changeType == REVOKE_ACTOR) {
                _revokeActor(account, actorChanges[i].actorId);
            } else {
                revert UnknownChangeType();
            }
        }
    }

    // ----------------------------------------------------------------------------------------------------------------
    // ACCOUNT LOCKS
    // ----------------------------------------------------------------------------------------------------------------

    /// @notice Locks the caller's account to freeze actor configuration until an unlock is initiated and elapses.
    ///
    /// @dev Reverts with AccountIsLocked when the account is already locked.
    /// @dev Reverts with ZeroUnlockDelay when `unlockDelay` is zero.
    ///
    /// @param unlockDelay Delay in seconds, after initiateUnlock, before the account unlocks (max uint16, ~18 hours).
    function lock(uint16 unlockDelay) external onlyUnlocked(msg.sender) {
        // Require non-zero unlock delay
        if (unlockDelay == 0) revert ZeroUnlockDelay();

        AccountState storage config = _accountState[msg.sender];

        config.unlocksAt = type(uint40).max;
        config.unlockDelay = unlockDelay;
        emit AccountLocked(msg.sender, unlockDelay);
    }

    /// @notice Initiates unlocking the caller's account; it becomes unlocked once the configured delay elapses.
    ///
    /// @dev Reverts with NotLocked when the account is not in the locked state.
    function initiateUnlock() external {
        AccountState storage config = _accountState[msg.sender];

        // Require account is locked and unlock has not been initiated
        if (config.unlocksAt != type(uint40).max) revert NotLocked();

        config.unlocksAt = uint40(block.timestamp + config.unlockDelay);
        config.unlockDelay = 0;
        emit AccountUnlockInitiated(msg.sender, config.unlocksAt);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // VIEW FUNCTIONS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Validates an account signature in `authenticator(20) || data` format; never reverts.
    ///
    /// @dev ERC-1271-style boolean check: returns false on any failure (invalid signature, unknown/revoked actor,
    ///      actorId not bound to the presented authenticator, or an actor lacking SIGNER scope). authenticateActor
    ///      reverts on failure, so it is called externally and the revert is caught.
    ///
    /// @param account The account the signature is validated against.
    /// @param hash The digest that was signed.
    /// @param signature Authenticator(20) || authenticator-specific data.
    ///
    /// @return verified True if the signature is valid and the resolved actor may sign messages.
    function verifySignature(address account, bytes32 hash, bytes calldata signature)
        external
        view
        returns (bool verified)
    {
        try this.authenticateActor(account, hash, signature) returns (uint8 scope, uint8, address) {
            return scope == 0 || scope & SCOPE_SIGNER != 0;
        } catch {
            return false;
        }
    }

    /// @notice Authenticates that an account approved `hash` using auth in `authenticator(20) || data` format,
    ///         returning the verified actor's authorization surface (scope plus policy) so a consumer can decide
    ///         authorization from a single call without re-deriving the actorId.
    ///
    /// @dev `policyTarget` is the resolved policy manager, never the signed commitment (an execution-time read via
    ///      getPolicy), or address(0) when ungated.
    /// @dev Reverts with InvalidAuthLength when `auth` is shorter than 20 bytes.
    /// @dev Reverts with AuthenticationFailed, AuthenticatorMismatch, ActorExpired, DefaultEoaRevoked, or
    ///      InvalidSignature when the actor cannot be authenticated.
    ///
    /// @param account The account the signature is validated against.
    /// @param hash The digest that was signed.
    /// @param auth Authenticator(20) || authenticator-specific data.
    ///
    /// @return scope The scope of the verified actor (0x00 = unrestricted).
    /// @return policyType The actor's policy sub-type byte (0x00 = none).
    /// @return policyTarget The actor's policy gate target (manager), or address(0) if ungated.
    function authenticateActor(address account, bytes32 hash, bytes calldata auth)
        public
        view
        returns (uint8 scope, uint8 policyType, address policyTarget)
    {
        if (auth.length < 20) revert InvalidAuthLength();
        return _authenticate(account, hash, address(bytes20(auth[:20])), auth[20:]);
    }

    /// @notice Computes the counterfactual CREATE2 address for an account without deploying it.
    ///
    /// @dev Reverts with BytecodeTooLarge when `bytecode` exceeds the maximum encodable length.
    ///
    /// @param userSalt Caller-chosen salt mixed into the CREATE2 address derivation.
    /// @param bytecode Account deployment bytecode.
    /// @param initialActors Bootstrap owners committed into the effective salt.
    ///
    /// @return The counterfactual account address.
    function computeAddress(bytes32 userSalt, bytes calldata bytecode, InitialActor[] calldata initialActors)
        public
        view
        returns (address)
    {
        bytes32 effectiveSalt = _computeEffectiveSalt(userSalt, initialActors);
        bytes32 codeHash = keccak256(_buildDeploymentCode(bytecode));
        bytes32 create2Hash = keccak256(abi.encodePacked(bytes1(0xFF), address(this), effectiveSalt, codeHash));
        return address(uint160(uint256(create2Hash)));
    }

    // ----------------------------------------------------------------------------------------------------------------
    // STORAGE VIEWS
    // ----------------------------------------------------------------------------------------------------------------

    /// @notice Returns whether `actorId` is currently a live actor on `account`.
    ///
    /// @param account The account to check.
    /// @param actorId The actor identifier to check.
    ///
    /// @return True if the actor is authorized and live.
    function isActor(address account, bytes32 actorId) public view returns (bool) {
        // A populated _actorConfig entry is always live: any non-self actor, or a non-k1 self authenticator.
        if (_actorConfig[actorId][account].authenticator >= K1_AUTHENTICATOR) return true;
        // No _actorConfig entry: the self-actorId's k1 key lives inline in AccountState, live unless the flag is set.
        if (actorId == bytes32(bytes20(account))) return !_isDefaultEoaRevoked(account);
        return false;
    }

    /// @notice Resolves the effective ActorConfig for `actorId` on `account`.
    ///
    /// @dev With a populated _actorConfig entry, returns it verbatim (any non-self actor, or a non-k1 self). For the
    ///      self-actorId without such an entry, the k1 self lives inline in AccountState: a live one (flag unset)
    ///      reports as a native ecrecover owner carrying its inline scope/expiry/policy (all-zero = full owner); a
    ///      disabled one, or any unknown actor, reports as the all-zero (empty) config, keeping live-vs-disabled
    ///      unambiguous without a sentinel.
    ///
    /// @param account The account to read.
    /// @param actorId The actor identifier to resolve.
    ///
    /// @return The resolved actor configuration, or the all-zero config if the actor is not live.
    function getActorConfig(address account, bytes32 actorId) external view returns (ActorConfig memory) {
        ActorConfig memory config = _actorConfig[actorId][account];
        if (config.authenticator != address(0)) return config;
        if (actorId == bytes32(bytes20(account)) && !_isDefaultEoaRevoked(account)) {
            AccountState storage st = _accountState[account];
            return ActorConfig({
                authenticator: K1_AUTHENTICATOR,
                scope: st.defaultEOAScope,
                expiry: st.defaultEOAExpiry,
                policyType: st.defaultEOAPolicyType
            });
        }
        return config;
    }

    /// @notice Resolves an actor's policy sub-type, gate target (manager), and signed commitment.
    ///
    /// @dev Convenience aggregator for off-chain consumers; on-chain consumers should prefer the single-SLOAD
    ///      getPolicyCommitment / getPolicyManager accessors. Ungated resolves to (0, 0, 0); gated resolves to
    ///      (policyType, manager, commitment).
    ///
    /// @param account The account to read.
    /// @param actorId The actor identifier to resolve.
    ///
    /// @return policyType The actor's policy sub-type byte (0x00 = none).
    /// @return target The actor's policy gate target (manager), or address(0) if ungated.
    /// @return commitment The actor's signed policy commitment, or bytes32(0) if ungated.
    function getPolicy(address account, bytes32 actorId)
        external
        view
        returns (uint8 policyType, address target, bytes32 commitment)
    {
        ActorConfig storage stored = _actorConfig[actorId][account];
        if (stored.authenticator != address(0)) {
            policyType = stored.policyType;
        } else if (actorId == bytes32(bytes20(account)) && !_isDefaultEoaRevoked(account)) {
            // Inline k1 self: policy lives in AccountState's policyType byte, manager/commitment keyed by actorId.
            policyType = _accountState[account].defaultEOAPolicyType;
        } else {
            return (POLICY_NONE, address(0), bytes32(0));
        }
        if (policyType == POLICY_NONE) return (POLICY_NONE, address(0), bytes32(0));
        return (policyType, _policyManager[actorId][account], _policyCommitment[actorId][account]);
    }

    /// @notice Resolves an actor's signed policy commitment, or bytes32(0) if ungated or no actor.
    ///
    /// @dev Single SLOAD. The invariant maintained by _authorizeActor / _revokeActor is that this slot is non-zero
    ///      iff the actor has a non-zero policyType, so a zero return unambiguously means "no policy / no actor".
    ///
    /// @param account The account to read.
    /// @param actorId The actor identifier to resolve.
    ///
    /// @return The signed policy commitment, or bytes32(0) if ungated or no actor.
    function getPolicyCommitment(address account, bytes32 actorId) external view returns (bytes32) {
        return _policyCommitment[actorId][account];
    }

    /// @notice Resolves an actor's policy gate target (manager), or address(0) if ungated or no actor.
    ///
    /// @dev Single SLOAD. Same invariant as getPolicyCommitment.
    ///
    /// @param account The account to read.
    /// @param actorId The actor identifier to resolve.
    ///
    /// @return The policy gate target (manager), or address(0) if ungated or no actor.
    function getPolicyManager(address account, bytes32 actorId) external view returns (address) {
        return _policyManager[actorId][account];
    }

    /// @notice Returns the account's multichain and local change sequences (replay counters).
    ///
    /// @param account The account to read.
    ///
    /// @return The account's ChangeSequences (multichain and local counters).
    function getChangeSequences(address account) external view returns (ChangeSequences memory) {
        AccountState storage state = _accountState[account];
        return ChangeSequences({multichain: state.multichainSequence, local: state.localSequence});
    }

    /// @notice Returns whether the account is currently locked (configuration frozen).
    ///
    /// @param account The account to check.
    ///
    /// @return True if the account is locked at the current block timestamp.
    function isLocked(address account) external view returns (bool) {
        return block.timestamp < _accountState[account].unlocksAt;
    }

    /// @notice Returns the account's full lock status.
    ///
    /// @param account The account to read.
    ///
    /// @return locked True if the account is locked at the current block timestamp.
    /// @return hasInitiatedUnlock True if an unlock has been initiated but not yet elapsed.
    /// @return unlocksAt The timestamp at which the account unlocks (type(uint40).max while hard-locked).
    /// @return unlockDelay The configured unlock delay in seconds.
    function getLockStatus(address account)
        external
        view
        returns (bool locked, bool hasInitiatedUnlock, uint40 unlocksAt, uint16 unlockDelay)
    {
        AccountState storage config = _accountState[account];
        return (
            block.timestamp < config.unlocksAt, // locked if current time is before unlocksAt
            config.unlocksAt != 0 && config.unlocksAt != type(uint40).max, // hasInitiatedUnlock if unlocksAt non-zero and not max
            config.unlocksAt,
            config.unlockDelay
        );
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // INTERNAL FUNCTIONS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Returns true if the account is locked; clears the stored unlock timestamp once it has expired.
    function _checkAndClearLock(address account) internal returns (bool locked) {
        // Early return if account is locked
        uint40 unlocksAt = _accountState[account].unlocksAt;
        if (block.timestamp < unlocksAt) return true;

        // Account is unlocked, clear storage if non-zero
        if (unlocksAt != 0) _accountState[account].unlocksAt = 0;
        return false;
    }

    // ----------------------------------------------------------------------------------------------------------------
    // ACTOR CHANGES
    // ----------------------------------------------------------------------------------------------------------------

    /// @dev Registers the bootstrap actor set shared by createAccount and importAccount: requires a non-empty,
    ///      strictly ascending-by-actorId list (rejecting unsorted or duplicate entries) and authorizes each entry
    ///      as an unrestricted owner (scope 0, no expiry, no policy). Reverts with NoInitialActors or
    ///      ActorsNotSortedOrDuplicate.
    function _initializeAccount(address account, InitialActor[] calldata initialActors)
        internal
        nonZeroAccount(account)
    {
        // Must have at least one initial actor
        if (initialActors.length == 0) revert NoInitialActors();

        bytes32 previousActorId;
        for (uint256 i; i < initialActors.length; i++) {
            // Enforce sorting with relative comparison of sequential actor ids
            if (initialActors[i].actorId <= previousActorId) revert ActorsNotSortedOrDuplicate();
            previousActorId = initialActors[i].actorId;

            // Initial actors are always unrestricted owners: scope 0x00, no expiry, no policy. The InitialActor type
            // cannot express scope/expiry/policy, so these defaults are structural. Scoped keys and session-key
            // policies are added later via applySignedActorChanges.
            ActorConfig memory config = ActorConfig({
                authenticator: initialActors[i].authenticator, scope: 0, expiry: 0, policyType: POLICY_NONE
            });
            _authorizeActor(account, initialActors[i].actorId, config, "");
        }
    }

    /// @dev Authorizes (upserts) `actorId` with `config` and optional `policyData`, emitting ActorAuthorized. Rejects
    ///      a sub-K1 authenticator and requires any policy-bearing actor to be scope-restricted without CONFIG scope.
    ///      The self-actorId is routed by authenticator type (a k1 self inline in AccountState, a non-k1 self in
    ///      _actorConfig) and the two are kept mutually exclusive; every other actor lives in _actorConfig. Reverts
    ///      with InvalidAuthenticator, InvalidPolicyScope, or InvalidPolicyData.
    function _authorizeActor(address account, bytes32 actorId, ActorConfig memory config, bytes memory policyData)
        internal
        nonZeroAccount(account)
    {
        if (config.authenticator < K1_AUTHENTICATOR) revert InvalidAuthenticator();

        // A policy-bearing actor must be scope-restricted and may not hold CONFIG scope: the policy gate only
        // covers SENDER-context calls, so a CONFIG-scoped (or unrestricted) key could authorize new, unrestricted
        // actors and escape its policy entirely. Applies to every home (inline self, non-k1 self, any other actor).
        if (config.policyType != POLICY_NONE) {
            if (config.scope == 0 || config.scope & SCOPE_CONFIG != 0) revert InvalidPolicyScope();
        }

        // Slice the signed policy by policyType. The commitment is opaque to the protocol.
        (address manager, bytes32 commitment) = _slicePolicy(config.policyType, policyData);

        if (actorId == bytes32(bytes20(account))) {
            // Self-actorId is routed by authenticator type and the two homes are mutually exclusive: the k1 self
            // lives inline in AccountState; a non-k1 self lives in _actorConfig. Authorizing one clears the
            // other so a k1 and a non-k1 self are never simultaneously live.
            AccountState storage st = _accountState[account];
            if (config.authenticator == K1_AUTHENTICATOR) {
                // Upsert: overwrite a live self in place (no re-auth guard); the end state equals revoke-then-
                // authorize. Re-enabling a previously revoked self is just the flag clear below.
                delete _actorConfig[actorId][account]; // mutual exclusion: drop any non-k1 self
                st.defaultEOAScope = config.scope;
                st.defaultEOAPolicyType = config.policyType;
                st.defaultEOAExpiry = config.expiry;
                st.flags &= ~FLAG_REVOKE_DEFAULT_EOA; // enable the inline self
            } else {
                // Upsert: overwrite any existing non-k1 self in place.
                _actorConfig[actorId][account] = config;
                // Mutual exclusion: disable and clear the inline k1 self.
                st.flags |= FLAG_REVOKE_DEFAULT_EOA;
                st.defaultEOAScope = 0;
                st.defaultEOAPolicyType = 0;
                st.defaultEOAExpiry = 0;
            }
            // Policy manager/commitment are keyed by actorId (shared keyspace across both self homes): reset, then
            // set for the incoming config.
            delete _policyCommitment[actorId][account];
            delete _policyManager[actorId][account];
            if (commitment != bytes32(0)) _policyCommitment[actorId][account] = commitment;
            if (manager != address(0)) _policyManager[actorId][account] = manager;

            _emitActorAuthorized(account, actorId, config, manager, commitment);
            return;
        }

        // Non-self actor: single _actorConfig home. Upsert: overwrite in place. Reset the policy slots first so an
        // actor moving policy-bearing -> none (or to a different manager) can't leak stale policy state, preserving
        // the "policy_commitment non-zero iff policyType non-zero" invariant.
        _actorConfig[actorId][account] = config;
        delete _policyCommitment[actorId][account];
        delete _policyManager[actorId][account];
        if (commitment != bytes32(0)) _policyCommitment[actorId][account] = commitment;
        if (manager != address(0)) _policyManager[actorId][account] = manager;

        _emitActorAuthorized(account, actorId, config, manager, commitment);
    }

    /// @dev Emit ActorAuthorized with a tightly packed payload. The config packs to 28 bytes
    ///      (authenticator || scope || expiry || policyType); the policy gate (manager || commitment, 52 bytes)
    ///      is appended only for a policy-bearing actor, so no zero policy words are emitted otherwise.
    function _emitActorAuthorized(
        address account,
        bytes32 actorId,
        ActorConfig memory config,
        address manager,
        bytes32 commitment
    ) private {
        bytes memory actorData = config.policyType == POLICY_NONE
            ? abi.encodePacked(config.authenticator, config.scope, config.expiry, config.policyType)
            : abi.encodePacked(
                config.authenticator, config.scope, config.expiry, config.policyType, manager, commitment
            );
        emit ActorAuthorized(account, actorId, actorData);
    }

    /// @dev Validates `policyData` against `policyType` and returns (manager, commitment).
    ///      0x00: empty data -> (0, 0). Any non-zero value: manager[20] || commitment[32] -> (manager, commitment).
    ///      Length mismatches revert. The protocol does not interpret the specific non-zero value; self-enforcement
    ///      is expressed as manager == account.
    function _slicePolicy(uint8 policyType, bytes memory policyData)
        internal
        pure
        returns (address manager, bytes32 commitment)
    {
        if (policyType == POLICY_NONE) {
            if (policyData.length != 0) revert InvalidPolicyData();
        } else {
            if (policyData.length != 52) revert InvalidPolicyData();
            assembly ("memory-safe") {
                manager := shr(96, mload(add(policyData, 0x20)))
                commitment := mload(add(policyData, 0x34))
            }
            if (manager == address(0) || commitment == bytes32(0)) revert InvalidPolicyData();
        }
    }

    /// @dev Revokes `actorId` from `account`, clearing its config and policy slots and emitting ActorRevoked. For the
    ///      self-actorId it also disables the inline k1 self (sets FLAG_REVOKE_DEFAULT_EOA and zeroes the inline
    ///      fields). Reverts with UnknownActor when the actor is not currently live.
    function _revokeActor(address account, bytes32 actorId) internal nonZeroAccount(account) {
        if (!isActor(account, actorId)) revert UnknownActor();
        delete _actorConfig[actorId][account];
        // Policy state is keyed by (account, actorId) and cleared exactly on revoke.
        delete _policyCommitment[actorId][account];
        delete _policyManager[actorId][account];
        // For the self-actorId, disable the k1 self: set the flag (so the inline full-owner path stays off) and
        // clear the inline config. Covers both homes — a non-k1 self was deleted above. Never auto-resurrected.
        if (actorId == bytes32(bytes20(account))) {
            AccountState storage st = _accountState[account];
            st.flags |= FLAG_REVOKE_DEFAULT_EOA;
            st.defaultEOAScope = 0;
            st.defaultEOAPolicyType = 0;
            st.defaultEOAExpiry = 0;
        }
        emit ActorRevoked(account, actorId);
    }

    /// @dev CREATE2 salt for account creation. This is a deterministic commitment (not a signed message), so it
    ///      uses a tightly packed encoding that protocol clients can reproduce cheaply across chains:
    ///      effective_salt = keccak256(user_salt || actors_commitment).
    function _computeEffectiveSalt(bytes32 userSalt, InitialActor[] calldata initialActors)
        internal
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(userSalt, _computeActorsCommitment(initialActors)));
    }

    /// @dev Packed commitment over the initial actor set, 52 bytes per actor: actorId (32) || authenticator (20).
    ///      Initial actors are always unrestricted owner keys, so no scope/expiry/policy fields participate.
    function _computeActorsCommitment(InitialActor[] calldata initialActors) internal pure returns (bytes32) {
        bytes memory packed;
        for (uint256 i; i < initialActors.length; i++) {
            packed = abi.encodePacked(packed, initialActors[i].actorId, initialActors[i].authenticator);
        }
        return keccak256(packed);
    }

    /// @dev Typed digest for the importAccount ERC-1271 signature (a signed message), so signers can reproduce it
    ///      with standard EIP-712-style struct hashing. `salt` is bound to the account address and the digest is
    ///      bound to `chainId` (0 = multichain) so its replay domain matches applySignedActorChanges.
    function _computeImportDigest(address account, uint256 chainId, InitialActor[] calldata initialActors)
        internal
        pure
        returns (bytes32)
    {
        bytes32[] memory actorHashes = new bytes32[](initialActors.length);
        for (uint256 i; i < initialActors.length; i++) {
            // Imported actors are unrestricted owners: scope, expiry, and policyType are 0 and policyData is empty.
            // The digest retains the full Actor/ActorConfig typehash structure (zero-filled) for a single canonical
            // type, matching the importAccount signature payload in EIP-8130.
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

    /// @dev Computes the digest signed over an applySignedActorChanges batch: each ActorChange is hashed structurally
    ///      (its variable-length `data` pre-hashed to a fixed-width layout) and the batch is bound to `account`,
    ///      `chainId`, and `sequence` via SIGNED_ACTOR_CHANGES_TYPEHASH.
    function _computeSignedActorChangesDigest(
        address account,
        uint256 chainId,
        uint64 sequence,
        ActorChange[] calldata actorChanges
    ) internal pure returns (bytes32) {
        // Hash each actor change structurally: the variable-length `data` is hashed before encoding so the
        // digest commits to a fixed-width layout (matches the ActorChange sub-type in SIGNED_ACTOR_CHANGES_TYPEHASH).
        bytes32[] memory actorChangeHashes = new bytes32[](actorChanges.length);
        for (uint256 i; i < actorChanges.length; i++) {
            actorChangeHashes[i] = keccak256(
                abi.encode(
                    ACTORCHANGE_TYPEHASH,
                    actorChanges[i].changeType,
                    actorChanges[i].actorId,
                    keccak256(actorChanges[i].data)
                )
            );
        }

        // Hash the batch of actor changes
        return keccak256(
            abi.encode(
                SIGNED_ACTOR_CHANGES_TYPEHASH,
                account,
                chainId,
                sequence,
                keccak256(abi.encodePacked(actorChangeHashes))
            )
        );
    }

    // ----------------------------------------------------------------------------------------------------------------
    // AUTHENTICATION
    // ----------------------------------------------------------------------------------------------------------------

    /// @dev Resolves and authenticates the actor behind `authenticator`/`data`, returning its (scope, policyType,
    ///      policyTarget). Routes the K1 sentinel to _authenticateK1; otherwise calls the IAuthenticator and requires
    ///      the resolved actorId to carry a matching, unexpired _actorConfig entry. Reverts with AuthenticationFailed,
    ///      AuthenticatorMismatch, or ActorExpired.
    function _authenticate(address account, bytes32 hash, address authenticator, bytes calldata data)
        internal
        view
        returns (uint8 scope, uint8 policyType, address policyTarget)
    {
        if (authenticator == K1_AUTHENTICATOR) return _authenticateK1(account, hash, data);

        bytes32 actorId = IAuthenticator(authenticator).authenticate(hash, data);
        if (actorId == bytes32(0)) revert AuthenticationFailed();

        ActorConfig memory config = _actorConfig[actorId][account];
        if (config.authenticator != authenticator) revert AuthenticatorMismatch();
        // Expiry is read from the same slot; an expired actor fails authentication. 0 = no expiry.
        if (config.expiry != 0 && block.timestamp > config.expiry) revert ActorExpired();
        return (config.scope, config.policyType, _resolvePolicyTarget(account, actorId, config.policyType));
    }

    /// @dev The single secp256k1 ("K1") path. Recovers the signer (EIP-2 enforced), then resolves the actor:
    ///        - signer == account -> the inline self config in AccountState (one SLOAD): the flag gates the whole
    ///          key (set => revert), and when live the scope/policy/expiry come from the inline fields (all-zero =
    ///          full owner; non-zero = a scoped self). A non-k1 self is unreachable here by construction (it
    ///          requires its own authenticator), and mutual exclusion keeps the flag set whenever one is live.
    ///        - otherwise the signer's actorId must carry an explicit K1 config in _actorConfig (any other k1 actor).
    ///      Both the common self and other-actor paths cost a single SLOAD.
    function _authenticateK1(address account, bytes32 hash, bytes calldata data)
        internal
        view
        returns (uint8, uint8, address)
    {
        address recovered = _recoverSigner(hash, data);
        if (recovered == address(0)) revert InvalidSignature();

        if (recovered == account) {
            // Inline self: a single SLOAD resolves the whole key. The flag disables it entirely; otherwise the
            // inline scope/policy/expiry govern (all-zero = full owner).
            AccountState storage st = _accountState[account];
            if (st.flags & FLAG_REVOKE_DEFAULT_EOA != 0) revert DefaultEoaRevoked();
            if (st.defaultEOAExpiry != 0 && block.timestamp > st.defaultEOAExpiry) revert ActorExpired();
            uint8 policyType = st.defaultEOAPolicyType;
            return
                (st.defaultEOAScope, policyType, _resolvePolicyTarget(account, bytes32(bytes20(account)), policyType));
        }

        bytes32 actorId = bytes32(bytes20(recovered));
        ActorConfig memory config = _actorConfig[actorId][account];
        if (config.authenticator != K1_AUTHENTICATOR) revert AuthenticatorMismatch();
        // Expiry is read from the same slot; an expired actor fails authentication. 0 = no expiry.
        if (config.expiry != 0 && block.timestamp > config.expiry) revert ActorExpired();
        return (config.scope, config.policyType, _resolvePolicyTarget(account, actorId, config.policyType));
    }

    /// @dev True if the account's default (implicit) EOA has been revoked via the AccountState flag.
    function _isDefaultEoaRevoked(address account) internal view returns (bool) {
        return _accountState[account].flags & FLAG_REVOKE_DEFAULT_EOA != 0;
    }

    /// @dev Resolves an actor's policy gate target: address(0) when ungated (policyType == 0x00), otherwise the
    ///      stored policy manager. Reads only the manager address, never the signed commitment, so it is safe to
    ///      call during signature validation (e.g. ERC-4337 validateUserOp).
    function _resolvePolicyTarget(address account, bytes32 actorId, uint8 policyType) internal view returns (address) {
        if (policyType == POLICY_NONE) return address(0);
        return _policyManager[actorId][account];
    }

    /// @dev Recovers the ECDSA signer from a 65-byte r‖s‖v signature over `hash`, enforcing EIP-2 (low-s only,
    ///      canonical v of 27 or 28). Reverts with InvalidSignature on a bad length or non-canonical encoding; may
    ///      return address(0) if ecrecover fails, which callers treat as a failed authentication.
    function _recoverSigner(bytes32 hash, bytes calldata data) internal pure returns (address recovered) {
        if (data.length != 65) revert InvalidSignature();
        bytes32 r = bytes32(data[:32]);
        bytes32 s = bytes32(data[32:64]);
        uint8 v = uint8(data[64]);
        // EIP-2: reject the malleable high-s half of each signature and non-canonical v to enforce a single
        // canonical encoding per signature.
        if (uint256(s) > SECP256K1_HALF_ORDER) revert InvalidSignature();
        if (v != 27 && v != 28) revert InvalidSignature();
        return ecrecover(hash, v, r, s);
    }

    // ----------------------------------------------------------------------------------------------------------------
    // ACCOUNT CREATION
    // ----------------------------------------------------------------------------------------------------------------

    /// @notice Constructs the deployment code for an account in a manner that doesn't immediately run constructor code.
    /// @dev Constructs DEPLOYMENT_HEADER(n) || bytecode. The 14-byte EVM loader
    ///      copies trailing bytecode into memory and returns it.
    function _buildDeploymentCode(bytes calldata bytecode) internal pure returns (bytes memory code) {
        // Bytecode must be less than 65536 bytes
        uint256 n = bytecode.length;
        if (n > 0xFFFF) revert BytecodeTooLarge();

        // Construct the deployment code with 14-byte header then provided bytecode
        code = new bytes(14 + n);
        code[0] = 0x61; //  PUSH2
        code[1] = bytes1(uint8(n >> 8));
        code[2] = bytes1(uint8(n));
        code[3] = 0x60; //  PUSH1
        code[4] = 0x0E; //  14 (offset)
        code[5] = 0x60; //  PUSH1
        code[6] = 0x00; //  0 (mem dest)
        code[7] = 0x39; //  CODECOPY
        code[8] = 0x61; //  PUSH2
        code[9] = bytes1(uint8(n >> 8));
        code[10] = bytes1(uint8(n));
        code[11] = 0x60; // PUSH1
        code[12] = 0x00; // 0 (mem offset)
        code[13] = 0xF3; // RETURN

        // Append the provided bytecode
        for (uint256 i; i < n; i++) {
            code[14 + i] = bytecode[i];
        }
        return code;
    }
}
