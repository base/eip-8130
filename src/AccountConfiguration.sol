// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

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

    /// @notice An actor's authorization: authenticator, scope, and expiry.
    struct ActorConfig {
        address authenticator;
        uint8 scope;
        uint48 expiry; // Unix seconds; 0 = no expiry. Actor invalid once block.timestamp > expiry
    }

    /// @notice Initial actor for account creation and import. Carries its scope and, when scope & SCOPE_POLICY is
    ///         set, its policy data; expiry is always 0 for initial actors (scoped-with-expiry keys are added later
    ///         via applySignedActorChanges).
    struct InitialActor {
        bytes32 actorId;
        address authenticator;
        uint8 scope; // 0x00 = unrestricted admin
        bytes policyData; // empty unless scope & SCOPE_POLICY; then manager(20) || commitment(32)
    }

    /// @notice A full actor record: identifier, config, and policy data.
    struct Actor {
        bytes32 actorId;
        ActorConfig config;
        // Sliced by scope: empty when scope & SCOPE_POLICY == 0; manager[20] || commitment[32] when set.
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
    /// @dev Packed into a single storage slot; the field layout is normative (nodes read the raw slot for mempool
    ///      rate-limit tiering, see the EIP's Account Lock section). Field order and widths match the spec's
    ///      account-state table: multichainSequence, localSequence, flags, lockUnion, defaultEOAScope,
    ///      defaultEOAExpiry, then 3 reserved bytes that MUST stay zero.
    ///      localSequence > 0 doubles as the account initialized flag.
    ///      `flags` is a bitfield: bit 0 (FLAG_REVOKE_DEFAULT_EOA) disables the k1 self key; bit 1 (FLAG_LOCKED)
    ///      freezes actor configuration; bit 2 (FLAG_UNLOCK_INITIATED) selects how `lockUnion` is interpreted.
    ///      `lockUnion` is a union field: while FLAG_UNLOCK_INITIATED is clear it holds the configured unlock delay
    ///      (seconds, uint16 range); while set it holds unlocksAt (the timestamp at which the unlock takes effect).
    ///      The defaultEOA* fields are the inline home for the account's own secp256k1 ("self") key — the actor whose
    ///      actorId is bytes32(bytes20(account)). When FLAG_REVOKE_DEFAULT_EOA is unset, a k1 signature recovering to
    ///      the account authenticates with this inline config (all-zero = full owner; non-zero scope/expiry = a
    ///      scoped self key), resolved in a single SLOAD. Policy gating (when scope & SCOPE_POLICY != 0) is still keyed
    ///      by actorId in the shared _policyManager/_policyCommitment keyspace. The separate _actorConfig[self][account]
    ///      slot is reserved for a *non-k1* self authenticator (e.g. a post-quantum verifier returning the
    ///      self-actorId); the two homes are mutually exclusive (see _authorizeActor).
    struct AccountState {
        uint64 multichainSequence; // 8 bytes
        uint64 localSequence; // 8 bytes – also serves as initialized flag
        uint8 flags; // 1 byte – bitfield: bit 0 REVOKE_DEFAULT_EOA, bit 1 LOCKED, bit 2 UNLOCK_INITIATED
        uint40 lockUnion; // 5 bytes – union: unlockDelay while UNLOCK_INITIATED clear, else unlocksAt (timestamp)
        uint8 defaultEOAScope; // 1 byte – inline self k1 scope (0 = full owner)
        uint48 defaultEOAExpiry; // 6 bytes – inline self k1 expiry (Unix seconds; 0 = no expiry)
        // 3 bytes reserved (remaining slot bytes); MUST stay zero.
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // CONSTANTS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @dev ERC-1271 isValidSignature(bytes32,bytes) selector, which also equals the ERC-1271 magic return value
    ///      (0x1626ba7e); used both to build the import staticcall and to validate its result.
    bytes4 internal constant ERC1271_SELECTOR = bytes4(keccak256("isValidSignature(bytes32,bytes)"));

    /// @notice Typehash binding an importAccount signature to its salt, chainId, and initial actor set.
    ///
    /// @dev NOT compliant with EIP-712, to mitigate eth_signTypedData phishing. Bound to the current chainId so an
    ///      import signature cannot be replayed on another chain. Initial actors are hashed structurally via
    ///      ACTOR_TYPEHASH / ACTORCONFIG_TYPEHASH below.
    bytes32 public constant ACTOR_INITIALIZATION_TYPEHASH = keccak256(
        "ActorInitialization(bytes32 salt,uint256 chainId,Actor[] initialActors)Actor(bytes32 actorId,ActorConfig config,bytes policyData)ActorConfig(address authenticator,uint8 scope,uint48 expiry)"
    );

    /// @notice Typehash used to structurally hash each Actor within an ActorInitialization import digest.
    bytes32 public constant ACTOR_TYPEHASH = keccak256(
        "Actor(bytes32 actorId,ActorConfig config,bytes policyData)ActorConfig(address authenticator,uint8 scope,uint48 expiry)"
    );

    /// @notice Typehash used to structurally hash an Actor's ActorConfig within an import digest.
    bytes32 public constant ACTORCONFIG_TYPEHASH =
        keccak256("ActorConfig(address authenticator,uint8 scope,uint48 expiry)");

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

    /// @notice Typehash binding a signed lock-state change to its account, chainId, op, unlock delay, and sequence.
    ///
    /// @dev NOT compliant with EIP-712, to mitigate phishing attacks. Lock changes are local-channel only, so the
    ///      digest always binds the current chainId (there is no multichain lock).
    bytes32 public constant LOCK_CHANGE_TYPEHASH =
        keccak256("SignedLockChange(address account,uint256 chainId,uint8 op,uint16 unlockDelay,uint64 sequence)");

    // ----------------------------------------------------------------------------------------------------------------
    // ACTOR CHANGE TYPES
    // ----------------------------------------------------------------------------------------------------------------

    /// @notice Authorize an actor to the account
    uint8 public constant AUTHORIZE_ACTOR = 0x01;

    /// @notice Revoke an actor from the account
    uint8 public constant REVOKE_ACTOR = 0x02;

    // ----------------------------------------------------------------------------------------------------------------
    // LOCK CHANGE OPS
    // ----------------------------------------------------------------------------------------------------------------

    /// @notice applySignedLockChanges op that hard-locks the account.
    uint8 public constant LOCK_OP = 0x01;

    /// @notice applySignedLockChanges op that initiates the unlock of a hard-locked account.
    uint8 public constant UNLOCK_OP = 0x02;

    // ----------------------------------------------------------------------------------------------------------------
    // ACTOR SCOPE BITS
    // ----------------------------------------------------------------------------------------------------------------

    /// @notice Actor can initiate transactions with account as sender
    uint8 public constant SCOPE_SENDER = 0x01;

    /// @notice Actor is gated to a policy: every call it makes must land on the resolved manager (this contract
    ///         stores manager + commitment; the protocol enforces that the actor's calls only ever reach that
    ///         target). This contract does not reject scope combinations (e.g. SCOPE_POLICY | SCOPE_SELF_PAYER) — any
    ///         use-time exclusivity between SCOPE_POLICY and the account's other capabilities is protocol-side, not
    ///         enforced here.
    uint8 public constant SCOPE_POLICY = 0x02;

    /// @notice Permits a restricted (non-admin) actor to use sequenced `nonce_key`s for sender-context transactions;
    ///         without it a restricted actor may use only the nonce-free key (NONCE_KEY_MAX), while admin actors are
    ///         unconstrained. This contract stores the scope bit verbatim and does not interpret it — nonce semantics
    ///         are enforced entirely protocol-side.
    uint8 public constant SCOPE_NONCE = 0x04;

    /// @notice Actor can self-pay gas for the account's own operations (payer == sender).
    uint8 public constant SCOPE_SELF_PAYER = 0x08;

    /// @notice Actor can sponsor gas on behalf of a different sender (payer != sender).
    uint8 public constant SCOPE_SPONSOR_PAYER = 0x10;

    // ERC-1271 signing rides on operational authority (admin scope == 0x00, or a SENDER actor without POLICY);
    // it is not its own scope bit. See verifySignature.

    // 0x20, 0x40, 0x80 are spare (unused).

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

    /// @notice AccountState.flags bit (spec `LOCKED`): when set, actor configuration is frozen — all config changes
    ///         and delegation are rejected on both the account-changes and applySignedActorChanges paths. The only
    ///         permitted operation while locked is initiating an unlock. Cleared lazily once an initiated unlock
    ///         elapses (see applySignedLockChanges).
    uint8 public constant FLAG_LOCKED = 0x02;

    /// @notice AccountState.flags bit (spec `UNLOCK_INITIATED`): selects how the packed `lockUnion` field is read.
    ///         While clear, `lockUnion` holds the configured unlock delay (seconds); while set, it holds unlocksAt
    ///         (the timestamp at which the pending unlock takes effect). Only meaningful when FLAG_LOCKED is set.
    uint8 public constant FLAG_UNLOCK_INITIATED = 0x04;

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
    /// @param actorData Tightly packed authorization surface, mirroring the wire packing:
    ///        authenticator(20) || scope(1) || expiry(6) || reserved(5 zero bytes) = 32 bytes, and, only when
    ///        scope & SCOPE_POLICY != 0, followed by the resolved policy gate manager(20) || commitment(32). So the
    ///        payload is 32 bytes for an ungated actor and 84 bytes for a policy-gated one.
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

    /// @notice A lock op (op = 1) carried a zero unlock delay.
    error ZeroUnlockDelay();

    /// @notice An unlock op (op = 2) was requested when the account was not in the hard-locked state (FLAG_LOCKED set,
    ///         FLAG_UNLOCK_INITIATED clear) — i.e. never locked, or an unlock was already initiated.
    error NotLocked();

    /// @notice applySignedLockChanges carried an unrecognized op (neither LOCK_OP nor UNLOCK_OP).
    error UnknownLockOp();

    /// @notice An unlock op (op = 2) carried a non-zero unlock delay (unlock delay is set only by the lock op).
    error InvalidUnlockDelay();

    /// @notice The authenticated actor lacks the scope required to change the lock state (admin, scope 0, only).
    error UnauthorizedLockChange();

    /// @notice The auth blob is shorter than the 20-byte authenticator selector prefix.
    error InvalidAuthLength();

    /// @notice createAccount/importAccount was called with an empty initialActors set.
    error NoInitialActors();

    /// @notice initialActors are not strictly ascending by actorId (unsorted or duplicated).
    error ActorsNotSortedOrDuplicate();

    /// @notice An actor config named an authenticator below the K1 sentinel (i.e. address(0)).
    error InvalidAuthenticator();
    /// @notice The policyData length did not match `scope & SCOPE_POLICY` (52 bytes when set, empty when unset).
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

    /// @notice Per-actor signed policy commitment. Set when the actor's scope carries SCOPE_POLICY.
    /// @dev Read only during execution (via getPolicy), never during signature validity checks.
    mapping(bytes32 actorId => mapping(address account => bytes32)) internal _policyCommitment;

    /// @notice Per-actor policy manager address. Set when the actor's scope carries SCOPE_POLICY.
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

    /// @notice Deploys a new account with its initial actors. Each initial actor is registered with its declared
    ///         `scope` and, when `scope & SCOPE_POLICY` is set, its `policyData` (an external `manager` is expressible
    ///         at create; `manager = account` is not, as the address is unknown at commitment time). `expiry` is
    ///         always 0 at create — scoped-with-expiry keys are added afterwards via applySignedActorChanges. The
    ///         implicit default-EOA key is disabled on creation.
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
    /// @param initialActors Bootstrap actors, strictly ascending by actorId; each carries its declared scope/policyData.
    ///
    /// @return account The deployed account address.
    function createAccount(bytes32 userSalt, bytes calldata bytecode, InitialActor[] calldata initialActors)
        external
        returns (address account)
    {
        bytes32 effectiveSalt;
        bytes memory deploymentCode;
        (account, effectiveSalt, deploymentCode) = _prepareDeployment(userSalt, bytecode, initialActors);

        // Block re-initialization of an already-bootstrapped account. This must be explicit: authorizeActor is now an
        // upsert (no duplicate-actor revert) and the create2 below is intentionally swallowed (pop), so a duplicate
        // createAccount would otherwise silently re-initialize.
        if (_isInitialized(account)) revert AlreadyInitialized();

        // Mark initialized (localSequence = 1) and disable the implicit default-EOA path. A created account has code
        // at its CREATE2 address, so the recovered==account owner path is unreachable; default it off (canonically
        // ECDSA-owner-free / quantum-safe), folded into the same slot write. Set *before* initializing actors so a
        // self-actorId k1 initial actor can re-enable the inline self (parity with import).
        _accountState[account].localSequence = 1;
        _accountState[account].flags = FLAG_REVOKE_DEFAULT_EOA;

        _initializeAccount(account, initialActors);

        // Deploy at the derived address. create2 returns address(0) on failure (EIP-170 size, EIP-3541 leading 0xEF,
        // or out of gas); reverting on mismatch unwinds every state write above, so a failed deploy can never leave
        // an initialized-but-codeless account behind.
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
    /// @param initialActors Bootstrap actors, strictly ascending by actorId; each carries its declared scope/policyData.
    /// @param signature ERC-1271 signature the account validates over the import digest.
    function importAccount(
        address account,
        uint256 chainId,
        InitialActor[] calldata initialActors,
        bytes calldata signature
    ) external onlyUnlocked(account) {
        if (chainId != 0 && chainId != block.chainid) revert InvalidChainId();

        // Import is a one-time bootstrap for accounts with no 8130 state yet.
        if (_isInitialized(account)) revert AlreadyInitialized();
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
    /// @dev Authenticates `auth` against the account's actors and requires the resolved actor to be unrestricted
    ///      (scope 0) — there is no elevated scope for changing actors; admin is exactly scope == 0. Replay is
    ///      bound by `chainId` (0 = multichain, else the current chain) and a monotonic per-account sequence
    ///      consumed on each call.
    /// @dev Reverts with AccountIsLocked when the account is locked.
    /// @dev Reverts with InvalidChainId when `chainId` is neither 0 (multichain) nor the current chain.
    /// @dev Reverts with InvalidAuthLength, InvalidSignature, AuthenticationFailed, AuthenticatorMismatch,
    ///      ActorExpired, or DefaultEoaRevoked when `auth` fails to authenticate a live actor.
    /// @dev Reverts with UnauthorizedActorChange when the authenticated actor is not unrestricted (scope != 0).
    /// @dev Reverts with UnknownChangeType when a change carries an unrecognized changeType.
    /// @dev Reverts with InvalidAuthenticator or InvalidPolicyData on a malformed authorize.
    /// @dev Reverts with UnknownActor when revoking an actor that is not authorized.
    ///
    /// @param account The account whose configuration is changed.
    /// @param chainId Replay domain: 0 = multichain (valid on every chain), otherwise the current chain.
    /// @param actorChanges Ordered authorize/revoke operations to apply.
    /// @param auth Authenticator(20) || authenticator-specific data authenticating an unrestricted actor.
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
        (, uint8 scope,) = authenticateActor(account, digest, auth);

        // Only an unrestricted actor (scope 0) may change actors; there is no elevated "admin" scope bit.
        if (scope != 0) revert UnauthorizedActorChange();

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

    /// @notice Applies a signed lock-state change (hard-lock or initiate-unlock) to an account.
    ///
    /// @dev Lock state changes ONLY through this signed EVM entry point. Authorization comes entirely from the
    ///      signature, so anyone may relay the call; the digest is authenticated against the account's actors and
    ///      the resolved actor must be unrestricted (scope 0, admin) — there is no elevated scope for changing the
    ///      lock. Lock changes are local-channel only: the digest binds `block.chainid` and a monotonic per-account
    ///      `localSequence` consumed on each call (mirroring applySignedActorChanges so both signed entry points
    ///      stay coherent on the same counter). Because both entry points share this counter, a pre-signed local
    ///      actor change and a lock op contend for the same sequence: whichever is relayed first consumes it and
    ///      invalidates the other until it is re-signed at the next sequence.
    /// @dev op = LOCK_OP (1): only from the unlocked state (reverts AccountIsLocked if currently locked). Sets
    ///      FLAG_LOCKED and stores `unlockDelay` in `lockUnion`. Emits AccountLocked.
    /// @dev op = UNLOCK_OP (2): only from the hard-locked state with no pending unlock (reverts NotLocked
    ///      otherwise); `unlockDelay` MUST be 0. Sets FLAG_UNLOCK_INITIATED and overwrites `lockUnion` with
    ///      unlocksAt = block.timestamp + storedDelay. Emits AccountUnlockInitiated.
    /// @dev Reverts with InvalidAuthLength, InvalidSignature, AuthenticationFailed, AuthenticatorMismatch,
    ///      ActorExpired, or DefaultEoaRevoked when `auth` fails to authenticate a live actor.
    /// @dev Reverts with UnauthorizedLockChange when the authenticated actor is not unrestricted (scope != 0).
    /// @dev Reverts with ZeroUnlockDelay when a lock op carries a zero unlock delay.
    /// @dev Reverts with AccountIsLocked when a lock op targets an already-locked account.
    /// @dev Reverts with InvalidUnlockDelay when an unlock op carries a non-zero unlock delay.
    /// @dev Reverts with NotLocked when an unlock op targets an account that is not hard-locked.
    /// @dev Reverts with UnknownLockOp when `op` is neither LOCK_OP nor UNLOCK_OP.
    ///
    /// @param account The account whose lock state is changed.
    /// @param op The lock operation: LOCK_OP (1) to hard-lock, UNLOCK_OP (2) to initiate an unlock.
    /// @param unlockDelay Delay in seconds before the account unlocks after an unlock is initiated (lock op only,
    ///        max uint16, ~18 hours); MUST be 0 for the unlock op.
    /// @param auth Authenticator(20) || authenticator-specific data authenticating an unrestricted actor.
    function applySignedLockChanges(address account, uint8 op, uint16 unlockDelay, bytes calldata auth) external {
        // Local channel only: bind the digest to the current chain and consume the local sequence (post-increment,
        // hashing the pre-increment value — identical to applySignedActorChanges so both paths share one counter).
        uint64 sequence = _accountState[account].localSequence++;

        bytes32 digest = _computeSignedLockChangesDigest(account, block.chainid, op, unlockDelay, sequence);
        (, uint8 scope,) = authenticateActor(account, digest, auth);

        // Only an unrestricted actor (scope 0) may change the lock; there is no elevated "admin" scope bit.
        if (scope != 0) revert UnauthorizedLockChange();

        AccountState storage config = _accountState[account];

        if (op == LOCK_OP) {
            // Lock only from the unlocked state; lazily clear any elapsed unlock (also clears LOCKED) first.
            if (_checkAndClearLock(account)) revert AccountIsLocked();
            // Require non-zero unlock delay.
            if (unlockDelay == 0) revert ZeroUnlockDelay();

            // Post-clear the lock bits are clear, so set FLAG_LOCKED and stash the delay in the union.
            config.flags |= FLAG_LOCKED;
            config.lockUnion = unlockDelay;
            emit AccountLocked(account, unlockDelay);
        } else if (op == UNLOCK_OP) {
            // The unlock op never sets the delay; it consumes the delay stored by the lock op.
            if (unlockDelay != 0) revert InvalidUnlockDelay();
            // Require the account is hard-locked (LOCKED set) with no unlock already initiated (UNLOCK_INITIATED clear).
            uint8 flags = config.flags;
            if (flags & FLAG_LOCKED == 0 || flags & FLAG_UNLOCK_INITIATED != 0) revert NotLocked();

            // Reinterpret the union: it held the stored delay, now it holds the effective unlock timestamp.
            uint40 unlocksAt = uint40(block.timestamp + uint16(config.lockUnion));
            config.flags = flags | FLAG_UNLOCK_INITIATED;
            config.lockUnion = unlocksAt;
            emit AccountUnlockInitiated(account, unlocksAt);
        } else {
            revert UnknownLockOp();
        }
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // VIEW FUNCTIONS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Validates an account signature in `authenticator(20) || data` format; never reverts.
    ///
    /// @dev ERC-1271-style boolean check: returns false on any failure (invalid signature, unknown/revoked actor,
    ///      actorId not bound to the presented authenticator, or a non-operational actor). authenticateActor
    ///      reverts on failure, so it is called externally and the revert is caught.
    ///
    /// @param account The account the signature is validated against.
    /// @param hash The digest that was signed.
    /// @param signature Authenticator(20) || authenticator-specific data.
    ///
    /// @return verified True if the signature is valid and the resolved actor is operational (admin, or a SENDER
    ///         actor that does not carry POLICY).
    function verifySignature(address account, bytes32 hash, bytes calldata signature)
        external
        view
        returns (bool verified)
    {
        try this.authenticateActor(account, hash, signature) returns (bytes32, uint8 scope, address) {
            // ERC-1271 signing is authorized for any operational actor: the admin (scope == 0x00), or a SENDER actor
            // that is not gated by a policy (SCOPE_SENDER set AND SCOPE_POLICY unset). Signing is an encoding of
            // authority a SENDER actor already holds via calls, not a separate grant, so it needs no dedicated scope
            // bit. A POLICY-bearing actor is not operational and cannot sign: a signature acts outside its policy
            // gate, so honoring one would let it act off its gate.
            return scope == 0 || ((scope & SCOPE_SENDER != 0) && (scope & SCOPE_POLICY == 0));
        } catch {
            return false;
        }
    }

    /// @notice Authenticates that an account approved `hash` using auth in `authenticator(20) || data` format,
    ///         returning the verified actor's identity and authorization surface so a consumer (e.g. an ERC-4337
    ///         account on a non-8130 chain) can decide authorization AND drive the policy flow from a single call,
    ///         without re-deriving (or re-invoking the authenticator to recover) the actorId.
    ///
    /// @dev `actorId` is the resolved actor identifier — the same value an 8130 chain surfaces via the tx-context
    ///      precompile. It lets an off-8130 consumer read `getPolicyCommitment(account, actorId)` (an execution-time
    ///      read) for a policy-gated actor, reaching parity with the native hot path.
    /// @dev `scope` is the actor's capability set, stored verbatim and never interpreted by this contract —
    ///      protocol-side semantics for bits like SCOPE_NONCE live outside this contract. Consumers decide policy
    ///      gating via `scope & SCOPE_POLICY`, NOT via `policyTarget != 0`.
    /// @dev `policyTarget` is the resolved policy manager, never the signed commitment (an execution-time read via
    ///      getPolicy). It MAY be address(0) for a policy-gated actor deliberately gated to address(0).
    /// @dev Reverts with InvalidAuthLength when `auth` is shorter than 20 bytes.
    /// @dev Reverts with AuthenticationFailed, AuthenticatorMismatch, ActorExpired, DefaultEoaRevoked, or
    ///      InvalidSignature when the actor cannot be authenticated.
    ///
    /// @param account The account the signature is validated against.
    /// @param hash The digest that was signed.
    /// @param auth Authenticator(20) || authenticator-specific data.
    ///
    /// @return actorId The identifier of the verified actor.
    /// @return scope The scope of the verified actor (0x00 = unrestricted).
    /// @return policyTarget The actor's policy gate target (manager), or address(0).
    function authenticateActor(address account, bytes32 hash, bytes calldata auth)
        public
        view
        returns (bytes32 actorId, uint8 scope, address policyTarget)
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
        (address account,,) = _prepareDeployment(userSalt, bytecode, initialActors);
        return account;
    }

    // ----------------------------------------------------------------------------------------------------------------
    // STORAGE VIEWS
    // ----------------------------------------------------------------------------------------------------------------

    /// @notice Returns whether `actorId` is currently authorized on `account` (a stored actor entry exists, or the
    ///         inline k1 self is enabled).
    ///
    /// @dev Does NOT check expiry: an expired-but-not-revoked actor still returns true. This is intentional —
    ///      _revokeActor relies on it to revoke expired actors — so callers needing liveness must check expiry too.
    ///
    /// @param account The account to check.
    /// @param actorId The actor identifier to check.
    ///
    /// @return True if the actor is authorized (possibly expired).
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
    ///      reports as a native ecrecover owner carrying its inline scope/expiry (all-zero = full owner); a
    ///      disabled one, or any unknown actor, reports as the all-zero (empty) config, keeping live-vs-disabled
    ///      unambiguous without a sentinel.
    ///
    /// @param account The account to read.
    /// @param actorId The actor identifier to resolve.
    ///
    /// @return The resolved actor configuration, or the all-zero config if the actor is not live.
    function getActorConfig(address account, bytes32 actorId) external view returns (ActorConfig memory) {
        ActorConfig memory config = _actorConfig[actorId][account];
        // Non-zero authenticator = a stored entry. Uses the same `>= K1_AUTHENTICATOR` namespace idiom as isActor:
        // every stored authenticator is K1_AUTHENTICATOR (0x1) or a contract, so this is equivalent to != address(0).
        if (config.authenticator >= K1_AUTHENTICATOR) return config;
        if (actorId == bytes32(bytes20(account)) && !_isDefaultEoaRevoked(account)) {
            AccountState storage st = _accountState[account];
            return
                ActorConfig({authenticator: K1_AUTHENTICATOR, scope: st.defaultEOAScope, expiry: st.defaultEOAExpiry});
        }
        return config;
    }

    /// @notice Resolves an actor's policy gate target (manager) and signed commitment.
    ///
    /// @dev Convenience aggregator for off-chain consumers, equivalent to `(getPolicyManager, getPolicyCommitment)`.
    ///      Enforcement is at execution: this resolves where a policy-gated actor may call and the commitment a
    ///      target validates presented parameters against. The policy manager/commitment are keyed by actorId, so
    ///      the inline k1 self and a non-k1 self share that keyspace; mutual exclusion guarantees at most one is
    ///      live, so the active gate is read by actorId. Both slots are non-zero only when the actor's scope carries
    ///      SCOPE_POLICY (see _authorizeActor / _revokeActor); either MAY still be zero for an actor deliberately
    ///      gated to a zero manager or a zero (no-params) commitment. On-chain consumers should prefer the
    ///      single-SLOAD `getPolicyCommitment` / `getPolicyManager` accessors directly.
    ///
    /// @param account The account to read.
    /// @param actorId The actor identifier to resolve.
    ///
    /// @return target The actor's policy gate target (manager), or address(0) if ungated.
    /// @return commitment The actor's signed policy commitment, or bytes32(0) if ungated.
    function getPolicy(address account, bytes32 actorId) external view returns (address target, bytes32 commitment) {
        return (_policyManager[actorId][account], _policyCommitment[actorId][account]);
    }

    /// @notice Resolves an actor's signed policy commitment, or bytes32(0) if ungated / no actor / zero commitment.
    ///
    /// @dev Single SLOAD. Intended for a policy manager's per-tx validation read on the protocol-dispatched
    ///      8130 tx path. This slot is non-zero only when the actor's scope carries SCOPE_POLICY (see _authorizeActor /
    ///      _revokeActor), but MAY be zero for a policy-gated actor with a zero (no-params) commitment; gating is
    ///      therefore determined by the SCOPE_POLICY bit, not by this slot being non-zero.
    ///
    /// @param account The account to read.
    /// @param actorId The actor identifier to resolve.
    ///
    /// @return The signed policy commitment, or bytes32(0).
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
        return _isLocked(_accountState[account]);
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
        uint8 flags = config.flags;
        if (flags & FLAG_LOCKED == 0) {
            // Unlocked: no lock bits set.
            return (false, false, 0, 0);
        }
        if (flags & FLAG_UNLOCK_INITIATED == 0) {
            // Hard-locked: lockUnion holds the configured delay; synthesize the max sentinel for unlocksAt.
            return (true, false, type(uint40).max, uint16(config.lockUnion));
        }
        // Unlock initiated: lockUnion holds the effective unlock timestamp; the delay has been consumed.
        uint40 unlockTime = config.lockUnion;
        return (block.timestamp < unlockTime, true, unlockTime, 0);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // INTERNAL FUNCTIONS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Returns whether the account's configuration is currently frozen, WITHOUT mutating storage.
    function _isLocked(AccountState storage st) private view returns (bool) {
        uint8 flags = st.flags;
        if (flags & FLAG_LOCKED == 0) return false; // not locked
        if (flags & FLAG_UNLOCK_INITIATED == 0) return true; // hard-locked
        return block.timestamp < st.lockUnion; // pending unlock: frozen until the timestamp elapses
    }

    /// @notice Returns true if the account is locked; lazily clears the lock flags/union once an initiated unlock has
    ///         elapsed (the "cleared by the next op" rule).
    function _checkAndClearLock(address account) internal returns (bool locked) {
        AccountState storage st = _accountState[account];
        if (_isLocked(st)) return true;
        // Not locked, but FLAG_LOCKED still set means an initiated unlock has now elapsed: clear the lock bits and
        // union so the account returns to a clean unlocked slot.
        if (st.flags & FLAG_LOCKED != 0) {
            st.flags &= ~(FLAG_LOCKED | FLAG_UNLOCK_INITIATED);
            st.lockUnion = 0;
        }
        return false;
    }

    /// @dev True once the account has been bootstrapped via createAccount or importAccount. localSequence doubles as
    ///      the initialized flag (set to 1 at bootstrap); multichainSequence covers an account that established 8130
    ///      state via a global (chainId 0) change.
    function _isInitialized(address account) private view returns (bool) {
        AccountState storage st = _accountState[account];
        return st.localSequence != 0 || st.multichainSequence != 0;
    }

    // ----------------------------------------------------------------------------------------------------------------
    // ACTOR CHANGES
    // ----------------------------------------------------------------------------------------------------------------

    /// @dev Registers the bootstrap actor set shared by createAccount and importAccount: requires a non-empty,
    ///      strictly ascending-by-actorId list (rejecting unsorted or duplicate entries) and authorizes each entry
    ///      with its declared scope and (when scope & SCOPE_POLICY is set) policyData. Expiry is always 0 for
    ///      initial actors; scoped-with-expiry keys are added later via applySignedActorChanges. Reverts with
    ///      NoInitialActors or ActorsNotSortedOrDuplicate.
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

            // Initial actors carry scope verbatim (0x00 = unrestricted admin) and never an expiry. When
            // scope & SCOPE_POLICY is set, policyData is validated by the same frozen rule as authorizeActor
            // (52 bytes). Authorizing the self-actorId as k1 writes its scope into the inline default-EOA fields.
            ActorConfig memory config =
                ActorConfig({authenticator: initialActors[i].authenticator, scope: initialActors[i].scope, expiry: 0});
            _authorizeActor(account, initialActors[i].actorId, config, initialActors[i].policyData);
        }
    }

    /// @dev Authorizes (upserts) `actorId` with `config` and optional `policyData`, emitting ActorAuthorized. Rejects
    ///      a sub-K1 authenticator. The self-actorId is routed by authenticator type (a k1 self inline in
    ///      AccountState, a non-k1 self in _actorConfig) and the two are kept mutually exclusive; every other actor
    ///      lives in _actorConfig. Reverts with InvalidAuthenticator or InvalidPolicyData.
    function _authorizeActor(address account, bytes32 actorId, ActorConfig memory config, bytes memory policyData)
        internal
        nonZeroAccount(account)
    {
        // Only reject the zero authenticator (the empty-slot sentinel). A non-zero authenticator with no code is
        // accepted deliberately: authenticators may be counterfactual (deployed later) and some are intentionally
        // codeless sentinels (e.g. EXTERNAL_POLICY_AUTHENTICATOR). A bad authenticator simply fails fail-closed at
        // authentication time, mirroring the reference PolicyManager's treatment of a zero-commitment policy actor.
        if (config.authenticator < K1_AUTHENTICATOR) revert InvalidAuthenticator();

        // Slice the signed policy by scope & SCOPE_POLICY. The commitment is opaque to the protocol. This contract
        // does not reject scope combinations (e.g. SCOPE_POLICY | SCOPE_SELF_PAYER) — any use-time exclusivity between
        // SCOPE_POLICY and the account's other capabilities is protocol-side, not enforced here.
        (address manager, bytes32 commitment) = _slicePolicy(config.scope, policyData);

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
                st.defaultEOAExpiry = config.expiry;
                st.flags &= ~FLAG_REVOKE_DEFAULT_EOA; // enable the inline self
            } else {
                // Upsert: overwrite any existing non-k1 self in place.
                _actorConfig[actorId][account] = config;
                // Mutual exclusion: disable and clear the inline k1 self.
                _disableInlineSelf(st);
            }
            // Policy slots are keyed by actorId (shared keyspace across both self homes).
            _writePolicySlots(actorId, account, manager, commitment);

            _emitActorAuthorized(account, actorId, config, manager, commitment);
            return;
        }

        // Non-self actor: single _actorConfig home. Upsert: overwrite in place.
        _actorConfig[actorId][account] = config;
        _writePolicySlots(actorId, account, manager, commitment);

        _emitActorAuthorized(account, actorId, config, manager, commitment);
    }

    /// @dev Writes an actor's policy slots verbatim. `_slicePolicy` yields a zero manager/commitment for a non-policy
    ///      scope, so an ungated actor simply zeroes the slots — a single unconditional write both installs a new gate
    ///      and clears any stale one when an actor moves policy-gated -> ungated or re-keys to a different manager,
    ///      preserving the "policy slots are non-zero iff scope & SCOPE_POLICY != 0" invariant.
    function _writePolicySlots(bytes32 actorId, address account, address manager, bytes32 commitment) private {
        _policyCommitment[actorId][account] = commitment;
        _policyManager[actorId][account] = manager;
    }

    /// @dev Disables the inline k1 ("self") key: sets FLAG_REVOKE_DEFAULT_EOA so the inline full-owner path stays off
    ///      and zeroes the inline scope/expiry. Used when authorizing a non-k1 self (mutual exclusion) and on revoke.
    function _disableInlineSelf(AccountState storage st) private {
        st.flags |= FLAG_REVOKE_DEFAULT_EOA;
        st.defaultEOAScope = 0;
        st.defaultEOAExpiry = 0;
    }

    /// @dev Emit ActorAuthorized with a tightly packed payload. The base packs to 32 bytes
    ///      (authenticator(20) || scope(1) || expiry(6) || reserved(5 zero bytes)); the policy gate
    ///      (manager(20) || commitment(32), 52 bytes) is appended only when scope & SCOPE_POLICY != 0.
    function _emitActorAuthorized(
        address account,
        bytes32 actorId,
        ActorConfig memory config,
        address manager,
        bytes32 commitment
    ) private {
        bytes memory actorData = (config.scope & SCOPE_POLICY != 0)
            ? abi.encodePacked(config.authenticator, config.scope, config.expiry, bytes5(0), manager, commitment)
            : abi.encodePacked(config.authenticator, config.scope, config.expiry, bytes5(0));
        emit ActorAuthorized(account, actorId, actorData);
    }

    /// @dev Validates `policyData` against `scope & SCOPE_POLICY` and returns (manager, commitment).
    ///      Unset: empty data -> (0, 0). Set: exactly 52 bytes manager[20] || commitment[32] -> (manager,
    ///      commitment), written verbatim. Neither field need be non-zero: a zero commitment is a valid "no
    ///      params" and a zero manager gates the actor to address(0). Only a length mismatch reverts. The protocol
    ///      does not interpret the commitment value; self-enforcement is expressed as manager == account.
    function _slicePolicy(uint8 scope, bytes memory policyData)
        internal
        pure
        returns (address manager, bytes32 commitment)
    {
        if (scope & SCOPE_POLICY == 0) {
            if (policyData.length != 0) revert InvalidPolicyData();
            return (address(0), bytes32(0));
        }
        if (policyData.length != 52) revert InvalidPolicyData();
        assembly ("memory-safe") {
            manager := shr(96, mload(add(policyData, 0x20)))
            commitment := mload(add(policyData, 0x34))
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
            _disableInlineSelf(_accountState[account]);
        }
        emit ActorRevoked(account, actorId);
    }

    /// @dev Derives the CREATE2 inputs once for both {createAccount} and {computeAddress}: the effective salt, the
    ///      deployment code, and the resulting counterfactual address. Sharing this avoids rebuilding and re-hashing
    ///      the (up to ~24KB) deployment code — and recomputing the actors commitment — twice per creation.
    function _prepareDeployment(bytes32 userSalt, bytes calldata bytecode, InitialActor[] calldata initialActors)
        private
        view
        returns (address account, bytes32 effectiveSalt, bytes memory deploymentCode)
    {
        effectiveSalt = _computeEffectiveSalt(userSalt, initialActors);
        deploymentCode = _buildDeploymentCode(bytecode);
        bytes32 codeHash = keccak256(deploymentCode);
        bytes32 create2Hash = keccak256(abi.encodePacked(bytes1(0xFF), address(this), effectiveSalt, codeHash));
        account = address(uint160(uint256(create2Hash)));
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

    /// @dev Packed commitment over the initial actor set. Per-actor contribution is
    ///      actorId (32) || authenticator (20) || scope (1) || policyData, where policyData is empty (POLICY unset)
    ///      or exactly 52 bytes (POLICY set), so the length is unambiguous. Expiry does not participate (always 0
    ///      for initial actors).
    function _computeActorsCommitment(InitialActor[] calldata initialActors) internal pure returns (bytes32) {
        bytes memory packed;
        for (uint256 i; i < initialActors.length; i++) {
            packed = abi.encodePacked(
                packed,
                initialActors[i].actorId,
                initialActors[i].authenticator,
                initialActors[i].scope,
                initialActors[i].policyData
            );
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
            // Hash the actor's real scope. Expiry is always 0 at import — an actor-provided expiry is never
            // accepted here. policyData is hashed via keccak256 into the Actor struct hash. The typehash structure
            // matches the importAccount signature payload in EIP-8130.
            bytes32 configHash = keccak256(
                abi.encode(ACTORCONFIG_TYPEHASH, initialActors[i].authenticator, initialActors[i].scope, uint48(0))
            );
            actorHashes[i] = keccak256(
                abi.encode(ACTOR_TYPEHASH, initialActors[i].actorId, configHash, keccak256(initialActors[i].policyData))
            );
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

    /// @dev Computes the digest signed over an applySignedLockChanges call, binding the lock op and its unlock delay
    ///      to `account`, `chainId`, and `sequence` via LOCK_CHANGE_TYPEHASH. Lock changes are local-channel only,
    ///      so callers always pass the current chainId.
    function _computeSignedLockChangesDigest(
        address account,
        uint256 chainId,
        uint8 op,
        uint16 unlockDelay,
        uint64 sequence
    ) internal pure returns (bytes32) {
        return keccak256(abi.encode(LOCK_CHANGE_TYPEHASH, account, chainId, op, unlockDelay, sequence));
    }

    // ----------------------------------------------------------------------------------------------------------------
    // AUTHENTICATION
    // ----------------------------------------------------------------------------------------------------------------

    /// @dev Resolves and authenticates the actor behind `authenticator`/`data`, returning its
    ///      (actorId, scope, policyTarget). Routes the K1 sentinel to _authenticateK1; otherwise calls the
    ///      IAuthenticator and requires the resolved actorId to carry a matching, unexpired _actorConfig entry.
    ///      Reverts with AuthenticationFailed, AuthenticatorMismatch, or ActorExpired.
    function _authenticate(address account, bytes32 hash, address authenticator, bytes calldata data)
        internal
        view
        returns (bytes32, uint8, address)
    {
        if (authenticator == K1_AUTHENTICATOR) return _authenticateK1(account, hash, data);

        bytes32 actorId = IAuthenticator(authenticator).authenticate(hash, data);
        if (actorId == bytes32(0)) revert AuthenticationFailed();

        (uint8 scope, address policyTarget) = _resolveExplicitActor(account, actorId, authenticator);
        return (actorId, scope, policyTarget);
    }

    /// @dev Resolves an explicit _actorConfig-homed actor: requires a matching authenticator and an unexpired entry,
    ///      returning its scope and policy gate target. Shared by the non-k1 (_authenticate) and k1 other-actor
    ///      (_authenticateK1) paths. Reverts with AuthenticatorMismatch or ActorExpired.
    function _resolveExplicitActor(address account, bytes32 actorId, address expectedAuthenticator)
        private
        view
        returns (uint8 scope, address policyTarget)
    {
        ActorConfig memory config = _actorConfig[actorId][account];
        if (config.authenticator != expectedAuthenticator) revert AuthenticatorMismatch();
        // Expiry is read from the same slot; an expired actor fails authentication. 0 = no expiry.
        if (config.expiry != 0 && block.timestamp > config.expiry) revert ActorExpired();
        scope = config.scope;
        policyTarget = _policyTargetFor(scope, actorId, account);
    }

    /// @dev Resolves the policy gate target for an actor: the policy manager for a policy-gated actor
    ///      (scope & SCOPE_POLICY != 0), or address(0) otherwise. Non-policy actors (incl. admin) skip the SLOAD.
    function _policyTargetFor(uint8 scope, bytes32 actorId, address account) private view returns (address) {
        return (scope & SCOPE_POLICY != 0) ? _policyManager[actorId][account] : address(0);
    }

    /// @dev The single secp256k1 ("K1") path. Recovers the signer (EIP-2 enforced), then resolves the actor:
    ///        - signer == account -> the inline self config in AccountState (one SLOAD): the flag gates the whole
    ///          key (set => revert), and when live the scope/expiry come from the inline fields (all-zero = full
    ///          owner; non-zero = a scoped self). A non-k1 self is unreachable here by construction (it requires
    ///          its own authenticator), and mutual exclusion keeps the flag set whenever one is live.
    ///        - otherwise the signer's actorId must carry an explicit K1 config in _actorConfig (any other k1 actor).
    ///      Both the common self and other-actor paths cost a single SLOAD; the policy-manager slot is read only for a
    ///      policy-gated actor (`scope & SCOPE_POLICY != 0`), so non-policy authentications avoid the extra SLOAD.
    function _authenticateK1(address account, bytes32 hash, bytes calldata data)
        internal
        view
        returns (bytes32, uint8, address)
    {
        address recovered = _recoverSigner(hash, data);
        if (recovered == address(0)) revert InvalidSignature();

        if (recovered == account) {
            // Inline self: a single SLOAD resolves the whole key. The flag disables it entirely; otherwise the
            // inline scope/expiry govern (all-zero = full owner).
            AccountState storage st = _accountState[account];
            if (st.flags & FLAG_REVOKE_DEFAULT_EOA != 0) revert DefaultEoaRevoked();
            if (st.defaultEOAExpiry != 0 && block.timestamp > st.defaultEOAExpiry) revert ActorExpired();
            bytes32 selfActorId = bytes32(bytes20(account));
            uint8 selfScope = st.defaultEOAScope;
            return (selfActorId, selfScope, _policyTargetFor(selfScope, selfActorId, account));
        }

        bytes32 actorId = bytes32(bytes20(recovered));
        (uint8 scope, address policyTarget) = _resolveExplicitActor(account, actorId, K1_AUTHENTICATOR);
        return (actorId, scope, policyTarget);
    }

    /// @dev True if the account's default (implicit) EOA has been revoked via the AccountState flag.
    function _isDefaultEoaRevoked(address account) internal view returns (bool) {
        return _accountState[account].flags & FLAG_REVOKE_DEFAULT_EOA != 0;
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
    /// @dev Returns a 14-byte EVM loader followed by `bytecode`. The loader copies the trailing `bytecode` into
    ///      memory and returns it as the deployed runtime:
    ///        PUSH2 n; PUSH1 0x0e; PUSH1 0x00; CODECOPY   // copy n bytes from code offset 14 to mem 0
    ///        PUSH2 n; PUSH1 0x00; RETURN                 // return mem[0..n]
    function _buildDeploymentCode(bytes calldata bytecode) internal pure returns (bytes memory) {
        uint256 n = bytecode.length;
        if (n > 0xFFFF) revert BytecodeTooLarge();
        return abi.encodePacked(
            bytes1(0x61), bytes2(uint16(n)), hex"600e600039", bytes1(0x61), bytes2(uint16(n)), hex"6000f3", bytecode
        );
    }
}
