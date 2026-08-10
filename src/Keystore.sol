// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {ActorId} from "./libraries/ActorId.sol";
import {IAuthenticator} from "./interfaces/IAuthenticator.sol";
import {Scopes} from "./libraries/Scopes.sol";

/// @notice Keystore system contract for EIP-8130.
///         Manages actor authorization, account creation, change sequencing, and account lock. This contract is
///         also the canonical reference for the EIP-8130 Keystore ABI: its public structs, events,
///         and function signatures are the spec surface, and there is no separate interface file to keep in sync.
///
/// @author Coinbase
contract Keystore {
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // STRUCTS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Per-account replay counters for signed changes.
    struct ChangeSequences {
        uint64 multichain; // chain_id 0 (multichain channel)
        uint32 localEpoch; // local channel epoch; incremented by IncrementLocalEpoch, invalidates unlanded local signatures
        uint32 localSequence; // current local counter; reset to 0 by IncrementLocalEpoch
    }

    /// @notice An actor's authorization: authenticator, expiry, and scope. Field order matches the normative
    ///         `actor_config` slot layout: authenticator(20) ‖ expiry(6) ‖ scope(2) ‖ reserved(4).
    struct ActorConfig {
        address authenticator;
        uint48 expiry; // Unix seconds; 0 = no expiry. Actor invalid once block.timestamp > expiry
        uint16 scope;
    }

    /// @notice Initial actor for account creation and import. Carries its scope and, when scope & Scopes.POLICY is
    ///         set, its policy data; expiry is always 0 for initial actors (scoped-with-expiry keys are added later
    ///         via applySignedAccountChanges).
    struct InitialActor {
        bytes32 actorId;
        address authenticator;
        uint16 scope; // 0x00 = unrestricted admin
        bytes policyData; // empty unless scope & Scopes.POLICY; then manager(20) || commitment(32)
    }

    /// @notice The operation an {AccountChange} applies within an {applySignedAccountChanges} batch.
    ///
    /// @dev ABI-encodes as uint8. A locked account freezes every op except Unlock and IncrementLocalEpoch, enforced by
    ///      the guard in {applySignedAccountChanges} (Unlock additionally self-checks it is hard-locked). Lock and
    ///      Unlock are Local-only and must each be the batch's only op.
    enum ChangeType {
        // Authority ops (mutate who can act).
        AuthorizeActor, // payload: abi.encode(bytes32 actorId, ActorConfig cfg, bytes policyData); cfg.expiry is the granted expiry
        RevokeActor, // payload: abi.encode(bytes32 actorId)
        // Environment ops (mutate the rules ops are checked against).
        IncrementLocalEpoch, // Either channel; payload: empty (length == 0 enforced)
        Lock, // Local only; payload: abi.encode(uint16 unlockDelay)
        Unlock // Local only; payload: empty (length == 0 enforced)
    }

    /// @notice The replay domain a {SignedAccountChanges} batch is bound to.
    ///
    /// @dev Replaces the prior `uint256 chainId` argument. {Local} binds `block.chainid` and carries the full local
    ///      epoch machinery (see {SignedAccountChanges.sequence}); {Multichain} binds chainId 0 and keeps a plain
    ///      monotonic counter with no epochs and no unsequenced (JIT) mode. {Lock} and {Unlock} are rejected on the
    ///      Multichain channel; {IncrementLocalEpoch} is allowed on either channel.
    enum AccountChangeChannel {
        Local,
        Multichain
    }

    /// @notice A single operation within a signed batch: its type and an operation-specific ABI-encoded payload.
    struct AccountChange {
        ChangeType changeType;
        bytes payload;
    }

    /// @notice An ordered, atomic batch of account changes with its replay binding and signature.
    ///
    /// @dev `changes` are applied in order, all-or-nothing (intersection-strict: any rejected op reverts the whole
    ///      batch). `sequence` is interpreted per `channel`:
    ///        - Local: localEpoch(32, high) || localSequence(32, low). A low half equal to {UNSEQUENCED} marks the
    ///          batch as unsequenced (JIT) — it does not consume a sequence (so it stays replayable until the epoch
    ///          moves); any other low value is a sequenced batch consumed against the account's localSequence.
    ///        - Multichain: a plain uint64 consumed against the account's multichainSequence; never {UNSEQUENCED},
    ///          never carries an epoch.
    ///      `signature` is the standard authenticator(20) || authenticator-data blob authenticating the signer.
    struct SignedAccountChanges {
        AccountChangeChannel channel;
        uint64 sequence;
        AccountChange[] changes;
        bytes signature;
    }

    /// @notice Per-account packed state: sequences, lock status, and the inline home for the account's k1 self key.
    ///
    /// @dev Packed into a single storage slot; the field layout is normative (nodes read the raw slot for mempool
    ///      rate-limit tiering, see the EIP's Account Lock section). Field order and widths match the spec's
    ///      account-state table: multichainSequence, localSequence, localEpoch, flags, lockUnion, defaultEOAExpiry,
    ///      defaultEOAScope, then 1 reserved byte that MUST stay zero.
    ///      The local replay counter is stored as two adjacent uint32 fields — `localSequence` (low) then `localEpoch`
    ///      (high) — which occupy the same 8 bytes as, and read identically to, the single `localEpoch(32)||
    ///      localSequence(32)` word committed in a signed batch's `sequence` (see {getChangeSequences}). Storing
    ///      them split keeps the layout size-neutral (still one slot) while removing pack/unpack math from the hot path.
    ///      The combined local word marks local initialization; the multichain counter covers global-only activity.
    ///      {IncrementLocalEpoch} resets the sequence while keeping the combined local word non-zero.
    ///      See {FLAG_REVOKE_DEFAULT_EOA}, {FLAG_LOCKED}, and {FLAG_UNLOCK_INITIATED} for `flags` and `lockUnion`.
    ///      The defaultEOA* fields are the inline home for the account's own secp256k1 ("self") key, whose actorId is
    ///      `ActorId.fromAddress(account)`. When FLAG_REVOKE_DEFAULT_EOA is unset, a k1 signature recovering to the
    ///      account authenticates with this inline config (all-zero = full owner; non-zero scope/expiry = a
    ///      scoped self key), resolved in a single SLOAD. Policy gating (when scope & Scopes.POLICY != 0) is still keyed
    ///      by actorId in the shared _policyManager/_policyCommitment keyspace. The separate _actorConfig[self][account]
    ///      slot is reserved for a *non-k1* self authenticator (e.g. a post-quantum verifier returning the
    ///      self-actorId); the two homes are mutually exclusive (see _authorizeActor).
    struct AccountState {
        uint64 multichainSequence; // 8 bytes
        uint32 localSequence; // 4 bytes – low half of the signed local word
        uint32 localEpoch; // 4 bytes – high half of the signed local word
        uint8 flags; // 1 byte – bitfield: bit 0 CONTRACT_ESTABLISHED, bit 1 REVOKE_DEFAULT_EOA, bit 2 LOCKED, bit 3 UNLOCK_INITIATED
        uint48 lockUnion; // 6 bytes – union: unlockDelay while UNLOCK_INITIATED clear, else unlocksAt (timestamp)
        uint48 defaultEOAExpiry; // 6 bytes – inline self k1 expiry (Unix seconds; 0 = no expiry)
        uint16 defaultEOAScope; // 2 bytes – inline self k1 scope (0 = full owner)
        // 1 byte reserved (remaining slot byte); MUST stay zero.
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // CONSTANTS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @dev ERC-1271 isValidSignature(bytes32,bytes) selector, which also equals the ERC-1271 magic return value
    ///      (0x1626ba7e); used both to build the import staticcall and to validate its result.
    bytes4 internal constant ERC1271_SELECTOR = bytes4(keccak256("isValidSignature(bytes32,bytes)"));

    /// @notice Typehash binding an importAccount signature to its accountId, chainId, and initial actor set.
    ///
    /// @dev NOT compliant with EIP-712, to mitigate eth_signTypedData phishing. `accountId` is the importing account's
    ///      actorId (`ActorId.fromAddress(account)`), binding the digest to that account so it cannot be replayed
    ///      against another. `chainId` is either the current chain or 0 for a multichain import. Initial actors are
    ///      hashed structurally below.
    bytes32 public constant ACTOR_INITIALIZATION_TYPEHASH = keccak256(
        "ActorInitialization(bytes32 accountId,uint256 chainId,Actor[] initialActors)Actor(bytes32 actorId,ActorConfig config,bytes policyData)ActorConfig(address authenticator,uint48 expiry,uint16 scope)"
    );

    /// @notice Typehash used to structurally hash each Actor within an ActorInitialization import digest.
    bytes32 public constant ACTOR_TYPEHASH = keccak256(
        "Actor(bytes32 actorId,ActorConfig config,bytes policyData)ActorConfig(address authenticator,uint48 expiry,uint16 scope)"
    );

    /// @notice Typehash used to structurally hash an Actor's ActorConfig within an import digest.
    bytes32 public constant ACTOR_CONFIG_TYPEHASH =
        keccak256("ActorConfig(address authenticator,uint48 expiry,uint16 scope)");

    /// @notice Typehash binding a signed account-change batch to its account, chainId, and sequence.
    ///
    /// @dev NOT compliant with EIP-712, to mitigate phishing attacks. `chainId` is the channel's replay domain
    ///      (0 for {AccountChangeChannel.Multichain}, block.chainid for {AccountChangeChannel.Local}). The digest
    ///      scheme is confined to {_changesDigest}, keeping it independent of the apply pipeline.
    bytes32 public constant SIGNED_ACCOUNT_CHANGES_TYPEHASH = keccak256(
        "SignedAccountChanges(address account,uint256 chainId,uint64 sequence,AccountChange[] changes)"
        "AccountChange(uint8 changeType,bytes payload)"
    );

    /// @notice Typehash used to structurally hash each AccountChange within a SignedAccountChanges batch.
    bytes32 public constant ACCOUNT_CHANGE_TYPEHASH = keccak256("AccountChange(uint8 changeType,bytes payload)");

    /// @notice Local-channel sequence low-half sentinel marking an unsequenced (JIT) batch. A {SignedAccountChanges}
    ///         whose low 32 bits equal this value does not consume a sequence, so it stays replayable until the local
    ///         epoch moves. Any op may use it, but Lock and Unlock must remain standalone. Sequenced batches may run up
    ///         to UNSEQUENCED - 2.
    uint32 public constant UNSEQUENCED = type(uint32).max;

    // ----------------------------------------------------------------------------------------------------------------
    // ACTOR SCOPE
    // ----------------------------------------------------------------------------------------------------------------

    // This contract is deliberately scope-agnostic. `scope == 0` is the admin predicate (the only scope value it
    // acts on for config/lock changes), and it interprets exactly one grant bit — Scopes.POLICY — to slice and
    // store an actor's policy data. Every other named grant (SENDER, NONCE, SELF_PAYER, SPONSOR_PAYER, and future
    // bits) is stored verbatim and never read here; its meaning is enforced by whoever consumes it (protocol nodes,
    // account contracts, policy managers). The full uint16 grant vocabulary lives in {Scopes}. This contract does
    // not reject scope combinations — any use-time exclusivity is protocol-side.

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

    /// @notice AccountState.flags bit: set on every account the keystore establishes (createAccount and importAccount),
    ///         marking it "keystore-established, not a proven address key."
    ///
    /// @dev Permanent once set; has no effect on authentication. The protocol can read it to make code-delegation or
    ///      other decisions — e.g. an account may have empty code yet retain EIP-8130 state (an EIP-6780 same-transaction
    ///      SELFDESTRUCT), so this flag lets consumers avoid treating empty code as proof of a known EOA key. A future
    ///      key-backed native path may deliberately leave it clear.
    uint8 public constant FLAG_CONTRACT_ESTABLISHED = 0x01;

    /// @notice AccountState.flags bit: when set, the account's secp256k1 ("self") key cannot authenticate — neither
    ///         the implicit full owner nor an inline-scoped self. The self key is a K1_AUTHENTICATOR signature whose
    ///         recovered signer equals the account; when this flag is unset, it authenticates with the inline
    ///         AccountState.defaultEOA* config (all-zero = full owner), resolved in a single SLOAD. The flag is set
    ///         by createAccount/importAccount (self k1 disabled by default — quantum-safe), by revoking the
    ///         self-actorId, and by authorizing the self-actorId to a *non-k1* authenticator (mutual exclusion: the
    ///         k1 self and a non-k1 self are never simultaneously live). Authorizing the self-actorId as a k1 actor
    ///         clears it (re-enabling the inline self, possibly scoped).
    uint8 public constant FLAG_REVOKE_DEFAULT_EOA = 0x02;

    /// @notice AccountState.flags bit (spec `LOCKED`): identifies a lock record. The account is frozen unless an
    ///         initiated unlock's timestamp has elapsed; expired lock bits remain until a later Lock overwrites them.
    uint8 public constant FLAG_LOCKED = 0x04;

    /// @notice AccountState.flags bit (spec `UNLOCK_INITIATED`): selects how the packed `lockUnion` field is read.
    ///         While clear, `lockUnion` holds the configured unlock delay (seconds); while set, it holds unlocksAt
    ///         (the timestamp at which the pending unlock takes effect). Only meaningful when FLAG_LOCKED is set.
    uint8 public constant FLAG_UNLOCK_INITIATED = 0x08;

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
    ///        authenticator(20) || expiry(6) || scope(2) || reserved(4 zero bytes) = 32 bytes, and, only when
    ///        scope & Scopes.POLICY != 0, followed by the resolved policy gate manager(20) || commitment(32). So the
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
    event AccountUnlockInitiated(address indexed account, uint48 unlocksAt);

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

    /// @notice The batch signer is not the account admin (scope 0). Every signed account change is admin-only.
    error UnauthorizedAccountChange();

    /// @notice The import target has no bytecode or its ERC-1271 signature check did not return the canonical magic
    ///         word.
    error InvalidImportSignature();

    /// @notice A lock op carried a zero unlock delay.
    error ZeroUnlockDelay();

    /// @notice An unlock op was requested when the account was not in the hard-locked state (FLAG_LOCKED set,
    ///         FLAG_UNLOCK_INITIATED clear) — i.e. never locked, or an unlock was already initiated.
    error NotLocked();

    /// @notice The batch's committed local epoch does not match the account's current local epoch: every unlanded
    ///         local signature at a prior epoch is dead. Applies to sequenced and unsequenced Local batches.
    error StaleEpoch();

    /// @notice A sequenced batch's sequence did not match the account's current (local or multichain) counter.
    error BadSequence();

    /// @notice The channel's sequence counter is at its terminal value and cannot advance.
    error SequenceSaturated();

    /// @notice The local epoch is at its terminal value and cannot be incremented.
    error EpochSaturated();

    /// @notice An AuthorizeActor's granted expiry is non-zero and not strictly in the future (self-expired on
    ///         arrival). A zero expiry is the "no expiry" sentinel and is accepted.
    error ExpiredChange();

    /// @notice A local-only change (Lock or Unlock) was submitted on the Multichain channel.
    error ChangeRequiresLocalChannel();

    /// @notice A change payload did not match the shape required by its ChangeType (e.g. a non-empty payload on
    ///         IncrementLocalEpoch / Unlock).
    error InvalidChangePayload();

    /// @notice A signed batch carried no changes. An empty batch is rejected so it can neither consume a sequence nor
    ///         initialize a fresh account without altering any configuration.
    error EmptyChangeSet();

    /// @notice An actor authorization targeted the zero actorId, which is not a usable actor identifier.
    error InvalidActorId();

    /// @notice A Lock or Unlock appeared in a batch alongside other changes. Lock/unlock must be the sole change in
    ///         their batch, so a lock transition can never interleave with actor changes in the same signed batch.
    error LockChangeMustBeStandalone();

    /// @notice Defensive guard for an unhandled ChangeType in the apply loop. Unreachable in practice — out-of-range
    ///         wire values are rejected by the enum decoder during ABI-decoding — but forces any future ChangeType to
    ///         be dispatched explicitly instead of silently falling through.
    error UnknownChangeType();

    /// @notice The auth blob is shorter than the 20-byte authenticator selector prefix.
    error InvalidAuthLength();

    /// @notice createAccount/importAccount was called with an empty initialActors set.
    error NoInitialActors();

    /// @notice initialActors are not strictly ascending by actorId (unsorted or duplicated).
    error ActorsNotSortedOrDuplicate();

    /// @notice An actor config named an authenticator below the K1 sentinel (i.e. address(0)).
    error InvalidAuthenticator();

    /// @notice The policyData length did not match `scope & Scopes.POLICY` (52 bytes when set, empty when unset).
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

    /// @notice createAccount was called with empty deployment bytecode.
    /// @dev Prevents creating a Keystore-initialized account with no runtime code.
    error EmptyBytecode();

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

    /// @notice Per-actor signed policy commitment. Set when the actor's scope carries Scopes.POLICY.
    /// @dev Read only during execution (via getPolicyCommitment / getActor), never during signature validity checks.
    mapping(bytes32 actorId => mapping(address account => bytes32)) internal _policyCommitment;

    /// @notice Per-actor policy manager address. Set when the actor's scope carries Scopes.POLICY.
    mapping(bytes32 actorId => mapping(address account => address)) internal _policyManager;

    /// @notice Per-account state: sequences, lock status (single slot per account)
    mapping(address account => AccountState) internal _accountState;

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // MODIFIERS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Modifier to check if an account is unlocked.
    /// @dev Reverts with AccountIsLocked when the account is locked.
    modifier onlyUnlocked(address account) {
        if (_isLocked(account)) {
            revert AccountIsLocked();
        }
        _;
    }

    /// @notice Modifier to check if an account is not the zero address.
    /// @dev Reverts with ZeroAccount when the account is the zero address.
    modifier nonZeroAccount(address account) {
        if (account == address(0)) {
            revert ZeroAccount();
        }
        _;
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // FUNCTIONS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Deploys a new account with its initial actors. Each initial actor is registered with its declared
    ///         `scope` and, when `scope & Scopes.POLICY` is set, its `policyData` (an external `manager` is expressible
    ///         at create; `manager = account` is not, as the address is unknown at commitment time). `expiry` is
    ///         always 0 at create — scoped-with-expiry keys are added afterwards via applySignedAccountChanges. The
    ///         implicit default-EOA key is disabled on creation.
    ///
    /// @dev Reverts with EmptyBytecode when `bytecode` is empty.
    /// @dev Reverts with BytecodeTooLarge when `bytecode` exceeds the maximum encodable length.
    /// @dev Reverts with AlreadyInitialized when the account already has EIP-8130 state.
    /// @dev Reverts with NoInitialActors when `initialActors` is empty.
    /// @dev Reverts with ActorsNotSortedOrDuplicate when `initialActors` is not strictly ascending by actorId.
    /// @dev Reverts with InvalidAuthenticator when an initial actor names a zero authenticator.
    /// @dev Reverts with InvalidPolicyData when an initial actor's policyData length does not match its scope.
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

        // Block re-initialization of an already-bootstrapped account. This must be explicit: authorizeActor is an
        // upsert (no duplicate-actor revert), so without this guard a duplicate createAccount would re-run
        // initialization over the existing actor set.
        if (_isInitialized(account)) {
            revert AlreadyInitialized();
        }

        // Created accounts disable the implicit EOA key. Set this before actor initialization so an explicit k1 self
        // actor can re-enable it. FLAG_CONTRACT_ESTABLISHED is set for every created account. See
        // {FLAG_CONTRACT_ESTABLISHED}.
        _accountState[account].localSequence = 1;
        _accountState[account].flags = FLAG_REVOKE_DEFAULT_EOA | FLAG_CONTRACT_ESTABLISHED;

        _initializeAccount(account, initialActors);

        // Deploy at the derived address. create2 returns address(0) on failure (EIP-170 size, EIP-3541 leading 0xEF,
        // or out of gas); reverting on mismatch unwinds every state write above, so a failed deploy can never leave
        // an initialized-but-codeless account behind. Assembly is required because Solidity has no high-level
        // equivalent for CREATE2 over arbitrary prepared initcode.
        address deployed;
        assembly ("memory-safe") {
            deployed := create2(0, add(deploymentCode, 0x20), mload(deploymentCode), effectiveSalt)
        }
        if (deployed != account) {
            revert AccountDeploymentFailed();
        }
        emit AccountCreated(account, userSalt, keccak256(bytecode));
    }

    /// @notice Imports an existing account (which must have bytecode) into Keystore management via an
    ///         ERC-1271 signature over a typed import digest. The implicit default-EOA key is disabled after import.
    ///
    /// @dev Uses a custom (non-EIP-712) digest to partially mitigate eth_signTypedData phishing.
    /// @dev Reverts with AccountIsLocked when the account is locked.
    /// @dev Reverts with InvalidChainId when `chainId` is neither 0 (multichain) nor the current chain.
    /// @dev Reverts with AlreadyInitialized when the account already has EIP-8130 state.
    /// @dev Reverts with InvalidImportSignature when the account has no bytecode or its ERC-1271 check does not return
    ///      the canonical 32-byte ABI encoding of the magic value.
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
        if (chainId != 0 && chainId != block.chainid) {
            revert InvalidChainId();
        }

        // Import is a one-time bootstrap for accounts with no 8130 state yet.
        if (_isInitialized(account)) {
            revert AlreadyInitialized();
        }
        if (account.code.length == 0) {
            revert InvalidImportSignature();
        }
        _accountState[account].localSequence = 1;

        bytes32 digest = _computeImportDigest(account, chainId, initialActors);
        (bool success, bytes memory result) =
            account.staticcall(abi.encodeWithSelector(ERC1271_SELECTOR, digest, signature));
        if (!success || result.length != 32 || abi.decode(result, (bytes32)) != bytes32(ERC1271_SELECTOR)) {
            revert InvalidImportSignature();
        }

        // Disable the implicit EOA key after ERC-1271 validation so a delegated EOA can use that key to authorize its
        // import. Including the k1 self in initialActors re-enables it explicitly. FLAG_CONTRACT_ESTABLISHED is set for
        // every import regardless of code shape (delegates included). See {FLAG_CONTRACT_ESTABLISHED}.
        _accountState[account].flags = FLAG_REVOKE_DEFAULT_EOA | FLAG_CONTRACT_ESTABLISHED;

        _initializeAccount(account, initialActors);
        emit AccountImported(account);
    }

    /// @notice The sole signed-change entry point: applies an ordered, atomic batch of account changes (authorize,
    ///         revoke, increment-local-epoch, lock, unlock) authenticated by `s.signature`.
    ///
    /// @dev The governing axiom is Replay: a signed local change is valid only while it could still be validly
    ///      applied — the committed local epoch must match and grants self-expire (`cfg.expiry > now`, unless
    ///      `cfg.expiry == 0` which is the never-expiring sentinel).
    ///
    ///      Reduction is NOT contract-enforced. Removing authority durably (revoke, shorter expiry, narrower scope)
    ///      requires retiring the signatures that granted it, which on the local channel means a {IncrementLocalEpoch};
    ///      the contract lets a bare reduction land, so pairing it with an increment is a wallet responsibility. A bare
    ///      revoke (or expiry cut) is not durable while a replayable unsequenced grant for that actor is outstanding.
    ///
    ///      Authorization is flat: every signed account change is admin-only, so a single up-front scope check
    ///      (signer scope must be 0) authorizes the whole batch — there is no per-op authorization and no per-op
    ///      sequencing restriction. Lock and Unlock are Local-only and must also be standalone; IncrementLocalEpoch is
    ///      allowed on either channel. Other ops may share a non-empty batch.
    ///
    ///      Pipeline (in order): (1) split the sequence word; (2) reject a stale epoch on Local batches;
    ///      (3) validate/advance the sequence counter BEFORE apply (reentrancy discipline); (4) compute the digest
    ///      via {_changesDigest}, authenticate, and reject a non-admin signer; (5) iterate
    ///      changes enforcing channel and lock policy (Lock/Unlock rejected on Multichain; authority ops
    ///      rejected while the account is locked; Lock/Unlock must be standalone). Anyone may relay — authorization
    ///      comes entirely from the signature.
    ///
    /// @param account The account whose configuration is changed.
    /// @param s The signed batch (channel, ordered changes, sequence word, signature).
    function applySignedAccountChanges(address account, SignedAccountChanges calldata s)
        external
        nonZeroAccount(account)
    {
        AccountState storage st = _accountState[account];
        bool isLocal = s.channel == AccountChangeChannel.Local;

        // Reject an empty batch: a no-op signed change would otherwise consume a sequence (or initialize a fresh
        // account, below) without altering any configuration.
        if (s.changes.length == 0) {
            revert EmptyChangeSet();
        }

        // Epoch / sequence gate. An unsequenced (JIT) batch exists only on the local channel (low half ==
        // UNSEQUENCED) and does not consume a counter; every other batch consumes its channel's counter.
        if (isLocal) {
            uint32 epoch = uint32(s.sequence >> 32);
            uint32 seq = uint32(s.sequence);
            if (epoch != st.localEpoch) {
                revert StaleEpoch();
            }
            if (seq != UNSEQUENCED) {
                if (seq != st.localSequence) {
                    revert BadSequence();
                }
                if (seq >= UNSEQUENCED - 1) {
                    revert SequenceSaturated();
                }
                // Advance the local sequence before apply. A trailing IncrementLocalEpoch in the same batch
                // overwrites this to 0, but that second write lands on an already-warm slot (~100 gas), so the
                // combo isn't worth special-casing here.
                st.localSequence = seq + 1;
            } else if (!_isInitialized(account)) {
                // Mark a fresh account initialized and invalidate outstanding sequence-0 signatures. The unsequenced
                // batch remains replayable; failed authentication rolls this write back.
                st.localSequence = 1;
            }
        } else {
            // Multichain: a plain monotonic counter, never epoch-bearing or UNSEQUENCED.
            uint64 seq = s.sequence;
            if (seq != st.multichainSequence) {
                revert BadSequence();
            }
            if (seq == type(uint64).max) {
                revert SequenceSaturated();
            }
            st.multichainSequence = seq + 1;
        }

        // Authenticate over the digest. Authorization is flat: every signed account change is
        // admin-only, so a single scope check up front replaces any per-op authorization.
        bytes32 digest = _changesDigest(account, s.channel, s.sequence, s.changes);
        (, uint16 scope) = authenticateActor(account, digest, s.signature);
        if (scope != 0) {
            revert UnauthorizedAccountChange();
        }

        // Lock state at batch entry gates every op below. This snapshot is EXACT for the whole batch: the only ops
        // that mutate lock state (Lock/Unlock) must be standalone, so no op observes a lock state that a peer changed
        // mid-loop. Relaxing standalone re-opens snapshot staleness — a later authority op could then run against a
        // lock a Lock earlier in the same batch just set (or a stale-unlocked one).
        bool locked = _isLocked(account);

        uint256 n = s.changes.length;
        for (uint256 i; i < n; i++) {
            ChangeType t = s.changes[i].changeType;

            // Preconditions: freeze non-exempt ops on a locked account, and hold Lock/Unlock to a standalone local batch.
            if (locked && t != ChangeType.Unlock && t != ChangeType.IncrementLocalEpoch) {
                revert AccountIsLocked();
            }
            if (t == ChangeType.Lock || t == ChangeType.Unlock) {
                if (!isLocal) {
                    revert ChangeRequiresLocalChannel();
                }
                if (n != 1) {
                    revert LockChangeMustBeStandalone();
                }
            }

            // Apply: dispatch the op to its handler.
            if (t == ChangeType.AuthorizeActor) {
                _applyAuthorize(account, s.changes[i].payload);
            } else if (t == ChangeType.RevokeActor) {
                _applyRevoke(account, s.changes[i].payload);
            } else if (t == ChangeType.IncrementLocalEpoch) {
                _applyIncrementLocalEpoch(account, s.changes[i].payload);
            } else if (t == ChangeType.Lock) {
                _applyLock(account, s.changes[i].payload);
            } else if (t == ChangeType.Unlock) {
                _applyUnlock(account, s.changes[i].payload);
            } else {
                // Defensive guard: every ChangeType must be dispatched explicitly. Unreachable today — out-of-range
                // wire values are rejected by the enum decoder while ABI-decoding the calldata — so this forces any
                // future ChangeType to be wired in here rather than silently falling through.
                revert UnknownChangeType();
            }
        }
    }

    // ----------------------------------------------------------------------------------------------------------------
    // SIGNED-CHANGE OP HANDLERS
    // ----------------------------------------------------------------------------------------------------------------

    /// @dev AuthorizeActor. `payload = abi.encode(bytes32 actorId, ActorConfig cfg, bytes policyData)`; `cfg.expiry`
    ///      is the granted expiry and the signature self-expires at it (or never, if `cfg.expiry == 0`). A plain
    ///      upsert on both channels and both sequencing modes — the only gate is that a non-zero expiry be in the
    ///      future. An unsequenced grant is replayable (it consumes no counter) and last-write-wins on its slot until
    ///      the grant lapses or the epoch is incremented; durable reduction (revoke, shorter expiry, narrower scope) is
    ///      therefore a wallet responsibility — batch the reducing op with a {IncrementLocalEpoch} to retire outstanding
    ///      grants.
    function _applyAuthorize(address account, bytes calldata payload) private {
        (bytes32 actorId, ActorConfig memory cfg, bytes memory policyData) =
            abi.decode(payload, (bytes32, ActorConfig, bytes));

        // A grant must not be already-expired: reject a non-zero expiry that is not strictly in the future. A zero
        // expiry is the canonical "no expiry" sentinel (unlimited, per {ActorConfig}) and is accepted.
        if (cfg.expiry != 0 && cfg.expiry <= block.timestamp) {
            revert ExpiredChange();
        }

        _authorizeActor(account, actorId, cfg, policyData);
    }

    /// @dev RevokeActor. `payload = abi.encode(bytes32 actorId)`. Clears the actor's config and policy slots (and
    ///      disables the inline k1 self for the self-actorId), emitting ActorRevoked; reverts UnknownActor if the
    ///      actor is not currently live. Not durable against an outstanding replayable unsequenced grant for the same
    ///      actorId (which would re-install into the emptied slot); batch a {IncrementLocalEpoch} for durable teardown.
    function _applyRevoke(address account, bytes calldata payload) private {
        bytes32 actorId = abi.decode(payload, (bytes32));
        if (!_isAuthorized(account, actorId)) {
            revert UnknownActor();
        }
        delete _actorConfig[actorId][account];
        delete _policyCommitment[actorId][account];
        delete _policyManager[actorId][account];
        if (actorId == _selfActorId(account)) {
            _disableInlineSelf(_accountState[account]);
        }
        emit ActorRevoked(account, actorId);
    }

    /// @dev IncrementLocalEpoch. Empty payload. Strict increment of the local epoch, resetting the local sequence to 0
    ///      and thereby invalidating every unlanded local signature (they commit the full 64-bit word). Allowed on
    ///      either channel: a Multichain batch may bump the local epoch even though it carries no epoch of its own.
    function _applyIncrementLocalEpoch(address account, bytes calldata payload) private {
        if (payload.length != 0) {
            revert InvalidChangePayload();
        }
        AccountState storage st = _accountState[account];
        // The epoch half has no reserved sentinel (unlike UNSEQUENCED on the sequence half), so the full uint32 range
        // is usable: only the terminal value itself cannot advance.
        if (st.localEpoch == type(uint32).max) {
            revert EpochSaturated();
        }
        st.localEpoch += 1;
        st.localSequence = 0;
    }

    /// @dev Lock. Local-only; `payload = abi.encode(uint16 unlockDelay)`. Must be standalone. The caller
    ///      ({applySignedAccountChanges}) guarantees the account is unlocked before dispatch, so this overwrites any
    ///      residue from an elapsed prior lock unconditionally.
    function _applyLock(address account, bytes calldata payload) private {
        AccountState storage st = _accountState[account];
        uint16 unlockDelay = abi.decode(payload, (uint16));
        if (unlockDelay == 0) {
            revert ZeroUnlockDelay();
        }
        st.flags = (st.flags | FLAG_LOCKED) & ~FLAG_UNLOCK_INITIATED;
        st.lockUnion = unlockDelay;
        emit AccountLocked(account, unlockDelay);
    }

    /// @dev Unlock. Local-only; empty payload. Only from the hard-locked state with no pending unlock; sets the
    ///      effective unlock timestamp from the stored delay.
    function _applyUnlock(address account, bytes calldata payload) private {
        if (payload.length != 0) {
            revert InvalidChangePayload();
        }
        AccountState storage st = _accountState[account];
        uint8 flags = st.flags;
        if (flags & FLAG_LOCKED == 0 || flags & FLAG_UNLOCK_INITIATED != 0) {
            revert NotLocked();
        }
        uint48 unlocksAt = uint48(block.timestamp + uint16(st.lockUnion));
        st.flags = flags | FLAG_UNLOCK_INITIATED;
        st.lockUnion = unlocksAt;
        emit AccountUnlockInitiated(account, unlocksAt);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // VIEW FUNCTIONS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Typehash binding a user signature to its account and chainId.
    /// @dev NOT compliant with EIP-712, to mitigate eth_signTypedData phishing, consistent with the other 8130
    ///      signed-message typehashes. First byte 0x9d: provably not a transaction encoding.
    bytes32 public constant SIGNED_MESSAGE_TYPEHASH =
        keccak256("EIP8130SignedMessage(address account,uint256 chainId,bytes32 hash)");

    /// @notice The chain-scoping channel a signature envelope's leading type byte selects.
    ///
    /// @dev Read from the envelope's leading byte (uint8), not ABI-decoded: Local = 0x01 (block.chainid),
    ///      Multichain = 0x02 (chainId = 0). Append-only. Invalid (0x00) is the reserved "unset" value; unlike the
    ///      ABI-decoded change enums there is no decoder guard, so {validateSignature} rejects Invalid and any
    ///      out-of-range byte with {UnknownSignatureType}.
    ///
    ///      Multichain binds chainId = 0, so the signature is replayable on EVERY chain; there is no strict
    ///      per-chain-list channel. This is intentional and mirrors the applySignedActorChanges all-chains channel.
    ///      A signer who wants single-chain binding uses Local; scoping to an arbitrary subset of chains is a broader
    ///      protocol change (a chainId-list binding across all signed-message typehashes) deliberately left out here.
    enum SignatureType {
        Invalid,
        Local,
        Multichain
    }

    /// @notice The signature envelope's leading type byte is not a recognized {SignatureType} value.
    error UnknownSignatureType(uint8 sigType);

    /// @notice The signature envelope is empty (missing its leading type byte).
    error EmptySignatureEnvelope();

    /// @notice Envelope digest to sign for `hash` to be accepted for `account` on `chainId`.
    /// @dev Pass `block.chainid` for a chain-local signature ({SignatureType.Local}) or `0` for an all-chains signature
    ///      ({SignatureType.Multichain}, mirroring the applySignedActorChanges multichain channel).
    /// @param account Account the signature is bound to.
    /// @param chainId Chain the signature is bound to (0 = all chains).
    /// @param hash Raw message digest.
    /// @return The digest to sign.
    function replaySafeHash(address account, uint256 chainId, bytes32 hash) public pure returns (bytes32) {
        return keccak256(abi.encode(SIGNED_MESSAGE_TYPEHASH, account, chainId, hash));
    }

    /// @notice The digest a signer must sign for `hash` to be accepted for `account` under signature type `sigType`.
    ///
    /// @dev Resolves the {SignatureType} to its bound chainId and returns the {replaySafeHash} digest, so clients can
    ///      build an envelope without hardcoding the chainId semantics: sign this digest, then prepend the type byte —
    ///      `sigType(1) || authenticator(20) || sign(envelopeDigest(sigType, account, hash))`. {validateSignature}
    ///      resolves the same digest, so the two never drift. Reverts {UnknownSignatureType} for Invalid.
    ///
    /// @param sigType Envelope channel: Local (binds block.chainid) or Multichain (binds chainId = 0, all chains).
    /// @param account Account the signature is bound to.
    /// @param hash Raw app digest.
    /// @return The digest to sign.
    function envelopeDigest(SignatureType sigType, address account, bytes32 hash) public view returns (bytes32) {
        if (sigType == SignatureType.Local) return replaySafeHash(account, block.chainid, hash);
        if (sigType == SignatureType.Multichain) return replaySafeHash(account, 0, hash);
        revert UnknownSignatureType(uint8(sigType)); // Invalid (0x00)
    }

    /// @notice Canonical validation of a typed-envelope user signature over an app `hash` for `account`.
    ///
    /// @dev The signature is validated against an envelope digest scoped to the account and chain ({envelopeDigest}),
    ///      binding it to a single account and channel; the keystore's own signed messages (actor changes, import,
    ///      lock) bind context in-struct via their own typehashes instead. Operational gating (which scopes may sign)
    ///      is left to the caller, which reads the returned `scope`.
    ///
    ///      This is a new signature-checking method that supersedes ERC-1271 for 8130 accounts. An 8130 account should
    ///      implement ERC-1271 support on top of it by gating on Scopes.isOperator (see DefaultAccount.isValidSignature).
    ///      Apps are free to use this method directly for finer-grained authorization control for 8130 accounts.
    /// @dev Reverts with EmptySignatureEnvelope when `auth` is empty.
    /// @dev Reverts with UnknownSignatureType when the leading sigType byte is not Local or Multichain.
    /// @dev Reverts with InvalidAuthLength, AuthenticationFailed, AuthenticatorMismatch, ActorExpired,
    ///      DefaultEoaRevoked, or InvalidSignature when the actor cannot be authenticated (via {authenticateActor}).
    ///
    /// @param account The account the signature is validated against.
    /// @param hash The raw app digest; validated against the account/chain-scoped envelope digest.
    /// @param auth sigType(1) || authenticator(20) || authenticator-specific data.
    ///
    /// @return actorId The identifier of the verified actor.
    /// @return scope The scope of the verified actor (0x00 = unrestricted).
    function validateSignature(address account, bytes32 hash, bytes calldata auth)
        external
        view
        returns (bytes32 actorId, uint16 scope)
    {
        if (auth.length == 0) revert EmptySignatureEnvelope();

        uint8 sigTypeByte = uint8(auth[0]);
        if (sigTypeByte > uint8(type(SignatureType).max)) revert UnknownSignatureType(sigTypeByte);

        bytes32 digest = envelopeDigest(SignatureType(sigTypeByte), account, hash);

        (actorId, scope) = authenticateActor(account, digest, auth[1:]);
    }

    /// @notice Authenticates that an account approved `hash` using auth in `authenticator(20) || data` format,
    ///         returning the verified actor's identity and scope so a consumer (e.g. an ERC-4337 account on a
    ///         non-8130 chain) can decide authorization without re-deriving (or re-invoking the authenticator to
    ///         recover) the actorId.
    ///
    /// @dev `actorId` is the resolved actor identifier — the same value an 8130 chain surfaces via the tx-context
    ///      precompile. It lets an off-8130 consumer read `getPolicyManager` / `getPolicyCommitment(account, actorId)`
    ///      (execution-time reads) for a policy-gated actor, reaching parity with the native hot path.
    /// @dev `scope` is the actor's capability set, stored verbatim and never interpreted by this contract —
    ///      protocol-side semantics for bits like Scopes.NONCE live outside this contract. Consumers decide policy
    ///      gating via `scope & Scopes.POLICY`, then resolve the gate target separately via {getPolicyManager}.
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
    function authenticateActor(address account, bytes32 hash, bytes calldata auth)
        public
        view
        returns (bytes32 actorId, uint16 scope)
    {
        if (auth.length < 20) {
            revert InvalidAuthLength();
        }
        return _authenticate(account, hash, address(bytes20(auth[:20])), auth[20:]);
    }

    /// @notice Computes the counterfactual CREATE2 address for an account without deploying it.
    ///
    /// @dev Reverts with EmptyBytecode when `bytecode` is empty.
    /// @dev Reverts with BytecodeTooLarge when `bytecode` exceeds the maximum encodable length.
    /// @dev Applies the same initial-actor validation as {createAccount} (see {_validateInitialActors}), so it never
    ///      returns an address for an actor set a later createAccount would reject. Reverts with NoInitialActors,
    ///      ActorsNotSortedOrDuplicate, InvalidAuthenticator, or InvalidPolicyData.
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

    /// @notice The liveness-gated {ActorConfig} for `actorId` — the all-zero config when the actor is not live
    ///         (unknown, revoked, disabled, or expired). See {_resolveActorConfig}.
    function getActorConfig(address account, bytes32 actorId) external view returns (ActorConfig memory) {
        return _resolveActorConfig(account, actorId);
    }

    /// @notice Returns an actor's config, policy manager, and policy commitment in one read. The manager and
    ///         commitment are non-zero only for a live actor with scope & Scopes.POLICY set; a non-live actor
    ///         returns the empty config and a zero manager/commitment.
    function getActor(address account, bytes32 actorId)
        external
        view
        returns (ActorConfig memory config, address policyManager, bytes32 policyCommitment)
    {
        config = _resolveActorConfig(account, actorId);
        // Gating is by the scope bit, matching {_emitActorAuthorized}; a non-live or ungated actor has a zero gate.
        if (config.authenticator != address(0) && config.scope & Scopes.POLICY != 0) {
            policyManager = _policyManager[actorId][account];
            policyCommitment = _policyCommitment[actorId][account];
        }
    }

    /// @dev The single liveness resolver behind every read surface ({getActorConfig}, {getActor},
    ///      {getPolicyCommitment}, {getPolicyManager}). A populated _actorConfig entry returns verbatim unless expired;
    ///      the k1 self (inline in AccountState) resolves to a native ecrecover owner unless disabled or expired;
    ///      anything unknown/revoked/disabled/expired resolves to the all-zero (empty) config. Centralizing this is
    ///      what makes "expired" read identically to "revoked" on every surface — the invariant that lets a node
    ///      garbage-collect an expired actor's slots without changing anything observable on-chain.
    function _resolveActorConfig(address account, bytes32 actorId) private view returns (ActorConfig memory) {
        // Common path first: the inline k1 self. A clear FLAG_REVOKE_DEFAULT_EOA means the inline self is live, so
        // resolve it from AccountState alone (all-zero = full owner). When the flag is set the inline self is off —
        // either a non-k1 self lives in _actorConfig, or the self was revoked — so fall through to the shared home.
        if (actorId == _selfActorId(account)) {
            AccountState storage st = _accountState[account];
            if (st.flags & FLAG_REVOKE_DEFAULT_EOA == 0) {
                if (_isExpired(st.defaultEOAExpiry)) {
                    return _emptyActorConfig();
                }
                return
                    ActorConfig({
                        authenticator: K1_AUTHENTICATOR, scope: st.defaultEOAScope, expiry: st.defaultEOAExpiry
                    });
            }
        }

        // Explicit actor (or a non-k1 self): the single _actorConfig home. A stored authenticator is K1_AUTHENTICATOR
        // (0x1) or a contract, so `>= K1_AUTHENTICATOR` is the "slot populated" test. An expired entry reports empty.
        ActorConfig memory config = _actorConfig[actorId][account];
        if (config.authenticator >= K1_AUTHENTICATOR) {
            return _isExpired(config.expiry) ? _emptyActorConfig() : config;
        }
        return config;
    }

    /// @dev The all-zero ActorConfig returned for a non-live actor (unknown, disabled, or expired).
    function _emptyActorConfig() private pure returns (ActorConfig memory) {
        return ActorConfig({authenticator: address(0), expiry: 0, scope: 0});
    }

    /// @notice The actor's policy commitment, or 0 when the actor is not live. Gating is by liveness (see
    ///         {_resolveActorConfig}), not by a non-zero commitment, and costs one extra SLOAD over the raw slot.
    function getPolicyCommitment(address account, bytes32 actorId) external view returns (bytes32) {
        if (_resolveActorConfig(account, actorId).authenticator == address(0)) {
            return bytes32(0);
        }
        return _policyCommitment[actorId][account];
    }

    /// @notice The actor's policy manager, or 0 when the actor is not live. See {_resolveActorConfig}.
    function getPolicyManager(address account, bytes32 actorId) external view returns (address) {
        if (_resolveActorConfig(account, actorId).authenticator == address(0)) {
            return address(0);
        }
        return _policyManager[actorId][account];
    }

    /// @notice Returns the account's replay counters: the multichain counter and the local channel's epoch and
    ///         sequence.
    ///
    /// @param account The account to read.
    ///
    /// @return The account's ChangeSequences (multichain counter, local epoch, local sequence).
    function getChangeSequences(address account) external view returns (ChangeSequences memory) {
        AccountState storage st = _accountState[account];
        return ChangeSequences({
            multichain: st.multichainSequence, localEpoch: st.localEpoch, localSequence: st.localSequence
        });
    }

    /// @notice Returns whether the account is currently locked (configuration frozen).
    ///
    /// @param account The account to check.
    ///
    /// @return True if the account is locked at the current block timestamp.
    function isLocked(address account) external view returns (bool) {
        return _isLocked(account);
    }

    /// @notice Whether the account was keystore-established (createAccount or importAccount) rather than backed by a
    ///         proven address key. See {FLAG_CONTRACT_ESTABLISHED}.
    ///
    /// @param account The account to check.
    ///
    /// @return True when the account was keystore-established and must not be treated as a key-backed EOA.
    function isContractEstablished(address account) external view returns (bool) {
        return _accountState[account].flags & FLAG_CONTRACT_ESTABLISHED != 0;
    }

    /// @notice Returns the account's full lock status.
    ///
    /// @param account The account to read.
    ///
    /// @return locked True if the account is locked at the current block timestamp.
    /// @return hasInitiatedUnlock True if an unlock has been initiated but not yet elapsed.
    /// @return unlocksAt The timestamp at which the account unlocks (type(uint48).max while hard-locked).
    /// @return unlockDelay The configured unlock delay in seconds.
    function getLockStatus(address account)
        external
        view
        returns (bool locked, bool hasInitiatedUnlock, uint48 unlocksAt, uint16 unlockDelay)
    {
        AccountState storage st = _accountState[account];
        uint8 flags = st.flags;
        if (flags & FLAG_LOCKED == 0) {
            // Unlocked: no lock bits set.
            return (false, false, 0, 0);
        }
        if (flags & FLAG_UNLOCK_INITIATED == 0) {
            // Hard-locked: lockUnion holds the configured delay; synthesize the max sentinel for unlocksAt.
            return (true, false, type(uint48).max, uint16(st.lockUnion));
        }
        // Unlock initiated: lockUnion holds the effective unlock timestamp. Once it has elapsed the account is
        // effectively unlocked, so report the clean unlocked state instead of surfacing the stale timestamp. Storage is
        // not canonicalized (lock reads are non-clearing); a later Lock overwrites the residue.
        uint48 unlockTime = st.lockUnion;
        if (block.timestamp >= unlockTime) {
            return (false, false, 0, 0);
        }
        return (true, true, unlockTime, 0);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // INTERNAL FUNCTIONS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @dev Returns whether the account's configuration is currently frozen without mutating storage.
    /// @dev An elapsed unlock reads as unlocked; a later {_applyLock} overwrites the stale lock fields.
    function _isLocked(address account) private view returns (bool) {
        AccountState storage st = _accountState[account];
        uint8 flags = st.flags;
        if (flags & FLAG_LOCKED == 0) {
            return false;
        }
        if (flags & FLAG_UNLOCK_INITIATED == 0) {
            return true;
        }
        return block.timestamp < st.lockUnion; // pending unlock: frozen until the timestamp elapses
    }

    /// @dev True after bootstrap or any successful signed change. The epoch and multichain counter keep initialization
    ///      observable when the current local sequence is zero.
    function _isInitialized(address account) private view returns (bool) {
        AccountState storage st = _accountState[account];
        return st.localSequence != 0 || st.localEpoch != 0 || st.multichainSequence != 0;
    }

    // ----------------------------------------------------------------------------------------------------------------
    // ACTOR CHANGES
    // ----------------------------------------------------------------------------------------------------------------

    /// @dev Registers the bootstrap actor set shared by createAccount and importAccount: requires a non-empty,
    ///      strictly ascending-by-actorId list (rejecting unsorted or duplicate entries) and authorizes each entry
    ///      with its declared scope and (when scope & Scopes.POLICY is set) policyData. Expiry is always 0 for
    ///      initial actors; scoped-with-expiry keys are added later via applySignedAccountChanges. Reverts with
    ///      NoInitialActors or ActorsNotSortedOrDuplicate.
    function _initializeAccount(address account, InitialActor[] calldata initialActors)
        private
        nonZeroAccount(account)
    {
        // Must have at least one initial actor
        if (initialActors.length == 0) {
            revert NoInitialActors();
        }

        bytes32 previousActorId;
        for (uint256 i; i < initialActors.length; i++) {
            // Enforce sorting with relative comparison of sequential actor ids
            if (initialActors[i].actorId <= previousActorId) {
                revert ActorsNotSortedOrDuplicate();
            }
            previousActorId = initialActors[i].actorId;

            // Initial actors carry scope verbatim (0x00 = unrestricted admin) and never an expiry. When
            // scope & Scopes.POLICY is set, policyData is validated by the same frozen rule as authorizeActor
            // (52 bytes). Authorizing the self-actorId as k1 writes its scope into the inline default-EOA fields.
            ActorConfig memory config =
                ActorConfig({authenticator: initialActors[i].authenticator, scope: initialActors[i].scope, expiry: 0});
            _authorizeActor(account, initialActors[i].actorId, config, initialActors[i].policyData);
        }
    }

    /// @dev Authorizes (upserts) `actorId` with `config` and optional `policyData`, emitting ActorAuthorized. Rejects
    ///      a sub-K1 authenticator. The self-actorId is routed by authenticator type (a k1 self inline in
    ///      AccountState, a non-k1 self in _actorConfig) and the two are kept mutually exclusive; every other actor
    ///      lives in _actorConfig. Reverts with InvalidActorId, InvalidAuthenticator, or InvalidPolicyData.
    function _authorizeActor(address account, bytes32 actorId, ActorConfig memory config, bytes memory policyData)
        private
        nonZeroAccount(account)
    {
        // Zero is reserved for "no actor." Bootstrap also rejects it through the ascending-order check.
        if (actorId == bytes32(0)) {
            revert InvalidActorId();
        }

        // Only reject the zero authenticator (the empty-slot sentinel). A non-zero authenticator with no code is
        // accepted deliberately: authenticators may be counterfactual (deployed later) and some are intentionally
        // codeless sentinels (e.g. EXTERNAL_POLICY_AUTHENTICATOR). A bad authenticator simply fails fail-closed at
        // authentication time, mirroring the reference PolicyManager's treatment of a zero-commitment policy actor.
        if (config.authenticator < K1_AUTHENTICATOR) {
            revert InvalidAuthenticator();
        }

        // Slice the signed policy by scope & Scopes.POLICY. The commitment is opaque to the protocol. This contract
        // does not reject scope combinations (e.g. Scopes.POLICY | Scopes.SELF_PAYER) — any use-time exclusivity between
        // Scopes.POLICY and the account's other capabilities is protocol-side, not enforced here.
        (address manager, bytes32 commitment) = _slicePolicy(config.scope, policyData);

        if (actorId == _selfActorId(account)) {
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

    /// @dev Writes the current policy values and clears stale values when an actor becomes ungated.
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
    ///      (authenticator(20) || expiry(6) || scope(2) || reserved(4 zero bytes)); the policy gate
    ///      (manager(20) || commitment(32), 52 bytes) is appended only when scope & Scopes.POLICY != 0.
    function _emitActorAuthorized(
        address account,
        bytes32 actorId,
        ActorConfig memory config,
        address manager,
        bytes32 commitment
    ) private {
        bytes memory actorData = (config.scope & Scopes.POLICY != 0)
            ? abi.encodePacked(config.authenticator, config.expiry, config.scope, bytes4(0), manager, commitment)
            : abi.encodePacked(config.authenticator, config.expiry, config.scope, bytes4(0));
        emit ActorAuthorized(account, actorId, actorData);
    }

    /// @dev Validates `policyData` against `scope & Scopes.POLICY` and returns (manager, commitment).
    ///      Unset: empty data -> (0, 0). Set: exactly 52 bytes manager[20] || commitment[32] -> (manager,
    ///      commitment), written verbatim. Neither field need be non-zero: a zero commitment is a valid "no
    ///      params" and a zero manager gates the actor to address(0). Only a length mismatch reverts. The protocol
    ///      does not interpret the commitment value; self-enforcement is expressed as manager == account.
    function _slicePolicy(uint16 scope, bytes memory policyData)
        private
        pure
        returns (address manager, bytes32 commitment)
    {
        if (scope & Scopes.POLICY == 0) {
            if (policyData.length != 0) {
                revert InvalidPolicyData();
            }
            return (address(0), bytes32(0));
        }
        if (policyData.length != 52) {
            revert InvalidPolicyData();
        }
        // The signed format is tightly packed to 52 bytes rather than ABI encoded to 64 bytes, so high-level
        // abi.decode cannot parse it. This assembly performs the two fixed-offset reads without copying/repacking.
        assembly ("memory-safe") {
            manager := shr(96, mload(add(policyData, 0x20)))
            commitment := mload(add(policyData, 0x34))
        }
    }

    /// @dev Checks authorization presence without expiry so expired actors can still be explicitly revoked.
    function _isAuthorized(address account, bytes32 actorId) private view returns (bool) {
        // A populated entry represents any non-self actor or a non-k1 self authenticator.
        if (_actorConfig[actorId][account].authenticator >= K1_AUTHENTICATOR) {
            return true;
        }
        // No _actorConfig entry: the self-actorId's k1 key lives inline in AccountState, live unless the flag is set.
        if (actorId == _selfActorId(account)) {
            return !_isDefaultEoaRevoked(account);
        }
        return false;
    }

    /// @dev The shared, read-only static gate on a bootstrap actor set, applying the exact rules that
    ///      _initializeAccount/_authorizeActor enforce at write time: non-empty, strictly ascending by actorId (which
    ///      also rejects duplicates and the zero actorId), a K1-or-above authenticator, and a policyData length that
    ///      matches scope & Scopes.POLICY (52 bytes when set, empty when clear). Running it inside {_prepareDeployment}
    ///      gives {computeAddress} the same validity as {createAccount}, so a predicted address is never returned for
    ///      an actor set a later createAccount would reject (which would otherwise let a client prefund and strand
    ///      funds at an undeployable address). Reverts with NoInitialActors, ActorsNotSortedOrDuplicate,
    ///      InvalidAuthenticator, or InvalidPolicyData.
    function _validateInitialActors(InitialActor[] calldata initialActors) private pure {
        if (initialActors.length == 0) {
            revert NoInitialActors();
        }

        bytes32 previousActorId;
        for (uint256 i; i < initialActors.length; i++) {
            InitialActor calldata actor = initialActors[i];

            // Strictly ascending: rejects unsorted, duplicate, and the zero actorId (previousActorId starts at 0).
            if (actor.actorId <= previousActorId) {
                revert ActorsNotSortedOrDuplicate();
            }
            if (actor.authenticator < K1_AUTHENTICATOR) {
                revert InvalidAuthenticator();
            }
            // Same frozen rule as _slicePolicy: 52 bytes when POLICY-scoped, empty otherwise.
            if (actor.policyData.length != (actor.scope & Scopes.POLICY != 0 ? 52 : 0)) {
                revert InvalidPolicyData();
            }

            previousActorId = actor.actorId;
        }
    }

    /// @dev Derives the CREATE2 inputs once for both {createAccount} and {computeAddress}: the effective salt, the
    ///      deployment code, and the resulting counterfactual address. Sharing this avoids rebuilding and re-hashing
    ///      the (up to ~24KB) deployment code — and recomputing the actors commitment — twice per creation. The actor
    ///      set is validated up front so a prediction is never returned for a set createAccount would later reject.
    function _prepareDeployment(bytes32 userSalt, bytes calldata bytecode, InitialActor[] calldata initialActors)
        private
        view
        returns (address account, bytes32 effectiveSalt, bytes memory deploymentCode)
    {
        _validateInitialActors(initialActors);

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
        private
        pure
        returns (bytes32)
    {
        return keccak256(abi.encodePacked(userSalt, _computeActorsCommitment(initialActors)));
    }

    /// @dev Commitment over the initial actor set, using the same hash-the-leaves-then-hash-the-list scheme as the
    ///      signed digests ({_computeImportDigest}, {_changesDigest}). Each actor hashes to a fixed-width leaf over
    ///      actorId (32) || authenticator (20) || scope (2) || policyData, where policyData is empty (POLICY unset)
    ///      or exactly 52 bytes (POLICY set); expiry does not participate (always 0 for initial actors). The
    ///      commitment is keccak256 over the tightly packed 32-byte leaves, so it is unambiguous by construction and
    ///      linear in the actor count. Protocol clients reproduce it as leaf_i = keccak256(actorId || authenticator ||
    ///      scope || policyData); commitment = keccak256(leaf_0 || ... || leaf_{n-1}).
    function _computeActorsCommitment(InitialActor[] calldata initialActors) private pure returns (bytes32) {
        bytes32[] memory leaves = new bytes32[](initialActors.length);
        for (uint256 i; i < initialActors.length; i++) {
            leaves[i] = keccak256(
                abi.encodePacked(
                    initialActors[i].actorId,
                    initialActors[i].authenticator,
                    initialActors[i].scope,
                    initialActors[i].policyData
                )
            );
        }
        return keccak256(abi.encodePacked(leaves));
    }

    /// @dev Typed digest for the importAccount ERC-1271 signature (a signed message), so signers can reproduce it
    ///      with standard EIP-712-style struct hashing. `accountId` is the account's actorId
    ///      (`ActorId.fromAddress(account)`) and the digest is bound to `chainId` (0 = multichain) so its replay
    ///      domain matches applySignedAccountChanges.
    function _computeImportDigest(address account, uint256 chainId, InitialActor[] calldata initialActors)
        private
        pure
        returns (bytes32)
    {
        bytes32[] memory actorHashes = new bytes32[](initialActors.length);
        for (uint256 i; i < initialActors.length; i++) {
            // Expiry is forced to 0 at import — an actor-provided expiry is never accepted here. policyData is
            // hashed via keccak256 into the Actor struct hash. The typehash structure matches the importAccount
            // signature payload in EIP-8130.
            bytes32 configHash = keccak256(
                abi.encode(ACTOR_CONFIG_TYPEHASH, initialActors[i].authenticator, uint48(0), initialActors[i].scope)
            );
            actorHashes[i] = keccak256(
                abi.encode(ACTOR_TYPEHASH, initialActors[i].actorId, configHash, keccak256(initialActors[i].policyData))
            );
        }

        return keccak256(
            abi.encode(
                ACTOR_INITIALIZATION_TYPEHASH, _selfActorId(account), chainId, keccak256(abi.encodePacked(actorHashes))
            )
        );
    }

    /// @dev Computes the digest signed over an applySignedAccountChanges batch: each AccountChange is hashed
    ///      structurally (its variable-length `payload` pre-hashed to a fixed-width layout) and the batch is bound to
    ///      `account`, the channel's replay `chainId` (0 for Multichain, block.chainid for Local), and the raw
    ///      `sequence` word via SIGNED_ACCOUNT_CHANGES_TYPEHASH. The entire digest scheme is confined to this function
    ///      so {applySignedAccountChanges} depends only on its output.
    function _changesDigest(
        address account,
        AccountChangeChannel channel,
        uint64 sequence,
        AccountChange[] calldata changes
    ) private view returns (bytes32) {
        uint256 chainId = channel == AccountChangeChannel.Multichain ? 0 : block.chainid;
        bytes32[] memory changeHashes = new bytes32[](changes.length);
        for (uint256 i; i < changes.length; i++) {
            changeHashes[i] = keccak256(
                abi.encode(ACCOUNT_CHANGE_TYPEHASH, uint8(changes[i].changeType), keccak256(changes[i].payload))
            );
        }
        return keccak256(
            abi.encode(
                SIGNED_ACCOUNT_CHANGES_TYPEHASH, account, chainId, sequence, keccak256(abi.encodePacked(changeHashes))
            )
        );
    }

    // ----------------------------------------------------------------------------------------------------------------
    // AUTHENTICATION
    // ----------------------------------------------------------------------------------------------------------------

    /// @dev Resolves and authenticates the actor behind `authenticator`/`data`, returning its
    ///      (actorId, scope). Routes the K1 sentinel to _authenticateK1; otherwise calls the
    ///      IAuthenticator and requires the resolved actorId to carry a matching, unexpired _actorConfig entry.
    ///      Reverts with AuthenticationFailed, AuthenticatorMismatch, or ActorExpired.
    function _authenticate(address account, bytes32 hash, address authenticator, bytes calldata data)
        private
        view
        returns (bytes32, uint16)
    {
        if (authenticator == K1_AUTHENTICATOR) {
            return _authenticateK1(account, hash, data);
        }

        bytes32 actorId = IAuthenticator(authenticator).authenticate(hash, data);
        if (actorId == bytes32(0)) {
            revert AuthenticationFailed();
        }

        return (actorId, _resolveExplicitActor(account, actorId, authenticator));
    }

    /// @dev Resolves an explicit _actorConfig-homed actor: requires a matching authenticator and an unexpired entry,
    ///      returning its scope. Shared by the non-k1 (_authenticate) and k1 other-actor (_authenticateK1) paths.
    ///      Reverts with AuthenticatorMismatch or ActorExpired.
    function _resolveExplicitActor(address account, bytes32 actorId, address expectedAuthenticator)
        private
        view
        returns (uint16 scope)
    {
        ActorConfig memory config = _actorConfig[actorId][account];
        if (config.authenticator != expectedAuthenticator) {
            revert AuthenticatorMismatch();
        }
        // Expiry is read from the same slot; an expired actor fails authentication. 0 = no expiry.
        if (_isExpired(config.expiry)) {
            revert ActorExpired();
        }
        scope = config.scope;
    }

    /// @dev The single secp256k1 ("K1") path. Recovers the signer (EIP-2 enforced), then resolves the actor:
    ///        - signer == account -> the inline self config in AccountState (one SLOAD): the flag gates the whole
    ///          key (set => revert), and when live the scope/expiry come from the inline fields (all-zero = full
    ///          owner; non-zero = a scoped self). A non-k1 self is unreachable here by construction (it requires
    ///          its own authenticator), and mutual exclusion keeps the flag set whenever one is live.
    ///        - otherwise the signer's actorId must carry an explicit K1 config in _actorConfig (any other k1 actor).
    ///      Both the common self and other-actor paths cost a single SLOAD.
    function _authenticateK1(address account, bytes32 hash, bytes calldata data)
        private
        view
        returns (bytes32, uint16)
    {
        address recovered = _recoverSigner(hash, data);
        if (recovered == address(0)) {
            revert InvalidSignature();
        }

        if (recovered == account) {
            // Inline self: a single SLOAD resolves the whole key. The flag disables it entirely; otherwise the
            // inline scope/expiry govern (all-zero = full owner).
            AccountState storage st = _accountState[account];
            if (st.flags & FLAG_REVOKE_DEFAULT_EOA != 0) {
                revert DefaultEoaRevoked();
            }
            if (_isExpired(st.defaultEOAExpiry)) {
                revert ActorExpired();
            }
            return (_selfActorId(account), st.defaultEOAScope);
        }

        bytes32 actorId = ActorId.fromAddress(recovered);
        return (actorId, _resolveExplicitActor(account, actorId, K1_AUTHENTICATOR));
    }

    /// @dev True if the account's default (implicit) EOA has been revoked via the AccountState flag.
    function _isDefaultEoaRevoked(address account) private view returns (bool) {
        return _accountState[account].flags & FLAG_REVOKE_DEFAULT_EOA != 0;
    }

    /// @dev The account's implicit self-actorId (`ActorId.fromAddress`), matching the normative self derivation.
    ///      Non-zero for any valid account.
    function _selfActorId(address account) private pure returns (bytes32) {
        return ActorId.fromAddress(account);
    }

    /// @dev True when `expiry` is set (non-zero) and has passed. A zero expiry means no expiry.
    function _isExpired(uint48 expiry) private view returns (bool) {
        return expiry != 0 && block.timestamp > expiry;
    }

    /// @dev Recovers the ECDSA signer from a 65-byte r‖s‖v signature over `hash`, enforcing EIP-2 (low-s only,
    ///      canonical v of 27 or 28). Reverts with InvalidSignature on a bad length or non-canonical encoding; may
    ///      return address(0) if ecrecover fails, which callers treat as a failed authentication.
    function _recoverSigner(bytes32 hash, bytes calldata data) private pure returns (address recovered) {
        if (data.length != 65) {
            revert InvalidSignature();
        }
        bytes32 r = bytes32(data[:32]);
        bytes32 s = bytes32(data[32:64]);
        uint8 v = uint8(data[64]);
        // EIP-2: reject the malleable high-s half of each signature and non-canonical v to enforce a single
        // canonical encoding per signature.
        if (uint256(s) > SECP256K1_HALF_ORDER) {
            revert InvalidSignature();
        }
        if (v != 27 && v != 28) {
            revert InvalidSignature();
        }
        return ecrecover(hash, v, r, s);
    }

    // ----------------------------------------------------------------------------------------------------------------
    // ACCOUNT CREATION
    // ----------------------------------------------------------------------------------------------------------------

    /// @dev Constructs a 14-byte EVM loader followed by `bytecode`. Reverts {EmptyBytecode} when `bytecode` is empty.
    ///      The loader copies the trailing `bytecode` into memory and returns it as the deployed runtime:
    ///        PUSH2 n; PUSH1 0x0e; PUSH1 0x00; CODECOPY   // copy n bytes from code offset 14 to mem 0
    ///        PUSH2 n; PUSH1 0x00; RETURN                 // return mem[0..n]
    function _buildDeploymentCode(bytes calldata bytecode) private pure returns (bytes memory) {
        uint256 n = bytecode.length;
        if (n == 0) {
            revert EmptyBytecode();
        }
        if (n > 0xFFFF) {
            revert BytecodeTooLarge();
        }
        return abi.encodePacked(
            bytes1(0x61), bytes2(uint16(n)), hex"600e600039", bytes1(0x61), bytes2(uint16(n)), hex"6000f3", bytecode
        );
    }
}
