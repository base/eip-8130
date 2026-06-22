// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IAccountConfiguration} from "./interfaces/IAccountConfiguration.sol";
import {IAuthenticator} from "./interfaces/IAuthenticator.sol";

/// @notice Account Configuration system contract for EIP-8130.
///         Manages actor authorization, account creation, change sequencing, and account lock.
contract AccountConfiguration is IAccountConfiguration {
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // STRUCTS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

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

    bytes4 constant ERC1271_SELECTOR = bytes4(keccak256("isValidSignature(bytes32,bytes)"));

    /// @dev Typehash for the importAccount ERC-1271 signature, NOT compliant with EIP-712 to mitigate phishing
    ///      attacks. Initial actors are hashed structurally via ACTOR_TYPEHASH / ACTORCONFIG_TYPEHASH below.
    bytes32 public constant ACTOR_INITIALIZATION_TYPEHASH = keccak256(
        "ActorInitialization(bytes32 salt,Actor[] initialActors)Actor(bytes32 actorId,ActorConfig config,bytes policyData)ActorConfig(address authenticator,uint8 scope,uint48 expiry,uint8 policyType)"
    );

    /// @dev Per-actor typehash used to structurally hash each Actor within an ActorInitialization import digest.
    bytes32 public constant ACTOR_TYPEHASH = keccak256(
        "Actor(bytes32 actorId,ActorConfig config,bytes policyData)ActorConfig(address authenticator,uint8 scope,uint48 expiry,uint8 policyType)"
    );

    /// @dev Per-config typehash used to structurally hash an Actor's ActorConfig within an import digest.
    bytes32 public constant ACTORCONFIG_TYPEHASH =
        keccak256("ActorConfig(address authenticator,uint8 scope,uint48 expiry,uint8 policyType)");

    /// @dev Typehash for signed actor changes, NOT compliant with EIP-712 to mitigate phishing attacks.
    bytes32 public constant SIGNED_ACTOR_CHANGES_TYPEHASH = keccak256(
        "SignedActorChanges(address account,uint64 chainId,uint64 sequence,ActorChange[] actorChanges)"
        "ActorChange(uint8 changeType,bytes32 actorId,bytes data)"
    );

    /// @dev Per-change typehash used to structurally hash each ActorChange within a SignedActorChanges batch.
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

    /// @notice Actor can change account actors
    uint8 public constant SCOPE_CHANGE_ACTORS = 0x08;

    /// @dev Authenticator namespace: 1 = the canonical secp256k1 ("K1") verifier (native ecrecover); 2..max = custom
    ///      IAuthenticator contracts. address(0) is reserved as the "no actor configured" storage sentinel and is
    ///      never a valid authenticator selector.
    /// @notice The single secp256k1 authenticator. The default EOA and every k1 actor share this one identity; the
    ///         actor config alone distinguishes a full-owner EOA from a scoped key. Signed with a K1_AUTHENTICATOR
    ///         (20) || r‖s‖v auth blob.
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

    modifier onlyUnlocked(address account) {
        if (_isLockedSideEffects(account)) revert();
        _;
    }

    modifier nonZero(address account) {
        require(account != address(0));
        _;
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // FUNCTIONS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Deploy a new account with its initial actors. Initial actors bootstrap account ownership and are always
    ///         registered as unrestricted owners (scope = 0x00, no expiry, no policy); scoped keys and session-key
    ///         policies are added afterwards via applySignedActorChanges. Lock state is initialized to safe defaults.
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
        require(_accountState[account].localSequence == 0 && _accountState[account].multichainSequence == 0);

        // Mark the account initialized: localSequence doubles as the initialized flag, so setting it to 1 blocks
        // importAccount (which requires localSequence == 0) from running against an already-created account.
        // Created accounts have contract code at a CREATE2 address, so the default EOA path (recovered == account)
        // is unreachable; disable it by default so the account is canonically ECDSA-owner-free (quantum-safe by
        // default). This folds into the same slot write as localSequence, costing no extra SSTORE. Set *before*
        // initializing actors so a self-actorId k1 initial actor can re-enable the inline self (parity with import).
        _accountState[account].localSequence = 1;
        _accountState[account].flags = FLAG_REVOKE_DEFAULT_EOA;

        _initializeAccount(account, initialActors);

        // Create account code at the CREATE2 address derived from the packed actors commitment.
        bytes memory deploymentCode = _buildDeploymentCode(bytecode);
        bytes32 effectiveSalt = _computeEffectiveSalt(userSalt, initialActors);
        assembly {
            pop(create2(0, add(deploymentCode, 0x20), mload(deploymentCode), effectiveSalt))
        }
        emit AccountCreated(account, userSalt, keccak256(bytecode));
    }

    /// @notice Import an existing account to AccountConfiguration management.
    /// @dev Verifies via ERC-1271. Accounts must have bytecode.
    /// @dev Custom hash used to partially mitigate phishing attacks on eth_signTypedData.
    function importAccount(address account, InitialActor[] calldata initialActors, bytes calldata signature)
        external
        onlyUnlocked(account)
    {
        // Import is a one-time bootstrap for accounts with no 8130 state yet
        require(_accountState[account].localSequence == 0 && _accountState[account].multichainSequence == 0);
        _accountState[account].localSequence = 1;

        bytes32 digest = _computeImportDigest(account, initialActors);
        (bool success, bytes memory result) =
            account.staticcall(abi.encodeWithSelector(ERC1271_SELECTOR, digest, signature));
        require(success && result.length == 32 && abi.decode(result, (bytes4)) == ERC1271_SELECTOR);

        // Disable the implicit default-EOA path (parity with createAccount). Set *after* the ERC-1271 check: for an
        // EIP-7702 delegated EOA its own k1 signature (the implicit full owner) is the only authenticator available
        // at import time, so it must stay live for that check. An owner who wants to keep using the key can include
        // the self-actorId as an explicit k1 actor in initialActors (still a full owner, now via its config), or
        // re-enable it later. Folds into the same slot as localSequence.
        _accountState[account].flags = FLAG_REVOKE_DEFAULT_EOA;

        _initializeAccount(account, initialActors);
        emit AccountImported(account);
    }

    /// @notice Apply actor changes (actor management only).
    ///         Direct authentication via authenticator + actor_config, isValidSignature fallback for migration.
    function applySignedActorChanges(
        address account,
        uint64 chainId,
        ActorChange[] calldata actorChanges,
        bytes calldata auth
    ) external onlyUnlocked(account) {
        require(chainId == 0 || chainId == block.chainid);

        // Increment the corresponding sequence
        uint64 sequence =
            chainId == 0 ? _accountState[account].multichainSequence++ : _accountState[account].localSequence++;

        // Compute digest and authenticate
        bytes32 digest = _computeSignedActorChangesDigest(account, chainId, sequence, actorChanges);
        (uint8 scope,,) = authenticateActor(account, digest, auth);

        // Require actor has scope to change actors (scope == 0 means unrestricted)
        require(scope == 0 || scope & SCOPE_CHANGE_ACTORS != 0);

        // Apply actorChanges
        for (uint256 i; i < actorChanges.length; i++) {
            if (actorChanges[i].changeType == AUTHORIZE_ACTOR) {
                (ActorConfig memory newActorConfig, bytes memory policyData) =
                    abi.decode(actorChanges[i].data, (ActorConfig, bytes));
                _authorizeActor(account, actorChanges[i].actorId, newActorConfig, policyData);
            } else if (actorChanges[i].changeType == REVOKE_ACTOR) {
                _revokeActor(account, actorChanges[i].actorId);
            } else {
                revert();
            }
        }
    }

    // ----------------------------------------------------------------------------------------------------------------
    // ACCOUNT LOCKS
    // ----------------------------------------------------------------------------------------------------------------

    /// @notice Lock the account to freeze actor configuration.
    /// @param unlockDelay The delay in seconds before the account can be unlocked (capped at ~18 hours).
    function lock(uint16 unlockDelay) external onlyUnlocked(msg.sender) {
        // Require non-zero unlock delay
        require(unlockDelay > 0);

        AccountState storage config = _accountState[msg.sender];

        config.unlocksAt = type(uint40).max;
        config.unlockDelay = unlockDelay;
        emit AccountLocked(msg.sender, unlockDelay);
    }

    /// @notice Initiate unlock of the account after delay has passed.
    function initiateUnlock() external {
        AccountState storage config = _accountState[msg.sender];

        // Require account is locked and unlock has not been initiated
        require(config.unlocksAt == type(uint40).max);

        config.unlocksAt = uint40(block.timestamp + config.unlockDelay);
        config.unlockDelay = 0;
        emit AccountUnlockInitiated(msg.sender, config.unlocksAt);
    }

    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡
    // VIEW FUNCTIONS
    // ≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡≡

    /// @notice Authenticate an account bytes signature in authenticator(20) || data format.
    /// @dev ERC-1271-style boolean check: returns false on any failure (invalid signature, unknown/revoked actor,
    ///      actorId not bound to the auth authenticator, or an actor lacking SIGNATURE scope) rather than reverting.
    ///      authenticateActor reverts on authentication failure, so it is called externally and the revert is caught.
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

    /// @notice Authenticate an account approved a hash using auth in authenticator(20) || data format, returning
    ///         the verified actor's authorization surface so a consumer (e.g. an ERC-4337 account) can make a
    ///         full authorization decision from a single call without re-deriving the actorId.
    /// @dev Authorization is scope + policy, not scope alone. `scope` is the actor's capability set; `policyType`
    ///      and `policyTarget` describe its policy gate. `policyType` is the per-actor policy sub-type byte —
    ///      currently `0x00` (none) or non-zero (gated); its specific non-zero value is reserved for future,
    ///      manager-defined semantics and is returned here so the return shape need not change when that lands.
    ///      `policyTarget` is the resolved policy *manager* (never the signed commitment, which stays an
    ///      execution-time read via getPolicy), or address(0) when ungated.
    /// @return scope The scope of the verified actor (0x00 = unrestricted).
    /// @return policyType The actor's policy sub-type byte (0x00 = none).
    /// @return policyTarget The actor's policy gate target, or address(0) if ungated.
    function authenticateActor(address account, bytes32 hash, bytes calldata auth)
        public
        view
        returns (uint8 scope, uint8 policyType, address policyTarget)
    {
        require(auth.length >= 20);
        return _authenticate(account, hash, address(bytes20(auth[:20])), auth[20:]);
    }

    /// @notice Compute the counterfactual address for an account.
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

    function isActor(address account, bytes32 actorId) public view returns (bool) {
        // A populated _actorConfig entry is always live: any non-self actor, or a non-k1 self authenticator.
        if (_actorConfig[actorId][account].authenticator >= K1_AUTHENTICATOR) return true;
        // No _actorConfig entry: the self-actorId's k1 key lives inline in AccountState, live unless the flag is set.
        if (actorId == bytes32(bytes20(account))) return !_isDefaultEoaRevoked(account);
        return false;
    }

    /// @dev With a populated _actorConfig entry, returns it verbatim (any non-self actor, or a non-k1 self). For the
    ///      self-actorId without such an entry, the k1 self lives inline in AccountState: a live one (flag unset)
    ///      reports as a native ecrecover owner carrying its inline scope/expiry/policy (all-zero = full owner); a
    ///      disabled one — or any unknown actor — reports as the all-zero (empty) config. This keeps live-vs-disabled
    ///      unambiguous without a sentinel.
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

    /// @notice Resolves an actor's policy sub-type, gate target, and signed commitment.
    /// @dev Convenience aggregator for off-chain consumers. Enforcement is at execution: this resolves the actor's
    ///      policy sub-type, where a policy-bearing actor may call, and the commitment a target validates presented
    ///      parameters against. 0x00 -> (0, 0, 0); non-zero -> (policyType, manager, commitment). The policy
    ///      manager/commitment are keyed by actorId, so the inline k1 self and a non-k1 self share that keyspace;
    ///      mutual exclusion guarantees at most one is live, so the active gate is read by actorId.
    ///      On-chain consumers (notably the policy manager validating a dispatched 8130 tx) should prefer the
    ///      single-SLOAD `getPolicyCommitment` / `getPolicyManager` accessors.
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

    /// @notice Resolves an actor's signed policy commitment, or bytes32(0) if ungated / no actor.
    /// @dev Single SLOAD. Intended for a policy manager's per-tx validation read on the protocol-dispatched
    ///      8130 tx path: the manager already knows its own address and policy sub-type, so the commitment is
    ///      the only state it needs from this contract to validate. The invariant maintained by
    ///      _authorizeActor / _revokeActor is that this slot is non-zero iff the actor has a non-zero
    ///      policyType, across both the inline-k1 self and the _actorConfig homes (manager/commitment share a
    ///      single keyspace keyed by actorId), so a zero return unambiguously means "no policy / no actor".
    function getPolicyCommitment(address account, bytes32 actorId) external view returns (bytes32) {
        return _policyCommitment[actorId][account];
    }

    /// @notice Resolves an actor's policy gate target (manager), or address(0) if ungated / no actor.
    /// @dev Single SLOAD. Same invariant as `getPolicyCommitment`.
    function getPolicyManager(address account, bytes32 actorId) external view returns (address) {
        return _policyManager[actorId][account];
    }

    function getChangeSequences(address account) external view returns (ChangeSequences memory) {
        AccountState storage state = _accountState[account];
        return ChangeSequences({multichain: state.multichainSequence, local: state.localSequence});
    }

    function isLocked(address account) external view returns (bool) {
        return block.timestamp < _accountState[account].unlocksAt;
    }

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

    /// @notice Returns true if the account is locked and clears storage if unlocked
    /// @dev Side effects to clear locked state
    function _isLockedSideEffects(address account) internal returns (bool locked) {
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

    function _initializeAccount(address account, InitialActor[] calldata initialActors) internal nonZero(account) {
        // Must have at least one initial actor
        require(initialActors.length > 0);

        bytes32 previousActorId;
        for (uint256 i; i < initialActors.length; i++) {
            // Enforce sorting with relative comparison of sequential actor ids
            require(initialActors[i].actorId > previousActorId);
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

    function _authorizeActor(address account, bytes32 actorId, ActorConfig memory config, bytes memory policyData)
        internal
        nonZero(account)
    {
        require(config.authenticator >= K1_AUTHENTICATOR);

        // A policy-bearing actor must be scope-restricted and may not hold CONFIG scope: the policy gate only
        // covers SENDER-context calls, so a CONFIG-scoped (or unrestricted) key could authorize new, unrestricted
        // actors and escape its policy entirely. Applies to every home (inline self, non-k1 self, any other actor).
        if (config.policyType != POLICY_NONE) {
            require(config.scope != 0 && config.scope & SCOPE_CHANGE_ACTORS == 0);
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

            emit ActorAuthorized(account, actorId, config, manager, commitment);
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

        emit ActorAuthorized(account, actorId, config, manager, commitment);
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
            require(policyData.length == 0);
        } else {
            require(policyData.length == 52);
            assembly ("memory-safe") {
                manager := shr(96, mload(add(policyData, 0x20)))
                commitment := mload(add(policyData, 0x34))
            }
            require(manager != address(0) && commitment != bytes32(0));
        }
    }

    function _revokeActor(address account, bytes32 actorId) internal nonZero(account) {
        require(isActor(account, actorId));
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
    ///      with standard EIP-712-style struct hashing. `salt` is bound to the account address.
    function _computeImportDigest(address account, InitialActor[] calldata initialActors)
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
                ACTOR_INITIALIZATION_TYPEHASH, bytes32(bytes20(account)), keccak256(abi.encodePacked(actorHashes))
            )
        );
    }

    function _computeSignedActorChangesDigest(
        address account,
        uint64 chainId,
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

    function _authenticate(address account, bytes32 hash, address authenticator, bytes calldata data)
        internal
        view
        returns (uint8 scope, uint8 policyType, address policyTarget)
    {
        if (authenticator == K1_AUTHENTICATOR) return _authenticateK1(account, hash, data);

        bytes32 actorId = IAuthenticator(authenticator).authenticate(hash, data);
        require(actorId != bytes32(0));

        ActorConfig memory config = _actorConfig[actorId][account];
        require(config.authenticator == authenticator);
        // Expiry is read from the same slot; an expired actor fails authentication. 0 = no expiry.
        require(config.expiry == 0 || block.timestamp <= config.expiry);
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
        require(recovered != address(0));

        if (recovered == account) {
            // Inline self: a single SLOAD resolves the whole key. The flag disables it entirely; otherwise the
            // inline scope/policy/expiry govern (all-zero = full owner).
            AccountState storage st = _accountState[account];
            require((st.flags & FLAG_REVOKE_DEFAULT_EOA) == 0);
            require(st.defaultEOAExpiry == 0 || block.timestamp <= st.defaultEOAExpiry);
            uint8 policyType = st.defaultEOAPolicyType;
            return
                (st.defaultEOAScope, policyType, _resolvePolicyTarget(account, bytes32(bytes20(account)), policyType));
        }

        bytes32 actorId = bytes32(bytes20(recovered));
        ActorConfig memory config = _actorConfig[actorId][account];
        require(config.authenticator == K1_AUTHENTICATOR);
        // Expiry is read from the same slot; an expired actor fails authentication. 0 = no expiry.
        require(config.expiry == 0 || block.timestamp <= config.expiry);
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

    function _recoverSigner(bytes32 hash, bytes calldata data) internal pure returns (address recovered) {
        require(data.length == 65);
        bytes32 r = bytes32(data[:32]);
        bytes32 s = bytes32(data[32:64]);
        uint8 v = uint8(data[64]);
        // EIP-2: reject the malleable high-s half of each signature and non-canonical v to enforce a single
        // canonical encoding per signature.
        require(uint256(s) <= SECP256K1_HALF_ORDER);
        require(v == 27 || v == 28);
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
        require(n <= 0xFFFF);

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
