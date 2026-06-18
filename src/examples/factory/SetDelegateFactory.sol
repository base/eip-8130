// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IAccountConfiguration} from "../../interfaces/IAccountConfiguration.sol";
import {IBootstrap} from "./IBootstrap.sol";

/// @notice Reference factory that deploys EIP-8130 accounts via the EIP-7819 `SETDELEGATE` opcode.
///
///         Flow (atomic, one tx frame):
///           1. `SETDELEGATE(salt, implementation)` places `0xef0100 || implementation` at a deterministic
///              address `keccak256(0xef0100 || factory || salt)[12:]`.
///           2. `bootstrap(actorsHash)` primes the implementation's bootstrap state in the account's storage.
///              `actorsHash` is the inner hash of EIP-8130's `ActorInitialization` digest and also feeds the
///              SETDELEGATE salt, so the address binds to the actor set.
///           3. `AccountConfiguration.importAccount(account, initialActors, "")` registers the actors.
///              The ERC-1271 callback lands at the implementation's bootstrap branch, which validates the
///              presented `ActorInitialization` digest against the primed `actorsHash`.
///
///         Squatting / front-running defenses:
///           - `SETDELEGATE` address derivation includes `msg.sender`, so a different factory yields a
///             different address.
///           - The salt includes a commitment to the actor set, so a different actor set yields a different
///             salt and therefore a different address.
///           - The full sequence runs in one transaction frame; no intermediate window exists.
///
///         AccountConfiguration is not aware of this factory. No registry, no privileged call path.
///
///         Requires: EIP-7819 (`SETDELEGATE`, opcode 0xf6). Not yet executable on most chains; `_setDelegate`
///         is `virtual` so a test subclass can simulate the opcode via `vm.etch`.
contract SetDelegateFactory {
    IAccountConfiguration public immutable ACCOUNT_CONFIGURATION;

    /// @dev EIP-7702 delegation indicator prefix used in SETDELEGATE address derivation.
    bytes3 internal constant DELEGATION_INDICATOR = 0xef0100;

    /// @dev Mirrors `AccountConfiguration.ACTOR_INITIALIZATION_TYPEHASH`.
    bytes32 internal constant _ACTOR_INITIALIZATION_TYPEHASH = keccak256(
        "ActorInitialization(bytes32 salt,Actor[] initialActors)Actor(bytes32 actorId,ActorConfig config,bytes policyData)ActorConfig(address authenticator,uint8 scope,uint48 expiry,uint8 policyType)"
    );

    /// @dev Mirrors `AccountConfiguration.ACTOR_TYPEHASH`.
    bytes32 internal constant _ACTOR_TYPEHASH = keccak256(
        "Actor(bytes32 actorId,ActorConfig config,bytes policyData)ActorConfig(address authenticator,uint8 scope,uint48 expiry,uint8 policyType)"
    );

    /// @dev Mirrors `AccountConfiguration.ACTORCONFIG_TYPEHASH`.
    bytes32 internal constant _ACTORCONFIG_TYPEHASH =
        keccak256("ActorConfig(address authenticator,uint8 scope,uint48 expiry,uint8 policyType)");

    /// @dev `keccak256("")` — cached because every imported (always-unrestricted) actor has empty `policyData`.
    bytes32 internal constant _EMPTY_HASH = keccak256("");

    constructor(address accountConfiguration) {
        ACCOUNT_CONFIGURATION = IAccountConfiguration(accountConfiguration);
    }

    // ══════════════════════════════════════════════
    //  DEPLOY
    // ══════════════════════════════════════════════

    /// @notice Deploy a new EIP-8130 account at a deterministic address.
    /// @param initialActors  Initial actor set. MUST be sorted by `actorId` ascending (matches Create Entry rules).
    /// @param implementation Wallet code; the SETDELEGATE target. MUST be a bootstrap-aware `IBootstrap`.
    /// @param userSalt       User-chosen uniqueness factor.
    /// @return account       The deployed account address.
    function deploy(
        IAccountConfiguration.InitialActor[] calldata initialActors,
        address implementation,
        bytes32 userSalt
    ) external returns (address account) {
        bytes32 ah = _actorsHash(initialActors);
        bytes32 salt = keccak256(abi.encodePacked(userSalt, ah));

        // (1) Place the delegation indicator at the SETDELEGATE-derived address.
        account = _setDelegate(salt, implementation);

        // (2) Prime the implementation's bootstrap state. Runs implementation code in `account`'s storage.
        IBootstrap(account).bootstrap(ah);

        // (3) Register actors. ERC-1271 callback lands at the implementation's bootstrap branch.
        ACCOUNT_CONFIGURATION.importAccount(account, initialActors, "");
    }

    // ══════════════════════════════════════════════
    //  UPGRADE
    // ══════════════════════════════════════════════

    /// @notice Swap an account's delegate implementation. The account proves authority by being the caller.
    /// @dev Within an EIP-8130 transaction, the dispatched call's `msg.sender` is the tx `sender`, so any actor
    ///      authorized on the account (with unrestricted or CONFIG scope) authorizes the upgrade via the
    ///      natural 8130 path — no factory-held upgrade authority.
    function upgrade(bytes32 userSalt, bytes32 actorsHash, address newImplementation) external {
        bytes32 salt = keccak256(abi.encodePacked(userSalt, actorsHash));
        require(msg.sender == computeAddress(salt), "only account");
        _setDelegate(salt, newImplementation);
    }

    // ══════════════════════════════════════════════
    //  VIEW
    // ══════════════════════════════════════════════

    /// @notice Compute the deterministic account address for a given initial actor set and user salt.
    function computeAccount(IAccountConfiguration.InitialActor[] calldata initialActors, bytes32 userSalt)
        external
        view
        returns (address)
    {
        bytes32 ah = _actorsHash(initialActors);
        bytes32 salt = keccak256(abi.encodePacked(userSalt, ah));
        return computeAddress(salt);
    }

    /// @notice Compute the SETDELEGATE-derived address for a fully-resolved salt.
    /// @dev    Mirrors EIP-7819 derivation: `keccak256(0xef0100 || factory || salt)[12:]`.
    function computeAddress(bytes32 salt) public view returns (address) {
        return address(uint160(uint256(keccak256(abi.encodePacked(DELEGATION_INDICATOR, address(this), salt)))));
    }

    /// @notice Compute the actors hash used both as the salt-commitment and as the bootstrap prime.
    /// @dev    `keccak256(actorHash_0 || ... || actorHash_n)` matching the inner hash of EIP-8130's
    ///         `ActorInitialization` digest for an unrestricted-actor import.
    function actorsHash(IAccountConfiguration.InitialActor[] calldata initialActors) external pure returns (bytes32) {
        return _actorsHash(initialActors);
    }

    // ══════════════════════════════════════════════
    //  INTERNALS
    // ══════════════════════════════════════════════

    function _actorsHash(IAccountConfiguration.InitialActor[] calldata initialActors) internal pure returns (bytes32) {
        bytes32[] memory perActor = new bytes32[](initialActors.length);
        for (uint256 i; i < initialActors.length; i++) {
            // Imported actors are always unrestricted: scope=0, expiry=0, policyType=0, empty policyData.
            bytes32 configHash = keccak256(
                abi.encode(_ACTORCONFIG_TYPEHASH, initialActors[i].authenticator, uint8(0), uint48(0), uint8(0))
            );
            perActor[i] = keccak256(abi.encode(_ACTOR_TYPEHASH, initialActors[i].actorId, configHash, _EMPTY_HASH));
        }
        return keccak256(abi.encodePacked(perActor));
    }

    /// @notice Execute EIP-7819 `SETDELEGATE` (opcode 0xf6) and return the resulting account address.
    /// @dev    Solidity inline assembly cannot emit a raw, currently-unassigned opcode (`verbatim` is Yul-object
    ///         scope only). When 7819 is adopted, this is expected to be implemented either with the future
    ///         Yul builtin (`setdelegate(salt, target)`) or with a wrapper contract whose bytecode contains
    ///         the opcode. Overridable so test environments can simulate the opcode via `vm.etch`; the
    ///         base implementation reverts so any non-overridden production deployment fails closed.
    function _setDelegate(
        bytes32,
        /* salt */
        address /* target */
    )
        internal
        virtual
        returns (
            address /* account */
        )
    {
        revert("SETDELEGATE: not implemented; override _setDelegate or wait for EIP-7819 deployment");
    }
}
