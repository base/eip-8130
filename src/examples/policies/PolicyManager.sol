// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Address} from "openzeppelin/utils/Address.sol";
import {ReentrancyGuard} from "openzeppelin/utils/ReentrancyGuard.sol";

import {AccountConfiguration} from "../../AccountConfiguration.sol";
import {ITransactionContext, TX_CONTEXT_ADDRESS} from "../../interfaces/ITransactionContext.sol";
import {Policy} from "./Policy.sol";

/// @dev Recommended `authenticator` for an actor that represents an *external caller* governed by a policy (e.g. a
///      subscription provider): an address that may act ONLY through its policy manager's external entrypoints, never
///      directly. Distinct from `TRUSTED_EXECUTOR` (which grants direct `executeBatch`): this is a
///      no-code, hash-derived sentinel, so the actor is recognized by AccountConfiguration (non-zero authenticator)
///      yet cannot drive the account directly and cannot authenticate an 8130 transaction (its `authenticate()` would
///      call into empty code and fail). Only the account-side authorization (and these examples/tests) ever reference
///      it; neither the account nor the manager runtime reads it — `executeFor` authorizes purely on
///      `actorId == bytes20(msg.sender)`, `policy_manager == this`, and a non-zero commitment.
address constant EXTERNAL_POLICY_AUTHENTICATOR = address(uint160(uint256(keccak256("externalPolicyCaller"))));

/// @title PolicyManager
///
/// @notice Minimal, self-contained reference policy manager for EIP-8130 actor policies.
///
/// @dev Role in the EIP-8130 flow:
///      - The manager is registered as an execution-enabled actor on the account (an actor whose authenticator is
///        `TRUSTED_EXECUTOR`), so it may drive the account via `executeBatch`.
///      - A restricted session-key actor is configured with a non-zero `policyType` and `policy_manager =
///        address(this)`, so the protocol gate forces every call that actor makes to land on this manager.
///      - When the session key transacts, the protocol dispatches its call *as the account*, so `msg.sender`
///        here is the account itself. That is the authorization boundary: only a gated session-key transaction
///        (routed through the account) can invoke {execute}.
///
///      Two acting models, two entrypoints:
///      - {execute}: the *account itself* acts (a gated session key, dispatched by the protocol as the account). The
///        acting identity comes from the transaction-context precompile and `account == msg.sender`.
///      - {executeFor} / {executeForMany}: an *external caller* acts on behalf of one or more accounts that authorized
///        it (e.g. a subscription provider pulling from many accounts in one transaction). Identity is the caller
///        itself (`actorId == bytes20(msg.sender)`) and `account` is an explicit argument. Because there is no
///        protocol routing on this path, these re-add the `policy_manager == address(this)` check that {execute}
///        omits.
///
///      Commitment binding: the account authorizes a {PolicyBinding}; its `keccak256` is the `commitment`. When the
///      account authorizes the session-key actor it stores a non-zero `policyType`, `policy_manager = address(this)`, and
///      `policy_commitment = commitment` in the Account Configuration contract. At {install} the manager reads that
///      binding back via the single-SLOAD {AccountConfiguration.getPolicyManager} / {AccountConfiguration.getPolicyCommitment}
///      accessors and requires the target and commitment to match, so an install can only succeed for a policy the
///      account actually signed for this manager.
///
///      Scope: permissionless {install} (gated by the account's signed commitment, not the caller), account-acting
///      {execute}, and external-caller {executeFor} / {executeForMany}.
contract PolicyManager is ReentrancyGuard {
    using Address for address;

    /// @notice The EIP-8130 Account Configuration system contract used to resolve signed policy commitments.
    AccountConfiguration public immutable ACCOUNT_CONFIGURATION;

    constructor(address accountConfiguration) {
        ACCOUNT_CONFIGURATION = AccountConfiguration(accountConfiguration);
    }

    /// @notice Policy binding authorized by the account. Its hash is the policy commitment.
    struct PolicyBinding {
        /// @dev Account that authorizes installation and is the execution target.
        address account;
        /// @dev Policy contract implementing the hook interface.
        address policy;
        /// @dev Committed, opaque policy configuration interpreted by `policy`.
        bytes policyConfig;
        /// @dev Earliest timestamp (seconds) at which execution is allowed. Zero = no lower bound.
        uint40 validAfter;
        /// @dev Timestamp (seconds) at/after which execution is disallowed. Zero = no upper bound.
        uint40 validUntil;
        /// @dev Salt allowing multiple distinct bindings for the same (account, policy, config).
        uint256 salt;
    }

    /// @notice Lifecycle record stored per (policy, commitment).
    struct PolicyRecord {
        bool installed;
        address account;
        uint40 validAfter;
        uint40 validUntil;
    }

    /// @dev policies[policy][commitment] => record.
    mapping(address policy => mapping(bytes32 commitment => PolicyRecord)) internal _policies;

    event PolicyInstalled(address indexed account, address indexed policy, bytes32 indexed commitment);
    event PolicyExecuted(address indexed account, address indexed policy, bytes32 indexed commitment, address caller);
    /// @dev Emitted by {executeForMany} when one account in a best-effort batch is skipped because its per-account
    ///      enforcement reverted (e.g. revoked/expired binding, over budget, or a failing account call).
    event ExecutionSkipped(address indexed account, address indexed policy, bytes32 indexed actorId);

    error PolicyNotInstalled(bytes32 commitment);
    error PolicyAlreadyInstalled(bytes32 commitment);
    error OutsideValidityWindow(uint40 validAfter, uint40 validUntil, uint256 timestamp);
    error CommitmentNotAuthorized(bytes32 actorId, address target, bytes32 commitment);
    /// @dev The executing account is not the account the commitment was installed for. Commitments are opaque in
    ///      AccountConfiguration, so this binds execution (and the commitment-keyed policy state) to its owner.
    error CommitmentAccountMismatch(address expected, address actual);
    /// @dev The acting actor has no live policy commitment for the account — i.e. it is not a gated actor of this
    ///      account, was revoked/expired, or (on the external path) the account did not gate this manager for it.
    error NoActivePolicy(bytes32 actorId);
    /// @dev {executeForMany} array length mismatch between `accounts` and `executionData`.
    error LengthMismatch();
    /// @dev The per-account self-call boundary used by {executeForMany} was invoked by someone other than this
    ///      contract.
    error OnlySelf();

    /// @notice Computes the commitment (binding identifier) for a binding.
    ///
    /// @dev This is the account-authorized, opaque commitment: `keccak256` over the binding fields, with the
    ///      config bound by its own hash. Portable by construction (no chain/domain mixed in).
    function commitmentOf(PolicyBinding calldata binding) public pure returns (bytes32) {
        return _commitment(binding);
    }

    /// @notice Returns the lifecycle record for an installed binding.
    function getPolicyRecord(address policy, bytes32 commitment) external view returns (PolicyRecord memory) {
        return _policies[policy][commitment];
    }

    /// @notice Installs a policy binding the account has authorized for a specific actor.
    ///
    /// @dev Permissionless: callable by anyone, not just `binding.account`. The account's *authorization* is the
    ///      gate, not the caller — the manager re-derives the binding's `commitment` and requires the account to have
    ///      signed exactly it for this manager when configuring `actorId` (the resolved policy manager must be this
    ///      contract and the resolved commitment must equal the binding's). An install can therefore only ever
    ///      materialize a binding the account already committed to, so anyone may submit it (e.g. a subscription
    ///      provider self-serving install after the account signs the actor change off-chain). The committed
    ///      `policyConfig` is then handed to the policy's install hook, which stores it keyed by commitment.
    ///
    ///      Install is one-shot per commitment: a second install of the same `(policy, commitment)` reverts
    ///      {PolicyAlreadyInstalled}, so it can never reset an installed binding's accounting (e.g. spend counters).
    ///      Changing any binding field yields a different commitment — a separate, independently-accounted binding,
    ///      not a reset of the old one.
    ///
    /// @param actorId The actor the account configured with this policy (non-zero policyType).
    /// @param binding The account-authorized binding.
    ///
    /// @return commitment The binding's commitment.
    function install(bytes32 actorId, PolicyBinding calldata binding)
        external
        nonReentrant
        returns (bytes32 commitment)
    {
        commitment = _commitment(binding);

        // The account must have signed this exact commitment for this manager when authorizing `actorId`. Read the
        // gate target and signed commitment via the single-SLOAD granular accessors: the manager never needs the
        // policyType byte, so this avoids the extra ActorConfig SLOAD that getPolicy performs. This (not msg.sender)
        // is the authorization gate, which is why install is permissionless.
        address target = ACCOUNT_CONFIGURATION.getPolicyManager(binding.account, actorId);
        bytes32 signedCommitment = ACCOUNT_CONFIGURATION.getPolicyCommitment(binding.account, actorId);
        if (target != address(this) || signedCommitment != commitment) {
            revert CommitmentNotAuthorized(actorId, target, signedCommitment);
        }

        PolicyRecord storage record = _policies[binding.policy][commitment];
        if (record.installed) revert PolicyAlreadyInstalled(commitment);

        record.installed = true;
        record.account = binding.account;
        record.validAfter = binding.validAfter;
        record.validUntil = binding.validUntil;

        Policy(binding.policy).onInstall(commitment, binding.account, binding.policyConfig);
        emit PolicyInstalled(binding.account, binding.policy, commitment);
    }

    /// @notice Exercises an installed policy and forwards the resulting call plan to the account.
    ///
    /// @dev Identity comes from the protocol, not the caller. In EIP-8130 the protocol resolves a gated actor's
    ///      allowed target — `policy_manager(account, actorId)` — and reverts any call whose `call.to` is not that
    ///      address (`ActorPolicyViolation`) before dispatch. So simply *reaching* this function as a dispatched
    ///      call proves this manager is the acting key's configured gate; re-checking the target here would only
    ///      duplicate that protocol guarantee. The manager therefore reads the acting `actorId` from the
    ///      transaction-context precompile and takes the account from `msg.sender` (the protocol sets
    ///      `msg.sender == sender == account` at a dispatched `call.to`, and using `msg.sender` confines execution
    ///      to that direct dispatch path). It then needs only the live signed `commitment` (a single SLOAD) to
    ///      locate the installed binding — a revoked or expired actor has a zero commitment and is rejected.
    ///
    /// @param policy        Policy contract for the binding.
    /// @param executionData Per-use action parameters interpreted by the policy.
    function execute(address policy, bytes calldata executionData) external nonReentrant {
        address account = msg.sender;
        bytes32 actorId = _actingActorId();

        // Single-SLOAD read of the live signed commitment for the acting actor. Zero means the actor is not a gated
        // key of this account (or was revoked/expired): there is no binding to enforce, so reject.
        bytes32 commitment = ACCOUNT_CONFIGURATION.getPolicyCommitment(account, actorId);
        if (commitment == bytes32(0)) revert NoActivePolicy(actorId);

        // No manager-match check here: on the protocol-dispatched path the 8130 gate already guarantees this manager
        // is the acting key's configured target (see the dev note above). The external entrypoints below re-add it.
        _enforce(account, policy, commitment, executionData, account);
    }

    /// @notice External-caller variant of {execute}: an external party drives a policy that an `account` authorized
    ///         for it. Used when the actor is not a key *on* the account but a separate party (e.g. a subscription
    ///         provider) the account opted into.
    ///
    /// @dev The acting identity is the caller itself — `actorId == bytes20(msg.sender)` — and `account` is explicit.
    ///      There is no protocol routing on this path, so unlike {execute} this re-verifies that the account gated
    ///      *this* manager for the caller (`policy_manager(account, actorId) == address(this)`); the caller cannot
    ///      forge the identity because it is derived from `msg.sender`. The account must also have registered this
    ///      manager as an execution-enabled actor (`TRUSTED_EXECUTOR`) for the forwarded `executeBatch`
    ///      to be accepted.
    ///
    /// @param account       Account the call plan will execute against (it authorized the caller).
    /// @param policy        Policy contract for the binding.
    /// @param executionData Per-use action parameters interpreted by the policy.
    function executeFor(address account, address policy, bytes calldata executionData) external nonReentrant {
        _enforceExternal(account, bytes32(bytes20(msg.sender)), policy, executionData, msg.sender);
    }

    /// @notice Best-effort cross-account batch of {executeFor}: one external caller, many accounts, one transaction.
    ///
    /// @dev Each account is enforced in its own self-call so a single failure (revoked/expired binding, over budget,
    ///      a reverting account call) is isolated and skipped — it does not roll back the accounts that succeeded.
    ///      Failures emit {ExecutionSkipped}; `results[i]` reports per-account success. The acting `actorId` is the
    ///      caller (`bytes20(msg.sender)`) for every entry.
    ///
    /// @param accounts      Accounts to pull from (each must have authorized the caller for `policy`).
    /// @param policy        Policy contract shared across the batch.
    /// @param executionData Per-account action parameters, parallel to `accounts`.
    ///
    /// @return results Per-account success flags, parallel to `accounts`.
    function executeForMany(address[] calldata accounts, address policy, bytes[] calldata executionData)
        external
        nonReentrant
        returns (bool[] memory results)
    {
        if (accounts.length != executionData.length) revert LengthMismatch();
        bytes32 actorId = bytes32(bytes20(msg.sender));
        address caller = msg.sender;
        results = new bool[](accounts.length);
        for (uint256 i; i < accounts.length; i++) {
            // Self-call gives each account its own revert boundary: a failure rolls back only this entry's effects
            // (its spend accounting + account call) and is caught, so the rest of the batch still settles.
            try this.enforceExternalSelf(accounts[i], actorId, policy, executionData[i], caller) {
                results[i] = true;
            } catch {
                emit ExecutionSkipped(accounts[i], policy, actorId);
            }
        }
    }

    /// @notice Self-call boundary used by {executeForMany} for per-account revert isolation. Not for external use.
    ///
    /// @dev Only callable by this contract (from within {executeForMany}), so the `(account, actorId, caller)` tuple
    ///      it trusts can only be supplied by the manager itself — never spoofed by an outside caller.
    function enforceExternalSelf(
        address account,
        bytes32 actorId,
        address policy,
        bytes calldata executionData,
        address caller
    ) external {
        if (msg.sender != address(this)) revert OnlySelf();
        _enforceExternal(account, actorId, policy, executionData, caller);
    }

    /// @dev External-path validation shared by {executeFor} and {enforceExternalSelf}: re-add the manager-match check
    ///      the protocol path can omit, resolve the live commitment, then run the common enforcement.
    function _enforceExternal(
        address account,
        bytes32 actorId,
        address policy,
        bytes calldata executionData,
        address caller
    ) internal {
        if (ACCOUNT_CONFIGURATION.getPolicyManager(account, actorId) != address(this)) {
            revert NoActivePolicy(actorId);
        }
        bytes32 commitment = ACCOUNT_CONFIGURATION.getPolicyCommitment(account, actorId);
        if (commitment == bytes32(0)) revert NoActivePolicy(actorId);
        _enforce(account, policy, commitment, executionData, caller);
    }

    /// @dev Common enforcement for both acting models: validate the installed binding's lifecycle window, run the
    ///      policy hook, and forward the returned call plan to the account.
    function _enforce(address account, address policy, bytes32 commitment, bytes calldata executionData, address caller)
        internal
    {
        PolicyRecord storage record = _policies[policy][commitment];
        if (!record.installed) revert PolicyNotInstalled(commitment);

        // Bind execution to the commitment's owning account. Commitments are opaque in AccountConfiguration, so a
        // different account could store a victim's commitment value in its own actor config and otherwise drive — and
        // exhaust — the victim's commitment-keyed policy state (e.g. a shared spend counter). `record.account` is
        // fixed at install to the account named in the commitment preimage, so this always holds for legitimate use.
        if (record.account != account) revert CommitmentAccountMismatch(record.account, account);

        if (
            (record.validAfter != 0 && block.timestamp < record.validAfter)
                || (record.validUntil != 0 && block.timestamp >= record.validUntil)
        ) {
            revert OutsideValidityWindow(record.validAfter, record.validUntil, block.timestamp);
        }

        bytes memory accountCallData = Policy(policy).onExecute(commitment, account, executionData, caller);
        if (accountCallData.length == 0) return;

        account.functionCall(accountCallData);
        emit PolicyExecuted(account, policy, commitment, caller);
    }

    /// @dev Reads the authenticated actor of the in-flight EIP-8130 transaction from the transaction-context
    ///      precompile. A low-level STATICCALL is used because the precompile carries no EXTCODESIZE (mirroring the
    ///      native precompiles); outside a protocol-dispatched call — or on a non-8130 chain — the call yields no
    ///      data and this returns bytes32(0), which the commitment check in {execute} rejects.
    function _actingActorId() internal view returns (bytes32 actorId) {
        (bool ok, bytes memory ret) = TX_CONTEXT_ADDRESS.staticcall(
            abi.encodeWithSelector(ITransactionContext.getTransactionSenderActorId.selector)
        );
        if (ok && ret.length == 32) actorId = abi.decode(ret, (bytes32));
    }

    function _commitment(PolicyBinding calldata binding) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                binding.account,
                binding.policy,
                keccak256(binding.policyConfig),
                binding.validAfter,
                binding.validUntil,
                binding.salt
            )
        );
    }
}
