// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Address} from "openzeppelin/utils/Address.sol";
import {ReentrancyGuard} from "openzeppelin/utils/ReentrancyGuard.sol";

import {AccountConfiguration} from "../AccountConfiguration.sol";
import {ITransactionContext, TX_CONTEXT_ADDRESS} from "../interfaces/ITransactionContext.sol";
import {Policy} from "./Policy.sol";

/// @dev Recommended `authenticator` for an actor that represents an *external caller* governed by a policy (e.g. a
///      subscription provider): an address that may act ONLY through its policy manager's external entrypoints, never
///      directly. Distinct from `TRUSTED_EXECUTOR` (which grants direct `executeBatch`): this is a
///      no-code, hash-derived sentinel, so the actor is recognized by AccountConfiguration (non-zero authenticator)
///      yet cannot drive the account directly and cannot authenticate an 8130 transaction (its `authenticate()` would
///      call into empty code and fail). Only the account-side authorization (and these examples/tests) ever reference
///      it; neither the account nor the manager runtime reads it — `executeFor` authorizes purely on
///      `actorId == bytes20(msg.sender)`, `policy_manager == this`, and a matching binding commitment.
address constant EXTERNAL_POLICY_AUTHENTICATOR = address(uint160(uint256(keccak256("externalPolicyCaller"))));

/// @title PolicyManager
///
/// @notice Minimal, self-contained reference policy manager for EIP-8130 actor policies.
///
/// @dev Role in the EIP-8130 flow:
///      - The manager is registered as an execution-enabled actor on the account (an actor whose authenticator is
///        `TRUSTED_EXECUTOR`), so it may drive the account via `executeBatch`.
///      - A restricted session-key actor is configured with `scope & SCOPE_POLICY != 0` and `policy_manager =
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
///        itself (`actorId == bytes20(msg.sender)`) and `account` comes from the supplied binding.
///
///      Commitment binding: the account authorizes a {PolicyBinding}; its `keccak256` is the `commitment`. When the
///      account authorizes the session-key actor it stores `scope & SCOPE_POLICY != 0`, `policy_manager =
///      address(this)`, and `policy_commitment = commitment` in Account Configuration. At {install} and every
///      execute path the manager recomputes the commitment from the supplied binding and requires it to equal the
///      live signed commitment — authenticating config, validity window, and owning account with zero config
///      storage on the manager or the policy (strictly better than storing a per-binding config hash).
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

    /// @dev Installed flag only. Account, validity window, and config are re-supplied via {PolicyBinding} and
    ///      authenticated by recomputing the commitment against AccountConfiguration.
    mapping(address policy => mapping(bytes32 commitment => bool installed)) internal _installed;

    event PolicyInstalled(address indexed account, address indexed policy, bytes32 indexed commitment);
    event PolicyExecuted(address indexed account, address indexed policy, bytes32 indexed commitment, address caller);
    /// @dev Emitted by {executeForMany} when one account in a best-effort batch is skipped because its per-account
    ///      enforcement reverted (e.g. revoked/expired binding, over budget, or a failing account call).
    event ExecutionSkipped(address indexed account, address indexed policy, bytes32 indexed actorId);

    /// @notice No installed binding exists for the given `(policy, commitment)`.
    error PolicyNotInstalled(bytes32 commitment);
    /// @notice A binding for this `(policy, commitment)` is already installed; installs are one-shot per commitment.
    error PolicyAlreadyInstalled(bytes32 commitment);
    /// @notice The current time is outside the binding's `[validAfter, validUntil)` execution window.
    error OutsideValidityWindow(uint40 validAfter, uint40 validUntil, uint256 timestamp);
    /// @notice The account has not signed this exact commitment for this manager on the given actor (the resolved
    ///         policy manager or commitment does not match the binding).
    error CommitmentNotAuthorized(bytes32 actorId, address target, bytes32 commitment);
    /// @notice The supplied binding does not recompute to the actor's live signed commitment.
    error BindingCommitmentMismatch(bytes32 expected, bytes32 actual);
    /// @notice {execute} requires `binding.account == msg.sender` (the protocol-dispatched account).
    error InvalidBindingAccount(address expected, address actual);
    /// @notice The acting actor has no live policy commitment for the account — i.e. it is not a gated actor of this
    ///         account, was revoked, or (on the external path) the account did not gate this manager for it.
    error NoActivePolicy(bytes32 actorId);
    /// @notice The acting actor's `ActorConfig.expiry` has passed. Commitment is not cleared on expiry (only on
    ///         revoke), so the manager must enforce this itself on {executeFor}, which has no protocol auth path.
    error ActorExpired(bytes32 actorId);
    /// @notice {executeForMany} array length mismatch between `bindings` and `executionData`.
    error LengthMismatch();
    /// @notice The per-account self-call boundary used by {executeForMany} was invoked by someone other than this
    ///         contract.
    error OnlySelf();

    /// @notice Computes the commitment (binding identifier) for a binding.
    ///
    /// @dev This is the account-authorized, opaque commitment: `keccak256` over the binding fields, with the
    ///      config bound by its own hash. Portable by construction (no chain/domain mixed in).
    function commitmentOf(PolicyBinding calldata binding) public pure returns (bytes32) {
        return _commitment(binding);
    }

    /// @notice True if `(policy, commitment)` has been installed.
    function isInstalled(address policy, bytes32 commitment) external view returns (bool) {
        return _installed[policy][commitment];
    }

    /// @notice Installs a policy binding the account has authorized for a specific actor.
    ///
    /// @dev Permissionless: callable by anyone, not just `binding.account`. The account's *authorization* is the
    ///      gate, not the caller — the manager re-derives the binding's `commitment` and requires the account to have
    ///      signed exactly it for this manager when configuring `actorId`. The committed `policyConfig` is handed to
    ///      the policy's install hook for validation only; the preimage is re-supplied at execute via the full
    ///      binding and authenticated by recomputing the commitment.
    ///
    ///      Install is one-shot per commitment: a second install of the same `(policy, commitment)` reverts
    ///      {PolicyAlreadyInstalled}, so it can never reset an installed binding's accounting (e.g. spend counters).
    ///
    /// @param actorId The actor the account configured with this policy (scope & SCOPE_POLICY != 0).
    /// @param binding The account-authorized binding.
    ///
    /// @return commitment The binding's commitment.
    function install(bytes32 actorId, PolicyBinding calldata binding)
        external
        nonReentrant
        returns (bytes32 commitment)
    {
        commitment = _commitment(binding);

        address target = ACCOUNT_CONFIGURATION.getPolicyManager(binding.account, actorId);
        bytes32 signedCommitment = ACCOUNT_CONFIGURATION.getPolicyCommitment(binding.account, actorId);
        if (target != address(this) || signedCommitment != commitment) {
            revert CommitmentNotAuthorized(actorId, target, signedCommitment);
        }

        if (_installed[binding.policy][commitment]) revert PolicyAlreadyInstalled(commitment);
        _installed[binding.policy][commitment] = true;

        Policy(binding.policy).onInstall(commitment, binding.account, binding.policyConfig);
        emit PolicyInstalled(binding.account, binding.policy, commitment);
    }

    /// @notice Exercises an installed policy and forwards the resulting call plan to the account.
    ///
    /// @dev Identity comes from the protocol, not the caller. Reaching this function as a dispatched call proves
    ///      this manager is the acting key's configured gate. The manager reads the acting `actorId` from the
    ///      transaction-context precompile and takes the account from `msg.sender`. The caller supplies the full
    ///      {PolicyBinding}; recomputing its commitment and comparing to the live signed commitment authenticates
    ///      config, validity window, and owning account in one check. Actor expiry is not re-checked here: protocol
    ///      authentication already rejects expired actors before dispatch.
    ///
    /// @param binding       Full account-authorized binding (config + window + salt).
    /// @param executionData Per-use action parameters interpreted by the policy.
    function execute(PolicyBinding calldata binding, bytes calldata executionData) external nonReentrant {
        address account = msg.sender;
        if (binding.account != account) revert InvalidBindingAccount(account, binding.account);

        bytes32 actorId = _actingActorId();
        bytes32 commitment = _commitment(binding);
        bytes32 signed = ACCOUNT_CONFIGURATION.getPolicyCommitment(account, actorId);
        if (signed == bytes32(0)) revert NoActivePolicy(actorId);
        if (signed != commitment) revert BindingCommitmentMismatch(signed, commitment);

        // No manager-match / expiry checks here: the 8130 gate already guarantees this manager is the acting key's
        // target and that the actor is unexpired. The external entrypoints below re-add both.
        _enforce(binding, commitment, executionData, account);
    }

    /// @notice External-caller variant of {execute}: an external party drives a policy that an account authorized
    ///         for it. Used when the actor is not a key *on* the account but a separate party (e.g. a subscription
    ///         provider) the account opted into.
    ///
    /// @dev The acting identity is the caller itself — `actorId == bytes20(msg.sender)` — and `account` is
    ///      `binding.account`. There is no protocol routing on this path, so unlike {execute} this re-verifies that
    ///      the account gated *this* manager for the caller and that the actor is unexpired.
    ///
    /// @param binding       Full account-authorized binding (config + window + salt).
    /// @param executionData Per-use action parameters interpreted by the policy.
    function executeFor(PolicyBinding calldata binding, bytes calldata executionData) external nonReentrant {
        _enforceExternal(binding, bytes32(bytes20(msg.sender)), executionData, msg.sender);
    }

    /// @notice Best-effort cross-account batch of {executeFor}: one external caller, many bindings, one transaction.
    ///
    /// @dev Each binding is enforced in its own self-call so a single failure is isolated and skipped. Each entry
    ///      carries its own binding (different `account` → different commitment). Failures emit {ExecutionSkipped}.
    ///
    /// @param bindings      Per-account bindings, parallel to `executionData`.
    /// @param executionData Per-account action parameters, parallel to `bindings`.
    ///
    /// @return results Per-account success flags, parallel to `bindings`.
    function executeForMany(PolicyBinding[] calldata bindings, bytes[] calldata executionData)
        external
        nonReentrant
        returns (bool[] memory results)
    {
        if (bindings.length != executionData.length) revert LengthMismatch();
        bytes32 actorId = bytes32(bytes20(msg.sender));
        address caller = msg.sender;
        results = new bool[](bindings.length);
        for (uint256 i; i < bindings.length; i++) {
            try this.enforceExternalSelf(bindings[i], actorId, executionData[i], caller) {
                results[i] = true;
            } catch {
                emit ExecutionSkipped(bindings[i].account, bindings[i].policy, actorId);
            }
        }
    }

    /// @notice Self-call boundary used by {executeForMany} for per-account revert isolation. Not for external use.
    function enforceExternalSelf(
        PolicyBinding calldata binding,
        bytes32 actorId,
        bytes calldata executionData,
        address caller
    ) external {
        if (msg.sender != address(this)) revert OnlySelf();
        _enforceExternal(binding, actorId, executionData, caller);
    }

    /// @dev External-path validation: manager-match, live commitment vs binding, actor expiry, then enforce.
    function _enforceExternal(
        PolicyBinding calldata binding,
        bytes32 actorId,
        bytes calldata executionData,
        address caller
    ) internal {
        address account = binding.account;
        if (ACCOUNT_CONFIGURATION.getPolicyManager(account, actorId) != address(this)) {
            revert NoActivePolicy(actorId);
        }

        bytes32 commitment = _commitment(binding);
        bytes32 signed = ACCOUNT_CONFIGURATION.getPolicyCommitment(account, actorId);
        if (signed == bytes32(0)) revert NoActivePolicy(actorId);
        if (signed != commitment) revert BindingCommitmentMismatch(signed, commitment);

        _requireNotExpired(account, actorId);
        _enforce(binding, commitment, executionData, caller);
    }

    /// @dev Reject when the acting actor's stored expiry has passed. Required on the external path (no protocol
    ///      auth); omitted on {execute}, where authentication already enforced expiry before dispatch.
    function _requireNotExpired(address account, bytes32 actorId) internal view {
        AccountConfiguration.ActorConfig memory config = ACCOUNT_CONFIGURATION.getActorConfig(account, actorId);
        if (config.expiry != 0 && block.timestamp > config.expiry) revert ActorExpired(actorId);
    }

    /// @dev Common enforcement: require installed, enforce the binding's validity window (authenticated by the
    ///      commitment check at the callsite), run the policy hooks, forward the account call, then post-execute.
    function _enforce(PolicyBinding calldata binding, bytes32 commitment, bytes calldata executionData, address caller)
        internal
    {
        if (!_installed[binding.policy][commitment]) revert PolicyNotInstalled(commitment);

        if (
            (binding.validAfter != 0 && block.timestamp < binding.validAfter)
                || (binding.validUntil != 0 && block.timestamp >= binding.validUntil)
        ) {
            revert OutsideValidityWindow(binding.validAfter, binding.validUntil, block.timestamp);
        }

        address account = binding.account;
        (bytes memory accountCallData, bytes memory postCallData) =
            Policy(binding.policy).onExecute(commitment, account, binding.policyConfig, executionData, caller);
        if (accountCallData.length == 0) return;

        account.functionCall(accountCallData);
        Policy(binding.policy).onPostExecute(commitment, account, postCallData);
        emit PolicyExecuted(account, binding.policy, commitment, caller);
    }

    /// @dev Reads the authenticated actor of the in-flight EIP-8130 transaction from the transaction-context
    ///      precompile. Outside a protocol-dispatched call the call yields no data and this returns bytes32(0).
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
