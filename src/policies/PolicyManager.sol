// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Address} from "openzeppelin/utils/Address.sol";
import {ReentrancyGuard} from "openzeppelin/utils/ReentrancyGuard.sol";

import {Keystore} from "../Keystore.sol";
import {ITransactionContext, TX_CONTEXT_ADDRESS} from "../interfaces/ITransactionContext.sol";
import {ActorId} from "../libraries/ActorId.sol";
import {Policy} from "./Policy.sol";

/// @dev Required `authenticator` for an actor that represents an *external caller* governed by a policy (e.g. a
///      subscription provider): an address that may act ONLY through its policy manager's external entrypoints, never
///      directly. Distinct from `TRUSTED_EXECUTOR` (which grants direct `executeBatch`): this is a
///      no-code, hash-derived sentinel, so the actor is recognized by Keystore (non-zero authenticator)
///      yet cannot drive the account directly and cannot authenticate an 8130 transaction (its `authenticate()` would
///      call into empty code and fail). `executeFor` / `executeForMany` require the acting actor's stored
///      authenticator to equal this sentinel: that restricts the external path to actors the account explicitly
///      provisioned as external-pull, so a native signing key gated to the same manager cannot be driven through the
///      auth-less external path. Authorization then also requires `actorId == ActorId.fromAddress(msg.sender)`,
///      `policy_manager == this`, and a matching binding commitment.
address constant EXTERNAL_POLICY_AUTHENTICATOR = address(uint160(uint256(keccak256("externalPolicyCaller"))));

/// @title PolicyManager
///
/// @notice Minimal, self-contained reference policy manager for EIP-8130 actor policies. The account-acting {execute}
///         path (direct protocol dispatch from the account itself) resolves identity from the transaction-context
///         precompile, so it is only usable on EIP-8130 chains; the external-caller {executeFor} / {executeForMany}
///         paths derive identity from `msg.sender` and work on any chain.
///
/// @dev Role in the EIP-8130 flow:
///      - The manager is registered as an execution-enabled actor on the account (an actor whose authenticator is
///        `TRUSTED_EXECUTOR`), so it may drive the account via `executeBatch`.
///      - A restricted session-key actor is configured with `scope & Scopes.POLICY != 0` and `policy_manager =
///        address(this)`, so the protocol gate forces every call that actor makes to land on this manager.
///      - When the session key transacts, the protocol dispatches its call *as the account*, so `msg.sender`
///        here is the account itself. That is the authorization boundary: only a gated session-key transaction
///        (routed through the account) can invoke {execute}.
///
///      Acting models and entrypoints:
///      - {execute}: the *account itself* acts — a policy-gated session key that the EIP-8130 protocol dispatches as
///        the account. The acting identity is read from the transaction-context precompile and `account == msg.sender`.
///      - {executeFor} / {executeForMany}: an *external caller* acts on behalf of one or more accounts that authorized
///        it (e.g. a subscription provider pulling from many accounts in one transaction). Identity is the caller
///        itself (`actorId == ActorId.fromAddress(msg.sender)`) and `account` comes from the supplied binding.
///
///      Commitment binding: the account authorizes a {PolicyBinding}; its `keccak256` is the `commitment`. When the
///      account authorizes the session-key actor it stores `scope & Scopes.POLICY != 0`, `policy_manager =
///      address(this)`, and `policy_commitment = commitment` in Keystore. That signed actor change *is*
///      the authorization — there is no separate install step and no manager-side install bit. At every execute path
///      the manager recomputes the commitment from the supplied binding and requires it to equal the live signed
///      commitment — authenticating config, validity window, and owning account with zero config storage on the
///      manager or the policy.
///
///      Shared {ReentrancyGuard}: beyond ordinary re-entrancy hygiene, a single status across {execute} /
///      {executeFor} / {executeForMany} is load-bearing for cross-account identity. The tx-context `actorId` is
///      global to the transaction; if the same session key is registered on two accounts (same derived actorId,
///      both gated here), a policy-approved call from account A's plan could land on a target that reenters
///      {execute} with that target's binding and would otherwise resolve identity. Do not "optimize" the
///      entrypoints onto separate reentrancy guards.
///
///      Scope: account-acting {execute} (transaction-context precompile) and external-caller {executeFor} /
///      {executeForMany}.
contract PolicyManager is ReentrancyGuard {
    using Address for address;

    /// @notice The EIP-8130 Keystore system contract used to resolve signed policy commitments.
    Keystore public immutable KEYSTORE;

    constructor(address keystore) {
        KEYSTORE = Keystore(keystore);
    }

    /// @notice Policy binding authorized by the account. Its hash is the policy commitment.
    struct PolicyBinding {
        /// @dev Account that authorizes the binding and is the execution target.
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

    event PolicyExecuted(address indexed account, address indexed policy, bytes32 indexed commitment, address caller);
    /// @dev Emitted by {executeForMany} when one account in a best-effort batch is skipped because its per-account
    ///      enforcement reverted (e.g. revoked/expired binding, over budget, or a failing account call).
    event ExecutionSkipped(address indexed account, address indexed policy, bytes32 indexed actorId);

    /// @notice The current time is outside the binding's `[validAfter, validUntil)` execution window.
    error OutsideValidityWindow(uint40 validAfter, uint40 validUntil, uint256 timestamp);
    /// @notice The supplied binding does not recompute to the actor's live signed commitment.
    error BindingCommitmentMismatch(bytes32 expected, bytes32 actual);
    /// @notice {execute} requires `binding.account == msg.sender` (the protocol-dispatched account).
    error InvalidBindingAccount(address expected, address actual);
    /// @notice The acting actor is a live actor of the account but has no policy binding that routes here — either it
    ///         is not policy-gated, or (on the external path) the account did not gate this manager for it, or its
    ///         signed commitment is zero.
    error NoActivePolicy(bytes32 actorId);
    /// @notice The acting actor is not a live external-pull actor of the account: it is unknown, revoked, or expired,
    ///         or its stored authenticator is not {EXTERNAL_POLICY_AUTHENTICATOR}. Enforced on the external path
    ///         ({executeFor} / {executeForMany}), which has no protocol auth to reject it first.
    error InvalidActor(bytes32 actorId);
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

    /// @notice Exercises a policy authorized by the account's signed commitment and forwards the resulting call plan
    ///         to the account.
    ///
    /// @dev Identity comes from the protocol, not the caller. Reaching this function as a dispatched call proves this
    ///      manager is the acting key's configured gate. The manager reads the acting `actorId` from the
    ///      transaction-context precompile and takes the account from `msg.sender`. The caller supplies the full
    ///      {PolicyBinding}; recomputing its commitment and comparing to the live signed commitment authenticates
    ///      config, validity window, and owning account in one check.
    ///
    ///      Actor liveness is not re-checked here: protocol authentication already rejects expired (or otherwise
    ///      non-live) actors before dispatch. `Keystore._authenticate` reverts `ActorExpired`, so a protocol-dispatched
    ///      call's sender actor was liveness-checked at authentication in the same transaction (same `block.timestamp`,
    ///      so no gap), and any non-dispatched call yields `actorId == 0` → {NoActivePolicy}. This trades
    ///      defense-in-depth for one SLOAD; soundness rests on the spec-level invariant that every conforming
    ///      implementation enforces expiry at authentication. {executeFor} retains a local liveness check
    ///      ({InvalidActor}) because it has no protocol auth.
    ///
    /// @param binding       Full account-authorized binding (config + window + salt).
    /// @param executionData Per-use action parameters interpreted by the policy.
    function execute(PolicyBinding calldata binding, bytes calldata executionData) external nonReentrant {
        address account = msg.sender;
        if (binding.account != account) revert InvalidBindingAccount(account, binding.account);

        bytes32 actorId = _actingActorId();
        bytes32 commitment = _commitment(binding);
        bytes32 signed = KEYSTORE.getPolicyCommitment(account, actorId);
        if (signed == bytes32(0)) revert NoActivePolicy(actorId);
        if (signed != commitment) revert BindingCommitmentMismatch(signed, commitment);

        // No manager-match / expiry checks here — see @dev above. The external entrypoints below re-add both.
        _enforce(binding, commitment, executionData, account);
    }

    /// @notice External-caller variant of {execute}: an external party drives a policy that an account authorized
    ///         for it. Used when the actor is not a key *on* the account but a separate party (e.g. a subscription
    ///         provider) the account opted into.
    ///
    /// @dev The acting identity is the caller itself — `actorId == ActorId.fromAddress(msg.sender)` — and `account` is
    ///      `binding.account`. There is no protocol routing on this path, so unlike {execute} this re-verifies that
    ///      the caller is a live external-pull actor (authenticator == {EXTERNAL_POLICY_AUTHENTICATOR}) and that the
    ///      account gated *this* manager for it.
    ///
    /// @param binding       Full account-authorized binding (config + window + salt).
    /// @param executionData Per-use action parameters interpreted by the policy.
    function executeFor(PolicyBinding calldata binding, bytes calldata executionData) external nonReentrant {
        _enforceExternal(binding, ActorId.fromAddress(msg.sender), executionData, msg.sender);
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
        bytes32 actorId = ActorId.fromAddress(msg.sender);
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

    /// @dev External-path validation: live external-pull actor, manager-match, live commitment vs binding, then
    ///      enforce.
    function _enforceExternal(
        PolicyBinding calldata binding,
        bytes32 actorId,
        bytes calldata executionData,
        address caller
    ) internal {
        address account = binding.account;

        // Liveness + verifier precondition. The external path has no protocol auth (omitted on {execute}, where
        // authentication already enforced this before dispatch), so the manager itself gates the caller. It requires
        // the actor to be provisioned with EXTERNAL_POLICY_AUTHENTICATOR — the no-code sentinel that marks an
        // external-pull actor (one that can act ONLY through this path and can never authenticate a native 8130 tx).
        // getActorConfig resolves an unknown, revoked, or expired actor to the all-zero config (authenticator 0), so
        // this single read both enforces liveness AND restricts executeFor to actors the account explicitly opted
        // into external pull. A native signing key gated to this manager (a real authenticator) is therefore not
        // drivable through the auth-less external path, where it would bypass protocol replay protection. Checked
        // before the policy-binding checks so those stay specific to a live external-pull actor.
        if (KEYSTORE.getActorConfig(account, actorId).authenticator != EXTERNAL_POLICY_AUTHENTICATOR) {
            revert InvalidActor(actorId);
        }

        if (KEYSTORE.getPolicyManager(account, actorId) != address(this)) {
            revert NoActivePolicy(actorId);
        }

        bytes32 commitment = _commitment(binding);
        bytes32 signed = KEYSTORE.getPolicyCommitment(account, actorId);
        if (signed == bytes32(0)) revert NoActivePolicy(actorId);
        if (signed != commitment) revert BindingCommitmentMismatch(signed, commitment);

        _enforce(binding, commitment, executionData, caller);
    }

    /// @dev Common enforcement: enforce the binding's validity window (authenticated by the commitment check at the
    ///      callsite), run the policy hooks, forward the account call, then post-execute.
    function _enforce(PolicyBinding calldata binding, bytes32 commitment, bytes calldata executionData, address caller)
        internal
    {
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
    ///      precompile. Outside a protocol-dispatched call (and on any chain without the precompile) the STATICCALL
    ///      yields no data and this returns bytes32(0); the manager has no other identity source, so such calls fail
    ///      as {NoActivePolicy}. Accepts the return only when it is exactly 32 bytes.
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
