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
///      Acting models and entrypoints:
///      - {execute}: the *account itself* acts (a gated session key, dispatched by the protocol as the account). The
///        acting identity comes from the transaction-context precompile and `account == msg.sender`.
///      - {executeAttested}: the *account itself* acts on a chain with no transaction-context precompile (e.g.
///        ERC-4337 only). There is no protocol identity, so the account is `msg.sender` and *attests* the acting
///        `actorId` explicitly. Guarded against self-origination and against use where a live precompile exists.
///      - {executeFor} / {executeForMany}: an *external caller* acts on behalf of one or more accounts that authorized
///        it (e.g. a subscription provider pulling from many accounts in one transaction). Identity is the caller
///        itself (`actorId == bytes20(msg.sender)`) and `account` comes from the supplied binding.
///
///      Commitment binding: the account authorizes a {PolicyBinding}; its `keccak256` is the `commitment`. When the
///      account authorizes the session-key actor it stores `scope & SCOPE_POLICY != 0`, `policy_manager =
///      address(this)`, and `policy_commitment = commitment` in Account Configuration. That signed actor change *is*
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
///      Scope: account-acting {execute} (precompile) and {executeAttested} (account-attested, no precompile), and
///      external-caller {executeFor} / {executeForMany}.
contract PolicyManager is ReentrancyGuard {
    using Address for address;

    /// @notice The EIP-8130 Account Configuration system contract used to resolve signed policy commitments.
    AccountConfiguration public immutable ACCOUNT_CONFIGURATION;

    constructor(address accountConfiguration) {
        ACCOUNT_CONFIGURATION = AccountConfiguration(accountConfiguration);
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
    /// @notice The acting actor has no live policy commitment for the account — i.e. it is not a gated actor of this
    ///         account, was revoked, or (on the external path) the account did not gate this manager for it.
    error NoActivePolicy(bytes32 actorId);
    /// @notice The acting actor's `ActorConfig.expiry` has passed. Commitment is not cleared on expiry (only on
    ///         revoke), so the manager must enforce this itself on {executeFor} and {executeAttested}, which have no
    ///         protocol auth path.
    error ActorExpired(bytes32 actorId);
    /// @notice {executeAttested} was invoked by a self-originating sender (`tx.origin == msg.sender`). That is the
    ///         signature of an EOA/7702 direct send or an 8130 self-dispatch — neither is an account-attested,
    ///         externally-driven execution, so the attested path is refused. Use {execute} (8130) or a normal tx.
    error SelfOrigination();
    /// @notice {executeAttested} was called while the transaction-context precompile is asserting a protocol
    ///         identity (`getTransactionSenderActorId() != 0`). On an 8130 chain the account-acting path is
    ///         {execute}; the attested path is refused so a gated actor cannot claim a different actor's identity.
    error ProtocolIdentityActive(bytes32 actorId);
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
    /// @dev Identity comes from the protocol, not the caller. Reaching this function as a dispatched call proves
    ///      this manager is the acting key's configured gate. The manager reads the acting `actorId` from the
    ///      transaction-context precompile and takes the account from `msg.sender`. The caller supplies the full
    ///      {PolicyBinding}; recomputing its commitment and comparing to the live signed commitment authenticates
    ///      config, validity window, and owning account in one check.
    ///
    ///      Actor expiry is not re-checked here: protocol authentication already rejects expired actors before
    ///      dispatch. `AccountConfiguration._authenticate` reverts `ActorExpired`, so a protocol-dispatched call's
    ///      sender actor was expiry-checked at authentication in the same transaction (same `block.timestamp`, so
    ///      no gap), and any non-dispatched or off-8130 call yields `actorId == 0` → {NoActivePolicy}. This trades
    ///      defense-in-depth for one SLOAD; soundness rests on the spec-level invariant that every conforming
    ///      implementation enforces expiry at authentication. {executeFor} retains a local expiry check because it
    ///      has no protocol auth.
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

        // No manager-match / expiry checks here — see @dev above. The external entrypoints below re-add both.
        _enforce(binding, commitment, executionData, account);
    }

    /// @notice Account-attested variant of {execute} for chains without the EIP-8130 transaction-context precompile
    ///         (e.g. an ERC-4337-only chain). The account itself drives the manager and *attests* which of its own
    ///         actors is acting by passing `actorId` explicitly, standing in for the protocol identity that
    ///         {execute} reads from the precompile.
    ///
    /// @dev Trust model — read carefully. {execute} gets two guarantees from the protocol: the `actorId` is
    ///      authentic (from the precompile) and a `SCOPE_POLICY` actor could *only* have reached this manager (the
    ///      8130 gate). Neither exists here, so BOTH move to the account, which is `msg.sender`:
    ///      - **Authenticity** — the account must have authenticated the acting key (e.g. in `validateUserOp`)
    ///        before calling, and pass that key's `actorId`.
    ///      - **Confinement** — the account MUST fill in `actorId` itself and MUST NOT let a restricted actor choose
    ///        it via user-supplied calldata. Otherwise a restricted key crafts a call to
    ///        `executeAttested(privilegedActorId, ...)` and self-escalates. Reproducing the 8130 gate in account code
    ///        (forcing a policy-scoped actor onto its own `actorId`) is the account's responsibility; the manager
    ///        cannot verify it and trusts `msg.sender`.
    ///
    ///      Two guards keep this path from being abused as a bypass of the protocol path on chains that *do* have
    ///      8130 semantics:
    ///      - `tx.origin != msg.sender` — forbids self-origination. An EOA/7702 direct send and an 8130 self-dispatch
    ///        both have `tx.origin == account == msg.sender`; only an externally-driven account (ERC-4337 EntryPoint
    ///        or other trusted executor) has a distinct origin. This is an anti-authentication (restriction) use of
    ///        `tx.origin`, not an identity check.
    ///      - `getTransactionSenderActorId() == 0` — if the precompile is asserting a protocol identity, the chain
    ///        supports 8130 and the correct account-acting path is {execute}. Refusing here stops a gated actor X
    ///        (dispatched as the account) from calling `executeAttested(Y, ...)` to drive another actor's binding.
    ///
    ///      Like {executeFor}, this path has no protocol auth, so it re-checks actor expiry locally.
    ///
    /// @param actorId       The account-attested acting actor (an actor configured on `msg.sender`).
    /// @param binding       Full account-authorized binding (config + window + salt); `binding.account` must be `msg.sender`.
    /// @param executionData Per-use action parameters interpreted by the policy.
    function executeAttested(bytes32 actorId, PolicyBinding calldata binding, bytes calldata executionData)
        external
        nonReentrant
    {
        // Forbid self-origination: only an externally-driven account (4337 EntryPoint / trusted executor) qualifies.
        if (tx.origin == msg.sender) revert SelfOrigination();

        // On a chain with a live precompile, the protocol asserts identity — use {execute}, not this path.
        bytes32 protocolActor = _actingActorId();
        if (protocolActor != bytes32(0)) revert ProtocolIdentityActive(protocolActor);

        address account = msg.sender;
        if (binding.account != account) revert InvalidBindingAccount(account, binding.account);

        bytes32 commitment = _commitment(binding);
        bytes32 signed = ACCOUNT_CONFIGURATION.getPolicyCommitment(account, actorId);
        if (signed == bytes32(0)) revert NoActivePolicy(actorId);
        if (signed != commitment) revert BindingCommitmentMismatch(signed, commitment);

        _requireNotExpired(account, actorId);
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
