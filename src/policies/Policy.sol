// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Address} from "openzeppelin/utils/Address.sol";
import {ReentrancyGuard} from "openzeppelin/utils/ReentrancyGuard.sol";

import {Keystore} from "../Keystore.sol";
import {Call, IExecuteBatch} from "../interfaces/IExecuteBatch.sol";
import {IPolicy} from "../interfaces/IPolicy.sol";
import {IPolicyCallEncoder} from "../interfaces/IPolicyCallEncoder.sol";
import {ITransactionContext, TX_CONTEXT_ADDRESS} from "../interfaces/ITransactionContext.sol";
import {ActorId} from "../libraries/ActorId.sol";
import {PolicyBinding, PolicyBindingLib} from "./PolicyBinding.sol";

/// @dev Sentinel `authenticator` marking an actor as a policy-only external-pull caller (e.g. a subscription
///      provider): recognized by Keystore but unable to drive the account directly or authenticate an 8130
///      transaction. Required by {Policy.executeFor} and {Policy.executeForMany}.
address constant EXTERNAL_POLICY_AUTHENTICATOR = address(uint160(uint256(keccak256("externalPolicyCaller"))));

/// @title Policy
///
/// @notice Self-executing base for EIP-8130 actor policies: the policy IS its own manager. The account gates a
///         policy-scoped key with `policy_manager = address(policy)`, so the protocol routes that key's calls
///         straight here — there is no separate manager contract and no per-ABI manager subclass.
///
/// @dev A policy turns an account-authorized binding plus a per-use action (`executionData`) into a wallet-agnostic
///      {Call} plan, then drives the account itself: it encodes the plan (default `executeBatch(Call[])`, or the
///      binding's `transformer` for a diverging ABI) and forwards it. It authenticates every call against the
///      canonical Keystore — it requires itself to be the manager the account installed for the acting actor
///      (`getActorWithPolicy(account, actorId).policyManager == address(this)`), the binding to name this policy, and
///      the binding to recompute to that actor's live signed commitment. The account authorizes the policy to drive
///      it exactly as it would any manager (the policy is an execution-enabled actor of the account).
///
/// @dev The account-acting {execute} path resolves identity from the transaction-context precompile, so it is only
///      usable on EIP-8130 chains; the external-caller {executeFor} / {executeForMany} paths derive identity from
///      `msg.sender` and work on any chain. All entrypoints share one {ReentrancyGuard}: the transaction-context
///      actorId is global to the transaction, so a shared guard is what stops a reentrant {execute} from resolving a
///      different account's identity mid-call, and the policy now performs external account calls itself.
///
/// @dev A policy MUST validate config in {_onExecute} and MUST NOT store a config hash. Store only mutable execution
///      state (e.g. spend counters), keyed by the authenticated commitment.
///
/// @author Coinbase
abstract contract Policy is IPolicy, ReentrancyGuard {
    using Address for address;
    using PolicyBindingLib for PolicyBinding;

    /// @notice The EIP-8130 Keystore used to authenticate that this policy is the account-installed manager.
    Keystore public immutable KEYSTORE;

    /// @notice Deploys the policy bound to a Keystore instance.
    /// @param keystore Address of the EIP-8130 Keystore system contract.
    constructor(address keystore) {
        KEYSTORE = Keystore(keystore);
    }

    /// @notice Emitted for each successful policy execution (a non-empty account call).
    ///
    /// @param account    Account the plan executed against.
    /// @param policy     Policy contract that produced and forwarded the plan (this contract).
    /// @param commitment Binding commitment that authorized the execution.
    /// @param caller     Address that drove the execution (the account for {execute}, the external caller otherwise).
    event PolicyExecuted(address indexed account, address indexed policy, bytes32 indexed commitment, address caller);

    /// @notice Emitted by {executeForMany} when one account is skipped because its per-account enforcement reverted
    ///         (e.g. revoked/expired binding, over budget, or a failing account call).
    ///
    /// @param account Account whose entry was skipped.
    /// @param policy  Policy contract for the skipped binding (this contract).
    /// @param actorId Acting external caller's actorId.
    event ExecutionSkipped(address indexed account, address indexed policy, bytes32 indexed actorId);

    /// @notice The binding names a policy other than this contract.
    error PolicyMismatch(address expected, address actual);

    /// @notice The acting actor has no binding that routes here: it is not policy-gated to this policy, or its signed
    ///         commitment is zero (unknown, revoked, or expired).
    error NoActivePolicy(bytes32 actorId);

    /// @notice The acting actor is not a live external-pull actor of the account (unknown, revoked, expired, or its
    ///         authenticator is not {EXTERNAL_POLICY_AUTHENTICATOR}). Enforced on the external path, which has no
    ///         protocol auth to reject it first.
    error InvalidActor(bytes32 actorId);

    /// @notice {execute} requires `binding.account == msg.sender` (the protocol-dispatched account).
    error InvalidBindingAccount(address expected, address actual);

    /// @notice The supplied binding does not recompute to the actor's live signed commitment.
    error BindingCommitmentMismatch(bytes32 expected, bytes32 actual);

    /// @notice The current time is outside the binding's `[validAfter, validUntil)` execution window.
    error OutsideValidityWindow(uint40 validAfter, uint40 validUntil, uint256 timestamp);

    /// @notice {executeForMany} was given `bindings` and `executionData` of differing lengths.
    error LengthMismatch();

    /// @notice The {executeForMany} self-call boundary was invoked by someone other than this contract.
    error OnlySelf();

    /// @notice Computes the commitment (binding identifier) for a binding.
    ///
    /// @param binding Full policy binding to hash.
    ///
    /// @return The binding commitment: keccak256 over the binding fields (config and transformer included), with the
    ///         config bound by its own hash.
    function commitmentOf(PolicyBinding calldata binding) public pure override returns (bytes32) {
        return binding.commitment();
    }

    /// @notice Account-acting entrypoint: a policy-gated key transacts and the protocol dispatches as the account,
    ///         routing here because this policy is the key's installed `policy_manager`.
    ///
    /// @dev Reverts with InvalidBindingAccount when `binding.account != msg.sender`.
    /// @dev Reverts with PolicyMismatch when `binding.policy != address(this)`.
    /// @dev Reverts with NoActivePolicy when the acting actor has no signed commitment or this policy is not its
    ///      installed manager.
    /// @dev Reverts with BindingCommitmentMismatch when `binding` does not recompute to the signed commitment.
    /// @dev Reverts with OutsideValidityWindow when the current time is outside `[validAfter, validUntil)`.
    /// @dev Identity is read from the transaction-context precompile, so this path is usable only on EIP-8130 chains.
    ///
    /// @param binding       Full account-authorized binding (config, window, salt, transformer).
    /// @param executionData Per-use action parameters interpreted by the policy.
    function execute(PolicyBinding calldata binding, bytes calldata executionData) external override nonReentrant {
        address account = msg.sender;
        if (binding.account != account) revert InvalidBindingAccount(account, binding.account);
        if (binding.policy != address(this)) revert PolicyMismatch(address(this), binding.policy);

        bytes32 actorId = _actingActorId();
        (, address manager, bytes32 signed) = KEYSTORE.getActorWithPolicy(account, actorId);
        if (signed == bytes32(0)) revert NoActivePolicy(actorId);
        if (manager != address(this)) revert NoActivePolicy(actorId);

        bytes32 commitment = binding.commitment();
        if (signed != commitment) revert BindingCommitmentMismatch(signed, commitment);

        _enforce(binding, actorId, commitment, executionData, account);
    }

    /// @notice External-caller entrypoint: a party that is not a key on the account (e.g. a subscription provider)
    ///         drives a policy the account authorized for it.
    ///
    /// @dev Reverts with PolicyMismatch, InvalidActor, NoActivePolicy, BindingCommitmentMismatch, or
    ///      OutsideValidityWindow (see {_enforceExternal}).
    /// @dev Identity is the caller (`ActorId.fromAddress(msg.sender)`); works on any chain. Unlike {execute}, it
    ///      re-verifies the actor and the manager binding since there is no protocol routing.
    ///
    /// @param binding       Full account-authorized binding (config, window, salt, transformer).
    /// @param executionData Per-use action parameters interpreted by the policy.
    function executeFor(PolicyBinding calldata binding, bytes calldata executionData) external override nonReentrant {
        _enforceExternal(binding, ActorId.fromAddress(msg.sender), executionData, msg.sender);
    }

    /// @notice Best-effort cross-account batch of {executeFor}: one external caller, many bindings, one transaction.
    ///
    /// @dev Reverts with LengthMismatch when `bindings` and `executionData` differ in length.
    /// @dev Each binding is enforced in its own self-call; a per-account failure is isolated, skipped, and reported
    ///      via {ExecutionSkipped} rather than reverting the batch.
    ///
    /// @param bindings      Per-account bindings, parallel to `executionData`.
    /// @param executionData Per-account action parameters, parallel to `bindings`.
    ///
    /// @return results Per-account success flags, parallel to `bindings`.
    function executeForMany(PolicyBinding[] calldata bindings, bytes[] calldata executionData)
        external
        override
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
    ///
    /// @dev Reverts with OnlySelf when the caller is not this contract, else runs {_enforceExternal}.
    ///
    /// @param binding       Full account-authorized binding.
    /// @param actorId       Acting external caller's actorId.
    /// @param executionData Per-use action parameters interpreted by the policy.
    /// @param caller        External caller forwarded to the policy hooks.
    function enforceExternalSelf(
        PolicyBinding calldata binding,
        bytes32 actorId,
        bytes calldata executionData,
        address caller
    ) external {
        if (msg.sender != address(this)) revert OnlySelf();
        _enforceExternal(binding, actorId, executionData, caller);
    }

    /// @dev External-path authentication then {_enforce}. Reverts with PolicyMismatch when the binding names another
    ///      policy, InvalidActor when the caller's stored authenticator is not EXTERNAL_POLICY_AUTHENTICATOR,
    ///      NoActivePolicy when this policy is not the caller's installed manager or the signed commitment is zero, or
    ///      BindingCommitmentMismatch when `binding` does not recompute to the signed commitment.
    function _enforceExternal(
        PolicyBinding calldata binding,
        bytes32 actorId,
        bytes calldata executionData,
        address caller
    ) internal {
        address account = binding.account;
        if (binding.policy != address(this)) revert PolicyMismatch(address(this), binding.policy);

        (Keystore.ActorConfig memory config, address manager, bytes32 signed) =
            KEYSTORE.getActorWithPolicy(account, actorId);
        if (config.authenticator != EXTERNAL_POLICY_AUTHENTICATOR) revert InvalidActor(actorId);
        if (manager != address(this)) revert NoActivePolicy(actorId);
        if (signed == bytes32(0)) revert NoActivePolicy(actorId);

        bytes32 commitment = binding.commitment();
        if (signed != commitment) revert BindingCommitmentMismatch(signed, commitment);

        _enforce(binding, actorId, commitment, executionData, caller);
    }

    /// @dev Enforces the binding's validity window, runs the policy hook, encodes and forwards the account call, then
    ///      post-executes. Reverts with OutsideValidityWindow outside `[validAfter, validUntil)`; bubbles the hook,
    ///      encoder, or account-call revert. Emits {PolicyExecuted} on a non-empty call plan.
    function _enforce(
        PolicyBinding calldata binding,
        bytes32 actorId,
        bytes32 commitment,
        bytes calldata executionData,
        address caller
    ) internal {
        actorId;
        if (
            (binding.validAfter != 0 && block.timestamp < binding.validAfter)
                || (binding.validUntil != 0 && block.timestamp >= binding.validUntil)
        ) {
            revert OutsideValidityWindow(binding.validAfter, binding.validUntil, block.timestamp);
        }

        address account = binding.account;
        (Call[] memory calls, bytes memory postCallData) =
            _onExecute(commitment, account, binding.policyConfig, executionData, caller);
        if (calls.length == 0) return;

        account.functionCall(_encodeFor(binding, calls));
        _onPostExecute(commitment, account, postCallData);
        emit PolicyExecuted(account, address(this), commitment, caller);
    }

    /// @dev Encodes the wallet-agnostic call plan into calldata for `binding.account`'s execution entrypoint. Default
    ///      is `executeBatch(Call[])`; a non-zero `binding.transformer` is an {IPolicyCallEncoder} reached by
    ///      STATICCALL (so it can be a shared per-ABI library or the account itself, but never executes).
    function _encodeFor(PolicyBinding calldata binding, Call[] memory calls) internal view returns (bytes memory) {
        if (binding.transformer == address(0)) {
            return abi.encodeCall(IExecuteBatch.executeBatch, (calls));
        }
        return IPolicyCallEncoder(binding.transformer).encodeCalls(binding.account, calls);
    }

    /// @dev Reads the in-flight transaction's authenticated actorId from the transaction-context precompile. Returns
    ///      bytes32(0) when not protocol-dispatched or the precompile is absent (accepts only a 32-byte return).
    function _actingActorId() internal view returns (bytes32 actorId) {
        (bool ok, bytes memory ret) = TX_CONTEXT_ADDRESS.staticcall(
            abi.encodeWithSelector(ITransactionContext.getTransactionSenderActorId.selector)
        );
        if (ok && ret.length == 32) actorId = abi.decode(ret, (bytes32));
    }

    /// @dev Policy-specific execute logic. Revert to refuse. Validate config here as needed. An empty `calls` return
    ///      is a no-op (no account call, no {_onPostExecute}, no event).
    function _onExecute(
        bytes32 commitment,
        address account,
        bytes calldata policyConfig,
        bytes calldata executionData,
        address caller
    ) internal virtual returns (Call[] memory calls, bytes memory postCallData);

    /// @dev Policy-specific post-execute hook. Default no-op; override for post-call checks (e.g. balance deltas).
    function _onPostExecute(bytes32 commitment, address account, bytes memory postCallData) internal virtual {
        commitment;
        account;
        postCallData;
    }
}
