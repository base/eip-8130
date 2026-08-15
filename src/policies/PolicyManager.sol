// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Address} from "openzeppelin/utils/Address.sol";
import {ReentrancyGuard} from "openzeppelin/utils/ReentrancyGuard.sol";

import {Keystore} from "../Keystore.sol";
import {ITransactionContext, TX_CONTEXT_ADDRESS} from "../interfaces/ITransactionContext.sol";
import {ActorId} from "../libraries/ActorId.sol";
import {Policy} from "./Policy.sol";

/// @dev Sentinel `authenticator` marking an actor as a policy-only external-pull caller (e.g. a subscription
///      provider): recognized by Keystore but unable to drive the account directly or authenticate an 8130
///      transaction. Required by {PolicyManager.executeFor} and {PolicyManager.executeForMany}.
address constant EXTERNAL_POLICY_AUTHENTICATOR = address(uint160(uint256(keccak256("externalPolicyCaller"))));

/// @title PolicyManager
///
/// @notice Minimal, self-contained reference policy manager for EIP-8130 actor policies. The account-acting {execute}
///         path (direct protocol dispatch from the account itself) resolves identity from the transaction-context
///         precompile, so it is only usable on EIP-8130 chains; the external-caller {executeFor} / {executeForMany}
///         paths derive identity from `msg.sender` and work on any chain.
///
/// @dev The account registers this manager as an execution-enabled actor and gates a restricted session key with
///      `scope & Scopes.POLICY != 0` and `policy_manager = address(this)`, so the protocol routes that key's calls
///      here. Authorization is the account's signed commitment: the keccak256 of a {PolicyBinding}, stored in
///      Keystore. Every entrypoint recomputes the commitment from the supplied binding and requires it to match, so
///      config, validity window, and owning account are authenticated in one check with no config stored here.
///
///      All entrypoints deliberately share one {ReentrancyGuard} status; do not split it per entrypoint. The
///      transaction-context actorId is global to the transaction, so a shared guard is what stops a reentrant
///      {execute} from resolving a different account's identity mid-call.
contract PolicyManager is ReentrancyGuard {
    using Address for address;

    /// @notice The EIP-8130 Keystore system contract used to resolve signed policy commitments.
    Keystore public immutable KEYSTORE;

    /// @notice Deploys the manager bound to a Keystore instance.
    /// @param keystore Address of the EIP-8130 Keystore system contract.
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

    /// @notice Emitted for each successful policy execution (a non-empty account call).
    ///
    /// @param account    Account the plan executed against.
    /// @param policy     Policy contract that produced the plan.
    /// @param commitment Binding commitment that authorized the execution.
    /// @param caller     Address that drove the execution (the account for {execute}, the external caller otherwise).
    event PolicyExecuted(address indexed account, address indexed policy, bytes32 indexed commitment, address caller);

    /// @notice Emitted by {executeForMany} when one account is skipped because its per-account enforcement reverted
    ///         (e.g. revoked/expired binding, over budget, or a failing account call).
    ///
    /// @param account Account whose entry was skipped.
    /// @param policy  Policy contract for the skipped binding.
    /// @param actorId Acting external caller's actorId.
    event ExecutionSkipped(address indexed account, address indexed policy, bytes32 indexed actorId);

    /// @notice The current time is outside the binding's `[validAfter, validUntil)` execution window.
    error OutsideValidityWindow(uint40 validAfter, uint40 validUntil, uint256 timestamp);

    /// @notice The supplied binding does not recompute to the actor's live signed commitment.
    error BindingCommitmentMismatch(bytes32 expected, bytes32 actual);

    /// @notice {execute} requires `binding.account == msg.sender` (the protocol-dispatched account).
    error InvalidBindingAccount(address expected, address actual);

    /// @notice The acting actor has no policy binding that routes here: it is not policy-gated, or (on the external
    ///         path) the account did not gate this manager for it, or its signed commitment is zero.
    error NoActivePolicy(bytes32 actorId);

    /// @notice The acting actor is not a live external-pull actor of the account (unknown, revoked, expired, or its
    ///         authenticator is not {EXTERNAL_POLICY_AUTHENTICATOR}). Enforced on the external path, which has no
    ///         protocol auth to reject it first.
    error InvalidActor(bytes32 actorId);

    /// @notice {executeForMany} was given `bindings` and `executionData` of differing lengths.
    error LengthMismatch();

    /// @notice The {executeForMany} self-call boundary was invoked by someone other than this contract.
    error OnlySelf();

    /// @notice Computes the commitment (binding identifier) for a binding.
    ///
    /// @param binding Full policy binding to hash.
    ///
    /// @return The binding commitment: keccak256 over the binding fields, with the config bound by its own hash.
    function commitmentOf(PolicyBinding calldata binding) public pure returns (bytes32) {
        return _commitment(binding);
    }

    /// @notice Exercises a policy authorized by the account's signed commitment and forwards the resulting call plan
    ///         to the account.
    ///
    /// @dev Reverts with InvalidBindingAccount when `binding.account != msg.sender`.
    /// @dev Reverts with NoActivePolicy when the acting actor has no signed policy commitment.
    /// @dev Reverts with BindingCommitmentMismatch when `binding` does not recompute to the signed commitment.
    /// @dev Reverts with OutsideValidityWindow when the current time is outside `[validAfter, validUntil)`.
    /// @dev Bubbles up the policy or account-call revert reason when the forwarded call reverts.
    /// @dev Account-acting path only: identity is read from the transaction-context precompile and the account is
    ///      `msg.sender`, so it is usable only on EIP-8130 chains. Actor liveness is enforced by the protocol before
    ///      dispatch and not re-checked here.
    ///
    /// @param binding       Full account-authorized binding (config, window, salt).
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

    /// @notice External-caller variant of {execute}: an external party drives a policy an account authorized for it
    ///         (e.g. a subscription provider), rather than a key on the account.
    ///
    /// @dev Reverts with InvalidActor when the caller is not a live external-pull actor of `binding.account`.
    /// @dev Reverts with NoActivePolicy when the account has not gated this manager for the caller.
    /// @dev Reverts with BindingCommitmentMismatch when `binding` does not recompute to the signed commitment.
    /// @dev Reverts with OutsideValidityWindow when the current time is outside `[validAfter, validUntil)`.
    /// @dev Bubbles up the policy or account-call revert reason when the forwarded call reverts.
    /// @dev Identity is the caller (`ActorId.fromAddress(msg.sender)`); works on any chain. Unlike {execute}, it
    ///      re-verifies the actor and manager binding since there is no protocol routing.
    ///
    /// @param binding       Full account-authorized binding (config, window, salt).
    /// @param executionData Per-use action parameters interpreted by the policy.
    function executeFor(PolicyBinding calldata binding, bytes calldata executionData) external nonReentrant {
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
    /// @dev Reverts with OnlySelf when the caller is not this contract.
    /// @dev Reverts via {_enforceExternal} with InvalidActor, NoActivePolicy, BindingCommitmentMismatch, or
    ///      OutsideValidityWindow, or bubbles the forwarded call's revert.
    ///
    /// @param binding       Full account-authorized binding (config, window, salt).
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

    /// @dev External-path validation then {_enforce}. Reverts with InvalidActor when the caller's stored
    ///      authenticator is not EXTERNAL_POLICY_AUTHENTICATOR, NoActivePolicy when this manager is not gated for the
    ///      caller or the signed commitment is zero, or BindingCommitmentMismatch when `binding` does not recompute
    ///      to the signed commitment.
    function _enforceExternal(
        PolicyBinding calldata binding,
        bytes32 actorId,
        bytes calldata executionData,
        address caller
    ) internal {
        address account = binding.account;

        (Keystore.ActorConfig memory config, address manager, bytes32 signed) =
            KEYSTORE.getActorWithPolicy(account, actorId);
        if (config.authenticator != EXTERNAL_POLICY_AUTHENTICATOR) revert InvalidActor(actorId);
        if (manager != address(this)) revert NoActivePolicy(actorId);

        bytes32 commitment = _commitment(binding);
        if (signed == bytes32(0)) revert NoActivePolicy(actorId);
        if (signed != commitment) revert BindingCommitmentMismatch(signed, commitment);

        _enforce(binding, commitment, executionData, caller);
    }

    /// @dev Enforces the binding's validity window, runs the policy hooks, forwards the account call, then
    ///      post-executes. Reverts with OutsideValidityWindow outside `[validAfter, validUntil)`; bubbles the policy
    ///      or account-call revert. Emits {PolicyExecuted} on a non-empty account call.
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

    /// @dev Reads the in-flight transaction's authenticated actorId from the transaction-context precompile.
    ///      Returns bytes32(0) when not protocol-dispatched or the precompile is absent (accepts only a 32-byte
    ///      return).
    function _actingActorId() internal view returns (bytes32 actorId) {
        (bool ok, bytes memory ret) = TX_CONTEXT_ADDRESS.staticcall(
            abi.encodeWithSelector(ITransactionContext.getTransactionSenderActorId.selector)
        );
        if (ok && ret.length == 32) actorId = abi.decode(ret, (bytes32));
    }

    /// @dev Computes the binding commitment: keccak256 over the binding fields, with the config bound by its hash.
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
