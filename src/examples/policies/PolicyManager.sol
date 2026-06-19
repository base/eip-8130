// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ReentrancyGuard} from "openzeppelin/utils/ReentrancyGuard.sol";
import {Address} from "openzeppelin/utils/Address.sol";

import {IAccountConfiguration} from "../../interfaces/IAccountConfiguration.sol";
import {ITransactionContext, TX_CONTEXT_ADDRESS} from "../../interfaces/ITransactionContext.sol";
import {Policy} from "./Policy.sol";

/// @title PolicyManager
///
/// @notice Minimal, self-contained reference policy manager for EIP-8130 actor policies.
///
/// @dev Role in the EIP-8130 flow:
///      - The manager is registered as an execution-enabled actor on the account (an actor whose authenticator is
///        `EXTERNAL_CALLER_AUTHENTICATOR`), so it may drive the account via `executeBatch`.
///      - A restricted session-key actor is configured with a non-zero `policyType` and `policy_manager =
///        address(this)`, so the protocol gate forces every call that actor makes to land on this manager.
///      - When the session key transacts, the protocol dispatches its call *as the account*, so `msg.sender`
///        here is the account itself. That is the authorization boundary: only a gated session-key transaction
///        (routed through the account) can invoke {execute}.
///
///      Commitment binding: the account authorizes a {PolicyBinding}; its `keccak256` is the `commitment`. When the
///      account authorizes the session-key actor it stores a non-zero `policyType`, `policy_manager = address(this)`, and
///      `policy_commitment = commitment` in the Account Configuration contract. At {install} the manager reads that
///      binding back via the single-SLOAD {IAccountConfiguration.getPolicyManager} / {IAccountConfiguration.getPolicyCommitment}
///      accessors and requires the target and commitment to match, so an install can only succeed for a policy the
///      account actually signed for this manager.
///
///      Scope: install-by-direct-account-call and execute only. Signature-based install, replacement, and
///      uninstall are intentionally omitted from this reference.
contract PolicyManager is ReentrancyGuard {
    using Address for address;

    /// @notice The EIP-8130 Account Configuration system contract used to resolve signed policy commitments.
    IAccountConfiguration public immutable ACCOUNT_CONFIGURATION;

    constructor(address accountConfiguration) {
        ACCOUNT_CONFIGURATION = IAccountConfiguration(accountConfiguration);
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

    error PolicyNotInstalled(bytes32 commitment);
    error PolicyAlreadyInstalled(bytes32 commitment);
    error UnauthorizedAccount(address caller, address account);
    error OutsideValidityWindow(uint40 validAfter, uint40 validUntil, uint256 timestamp);
    error CommitmentNotAuthorized(bytes32 actorId, address target, bytes32 commitment);
    /// @dev The acting actor (from the transaction-context precompile) has no live policy commitment for the
    ///      caller account — i.e. it is not a gated actor of this account, or it has been revoked/expired.
    error NoActivePolicy(bytes32 actorId);

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
    /// @dev MUST be called by `binding.account`. The manager re-derives the binding's `commitment` and confirms the
    ///      account signed it for this manager by reading the resolved policy manager and commitment for `actorId`
    ///      (via the granular accessors): the resolved target must be this manager and the resolved commitment must
    ///      equal the binding's. The committed `policyConfig` is then handed to the policy's install hook, which
    ///      stores it keyed by commitment.
    ///
    /// @param actorId The session-key actor the account configured with this policy (non-zero policyType).
    /// @param binding The account-authorized binding.
    ///
    /// @return commitment The binding's commitment.
    function install(bytes32 actorId, PolicyBinding calldata binding) external returns (bytes32 commitment) {
        if (msg.sender != binding.account) revert UnauthorizedAccount(msg.sender, binding.account);

        commitment = _commitment(binding);

        // The account must have signed this exact commitment for this manager when authorizing `actorId`. Read the
        // gate target and signed commitment via the single-SLOAD granular accessors: the manager never needs the
        // policyType byte, so this avoids the extra ActorConfig SLOAD that getPolicy performs.
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

        PolicyRecord storage record = _policies[policy][commitment];
        if (!record.installed) revert PolicyNotInstalled(commitment);

        if (
            (record.validAfter != 0 && block.timestamp < record.validAfter)
                || (record.validUntil != 0 && block.timestamp >= record.validUntil)
        ) {
            revert OutsideValidityWindow(record.validAfter, record.validUntil, block.timestamp);
        }

        bytes memory accountCallData = Policy(policy).onExecute(commitment, account, executionData, account);
        if (accountCallData.length == 0) return;

        account.functionCall(accountCallData);
        emit PolicyExecuted(account, policy, commitment, account);
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
