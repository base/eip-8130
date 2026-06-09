// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ReentrancyGuard} from "openzeppelin/utils/ReentrancyGuard.sol";
import {Address} from "openzeppelin/utils/Address.sol";

import {IAccountConfiguration} from "../../interfaces/IAccountConfiguration.sol";
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
///      binding back via {IAccountConfiguration.getPolicy} and requires the target and commitment to match, so an
///      install can only succeed for a policy the account actually signed for this manager.
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
    ///      account signed it for this manager by reading {IAccountConfiguration.getPolicy} for `actorId`: the
    ///      resolved target must be this manager and the resolved commitment must equal the binding's. The committed
    ///      `policyConfig` is then handed to the policy's install hook, which stores it keyed by commitment.
    ///
    /// @param actorId The session-key actor the account configured with this policy (non-zero policyType).
    /// @param binding The account-authorized binding.
    ///
    /// @return commitment The binding's commitment.
    function install(bytes32 actorId, PolicyBinding calldata binding) external returns (bytes32 commitment) {
        if (msg.sender != binding.account) revert UnauthorizedAccount(msg.sender, binding.account);

        commitment = _commitment(binding);

        // The account must have signed this exact commitment for this manager when authorizing `actorId`.
        (address target, bytes32 signedCommitment) = ACCOUNT_CONFIGURATION.getPolicy(binding.account, actorId);
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
    /// @dev Authorization is resolved per call against the live signed policy: in EIP-8130 the protocol dispatches a
    ///      gated session key's call as the account (`msg.sender == account`) and the manager identifies the acting
    ///      key via the transaction-context precompile. Here the caller supplies `actorId`, and the manager requires
    ///      `getPolicy(account, actorId)` to resolve to itself with a non-zero `commitment` — so a revoked or expired
    ///      actor (whose policy slots are cleared) can no longer execute, without relying on a cached record. The
    ///      manager then drives the account as an execution-enabled actor via the policy-built `accountCallData`.
    ///
    /// @param actorId       The session-key actor whose signed policy authorizes this call.
    /// @param policy        Policy contract for the binding.
    /// @param executionData Per-use action parameters interpreted by the policy.
    function execute(bytes32 actorId, address policy, bytes calldata executionData) external nonReentrant {
        address account = msg.sender;

        // Re-read the live signed policy every call; the key must still be gated to this manager.
        (address target, bytes32 commitment) = ACCOUNT_CONFIGURATION.getPolicy(account, actorId);
        if (target != address(this) || commitment == bytes32(0)) {
            revert CommitmentNotAuthorized(actorId, target, commitment);
        }

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
