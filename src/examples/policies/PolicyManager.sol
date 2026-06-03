// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ReentrancyGuard} from "openzeppelin/utils/ReentrancyGuard.sol";
import {Address} from "openzeppelin/utils/Address.sol";

import {Policy} from "./Policy.sol";

/// @title PolicyManager
///
/// @notice Minimal, self-contained reference policy manager for EIP-8130 `policyType = 0x02`.
///
/// @dev Role in the EIP-8130 flow:
///      - The manager is registered as an execution-enabled owner on the account (an owner whose verifier is
///        `EXTERNAL_CALLER_VERIFIER`), so it may drive the account via `executeBatch`.
///      - A restricted session-key owner is configured with `policyType = 0x02` and `policyTarget = address(this)`,
///        so the protocol gate forces every call that owner makes to land on this manager.
///      - When the session key transacts, the protocol dispatches its call *as the account*, so `msg.sender`
///        here is the account itself. That is the authorization boundary: only a gated session-key transaction
///        (routed through the account) can invoke {execute}.
///
///      Commitment binding: the account authorizes a {PolicyBinding}; its `keccak256` is the `commitment`. This is
///      the example analogue of the signed, opaque commitment stored per-owner by the protocol. (This reference
///      keeps the commitment in the manager; a future version can instead verify it against the account's
///      protocol-stored `policy_commitment` once the system contract exposes it.)
///
///      Scope: install-by-direct-account-call and execute only. Signature-based install, replacement, and
///      uninstall are intentionally omitted from this reference.
contract PolicyManager is ReentrancyGuard {
    using Address for address;

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

    /// @notice Installs a policy binding. MUST be called by `binding.account`.
    ///
    /// @dev In EIP-8130 this is performed by the account (e.g. authorized by the account's root owner). The
    ///      committed `policyConfig` is handed to the policy's install hook, which stores it keyed by commitment.
    ///
    /// @param binding The account-authorized binding.
    ///
    /// @return commitment The binding's commitment.
    function install(PolicyBinding calldata binding) external returns (bytes32 commitment) {
        if (msg.sender != binding.account) revert UnauthorizedAccount(msg.sender, binding.account);

        commitment = _commitment(binding);
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
    /// @dev Authorization is `msg.sender == account`: in EIP-8130 the protocol dispatches a gated session key's
    ///      call as the account, so only such a transaction reaches here. The manager then drives the account as
    ///      an execution-enabled owner via the policy-built `accountCallData`.
    ///
    /// @param policy        Policy contract for the binding.
    /// @param commitment    Identifier of the installed binding.
    /// @param executionData Per-use action parameters interpreted by the policy.
    function execute(address policy, bytes32 commitment, bytes calldata executionData) external nonReentrant {
        PolicyRecord storage record = _policies[policy][commitment];
        if (!record.installed) revert PolicyNotInstalled(commitment);
        if (msg.sender != record.account) revert UnauthorizedAccount(msg.sender, record.account);

        if (
            (record.validAfter != 0 && block.timestamp < record.validAfter)
                || (record.validUntil != 0 && block.timestamp >= record.validUntil)
        ) {
            revert OutsideValidityWindow(record.validAfter, record.validUntil, block.timestamp);
        }

        bytes memory accountCallData = Policy(policy).onExecute(commitment, record.account, executionData, msg.sender);
        if (accountCallData.length == 0) return;

        record.account.functionCall(accountCallData);
        emit PolicyExecuted(record.account, policy, commitment, msg.sender);
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
