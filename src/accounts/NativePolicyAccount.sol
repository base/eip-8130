// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {ReentrancyGuard} from "openzeppelin/utils/ReentrancyGuard.sol";
import {LibCall} from "solady/utils/LibCall.sol";

import {Keystore} from "../Keystore.sol";
import {Call} from "../interfaces/IExecuteBatch.sol";
import {ITransactionContext, TX_CONTEXT_ADDRESS} from "../interfaces/ITransactionContext.sol";
import {ActorId} from "../libraries/ActorId.sol";
import {Scopes} from "../libraries/Scopes.sol";
import {Policy} from "../policies/Policy.sol";
import {PolicyBinding, PolicyBindingLib} from "../policies/PolicyBinding.sol";
import {EXTERNAL_POLICY_AUTHENTICATOR} from "../policies/PolicyManager.sol";
import {DefaultAccount} from "./DefaultAccount.sol";

/// @title NativePolicyAccount
/// @notice Exploration: account-first policy execution, without protocol selector gating or a separate manager.
/// @dev NOT production-ready. Install policy actors with manager = this account. The policy address is revealed
///      by the signed binding, not another Keystore field. Both policy entrypoints authenticate that binding before
///      calling any policy code. Shared policies self-authenticate unchanged, then return a native Call[] plan.
///
///      Unlike DefaultAccount, self-caller status is never sufficient for operational authority: self-calls require
///      a transaction context belonging to this account and a live operational actor. External operational callers
///      retain DefaultAccount's k1-only rule. All execution entrypoints share a reentrancy guard, and policy plans
///      execute internally, never by externally self-calling executeBatch or temporarily granting root authority.
///
///      Extensions MUST guard every privileged entrypoint (including custom conditional functions) and use the
///      shared execution helpers. Administrative changes require admin authority, not merely OPERATOR. This spike
///      implements the single-account execute/executeFor conventions, NOT IPolicyManager.executeForMany.
contract NativePolicyAccount is DefaultAccount, ReentrancyGuard {
    using PolicyBindingLib for PolicyBinding;

    error InvalidBindingAccount();
    error InvalidPolicyActor(bytes32 actorId);
    error NoActivePolicy(bytes32 actorId);
    error BindingCommitmentMismatch();
    error OutsideValidityWindow();
    error AccountLocked();

    event PolicyExecuted(bytes32 indexed actorId, address indexed policy, bytes32 indexed commitment, address caller);

    constructor(address keystore) DefaultAccount(keystore) {}

    /// @dev Use with nonReentrant on every operational entrypoint in derived accounts.
    modifier onlyOperationalActor() {
        if (!_isAuthorizedCaller(msg.sender)) revert UnauthorizedCaller();
        _;
    }

    /// @dev Use with nonReentrant on every administrative entrypoint in derived accounts.
    modifier onlyAdminActor() {
        Keystore.ActorConfig memory config = _callerConfig(msg.sender);
        if (config.authenticator == address(0) || config.scope != 0) revert UnauthorizedCaller();
        _;
    }

    /// @notice Operational batch execution; restricted self-calls cannot bypass policy enforcement.
    function executeBatch(Call[] calldata calls) external override onlyOperationalActor nonReentrant {
        _executeCalls(calls);
    }

    /// @notice Operational single-call execution through the same execution safeguards as policy plans.
    function execute(address target, uint256 value, bytes calldata data)
        external
        override
        onlyOperationalActor
        nonReentrant
    {
        _executeCall(Call(target, value, data));
    }

    /// @notice Session-key entrypoint, matching the single-account PolicyManager use-time ABI.
    /// @dev The protocol gate is address-only: call.to == account. No special selector or callback is needed.
    function execute(PolicyBinding calldata binding, bytes calldata executionData) external nonReentrant {
        if (msg.sender != address(this)) revert UnauthorizedCaller();
        bytes32 actorId = _transactionActorId();
        if (actorId == bytes32(0)) revert UnauthorizedCaller();
        _executePolicy(binding, actorId, executionData, true);
    }

    /// @notice External subscription caller. Identity is the immediate caller, not tx.origin or transaction actor.
    /// @dev One actor slot per (account, caller address), matching the existing external-pull convention. A router
    ///      changes msg.sender and must itself be authorized; arbitrary forwarded caller arguments are not accepted.
    function executeFor(PolicyBinding calldata binding, bytes calldata executionData) external nonReentrant {
        _executePolicy(binding, ActorId.fromAddress(msg.sender), executionData, false);
    }

    function commitmentOf(PolicyBinding calldata binding) external pure returns (bytes32) {
        return binding.commitment();
    }

    function _executePolicy(
        PolicyBinding calldata binding,
        bytes32 actorId,
        bytes calldata executionData,
        bool accountActing
    ) internal {
        if (binding.account != address(this)) revert InvalidBindingAccount();
        (Keystore.ActorConfig memory config, address manager, bytes32 signed) =
            KEYSTORE.getActorWithPolicy(address(this), actorId);

        if (accountActing) {
            if (
                config.authenticator == address(0) || config.authenticator == EXTERNAL_POLICY_AUTHENTICATOR
                    || config.scope & Scopes.POLICY == 0 || Scopes.isOperator(config.scope)
            ) revert InvalidPolicyActor(actorId);
        } else if (config.authenticator != EXTERNAL_POLICY_AUTHENTICATOR) {
            revert InvalidPolicyActor(actorId);
        }
        if (manager != address(this) || signed == bytes32(0)) revert NoActivePolicy(actorId);
        bytes32 commitment = binding.commitment();
        if (signed != commitment) revert BindingCommitmentMismatch();
        if (
            (binding.validAfter != 0 && block.timestamp < binding.validAfter)
                || (binding.validUntil != 0 && block.timestamp >= binding.validUntil)
        ) revert OutsideValidityWindow();

        // Do not rely ONLY on the policy's self-authentication: an uninstalled malicious policy could skip it.
        (Call[] memory calls, bytes memory postCallData) =
            Policy(binding.policy).onExecute(binding, actorId, executionData, msg.sender);
        if (calls.length == 0) return; // Matches PolicyManager's empty-plan semantics.
        _executeCalls(calls);
        Policy(binding.policy).onPostExecute(binding, actorId, postCallData);
        emit PolicyExecuted(actorId, binding.policy, commitment, msg.sender);
    }

    /// @dev Both policy and operational paths preserve this account's execution invariants.
    function _executeCalls(Call[] memory calls) internal {
        for (uint256 i; i < calls.length; ++i) {
            _executeCall(calls[i]);
        }
    }

    function _executeCall(Call memory call_) internal returns (bytes memory result) {
        bool success;
        (success, result) = _tryExecuteCall(call_);
        if (!success) LibCall.bubbleUpRevert(result);
    }

    /// @dev Allows operational extensions to implement try/fallback logic without duplicating transfer safeguards.
    ///      Account invariant failures revert; only destination-call failures are returned for optional recovery.
    function _tryExecuteCall(Call memory call_) internal returns (bool success, bytes memory result) {
        if (call_.value != 0) {
            (bool locked,,,) = KEYSTORE.getLockStatus(address(this));
            if (locked) revert AccountLocked();
        }
        return call_.target.call{value: call_.value}(call_.data);
    }

    function _isAuthorizedCaller(address caller) internal view override returns (bool) {
        Keystore.ActorConfig memory config = _callerConfig(caller);
        // Missing/revoked actors resolve to all-zero config. Never interpret their zero scope as admin.
        return config.authenticator != address(0) && Scopes.isOperator(config.scope);
    }

    function _callerConfig(address caller) internal view returns (Keystore.ActorConfig memory config) {
        if (caller == address(this)) {
            bytes32 actorId = _transactionActorId();
            if (actorId == bytes32(0)) return config;
            return KEYSTORE.getActorConfig(address(this), actorId);
        }
        config = KEYSTORE.getActorConfig(address(this), ActorId.fromAddress(caller));
        if (config.authenticator != KEYSTORE.K1_AUTHENTICATOR()) {
            // Preserve DefaultAccount's direct-caller authenticator boundary.
            return Keystore.ActorConfig({authenticator: address(0), expiry: 0, scope: 0});
        }
    }

    /// @dev Transaction context is not ambient caller authority. Callers must separately authenticate msg.sender.
    ///      Absent, reverting, malformed, zero, or another account's context fails closed.
    function _transactionActorId() internal view returns (bytes32 actorId) {
        (bool ok, bytes memory result) =
            TX_CONTEXT_ADDRESS.staticcall(abi.encodeCall(ITransactionContext.getTransactionSender, ()));
        if (!ok || result.length != 32 || abi.decode(result, (bytes32)) != bytes32(uint256(uint160(address(this))))) {
            return bytes32(0);
        }
        (ok, result) =
            TX_CONTEXT_ADDRESS.staticcall(abi.encodeCall(ITransactionContext.getTransactionSenderActorId, ()));
        if (ok && result.length == 32) actorId = abi.decode(result, (bytes32));
    }
}
