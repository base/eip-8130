// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {LibCall} from "solady/utils/LibCall.sol";

import {Call} from "../interfaces/IExecuteBatch.sol";
import {ITransactionContext, TX_CONTEXT_ADDRESS} from "../interfaces/ITransactionContext.sol";
import {Policy} from "../policies/Policy.sol";
import {PolicyBinding} from "../policies/PolicyBinding.sol";
import {DefaultAccount} from "./DefaultAccount.sol";

/// @title PolicyAccount
///
/// @notice EXPLORATION of Option D: the account is its own policy manager. Instead of gating policy-scoped keys to a
///         separate {PolicyManager} contract, the protocol gates them to this account's {executeForPolicy} entrypoint;
///         that entrypoint resolves the acting actor, runs the bound policy (which self-authenticates against the
///         Keystore), and executes the resulting plan natively — so there is no wallet-ABI encoding seam at all.
///
/// @dev NOT production-ready; a draft to evaluate Option D against the transformer (#108) and shared-policy self-auth
///      (#110) designs. It stacks on #110: the shared {Policy} is reused unchanged, with this account playing the
///      manager role (it registers ITSELF as the actor's `policy_manager`, and calls the policy as `msg.sender`, so
///      `Policy._authenticate`'s `msg.sender == installed manager` check passes).
///
///      SAFETY IS LOAD-BEARING ON A PROTOCOL CHANGE. The 8130 gate must route a policy-scoped key to
///      `(call.to == account, selector == executeForPolicy)`, NOT merely `call.to == account`. Today the gate
///      constrains only `call.to`. Without selector-level gating a policy key could instead call {executeBatch}:
///      on the account-acting path the protocol dispatches the key AS the account, so `msg.sender == address(this)`,
///      and {DefaultAccount._isAuthorizedCaller} authorizes any self-call — i.e. the policy key would gain
///      unrestricted root execution. See test `test_executeBatch_selfCallBypass_isRoot`.
///
///      The upside (the reason to explore this): with selector-gating, {executeBatch} and every other operational
///      function keep their cheap `msg.sender == address(this)` authorization with NO per-call actorId/scope read on
///      the hot path. Only {executeForPolicy} pays for actor scrutiny, because it is the only function policy keys
///      are routed to.
///
///      Known gaps in this prototype (see the PR description):
///        - Only the account-acting (session-key) path is modeled; the external-caller (subscription) path is TODO.
///        - No reentrancy guard: the separate {PolicyManager} had one; an account-as-manager would need its own.
///        - Native execution here does not share {DefaultAccount}/{CanonicalHighRatePayerAccount} execution
///          invariants (e.g. the payer lock); a real impl should route through shared execution logic.
///
/// @author Coinbase
contract PolicyAccount is DefaultAccount {
    constructor(address keystore) DefaultAccount(keystore) {}

    /// @notice Policy-execution entrypoint: runs a bound policy and executes its plan natively as the account.
    ///
    /// @dev Reverts via {Policy.onExecute} (PolicyMismatch / NoActivePolicy / UnauthorizedManager /
    ///      CommitmentMismatch / OutsideValidityWindow) when the supplied binding fails self-authentication against
    ///      the Keystore. Bubbles up any inner call's revert reason.
    /// @dev Account-acting path only: the acting actor is read from the transaction-context precompile, so this is
    ///      usable only on EIP-8130 chains and only when protocol-dispatched. Protocol selector-gating (see the
    ///      contract-level notes) is what prevents a policy key from reaching {executeBatch} instead of this function.
    ///
    /// @param binding       Full account-authorized policy binding (`policy` set; `account == address(this)`).
    /// @param executionData Per-use action parameters interpreted by the policy.
    function executeForPolicy(PolicyBinding calldata binding, bytes calldata executionData) external {
        bytes32 actorId = _actingActorId();
        (Call[] memory calls,) = Policy(binding.policy).onExecute(binding, actorId, executionData, address(this));
        for (uint256 i; i < calls.length; i++) {
            (bool success, bytes memory result) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            if (!success) LibCall.bubbleUpRevert(result);
        }
    }

    /// @dev Reads the in-flight transaction's authenticated actorId from the transaction-context precompile.
    function _actingActorId() internal view returns (bytes32 actorId) {
        (bool ok, bytes memory ret) = TX_CONTEXT_ADDRESS.staticcall(
            abi.encodeWithSelector(ITransactionContext.getTransactionSenderActorId.selector)
        );
        if (ok && ret.length == 32) actorId = abi.decode(ret, (bytes32));
    }
}
