// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfiguration} from "../../src/AccountConfiguration.sol";

/// @notice Formal-verification / invariant-testing harness for {AccountConfiguration}.
/// @dev Adds *read-only* accessors for `internal` storage that the public interface intentionally hides behind the
///      merged self-home view (see {AccountConfiguration.getActorConfig}). The invariants we want to prove — most
///      importantly the mutual exclusion of the inline-k1 self and the non-k1 self — are about the *raw* storage
///      state, which the merged view cannot distinguish. This contract adds no state and overrides no behavior; the
///      deployed logic under test is byte-for-byte the base contract.
contract AccountConfigurationHarness is AccountConfiguration {
    /// @notice Raw `_actorConfig[actorId][account].authenticator`, without the inline-self synthesis that
    ///         {getActorConfig} applies. `address(0)` means "no explicit `_actorConfig` entry".
    function h_actorConfigAuthenticator(address account, bytes32 actorId) external view returns (address) {
        return _actorConfig[actorId][account].authenticator;
    }

    function h_actorConfigScope(address account, bytes32 actorId) external view returns (uint8) {
        return _actorConfig[actorId][account].scope;
    }

    function h_actorConfigExpiry(address account, bytes32 actorId) external view returns (uint48) {
        return _actorConfig[actorId][account].expiry;
    }

    function h_actorConfigPolicyType(address account, bytes32 actorId) external view returns (uint8) {
        return _actorConfig[actorId][account].policyType;
    }

    /// @notice Raw `AccountState.flags` byte.
    function h_flags(address account) external view returns (uint8) {
        return _accountState[account].flags;
    }

    /// @notice True when the inline-k1 self (the implicit/scoped default EOA in `AccountState`) is live — i.e. the
    ///         FLAG_REVOKE_DEFAULT_EOA bit is unset. This is the exact predicate `_authenticateK1` gates on.
    function h_inlineSelfLive(address account) external view returns (bool) {
        return _accountState[account].flags & FLAG_REVOKE_DEFAULT_EOA == 0;
    }

    /// @notice True when a *non-k1* self authenticator occupies the `_actorConfig` self home.
    function h_nonK1SelfLive(address account) external view returns (bool) {
        return _actorConfig[bytes32(bytes20(account))][account].authenticator > K1_AUTHENTICATOR;
    }

    function h_inlineSelfScope(address account) external view returns (uint8) {
        return _accountState[account].defaultEOAScope;
    }

    function h_inlineSelfPolicyType(address account) external view returns (uint8) {
        return _accountState[account].defaultEOAPolicyType;
    }

    function h_inlineSelfExpiry(address account) external view returns (uint48) {
        return _accountState[account].defaultEOAExpiry;
    }

    /// @notice Raw policy-slot reads (identical to the public accessors, mirrored here for symmetry in specs).
    function h_policyCommitment(address account, bytes32 actorId) external view returns (bytes32) {
        return _policyCommitment[actorId][account];
    }

    function h_policyManager(address account, bytes32 actorId) external view returns (address) {
        return _policyManager[actorId][account];
    }

    function h_selfActorId(address account) external pure returns (bytes32) {
        return bytes32(bytes20(account));
    }

    // ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
    // SYMBOLIC-VERIFICATION WRAPPERS
    //
    // Direct entrypoints to the internal state-machine units, so a symbolic engine (Halmos) can verify them over the
    // full input domain *without* modeling `ecrecover` (the signature gate on the public change path). These call the
    // exact same internal functions the production paths use; they add no logic of their own.
    // ─────────────────────────────────────────────────────────────────────────────────────────────────────────────

    function sym_slicePolicy(uint8 policyType, bytes calldata policyData)
        external
        pure
        returns (address manager, bytes32 commitment)
    {
        return _slicePolicy(policyType, policyData);
    }

    function sym_authorizeActor(
        address account,
        bytes32 actorId,
        AccountConfiguration.ActorConfig calldata config,
        bytes calldata policyData
    ) external {
        _authorizeActor(account, actorId, config, policyData);
    }

    function sym_revokeActor(address account, bytes32 actorId) external {
        _revokeActor(account, actorId);
    }
}
