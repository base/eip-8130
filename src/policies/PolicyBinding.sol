// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @notice Account-authorized policy binding. Its hash (see {PolicyBindingLib.commitment}) is the policy commitment
///         the account signs into the Keystore. Shared by {PolicyManager} and {Policy} so neither owns it.
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
    /// @dev Optional {IPolicyCallEncoder} that transforms the policy's wallet-agnostic {Call} plan into the account's
    ///      execution ABI. address(0) selects the default `executeBatch(Call[])` encoding. Bound into the commitment
    ///      so the account authorizes exactly which encoder runs.
    address transformer;
}

/// @title PolicyBindingLib
///
/// @notice Commitment derivation for a {PolicyBinding}.
///
/// @dev Shared by {PolicyManager} (which authenticates the binding against the actor's signed commitment) and
///      {Policy} (which re-derives the same commitment to self-authenticate), so both compute an identical value.
///
/// @author Coinbase
library PolicyBindingLib {
    /// @notice The binding commitment: keccak256 over the binding fields, with the config bound by its own hash.
    ///
    /// @param binding Full policy binding to hash.
    ///
    /// @return The binding commitment.
    function commitment(PolicyBinding calldata binding) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                binding.account,
                binding.policy,
                keccak256(binding.policyConfig),
                binding.validAfter,
                binding.validUntil,
                binding.salt,
                binding.transformer
            )
        );
    }
}
