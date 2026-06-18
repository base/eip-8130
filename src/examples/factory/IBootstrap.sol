// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @notice Minimal interface a SETDELEGATE-factory implementation must expose for atomic bootstrap.
///
///         A bootstrap-aware implementation:
///           - Accepts a single `bootstrap(actorsHash)` call from the factory before `importAccount` runs.
///           - In its ERC-1271 `isValidSignature`, while `AccountConfiguration.getChangeSequences(this).local == 0`,
///             validates that the presented digest equals the canonical EIP-8130 `ActorInitialization` digest
///             reconstructed from the stored `actorsHash`.
///           - After bootstrap (once AccountConfiguration records the local sequence as 1), permanently switches
///             to deferring `isValidSignature` to `AccountConfiguration`.
interface IBootstrap {
    /// @notice Prime the implementation's bootstrap state with the typed actors hash.
    /// @param actorsHash The inner hash of the EIP-8130 `ActorInitialization` digest for the initial actor set:
    ///                   `keccak256(actorHash_0 || ... || actorHash_n)`.
    function bootstrap(bytes32 actorsHash) external;
}
