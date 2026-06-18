// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IAccountConfiguration} from "../../interfaces/IAccountConfiguration.sol";

/// @notice Minimal interface a SETDELEGATE-factory implementation must expose for atomic bootstrap.
///
///         A bootstrap-aware implementation:
///           - Exposes a single `bootstrap(actorsHash, initialActors)` entrypoint that the factory calls in the
///             same tx frame as `SETDELEGATE`. It primes a transient latch, drives `importAccount` on itself, then
///             clears the latch.
///           - In its ERC-1271 `isValidSignature`, while that transient latch is set, validates that the presented
///             digest equals the canonical EIP-8130 `ActorInitialization` digest reconstructed from `actorsHash`.
///           - In every other context permanently defers `isValidSignature` to `AccountConfiguration`.
///
///         This requires no changes to AccountConfiguration: the bootstrap window is tracked entirely by the
///         account's own transient state rather than by reading AccountConfiguration's local sequence.
interface IBootstrap {
    /// @notice Prime the bootstrap latch and atomically import the actor set.
    /// @param actorsHash    The inner hash of the EIP-8130 `ActorInitialization` digest for the initial actor set:
    ///                       `keccak256(actorHash_0 || ... || actorHash_n)`.
    /// @param initialActors The actor set to import. MUST correspond to `actorsHash`.
    function bootstrap(bytes32 actorsHash, IAccountConfiguration.InitialActor[] calldata initialActors) external;
}
