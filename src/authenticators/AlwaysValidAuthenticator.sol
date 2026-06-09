// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IAuthenticator} from "../interfaces/IAuthenticator.sol";

/// @notice Authenticator that always succeeds — no signature data required.
///
///         Returns a fixed actorId (keccak256("ALWAYS_VALID")). Register this actorId
///         with the AlwaysValidAuthenticator on your account to enable keyless submission.
///
///         Use case: keyless privacy relay. Anyone can submit transactions on behalf
///         of the account — gas is paid by a separate payer or acquired during
///         committed_calldata.
///
///         WARNING: An AlwaysValid actor authorizes ANY transaction for the account.
///
contract AlwaysValidAuthenticator is IAuthenticator {
    bytes32 public constant ACTOR_ID = keccak256("ALWAYS_VALID");

    function authenticate(bytes32, bytes calldata) external pure returns (bytes32) {
        return ACTOR_ID;
    }
}
