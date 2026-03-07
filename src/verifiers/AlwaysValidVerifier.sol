// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IAuthVerifier} from "./IAuthVerifier.sol";

/// @notice Verifier that always returns the provided ownerId — no signature data required.
///
///         Use case: keyless privacy relay. Anyone can submit transactions on behalf
///         of the account — gas is paid by a separate payer or acquired during
///         committed_calldata.
///
///         WARNING: An AlwaysValid owner authorizes ANY transaction for the account.
///
contract AlwaysValidVerifier is IAuthVerifier {
    function verify(bytes32, bytes calldata data) external pure returns (bytes32 ownerId) {
        if (data.length >= 32) {
            ownerId = bytes32(data[:32]);
        }
    }
}
