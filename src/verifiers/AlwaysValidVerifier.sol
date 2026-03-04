// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IAuthVerifier} from "./IAuthVerifier.sol";

/// @notice Verifier that always returns true — no signature data required.
///
///         Use case: keyless privacy relay. The account registers an AlwaysValid
///         key with `disableGasPayment = true` so it cannot drain ETH. Anyone
///         can then submit transactions on behalf of the account — gas is paid
///         by a separate payer or acquired during committed_calldata.
///
///         WARNING: An AlwaysValid key authorizes ANY transaction for the account.
///
contract AlwaysValidVerifier is IAuthVerifier {
    function verify(address, bytes32, bytes32, bytes calldata) external pure returns (bool) {
        return true;
    }
}
