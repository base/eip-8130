// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {DefaultAccount} from "./DefaultAccount.sol";

struct PackedUserOperation {
    address sender;
    uint256 nonce;
    bytes initCode;
    bytes callData;
    bytes32 accountGasLimits;
    uint256 preVerificationGas;
    bytes32 gasFees;
    bytes paymasterAndData;
    bytes signature;
}

/// @notice Universal ERC-4337 + EIP-8130 account implementation.
///         Extends DefaultAccount with validateUserOp for ERC-4337 backward compatibility.
///
///         Designed to be THE permanent wallet — users never upgrade the implementation.
///         New capabilities are added by registering owners/verifiers via AccountConfiguration.
///
///         Supports:
///           - EIP-8130 direct dispatch (msg.sender = from, always authorized as self-call)
///           - ERC-4337 via validateUserOp (ENTRY_POINT hardcoded as always authorized)
///           - Account Policies (PolicyManager registered with EXTERNAL_CALLER_VERIFIER)
///           - ERC-1271 signature validation via AccountConfiguration
///
///         The EntryPoint is an immutable — guaranteed authorized at the implementation level
///         so accounts can never be bricked by a missing initial owner registration.
///         Other external callers go through AccountConfiguration + EXTERNAL_CALLER_VERIFIER.
contract ERC4337Account is DefaultAccount {
    address public immutable ENTRY_POINT;

    constructor(address accountConfiguration, address entryPoint) DefaultAccount(accountConfiguration) {
        ENTRY_POINT = entryPoint;
    }

    /// @notice Validates a UserOperation signature via the AccountConfiguration system.
    ///         Signature format follows 8130 verifier conventions (verifier_type || data).
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256 validationData)
    {
        require(_isAuthorizedCaller(msg.sender));

        (bool valid,,) = ACCOUNT_CONFIGURATION.verifySignature(address(this), userOpHash, userOp.signature);
        validationData = valid ? 0 : 1;

        if (missingAccountFunds != 0) {
            assembly {
                pop(call(gas(), caller(), missingAccountFunds, 0, 0, 0, 0))
            }
        }
    }

    function _isAuthorizedCaller(address caller) internal view override returns (bool) {
        return caller == ENTRY_POINT || super._isAuthorizedCaller(caller);
    }
}
