// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Receiver} from "solady/accounts/Receiver.sol";

import {AccountConfiguration} from "../AccountConfiguration.sol";

struct Call {
    address target;
    uint256 value;
    bytes data;
}

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
///         Deployed behind ERC-1167 minimal proxy (45 bytes, deterministic pattern).
///
///         Designed to be THE permanent wallet — users never upgrade the implementation.
///         New capabilities are added by authorizing callers (PolicyManager, etc.)
///         and registering owners/verifiers via the AccountConfiguration system contract.
///
///         Supports:
///           - EIP-8130 direct dispatch (msg.sender = from, always authorized as self-call)
///           - ERC-4337 via validateUserOp (EntryPoint is always authorized)
///           - Account Policies via authorized caller (add PolicyManager as authorized caller)
///           - ERC-1271 signature validation via AccountConfiguration
///
///         Caller authorization (hardcoded, always authorized):
///           - address(this) — covers 8130 direct dispatch
///           - ENTRY_POINT — covers ERC-4337 on any chain, no setup required
///         Dynamic callers managed via authorizeCaller/revokeCaller (self-call only)
contract ERC4337Account is Receiver {
    AccountConfiguration public immutable ACCOUNT_CONFIGURATION;
    address public immutable ENTRY_POINT;

    mapping(address => bool) internal _authorizedCallers;

    event CallerAuthorized(address indexed caller);
    event CallerRevoked(address indexed caller);

    constructor(address accountConfiguration, address entryPoint) {
        ACCOUNT_CONFIGURATION = AccountConfiguration(accountConfiguration);
        ENTRY_POINT = entryPoint;
    }

    // ══════════════════════════════════════════════
    //  CALLER MANAGEMENT (self-call only)
    // ══════════════════════════════════════════════

    function authorizeCaller(address caller) external {
        require(msg.sender == address(this));
        _authorizedCallers[caller] = true;
        emit CallerAuthorized(caller);
    }

    function revokeCaller(address caller) external {
        require(msg.sender == address(this));
        delete _authorizedCallers[caller];
        emit CallerRevoked(caller);
    }

    function isAuthorizedCaller(address caller) external view returns (bool) {
        return _isAuthorizedCaller(caller);
    }

    // ══════════════════════════════════════════════
    //  EXECUTION
    // ══════════════════════════════════════════════

    function executeBatch(Call[] calldata calls) external {
        require(_isAuthorizedCaller(msg.sender));
        for (uint256 i; i < calls.length; i++) {
            (bool success,) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            require(success);
        }
    }

    // ══════════════════════════════════════════════
    //  ERC-4337
    // ══════════════════════════════════════════════

    /// @notice Validates a UserOperation signature via the AccountConfiguration system.
    ///         Signature format follows 8130 verifier conventions (verifier_type || data).
    function validateUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 missingAccountFunds)
        external
        returns (uint256 validationData)
    {
        require(_isAuthorizedCaller(msg.sender));

        bool valid;
        try ACCOUNT_CONFIGURATION.verify(address(this), userOpHash, userOp.signature) returns (uint8) {
            valid = true;
        } catch {
            valid = false;
        }
        validationData = valid ? 0 : 1;

        if (missingAccountFunds != 0) {
            assembly {
                pop(call(gas(), caller(), missingAccountFunds, 0, 0, 0, 0))
            }
        }
    }

    // ══════════════════════════════════════════════
    //  ERC-1271
    // ══════════════════════════════════════════════

    /// @notice Signature validation via AccountConfiguration's verifier infrastructure.
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        try ACCOUNT_CONFIGURATION.verify(address(this), hash, signature) returns (uint8) {
            return bytes4(0x1626ba7e);
        } catch {
            return bytes4(0xFFFFFFFF);
        }
    }

    // ══════════════════════════════════════════════
    //  INTERNALS
    // ══════════════════════════════════════════════

    function _isAuthorizedCaller(address caller) internal view returns (bool) {
        return caller == address(this) || caller == ENTRY_POINT || _authorizedCallers[caller];
    }
}
