// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Receiver} from "solady/accounts/Receiver.sol";

import {AccountConfiguration} from "../AccountConfiguration.sol";
import {IAccountConfiguration} from "../interfaces/IAccountConfiguration.sol";

struct Call {
    address target;
    uint256 value;
    bytes data;
}

/// @dev Sentinel address for external caller authorization. No contract exists here —
///      if the protocol ever calls verify() on it, the call naturally fails.
///      Deterministic across all chains (hash-derived, no deployment needed).
address constant EXTERNAL_CALLER_VERIFIER = address(uint160(uint256(keccak256("externalCaller"))));

/// @notice Default account implementation for EIP-8130.
///         Deployed behind ERC-1167 minimal proxy (45 bytes, deterministic pattern).
///
///         With direct dispatch, the protocol sends calls to `to` addresses with `msg.sender = from`.
///         This contract handles ETH transfers (via self-call) and batched operations.
///
///         Caller authorization via AccountConfiguration:
///           - address(this) is always authorized (hardcoded) — covers 8130 direct dispatch
///           - External callers (EntryPoints, PolicyManagers) are registered as owners
///             with EXTERNAL_CALLER_VERIFIER as the verifier in AccountConfiguration
contract DefaultAccount is Receiver {
    AccountConfiguration public immutable ACCOUNT_CONFIGURATION;

    constructor(address accountConfiguration) {
        ACCOUNT_CONFIGURATION = AccountConfiguration(accountConfiguration);
    }

    // ══════════════════════════════════════════════
    //  EXECUTION
    // ══════════════════════════════════════════════

    function executeBatch(Call[] calldata calls) external virtual {
        require(_isAuthorizedCaller(msg.sender));
        for (uint256 i; i < calls.length; i++) {
            (bool success,) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            require(success);
        }
    }

    // ══════════════════════════════════════════════
    //  ERC-1271
    // ══════════════════════════════════════════════

    /// @notice Signature validation via AccountConfiguration's verifier infrastructure.
    /// @param hash The digest to verify
    /// @param signature Auth data in verifier || data format
    /// @return magicValue 0x1626ba7e if valid, 0xffffffff otherwise
    function isValidSignature(bytes32 hash, bytes calldata signature) external view virtual returns (bytes4) {
        try ACCOUNT_CONFIGURATION.verify(address(this), hash, signature) returns (uint8) {
            return bytes4(0x1626ba7e);
        } catch {
            return bytes4(0xFFFFFFFF);
        }
    }

    // ══════════════════════════════════════════════
    //  VIEW
    // ══════════════════════════════════════════════

    function isAuthorizedCaller(address caller) external view returns (bool) {
        return _isAuthorizedCaller(caller);
    }

    // ══════════════════════════════════════════════
    //  INTERNALS
    // ══════════════════════════════════════════════

    function _isAuthorizedCaller(address caller) internal view virtual returns (bool) {
        if (caller == address(this)) return true;
        IAccountConfiguration.OwnerConfig memory config =
            ACCOUNT_CONFIGURATION.getOwnerConfig(address(this), bytes32(bytes20(caller)));
        return config.verifier == EXTERNAL_CALLER_VERIFIER;
    }
}
