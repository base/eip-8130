// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Receiver} from "solady/accounts/Receiver.sol";

import {AccountConfiguration} from "../AccountConfiguration.sol";

struct Call {
    address target;
    uint256 value;
    bytes data;
}

/// @notice Default account implementation for EIP-8130.
///         Deployed behind ERC-1167 minimal proxy (45 bytes, deterministic pattern).
///
///         With direct dispatch, the protocol sends calls to `to` addresses with `msg.sender = from`.
///         This contract handles ETH transfers (via self-call) and batched operations.
///
///         Supports Account Policies (https://github.com/base/account-policies) via a caller
///         allowlist. The PolicyManager is added as an authorized caller, giving it execution
///         capability on the account while policies define the authorization semantics.
///
///         Caller authorization:
///           - address(this) is always authorized (hardcoded) — covers 8130 direct dispatch
///           - Additional callers managed via authorizeCaller/revokeCaller (self-call only)
contract DefaultAccount is Receiver {
    AccountConfiguration public immutable ACCOUNT_CONFIGURATION;

    mapping(address => bool) internal _authorizedCallers;

    event CallerAuthorized(address indexed caller);
    event CallerRevoked(address indexed caller);

    constructor(address accountConfiguration) {
        ACCOUNT_CONFIGURATION = AccountConfiguration(accountConfiguration);
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
        try ACCOUNT_CONFIGURATION.verify(address(this), hash, signature) returns (bytes32, AccountConfiguration.OwnerConfig memory) {
            return bytes4(0x1626ba7e);
        } catch {
            return bytes4(0xFFFFFFFF);
        }
    }

    // ══════════════════════════════════════════════
    //  INTERNALS
    // ══════════════════════════════════════════════

    function _isAuthorizedCaller(address caller) internal view returns (bool) {
        return caller == address(this) || _authorizedCallers[caller];
    }
}
