// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {Scopes} from "../../../src/libraries/Scopes.sol";

/// @notice Unit tests for the Scopes.isOperational predicate — the single shared definition of ERC-1271 signing and
///         execution authority (admin, or a SENDER actor without POLICY) consumed by DefaultAccount.
contract ScopesTest is Test {
    /// @notice Admin (scope == 0) is operational.
    function test_isOperational_true_admin() public pure {
        assertTrue(Scopes.isOperational(0));
    }

    /// @notice A SENDER actor without POLICY is operational, including when combined with non-POLICY capability bits.
    function test_isOperational_true_senderWithoutPolicy() public pure {
        assertTrue(Scopes.isOperational(Scopes.SENDER));
        assertTrue(Scopes.isOperational(Scopes.SENDER | Scopes.SELF_PAYER));
        assertTrue(Scopes.isOperational(Scopes.SENDER | Scopes.NONCE | Scopes.SPONSOR_PAYER));
    }

    /// @notice Any POLICY-bearing scope is NOT operational, even with SENDER set.
    function test_isOperational_false_policy() public pure {
        assertFalse(Scopes.isOperational(Scopes.POLICY));
        assertFalse(Scopes.isOperational(Scopes.SENDER | Scopes.POLICY));
    }

    /// @notice A non-SENDER capability-only scope (no admin, no SENDER) is NOT operational.
    function test_isOperational_false_nonSenderCapabilities() public pure {
        assertFalse(Scopes.isOperational(Scopes.SELF_PAYER));
        assertFalse(Scopes.isOperational(Scopes.SPONSOR_PAYER));
        assertFalse(Scopes.isOperational(Scopes.NONCE));
    }

    /// @notice Fuzz: isOperational exactly equals `scope == 0 || (SENDER set && POLICY unset)` across the space.
    function test_isOperational_matchesPredicate(uint16 scope) public pure {
        bool expected = scope == 0 || ((scope & Scopes.SENDER != 0) && (scope & Scopes.POLICY == 0));
        assertEq(Scopes.isOperational(scope), expected);
    }
}
