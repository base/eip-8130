// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {Scopes} from "../../../src/libraries/Scopes.sol";

/// @notice Unit tests for the Scopes.isOperator predicate — the single shared definition of ERC-1271 signing and
///         execution authority (admin, or a SENDER actor without POLICY) consumed by DefaultAccount.
contract ScopesTest is Test {
    /// @notice Admin (scope == 0) is operational.
    function test_isOperator_true_admin() public pure {
        assertTrue(Scopes.isOperator(0));
    }

    /// @notice A SENDER actor without POLICY is operational, including when combined with non-POLICY capability bits.
    function test_isOperator_true_senderWithoutPolicy() public pure {
        assertTrue(Scopes.isOperator(Scopes.SENDER));
        assertTrue(Scopes.isOperator(Scopes.SENDER | Scopes.SELF_PAYER));
        assertTrue(Scopes.isOperator(Scopes.SENDER | Scopes.NONCE | Scopes.SPONSOR_PAYER));
    }

    /// @notice Any POLICY-bearing scope is NOT operational, even with SENDER set.
    function test_isOperator_false_policy() public pure {
        assertFalse(Scopes.isOperator(Scopes.POLICY));
        assertFalse(Scopes.isOperator(Scopes.SENDER | Scopes.POLICY));
    }

    /// @notice A non-SENDER capability-only scope (no admin, no SENDER) is NOT operational.
    function test_isOperator_false_nonSenderCapabilities() public pure {
        assertFalse(Scopes.isOperator(Scopes.SELF_PAYER));
        assertFalse(Scopes.isOperator(Scopes.SPONSOR_PAYER));
        assertFalse(Scopes.isOperator(Scopes.NONCE));
    }

    /// @notice Fuzz: isOperator exactly equals `scope == 0 || (SENDER set && POLICY unset)` across the space.
    function test_isOperator_matchesPredicate(uint16 scope) public pure {
        bool expected = scope == 0 || ((scope & Scopes.SENDER != 0) && (scope & Scopes.POLICY == 0));
        assertEq(Scopes.isOperator(scope), expected);
    }
}
