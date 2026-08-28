// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {Scopes} from "../../../src/libraries/Scopes.sol";

/// @notice Unit tests for the Scopes.isOperator predicate — the single shared definition of ERC-1271 signing and
///         execution authority (admin, or an OPERATOR actor) consumed by DefaultAccount.
contract ScopesTest is Test {
    /// @notice Admin (scope == 0) is operational.
    function test_isOperator_true_admin() public pure {
        assertTrue(Scopes.isOperator(0));
    }

    /// @notice An OPERATOR actor is operational, including when combined with other capability bits.
    function test_isOperator_true_operator() public pure {
        assertTrue(Scopes.isOperator(Scopes.OPERATOR));
        assertTrue(Scopes.isOperator(Scopes.OPERATOR | Scopes.SELF_PAYER));
        assertTrue(Scopes.isOperator(Scopes.OPERATOR | Scopes.NONCE | Scopes.SPONSOR_PAYER));
        // OPERATOR is more permissive than POLICY; the bits do not combine to suppress OPERATOR.
        assertTrue(Scopes.isOperator(Scopes.OPERATOR | Scopes.POLICY));
    }

    /// @notice A POLICY-only scope is NOT operational.
    function test_isOperator_false_policyOnly() public pure {
        assertFalse(Scopes.isOperator(Scopes.POLICY));
        assertFalse(Scopes.isOperator(Scopes.POLICY | Scopes.SELF_PAYER));
    }

    /// @notice A non-OPERATOR capability-only scope (no admin, no OPERATOR) is NOT operational.
    function test_isOperator_false_nonOperatorCapabilities() public pure {
        assertFalse(Scopes.isOperator(Scopes.SELF_PAYER));
        assertFalse(Scopes.isOperator(Scopes.SPONSOR_PAYER));
        assertFalse(Scopes.isOperator(Scopes.NONCE));
    }

    /// @notice Fuzz: isOperator exactly equals `scope == 0 || OPERATOR set` across the space.
    function test_isOperator_matchesPredicate(uint16 scope) public pure {
        bool expected = scope == 0 || (scope & Scopes.OPERATOR != 0);
        assertEq(Scopes.isOperator(scope), expected);
    }

    /// @notice Core grants occupy bits 0–2 so POLICY/NONCE can be omitted without renumbering.
    function test_bitLayout_coreThenOptional() public pure {
        assertEq(Scopes.OPERATOR, uint16(0x0001));
        assertEq(Scopes.SELF_PAYER, uint16(0x0002));
        assertEq(Scopes.SPONSOR_PAYER, uint16(0x0004));
        assertEq(Scopes.POLICY, uint16(0x0008));
        assertEq(Scopes.NONCE, uint16(0x0010));
    }
}
