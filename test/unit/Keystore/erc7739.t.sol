// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {KeystoreTest} from "../../lib/KeystoreTest.sol";

/// @notice EIP-7739 (PersonalSign) rehashing for account-level ERC-1271 (DefaultAccount.isValidSignature), built on
///         the account-scoped digest DefaultAccount.replaySafeHash.
///
/// @dev ERC-1271 verification and the account-scoped digest both live on the account contract (Keystore is
///      scope-agnostic and exposes neither verifySignature nor replaySafeHash). Because the account authenticates
///      against replaySafeHash(hash) — an EIP-712 digest with verifyingContract = account — a signature is bound to a
///      single account, so a signature made for one account cannot be replayed onto another account that shares the
///      same owner key.
contract KeystoreERC7739Test is KeystoreTest {
    uint256 constant OWNER_PK = 0xA11CE;

    /// @dev isValidSignature rehashes: a signature over the RAW app hash is rejected; the signer must sign the
    ///      account-scoped replaySafeHash.
    function test_isValidSignature_requiresAccountScopedDigest() public {
        (address account,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(1)));
        bytes32 appHash = keccak256("hello world");

        assertFalse(
            _isValidSig(account, appHash, _buildK1Auth(OWNER_PK, appHash)),
            "raw-hash signature must be rejected now that isValidSignature rehashes"
        );

        bytes32 signable = _replaySafeHash(account, appHash);
        assertTrue(
            _isValidSig(account, appHash, _buildK1Auth(OWNER_PK, signable)),
            "account-scoped (replaySafeHash) signature must validate"
        );
    }

    /// @dev The core fix: a signature made for one account does NOT validate on another account that shares the
    ///      same owner key (a wallet and its sub-account share an owner).
    function test_isValidSignature_blocksCrossAccountReplay() public {
        (address accountA,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(0xA)));
        (address accountB,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(0xB)));
        assertTrue(accountA != accountB, "accounts must differ");

        bytes32 appHash = keccak256("sign in to dapp");
        bytes memory sigForA = _buildK1Auth(OWNER_PK, _replaySafeHash(accountA, appHash));

        assertTrue(_isValidSig(accountA, appHash, sigForA), "valid on the intended account");
        assertFalse(
            _isValidSig(accountB, appHash, sigForA), "must NOT replay onto another account with the same owner key"
        );
    }

    /// @dev replaySafeHash is account-scoped: the same message yields different digests per account (and per chain,
    ///      via the EIP-712 domain).
    function test_replaySafeHash_isAccountScoped() public {
        (address accountA,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(0xA)));
        (address accountB,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(0xB)));
        bytes32 appHash = keccak256("msg");

        assertTrue(
            _replaySafeHash(accountA, appHash) != _replaySafeHash(accountB, appHash), "digests must differ by account"
        );
    }

    /// @dev A non-owner key is rejected even when it signs the correct account-scoped digest.
    function test_isValidSignature_rejectsNonOwner() public {
        (address account,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(1)));
        bytes32 appHash = keccak256("hello world");
        bytes32 signable = _replaySafeHash(account, appHash);

        assertFalse(
            _isValidSig(account, appHash, _buildK1Auth(0xBEEF, signable)), "a non-owner signature must be rejected"
        );
    }
}
