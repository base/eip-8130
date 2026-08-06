// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

/// @notice Registry-native account- and chain-scoping of ERC-1271 signatures in AccountConfiguration.verifySignature.
///
/// @dev Demonstrates that ERC-1271 signatures are bound to a specific account and chain at the singleton level
///      (via replaySafeHash), so cross-account and cross-chain replay are closed for EVERY consumer of
///      verifySignature, including registry-direct verifiers (e.g. precompile-based permits) that cannot call
///      account bytecode.
contract AccountConfigurationERC7739Test is AccountConfigurationTest {
    uint256 constant OWNER_PK = 0xA11CE;

    /// @dev verifySignature now rehashes: a signature over the RAW app hash is rejected; the signer must sign the
    ///      account-scoped replaySafeHash.
    function test_verifySignature_requiresAccountScopedDigest() public {
        (address account,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(1)));
        bytes32 appHash = keccak256("hello world");

        assertFalse(
            accountConfiguration.verifySignature(account, appHash, _buildK1Auth(OWNER_PK, appHash)),
            "raw-hash signature must be rejected now that verifySignature rehashes"
        );

        bytes32 signable = accountConfiguration.replaySafeHash(account, appHash);
        assertTrue(
            accountConfiguration.verifySignature(account, appHash, _buildK1Auth(OWNER_PK, signable)),
            "account-scoped (replaySafeHash) signature must validate"
        );
    }

    /// @dev The core fix: a signature made for one account does NOT validate on another account that shares the
    ///      same owner key (a wallet and its sub-account share an owner). Enforced at the registry, so a
    ///      registry-direct verifier gets this without ever calling the account.
    function test_verifySignature_blocksCrossAccountReplay() public {
        (address accountA,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(0xA)));
        (address accountB,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(0xB)));
        assertTrue(accountA != accountB, "accounts must differ");

        bytes32 appHash = keccak256("sign in to dapp");
        bytes memory sigForA = _buildK1Auth(OWNER_PK, accountConfiguration.replaySafeHash(accountA, appHash));

        assertTrue(accountConfiguration.verifySignature(accountA, appHash, sigForA), "valid on the intended account");
        assertFalse(
            accountConfiguration.verifySignature(accountB, appHash, sigForA),
            "must NOT replay onto another account with the same owner key"
        );
    }

    /// @dev replaySafeHash is account-scoped: the same message yields different digests per account. Chain-scoping
    ///      is covered by test_replaySafeHash_isChainScoped.
    function test_replaySafeHash_isAccountScoped() public {
        (address accountA,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(0xA)));
        (address accountB,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(0xB)));
        bytes32 appHash = keccak256("msg");

        assertTrue(
            accountConfiguration.replaySafeHash(accountA, appHash)
                != accountConfiguration.replaySafeHash(accountB, appHash),
            "digests must differ by account"
        );
    }

    /// @dev A non-owner key is rejected even when it signs the correct account-scoped digest.
    function test_verifySignature_rejectsNonOwner() public {
        (address account,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(1)));
        bytes32 appHash = keccak256("hello world");
        bytes32 signable = accountConfiguration.replaySafeHash(account, appHash);

        assertFalse(
            accountConfiguration.verifySignature(account, appHash, _buildK1Auth(0xBEEF, signable)),
            "a non-owner signature must be rejected"
        );
    }

    /// @dev A signature bound to one chain does NOT validate on another: replaySafeHash mixes in block.chainid, so
    ///      the same (account, appHash) yields a different digest per chain and a chain-A signature is rejected on
    ///      chain B. Mirrors {test_verifySignature_blocksCrossAccountReplay} on the chain axis.
    function test_verifySignature_blocksCrossChainReplay() public {
        (address account,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(1)));
        bytes32 appHash = keccak256("sign in to dapp");

        bytes memory sig = _buildK1Auth(OWNER_PK, accountConfiguration.replaySafeHash(account, appHash));
        assertTrue(accountConfiguration.verifySignature(account, appHash, sig), "valid on the signing chain");

        vm.chainId(block.chainid + 1);
        assertFalse(
            accountConfiguration.verifySignature(account, appHash, sig), "must NOT replay onto another chain"
        );
    }

    /// @dev replaySafeHash is chain-scoped: the same (account, message) yields different digests per chain.
    function test_replaySafeHash_isChainScoped() public {
        (address account,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(1)));
        bytes32 appHash = keccak256("msg");

        bytes32 digestChainA = accountConfiguration.replaySafeHash(account, appHash);
        vm.chainId(block.chainid + 1);
        bytes32 digestChainB = accountConfiguration.replaySafeHash(account, appHash);

        assertTrue(digestChainA != digestChainB, "digests must differ by chain");
    }
}
