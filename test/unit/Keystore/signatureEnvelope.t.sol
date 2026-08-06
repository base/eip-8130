// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {KeystoreTest} from "../../lib/KeystoreTest.sol";

/// @notice Account- and chain-scoping of the Keystore signature envelope (validateSignature / replaySafeHash /
///         multichainSafeHash).
///
/// @dev The envelope digest binds a signature to a specific account and channel at the singleton level, so
///      cross-account replay is closed for EVERY consumer of validateSignature — including registry-direct verifiers
///      (e.g. precompile-based permits) that cannot call account bytecode.
contract SignatureEnvelopeTest is KeystoreTest {
    uint256 constant OWNER_PK = 0xA11CE;

    /// @dev validateSignature binds to the account-scoped digest: a signature over the RAW app hash does not resolve
    ///      to the owner, so authentication reverts; the signer must sign replaySafeHash(account, appHash).
    function test_validateSignature_requiresAccountScopedDigest() public {
        (address account,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(1)));
        bytes32 appHash = keccak256("hello world");

        // Inner signature over the RAW hash recovers an address that is not a registered actor -> reverts.
        vm.expectRevert();
        keystore.validateSignature(account, appHash, _wrapLocal(_buildK1Auth(OWNER_PK, appHash)));

        // The account-scoped digest validates and resolves the owner actor (actorId = owner EOA).
        bytes memory signable = _wrapLocal(_buildK1Auth(OWNER_PK, keystore.replaySafeHash(account, appHash)));
        (bytes32 actorId,) = keystore.validateSignature(account, appHash, signable);
        assertEq(actorId, bytes32(bytes20(vm.addr(OWNER_PK))), "must resolve the owner actor");
    }

    /// @dev The core property: a signature made for one account does NOT validate on another account that shares the
    ///      same owner key (a wallet and its sub-account share an owner). Enforced at the registry, so a
    ///      registry-direct verifier gets this without ever calling the account.
    function test_validateSignature_blocksCrossAccountReplay() public {
        (address accountA,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(0xA)));
        (address accountB,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(0xB)));
        assertTrue(accountA != accountB, "accounts must differ");

        bytes32 appHash = keccak256("sign in to dapp");
        bytes memory sigForA = _wrapLocal(_buildK1Auth(OWNER_PK, keystore.replaySafeHash(accountA, appHash)));

        (bytes32 actorId,) = keystore.validateSignature(accountA, appHash, sigForA);
        assertEq(actorId, bytes32(bytes20(vm.addr(OWNER_PK))), "valid on the intended account");

        // The same envelope replayed onto accountB recovers a non-owner address -> reverts.
        vm.expectRevert();
        keystore.validateSignature(accountB, appHash, sigForA);
    }

    /// @dev replaySafeHash is account-scoped: the same message yields different digests per account.
    function test_replaySafeHash_isAccountScoped() public {
        (address accountA,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(0xA)));
        (address accountB,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(0xB)));
        bytes32 appHash = keccak256("msg");

        assertTrue(
            keystore.replaySafeHash(accountA, appHash) != keystore.replaySafeHash(accountB, appHash),
            "digests must differ by account"
        );
    }

    /// @dev The chain-local digest binds the current chainId (moves with it); the multichain (chainId = 0) digest is
    ///      chain-independent, and the two channels never collide.
    function test_multichainSafeHash_differsFromLocalAndIsChainIndependent() public {
        (address account,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(1)));
        bytes32 appHash = keccak256("msg");

        bytes32 localBefore = keystore.replaySafeHash(account, appHash);
        bytes32 multichain = keystore.multichainSafeHash(account, appHash);
        assertTrue(localBefore != multichain, "local (chainId) and multichain (0) digests must differ");

        vm.chainId(block.chainid + 1);
        assertTrue(keystore.replaySafeHash(account, appHash) != localBefore, "local digest must move with chainId");
        assertEq(
            keystore.multichainSafeHash(account, appHash), multichain, "multichain digest must be chain-independent"
        );
    }

    /// @dev A non-owner key is rejected even when it signs the correct account-scoped digest.
    function test_validateSignature_rejectsNonOwner() public {
        (address account,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(1)));
        bytes32 appHash = keccak256("hello world");
        bytes memory signable = _wrapLocal(_buildK1Auth(0xBEEF, keystore.replaySafeHash(account, appHash)));

        vm.expectRevert();
        keystore.validateSignature(account, appHash, signable);
    }
}
