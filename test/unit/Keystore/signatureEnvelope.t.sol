// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Keystore} from "../../../src/Keystore.sol";

import {KeystoreTest} from "../../lib/KeystoreTest.sol";

/// @notice Scoping of the Keystore signature envelope to the account and chain (validateSignature / replaySafeHash).
///
/// @dev The envelope digest binds a signature to a specific account and channel at the singleton level, so
///      cross-account replay is closed for EVERY consumer of validateSignature — including registry-direct verifiers
///      (e.g. precompile-based permits) that cannot call account bytecode.
contract SignatureEnvelopeTest is KeystoreTest {
    uint256 constant OWNER_PK = 0xA11CE;

    /// @dev validateSignature binds to the account-scoped digest: a signature over the RAW app hash does not resolve
    ///      to the owner, so authentication reverts; the signer must sign replaySafeHash(account, block.chainid, appHash).
    function test_validateSignature_requiresAccountScopedDigest() public {
        (address account,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(1)));
        bytes32 appHash = keccak256("hello world");

        // Inner signature over the RAW hash recovers an address that is not a registered actor -> reverts.
        vm.expectRevert();
        keystore.validateSignature(account, appHash, _wrapLocal(_buildK1Auth(OWNER_PK, appHash)));

        // The account-scoped digest validates and resolves the owner actor (actorId = owner EOA).
        bytes memory signable =
            _wrapLocal(_buildK1Auth(OWNER_PK, keystore.replaySafeHash(account, block.chainid, appHash)));
        (bytes32 actorId,) = keystore.validateSignature(account, appHash, signable);
        assertEq(actorId, bytes32(uint256(uint160(vm.addr(OWNER_PK)))), "must resolve the owner actor");
    }

    /// @dev The core property: a signature made for one account does NOT validate on another account that shares the
    ///      same owner key (a wallet and its sub-account share an owner). Enforced at the registry, so a
    ///      registry-direct verifier gets this without ever calling the account.
    function test_validateSignature_blocksCrossAccountReplay() public {
        (address accountA,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(0xA)));
        (address accountB,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(0xB)));
        assertTrue(accountA != accountB, "accounts must differ");

        bytes32 appHash = keccak256("sign in to dapp");
        bytes memory sigForA =
            _wrapLocal(_buildK1Auth(OWNER_PK, keystore.replaySafeHash(accountA, block.chainid, appHash)));

        (bytes32 actorId,) = keystore.validateSignature(accountA, appHash, sigForA);
        assertEq(actorId, bytes32(uint256(uint160(vm.addr(OWNER_PK)))), "valid on the intended account");

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
            keystore.replaySafeHash(accountA, block.chainid, appHash)
                != keystore.replaySafeHash(accountB, block.chainid, appHash),
            "digests must differ by account"
        );
    }

    /// @dev The digest binds chainId: the chain-local digest (block.chainid) and the all-chains digest (0) differ,
    ///      and the digest is a deterministic function of the chainId argument.
    function test_replaySafeHash_bindsChainId() public {
        (address account,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(1)));
        bytes32 appHash = keccak256("msg");

        bytes32 local = keystore.replaySafeHash(account, block.chainid, appHash);
        bytes32 multichain = keystore.replaySafeHash(account, 0, appHash);
        assertTrue(local != multichain, "chain-local (block.chainid) and all-chains (0) digests must differ");
        assertTrue(
            keystore.replaySafeHash(account, block.chainid + 1, appHash) != local, "digest must differ by chainId"
        );
    }

    /// @dev envelopeDigest resolves each SignatureType to the same digest validateSignature uses, so clients can build
    ///      envelopes without hardcoding chainId semantics. Invalid reverts.
    function test_envelopeDigest_matchesReplaySafeHashPerType() public {
        (address account,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(1)));
        bytes32 appHash = keccak256("msg");

        assertEq(
            keystore.envelopeDigest(Keystore.SignatureType.Local, account, appHash),
            keystore.replaySafeHash(account, block.chainid, appHash),
            "Local must bind block.chainid"
        );
        assertEq(
            keystore.envelopeDigest(Keystore.SignatureType.Multichain, account, appHash),
            keystore.replaySafeHash(account, 0, appHash),
            "Multichain must bind chainId 0"
        );

        vm.expectRevert(abi.encodeWithSelector(Keystore.UnknownSignatureType.selector, uint8(0)));
        keystore.envelopeDigest(Keystore.SignatureType.Invalid, account, appHash);
    }

    /// @dev A non-owner key is rejected even when it signs the correct account-scoped digest.
    function test_validateSignature_rejectsNonOwner() public {
        (address account,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(1)));
        bytes32 appHash = keccak256("hello world");
        bytes memory signable =
            _wrapLocal(_buildK1Auth(0xBEEF, keystore.replaySafeHash(account, block.chainid, appHash)));

        vm.expectRevert();
        keystore.validateSignature(account, appHash, signable);
    }
}
