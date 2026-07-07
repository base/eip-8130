// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

/// @dev Minimal ERC-1271 wallet that validates an owner ECDSA signature over the presented hash.
contract MockERC1271Wallet {
    address public immutable owner;

    constructor(address _owner) {
        owner = _owner;
    }

    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4) {
        if (ECDSA.recover(hash, signature) == owner) return 0x1626ba7e;
        return 0xFFFFFFFF;
    }
}

contract ImportAccountTest is AccountConfigurationTest {
    // Independent reimplementation of the contract's typed import digest (see _computeImportDigest). The digest retains
    // the full Actor/ActorConfig typehash structure; for imported (always unrestricted) actors the config fields are
    // zero and policyData is empty.
    bytes32 constant ACTOR_INITIALIZATION_TYPEHASH = keccak256(
        "ActorInitialization(bytes32 salt,uint256 chainId,Actor[] initialActors)Actor(bytes32 actorId,ActorConfig config,bytes policyData)ActorConfig(address authenticator,uint8 scope,uint48 expiry,uint8 policyType)"
    );
    bytes32 constant ACTOR_TYPEHASH = keccak256(
        "Actor(bytes32 actorId,ActorConfig config,bytes policyData)ActorConfig(address authenticator,uint8 scope,uint48 expiry,uint8 policyType)"
    );
    bytes32 constant ACTORCONFIG_TYPEHASH =
        keccak256("ActorConfig(address authenticator,uint8 scope,uint48 expiry,uint8 policyType)");

    /// @dev Convenience: bind the digest to the current chain (the common per-chain import).
    function _computeImportDigest(address account, AccountConfiguration.InitialActor[] memory initialActors)
        internal
        view
        returns (bytes32)
    {
        return _computeImportDigest(account, block.chainid, initialActors);
    }

    function _computeImportDigest(
        address account,
        uint256 chainId,
        AccountConfiguration.InitialActor[] memory initialActors
    ) internal pure returns (bytes32) {
        bytes32[] memory actorHashes = new bytes32[](initialActors.length);
        for (uint256 i; i < initialActors.length; i++) {
            bytes32 configHash = keccak256(
                abi.encode(ACTORCONFIG_TYPEHASH, initialActors[i].authenticator, uint8(0), uint48(0), uint8(0))
            );
            actorHashes[i] = keccak256(abi.encode(ACTOR_TYPEHASH, initialActors[i].actorId, configHash, keccak256("")));
        }
        return keccak256(
            abi.encode(
                ACTOR_INITIALIZATION_TYPEHASH,
                bytes32(bytes20(account)),
                chainId,
                keccak256(abi.encodePacked(actorHashes))
            )
        );
    }

    function _singleUnrestrictedActor(address signer)
        internal
        view
        returns (AccountConfiguration.InitialActor[] memory actors)
    {
        actors = new AccountConfiguration.InitialActor[](1);
        actors[0] = AccountConfiguration.InitialActor({
            actorId: bytes32(bytes20(signer)), authenticator: address(k1Authenticator)
        });
    }

    function test_importAccount_validSignature() public {
        uint256 ownerPk = 700;
        MockERC1271Wallet wallet = new MockERC1271Wallet(vm.addr(ownerPk));

        AccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(vm.addr(ownerPk));
        bytes32 digest = _computeImportDigest(address(wallet), actors);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);

        accountConfiguration.importAccount(address(wallet), uint64(block.chainid), actors, abi.encodePacked(r, s, v));

        assertEq(accountConfiguration.getChangeSequences(address(wallet)).local, 1);
        assertTrue(accountConfiguration.isActor(address(wallet), bytes32(bytes20(vm.addr(ownerPk)))));
    }

    function test_importAccount_revertsOnBadSignature() public {
        uint256 ownerPk = 700;
        MockERC1271Wallet wallet = new MockERC1271Wallet(vm.addr(ownerPk));

        AccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(vm.addr(ownerPk));
        bytes32 digest = _computeImportDigest(address(wallet), actors);
        // Sign with a different key so the wallet rejects the signature.
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(701, digest);

        vm.expectRevert();
        accountConfiguration.importAccount(address(wallet), uint64(block.chainid), actors, abi.encodePacked(r, s, v));
    }

    function test_importAccount_revertsOnReimport() public {
        uint256 ownerPk = 700;
        MockERC1271Wallet wallet = new MockERC1271Wallet(vm.addr(ownerPk));

        AccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(vm.addr(ownerPk));
        bytes32 digest = _computeImportDigest(address(wallet), actors);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        accountConfiguration.importAccount(address(wallet), uint64(block.chainid), actors, sig);

        vm.expectRevert();
        accountConfiguration.importAccount(address(wallet), uint64(block.chainid), actors, sig);
    }

    function test_importAccount_revertsOnCreatedAccount() public {
        // A created account is already initialized (localSequence == 1), so it cannot be imported.
        (address account,) = _createK1Account(900);

        AccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(vm.addr(901));
        vm.expectRevert();
        accountConfiguration.importAccount(account, uint64(block.chainid), actors, "");
    }

    function test_importAccount_revertsAfterGlobalChange() public {
        // A code-less 8130 EOA can apply a *global* (chainId 0) actor change signed by its implicit default EOA.
        // That advances the multichain channel while localSequence stays 0. Import must still be blocked: the gate
        // now requires *both* sequence channels empty, so an account that has already established 8130 state on the
        // multichain channel cannot be bootstrapped via import (which would re-open the old key).
        uint256 eoaPk = 700;
        address eoa = vm.addr(eoaPk);
        address device = vm.addr(701);

        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({
            actorId: bytes32(bytes20(device)),
            changeType: 0x01,
            data: abi.encode(
                AccountConfiguration.ActorConfig({
                    authenticator: address(k1Authenticator), scope: 0x00, expiry: 0, policyType: 0x00
                }),
                bytes("")
            )
        });
        uint64 seq = accountConfiguration.getChangeSequences(eoa).multichain;
        bytes32 changeDigest = _computeActorChangeBatchDigest(eoa, 0, seq, changes);
        accountConfiguration.applySignedActorChanges(eoa, 0, changes, _buildK1Auth(eoaPk, changeDigest));

        // Multichain channel advanced; local channel untouched.
        assertEq(accountConfiguration.getChangeSequences(eoa).multichain, 1);
        assertEq(accountConfiguration.getChangeSequences(eoa).local, 0);

        // Import is gated even though localSequence == 0, because the multichain channel is non-zero.
        AccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(device);
        bytes32 importDigest = _computeImportDigest(eoa, actors);
        vm.expectRevert();
        accountConfiguration.importAccount(eoa, uint64(block.chainid), actors, _buildK1Auth(eoaPk, importDigest));
    }

    function test_importAccount_revertsWhenLocked() public {
        uint256 ownerPk = 700;
        MockERC1271Wallet wallet = new MockERC1271Wallet(vm.addr(ownerPk));

        vm.prank(address(wallet));
        accountConfiguration.lock(1 hours);

        AccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(vm.addr(ownerPk));
        bytes32 digest = _computeImportDigest(address(wallet), actors);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);

        vm.expectRevert();
        accountConfiguration.importAccount(address(wallet), uint64(block.chainid), actors, abi.encodePacked(r, s, v));
    }

    function test_importAccount_allowsDelegatedAccount() public {
        // EIP-7702 delegated accounts are no longer rejected: the delegate-indicator check has been removed, so
        // import is gated solely by the ERC-1271 signature against the (delegated) account's authorization logic.
        uint256 ownerPk = 700;
        address eoa = vm.addr(ownerPk);
        MockERC1271Wallet impl = new MockERC1271Wallet(eoa);
        // Delegate the EOA's code to the ERC-1271 implementation (code = 0xef0100 || delegate).
        vm.etch(eoa, abi.encodePacked(hex"ef0100", address(impl)));

        // Register a distinct device key as the initial actor.
        address device = vm.addr(701);
        AccountConfiguration.InitialActor[] memory actors = new AccountConfiguration.InitialActor[](1);
        actors[0] = AccountConfiguration.InitialActor({
            actorId: bytes32(bytes20(device)), authenticator: address(k1Authenticator)
        });

        bytes32 digest = _computeImportDigest(eoa, actors);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);

        accountConfiguration.importAccount(eoa, uint64(block.chainid), actors, abi.encodePacked(r, s, v));

        assertEq(accountConfiguration.getChangeSequences(eoa).local, 1);
        assertTrue(accountConfiguration.isActor(eoa, bytes32(bytes20(device))));
        // The implicit default EOA is disabled by default on import.
        assertFalse(accountConfiguration.isActor(eoa, bytes32(bytes20(eoa))));
    }

    function test_importAccount_7702_selfSignDisablesEoa() public {
        // A real EIP-7702 EOA delegated to DefaultAccount self-imports using its own (default-EOA) k1 signature.
        // That implicit full-owner path is the only authenticator available at import time, so this pins the
        // ordering invariant: the ERC-1271 check must run before the flag is set, and the default EOA is disabled
        // only after import succeeds.
        uint256 eoaPk = 700;
        address eoa = vm.addr(eoaPk);
        vm.etch(eoa, abi.encodePacked(hex"ef0100", defaultAccountImplementation));

        address device = vm.addr(701);
        AccountConfiguration.InitialActor[] memory actors = new AccountConfiguration.InitialActor[](1);
        actors[0] = AccountConfiguration.InitialActor({
            actorId: bytes32(bytes20(device)), authenticator: address(k1Authenticator)
        });

        bytes32 digest = _computeImportDigest(eoa, actors);
        // Canonical k1 auth blob: K1_AUTHENTICATOR || signature, signed by the EOA's own key (the implicit owner).
        accountConfiguration.importAccount(eoa, uint64(block.chainid), actors, _buildK1Auth(eoaPk, digest));

        assertEq(accountConfiguration.getChangeSequences(eoa).local, 1);
        assertTrue(accountConfiguration.isActor(eoa, bytes32(bytes20(device))));
        // The implicit default EOA is disabled after import: its own k1 sig now finds no config and the flag
        // disables the full-owner fallback.
        assertFalse(accountConfiguration.isActor(eoa, bytes32(bytes20(eoa))));
        bytes32 h = keccak256("post import");
        vm.expectRevert();
        accountConfiguration.authenticateActor(eoa, h, _buildK1Auth(eoaPk, h));
    }

    function test_importAccount_7702_keepKeyViaExplicitSelfActor() public {
        // A live 7702 EOA that wants to keep using its key past import lists the self-actorId as an explicit k1
        // owner. Import disables the implicit full-owner fallback (sets the flag), but the same key stays a full
        // owner through its explicit self config — lossless, no extra import option needed.
        uint256 eoaPk = 700;
        address eoa = vm.addr(eoaPk);
        vm.etch(eoa, abi.encodePacked(hex"ef0100", defaultAccountImplementation));

        AccountConfiguration.InitialActor[] memory actors = new AccountConfiguration.InitialActor[](1);
        actors[0] = AccountConfiguration.InitialActor({
            actorId: bytes32(bytes20(eoa)), authenticator: accountConfiguration.K1_AUTHENTICATOR()
        });

        bytes32 digest = _computeImportDigest(eoa, actors);
        accountConfiguration.importAccount(eoa, uint64(block.chainid), actors, _buildK1Auth(eoaPk, digest));

        assertEq(accountConfiguration.getChangeSequences(eoa).local, 1);
        // The self-actorId is a live explicit owner.
        assertTrue(accountConfiguration.isActor(eoa, bytes32(bytes20(eoa))));

        // The same key still authenticates as a full owner — now resolved through its explicit self config rather
        // than the (disabled) implicit fallback.
        bytes32 h = keccak256("post import");
        (uint8 scope,,) = accountConfiguration.authenticateActor(eoa, h, _buildK1Auth(eoaPk, h));
        assertEq(scope, 0);
    }

    function test_importAccount_multichainSignatureValid() public {
        // A chainId == 0 import signature authorizes import on any chain (mirrors the multichain actor-change path).
        uint256 ownerPk = 700;
        MockERC1271Wallet wallet = new MockERC1271Wallet(vm.addr(ownerPk));

        AccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(vm.addr(ownerPk));
        bytes32 digest = _computeImportDigest(address(wallet), 0, actors);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);

        accountConfiguration.importAccount(address(wallet), 0, actors, abi.encodePacked(r, s, v));

        assertEq(accountConfiguration.getChangeSequences(address(wallet)).local, 1);
        assertTrue(accountConfiguration.isActor(address(wallet), bytes32(bytes20(vm.addr(ownerPk)))));
    }

    function test_importAccount_revertsOnForeignChainId() public {
        // A chainId that is neither 0 nor the current chain is rejected before any signature work.
        uint256 ownerPk = 700;
        MockERC1271Wallet wallet = new MockERC1271Wallet(vm.addr(ownerPk));
        uint256 foreignChainId = block.chainid + 1;

        AccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(vm.addr(ownerPk));
        bytes32 digest = _computeImportDigest(address(wallet), foreignChainId, actors);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);

        vm.expectRevert(AccountConfiguration.InvalidChainId.selector);
        accountConfiguration.importAccount(address(wallet), foreignChainId, actors, abi.encodePacked(r, s, v));
    }
}
