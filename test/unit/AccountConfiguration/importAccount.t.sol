// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {IAccountConfiguration} from "../../../src/interfaces/IAccountConfiguration.sol";
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
        "ActorInitialization(bytes32 salt,Actor[] initialActors)Actor(bytes32 actorId,ActorConfig config,bytes policyData)ActorConfig(address verifier,uint8 scope,uint48 expiry,uint8 policyType)"
    );
    bytes32 constant ACTOR_TYPEHASH = keccak256(
        "Actor(bytes32 actorId,ActorConfig config,bytes policyData)ActorConfig(address verifier,uint8 scope,uint48 expiry,uint8 policyType)"
    );
    bytes32 constant ACTORCONFIG_TYPEHASH =
        keccak256("ActorConfig(address verifier,uint8 scope,uint48 expiry,uint8 policyType)");

    function _computeImportDigest(address account, IAccountConfiguration.InitialActor[] memory initialActors)
        internal
        pure
        returns (bytes32)
    {
        bytes32[] memory actorHashes = new bytes32[](initialActors.length);
        for (uint256 i; i < initialActors.length; i++) {
            bytes32 configHash =
                keccak256(abi.encode(ACTORCONFIG_TYPEHASH, initialActors[i].verifier, uint8(0), uint48(0), uint8(0)));
            actorHashes[i] = keccak256(abi.encode(ACTOR_TYPEHASH, initialActors[i].actorId, configHash, keccak256("")));
        }
        return keccak256(
            abi.encode(
                ACTOR_INITIALIZATION_TYPEHASH, bytes32(bytes20(account)), keccak256(abi.encodePacked(actorHashes))
            )
        );
    }

    function _singleUnrestrictedActor(address signer)
        internal
        view
        returns (IAccountConfiguration.InitialActor[] memory actors)
    {
        actors = new IAccountConfiguration.InitialActor[](1);
        actors[0] =
            IAccountConfiguration.InitialActor({actorId: bytes32(bytes20(signer)), verifier: address(k1Verifier)});
    }

    function test_importAccount_validSignature() public {
        uint256 ownerPk = 700;
        MockERC1271Wallet wallet = new MockERC1271Wallet(vm.addr(ownerPk));

        IAccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(vm.addr(ownerPk));
        bytes32 digest = _computeImportDigest(address(wallet), actors);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);

        accountConfiguration.importAccount(address(wallet), actors, abi.encodePacked(r, s, v));

        assertEq(accountConfiguration.getChangeSequences(address(wallet)).local, 1);
        assertTrue(accountConfiguration.isActor(address(wallet), bytes32(bytes20(vm.addr(ownerPk)))));
    }

    function test_importAccount_revertsOnBadSignature() public {
        uint256 ownerPk = 700;
        MockERC1271Wallet wallet = new MockERC1271Wallet(vm.addr(ownerPk));

        IAccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(vm.addr(ownerPk));
        bytes32 digest = _computeImportDigest(address(wallet), actors);
        // Sign with a different key so the wallet rejects the signature.
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(701, digest);

        vm.expectRevert();
        accountConfiguration.importAccount(address(wallet), actors, abi.encodePacked(r, s, v));
    }

    function test_importAccount_revertsOnReimport() public {
        uint256 ownerPk = 700;
        MockERC1271Wallet wallet = new MockERC1271Wallet(vm.addr(ownerPk));

        IAccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(vm.addr(ownerPk));
        bytes32 digest = _computeImportDigest(address(wallet), actors);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        accountConfiguration.importAccount(address(wallet), actors, sig);

        vm.expectRevert();
        accountConfiguration.importAccount(address(wallet), actors, sig);
    }

    function test_importAccount_revertsOnCreatedAccount() public {
        // A created account is already initialized (localSequence == 1), so it cannot be imported.
        (address account,) = _createK1Account(900);

        IAccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(vm.addr(901));
        vm.expectRevert();
        accountConfiguration.importAccount(account, actors, "");
    }

    function test_importAccount_revertsWhenLocked() public {
        uint256 ownerPk = 700;
        MockERC1271Wallet wallet = new MockERC1271Wallet(vm.addr(ownerPk));

        vm.prank(address(wallet));
        accountConfiguration.lock(1 hours);

        IAccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(vm.addr(ownerPk));
        bytes32 digest = _computeImportDigest(address(wallet), actors);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);

        vm.expectRevert();
        accountConfiguration.importAccount(address(wallet), actors, abi.encodePacked(r, s, v));
    }

    function test_importAccount_revertsOnDelegatedAccount() public {
        uint256 ownerPk = 700;
        address eoa = vm.addr(ownerPk);
        // Make the EOA an EIP-7702 delegated account (code = 0xef0100 || delegate).
        vm.etch(eoa, abi.encodePacked(hex"ef0100", defaultAccountImplementation));

        IAccountConfiguration.InitialActor[] memory actors = _singleUnrestrictedActor(eoa);
        bytes32 digest = _computeImportDigest(eoa, actors);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);

        // Rejected before the ERC-1271 check: delegated accounts cannot be imported.
        vm.expectRevert();
        accountConfiguration.importAccount(eoa, actors, abi.encodePacked(r, s, v));
    }
}
