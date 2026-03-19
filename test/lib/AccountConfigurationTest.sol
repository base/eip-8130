// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";

import {AccountConfiguration} from "../../src/AccountConfiguration.sol";
import {InitialOwner} from "../../src/AccountDeployer.sol";
import {ConfigOperation} from "../../src/AccountConfigDigest.sol";
import {IVerifier} from "../../src/verifiers/IVerifier.sol";
import {K1Verifier} from "../../src/verifiers/K1Verifier.sol";
import {P256Verifier} from "../../src/verifiers/P256Verifier.sol";
import {WebAuthnVerifier} from "../../src/verifiers/WebAuthnVerifier.sol";
import {DelegateVerifier} from "../../src/verifiers/DelegateVerifier.sol";
import {DefaultAccount} from "../../src/accounts/DefaultAccount.sol";

contract AccountConfigurationTest is Test {
    AccountConfiguration public accountConfiguration;
    IVerifier public k1Verifier;
    IVerifier public p256Verifier;
    IVerifier public webAuthnVerifier;
    IVerifier public delegateVerifier;
    address public defaultAccountImplementation;

    bytes32 constant CONFIG_CHANGE_TYPEHASH = keccak256(
        "ConfigChange(address account,uint64 chainId,uint64 sequence,ConfigOperation[] operations)"
        "ConfigOperation(uint8 opType,address verifier,bytes32 ownerId,uint8 scope)"
    );

    function setUp() public virtual {
        k1Verifier = IVerifier(new K1Verifier());
        p256Verifier = IVerifier(new P256Verifier());
        webAuthnVerifier = IVerifier(new WebAuthnVerifier());
        accountConfiguration =
            new AccountConfiguration(address(k1Verifier), address(p256Verifier), address(webAuthnVerifier), address(0));
        delegateVerifier = IVerifier(new DelegateVerifier(address(accountConfiguration)));
        defaultAccountImplementation = address(new DefaultAccount(address(accountConfiguration)));
    }

    // ── Bytecode helpers ──

    function _computeERC1167Bytecode(address implementation) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"363d3d373d3d3d363d73", implementation, hex"5af43d82803e903d91602b57fd5bf3");
    }

    // ── Account creation helpers ──

    function _createK1Account(uint256 pk) internal returns (address account, bytes32 ownerId) {
        address signer = vm.addr(pk);
        ownerId = bytes32(bytes20(signer));

        InitialOwner[] memory owners = new InitialOwner[](1);
        owners[0] = InitialOwner({verifier: address(k1Verifier), ownerId: ownerId, scope: 0x00});

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        account = accountConfiguration.createAccount(bytes32(0), bytecode, owners);
    }

    function _createK1AccountWithSalt(uint256 pk, bytes32 salt) internal returns (address account, bytes32 ownerId) {
        address signer = vm.addr(pk);
        ownerId = bytes32(bytes20(signer));

        InitialOwner[] memory owners = new InitialOwner[](1);
        owners[0] = InitialOwner({verifier: address(k1Verifier), ownerId: ownerId, scope: 0x00});

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        account = accountConfiguration.createAccount(salt, bytecode, owners);
    }

    // ── K1 signature helpers ──

    function _signDigest(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Build authorizerAuth for verifySignature / isValidSignature: type_byte || ecdsaSig
    function _buildK1Auth(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        bytes memory sig = _signDigest(pk, digest);
        return abi.encodePacked(uint8(0x01), sig);
    }

    // ── Canonical digest computation ──

    function _computeConfigChangeDigest(
        address account,
        uint64 chainId,
        uint64 sequence,
        ConfigOperation[] memory operations
    ) internal pure returns (bytes32) {
        bytes32[] memory opHashes = new bytes32[](operations.length);
        for (uint256 i; i < operations.length; i++) {
            opHashes[i] = keccak256(
                abi.encode(operations[i].opType, operations[i].verifier, operations[i].ownerId, operations[i].scope)
            );
        }
        return keccak256(
            abi.encode(CONFIG_CHANGE_TYPEHASH, account, chainId, sequence, keccak256(abi.encodePacked(opHashes)))
        );
    }
}
