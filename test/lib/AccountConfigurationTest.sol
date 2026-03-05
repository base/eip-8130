// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";

import {AccountConfiguration} from "../../src/AccountConfiguration.sol";
import {InitialKey} from "../../src/AccountDeployer.sol";
import {KeyOperation, AccountOperation} from "../../src/AccountConfigDigest.sol";
import {IAuthVerifier} from "../../src/verifiers/IAuthVerifier.sol";
import {K1Verifier} from "../../src/verifiers/K1Verifier.sol";
import {P256Verifier} from "../../src/verifiers/P256Verifier.sol";
import {WebAuthnVerifier} from "../../src/verifiers/WebAuthnVerifier.sol";
import {DelegateVerifier} from "../../src/verifiers/DelegateVerifier.sol";
import {DefaultAccount} from "../../src/accounts/DefaultAccount.sol";

contract AccountConfigurationTest is Test {
    AccountConfiguration public accountConfiguration;
    IAuthVerifier public k1Verifier;
    IAuthVerifier public p256Verifier;
    IAuthVerifier public webAuthnVerifier;
    IAuthVerifier public delegateVerifier;
    address public defaultAccountImplementation;

    bytes32 constant KEY_CHANGE_TYPEHASH = keccak256(
        "KeyChange(address account,uint64 chainId,uint64 sequence,KeyOperation[] operations)"
        "KeyOperation(uint8 opType,address verifier,bytes32 keyId,uint8 flags)"
    );
    bytes32 constant ACCOUNT_CHANGE_TYPEHASH = keccak256(
        "AccountChange(address account,uint64 chainId,uint64 sequence,AccountOperation[] operations)"
        "AccountOperation(uint8 opType,uint8 flags,uint32 unlockDelay)"
    );

    function setUp() public virtual {
        accountConfiguration = new AccountConfiguration();
        k1Verifier = IAuthVerifier(new K1Verifier());
        p256Verifier = IAuthVerifier(new P256Verifier());
        webAuthnVerifier = IAuthVerifier(new WebAuthnVerifier());
        delegateVerifier = IAuthVerifier(new DelegateVerifier(address(accountConfiguration)));
        defaultAccountImplementation = address(new DefaultAccount(address(accountConfiguration)));
    }

    // ── Bytecode helpers ──

    function _computeERC1167Bytecode(address implementation) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"363d3d373d3d3d363d73", implementation, hex"5af43d82803e903d91602b57fd5bf3");
    }

    // ── Account creation helpers ──

    function _createK1Account(uint256 pk) internal returns (address account, bytes32 keyId) {
        address signer = vm.addr(pk);
        keyId = bytes32(bytes20(signer));

        InitialKey[] memory keys = new InitialKey[](1);
        keys[0] = InitialKey({verifier: address(k1Verifier), keyId: keyId});

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        account = accountConfiguration.createAccount(bytes32(0), bytecode, keys);
    }

    function _createK1AccountWithSalt(uint256 pk, bytes32 salt) internal returns (address account, bytes32 keyId) {
        address signer = vm.addr(pk);
        keyId = bytes32(bytes20(signer));

        InitialKey[] memory keys = new InitialKey[](1);
        keys[0] = InitialKey({verifier: address(k1Verifier), keyId: keyId});

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        account = accountConfiguration.createAccount(salt, bytecode, keys);
    }

    // ── K1 signature helpers ──

    function _signDigest(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Build authorizerAuth for isValidSignature: abi.encode(keyId, ecdsaSig)
    function _buildK1Auth(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        address signer = vm.addr(pk);
        bytes32 keyId = bytes32(bytes20(signer));
        bytes memory sig = _signDigest(pk, digest);
        return abi.encode(keyId, sig);
    }

    // ── Canonical digest computation ──

    function _computeKeyChangeDigest(address account, uint64 chainId, uint64 sequence, KeyOperation[] memory operations)
        internal
        pure
        returns (bytes32)
    {
        bytes32[] memory opHashes = new bytes32[](operations.length);
        for (uint256 i; i < operations.length; i++) {
            opHashes[i] = keccak256(
                abi.encode(operations[i].opType, operations[i].verifier, operations[i].keyId, operations[i].flags)
            );
        }
        return
            keccak256(
                abi.encode(KEY_CHANGE_TYPEHASH, account, chainId, sequence, keccak256(abi.encodePacked(opHashes)))
            );
    }

    function _computeAccountChangeDigest(
        address account,
        uint64 chainId,
        uint64 sequence,
        AccountOperation[] memory operations
    ) internal pure returns (bytes32) {
        bytes32[] memory opHashes = new bytes32[](operations.length);
        for (uint256 i; i < operations.length; i++) {
            opHashes[i] = keccak256(abi.encode(operations[i].opType, operations[i].flags, operations[i].unlockDelay));
        }
        return keccak256(
            abi.encode(ACCOUNT_CHANGE_TYPEHASH, account, chainId, sequence, keccak256(abi.encodePacked(opHashes)))
        );
    }
}
