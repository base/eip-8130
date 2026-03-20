// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";

import {AccountConfiguration} from "../../src/AccountConfiguration.sol";
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

    bytes32 constant OWNER_CHANGE_BATCH_TYPEHASH = keccak256(
        "OwnerChangeBatch(address account,uint64 chainId,uint64 sequence,OwnerChange[] ownerChanges)"
        "OwnerChange(bytes32 ownerId,uint8 changeType,bytes changeData)"
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

        AccountConfiguration.InitializeOwner[] memory owners = new AccountConfiguration.InitializeOwner[](1);
        owners[0] = AccountConfiguration.InitializeOwner({ownerId: ownerId, config: AccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scope: 0x00})});

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        account = accountConfiguration.createAccount(bytes32(0), bytecode, owners);
    }

    function _createK1AccountWithSalt(uint256 pk, bytes32 salt) internal returns (address account, bytes32 ownerId) {
        address signer = vm.addr(pk);
        ownerId = bytes32(bytes20(signer));

        AccountConfiguration.InitializeOwner[] memory owners = new AccountConfiguration.InitializeOwner[](1);
        owners[0] = AccountConfiguration.InitializeOwner({ownerId: ownerId, config: AccountConfiguration.OwnerConfig({verifier: address(k1Verifier), scope: 0x00})});

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

    function _computeOwnerChangeBatchDigest(
        address account,
        uint64 chainId,
        uint64 sequence,
        AccountConfiguration.OwnerChange[] memory ownerChanges
    ) internal pure returns (bytes32) {
        bytes32[] memory ownerChangeHash = new bytes32[](ownerChanges.length);
        for (uint256 i; i < ownerChanges.length; i++) {
            ownerChangeHash[i] = keccak256(
                abi.encode(ownerChanges[i].ownerId, ownerChanges[i].changeType, keccak256(ownerChanges[i].configData))
            );
        }
        return keccak256(
            abi.encode(
                OWNER_CHANGE_BATCH_TYPEHASH, account, chainId, sequence, keccak256(abi.encodePacked(ownerChangeHash))
            )
        );
    }
}
