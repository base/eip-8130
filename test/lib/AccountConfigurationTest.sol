// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";

import {AccountConfiguration} from "../../src/AccountConfiguration.sol";
import {IAccountConfiguration} from "../../src/interfaces/IAccountConfiguration.sol";
import {IVerifier} from "../../src/interfaces/IVerifier.sol";
import {K1Verifier} from "../../src/verifiers/K1Verifier.sol";
import {P256Verifier} from "../../src/verifiers/P256Verifier.sol";
import {DelegateVerifier} from "../../src/verifiers/DelegateVerifier.sol";
import {DefaultAccount} from "../../src/accounts/DefaultAccount.sol";

contract AccountConfigurationTest is Test {
    AccountConfiguration public accountConfiguration;
    IVerifier public k1Verifier;
    IVerifier public p256Verifier;
    IVerifier public delegateVerifier;
    address public defaultAccountImplementation;

    bytes32 constant SIGNED_ACTOR_CHANGES_TYPEHASH = keccak256(
        "SignedActorChanges(address account,uint64 chainId,uint64 sequence,ActorChange[] actorChanges)"
        "ActorChange(uint8 changeType,bytes32 actorId,bytes data)"
    );

    bytes32 constant ACTORCHANGE_TYPEHASH = keccak256("ActorChange(uint8 changeType,bytes32 actorId,bytes data)");

    function setUp() public virtual {
        k1Verifier = IVerifier(new K1Verifier());
        p256Verifier = IVerifier(new P256Verifier());
        accountConfiguration = new AccountConfiguration();
        delegateVerifier = IVerifier(new DelegateVerifier(address(accountConfiguration)));
        defaultAccountImplementation = address(new DefaultAccount(address(accountConfiguration)));
    }

    // ── Bytecode helpers ──

    function _computeERC1167Bytecode(address implementation) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"363d3d373d3d3d363d73", implementation, hex"5af43d82803e903d91602b57fd5bf3");
    }

    // ── Account creation helpers ──

    function _createK1Account(uint256 pk) internal returns (address account, bytes32 actorId) {
        address signer = vm.addr(pk);
        actorId = bytes32(bytes20(signer));

        IAccountConfiguration.InitialActor[] memory actors = new IAccountConfiguration.InitialActor[](1);
        actors[0] = IAccountConfiguration.InitialActor({actorId: actorId, verifier: address(k1Verifier)});

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        account = accountConfiguration.createAccount(bytes32(0), bytecode, actors);
    }

    function _createK1AccountWithSalt(uint256 pk, bytes32 salt) internal returns (address account, bytes32 actorId) {
        address signer = vm.addr(pk);
        actorId = bytes32(bytes20(signer));

        IAccountConfiguration.InitialActor[] memory actors = new IAccountConfiguration.InitialActor[](1);
        actors[0] = IAccountConfiguration.InitialActor({actorId: actorId, verifier: address(k1Verifier)});

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        account = accountConfiguration.createAccount(salt, bytecode, actors);
    }

    // ── K1 signature helpers ──

    function _signDigest(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Build auth bytes in verifier(20) || data format for K1 verification.
    function _buildK1Auth(uint256 pk, bytes32 digest) internal view returns (bytes memory) {
        bytes memory sig = _signDigest(pk, digest);
        return abi.encodePacked(address(k1Verifier), sig);
    }

    /// @dev Build auth bytes for implicit EOA path: address(0) || ecdsa signature.
    function _buildImplicitEOAAuth(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(address(0), r, s, v);
    }

    /// @dev Build auth bytes for explicit EOA path: address(1) || ecdsa signature.
    function _buildExplicitEOAAuth(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(address(1), r, s, v);
    }

    // ── Canonical digest computation ──

    function _computeActorChangeBatchDigest(
        address account,
        uint64 chainId,
        uint64 sequence,
        IAccountConfiguration.ActorChange[] memory actorChanges
    ) internal pure returns (bytes32) {
        bytes32[] memory actorChangeHash = new bytes32[](actorChanges.length);
        for (uint256 i; i < actorChanges.length; i++) {
            actorChangeHash[i] = keccak256(
                abi.encode(
                    ACTORCHANGE_TYPEHASH,
                    actorChanges[i].changeType,
                    actorChanges[i].actorId,
                    keccak256(actorChanges[i].data)
                )
            );
        }
        return keccak256(
            abi.encode(
                SIGNED_ACTOR_CHANGES_TYPEHASH, account, chainId, sequence, keccak256(abi.encodePacked(actorChangeHash))
            )
        );
    }
}
