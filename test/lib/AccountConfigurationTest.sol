// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";

import {AccountConfiguration} from "../../src/AccountConfiguration.sol";
import {IAccountConfiguration} from "../../src/interfaces/IAccountConfiguration.sol";
import {IAuthenticator} from "../../src/interfaces/IAuthenticator.sol";
import {P256Authenticator} from "../../src/authenticators/P256Authenticator.sol";
import {DelegateAuthenticator} from "../../src/authenticators/DelegateAuthenticator.sol";
import {DefaultAccount} from "../../src/accounts/DefaultAccount.sol";

contract AccountConfigurationTest is Test {
    AccountConfiguration public accountConfiguration;
    // The single canonical secp256k1 authenticator (internal ecrecover). Not a deployed contract — it's the
    // K1_AUTHENTICATOR sentinel (address(1)); k1 auth blobs are K1_AUTHENTICATOR(20) || r‖s‖v.
    address public k1Authenticator;
    IAuthenticator public p256Authenticator;
    IAuthenticator public delegateAuthenticator;
    address public defaultAccountImplementation;

    bytes32 constant SIGNED_ACTOR_CHANGES_TYPEHASH = keccak256(
        "SignedActorChanges(address account,uint64 chainId,uint64 sequence,ActorChange[] actorChanges)"
        "ActorChange(uint8 changeType,bytes32 actorId,bytes data)"
    );

    bytes32 constant ACTORCHANGE_TYPEHASH = keccak256("ActorChange(uint8 changeType,bytes32 actorId,bytes data)");

    function setUp() public virtual {
        accountConfiguration = new AccountConfiguration();
        k1Authenticator = accountConfiguration.K1_AUTHENTICATOR();
        p256Authenticator = IAuthenticator(new P256Authenticator());
        delegateAuthenticator = IAuthenticator(new DelegateAuthenticator(address(accountConfiguration)));
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
        actors[0] = IAccountConfiguration.InitialActor({actorId: actorId, authenticator: address(k1Authenticator)});

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        account = accountConfiguration.createAccount(bytes32(0), bytecode, actors);
    }

    function _createK1AccountWithSalt(uint256 pk, bytes32 salt) internal returns (address account, bytes32 actorId) {
        address signer = vm.addr(pk);
        actorId = bytes32(bytes20(signer));

        IAccountConfiguration.InitialActor[] memory actors = new IAccountConfiguration.InitialActor[](1);
        actors[0] = IAccountConfiguration.InitialActor({actorId: actorId, authenticator: address(k1Authenticator)});

        bytes memory bytecode = _computeERC1167Bytecode(defaultAccountImplementation);
        account = accountConfiguration.createAccount(salt, bytecode, actors);
    }

    // ── K1 signature helpers ──

    function _signDigest(uint256 pk, bytes32 digest) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, digest);
        return abi.encodePacked(r, s, v);
    }

    /// @dev Build a canonical K1 auth blob: K1_AUTHENTICATOR(20) || r‖s‖v. This is the single secp256k1 encoding
    ///      for the default EOA and every k1 actor; meaning (implicit owner vs scoped key) is decided by config.
    function _buildK1Auth(uint256 pk, bytes32 digest) internal view returns (bytes memory) {
        bytes memory sig = _signDigest(pk, digest);
        return abi.encodePacked(k1Authenticator, sig);
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
