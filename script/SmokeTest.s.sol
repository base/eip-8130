// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";

import {AccountConfiguration} from "../src/AccountConfiguration.sol";
import {IAuthenticator} from "../src/interfaces/IAuthenticator.sol";

/// @notice End-to-end smoke test against a live deployment.
///
///         Tests:
///           1. Account creation via AccountConfiguration
///           2. Actor authorization + data reads
///           3. K1 signature authentication
///           4. ERC-1167 proxy bytecode correctness
contract SmokeTest is Script {
    uint256 constant SIGNER_PK = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    function run(address acctConfig, address k1Authenticator, address defaultImpl) public {
        address signer = vm.addr(SIGNER_PK);
        bytes32 actorId = bytes32(bytes20(signer));
        AccountConfiguration config = AccountConfiguration(acctConfig);

        // 1. Create account
        address account = _createAccount(config, k1Authenticator, defaultImpl, actorId);
        console.log("[PASS] Account created:", account);

        // 2. Actor authorization + data reads
        _checkActor(config, account, actorId, k1Authenticator);
        console.log("[PASS] Actor authorized with correct authenticator");

        // 3. K1 signature authentication
        _checkSignature(config, k1Authenticator, account);
        console.log("[PASS] K1 authenticate");

        // 4. ERC-1167 proxy
        require(account.code.length == 45, "expected 45-byte ERC-1167 proxy");
        console.log("[PASS] Account is 45-byte ERC-1167 proxy");

        console.log("");
        console.log("=== ALL SMOKE TESTS PASSED ===");
    }

    function _createAccount(AccountConfiguration config, address k1Authenticator, address defaultImpl, bytes32 actorId)
        internal
        returns (address)
    {
        AccountConfiguration.InitialActor[] memory actors = new AccountConfiguration.InitialActor[](1);
        actors[0] = AccountConfiguration.InitialActor({actorId: actorId, authenticator: k1Authenticator});

        bytes memory bytecode =
            abi.encodePacked(hex"363d3d373d3d3d363d73", defaultImpl, hex"5af43d82803e903d91602b57fd5bf3");

        vm.startBroadcast(SIGNER_PK);
        address account = config.createAccount(bytes32(0), bytecode, actors);
        vm.stopBroadcast();
        return account;
    }

    function _checkActor(AccountConfiguration config, address account, bytes32 actorId, address k1Authenticator)
        internal
        view
    {
        AccountConfiguration.ActorConfig memory actorCfg = config.getActorConfig(account, actorId);
        require(actorCfg.authenticator != address(0), "actor not authorized");
        require(actorCfg.authenticator == k1Authenticator, "wrong authenticator");
    }

    function _checkSignature(AccountConfiguration config, address k1Authenticator, address account) internal view {
        bytes32 testHash = keccak256("hello EIP-8130");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, testHash);

        bytes memory auth = abi.encodePacked(k1Authenticator, r, s, v);
        config.authenticateActor(account, testHash, auth);
    }
}
