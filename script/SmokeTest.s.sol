// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";

import {AccountConfiguration} from "../src/AccountConfiguration.sol";
import {IAccountConfiguration} from "../src/interfaces/IAccountConfiguration.sol";
import {IVerifier} from "../src/interfaces/IVerifier.sol";

/// @notice End-to-end smoke test against a live deployment.
///
///         Tests:
///           1. Account creation via AccountConfiguration
///           2. Actor authorization + data reads
///           3. K1 signature verification
///           4. ERC-1167 proxy bytecode correctness
contract SmokeTest is Script {
    uint256 constant SIGNER_PK = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    function run(address acctConfig, address k1Verifier, address defaultImpl) public {
        address signer = vm.addr(SIGNER_PK);
        bytes32 actorId = bytes32(bytes20(signer));
        AccountConfiguration config = AccountConfiguration(acctConfig);

        // 1. Create account
        address account = _createAccount(config, k1Verifier, defaultImpl, actorId);
        console.log("[PASS] Account created:", account);

        // 2. Actor authorization + data reads
        _checkActor(config, account, actorId, k1Verifier);
        console.log("[PASS] Actor authorized with correct verifier");

        // 3. K1 signature verification
        _checkSignature(config, k1Verifier, account);
        console.log("[PASS] K1 verify");

        // 4. ERC-1167 proxy
        require(account.code.length == 45, "expected 45-byte ERC-1167 proxy");
        console.log("[PASS] Account is 45-byte ERC-1167 proxy");

        console.log("");
        console.log("=== ALL SMOKE TESTS PASSED ===");
    }

    function _createAccount(AccountConfiguration config, address k1Verifier, address defaultImpl, bytes32 actorId)
        internal
        returns (address)
    {
        IAccountConfiguration.InitialActor[] memory actors = new IAccountConfiguration.InitialActor[](1);
        actors[0] = IAccountConfiguration.InitialActor({actorId: actorId, verifier: k1Verifier});

        bytes memory bytecode =
            abi.encodePacked(hex"363d3d373d3d3d363d73", defaultImpl, hex"5af43d82803e903d91602b57fd5bf3");

        vm.startBroadcast(SIGNER_PK);
        address account = config.createAccount(bytes32(0), bytecode, actors);
        vm.stopBroadcast();
        return account;
    }

    function _checkActor(AccountConfiguration config, address account, bytes32 actorId, address k1Verifier)
        internal
        view
    {
        IAccountConfiguration.ActorConfig memory actorCfg = config.getActorConfig(account, actorId);
        require(actorCfg.verifier != address(0), "actor not authorized");
        require(actorCfg.verifier == k1Verifier, "wrong verifier");
    }

    function _checkSignature(AccountConfiguration config, address k1Verifier, address account) internal view {
        bytes32 testHash = keccak256("hello EIP-8130");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, testHash);

        bytes memory auth = abi.encodePacked(k1Verifier, r, s, v);
        config.verifyActor(account, testHash, auth);
    }
}
