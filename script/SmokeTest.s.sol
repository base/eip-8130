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
///           2. Owner authorization + data reads
///           3. K1 signature verification
///           4. ERC-1167 proxy bytecode correctness
contract SmokeTest is Script {
    uint256 constant SIGNER_PK = 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80;

    function run(address acctConfig, address k1Verifier, address defaultImpl) public {
        address signer = vm.addr(SIGNER_PK);
        bytes32 ownerId = bytes32(bytes20(signer));
        AccountConfiguration config = AccountConfiguration(acctConfig);

        // 1. Create account
        address account = _createAccount(config, k1Verifier, defaultImpl, ownerId);
        console.log("[PASS] Account created:", account);

        // 2. Owner authorization + data reads
        _checkOwner(config, account, ownerId, k1Verifier);
        console.log("[PASS] Owner authorized with correct verifier");

        // 3. K1 signature verification
        _checkSignature(config, k1Verifier, account);
        console.log("[PASS] K1 verify");

        // 4. ERC-1167 proxy
        require(account.code.length == 45, "expected 45-byte ERC-1167 proxy");
        console.log("[PASS] Account is 45-byte ERC-1167 proxy");

        console.log("");
        console.log("=== ALL SMOKE TESTS PASSED ===");
    }

    function _createAccount(AccountConfiguration config, address k1Verifier, address defaultImpl, bytes32 ownerId)
        internal
        returns (address)
    {
        IAccountConfiguration.InitializeOwner[] memory owners = new IAccountConfiguration.InitializeOwner[](1);
        owners[0] = IAccountConfiguration.InitializeOwner({
            ownerId: ownerId, config: IAccountConfiguration.OwnerConfig({verifier: k1Verifier, scopes: 0x00})
        });

        bytes memory bytecode =
            abi.encodePacked(hex"363d3d373d3d3d363d73", defaultImpl, hex"5af43d82803e903d91602b57fd5bf3");

        vm.startBroadcast(SIGNER_PK);
        address account = config.createAccount(bytes32(0), bytecode, owners);
        vm.stopBroadcast();
        return account;
    }

    function _checkOwner(AccountConfiguration config, address account, bytes32 ownerId, address k1Verifier)
        internal
        view
    {
        IAccountConfiguration.OwnerConfig memory ownerCfg = config.getOwnerConfig(account, ownerId);
        require(ownerCfg.verifier != address(0), "owner not authorized");
        require(ownerCfg.verifier == k1Verifier, "wrong verifier");
    }

    function _checkSignature(AccountConfiguration config, address k1Verifier, address account) internal view {
        bytes32 testHash = keccak256("hello EIP-8130");
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_PK, testHash);

        IAccountConfiguration.Verification memory verification = IAccountConfiguration.Verification({
            ownerId: bytes32(bytes20(vm.addr(SIGNER_PK))), verifierData: abi.encodePacked(r, s, v)
        });
        config.verify(account, testHash, verification);
    }
}
