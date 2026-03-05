// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";

import {AccountConfiguration} from "../src/AccountConfiguration.sol";
import {DefaultAccount} from "../src/accounts/DefaultAccount.sol";
import {DefaultHighThroughputAccount} from "../src/accounts/DefaultHighThroughputAccount.sol";
import {K1Verifier} from "../src/verifiers/K1Verifier.sol";
import {P256Verifier} from "../src/verifiers/P256Verifier.sol";
import {WebAuthnVerifier} from "../src/verifiers/WebAuthnVerifier.sol";
import {DelegateVerifier} from "../src/verifiers/DelegateVerifier.sol";
import {BLSVerifier} from "../src/verifiers/BLSVerifier.sol";
import {SchnorrVerifier} from "../src/verifiers/SchnorrVerifier.sol";
import {MultisigVerifier} from "../src/verifiers/MultisigVerifier.sol";
import {Groth16Verifier} from "../src/verifiers/Groth16Verifier.sol";
import {AlwaysValidVerifier} from "../src/verifiers/AlwaysValidVerifier.sol";

/// @notice Deploys the full EIP-8130 system.
///
///         On 8130 chains the protocol recognises native verifier addresses and uses
///         built-in implementations; unknown verifiers are executed in a sandboxed
///         environment enforced at runtime by the node. On non-8130 chains verifiers
///         are called directly via the Account Configuration contract.
contract Deploy is Script {
    function run() public {
        vm.startBroadcast();

        // ── Core contracts ──

        AccountConfiguration accountConfig = new AccountConfiguration{salt: 0}();
        console.log("AccountConfiguration:", address(accountConfig));

        address defaultAccount = address(new DefaultAccount{salt: 0}(address(accountConfig)));
        console.log("DefaultAccount:      ", defaultAccount);

        address defaultHighThroughputAccount =
            address(new DefaultHighThroughputAccount{salt: 0}(address(accountConfig)));
        console.log("DefaultHighThroughputAccount:      ", defaultHighThroughputAccount);

        // ── Verifiers ──

        console.log("K1Verifier:          ", address(new K1Verifier{salt: 0}()));
        console.log("P256Verifier:        ", address(new P256Verifier{salt: 0}()));
        console.log("WebAuthnVerifier:    ", address(new WebAuthnVerifier{salt: 0}()));
        console.log("DelegateVerifier:    ", address(new DelegateVerifier{salt: 0}(address(accountConfig))));
        console.log("BLSVerifier:         ", address(new BLSVerifier{salt: 0}()));
        console.log("SchnorrVerifier:     ", address(new SchnorrVerifier{salt: 0}()));
        console.log("MultisigVerifier:    ", address(new MultisigVerifier{salt: 0}()));
        console.log("Groth16Verifier:     ", address(new Groth16Verifier{salt: 0}()));
        console.log("AlwaysValidVerifier: ", address(new AlwaysValidVerifier{salt: 0}()));

        vm.stopBroadcast();
    }
}
