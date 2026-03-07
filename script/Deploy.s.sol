// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";

import {AccountConfiguration} from "../src/AccountConfiguration.sol";
import {DefaultAccount} from "../src/accounts/DefaultAccount.sol";
import {DefaultHighRateAccount} from "../src/accounts/DefaultHighRateAccount.sol";
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
contract Deploy is Script {
    function run() public {
        vm.startBroadcast();

        // ── Reference verifiers (deployed first — addresses needed by AccountConfiguration) ──

        address k1 = address(new K1Verifier{salt: 0}());
        address p256Raw = address(new P256Verifier{salt: 0}());
        address p256WebAuthn = address(new WebAuthnVerifier{salt: 0}());

        // DelegateVerifier needs AccountConfiguration — use address(0) placeholder,
        // deploy AccountConfiguration, then deploy DelegateVerifier
        AccountConfiguration accountConfig = new AccountConfiguration{salt: 0}(k1, p256Raw, p256WebAuthn, address(0));
        console.log("AccountConfiguration:", address(accountConfig));

        address delegateAddr = address(new DelegateVerifier{salt: 0}(address(accountConfig)));

        address defaultAccount = address(new DefaultAccount{salt: 0}(address(accountConfig)));
        address defaultHighRate = address(new DefaultHighRateAccount{salt: 0}(address(accountConfig)));

        console.log("DefaultAccount:       ", defaultAccount);
        console.log("DefaultHighRateAccount:", defaultHighRate);

        // ── Reference verifiers ──

        console.log("K1Verifier:          ", k1);
        console.log("P256Verifier:        ", p256Raw);
        console.log("WebAuthnVerifier:    ", p256WebAuthn);
        console.log("DelegateVerifier:    ", delegateAddr);

        // ── Additional verifiers ──

        console.log("BLSVerifier:         ", address(new BLSVerifier{salt: 0}()));
        console.log("SchnorrVerifier:     ", address(new SchnorrVerifier{salt: 0}()));
        console.log("MultisigVerifier:    ", address(new MultisigVerifier{salt: 0}()));
        console.log("Groth16Verifier:     ", address(new Groth16Verifier{salt: 0}()));
        console.log("AlwaysValidVerifier: ", address(new AlwaysValidVerifier{salt: 0}()));

        vm.stopBroadcast();
    }
}
