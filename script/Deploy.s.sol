// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";

import {AccountConfiguration} from "../src/AccountConfiguration.sol";
import {K1Verifier} from "../src/verifiers/K1Verifier.sol";
import {P256Verifier} from "../src/verifiers/P256Verifier.sol";
import {WebAuthnVerifier} from "../src/verifiers/WebAuthnVerifier.sol";
import {DelegatedVerifier} from "../src/verifiers/DelegatedVerifier.sol";

contract Deploy is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        address accountConfiguration = address(new AccountConfiguration{salt: 0}());
        new K1Verifier{salt: 0}();
        new P256Verifier{salt: 0}();
        new WebAuthnVerifier{salt: 0}();
        new DelegatedVerifier{salt: 0}(accountConfiguration);

        vm.stopBroadcast();
    }
}
