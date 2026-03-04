// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";

import {AccountConfiguration} from "../src/AccountConfiguration.sol";
import {DefaultAccount} from "../src/accounts/DefaultAccount.sol";
import {K1Verifier} from "../src/verifiers/K1Verifier.sol";
import {P256Verifier} from "../src/verifiers/P256Verifier.sol";
import {WebAuthnVerifier} from "../src/verifiers/WebAuthnVerifier.sol";
import {DelegateVerifier} from "../src/verifiers/DelegateVerifier.sol";
import {BLSVerifier} from "../src/verifiers/BLSVerifier.sol";
import {SchnorrVerifier} from "../src/verifiers/SchnorrVerifier.sol";
import {MultisigVerifier} from "../src/verifiers/MultisigVerifier.sol";
import {Groth16Verifier} from "../src/verifiers/Groth16Verifier.sol";
import {AlwaysValidVerifier} from "../src/verifiers/AlwaysValidVerifier.sol";

import {SandboxLib} from "../src/SandboxLib.sol";

/// @notice Deploys the full EIP-8130 system with sandbox-wrapped verifiers.
///
///         Each native verifier is deployed in two forms:
///           1. Regular contract   — used for direct calls and as the STATICCALL target
///           2. Sandbox wrapper    — 52-byte contract with the 7-byte 8130 sandbox header
///                                   that forwards calls to (1) via STATICCALL
///
///         The sandbox wrappers carry the EIP-8130 header metadata (magic, version)
///         so the protocol on 8130 chains can recognise them. Gas metering is handled
///         by the node (configurable gas cap). On non-8130 chains the wrapper
///         transparently forwards to the real verifier.
contract Deploy is Script {
    uint8 constant SANDBOX_VERSION = 0;

    function run() public {
        vm.startBroadcast();

        // ── Core contracts ──

        AccountConfiguration accountConfig = new AccountConfiguration{salt: 0}();
        console.log("AccountConfiguration:", address(accountConfig));

        address defaultAccount = address(new DefaultAccount{salt: 0}(address(accountConfig)));
        console.log("DefaultAccount:      ", defaultAccount);

        // ── Verifiers (deploy impl + sandbox wrapper, then log) ──

        _deployVerifier("K1Verifier", address(new K1Verifier{salt: 0}()), bytes32("K1"));
        _deployVerifier("P256Verifier", address(new P256Verifier{salt: 0}()), bytes32("P256_RAW"));
        _deployVerifier("WebAuthnVerifier", address(new WebAuthnVerifier{salt: 0}()), bytes32("P256_WEBAUTHN"));
        _deployVerifier(
            "DelegateVerifier",
            address(new DelegateVerifier{salt: 0}(address(accountConfig))),
            bytes32("DELEGATE")
        );
        _deployVerifier("BLSVerifier", address(new BLSVerifier{salt: 0}()), bytes32("BLS"));
        _deployVerifier("SchnorrVerifier", address(new SchnorrVerifier{salt: 0}()), bytes32("SCHNORR"));
        _deployVerifier("MultisigVerifier", address(new MultisigVerifier{salt: 0}()), bytes32("MULTISIG"));
        _deployVerifier("Groth16Verifier", address(new Groth16Verifier{salt: 0}()), bytes32("GROTH16"));
        _deployVerifier(
            "AlwaysValidVerifier", address(new AlwaysValidVerifier{salt: 0}()), bytes32("ALWAYS_VALID")
        );

        vm.stopBroadcast();
    }

    function _deployVerifier(string memory name, address impl, bytes32 salt) internal {
        address sandbox = SandboxLib.deploy(impl, SANDBOX_VERSION, salt);

        console.log(string.concat(name, ":"));
        console.log("  impl:   ", impl);
        console.log("  sandbox:", sandbox);

        (uint8 version, address wrapped, bool valid) = SandboxLib.parseSandboxHeader(sandbox);
        require(valid, string.concat(name, ": invalid sandbox header"));
        require(wrapped == impl, string.concat(name, ": wrapper points to wrong impl"));
        console.log("  header:  magic=8130, version=%d, wraps=%s", version, impl);
    }
}
