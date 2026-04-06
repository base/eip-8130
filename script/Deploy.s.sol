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

/// @dev Nick's deterministic deployment proxy — same address on every EVM chain.
///      Receives (salt ++ initCode) as calldata and deploys via CREATE2.
///      https://github.com/Arachnid/deterministic-deployment-proxy
address constant CREATE2_FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

bytes32 constant SALT = bytes32(0);

/// @notice Deploys the full EIP-8130 system.
///         All addresses are canonical: determined solely by salt + bytecode,
///         independent of the deployer's address or nonce.
///
/// @dev Preview all addresses without deploying:
///      forge script script/Deploy.s.sol --sig "addresses()"
contract Deploy is Script {
    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev Computes the canonical CREATE2 address for the given init code.
    function _addr(bytes memory initCode) internal pure returns (address) {
        return address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), CREATE2_FACTORY, SALT, keccak256(initCode)))))
        );
    }

    /// @dev Deploys initCode through the singleton CREATE2 factory.
    ///      Idempotent: if the contract is already deployed the call is skipped
    ///      and the pre-existing address is returned.
    function _create2(bytes memory initCode) internal returns (address addr) {
        addr = _addr(initCode);
        if (addr.code.length > 0) return addr;
        (bool ok,) = CREATE2_FACTORY.call(abi.encodePacked(SALT, initCode));
        require(ok && addr.code.length > 0, "create2 deployment failed");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Address preview  (no deployment)
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Logs the canonical address of every contract in the system.
    ///         Addresses depend only on the compiler output and SALT — they are
    ///         the same on every chain and are known before deployment.
    function addresses() public {
        address accountConfig = _addr(type(AccountConfiguration).creationCode);

        console.log("AccountConfiguration:  ", accountConfig);
        console.log(
            "DefaultAccount:        ",
            _addr(abi.encodePacked(type(DefaultAccount).creationCode, abi.encode(accountConfig)))
        );
        console.log(
            "DefaultHighRateAccount:",
            _addr(abi.encodePacked(type(DefaultHighRateAccount).creationCode, abi.encode(accountConfig)))
        );
        console.log("");
        console.log("K1Verifier:            ", _addr(type(K1Verifier).creationCode));
        console.log("P256Verifier:          ", _addr(type(P256Verifier).creationCode));
        console.log("WebAuthnVerifier:      ", _addr(type(WebAuthnVerifier).creationCode));
        console.log(
            "DelegateVerifier:      ",
            _addr(abi.encodePacked(type(DelegateVerifier).creationCode, abi.encode(accountConfig)))
        );
        console.log("BLSVerifier:           ", _addr(type(BLSVerifier).creationCode));
        console.log("SchnorrVerifier:       ", _addr(type(SchnorrVerifier).creationCode));
        console.log("MultisigVerifier:      ", _addr(type(MultisigVerifier).creationCode));
        console.log("Groth16Verifier:       ", _addr(type(Groth16Verifier).creationCode));
        console.log("AlwaysValidVerifier:   ", _addr(type(AlwaysValidVerifier).creationCode));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Deployment
    // ─────────────────────────────────────────────────────────────────────────

    function run() public {
        vm.startBroadcast();

        // ── Core ──

        address accountConfig = _create2(type(AccountConfiguration).creationCode);
        address defaultAccount =
            _create2(abi.encodePacked(type(DefaultAccount).creationCode, abi.encode(accountConfig)));
        address defaultHighRate =
            _create2(abi.encodePacked(type(DefaultHighRateAccount).creationCode, abi.encode(accountConfig)));

        // ── Verifiers ──

        address k1 = _create2(type(K1Verifier).creationCode);
        address p256 = _create2(type(P256Verifier).creationCode);
        address webAuthn = _create2(type(WebAuthnVerifier).creationCode);
        address delegate = _create2(abi.encodePacked(type(DelegateVerifier).creationCode, abi.encode(accountConfig)));
        address bls = _create2(type(BLSVerifier).creationCode);
        address schnorr = _create2(type(SchnorrVerifier).creationCode);
        address multisig = _create2(type(MultisigVerifier).creationCode);
        address groth16 = _create2(type(Groth16Verifier).creationCode);
        address alwaysValid = _create2(type(AlwaysValidVerifier).creationCode);

        console.log("AccountConfiguration:  ", accountConfig);
        console.log("DefaultAccount:        ", defaultAccount);
        console.log("DefaultHighRateAccount:", defaultHighRate);
        console.log("");
        console.log("K1Verifier:            ", k1);
        console.log("P256Verifier:          ", p256);
        console.log("WebAuthnVerifier:      ", webAuthn);
        console.log("DelegateVerifier:      ", delegate);
        console.log("BLSVerifier:           ", bls);
        console.log("SchnorrVerifier:       ", schnorr);
        console.log("MultisigVerifier:      ", multisig);
        console.log("Groth16Verifier:       ", groth16);
        console.log("AlwaysValidVerifier:   ", alwaysValid);

        vm.stopBroadcast();
    }
}
