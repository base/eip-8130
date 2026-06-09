// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";

import {AccountConfiguration} from "../src/AccountConfiguration.sol";
import {DefaultAccount} from "../src/accounts/DefaultAccount.sol";
import {DefaultHighRateAccount} from "../src/accounts/DefaultHighRateAccount.sol";
import {K1Authenticator} from "../src/authenticators/K1Authenticator.sol";
import {P256Authenticator} from "../src/authenticators/P256Authenticator.sol";
import {WebAuthnAuthenticator} from "../src/authenticators/WebAuthnAuthenticator.sol";
import {DelegateAuthenticator} from "../src/authenticators/DelegateAuthenticator.sol";
import {AlwaysValidAuthenticator} from "../src/authenticators/AlwaysValidAuthenticator.sol";

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
        console.log("K1Authenticator:            ", _addr(type(K1Authenticator).creationCode));
        console.log("P256Authenticator:          ", _addr(type(P256Authenticator).creationCode));
        console.log("WebAuthnAuthenticator:      ", _addr(type(WebAuthnAuthenticator).creationCode));
        console.log(
            "DelegateAuthenticator:      ",
            _addr(abi.encodePacked(type(DelegateAuthenticator).creationCode, abi.encode(accountConfig)))
        );
        console.log("AlwaysValidAuthenticator:   ", _addr(type(AlwaysValidAuthenticator).creationCode));
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

        // ── Authenticators ──

        address k1 = _create2(type(K1Authenticator).creationCode);
        address p256 = _create2(type(P256Authenticator).creationCode);
        address webAuthn = _create2(type(WebAuthnAuthenticator).creationCode);
        address delegate =
            _create2(abi.encodePacked(type(DelegateAuthenticator).creationCode, abi.encode(accountConfig)));
        address alwaysValid = _create2(type(AlwaysValidAuthenticator).creationCode);

        console.log("AccountConfiguration:  ", accountConfig);
        console.log("DefaultAccount:        ", defaultAccount);
        console.log("DefaultHighRateAccount:", defaultHighRate);
        console.log("");
        console.log("K1Authenticator:            ", k1);
        console.log("P256Authenticator:          ", p256);
        console.log("WebAuthnAuthenticator:      ", webAuthn);
        console.log("DelegateAuthenticator:      ", delegate);
        console.log("AlwaysValidAuthenticator:   ", alwaysValid);

        vm.stopBroadcast();
    }
}
