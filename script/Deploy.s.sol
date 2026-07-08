// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";

import {AccountConfiguration} from "../src/AccountConfiguration.sol";
import {DefaultAccount} from "../src/accounts/DefaultAccount.sol";
import {DefaultHighRateAccount} from "../src/accounts/DefaultHighRateAccount.sol";
import {UpgradeableAccount} from "../src/accounts/UpgradeableAccount.sol";
import {P256Authenticator} from "../src/authenticators/P256Authenticator.sol";
import {WebAuthnAuthenticator} from "../src/authenticators/WebAuthnAuthenticator.sol";
import {DelegateAuthenticator} from "../src/authenticators/DelegateAuthenticator.sol";
import {AlwaysValidAuthenticator} from "../src/authenticators/AlwaysValidAuthenticator.sol";

/// @dev Nick's deterministic deployment proxy — same address on every EVM chain.
///      Receives (salt ++ initCode) as calldata and deploys via CREATE2.
///      https://github.com/Arachnid/deterministic-deployment-proxy
address constant CREATE2_FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

bytes32 constant SALT = bytes32(0);

/// @notice Deploys the full EIP-8130 system: the AccountConfiguration system contract, the account
///         implementations, and every canonical authenticator.
///
///         Three account implementations are deployed:
///           - DefaultAccount         — the bare building block, deployed standalone as the direct EIP-7702
///                                      delegation target for EOAs (no proxy needed; a 7702 EOA can just
///                                      re-delegate to a new address later, so it needs no UUPS wrapper);
///           - DefaultHighRateAccount — the immutable smart-account variant (deployed behind a 45-byte ERC-1167
///                                      proxy);
///           - UpgradeableAccount     — the general upgradeable smart-account variant (behind UpgradeableProxy).
///         BackwardsCompatible4337Account is a separate, opt-in ERC-4337 example that none of the above depend on
///         by default.
///
///         All addresses are canonical: determined solely by salt + bytecode, independent of the
///         deployer's address or nonce, and identical on every chain.
///
/// @dev Preview all addresses without deploying:
///      forge script script/Deploy.s.sol --sig "addresses()"
///
///      Deploy + verify (Blockscout, no API key needed):
///      forge script script/Deploy.s.sol --rpc-url $RPC_URL --broadcast \
///        --private-key $PRIVATE_KEY --verify \
///        --verifier blockscout --verifier-url https://base-sepolia.blockscout.com/api/
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

    /// @dev Init code for each contract, given the resolved AccountConfiguration address.
    function _accountConfigInit() internal pure returns (bytes memory) {
        return type(AccountConfiguration).creationCode;
    }

    function _defaultAccountInit(address accountConfig) internal pure returns (bytes memory) {
        return abi.encodePacked(type(DefaultAccount).creationCode, abi.encode(accountConfig));
    }

    function _defaultHighRateInit(address accountConfig) internal pure returns (bytes memory) {
        return abi.encodePacked(type(DefaultHighRateAccount).creationCode, abi.encode(accountConfig));
    }

    function _upgradeableAccountInit(address accountConfig) internal pure returns (bytes memory) {
        return abi.encodePacked(type(UpgradeableAccount).creationCode, abi.encode(accountConfig));
    }

    function _delegateAuthInit(address accountConfig) internal pure returns (bytes memory) {
        return abi.encodePacked(type(DelegateAuthenticator).creationCode, abi.encode(accountConfig));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Address preview  (no deployment)
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Logs the canonical address of every contract in the system.
    ///         Addresses depend only on the compiler output and SALT — they are
    ///         the same on every chain and are known before deployment.
    function addresses() public pure {
        address accountConfig = _addr(_accountConfigInit());

        console.log("AccountConfiguration:    ", accountConfig);
        console.log("");
        console.log("=== Account implementations ===");
        console.log("DefaultAccount:          ", _addr(_defaultAccountInit(accountConfig)));
        console.log("DefaultHighRateAccount:  ", _addr(_defaultHighRateInit(accountConfig)));
        console.log("UpgradeableAccount:      ", _addr(_upgradeableAccountInit(accountConfig)));
        console.log("");
        console.log("=== Authenticators ===");
        console.log("(secp256k1 is built in: AccountConfiguration.K1_AUTHENTICATOR() == address(1))");
        console.log("P256Authenticator:       ", _addr(type(P256Authenticator).creationCode));
        console.log("WebAuthnAuthenticator:   ", _addr(type(WebAuthnAuthenticator).creationCode));
        console.log("DelegateAuthenticator:   ", _addr(_delegateAuthInit(accountConfig)));
        console.log("AlwaysValidAuthenticator:", _addr(type(AlwaysValidAuthenticator).creationCode));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Deployment
    // ─────────────────────────────────────────────────────────────────────────

    function run() public {
        vm.startBroadcast();

        // ── Core system contract ──

        address accountConfig = _create2(_accountConfigInit());

        // ── Account implementations (singletons; every account proxy — and every 7702 EOA — delegates to one) ──
        //    DefaultAccount is deployed standalone as the direct EIP-7702 delegation target for EOAs.
        //    DefaultHighRateAccount is the immutable (ERC-1167) smart-account variant; UpgradeableAccount is the
        //    general upgradeable smart-account variant. BackwardsCompatible4337Account is a separate, opt-in
        //    example that none of the above depend on by default.

        address defaultAccount = _create2(_defaultAccountInit(accountConfig));
        address defaultHighRate = _create2(_defaultHighRateInit(accountConfig));
        address upgradeableAccount = _create2(_upgradeableAccountInit(accountConfig));

        // ── Authenticators (secp256k1 is built into AccountConfiguration; no contract to deploy) ──

        address p256 = _create2(type(P256Authenticator).creationCode);
        address webAuthn = _create2(type(WebAuthnAuthenticator).creationCode);
        address delegate = _create2(_delegateAuthInit(accountConfig));
        address alwaysValid = _create2(type(AlwaysValidAuthenticator).creationCode);

        console.log("AccountConfiguration:    ", accountConfig);
        console.log("");
        console.log("=== Account implementations ===");
        console.log("DefaultAccount:          ", defaultAccount);
        console.log("DefaultHighRateAccount:  ", defaultHighRate);
        console.log("UpgradeableAccount:      ", upgradeableAccount);
        console.log("");
        console.log("=== Authenticators ===");
        console.log("(secp256k1 is built in: AccountConfiguration.K1_AUTHENTICATOR() == address(1))");
        console.log("P256Authenticator:       ", p256);
        console.log("WebAuthnAuthenticator:   ", webAuthn);
        console.log("DelegateAuthenticator:   ", delegate);
        console.log("AlwaysValidAuthenticator:", alwaysValid);

        vm.stopBroadcast();
    }
}
