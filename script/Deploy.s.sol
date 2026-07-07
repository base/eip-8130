// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";

import {AccountConfiguration} from "../src/AccountConfiguration.sol";
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
///         Only two account implementations are deployed as usable accounts:
///           - DefaultHighRateAccount — the immutable account (deployed behind a 45-byte ERC-1167 proxy);
///           - UpgradeableAccount     — the general upgradeable account (behind UpgradeableProxy).
///         DefaultAccount is the base building block (inherited by both); its bytecode is embedded in the deployed
///         implementations, so it is not deployed standalone. BackwardsCompatible4337Account is a separate, opt-in
///         ERC-4337 example that neither deployed account depends on by default.
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

        // ── Account implementations (singletons; every account proxy delegates to one) ──
        //    DefaultHighRateAccount is the immutable (ERC-1167) account; UpgradeableAccount is the general
        //    upgradeable account. DefaultAccount is an inherited base building block and is not deployed
        //    standalone; BackwardsCompatible4337Account is a separate, opt-in example neither depends on by default.

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
