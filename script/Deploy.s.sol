// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";

import {AccountConfiguration} from "../src/AccountConfiguration.sol";
import {DefaultAccount} from "../src/accounts/DefaultAccount.sol";
import {P256Authenticator} from "../src/authenticators/P256Authenticator.sol";
import {WebAuthnAuthenticator} from "../src/authenticators/WebAuthnAuthenticator.sol";
import {DelegateAuthenticator} from "../src/authenticators/DelegateAuthenticator.sol";
import {AlwaysValidAuthenticator} from "../src/authenticators/AlwaysValidAuthenticator.sol";
import {PolicyManager} from "../src/policies/PolicyManager.sol";
import {SessionPolicy} from "../src/policies/SessionPolicy.sol";

/// @dev Nick's deterministic deployment proxy — same address on every EVM chain.
///      Receives (salt ++ initCode) as calldata and deploys via CREATE2.
///      https://github.com/Arachnid/deterministic-deployment-proxy
address constant CREATE2_FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

bytes32 constant SALT = bytes32(0);

/// @notice Deploys the full EIP-8130 system: AccountConfiguration, account implementations, canonical
///         authenticators, and the unaudited example policy contracts (PolicyManager, SessionPolicy).
///
///         One account implementation is deployed:
///           - DefaultAccount — the canonical EIP-8130 account, deployed standalone as the direct EIP-7702 delegation
///                              target for EOAs (a 7702 EOA can re-delegate later, so it needs no UUPS wrapper). It is
///                              also the high-rate payer implementation: it respects the AccountConfiguration lock
///                              (blocking outbound value while locked), so an ERC-1167 clone of this address is the
///                              high-rate payer admission path. This script logs that 45-byte runtime bytecode (and
///                              its keccak256) so nodes can pin it.
///
///         Example/unaudited account variants (UpgradeableAccount, BackwardsCompatible4337Account) live in a
///         separate repository and are not deployed here. PolicyManager / SessionPolicy are UNAUDITED reference
///         implementations — integrators should not treat their addresses as blessed infrastructure.
///
///         All addresses are canonical: determined solely by salt + bytecode, independent of the
///         deployer's address or nonce, and identical on every chain.
///
/// @dev Preview all addresses + high-rate payer 1167 match bytecode without deploying:
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

    /// @dev ERC-1167 minimal-proxy runtime bytecode for `implementation`.
    ///      Same encoding used by AccountConfiguration.createAccount callers and by nodes when admitting
    ///      high-rate payer accounts (exact 45-byte code match).
    function _erc1167Runtime(address implementation) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"363d3d373d3d3d363d73", implementation, hex"5af43d82803e903d91602b57fd5bf3");
    }

    /// @dev Init code for each contract, given the resolved AccountConfiguration address.
    function _accountConfigInit() internal pure returns (bytes memory) {
        return type(AccountConfiguration).creationCode;
    }

    function _defaultAccountInit(address accountConfig) internal pure returns (bytes memory) {
        return abi.encodePacked(type(DefaultAccount).creationCode, abi.encode(accountConfig));
    }

    function _delegateAuthInit(address accountConfig) internal pure returns (bytes memory) {
        return abi.encodePacked(type(DelegateAuthenticator).creationCode, abi.encode(accountConfig));
    }

    function _policyManagerInit(address accountConfig) internal pure returns (bytes memory) {
        return abi.encodePacked(type(PolicyManager).creationCode, abi.encode(accountConfig));
    }

    function _sessionPolicyInit(address policyManager) internal pure returns (bytes memory) {
        return abi.encodePacked(type(SessionPolicy).creationCode, abi.encode(policyManager));
    }

    /// @dev Logs the ERC-1167 runtime bytecode (and hash) nodes must match for high-rate payer accounts.
    function _logHighRatePayerMatchBytecode(address implementation) internal pure {
        bytes memory runtime = _erc1167Runtime(implementation);
        console.log("");
        console.log("=== DefaultAccount ERC-1167 match bytecode (high-rate payer, node) ===");
        console.log("Implementation:          ", implementation);
        console.log("Runtime bytecode length: ", runtime.length);
        console.log("Runtime bytecode:");
        console.logBytes(runtime);
        console.log("keccak256(runtime):");
        console.logBytes32(keccak256(runtime));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Address preview  (no deployment)
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Logs the canonical address of every contract in the system, plus the ERC-1167 runtime
    ///         bytecode nodes must match for high-rate payer (DefaultAccount) clones.
    ///         Addresses depend only on the compiler output and SALT — they are
    ///         the same on every chain and are known before deployment.
    function addresses() public pure {
        address accountConfig = _addr(_accountConfigInit());
        address defaultAccount = _addr(_defaultAccountInit(accountConfig));
        address policyManager = _addr(_policyManagerInit(accountConfig));

        console.log("AccountConfiguration:    ", accountConfig);
        console.log("");
        console.log("=== Account implementation ===");
        console.log("DefaultAccount:          ", defaultAccount);
        console.log("");
        console.log("=== Authenticators ===");
        console.log("(secp256k1 is built in: AccountConfiguration.K1_AUTHENTICATOR() == address(1))");
        console.log("P256Authenticator:       ", _addr(type(P256Authenticator).creationCode));
        console.log("WebAuthnAuthenticator:   ", _addr(type(WebAuthnAuthenticator).creationCode));
        console.log("DelegateAuthenticator:   ", _addr(_delegateAuthInit(accountConfig)));
        console.log("AlwaysValidAuthenticator:", _addr(type(AlwaysValidAuthenticator).creationCode));
        console.log("");
        console.log("=== Example policies (unaudited) ===");
        console.log("PolicyManager:           ", policyManager);
        console.log("SessionPolicy:           ", _addr(_sessionPolicyInit(policyManager)));

        _logHighRatePayerMatchBytecode(defaultAccount);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Deployment
    // ─────────────────────────────────────────────────────────────────────────

    function run() public {
        vm.startBroadcast();

        // ── Core system contract ──

        address accountConfig = _create2(_accountConfigInit());

        // ── Account implementation (singleton; every account proxy — and every 7702 EOA — delegates to it) ──
        //    DefaultAccount is deployed standalone as the direct EIP-7702 delegation target for EOAs, and its
        //    ERC-1167 clone is the high-rate payer admission path.

        address defaultAccount = _create2(_defaultAccountInit(accountConfig));

        // ── Authenticators (secp256k1 is built into AccountConfiguration; no contract to deploy) ──

        address p256 = _create2(type(P256Authenticator).creationCode);
        address webAuthn = _create2(type(WebAuthnAuthenticator).creationCode);
        address delegate = _create2(_delegateAuthInit(accountConfig));
        address alwaysValid = _create2(type(AlwaysValidAuthenticator).creationCode);

        // ── Example policies (unaudited reference implementations) ──

        address policyManager = _create2(_policyManagerInit(accountConfig));
        address sessionPolicy = _create2(_sessionPolicyInit(policyManager));

        vm.stopBroadcast();

        console.log("AccountConfiguration:    ", accountConfig);
        console.log("");
        console.log("=== Account implementation ===");
        console.log("DefaultAccount:          ", defaultAccount);
        console.log("");
        console.log("=== Authenticators ===");
        console.log("(secp256k1 is built in: AccountConfiguration.K1_AUTHENTICATOR() == address(1))");
        console.log("P256Authenticator:       ", p256);
        console.log("WebAuthnAuthenticator:   ", webAuthn);
        console.log("DelegateAuthenticator:   ", delegate);
        console.log("AlwaysValidAuthenticator:", alwaysValid);
        console.log("");
        console.log("=== Example policies (unaudited) ===");
        console.log("PolicyManager:           ", policyManager);
        console.log("SessionPolicy:           ", sessionPolicy);

        // Emit the exact 45-byte ERC-1167 runtime bytecode (and hash) nodes must match for high-rate payers.
        _logHighRatePayerMatchBytecode(defaultAccount);
    }
}
