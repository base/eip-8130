// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";

import {Keystore} from "../src/Keystore.sol";
import {DefaultAccount} from "../src/accounts/DefaultAccount.sol";
import {CanonicalHighRatePayerAccount} from "../src/accounts/CanonicalHighRatePayerAccount.sol";
import {P256Authenticator} from "../src/authenticators/P256Authenticator.sol";
import {WebAuthnAuthenticator} from "../src/authenticators/WebAuthnAuthenticator.sol";
import {DelegateAuthenticator} from "../src/authenticators/DelegateAuthenticator.sol";
import {PolicyManager} from "../src/policies/PolicyManager.sol";
import {SessionPolicy} from "../src/policies/SessionPolicy.sol";

/// @dev Nick's deterministic deployment proxy — same address on every EVM chain.
///      Receives (salt ++ initCode) as calldata and deploys via CREATE2.
///      https://github.com/Arachnid/deterministic-deployment-proxy
address constant CREATE2_FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

bytes32 constant DEFAULT_SALT = bytes32(0);

/// @dev Keystore: 0x8130...00ac
bytes32 constant KEYSTORE_SALT = 0xf8341777f1a47fdc9c6bbb706dfa8e4f44580ec92fb58e3aae32d77c9d6039a8;
/// @dev DefaultAccount: 0x8130...adef
bytes32 constant DEFAULT_ACCOUNT_SALT = 0x0000000000000000000000000000000000000000000000000000000139a99218;
/// @dev CanonicalHighRatePayerAccount: 0x8130...fa57
bytes32 constant HIGH_RATE_PAYER_SALT = 0x00000000000000000000000000000000000000000000000000000000ac6f081b;
/// @dev P256Authenticator: 0x8130...a256
bytes32 constant P256_SALT = 0x000000000000000000000000000000000000000000000000000000014139e07b;
/// @dev WebAuthnAuthenticator: 0x8130...f1d0
bytes32 constant WEBAUTHN_SALT = 0x000000000000000000000000000000000000000000000000000000015ec496a4;
/// @dev DelegateAuthenticator: 0x8130...ade1
bytes32 constant DELEGATE_SALT = 0x000000000000000000000000000000000000000000000000000000006f100b8d;
/// @dev PolicyManager: 0x8130...0ac1
bytes32 constant POLICY_MANAGER_SALT = 0x000000000000000000000000000000000000000000000000000000003c1c1ee0;
/// @dev SessionPolicy: 0x8130...5e55
bytes32 constant SESSION_POLICY_SALT = 0x0000000000000000000000000000000000000000000000000000000020ca10ab;

/// @notice Deploys the full EIP-8130 system: Keystore, account implementations, canonical
///         authenticators, and the unaudited example policy contracts (PolicyManager, SessionPolicy).
///
///         Two account implementations are deployed:
///           - DefaultAccount                  — the bare building block, deployed standalone as the direct
///                                                EIP-7702 delegation target for EOAs (no proxy needed; a 7702 EOA
///                                                can just re-delegate to a new address later, so it needs no UUPS
///                                                wrapper);
///           - CanonicalHighRatePayerAccount   — high-rate payer account implementation. Per-account instances are
///                                                ERC-1167 clones of this address (the same bytecode nodes match for
///                                                high-rate payer admission). This script logs that 45-byte runtime
///                                                bytecode (and its keccak256) so nodes can pin it.
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

    /// @dev Computes the canonical CREATE2 address for the given init code and salt.
    function _addr(bytes memory initCode, bytes32 salt) internal pure returns (address) {
        return address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), CREATE2_FACTORY, salt, keccak256(initCode)))))
        );
    }

    /// @dev Deploys initCode through the singleton CREATE2 factory.
    ///      Idempotent: if the contract is already deployed the call is skipped
    ///      and the pre-existing address is returned.
    function _create2(bytes memory initCode, bytes32 salt) internal returns (address addr) {
        addr = _addr(initCode, salt);
        if (addr.code.length > 0) return addr;
        (bool ok,) = CREATE2_FACTORY.call(abi.encodePacked(salt, initCode));
        require(ok && addr.code.length > 0, "create2 deployment failed");
    }

    /// @dev ERC-1167 minimal-proxy runtime bytecode for `implementation`.
    ///      Same encoding used by Keystore.createAccount callers and by nodes when admitting
    ///      high-rate payer accounts (exact 45-byte code match).
    function _erc1167Runtime(address implementation) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"363d3d373d3d3d363d73", implementation, hex"5af43d82803e903d91602b57fd5bf3");
    }

    /// @dev Init code for each contract, given the resolved Keystore address.
    function _accountConfigInit() internal pure returns (bytes memory) {
        return type(Keystore).creationCode;
    }

    function _defaultAccountInit(address accountConfig) internal pure returns (bytes memory) {
        return abi.encodePacked(type(DefaultAccount).creationCode, abi.encode(accountConfig));
    }

    function _canonicalHighRatePayerInit(address accountConfig) internal pure returns (bytes memory) {
        return abi.encodePacked(type(CanonicalHighRatePayerAccount).creationCode, abi.encode(accountConfig));
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
        console.log("=== CanonicalHighRatePayerAccount ERC-1167 match bytecode (node) ===");
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
    ///         bytecode nodes must match for CanonicalHighRatePayerAccount clones.
    ///         Addresses depend only on the compiler output and deployment salts — they are
    ///         the same on every chain and are known before deployment.
    function addresses() public pure {
        address accountConfig = _addr(_accountConfigInit(), KEYSTORE_SALT);
        address canonicalHighRatePayer = _addr(_canonicalHighRatePayerInit(accountConfig), HIGH_RATE_PAYER_SALT);
        address policyManager = _addr(_policyManagerInit(accountConfig), POLICY_MANAGER_SALT);

        console.log("Keystore:    ", accountConfig);
        console.log("");
        console.log("=== Account implementations ===");
        console.log("DefaultAccount:          ", _addr(_defaultAccountInit(accountConfig), DEFAULT_ACCOUNT_SALT));
        console.log("CanonicalHighRatePayerAccount:", canonicalHighRatePayer);
        console.log("");
        console.log("=== Authenticators ===");
        console.log("(secp256k1 is built in: Keystore.K1_AUTHENTICATOR() == address(1))");
        console.log("P256Authenticator:       ", _addr(type(P256Authenticator).creationCode, P256_SALT));
        console.log("WebAuthnAuthenticator:   ", _addr(type(WebAuthnAuthenticator).creationCode, WEBAUTHN_SALT));
        console.log("DelegateAuthenticator:   ", _addr(_delegateAuthInit(accountConfig), DELEGATE_SALT));
        console.log("");
        console.log("=== Example policies (unaudited) ===");
        console.log("PolicyManager:           ", policyManager);
        console.log("SessionPolicy:           ", _addr(_sessionPolicyInit(policyManager), SESSION_POLICY_SALT));

        _logHighRatePayerMatchBytecode(canonicalHighRatePayer);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Deployment
    // ─────────────────────────────────────────────────────────────────────────

    function run() public {
        vm.startBroadcast();

        // ── Core system contract ──

        address accountConfig = _create2(_accountConfigInit(), KEYSTORE_SALT);

        // ── Account implementations (singletons; every account proxy — and every 7702 EOA — delegates to one) ──
        //    DefaultAccount is deployed standalone as the direct EIP-7702 delegation target for EOAs.
        //    CanonicalHighRatePayerAccount is the ERC-1167 high-rate payer implementation singleton.

        address defaultAccount = _create2(_defaultAccountInit(accountConfig), DEFAULT_ACCOUNT_SALT);
        address canonicalHighRatePayer = _create2(_canonicalHighRatePayerInit(accountConfig), HIGH_RATE_PAYER_SALT);

        // ── Authenticators (secp256k1 is built into Keystore; no contract to deploy) ──

        address p256 = _create2(type(P256Authenticator).creationCode, P256_SALT);
        address webAuthn = _create2(type(WebAuthnAuthenticator).creationCode, WEBAUTHN_SALT);
        address delegate = _create2(_delegateAuthInit(accountConfig), DELEGATE_SALT);

        // ── Example policies (unaudited reference implementations) ──

        address policyManager = _create2(_policyManagerInit(accountConfig), POLICY_MANAGER_SALT);
        address sessionPolicy = _create2(_sessionPolicyInit(policyManager), SESSION_POLICY_SALT);

        vm.stopBroadcast();

        console.log("Keystore:    ", accountConfig);
        console.log("");
        console.log("=== Account implementations ===");
        console.log("DefaultAccount:          ", defaultAccount);
        console.log("CanonicalHighRatePayerAccount:", canonicalHighRatePayer);
        console.log("");
        console.log("=== Authenticators ===");
        console.log("(secp256k1 is built in: Keystore.K1_AUTHENTICATOR() == address(1))");
        console.log("P256Authenticator:       ", p256);
        console.log("WebAuthnAuthenticator:   ", webAuthn);
        console.log("DelegateAuthenticator:   ", delegate);
        console.log("");
        console.log("=== Example policies (unaudited) ===");
        console.log("PolicyManager:           ", policyManager);
        console.log("SessionPolicy:           ", sessionPolicy);

        // Emit the exact 45-byte ERC-1167 runtime bytecode (and hash) nodes must match for high-rate payers.
        _logHighRatePayerMatchBytecode(canonicalHighRatePayer);
    }
}
