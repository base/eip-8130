// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Script, console} from "forge-std/Script.sol";

import {AccountConfiguration} from "../src/AccountConfiguration.sol";
import {PolicyManager} from "../src/policies/PolicyManager.sol";
import {SessionPolicy} from "../src/policies/SessionPolicy.sol";

/// @dev Nick's deterministic deployment proxy — same address on every EVM chain.
address constant CREATE2_FACTORY = 0x4e59b44847b379578588920cA78FbF26c0B4956C;

bytes32 constant SALT = bytes32(0);

/// @notice Deploys the EIP-8130 example policy contracts: the reference {PolicyManager} and the {SessionPolicy}.
///
///         These are UNAUDITED reference implementations and are deployed separately from the canonical system
///         contracts (see Deploy.s.sol) so the two concerns stay independent — integrators should not assume these
///         example addresses are blessed infrastructure.
///
///         All addresses are canonical: determined solely by salt + bytecode, identical on every chain. The
///         policies are constructor-bound to the PolicyManager address; the manager is bound to the canonical
///         AccountConfiguration address (computed identically to Deploy.s.sol).
///
/// @dev Preview all addresses without deploying:
///      forge script script/DeployExamples.s.sol --sig "addresses()"
///
///      Deploy + verify (Blockscout, no API key needed):
///      forge script script/DeployExamples.s.sol --rpc-url $RPC_URL --broadcast \
///        --private-key $PRIVATE_KEY --verify \
///        --verifier blockscout --verifier-url https://base-sepolia.blockscout.com/api/
contract DeployExamplePolicies is Script {
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
    ///      Idempotent: if the contract is already deployed the call is skipped and the address is returned.
    function _create2(bytes memory initCode) internal returns (address addr) {
        addr = _addr(initCode);
        if (addr.code.length > 0) return addr;
        (bool ok,) = CREATE2_FACTORY.call(abi.encodePacked(SALT, initCode));
        require(ok && addr.code.length > 0, "create2 deployment failed");
    }

    /// @dev Canonical AccountConfiguration address, computed the same way as Deploy.s.sol (no constructor args).
    function _accountConfigInit() internal pure returns (bytes memory) {
        return type(AccountConfiguration).creationCode;
    }

    function _policyManagerInit(address accountConfig) internal pure returns (bytes memory) {
        return abi.encodePacked(type(PolicyManager).creationCode, abi.encode(accountConfig));
    }

    function _sessionPolicyInit(address policyManager) internal pure returns (bytes memory) {
        return abi.encodePacked(type(SessionPolicy).creationCode, abi.encode(policyManager));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Address preview  (no deployment)
    // ─────────────────────────────────────────────────────────────────────────

    /// @notice Logs the canonical address of every example contract. Same on every chain, known before deploy.
    function addresses() public pure {
        address accountConfig = _addr(_accountConfigInit());
        address policyManager = _addr(_policyManagerInit(accountConfig));

        console.log("AccountConfiguration:    ", accountConfig);
        console.log("");
        console.log("=== Example policies ===");
        console.log("PolicyManager:           ", policyManager);
        console.log("SessionPolicy:           ", _addr(_sessionPolicyInit(policyManager)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Deployment
    // ─────────────────────────────────────────────────────────────────────────

    function run() public {
        // The manager is bound to the canonical AccountConfiguration. Require it to be live so we never deploy a
        // manager pointing at an empty address (Deploy.s.sol must run first on a fresh chain).
        address accountConfig = _addr(_accountConfigInit());
        require(accountConfig.code.length > 0, "AccountConfiguration not deployed; run Deploy.s.sol first");

        vm.startBroadcast();

        address policyManager = _create2(_policyManagerInit(accountConfig));
        address sessionPolicy = _create2(_sessionPolicyInit(policyManager));

        vm.stopBroadcast();

        console.log("AccountConfiguration:    ", accountConfig);
        console.log("");
        console.log("=== Example policies ===");
        console.log("PolicyManager:           ", policyManager);
        console.log("SessionPolicy:           ", sessionPolicy);
    }
}
