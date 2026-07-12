// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test, console} from "forge-std/Test.sol";

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {DefaultAccount} from "../../../src/accounts/DefaultAccount.sol";
import {IAuthenticator} from "../../../src/interfaces/IAuthenticator.sol";
import {P256Authenticator} from "../../../src/authenticators/P256Authenticator.sol";
import {WebAuthnAuthenticator} from "../../../src/authenticators/WebAuthnAuthenticator.sol";
import {DelegateAuthenticator} from "../../../src/authenticators/DelegateAuthenticator.sol";

/// @dev Measures authenticator gas under two conditions:
///      - Cold: first call (includes 2600 cold account access)
///      - Warm: second call (100 warm access)
///
///      Run:  forge test --match-contract GasBenchmarkTest -vv
///      Trace: forge test --match-contract GasBenchmarkTest -vvvv
contract GasBenchmarkTest is Test {
    P256Authenticator p256;
    WebAuthnAuthenticator webAuthn;
    DelegateAuthenticator delegate;
    AccountConfiguration config;
    address defaultImpl;

    bytes32 testHash;
    bytes p256Data;
    bytes32 expectedP256ActorId;
    bytes delegateData;

    function setUp() public {
        p256 = new P256Authenticator();
        webAuthn = new WebAuthnAuthenticator();
        config = new AccountConfiguration();
        delegate = new DelegateAuthenticator(address(config));
        defaultImpl = address(new DefaultAccount(address(config)));

        testHash = keccak256("benchmark");

        // P256 data
        {
            uint256 pk = 0xBEEF;
            (uint256 pubXu, uint256 pubYu) = vm.publicKeyP256(pk);
            (bytes32 r, bytes32 s) = vm.signP256(pk, testHash);
            p256Data = abi.encodePacked(r, s, bytes32(pubXu), bytes32(pubYu), uint8(0));
            expectedP256ActorId = keccak256(abi.encodePacked(bytes32(pubXu), bytes32(pubYu)));
        }

        // Delegate data
        {
            uint256 pkA = 0xA001;
            address signerA = vm.addr(pkA);
            bytes32 actorIdA = bytes32(bytes20(signerA));
            AccountConfiguration.InitialActor[] memory actorsA = new AccountConfiguration.InitialActor[](1);
            actorsA[0] = AccountConfiguration.InitialActor({
                actorId: actorIdA, authenticator: config.K1_AUTHENTICATOR(), scope: 0, policyData: ""
            });
            bytes memory bytecode =
                abi.encodePacked(hex"363d3d373d3d3d363d73", defaultImpl, hex"5af43d82803e903d91602b57fd5bf3");
            config.createAccount(bytes32("benchA"), bytecode, actorsA);
            address accountA = config.computeAddress(bytes32("benchA"), bytecode, actorsA);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pkA, testHash);
            // Nested auth: K1_AUTHENTICATOR(20) || sig
            bytes memory nestedAuth = abi.encodePacked(config.K1_AUTHENTICATOR(), r, s, v);
            delegateData = abi.encodePacked(accountA, nestedAuth);
        }
    }

    // ─── Individual tests (for -vvvv traces) ────────────────────────────────

    function test_gasP256Authenticator() public {
        p256.authenticate(testHash, p256Data);
        uint256 gas0 = gasleft();
        p256.authenticate(testHash, p256Data);
        uint256 gasUsed = gas0 - gasleft();
        emit log_named_uint("P256Authenticator.authenticate (warm)", gasUsed);
    }

    function test_gasDelegateAuthenticator() public {
        delegate.authenticate(testHash, delegateData);
        uint256 gas0 = gasleft();
        delegate.authenticate(testHash, delegateData);
        uint256 gasUsed = gas0 - gasleft();
        emit log_named_uint("DelegateAuthenticator.authenticate (warm)", gasUsed);
    }

    // ─── Summary ─────────────────────────────────────────────────────────────

    function test_gasSummary() public {
        console.log("");
        console.log("=== EIP-8130 Authenticator Gas Benchmark ===");
        console.log("");
        console.log("  Authenticator                Cold      Warm     Precompile");
        console.log("  ---------------------------------------------------------");

        // P256 Authenticator
        {
            uint256 g0 = gasleft();
            p256.authenticate(testHash, p256Data);
            uint256 cold = g0 - gasleft();
            g0 = gasleft();
            p256.authenticate(testHash, p256Data);
            uint256 warm = g0 - gasleft();
            console.log("  P256Authenticator            %s     %s    P256VERIFY (6900)", _pad(cold), _pad(warm));
        }

        // Delegate Authenticator
        {
            uint256 g0 = gasleft();
            delegate.authenticate(testHash, delegateData);
            uint256 cold = g0 - gasleft();
            g0 = gasleft();
            delegate.authenticate(testHash, delegateData);
            uint256 warm = g0 - gasleft();
            console.log("  DelegateAuthenticator        %s     %s    ecrecover (3000)", _pad(cold), _pad(warm));
        }

        console.log("  ---------------------------------------------------------");
        console.log("");
        console.log("  Cold = first call (includes 2600 cold account access)");
        console.log("  Warm = second call (100 warm access)");
        console.log("");
    }

    function _pad(uint256 n) internal pure returns (string memory) {
        return _leftPad(vm.toString(n), 6);
    }

    function _leftPad(string memory s, uint256 width) internal pure returns (string memory) {
        bytes memory b = bytes(s);
        if (b.length >= width) return s;
        bytes memory padded = new bytes(width);
        uint256 offset = width - b.length;
        for (uint256 i; i < width; i++) {
            padded[i] = i < offset ? bytes1(" ") : b[i - offset];
        }
        return string(padded);
    }
}
