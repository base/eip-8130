// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test, console} from "forge-std/Test.sol";

import {AccountConfiguration} from "../../../src/AccountConfiguration.sol";
import {InitialOwner} from "../../../src/AccountDeployer.sol";
import {DefaultAccount} from "../../../src/accounts/DefaultAccount.sol";
import {IAuthVerifier} from "../../../src/verifiers/IAuthVerifier.sol";
import {K1Verifier} from "../../../src/verifiers/K1Verifier.sol";
import {K1Sandbox} from "../../../src/verifiers/sandbox/K1Verifier.sol";
import {P256Verifier} from "../../../src/verifiers/P256Verifier.sol";
import {P256Sandbox} from "../../../src/verifiers/sandbox/P256Verifier.sol";
import {WebAuthnVerifier} from "../../../src/verifiers/WebAuthnVerifier.sol";
import {DelegateVerifier} from "../../../src/verifiers/DelegateVerifier.sol";

/// @dev Measures verifier gas under two conditions:
///      - Cold: first call (includes 2600 cold account access)
///      - Warm: second call (100 warm access — closer to sandbox execution)
///
///      Run:  forge test --match-contract GasBenchmarkTest -vv
///      Trace: forge test --match-contract GasBenchmarkTest -vvvv
contract GasBenchmarkTest is Test {
    K1Verifier k1;
    P256Verifier p256;
    WebAuthnVerifier webAuthn;
    DelegateVerifier delegate;
    AccountConfiguration config;
    address defaultImpl;
    address k1Sandbox;
    address p256Sandbox;

    // Pre-built test data
    bytes k1Sig;
    bytes32 testHash;
    bytes32 expectedK1OwnerId;
    bytes p256Data;
    bytes32 expectedP256OwnerId;
    bytes delegateData;

    function setUp() public {
        k1 = new K1Verifier();
        p256 = new P256Verifier();
        webAuthn = new WebAuthnVerifier();
        config = new AccountConfiguration(address(k1), address(p256), address(webAuthn), address(0));
        delegate = new DelegateVerifier(address(config));
        defaultImpl = address(new DefaultAccount(address(config)));
        k1Sandbox = K1Sandbox.deploy(bytes32(0));
        p256Sandbox = P256Sandbox.deploy(bytes32(uint256(1)));

        testHash = keccak256("benchmark");

        // K1 sig
        {
            uint256 pk = 0xBEEF;
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, testHash);
            k1Sig = abi.encodePacked(r, s, v);
            expectedK1OwnerId = bytes32(bytes20(vm.addr(pk)));
        }

        // P256 data
        {
            uint256 pk = 0xBEEF;
            (uint256 pubXu, uint256 pubYu) = vm.publicKeyP256(pk);
            (bytes32 r, bytes32 s) = vm.signP256(pk, testHash);
            p256Data = abi.encodePacked(r, s, bytes32(pubXu), bytes32(pubYu), uint8(0));
            expectedP256OwnerId = keccak256(abi.encodePacked(bytes32(pubXu), bytes32(pubYu)));
        }

        // Delegate data
        {
            uint256 pkA = 0xA001;
            address signerA = vm.addr(pkA);
            bytes32 ownerIdA = bytes32(bytes20(signerA));
            InitialOwner[] memory ownersA = new InitialOwner[](1);
            ownersA[0] = InitialOwner({verifier: address(k1), ownerId: ownerIdA});
            bytes memory bytecode =
                abi.encodePacked(hex"363d3d373d3d3d363d73", defaultImpl, hex"5af43d82803e903d91602b57fd5bf3");
            config.createAccount(bytes32("benchA"), bytecode, ownersA);
            address accountA = config.getAddress(bytes32("benchA"), bytecode, ownersA);
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(pkA, testHash);
            delegateData = abi.encodePacked(accountA, uint8(0x01), abi.encodePacked(r, s, v));
        }
    }

    // ─── Individual tests (for -vvvv traces) ────────────────────────────────

    function test_gasK1Verifier() public {
        k1.verify(testHash, k1Sig); // warm up
        uint256 gas0 = gasleft();
        k1.verify(testHash, k1Sig);
        uint256 gasUsed = gas0 - gasleft();
        emit log_named_uint("K1Verifier.verify (warm)", gasUsed);
    }

    function test_gasK1Sandbox() public {
        bytes memory cd = abi.encodeWithSelector(IAuthVerifier.verify.selector, testHash, k1Sig);
        k1Sandbox.staticcall(cd); // warm up
        uint256 gas0 = gasleft();
        (bool ok, bytes memory ret) = k1Sandbox.staticcall(cd);
        uint256 gasUsed = gas0 - gasleft();
        require(ok, "K1Sandbox call failed");
        bytes32 ownerId = abi.decode(ret, (bytes32));
        assertEq(ownerId, expectedK1OwnerId, "K1Sandbox ownerId mismatch");
        emit log_named_uint("K1Sandbox.verify (warm)", gasUsed);
    }

    function test_gasP256Verifier() public {
        p256.verify(testHash, p256Data); // warm up
        uint256 gas0 = gasleft();
        p256.verify(testHash, p256Data);
        uint256 gasUsed = gas0 - gasleft();
        emit log_named_uint("P256Verifier.verify (warm)", gasUsed);
    }

    function test_gasP256Sandbox() public {
        bytes memory cd = abi.encodeWithSelector(IAuthVerifier.verify.selector, testHash, p256Data);
        p256Sandbox.staticcall(cd); // warm up
        uint256 gas0 = gasleft();
        (bool ok, bytes memory ret) = p256Sandbox.staticcall(cd);
        uint256 gasUsed = gas0 - gasleft();
        require(ok, "P256Sandbox call failed");
        bytes32 ownerId = abi.decode(ret, (bytes32));
        assertEq(ownerId, expectedP256OwnerId, "P256Sandbox ownerId mismatch");
        emit log_named_uint("P256Sandbox.verify (warm)", gasUsed);
    }

    function test_gasDelegateVerifier() public {
        delegate.verify(testHash, delegateData); // warm up
        uint256 gas0 = gasleft();
        delegate.verify(testHash, delegateData);
        uint256 gasUsed = gas0 - gasleft();
        emit log_named_uint("DelegateVerifier.verify (warm)", gasUsed);
    }

    // ─── Summary ─────────────────────────────────────────────────────────────

    function test_gasSummary() public {
        console.log("");
        console.log("=== EIP-8130 Verifier Gas Benchmark ===");
        console.log("");
        console.log("  Verifier                Cold      Warm     Precompile");
        console.log("  ---------------------------------------------------------");

        // K1 Verifier (Solidity)
        {
            uint256 g0 = gasleft();
            k1.verify(testHash, k1Sig);
            uint256 cold = g0 - gasleft();
            g0 = gasleft();
            k1.verify(testHash, k1Sig);
            uint256 warm = g0 - gasleft();
            console.log("  K1Verifier              %s     %s    ecrecover (3000)", _pad(cold), _pad(warm));
        }

        // K1 Sandbox (hand-written)
        {
            bytes memory cd = abi.encodeWithSelector(IAuthVerifier.verify.selector, testHash, k1Sig);
            uint256 g0 = gasleft();
            k1Sandbox.staticcall(cd);
            uint256 cold = g0 - gasleft();
            g0 = gasleft();
            k1Sandbox.staticcall(cd);
            uint256 warm = g0 - gasleft();
            console.log("  K1Sandbox               %s     %s    ecrecover (3000)", _pad(cold), _pad(warm));
        }

        // P256 Verifier (Solidity)
        {
            uint256 g0 = gasleft();
            p256.verify(testHash, p256Data);
            uint256 cold = g0 - gasleft();
            g0 = gasleft();
            p256.verify(testHash, p256Data);
            uint256 warm = g0 - gasleft();
            console.log("  P256Verifier            %s     %s    P256VERIFY (6900)", _pad(cold), _pad(warm));
        }

        // P256 Sandbox (hand-written)
        {
            bytes memory cd = abi.encodeWithSelector(IAuthVerifier.verify.selector, testHash, p256Data);
            uint256 g0 = gasleft();
            p256Sandbox.staticcall(cd);
            uint256 cold = g0 - gasleft();
            g0 = gasleft();
            p256Sandbox.staticcall(cd);
            uint256 warm = g0 - gasleft();
            console.log("  P256Sandbox             %s     %s    P256VERIFY (6900)", _pad(cold), _pad(warm));
        }

        // Delegate Verifier
        {
            uint256 g0 = gasleft();
            delegate.verify(testHash, delegateData);
            uint256 cold = g0 - gasleft();
            g0 = gasleft();
            delegate.verify(testHash, delegateData);
            uint256 warm = g0 - gasleft();
            console.log("  DelegateVerifier        %s     %s    ecrecover (3000)", _pad(cold), _pad(warm));
        }

        console.log("  ---------------------------------------------------------");
        console.log("");
        console.log("  Cold = first call (includes 2600 cold account access)");
        console.log("  Warm = second call (100 warm access, closer to sandbox)");
        console.log("  Sandbox overhead = Warm - STATICCALL base (100) - precompile");
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
