// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ConfigOperation} from "../../../src/AccountConfigDigest.sol";
import {AccountConfigurationTest} from "../../lib/AccountConfigurationTest.sol";

contract VerifyTest is AccountConfigurationTest {
    uint256 constant OWNER_PK = 400;

    function test_verifySignature_validK1() public {
        (address account, bytes32 ownerId) = _createK1Account(OWNER_PK);

        bytes32 hash = keccak256("verify me");
        bytes memory sig = _signDigest(OWNER_PK, hash);
        bytes memory auth = abi.encodePacked(uint8(0x01), sig);

        (bool valid, bytes32 returnedOwnerId, address verifier) =
            accountConfiguration.verifySignature(account, hash, auth);
        assertTrue(valid);
        assertEq(returnedOwnerId, ownerId);
        assertEq(verifier, address(k1Verifier));
    }

    function test_verifySignature_wrongSignature() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 hash = keccak256("verify me");
        bytes memory wrongSig = _signDigest(999, hash);
        bytes memory auth = abi.encodePacked(uint8(0x01), wrongSig);

        (bool valid,,) = accountConfiguration.verifySignature(account, hash, auth);
        assertFalse(valid);
    }

    function test_verifySignature_unregisteredOwner() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 hash = keccak256("verify me");
        bytes memory sig = _signDigest(999, hash);
        bytes memory auth = abi.encodePacked(uint8(0x01), sig);

        (bool valid,,) = accountConfiguration.verifySignature(account, hash, auth);
        assertFalse(valid);
    }

    function test_verifySignature_revokedOwner() public {
        (address account, bytes32 ownerOwnerId) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(401);
        bytes32 newOwnerId = bytes32(bytes20(newSigner));
        _authorizeOwner(account, OWNER_PK, newOwnerId, address(k1Verifier));

        _revokeOwner(account, OWNER_PK, newOwnerId);

        bytes32 hash = keccak256("after revoke");
        bytes memory sig = _signDigest(401, hash);
        bytes memory auth = abi.encodePacked(uint8(0x01), sig);

        (bool valid,,) = accountConfiguration.verifySignature(account, hash, auth);
        assertFalse(valid);

        // Owner should still work
        bytes memory ownerSig = _signDigest(OWNER_PK, hash);
        bytes memory ownerAuth = abi.encodePacked(uint8(0x01), ownerSig);

        (valid,,) = accountConfiguration.verifySignature(account, hash, ownerAuth);
        assertTrue(valid);
    }

    function test_verifySignature_differentAccounts() public {
        (address account1, bytes32 ownerId1) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(1)));
        (address account2,) = _createK1AccountWithSalt(OWNER_PK, bytes32(uint256(2)));

        bytes32 hash = keccak256("cross-account test");
        bytes memory sig = _signDigest(OWNER_PK, hash);
        bytes memory auth = abi.encodePacked(uint8(0x01), sig);

        (bool valid1,,) = accountConfiguration.verifySignature(account1, hash, auth);
        (bool valid2,,) = accountConfiguration.verifySignature(account2, hash, auth);

        assertTrue(valid1);
        assertTrue(valid2);
    }

    function test_getOwner_returnsVerifierAndScope() public {
        (address account, bytes32 ownerId) = _createK1Account(OWNER_PK);

        (address verifier, uint8 scope) = accountConfiguration.getOwner(account, ownerId);
        assertEq(verifier, address(k1Verifier));
        assertEq(scope, 0x00);
    }

    function test_getOwner_returnsZeroForUnknownOwner() public {
        (address account,) = _createK1Account(OWNER_PK);

        bytes32 unknownOwnerId = bytes32(bytes20(vm.addr(999)));
        (address verifier, uint8 scope) = accountConfiguration.getOwner(account, unknownOwnerId);
        assertEq(verifier, address(0));
        assertEq(scope, 0);
    }

    function test_computeERC1167Bytecode() public view {
        bytes memory bytecode = accountConfiguration.computeERC1167Bytecode(defaultAccountImplementation);
        assertEq(bytecode.length, 45);

        bytes memory expected = _computeERC1167Bytecode(defaultAccountImplementation);
        assertEq(keccak256(bytecode), keccak256(expected));
    }

    function test_verifySignature_scopedOwner_signatureScope() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(401);
        bytes32 newOwnerId = bytes32(bytes20(newSigner));
        _authorizeOwnerWithScope(account, OWNER_PK, newOwnerId, address(k1Verifier), 0x01);

        bytes32 hash = keccak256("scoped verify");
        bytes memory sig = _signDigest(401, hash);
        bytes memory auth = abi.encodePacked(uint8(0x01), sig);

        (bool valid,,) = accountConfiguration.verifySignature(account, hash, auth);
        assertTrue(valid);
    }

    function test_verifySignature_scopedOwner_wrongScope() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(401);
        bytes32 newOwnerId = bytes32(bytes20(newSigner));
        // Authorize with SENDER scope only (0x02) — should fail SIGNATURE (0x01) check
        _authorizeOwnerWithScope(account, OWNER_PK, newOwnerId, address(k1Verifier), 0x02);

        bytes32 hash = keccak256("scoped verify");
        bytes memory sig = _signDigest(401, hash);
        bytes memory auth = abi.encodePacked(uint8(0x01), sig);

        (bool valid,,) = accountConfiguration.verifySignature(account, hash, auth);
        assertFalse(valid);
    }

    function test_verifySignature_unrestrictedScope() public {
        (address account,) = _createK1Account(OWNER_PK);

        address newSigner = vm.addr(401);
        bytes32 newOwnerId = bytes32(bytes20(newSigner));
        _authorizeOwnerWithScope(account, OWNER_PK, newOwnerId, address(k1Verifier), 0x00);

        bytes32 hash = keccak256("unrestricted");
        bytes memory sig = _signDigest(401, hash);
        bytes memory auth = abi.encodePacked(uint8(0x01), sig);

        (bool valid,,) = accountConfiguration.verifySignature(account, hash, auth);
        assertTrue(valid);
    }

    // ── Helpers ──

    function _authorizeOwner(address account, uint256 pk, bytes32 newOwnerId, address verifier) internal {
        _authorizeOwnerWithScope(account, pk, newOwnerId, verifier, 0x00);
    }

    function _authorizeOwnerWithScope(address account, uint256 pk, bytes32 newOwnerId, address verifier, uint8 scope)
        internal
    {
        ConfigOperation[] memory ops = new ConfigOperation[](1);
        ops[0] = ConfigOperation({opType: 0x01, verifier: verifier, ownerId: newOwnerId, scope: scope});

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeConfigChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(pk, digest);

        accountConfiguration.applyConfigChange(account, chainId, seq, ops, auth);
    }

    function _revokeOwner(address account, uint256 pk, bytes32 ownerId) internal {
        ConfigOperation[] memory ops = new ConfigOperation[](1);
        ops[0] = ConfigOperation({opType: 0x02, verifier: address(0), ownerId: ownerId, scope: 0});

        uint64 chainId = uint64(block.chainid);
        uint64 seq = accountConfiguration.getChangeSequence(account, chainId);
        bytes32 digest = _computeConfigChangeDigest(account, chainId, seq, ops);
        bytes memory auth = _buildK1Auth(pk, digest);

        accountConfiguration.applyConfigChange(account, chainId, seq, ops, auth);
    }
}
