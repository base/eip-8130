// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {DefaultAccount} from "../../../src/accounts/DefaultAccount.sol";
import {Keystore} from "../../../src/Keystore.sol";
import {KeystoreLayout} from "../../../src/libraries/KeystoreLayout.sol";
import {Scopes} from "../../../src/libraries/Scopes.sol";
import {KeystoreTest} from "../../lib/KeystoreTest.sol";

/// @dev Exposes {_reapRecord} so tests can drive the protocol reaper without adding it to the Keystore ABI.
contract KeystoreReapHarness is Keystore {
    function reapRecord(bytes32 base, uint256 nowTs) external returns (bool) {
        return _reapRecord(base, nowTs);
    }
}

/// @notice Layout and reaper tests for the co-located 3-word actor record.
contract CleanableLayoutTest is KeystoreTest {
    uint256 constant OWNER_PK = 0xA11CE;

    KeystoreReapHarness internal reapable;

    function setUp() public override {
        reapable = new KeystoreReapHarness();
        keystore = reapable;
        k1Authenticator = keystore.K1_AUTHENTICATOR();
        defaultAccountImplementation = address(new DefaultAccount(address(keystore)));
    }

    function test_recordBase_ceilingAlignedToFour(address account, bytes32 actorId) public pure {
        bytes32 h = keccak256(abi.encode(account, actorId, KeystoreLayout.ACTOR_RECORD_BASE));
        bytes32 base = KeystoreLayout.recordBase(account, actorId);
        uint256 delta = uint256(base) - uint256(h);
        assertEq(uint256(base) % 4, 0, "base must be 4-aligned");
        assertLe(delta, 3, "ceiling-align stays at keccak256(account||x)+n for n<4");
    }

    function test_authorize_writesColocatedCleanableRecord() public {
        (address account,) = _createK1Account(OWNER_PK);
        bytes32 actorId = bytes32(uint256(0xB0B));
        uint48 expiry = uint48(block.timestamp + 100);
        address manager = address(0xCAFE);
        bytes32 commitment = bytes32(uint256(0xC0FFEE));

        _applyLocal(
            OWNER_PK,
            account,
            _one(
                _authorizeChange(actorId, k1Authenticator, Scopes.POLICY, expiry, abi.encodePacked(manager, commitment))
            )
        );

        bytes32 base = KeystoreLayout.recordBase(account, actorId);
        uint256 w0 = uint256(vm.load(address(keystore), base));
        uint256 w1 = uint256(vm.load(address(keystore), bytes32(uint256(base) + 1)));
        uint256 w2 = uint256(vm.load(address(keystore), bytes32(uint256(base) + 2)));

        assertEq(w0 & KeystoreLayout.CLEANABLE, KeystoreLayout.CLEANABLE, "actor record is CLEANABLE");
        assertEq(address(uint160(w0)), k1Authenticator);
        assertEq(uint48(w0 >> 160), expiry);
        assertEq(uint16(w0 >> 208), Scopes.POLICY);
        assertEq(address(uint160(w1)), manager);
        assertEq(bytes32(w2), commitment);

        Keystore.ActorConfig memory cfg = keystore.getActorConfig(account, actorId);
        assertEq(cfg.authenticator, k1Authenticator);
        assertEq(cfg.expiry, expiry);
        assertEq(cfg.scope, Scopes.POLICY);
        assertEq(keystore.getPolicyManager(account, actorId), manager);
        assertEq(keystore.getPolicyCommitment(account, actorId), commitment);
    }

    function test_k1Self_word0NotCleanable() public {
        (address account,) = _createK1Account(OWNER_PK);
        bytes32 selfId = bytes32(uint256(uint160(account)));
        bytes32 base = KeystoreLayout.recordBase(account, selfId);
        uint256 w0 = uint256(vm.load(address(keystore), base));
        assertEq(w0, 0, "k1 self config is inline; actor-record word0 stays empty");
        assertEq(w0 & KeystoreLayout.CLEANABLE, 0);
    }

    function test_accountState_notCleanableAndReaperSkips() public {
        (address account,) = _createK1Account(OWNER_PK);
        bytes32 slot = _accountStateSlot(account);
        uint256 before = uint256(vm.load(address(keystore), slot));
        assertEq(before & KeystoreLayout.CLEANABLE, 0, "AccountState reserved byte stays zero");

        assertFalse(reapable.reapRecord(slot, type(uint256).max));
        assertEq(uint256(vm.load(address(keystore), slot)), before);
    }

    function test_revoke_clearsWholeRecord() public {
        (address account,) = _createK1Account(OWNER_PK);
        bytes32 actorId = bytes32(uint256(0xB0B));
        _applyLocal(OWNER_PK, account, _one(_authorizeChange(actorId, k1Authenticator, 0, UNBOUNDED, "")));
        _applyLocal(OWNER_PK, account, _one(_revokeChange(actorId)));

        bytes32 base = KeystoreLayout.recordBase(account, actorId);
        assertEq(uint256(vm.load(address(keystore), base)), 0);
        assertEq(uint256(vm.load(address(keystore), bytes32(uint256(base) + 1))), 0);
        assertEq(uint256(vm.load(address(keystore), bytes32(uint256(base) + 2))), 0);
    }

    function test_reapRecord_clearsExpiredAndSkipsLive() public {
        (address account,) = _createK1Account(OWNER_PK);
        bytes32 actorId = bytes32(uint256(0xB0B));
        uint48 expiry = uint48(block.timestamp + 50);
        address manager = address(0xCAFE);
        bytes32 commitment = bytes32(uint256(0xC0FFEE));
        _applyLocal(
            OWNER_PK,
            account,
            _one(
                _authorizeChange(actorId, k1Authenticator, Scopes.POLICY, expiry, abi.encodePacked(manager, commitment))
            )
        );

        bytes32 base = KeystoreLayout.recordBase(account, actorId);

        assertFalse(reapable.reapRecord(base, expiry), "still live at expiry");
        assertTrue(keystore.getActorConfig(account, actorId).authenticator != address(0));

        vm.warp(uint256(expiry) + 1);
        assertEq(keystore.getActorConfig(account, actorId).authenticator, address(0), "expired reads empty");
        assertTrue(reapable.reapRecord(base, block.timestamp), "expired CLEANABLE record is reaped");

        assertEq(uint256(vm.load(address(keystore), base)), 0);
        assertEq(uint256(vm.load(address(keystore), bytes32(uint256(base) + 1))), 0);
        assertEq(uint256(vm.load(address(keystore), bytes32(uint256(base) + 2))), 0);
        assertFalse(reapable.reapRecord(base, block.timestamp), "already empty");
    }

    function test_reapRecord_skipsNoExpiry() public {
        (address account,) = _createK1Account(OWNER_PK);
        bytes32 actorId = bytes32(uint256(0xB0B));
        _applyLocal(OWNER_PK, account, _one(_authorizeChange(actorId, k1Authenticator, 0, 0, "")));

        bytes32 base = KeystoreLayout.recordBase(account, actorId);
        assertTrue(uint256(vm.load(address(keystore), base)) & KeystoreLayout.CLEANABLE != 0);
        assertFalse(reapable.reapRecord(base, type(uint256).max));
        assertEq(keystore.getActorConfig(account, actorId).authenticator, k1Authenticator);
    }
}
