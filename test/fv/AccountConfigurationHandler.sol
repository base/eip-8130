// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";

import {AccountConfiguration} from "../../src/AccountConfiguration.sol";
import {AccountConfigurationHarness} from "./AccountConfigurationHarness.sol";
import {DefaultAccount} from "../../src/accounts/DefaultAccount.sol";

/// @notice Stateful-fuzzing handler for the {AccountConfiguration} invariant suite. It drives the contract through
///         validly-signed, in-distribution operations (create, authorize/revoke actors across both self homes, lock,
///         unlock, and time travel) so the fuzzer explores *reachable* states. Every state-mutating call is wrapped in
///         try/catch: invalid fuzzed combinations are expected to revert and are simply skipped, while the successful
///         ones evolve the system. The handler also tracks the (account, actorId) pairs it has touched and the last
///         observed sequence numbers, which the invariant contract reads to phrase its assertions.
contract AccountConfigurationHandler is Test {
    AccountConfigurationHarness public immutable cfg;
    address public immutable accountImpl;
    address public immutable K1;

    bytes32 constant SIGNED_ACTOR_CHANGES_TYPEHASH = keccak256(
        "SignedActorChanges(address account,uint256 chainId,uint64 sequence,ActorChange[] actorChanges)"
        "ActorChange(uint8 changeType,bytes32 actorId,bytes data)"
    );
    bytes32 constant ACTORCHANGE_TYPEHASH = keccak256("ActorChange(uint8 changeType,bytes32 actorId,bytes data)");

    uint8 constant AUTHORIZE_ACTOR = 0x01;
    uint8 constant REVOKE_ACTOR = 0x02;
    uint8 constant SCOPE_CONFIG = 0x08;

    /// @dev A non-k1 authenticator selector. `_authorizeActor` only requires `authenticator >= K1_AUTHENTICATOR` and
    ///      does not call it, so any address > K1 exercises the non-k1 self / non-k1 actor storage home.
    address constant NON_K1_AUTHENTICATOR = address(0xA11CE);

    // Owner private keys. Each created account is bootstrapped with exactly one of these as its unrestricted owner
    // (a non-self k1 actor), and that owner signs every subsequent change for the account.
    uint256[3] internal OWNER_PKS = [uint256(0xA1), uint256(0xB2), uint256(0xC3)];
    // Target keys used as the actorIds we authorize/revoke.
    uint256[3] internal TARGET_PKS = [uint256(0xD4), uint256(0xE5), uint256(0xF6)];

    address[] public accounts;
    mapping(address => uint256) public ownerPkOf;
    mapping(address => bool) public isCreated;

    // Addresses whose createAccount was expected to fail at the CREATE2 step; they must never carry state or code.
    address[] public failedCreations;

    // Touched (account, actorId) pairs, for invariant enumeration.
    struct Pair {
        address account;
        bytes32 actorId;
    }

    Pair[] internal _pairs;
    mapping(bytes32 => bool) internal _pairSeen;

    // Monotonicity tracking.
    mapping(address => uint64) public lastLocalSeq;
    mapping(address => uint64) public lastMultiSeq;
    bool public sequenceMonotonicityHeld = true;

    uint256 internal _saltNonce;

    constructor(AccountConfigurationHarness _cfg, address _accountImpl) {
        cfg = _cfg;
        accountImpl = _accountImpl;
        K1 = _cfg.K1_AUTHENTICATOR();
    }

    // ── Views for the invariant contract ──

    function accountsLength() external view returns (uint256) {
        return accounts.length;
    }

    function pairsLength() external view returns (uint256) {
        return _pairs.length;
    }

    function pairAt(uint256 i) external view returns (address account, bytes32 actorId) {
        Pair storage p = _pairs[i];
        return (p.account, p.actorId);
    }

    function failedCreationsLength() external view returns (uint256) {
        return failedCreations.length;
    }

    // ── Handler actions ──

    function handler_createAccount(uint256 ownerSeed) external {
        uint256 pk = OWNER_PKS[ownerSeed % OWNER_PKS.length];
        if (accounts.length >= 4) return; // bound state size

        address owner = vm.addr(pk);
        bytes32 ownerActorId = bytes32(bytes20(owner));

        AccountConfiguration.InitialActor[] memory actors = new AccountConfiguration.InitialActor[](1);
        actors[0] = AccountConfiguration.InitialActor({actorId: ownerActorId, authenticator: K1});

        bytes memory bytecode = _erc1167(accountImpl);
        bytes32 salt = bytes32(++_saltNonce);

        try cfg.createAccount(salt, bytecode, actors) returns (address account) {
            if (!isCreated[account]) {
                isCreated[account] = true;
                accounts.push(account);
                ownerPkOf[account] = pk;
                _registerPair(account, ownerActorId);
                _registerPair(account, bytes32(bytes20(account))); // self-actorId
                _syncSeq(account);
            }
        } catch {}
    }

    /// @dev Attempts a createAccount whose runtime code begins with 0xEF, which EIP-3541 rejects, so the underlying
    ///      CREATE2 returns address(0). The contract must revert (unwinding state) rather than leave an
    ///      initialized-but-codeless account. The predicted address is recorded for the orphaned-state invariant.
    function handler_createAccountBadCode(uint256 ownerSeed) external {
        if (failedCreations.length >= 8) return; // bound state size
        uint256 pk = OWNER_PKS[ownerSeed % OWNER_PKS.length];
        address owner = vm.addr(pk);

        AccountConfiguration.InitialActor[] memory actors = new AccountConfiguration.InitialActor[](1);
        actors[0] = AccountConfiguration.InitialActor({actorId: bytes32(bytes20(owner)), authenticator: K1});

        bytes memory bytecode = hex"EF"; // EIP-3541: a leading 0xEF byte makes deployment fail.
        bytes32 salt = bytes32(++_saltNonce);
        address predicted = cfg.computeAddress(salt, bytecode, actors);

        try cfg.createAccount(salt, bytecode, actors) returns (address created) {
            // Not expected to succeed; if a future EVM ever allowed it, treat it like a normal creation.
            if (!isCreated[created]) {
                isCreated[created] = true;
                accounts.push(created);
                ownerPkOf[created] = pk;
                _syncSeq(created);
            }
        } catch {
            failedCreations.push(predicted);
        }
    }

    function handler_authorize(
        uint256 acctSeed,
        uint256 targetSeed,
        bool selfTarget,
        bool nonK1,
        uint8 scope,
        uint48 expiry,
        uint8 policyType
    ) external {
        if (accounts.length == 0) return;
        address account = accounts[acctSeed % accounts.length];

        bytes32 actorId = selfTarget
            ? bytes32(bytes20(account))
            : bytes32(bytes20(vm.addr(TARGET_PKS[targetSeed % TARGET_PKS.length])));
        address authenticator = nonK1 ? NON_K1_AUTHENTICATOR : K1;

        AccountConfiguration.ActorConfig memory config = AccountConfiguration.ActorConfig({
            authenticator: authenticator, scope: scope, expiry: expiry, policyType: policyType
        });

        bytes memory policyData;
        if (policyType != 0) {
            // Provide a well-formed policy blob; whether the (scope, policyType) combo is legal is enforced by the
            // contract (and rejected combos simply revert into the catch below).
            policyData = abi.encodePacked(address(0xBEEF), keccak256(abi.encode("commit", acctSeed, targetSeed)));
        }

        _apply(account, actorId, AUTHORIZE_ACTOR, abi.encode(config, policyData));
        _registerPair(account, actorId);
    }

    function handler_revoke(uint256 acctSeed, uint256 targetSeed, bool selfTarget) external {
        if (accounts.length == 0) return;
        address account = accounts[acctSeed % accounts.length];
        bytes32 actorId = selfTarget
            ? bytes32(bytes20(account))
            : bytes32(bytes20(vm.addr(TARGET_PKS[targetSeed % TARGET_PKS.length])));

        _apply(account, actorId, REVOKE_ACTOR, "");
    }

    function handler_lock(uint256 acctSeed, uint16 delay) external {
        if (accounts.length == 0) return;
        address account = accounts[acctSeed % accounts.length];
        vm.prank(account);
        try cfg.lock(delay) {} catch {}
    }

    function handler_initiateUnlock(uint256 acctSeed) external {
        if (accounts.length == 0) return;
        address account = accounts[acctSeed % accounts.length];
        vm.prank(account);
        try cfg.initiateUnlock() {} catch {}
    }

    function handler_warp(uint32 dt) external {
        vm.warp(block.timestamp + (uint256(dt) % 40 days) + 1);
    }

    // ── Internal ──

    function _apply(address account, bytes32 actorId, uint8 changeType, bytes memory data) internal {
        AccountConfiguration.ActorChange[] memory changes = new AccountConfiguration.ActorChange[](1);
        changes[0] = AccountConfiguration.ActorChange({changeType: changeType, actorId: actorId, data: data});

        uint256 chainId = block.chainid;
        uint64 seq = cfg.getChangeSequences(account).local;
        bytes32 digest = _digest(account, chainId, seq, changes);

        uint256 ownerPk = ownerPkOf[account];
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(ownerPk, digest);
        bytes memory auth = abi.encodePacked(K1, r, s, v);

        try cfg.applySignedActorChanges(account, chainId, changes, auth) {
            _syncSeq(account);
        } catch {}
    }

    function _syncSeq(address account) internal {
        AccountConfiguration.ChangeSequences memory s = cfg.getChangeSequences(account);
        if (s.local < lastLocalSeq[account] || s.multichain < lastMultiSeq[account]) {
            sequenceMonotonicityHeld = false;
        }
        lastLocalSeq[account] = s.local;
        lastMultiSeq[account] = s.multichain;
    }

    function _registerPair(address account, bytes32 actorId) internal {
        bytes32 key = keccak256(abi.encodePacked(account, actorId));
        if (!_pairSeen[key]) {
            _pairSeen[key] = true;
            _pairs.push(Pair({account: account, actorId: actorId}));
        }
    }

    function _digest(
        address account,
        uint256 chainId,
        uint64 sequence,
        AccountConfiguration.ActorChange[] memory changes
    ) internal pure returns (bytes32) {
        bytes32[] memory h = new bytes32[](changes.length);
        for (uint256 i; i < changes.length; i++) {
            h[i] = keccak256(
                abi.encode(ACTORCHANGE_TYPEHASH, changes[i].changeType, changes[i].actorId, keccak256(changes[i].data))
            );
        }
        return keccak256(
            abi.encode(SIGNED_ACTOR_CHANGES_TYPEHASH, account, chainId, sequence, keccak256(abi.encodePacked(h)))
        );
    }

    function _erc1167(address impl) internal pure returns (bytes memory) {
        return abi.encodePacked(hex"363d3d373d3d3d363d73", impl, hex"5af43d82803e903d91602b57fd5bf3");
    }
}
