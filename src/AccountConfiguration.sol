// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IInitialized} from "./accounts/IInitialized.sol";
import {IVerifier} from "./verifiers/IVerifier.sol";

contract AccountConfiguration {
    struct AccountConfig {
        uint32 ownerChangeSequence;
        bool locked;
        uint40 unlockDelay;
        uint40 unlockInitiatedAt;
    }

    struct OwnerConfig {
        address verifier;
    }

    struct Owner {
        bytes32 id;
        OwnerConfig config;
    }

    struct OwnerChange {
        bool add; // true if adding owner, false if removing owner
        Owner owner;
    }

    mapping(address account => AccountConfig config) public accountConfigs;
    mapping(bytes32 ownerId => mapping(address account => OwnerConfig config)) public ownerConfigs;

    event AccountCreated(address indexed account, bytes32 bytecodeHash);
    event OwnerAdded(address indexed account, bytes32 ownerId, address verifier);
    event OwnerRemoved(address indexed account, bytes32 ownerId);

    ////////
    // INITIALIZATION
    ////////

    function createAccount(
        Owner[] calldata initialOwners,
        uint256 nonce,
        bytes calldata bytecode,
        bytes calldata initializeCall // helpful for ERC-1167 proxies
    ) external returns (address account) {
        // Early return if account deployed
        account = computeAddress(initialOwners, nonce, bytecode, initializeCall);
        if (account.code.length > 0) return account;

        // Configure intitial owners
        bytes32 previousOwnerId = bytes32(0);
        for (uint256 i; i < initialOwners.length; i++) {
            // Require owners sorted by id to enforce same set of owners produce same address
            require(initialOwners[i].id > previousOwnerId);
            previousOwnerId = initialOwners[i].id;
            _addOwner(account, initialOwners[i]);
        }

        // Create account
        bytes32 salt = computeSalt(initialOwners, nonce, initializeCall);
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, bytecode.offset, bytecode.length)
            mstore(0x40, add(ptr, bytecode.length))
            pop(create2(0, ptr, bytecode.length, salt))
        }
        emit AccountCreated(account, keccak256(bytecode));

        // Initialize account
        if (initializeCall.length > 0) {
            (bool success,) = account.call(initializeCall);
            require(success);
        }

        // Assert account is initialized to mitigate undeployed implementations
        require(IInitialized(account).initialized());
    }

    ////////
    // OWNER MANAGEMENT
    ////////

    function addOwner(Owner calldata owner) external {
        _addOwner(msg.sender, owner);
    }

    function removeOwner(bytes32 ownerId) external {
        _removeOwner(msg.sender, ownerId);
    }

    function applyOwnerChanges(
        address account,
        OwnerChange[] calldata ownerChanges,
        bytes32 ownerId,
        bytes calldata verifyData
    ) external {
        bytes32 digest = keccak256(abi.encode(account, ownerChanges, accountConfigs[account].ownerChangeSequence++));
        require(verifyIntent(account, ownerId, digest, verifyData));
        for (uint256 i; i < ownerChanges.length; i++) {
            ownerChanges[i].add
                ? _addOwner(account, ownerChanges[i].owner)
                : _removeOwner(account, ownerChanges[i].owner.id);
        }
    }

    function multicall(bytes[] calldata data) external {
        for (uint256 i; i < data.length; i++) {
            (bool success,) = address(this).delegatecall(data[i]);
            require(success);
        }
    }

    function lockOwnerChanges(uint40 unlockDelay) external {
        require(unlockDelay > 0);
        AccountConfig memory accountConfig = accountConfigs[msg.sender];
        require(!accountConfig.locked);
        accountConfig.locked = true;
        accountConfig.unlockDelay = unlockDelay;
        accountConfigs[msg.sender] = accountConfig;
    }

    function initiateUnlockOwnerChanges() external {
        AccountConfig memory accountConfig = accountConfigs[msg.sender];
        require(accountConfig.locked && accountConfig.unlockInitiatedAt == 0);
        accountConfig.unlockInitiatedAt = uint40(block.timestamp) + accountConfig.unlockDelay;
        accountConfigs[msg.sender] = accountConfig;
    }

    function finalizeUnlockOwnerChanges() external {
        AccountConfig memory accountConfig = accountConfigs[msg.sender];
        require(accountConfig.locked && block.timestamp > accountConfig.unlockInitiatedAt + accountConfig.unlockDelay);
        accountConfig.locked = false;
        accountConfig.unlockInitiatedAt = 0;
        accountConfigs[msg.sender] = accountConfig;
    }

    ////////
    // TRANSIENT STORAGE VIEWS
    ////////

    function getCurrentPayer() external view returns (address payer) {
        bytes32 slot = keccak256("context.payer");
        assembly {
            payer := tload(slot)
        }
    }

    function getCurrentOwnerId() external view returns (bytes32 ownerId) {
        bytes32 slot = keccak256("context.ownerId");
        assembly {
            ownerId := tload(slot)
        }
    }

    ////////
    // STORAGE VIEWS
    ////////

    function isOwner(address account, bytes32 ownerId) public view returns (bool) {
        return ownerConfigs[ownerId][account].verifier != address(0);
    }

    function verifyIntent(address account, bytes32 ownerId, bytes32 hash, bytes calldata data)
        public
        view
        returns (bool)
    {
        address verifier = ownerConfigs[ownerId][account].verifier;
        if (verifier == address(0)) return false;
        return IVerifier(verifier).verifyIntent(account, ownerId, hash, data);
    }

    ////////
    // UTILITIES
    ////////

    function computeAddress(
        Owner[] calldata initialOwners,
        uint256 nonce,
        bytes calldata bytecode,
        bytes calldata initializeCall
    ) public view returns (address) {
        bytes32 salt = computeSalt(initialOwners, nonce, initializeCall);
        bytes32 bytecodeHash = keccak256(bytecode);
        bytes32 create2Hash = keccak256(abi.encodePacked(uint8(0xFF), address(this), salt, bytecodeHash));
        return address(uint160(uint256(create2Hash)));
    }

    function computeSalt(Owner[] calldata initialOwners, uint256 nonce, bytes calldata initializeCall)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(initialOwners, nonce, initializeCall));
    }

    ////////
    // INTERNALS
    ////////

    function _addOwner(address account, Owner calldata owner) internal {
        address verifier = owner.config.verifier;
        require(verifier != address(0) && verifier.code.length > 0);
        require(!accountConfigs[account].locked);
        require(!isOwner(account, owner.id));
        ownerConfigs[owner.id][account] = OwnerConfig({verifier: verifier});
        emit OwnerAdded(account, owner.id, verifier);
    }

    function _removeOwner(address account, bytes32 ownerId) internal {
        require(!accountConfigs[account].locked);
        require(isOwner(account, ownerId));
        delete ownerConfigs[ownerId][account];
        emit OwnerRemoved(account, ownerId);
    }
}
