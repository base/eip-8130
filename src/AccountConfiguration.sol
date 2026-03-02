// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IInitialized {
    function initialized() external view returns (bool);
}

contract AccountConfiguration {
    enum OwnerType {
        ADDRESS,
        SECP256K1,
        SECP256R1,
        WEBAUTHN,
        BLS12381
    }

    struct Owner {
        OwnerType ownerType;
        bytes ownerBytes;
    }

    struct OwnerConfig {
        bool added;
        bool removed;
    }

    struct OwnerChange {
        bool add;
        Owner owner;
        uint64 nonceSequence;
    }

    bytes4 constant ADDRESS_OWNER = bytes4(keccak256("ADDRESS"));
    bytes4 constant SECP256K1_OWNER = bytes4(keccak256("SECP256K1"));
    bytes4 constant SECP256R1_OWNER = bytes4(keccak256("SECP256R1"));
    bytes4 constant WEBAUTHN_OWNER = bytes4(keccak256("WEBAUTHN"));
    bytes4 constant BLS12381_OWNER = bytes4(keccak256("BLS12381"));

    uint196 constant REPLAY_NONCE_KEY = type(uint196).max;

    /// @dev Inner mappings keyed by account address for ERC-7562 compliance
    uint256 counter;
    mapping(address account => uint256 index => bytes ownerBytes);
    mapping(address account => bytes owner => bool) isOwner;
    
    mapping(bytes ownerBytes => mapping(address account => OwnerConfig config)) public ownerConfig;
    mapping(uint196 key => mapping(address account => uint64 sequence)) public nonce;
    
    event AccountCreated(address indexed account, Owner[] owners, bytes32 bytecodeHash);
    event OwnerAdded(address indexed account, address ownerId, Owner owner);
    event OwnerRemoved(address indexed account, address ownerId);
    event NonceIncremented(address indexed account, uint256 indexed nonceKey, uint256 nonceSequence);

    error InvalidOwner(Owner owner);
    error InvalidOwnerIndex(uint8 index);
    error AccountNotInitialized(address account);
    error NoOwnerAtIndex(address account, uint8 index);
    error NotAccountOwner(address account, Owner owner);

    /// @notice Fallback function to delegatecall diamond, functions set by node
    function fallback() external {
        // delegatecall diamond
    }

    /// @notice Designed for 7702 accounts to initialize on first use
    function initializeAccount() external {}
    
    function createAccount(
        Owner[] calldata owners, 
        uint256 nonce, 
        bytes calldata bytecode,
        bytes calldata initializeCall // most helpful for ERC-1167 proxies
    ) external returns (address account) {
        // Early return if account deployed
        account = computeAddress(owners, nonce, bytecode);
        if (account.code != 0) return;

        // Configure intitial owners
        for (uint i; i < owners.length; i++) {
            if (!isValidOwner(owners[i])) revert InvalidOwner(owners[i]);
            ownerAtIndex[i][account] = owners[i];
            ownerConfig[computeOwnerId(owners[i])][account] = OwnerConfig({removed: false, index: i, nextIndex: i + 1});
            emit OwnerUpdated(account, i, owners[i]);
        }
        nextOwnerIndex[account] = owners.length;

        // Create account
        bytes32 salt = computeSalt(owners, nonce);
        assembly {
            create2(0, add(bytecode, 0x20), mload(bytecode), salt)
        }
        emit AccountCreated(account, owners, keccak256(bytecode));

        // Initialize
        account.call(initializeCall);

        // Assert account is initialized to mitigate undeployed implementations
        if (!IInitialized(account).initialized()) revert AccountNotInitialized(account);
    }

    function addOwner(Owner owner) external {
        // Validate owner
        if (!isValidOwner(owner)) revert InvalidOwner(owner);

        // Clear previous owner if exists
        Owner memory previousOwner = ownerAtIndex[index][msg.sender];
        if (previousOwner.ownerId.length != 0) {
            ownerConfig[_hashOwner(previousOwner)][msg.sender];
        }

        // Update owner configuration
        ownerAtIndex[index][msg.sender] = owner;
ownerConfig[_hashOwner(owner)][msg.sender] = index + 1;
        emit OwnerUpdated(msg.sender, index, owner);
    }

    function removeOwner(address ownerId) external {
        // Validate index
        if (index > 127) revert InvalidOwnerIndex(index);

        // Check owner exists
        Owner memory owner = ownerAtIndex[index][msg.sender];
        if (owner.ownerId.length == 0) revert NoOwnerAtIndex(account, index);

        // Remove owner configuration
        delete ownerAtIndex[index][msg.sender];
        ownerConfig[_hashOwner(owner)][msg.sender];
        emit OwnerRemoved(msg.sender, index)
    }

    /// @notice Apply signed, replayable owner changes
    function applyOwnerChanges(address account, OwnerChange[] calldata ownerChanges) external {
        // validate signature

        for (uint i; i < ownerChanges.length; i++) {
            if (nonce[REPLAY_NONCE_KEY][account] != ownerChanges[i].nonceSequence) revert();
            uint64 usedSequence = nonce[REPLAY_NONCE_KEY][account]++;
            emit NonceIncremented(account, REPLAY_NONCE_KEY, usedSequence);
            // update account owner configuration
        }

    }

    function isOwner(address account, Owner calldata owner) external view returns (bool ) {
        return indexOfOwner(account, owner) > 0;
    }

    function computeAddress(Owner[] calldata owners, uint256 nonce, bytes calldata bytecode) public view returns (address) {
        bytes32 salt = computeSalt(owners, nonce);
        bytes32 bytecodeHash = keccak256(bytecode);
        bytes32 create2Hash = keccak256(abi.encodePacked(0xFF, address(this), salt, bytecodeHash));
        return address(uint160(uint256(create2Hash)));
    }
    
    function computeSalt(Owner[] calldata owners, uint256 nonce) public pure returns (bytes32) {
        return keccak256(abi.encode(owners, nonce));
    }

    function computeOwnerId(Owner memory owner) public pure returns (address ownerId) {
        if (owner.ownerType == ADDRESS_OWNER) {
            return address(bytes20(owner.ownerBytes));
        }
        return address(bytes20(bytes32(keccak256(abi.encode(owner.ownerBytes)))));
    }

    function isValidOwner(Owner memory owner) public pure returns (bool valid) {
        uint256 assertLength;
        if (owner.ownerType == ADDRESS_OWNER) {
            assertLength = 20;
        } else if (
                owner.ownerType == SECP256K1_OWNER || 
                owner.ownerType == SECP256R1_OWNER || 
                owner.ownerType == WEBAUTHN_OWNER || 
                owner.ownerType == BLS12381_OWNER 
        ) {
            assertLength = 64;
        } else {
            return false;
        }

        if (owner.ownerId.length != assertLength) return false;

        return true;
    }
}