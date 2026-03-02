// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import {IVerifier} from "./verifiers/IVerifier.sol";

interface IInitialized {
    function initialized() external view returns (bool);
}

contract AccountConfiguration {
    struct Owner {
        bytes32 id;
        address verifier;
    }

    struct OwnerChange {
        bool add; // true if adding owner, false if removing owner
        Owner owner;
    }

    mapping(bytes32 ownerId => mapping(address account => address verifier)) public verifiers;
    mapping(address account => uint256 sequence) public ownerChangeSequence;

    event AccountCreated(address indexed account, Owner[] owners, bytes32 bytecodeHash);
    event OwnerAdded(address indexed account, bytes32 ownerId, address verifier);
    event OwnerRemoved(address indexed account, bytes32 ownerId);

    error InvalidOwner(Owner owner);
    error InvalidOwnerId(bytes32 ownerId);
    error AccountNotInitialized(address account);
    error NoOwner(address account, bytes32 ownerId);
    error NotAccountOwner(address account, bytes32 ownerId);

    ////////
    // INITIALIZATION
    ////////

    function createAccount(
        Owner[] calldata initialOwners,
        uint256 nonce,
        bytes calldata bytecode,
        bytes calldata initializeCall // most helpful for ERC-1167 proxies
    ) external returns (address account) {
        // Early return if account deployed
        account = computeAddress(initialOwners, initializeCall, nonce, bytecode);
        if (account.code.length > 0) return account;

        // Configure intitial owners
        for (uint256 i; i < initialOwners.length; i++) {
            _addOwner(account, initialOwners[i]);
        }

        // Create account
        bytes32 salt = computeSalt(initialOwners, initializeCall, nonce);
        assembly {
            let ptr := mload(0x40)
            calldatacopy(ptr, bytecode.offset, bytecode.length)
            mstore(0x40, add(ptr, bytecode.length))
            pop(create2(0, ptr, bytecode.length, salt))
        }
        emit AccountCreated(account, initialOwners, keccak256(bytecode));

        // Initialize
        if (initializeCall.length > 0) {
            (bool success,) = account.call(initializeCall);
            if (!success) revert AccountNotInitialized(account);
        }

        // Assert account is initialized to mitigate undeployed implementations
        if (!IInitialized(account).initialized()) revert AccountNotInitialized(account);
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

    /// @notice Apply replayable owner changes
    function applyOwnerChanges(
        address account,
        OwnerChange[] calldata ownerChanges,
        bytes32 ownerId,
        bytes calldata verifyData
    ) external {
        bytes32 digest = keccak256(abi.encode(account, ownerChanges, ownerChangeSequence[account]++));
        require(IVerifier(verifiers[ownerId][account]).verify(account, ownerId, digest, verifyData));
        for (uint256 i; i < ownerChanges.length; i++) {
            if (ownerChanges[i].add) {
                _addOwner(account, ownerChanges[i].owner);
            } else {
                _removeOwner(account, ownerChanges[i].owner.id);
            }
        }
    }

    ////////
    // STATE VIEWS
    ////////

    function isValidSignature(address account, bytes32 ownerId, bytes32 hash, bytes calldata signature)
        external
        view
        returns (bool)
    {
        address verifier = verifiers[ownerId][account];
        if (verifier == address(0)) return false;
        return IVerifier(verifier).verify(account, ownerId, hash, signature);
    }

    function isOwner(address account, bytes32 ownerId) public view returns (bool) {
        return verifiers[ownerId][account] != address(0);
    }

    function validateOwner(Owner memory owner) public view {
        if (owner.verifier == address(0)) revert InvalidOwner(owner);
        if (owner.verifier.code.length == 0) revert InvalidOwner(owner);
    }

    ////////
    // UTILITIES
    ////////

    function computeAddress(
        Owner[] calldata initialOwners,
        bytes calldata initializeCall,
        uint256 nonce,
        bytes calldata bytecode
    ) public view returns (address) {
        bytes32 salt = computeSalt(initialOwners, initializeCall, nonce);
        bytes32 bytecodeHash = keccak256(bytecode);
        bytes32 create2Hash = keccak256(abi.encodePacked(uint8(0xFF), address(this), salt, bytecodeHash));
        return address(uint160(uint256(create2Hash)));
    }

    function computeSalt(Owner[] calldata initialOwners, bytes calldata initializeCall, uint256 nonce)
        public
        pure
        returns (bytes32)
    {
        return keccak256(abi.encode(initialOwners, initializeCall, nonce));
    }

    ////////
    // INTERNALS
    ////////

    function _addOwner(address account, Owner calldata owner) internal {
        validateOwner(owner);
        require(!isOwner(account, owner.id));
        verifiers[owner.id][account] = owner.verifier;
        emit OwnerAdded(account, owner.id, owner.verifier);
    }

    function _removeOwner(address account, bytes32 ownerId) internal {
        require(isOwner(account, ownerId));
        delete verifiers[ownerId][account];
        emit OwnerRemoved(account, ownerId);
    }
}
