// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

struct ConfigOperation {
    uint8 opType; // 0x01 = authorizeOwner, 0x02 = revokeOwner
    address verifier; // authorizeOwner only
    bytes32 ownerId; // authorizeOwner, revokeOwner
    uint8 scope; // authorizeOwner only (0x00 = unrestricted)
}

/// @notice Canonical ABI-encoded digest computation for EIP-8130 config changes and account lock.
///         Operations are individually ABI-encoded and hashed into an array digest.
abstract contract AccountConfigDigest {
    bytes32 constant CONFIG_CHANGE_TYPEHASH = keccak256(
        "ConfigChange(address account,uint64 chainId,uint64 sequence,ConfigOperation[] operations)"
        "ConfigOperation(uint8 opType,address verifier,bytes32 ownerId,uint8 scope)"
    );

    bytes32 constant LOCK_TYPEHASH = keccak256("Lock(address account,uint32 unlockDelay)");
    bytes32 constant REQUEST_UNLOCK_TYPEHASH = keccak256("RequestUnlock(address account)");
    bytes32 constant UNLOCK_TYPEHASH = keccak256("Unlock(address account)");

    function _computeConfigChangeDigest(
        address account,
        uint64 chainId,
        uint64 sequence,
        ConfigOperation[] calldata operations
    ) internal pure returns (bytes32) {
        bytes32[] memory opHashes = new bytes32[](operations.length);
        for (uint256 i; i < operations.length; i++) {
            opHashes[i] = keccak256(
                abi.encode(operations[i].opType, operations[i].verifier, operations[i].ownerId, operations[i].scope)
            );
        }
        return keccak256(
            abi.encode(CONFIG_CHANGE_TYPEHASH, account, chainId, sequence, keccak256(abi.encodePacked(opHashes)))
        );
    }

    function _computeLockDigest(address account, uint32 unlockDelay) internal pure returns (bytes32) {
        return keccak256(abi.encode(LOCK_TYPEHASH, account, unlockDelay));
    }

    function _computeRequestUnlockDigest(address account) internal pure returns (bytes32) {
        return keccak256(abi.encode(REQUEST_UNLOCK_TYPEHASH, account));
    }

    function _computeUnlockDigest(address account) internal pure returns (bytes32) {
        return keccak256(abi.encode(UNLOCK_TYPEHASH, account));
    }
}
