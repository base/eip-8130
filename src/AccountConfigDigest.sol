// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

struct ConfigOperation {
    uint8 opType; // 0x01 = authorizeOwner, 0x02 = revokeOwner
    address verifier; // authorizeOwner only
    bytes32 ownerId; // authorizeOwner, revokeOwner
}

/// @notice Canonical ABI-encoded digest computation for EIP-8130 config changes.
///         Operations are individually ABI-encoded and hashed into an array digest.
abstract contract AccountConfigDigest {
    bytes32 constant CONFIG_CHANGE_TYPEHASH = keccak256(
        "ConfigChange(address account,uint64 chainId,uint64 sequence,ConfigOperation[] operations)"
        "ConfigOperation(uint8 opType,address verifier,bytes32 ownerId)"
    );

    function _computeConfigChangeDigest(
        address account,
        uint64 chainId,
        uint64 sequence,
        ConfigOperation[] calldata operations
    ) internal pure returns (bytes32) {
        bytes32[] memory opHashes = new bytes32[](operations.length);
        for (uint256 i; i < operations.length; i++) {
            opHashes[i] = keccak256(abi.encode(operations[i].opType, operations[i].verifier, operations[i].ownerId));
        }
        return keccak256(
            abi.encode(CONFIG_CHANGE_TYPEHASH, account, chainId, sequence, keccak256(abi.encodePacked(opHashes)))
        );
    }
}
