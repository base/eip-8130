// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

struct KeyOperation {
    uint8 opType;
    address verifier;
    bytes32 keyId;
    uint8 flags;
}

struct AccountOperation {
    uint8 opType;
    uint8 flags;
    uint32 unlockDelay;
}

/// @notice Canonical ABI-encoded digest computation for EIP-8130 account changes.
///         Each entry type has a distinct type hash derived from its canonical type string.
///         Operations are individually ABI-encoded and hashed into an array digest.
///         Wallets may wrap these digests in EIP-712 typed data at the account level for UX.
abstract contract AccountConfigDigest {
    bytes32 constant KEY_CHANGE_TYPEHASH = keccak256(
        "KeyChange(address account,uint64 chainId,uint64 sequence,KeyOperation[] operations)"
        "KeyOperation(uint8 opType,address verifier,bytes32 keyId,uint8 flags)"
    );

    bytes32 constant ACCOUNT_CHANGE_TYPEHASH = keccak256(
        "AccountChange(address account,uint64 chainId,uint64 sequence,AccountOperation[] operations)"
        "AccountOperation(uint8 opType,uint8 flags,uint32 unlockDelay)"
    );

    function _computeKeyChangeDigest(
        address account,
        uint64 chainId,
        uint64 sequence,
        KeyOperation[] calldata operations
    ) internal pure returns (bytes32) {
        bytes32[] memory opHashes = new bytes32[](operations.length);
        for (uint256 i; i < operations.length; i++) {
            opHashes[i] = keccak256(
                abi.encode(operations[i].opType, operations[i].verifier, operations[i].keyId, operations[i].flags)
            );
        }
        return
            keccak256(
                abi.encode(KEY_CHANGE_TYPEHASH, account, chainId, sequence, keccak256(abi.encodePacked(opHashes)))
            );
    }

    function _computeAccountChangeDigest(
        address account,
        uint64 chainId,
        uint64 sequence,
        AccountOperation[] calldata operations
    ) internal pure returns (bytes32) {
        bytes32[] memory opHashes = new bytes32[](operations.length);
        for (uint256 i; i < operations.length; i++) {
            opHashes[i] = keccak256(abi.encode(operations[i].opType, operations[i].flags, operations[i].unlockDelay));
        }
        return keccak256(
            abi.encode(ACCOUNT_CHANGE_TYPEHASH, account, chainId, sequence, keccak256(abi.encodePacked(opHashes)))
        );
    }
}
