// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

/// @notice Account-scoped ERC-1271 / EIP-7739 signing domain shared by EIP-8130 account implementations.
///
/// @dev Produces the account-scoped digest a signer must sign for an account's `isValidSignature` to accept a
///      message: the raw hash wrapped in an EIP-712 PersonalSign struct under a domain whose verifyingContract is
///      the account and whose chainId is the current chain. Binding to the account prevents a signature made for one
///      account from replaying onto another that shares the same key (EIP-7739; TypedDataSign is not implemented).
///      The name and version are fixed for all 8130 accounts. This is not a scope grant.
///
/// @author Coinbase
library AccountDomain {
    /// @dev EIP-712 domain typehash.
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @dev keccak256("PersonalSign(bytes prefixed)").
    bytes32 internal constant PERSONAL_SIGN_TYPEHASH =
        0x983e65e5148e570cd828ead231ee759a8d7958721a768f93bc4483ba005c32de;

    /// @dev Account ERC-1271 domain name/version, fixed for all accounts.
    bytes32 internal constant DOMAIN_NAME_HASH = keccak256("EIP8130Account");
    bytes32 internal constant DOMAIN_VERSION_HASH = keccak256("1");

    /// @notice Account-scoped digest to sign for `hash` to be accepted by `account`'s ERC-1271 check: `hash` wrapped
    ///         in an EIP-712 domain with verifyingContract = `account` and the current chainId.
    ///
    /// @param account The account the signature is bound to (verifyingContract).
    /// @param hash Raw message digest.
    ///
    /// @return The digest to sign.
    function replaySafeHash(address account, bytes32 hash) internal view returns (bytes32) {
        bytes32 structHash = keccak256(abi.encode(PERSONAL_SIGN_TYPEHASH, hash));
        return keccak256(abi.encodePacked(hex"1901", domainSeparator(account), structHash));
    }

    /// @dev EIP-712 domain separator for `account`'s ERC-1271 domain (verifyingContract = account, current chainId).
    function domainSeparator(address account) internal view returns (bytes32) {
        return
            keccak256(abi.encode(EIP712_DOMAIN_TYPEHASH, DOMAIN_NAME_HASH, DOMAIN_VERSION_HASH, block.chainid, account));
    }
}
