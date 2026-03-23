// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

/// @notice Reference interface for the EIP-8130 Native Verifier precompile at NATIVE_VERIFIERS_ADDRESS.
///         Read-only. Gas is charged as a base cost plus 3 gas per 32 bytes of returned data.
///         On non-8130 chains, no code at NATIVE_VERIFIERS_ADDRESS; STATICCALL returns zero/default values.
interface INativeVerifiers {
    struct NativeVerifier {
        uint8 verifierType;
        address verifier;
    }

    function getNativeVerifier(uint8 verifierType) external view returns (address verifier);
    function getAllNativeVerifiers() external view returns (NativeVerifier[] memory nativeVerifiers);
}
