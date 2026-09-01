// SPDX-License-Identifier: MIT
pragma solidity 0.8.36;

import {Keystore} from "../Keystore.sol";

/// @notice Opt-in for {Keystore.importAccount}. Not part of the EIP-8130 account ABI: created 8130 accounts
///         never implement it. Existing wallets implement it so Keystore can read the bootstrap actor set and
///         confirm its digest. A wallet that does not implement this function cannot be imported.
///
///         {confirmKeystoreImport} must return the intended actors and {Keystore.computeImportDigest} of that
///         set. A wallet that always returns a valid pair reopens `execute(importAccount())` for itself — gate
///         the return on the wallet's own import entry, or accept that anyone who can `execute` can finalize it.
/// @author Coinbase
interface IKeystoreImport {
    /// @notice Returns this account's intended import actor set and {Keystore.computeImportDigest} of that set.
    ///         A digest that does not match the returned actors (or a revert) is {Keystore.ImportNotConfirmed}.
    function confirmKeystoreImport()
        external
        view
        returns (bytes32 digest, Keystore.InitialActor[] memory initialActors);
}
