// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";

import {AccountConfiguration} from "../../src/AccountConfiguration.sol";
import {IVerifier} from "../../src/verifiers/IVerifier.sol";
import {K1Verifier} from "../../src/verifiers/K1Verifier.sol";
import {P256Verifier} from "../../src/verifiers/P256Verifier.sol";
import {WebAuthnVerifier} from "../../src/verifiers/WebAuthnVerifier.sol";
import {DelegatedVerifier} from "../../src/verifiers/DelegatedVerifier.sol";
import {DefaultAccount} from "../../src/accounts/DefaultAccount.sol";

contract AccountConfigurationTest is Test {
    AccountConfiguration public accountConfiguration;
    IVerifier public k1Verifier;
    IVerifier public p256Verifier;
    IVerifier public webAuthnVerifier;
    IVerifier public delegatedVerifier;
    address public defaultAccountImplementation;

    function setUp() public {
        accountConfiguration = new AccountConfiguration();
        k1Verifier = IVerifier(new K1Verifier());
        p256Verifier = IVerifier(new P256Verifier());
        webAuthnVerifier = IVerifier(new WebAuthnVerifier());
        delegatedVerifier = IVerifier(new DelegatedVerifier(address(accountConfiguration)));
        defaultAccountImplementation = address(new DefaultAccount(address(accountConfiguration)));
    }
}
