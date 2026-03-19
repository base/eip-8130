// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IVerifier} from "./IVerifier.sol";
import {ITxContext} from "../interfaces/ITxContext.sol";

interface IERC20Minimal {
    function balanceOf(address account) external view returns (uint256);
}

interface AggregatorV3Interface {
    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound);
}

/// @notice Chainlink-priced payer verifier for gas sponsorship.
///
///         Works with any ERC-20 that has a Chainlink ETH/USD-denominated price path.
///         Optional blocklist enforcement — pass address(0) to disable.
///
///         Zero untrusted input — `data` is ignored entirely. Everything is derived on-chain:
///           - Token address, blocklist, and feed config are immutables
///           - ETH/USD price is read from a Chainlink price feed (single SLOAD)
///           - Max cost and gas limit come from the TX_CONTEXT precompile
///
///         Validation flow:
///           1. Derive ownerId from the immutable TOKEN address
///           2. Check gas limit is sufficient to execute the token transfer
///           3. Compute ETH cost: TX_CONTEXT.getMaxCost() + verifier gas overhead
///           4. Read Chainlink ETH/USD price, convert ETH cost to token amount
///           5. If blocklist is set, check sender and payer are not blocklisted
///           6. Check sender's token balance ≥ required amount
///           7. Validate first call phase: exactly 1 call, transfer(payer, amount ≥ required)
///
///         ownerId = bytes32(uint256(uint160(TOKEN))) — the token address, right-aligned.
///         Naturally collision-free with K1/DELEGATE's left-aligned bytes32(bytes20(address)).
contract ChainlinkPayerVerifier is IVerifier {
    bytes4 private constant TRANSFER_SELECTOR = 0xa9059cbb; // transfer(address,uint256)

    address public immutable TOKEN;
    address public immutable ETH_USD_FEED;
    address public immutable BLOCKLIST; // address(0) = no blocklist checks
    bytes4 public immutable BLOCKLIST_SELECTOR; // e.g., isBlacklisted(address), isBlackListed(address)
    address public immutable TX_CONTEXT;
    bytes32 public immutable OWNER_ID;
    uint256 public immutable VERIFIER_GAS_OVERHEAD;
    uint256 public immutable MIN_GAS_LIMIT;
    uint256 public immutable MAX_STALENESS;
    uint8 public immutable TOKEN_DECIMALS;
    uint8 public immutable FEED_DECIMALS;

    /// @param token ERC-20 token address (e.g., USDC)
    /// @param ethUsdFeed Chainlink ETH/USD price feed address
    /// @param blocklist Blocklist contract (address(0) to disable). For USDC, pass the token address
    /// @param blocklistSelector Function selector for the blocklist check (e.g., isBlacklisted(address))
    /// @param txContext Transaction Context precompile address (TX_CONTEXT_ADDRESS)
    /// @param verifierGasOverhead Extra gas to account for the verifier's own metered execution
    /// @param minGasLimit Minimum gas_limit required to ensure the token transfer succeeds
    /// @param maxStaleness Maximum age (seconds) of the Chainlink price before rejection
    /// @param tokenDecimals Token decimals (e.g., 6 for USDC)
    /// @param feedDecimals Chainlink feed decimals (typically 8)
    constructor(
        address token,
        address ethUsdFeed,
        address blocklist,
        bytes4 blocklistSelector,
        address txContext,
        uint256 verifierGasOverhead,
        uint256 minGasLimit,
        uint256 maxStaleness,
        uint8 tokenDecimals,
        uint8 feedDecimals
    ) {
        TOKEN = token;
        ETH_USD_FEED = ethUsdFeed;
        BLOCKLIST = blocklist;
        BLOCKLIST_SELECTOR = blocklistSelector;
        TX_CONTEXT = txContext;
        OWNER_ID = bytes32(uint256(uint160(token)));
        VERIFIER_GAS_OVERHEAD = verifierGasOverhead;
        MIN_GAS_LIMIT = minGasLimit;
        MAX_STALENESS = maxStaleness;
        TOKEN_DECIMALS = tokenDecimals;
        FEED_DECIMALS = feedDecimals;
    }

    function verify(bytes32, bytes calldata) external view returns (bytes32) {
        ITxContext ctx = ITxContext(TX_CONTEXT);
        require(ctx.getGasLimit() >= MIN_GAS_LIMIT, "gas limit too low for transfer");

        uint256 maxEthCost = ctx.getMaxCost() + VERIFIER_GAS_OVERHEAD * tx.gasprice;
        uint256 requiredTokens = _ethToTokens(maxEthCost);

        _checkSender(ctx, requiredTokens);
        _checkPaymentPhase(ctx, requiredTokens);

        return OWNER_ID;
    }

    /// @dev Converts wei to token amount using Chainlink ETH/USD price.
    ///      ethAmount (18 decimals) * price (FEED_DECIMALS) / 10^(18 + FEED_DECIMALS - TOKEN_DECIMALS)
    function _ethToTokens(uint256 ethAmount) internal view returns (uint256) {
        (, int256 price,, uint256 updatedAt,) = AggregatorV3Interface(ETH_USD_FEED).latestRoundData();
        require(price > 0, "invalid price");
        require(block.timestamp - updatedAt <= MAX_STALENESS, "stale price");

        return ethAmount * uint256(price) / 10 ** (18 + FEED_DECIMALS - TOKEN_DECIMALS);
    }

    function _checkSender(ITxContext ctx, uint256 requiredTokens) internal view {
        address sender = ctx.getSender();
        _requireNotBlocklisted(sender);
        require(IERC20Minimal(TOKEN).balanceOf(sender) >= requiredTokens, "insufficient token balance");
    }

    function _checkPaymentPhase(ITxContext ctx, uint256 requiredTokens) internal view {
        address payer = ctx.getPayer();
        _requireNotBlocklisted(payer);

        ITxContext.Call[][] memory phases = ctx.getCalls();
        require(phases.length > 0, "no call phases");
        require(phases[0].length == 1, "first phase must have exactly 1 call");
        require(phases[0][0].to == TOKEN, "first call must target token");

        _checkTransferCalldata(phases[0][0].data, payer, requiredTokens);
    }

    /// @dev Calls BLOCKLIST with BLOCKLIST_SELECTOR(account) and requires the result is false.
    ///      No-op if BLOCKLIST is address(0).
    function _requireNotBlocklisted(address account) internal view {
        if (BLOCKLIST == address(0)) return;
        (bool success, bytes memory result) = BLOCKLIST.staticcall(abi.encodeWithSelector(BLOCKLIST_SELECTOR, account));
        require(success && result.length >= 32, "blocklist check failed");
        require(!abi.decode(result, (bool)), "blocklisted");
    }

    function _checkTransferCalldata(bytes memory cd, address payer, uint256 requiredTokens) internal pure {
        require(cd.length >= 68, "invalid transfer calldata");

        bytes4 sel;
        address recipient;
        uint256 amt;
        assembly {
            sel := mload(add(cd, 0x20))
            recipient := mload(add(cd, 0x24))
            amt := mload(add(cd, 0x44))
        }

        require(sel == TRANSFER_SELECTOR, "must be transfer call");
        require(recipient == payer, "transfer recipient must be payer");
        require(amt >= requiredTokens, "transfer amount insufficient");
    }
}
