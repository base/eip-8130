// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @title RecurringAllowance
///
/// @notice Reusable recurring-allowance accounting for policies (weekly/periodic spend limits).
///
/// @dev Keyed by `commitment` so the manager can remain fully stateless.
library RecurringAllowance {
    /// @notice Allowance bounds for a recurring spend window.
    struct Limit {
        /// @dev Maximum spend per period window.
        uint160 allowance;
        /// @dev Period length in seconds.
        uint40 period;
        /// @dev Start timestamp (seconds) inclusive.
        uint40 start;
        /// @dev End timestamp (seconds) exclusive.
        uint40 end;
    }

    /// @notice Stored usage snapshot for a particular active period.
    struct PeriodUsage {
        /// @dev Period start timestamp (seconds).
        uint40 start;
        /// @dev Period end timestamp (seconds).
        uint40 end;
        /// @dev Amount spent during the period window.
        uint160 spend;
    }

    /// @notice Storage container for usage snapshots.
    struct State {
        /// @dev Most recent stored usage window per commitment.
        mapping(bytes32 commitment => PeriodUsage) lastUpdated;
    }

    /// @notice Thrown when the period length is zero.
    error ZeroPeriod();

    /// @notice Thrown when the allowance is zero.
    error ZeroAllowance();

    /// @notice Thrown when `start >= end` in the limit bounds.
    error InvalidStartEnd(uint40 start, uint40 end);

    /// @notice Thrown when the current timestamp is before the allowance window.
    error BeforeStart(uint40 currentTimestamp, uint40 start);

    /// @notice Thrown when the current timestamp is at or past the allowance window end.
    error AfterEnd(uint40 currentTimestamp, uint40 end);

    /// @notice Thrown when the spend value is zero.
    error ZeroValue();

    /// @notice Thrown when cumulative spend exceeds the period allowance.
    error ExceededAllowance(uint256 value, uint256 allowance);

    /// @notice Validates and consumes allowance for `value`, updating stored usage for the current period.
    ///
    /// @dev Reverts with ZeroValue when `value` is zero.
    /// @dev Reverts with ZeroPeriod when `limit.period` is zero.
    /// @dev Reverts with ZeroAllowance when `limit.allowance` is zero.
    /// @dev Reverts with InvalidStartEnd when `limit.start >= limit.end`.
    /// @dev Reverts with BeforeStart when the current timestamp is before `limit.start`.
    /// @dev Reverts with AfterEnd when the current timestamp is at or past `limit.end`.
    /// @dev Reverts with ExceededAllowance when cumulative period spend would exceed `limit.allowance`.
    ///
    /// @param state Allowance usage storage.
    /// @param commitment Binding identifier the usage is keyed by.
    /// @param limit Allowance bounds for the spend window.
    /// @param value Amount to spend.
    ///
    /// @return current Updated current-period usage after consuming `value`.
    function useLimit(State storage state, bytes32 commitment, Limit memory limit, uint256 value)
        internal
        returns (PeriodUsage memory current)
    {
        if (value == 0) revert ZeroValue();
        if (limit.period == 0) revert ZeroPeriod();
        if (limit.allowance == 0) revert ZeroAllowance();
        if (limit.start >= limit.end) revert InvalidStartEnd(limit.start, limit.end);

        current = getCurrentPeriod(state, commitment, limit);
        uint256 totalSpend = value + uint256(current.spend);
        if (totalSpend > limit.allowance) revert ExceededAllowance(totalSpend, limit.allowance);

        current.spend = uint160(totalSpend);
        state.lastUpdated[commitment] = current;
    }

    /// @notice Returns the most recent stored usage window for `commitment`.
    ///
    /// @param state Allowance usage storage.
    /// @param commitment Binding identifier the usage is keyed by.
    ///
    /// @return The most recent stored period usage (zeroed if none recorded).
    function getLastUpdated(State storage state, bytes32 commitment) internal view returns (PeriodUsage memory) {
        return state.lastUpdated[commitment];
    }

    /// @notice Computes the current period window, including stored spend if the window is still active.
    ///
    /// @dev Reverts with BeforeStart when the current timestamp is before `limit.start`.
    /// @dev Reverts with AfterEnd when the current timestamp is at or past `limit.end`.
    ///
    /// @param state Allowance usage storage.
    /// @param commitment Binding identifier the usage is keyed by.
    /// @param limit Allowance bounds for the spend window.
    ///
    /// @return Current period usage snapshot (including stored spend if still active).
    function getCurrentPeriod(State storage state, bytes32 commitment, Limit memory limit)
        internal
        view
        returns (PeriodUsage memory)
    {
        uint40 currentTimestamp = uint40(block.timestamp);
        if (currentTimestamp < limit.start) revert BeforeStart(currentTimestamp, limit.start);
        if (currentTimestamp >= limit.end) revert AfterEnd(currentTimestamp, limit.end);

        PeriodUsage memory lastUpdated = state.lastUpdated[commitment];
        bool lastExists = lastUpdated.spend != 0;
        bool lastStillActive = currentTimestamp < lastUpdated.end;
        if (lastExists && lastStillActive) return lastUpdated;

        uint40 currentPeriodProgress = (currentTimestamp - limit.start) % limit.period;
        uint40 start = currentTimestamp - currentPeriodProgress;
        bool endOverflow = uint256(start) + uint256(limit.period) > limit.end;
        uint40 end = endOverflow ? limit.end : start + limit.period;
        return PeriodUsage({start: start, end: end, spend: 0});
    }
}
