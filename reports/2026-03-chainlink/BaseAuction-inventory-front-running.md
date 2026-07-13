# Public `bid()` can be front-run to consume auction inventory and revert later bids

## Finding Metadata

| Field                 | Value                                                                                                                                         |
| --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| Target project        | [Chainlink Payment Abstraction V2](https://github.com/code-423n4/2026-03-chainlink)                                                           |
| Affected contract     | [`src/BaseAuction.sol`](https://github.com/code-423n4/2026-03-chainlink/blob/5317782e3855d9547412ab5a490257d7c5e51fac/src/BaseAuction.sol)    |
| Fixed source revision | [`5317782e3855d9547412ab5a490257d7c5e51fac`](https://github.com/code-423n4/2026-03-chainlink/commit/5317782e3855d9547412ab5a490257d7c5e51fac) |
| Vulnerability class   | Transaction-ordering dependence / inventory preemption                                                                                        |
| Suggested severity    | Low / Informational (design-dependent)                                                                                                        |
| Proof of concept      | [HUODONGREN/front-run_0day Issue #7](https://github.com/HUODONGREN/front-run_0day/issues/7)                                                   |

## Summary

`BaseAuction.bid()` is permissionless and settles bids using the auction contract's asset balance at transaction execution time. A bidder receives the requested auctioned asset only when the requested `amount` does not exceed the balance that remains when the transaction is executed.

An attacker can observe a victim's pending full- or large-inventory bid and submit an earlier transaction for the same inventory. If the attacker's transaction executes first, it receives the available auctioned assets and reduces the contract balance. The victim's later transaction then reverts with `BidAmountTooHigh`.

The ordering dependency is reproducible, but the attacker must pay the required `assetOut` amount and does not take funds from the victim. Because the protocol describes the mechanism as a permissionless Dutch auction, this behavior may be considered expected first-come-first-served competition rather than a High- or Medium-severity vulnerability.

It should therefore be treated as a Low/Informational availability and user-experience risk unless a stronger impact—such as sustained denial of service, protocol loss, or violation of a guaranteed fill—is demonstrated.

## Vulnerable Code

The inventory check is performed against the live token balance:

[`BaseAuction.sol#L437-L440`](https://github.com/code-423n4/2026-03-chainlink/blob/5317782e3855d9547412ab5a490257d7c5e51fac/src/BaseAuction.sol#L437-L440)

```solidity
uint256 availableBalance = IERC20(asset).balanceOf(address(this));
if (amount > availableBalance) {
    revert BidAmountTooHigh(amount, availableBalance);
}
```

After the check, the requested asset is transferred to the currently executing bidder and the corresponding payment is collected:

[`BaseAuction.sol#L442-L456`](https://github.com/code-423n4/2026-03-chainlink/blob/5317782e3855d9547412ab5a490257d7c5e51fac/src/BaseAuction.sol#L442-L456)

```solidity
uint256 assetOutAmount =
    _getAssetOutAmount(assetParams, assetPrice, amount, elapsedTime, true);

IERC20(asset).safeTransfer(msg.sender, amount);

address assetOut = s_assetOut;

if (data.length != 0) {
    IAuctionCallback(msg.sender).auctionCallback(
        msg.sender,
        assetOut,
        assetOutAmount,
        data
    );
}

IERC20(assetOut).safeTransferFrom(
    msg.sender,
    address(this),
    assetOutAmount
);
```

## Root Cause

The function provides no reservation or commitment mechanism for a pending bid. Its success depends on mutable shared inventory:

```text
success(bid_i) =
    requestedAmount_i <= balance(asset, BaseAuction)
```

An earlier successful bid changes that balance:

```text
balance_after =
    balance_before - filledAmount
```

Consequently, two individually valid transactions are not commutative:

```text
Exec(attackerBid ; victimBid)
    !=
Exec(victimBid ; attackerBid)
```

There is also no partial-fill option that could reduce the victim's requested amount to the inventory remaining at execution time.

## Preconditions

The behavior requires all of the following:

1. The auction for the asset is live.
2. The victim's transaction is visible before inclusion.
3. The remaining inventory is insufficient to fill both bids.
4. The attacker owns and has approved enough `assetOut` to pay for the bid.
5. The attacker obtains earlier execution through transaction ordering or a higher priority fee.

## Attack Scenario

1. A live auction contains `1000e18` units of `assetIn`.
2. The victim submits `bid(assetIn, 1000e18, "")`.
3. The attacker observes the pending transaction.
4. The attacker submits the same bid with earlier execution priority.
5. The attacker's transaction executes first.
6. The attacker receives all `1000e18` units of `assetIn`.
7. The auction's `assetIn` balance becomes zero.
8. The victim's transaction executes afterward.
9. The balance check observes `availableBalance == 0`.
10. The victim's transaction reverts with `BidAmountTooHigh(1000e18, 0)`.

## Proof of Concept

The complete Foundry PoC is published at:

[PoC — `HUODONGREN/front-run_0day#7`](https://github.com/HUODONGREN/front-run_0day/issues/7)

The PoC contains two tests:

```text
test_FrontRun_AttackerBuysAllBeforeVictim_OnFlattenedBaseAuction
test_NoFrontRun_VictimCanBidIfExecutedFirst_OnFlattenedBaseAuction
```

The first test executes the attacker before the victim and expects the victim's bid to revert.

The control test executes the victim first and confirms that the same bid succeeds when the transaction ordering is reversed.

## Reproduction Steps

Save the test code from Issue #7 as:

```text
test/BaseAuctionExactFrontRun.t.sol
```

Place the flattened target contract at:

```text
src/BaseAuction_flattened.sol
```

The import in the test should be:

```solidity
import "../src/BaseAuction_flattened.sol";
```

Install Foundry dependencies if they have not already been installed:

```bash
forge install foundry-rs/forge-std --no-commit
```

Compile the project:

```bash
forge clean
forge build
```

Run only the relevant PoC contract:

```bash
forge test \
  --match-contract BaseAuctionExactFrontRunTest \
  -vvvv
```

The expected result is that both tests pass:

```text
[PASS] test_FrontRun_AttackerBuysAllBeforeVictim_OnFlattenedBaseAuction()
[PASS] test_NoFrontRun_VictimCanBidIfExecutedFirst_OnFlattenedBaseAuction()
```

## PoC Result

The attack-order test demonstrates the following state transition:

```text
auction assetIn balance before attack:
1000000000000000000000

auction assetIn balance after attacker bid:
0

attacker assetIn after attacker bid:
1000000000000000000000

victim assetIn final balance:
0
```

The victim's later transaction reverts because the attacker consumed the complete auction inventory first.

The control test confirms that the victim receives the full inventory when the victim's transaction executes before the attacker's transaction.

## Impact

A competing bidder can cause a victim's pending bid to fail by purchasing the remaining auction inventory first. The victim may lose transaction gas, and any off-chain workflow that assumes successful execution may need to retry.

The PoC does not demonstrate theft of the victim's approved tokens because the reverting transaction rolls back all state changes.

It also does not demonstrate a sustained protocol-wide denial of service because the attacker must purchase the inventory and pay the calculated auction price. Once the inventory is legitimately purchased, the corresponding auction is effectively filled rather than permanently blocked.

## Design and Severity Considerations

The project documentation describes the system as a permissionless Dutch auction in which any participant may bid.

It also acknowledges that concurrent participants affect auction balances and may make full-quantity CowSwap orders stale or cause them to fail:

[README — publicly known concurrency behavior](https://github.com/code-423n4/2026-03-chainlink/blob/5317782e3855d9547412ab5a490257d7c5e51fac/README.md#L327-L338)

Accordingly, transaction-order-dependent inventory consumption is likely inherent to the intended auction model.

A High or Medium rating would require additional evidence that this behavior causes one of the following:

* sustained denial of auction participation;
* protocol or user fund loss beyond transaction gas;
* violation of an explicit reservation or guaranteed-fill property;
* economically profitable manipulation beyond ordinary auction participation;
* failure of a critical settlement process that cannot recover through retrying.

Without such evidence, Low/Informational is the most defensible classification.

## Recommendation

If strict first-come-first-served behavior is intended, document it explicitly and ensure that front ends refresh the available inventory immediately before transaction submission.

For improved bidder protection, consider supporting a fill-tolerant interface:

```solidity
function bid(
    address asset,
    uint256 desiredAmount,
    uint256 minFillAmount,
    uint256 maxAssetOutAmount,
    uint256 deadline,
    bytes calldata data
) external;
```

At execution time, the contract could fill up to the remaining inventory and revert only when:

```text
actualFill < minFillAmount
```

or:

```text
requiredAssetOut > maxAssetOutAmount
```

This would allow bidders to specify how much inventory reduction they are willing to tolerate.

If transaction fairness or temporary inventory reservation is a protocol requirement, stronger alternatives include:

* signed, short-lived auction quotes;
* batch auction settlement;
* temporary order reservation;
* commit-reveal bidding;
* private transaction submission.

## References

* [Target repository](https://github.com/code-423n4/2026-03-chainlink)
* [Affected contract](https://github.com/code-423n4/2026-03-chainlink/blob/5317782e3855d9547412ab5a490257d7c5e51fac/src/BaseAuction.sol)
* [Fixed source commit](https://github.com/code-423n4/2026-03-chainlink/commit/5317782e3855d9547412ab5a490257d7c5e51fac)
* [Proof of Concept — Issue #7](https://github.com/HUODONGREN/front-run_0day/issues/7)
