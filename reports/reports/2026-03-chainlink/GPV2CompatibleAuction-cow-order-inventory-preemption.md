# Public `bid()` can front-run CoW orders and invalidate settlement by consuming inventory

## Finding Metadata

| Field                      | Value                                                                                                                                                          |
| -------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Target project             | [Chainlink Payment Abstraction V2](https://github.com/code-423n4/2026-03-chainlink)                                                                            |
| Affected contract          | [`src/GPV2CompatibleAuction.sol`](https://github.com/code-423n4/2026-03-chainlink/blob/5317782e3855d9547412ab5a490257d7c5e51fac/src/GPV2CompatibleAuction.sol) |
| Related inherited function | [`BaseAuction.bid()`](https://github.com/code-423n4/2026-03-chainlink/blob/5317782e3855d9547412ab5a490257d7c5e51fac/src/BaseAuction.sol#L405-L456)             |
| Fixed source revision      | [`5317782e3855d9547412ab5a490257d7c5e51fac`](https://github.com/code-423n4/2026-03-chainlink/commit/5317782e3855d9547412ab5a490257d7c5e51fac)                  |
| Vulnerability class        | Transaction-ordering dependence / shared-inventory preemption                                                                                                  |
| Suggested severity         | Informational / Known limitation                                                                                                                               |
| Proof of concept           | [HUODONGREN/front-run_0day Issue #8](https://github.com/HUODONGREN/front-run_0day/issues/8)                                                                    |

## Summary

`GPV2CompatibleAuction` supports CoW Protocol settlement through EIP-1271 order validation while inheriting the public and permissionless `bid()` function from `BaseAuction`. Both execution paths use the same auctioned-token inventory held by the auction contract.

A CoW order is considered valid only when its complete `sellAmount` does not exceed the auction contract's current token balance. An attacker can observe a pending CoW settlement and submit a direct `bid()` transaction with earlier execution priority. If the direct bid consumes all or enough of the shared inventory, the previously valid CoW order becomes invalid and the later call to `isValidSignature()` reverts with `InsufficientAssetInBalance`.

The ordering dependency is reproducible, but the direct bidder must pay the required auction price and does not directly steal funds from the solver or order creator. The project documentation also explicitly acknowledges that independent bidders may make CoW order quantities stale and cause full-fill solver attempts to fail.

It should therefore be treated as an Informational known limitation unless a stronger impact—such as sustained denial of settlement, unrecoverable protocol disruption, or direct loss of funds—is demonstrated.

## Vulnerable Code

The CoW order is validated against the auction contract's live token balance:

[`GPV2CompatibleAuction.sol#L141-L151`](https://github.com/code-423n4/2026-03-chainlink/blob/5317782e3855d9547412ab5a490257d7c5e51fac/src/GPV2CompatibleAuction.sol#L141-L151)

```solidity
if (order.sellAmount == 0) {
    revert Errors.InvalidZeroAmount();
}

uint256 assetInBalance = order.sellToken.balanceOf(address(this));

if (order.sellAmount > assetInBalance) {
    revert InsufficientAssetInBalance(
        address(order.sellToken),
        order.sellAmount,
        assetInBalance
    );
}
```

The contract requires the CoW order to be partially fillable:

[`GPV2CompatibleAuction.sol#L173-L175`](https://github.com/code-423n4/2026-03-chainlink/blob/5317782e3855d9547412ab5a490257d7c5e51fac/src/GPV2CompatibleAuction.sol#L173-L175)

```solidity
if (!order.partiallyFillable) {
    revert OrderNotPartiallyFillable();
}
```

However, `isValidSignature()` still compares the order's original complete `sellAmount` with the current inventory balance. A partially fillable order may therefore fail validation before the solver can settle a smaller remaining amount.

At the same time, the inherited `bid()` function allows any participant to consume the same inventory:

[`BaseAuction.sol#L405-L413`](https://github.com/code-423n4/2026-03-chainlink/blob/5317782e3855d9547412ab5a490257d7c5e51fac/src/BaseAuction.sol#L405-L413)

```solidity
function bid(
    address asset,
    uint256 amount,
    bytes calldata data
) external whenNotPaused {
```

The direct bid reads the live balance and transfers the requested auctioned asset to the currently executing bidder:

[`BaseAuction.sol#L437-L456`](https://github.com/code-423n4/2026-03-chainlink/blob/5317782e3855d9547412ab5a490257d7c5e51fac/src/BaseAuction.sol#L437-L456)

```solidity
uint256 availableBalance = IERC20(asset).balanceOf(address(this));

if (amount > availableBalance) {
    revert BidAmountTooHigh(amount, availableBalance);
}

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

The CoW-order settlement path and the direct-bidding path use the same mutable inventory without reservation, isolation, or synchronization.

The validity of a CoW order depends on:

```text
valid(order_i) =
    order_i.sellAmount <= balance(order_i.sellToken, auction)
```

An earlier successful direct bid changes the same balance:

```text
balance_after =
    balance_before - directBidAmount
```

Consequently, validating the same CoW order before and after a direct bid can produce different results:

```text
Validate(cowOrder) ; DirectBid
    !=
DirectBid ; Validate(cowOrder)
```

More specifically:

```text
Validate(cowOrder) before DirectBid
    -> returns EIP-1271 magic value
```

while:

```text
DirectBid before Validate(cowOrder)
    -> reverts with InsufficientAssetInBalance
```

There is no on-chain reservation binding a published CoW order to the inventory that existed when the order was created.

There is also no inventory version, order-specific balance allocation, or automatic order-quantity update when an independent bidder consumes the auctioned asset.

## Preconditions

The behavior requires all of the following:

1. An auction for the relevant `sellToken` is live.
2. `GPV2CompatibleAuction` holds sufficient inventory for the original CoW order.
3. A CoW order has been created using some or all of that inventory.
4. The order's settlement transaction is visible before inclusion.
5. The attacker owns and has approved enough `assetOut` to pay for a direct bid.
6. The direct bid and the CoW order compete for the same auctioned asset.
7. The remaining inventory is insufficient to satisfy both transactions.
8. The attacker obtains earlier execution through transaction ordering or a higher priority fee.

## Attack Scenario

1. A live `GPV2CompatibleAuction` contains `1000e18` units of `assetIn`.
2. A CoW order is created with `sellAmount = 1000e18`.
3. The order is initially valid because the auction balance equals its `sellAmount`.
4. A CoW solver prepares and broadcasts a settlement using the order.
5. The attacker observes the pending settlement transaction.
6. The attacker submits `bid(assetIn, 1000e18, "")` with earlier execution priority.
7. The attacker's direct bid executes first.
8. The attacker pays the required `assetOut` amount.
9. The auction transfers all `1000e18` units of `assetIn` to the attacker.
10. The auction's remaining `assetIn` balance becomes zero.
11. The CoW settlement executes afterward.
12. `isValidSignature()` reads `assetInBalance == 0`.
13. The unchanged CoW order still has `sellAmount == 1000e18`.
14. Validation reverts with:

```text
InsufficientAssetInBalance(
    assetIn,
    1000e18,
    0
)
```

## Proof of Concept

The complete Foundry PoC is published at:

[PoC — HUODONGREN/front-run_0day#8](https://github.com/HUODONGREN/front-run_0day/issues/8)

The PoC contains two tests:

```text
test_FrontRun_DirectBidInvalidatesCowOrder_OnFlattenedGPV2Auction
test_NoFrontRun_CowOrderIsValidIfInventoryStillAvailable_OnFlattenedGPV2Auction
```

The first test initially validates the CoW order and confirms that `isValidSignature()` returns the EIP-1271 magic value.

The attacker then executes the inherited direct `bid()` function and consumes all of the auction inventory.

The test validates the same CoW order again and expects the call to revert with `InsufficientAssetInBalance`.

The control test does not execute the attacker's direct bid and confirms that the same CoW order remains valid while sufficient inventory is still available.

## Reproduction Steps

Save the test code from Issue #8 as:

```text
test/GPV2CompatibleAuctionExactFrontRun.t.sol
```

Place the flattened target contract at:

```text
src/GPV2CompatibleAuction_flattened.sol
```

The import in the test should be:

```solidity
import "../src/GPV2CompatibleAuction_flattened.sol";
```

Install Foundry dependencies if they have not already been installed:

```bash
forge install foundry-rs/forge-std --no-commit
```

For Foundry versions that no longer support `--no-commit`, use:

```bash
forge install foundry-rs/forge-std
```

Configure the project in `foundry.toml`:

```toml
[profile.default]
src = "src"
test = "test"
libs = ["lib"]

solc_version = "0.8.26"
optimizer = true
optimizer_runs = 200
via_ir = true
```

Compile the project:

```bash
forge clean
forge build
```

Run only the relevant PoC contract:

```bash
forge test \
  --match-contract GPV2CompatibleAuctionExactFrontRunTest \
  -vvvv
```

The expected result is that both tests pass:

```text
[PASS] test_FrontRun_DirectBidInvalidatesCowOrder_OnFlattenedGPV2Auction()
[PASS] test_NoFrontRun_CowOrderIsValidIfInventoryStillAvailable_OnFlattenedGPV2Auction()
```

The attack test can also be run independently:

```bash
forge test \
  --match-test test_FrontRun_DirectBidInvalidatesCowOrder_OnFlattenedGPV2Auction \
  -vvvv
```

The control test can be run independently:

```bash
forge test \
  --match-test test_NoFrontRun_CowOrderIsValidIfInventoryStillAvailable_OnFlattenedGPV2Auction \
  -vvvv
```

## PoC Result

Before the attacker's direct bid, the test confirms the following state:

```text
auction assetIn before attack:
1000000000000000000000

order sellAmount:
1000000000000000000000
```

The initial validation succeeds:

```text
isValidSignature(orderHash, order)
    == IERC1271.isValidSignature.selector
```

After the attacker executes the direct bid, the state becomes:

```text
auction assetIn after attacker bid:
0

attacker assetIn after attacker bid:
1000000000000000000000
```

The later validation of the same order reverts with:

```text
InsufficientAssetInBalance(
    assetIn,
    1000000000000000000000,
    0
)
```

The attack-order test therefore demonstrates that a direct bidder can consume the inventory backing a previously valid CoW order.

The control test confirms that the same order continues to return the EIP-1271 magic value when the auction inventory remains available.

## Impact

A direct bidder can cause a previously valid CoW order to fail by purchasing the shared auction inventory before the solver's settlement transaction executes.

Potential consequences include:

* failed CoW settlement transactions;
* wasted solver gas;
* stale order quantities on the CoW orderbook;
* delayed auction settlement;
* additional retries by off-chain automation;
* temporary disruption of the auction workflow.

The PoC does not demonstrate theft of the solver's or order creator's funds.

The attacker does not receive auctioned assets for free. The attacker must pay the auction price calculated by the protocol and must hold sufficient `assetOut` balance and allowance.

The PoC also does not demonstrate a sustained protocol-wide denial of service. Once the direct bidder purchases the inventory, the auction has been legitimately filled rather than permanently blocked.

The off-chain workflow may update or replace the stale CoW order after observing the changed balance.

## Design and Severity Considerations

The project documentation describes the system as a permissionless Dutch auction in which independent bidders and CoW solvers may participate concurrently.

It explicitly acknowledges that independent bidders affect the auctioned-token balance and may make the amount exposed through a CoW order stale:

[README — publicly known concurrency behavior](https://github.com/code-423n4/2026-03-chainlink/blob/5317782e3855d9547412ab5a490257d7c5e51fac/README.md#L327-L338)

The documented behavior includes the possibility that a solver attempting to fill the complete CoW order may fail after another participant consumes part of the inventory.

Accordingly, the transaction-order-dependent invalidation reproduced by the PoC appears to be inherent to the intended permissionless auction model and is already known to the project.

A High or Medium rating would require additional evidence that the behavior causes one of the following:

* sustained denial of CoW settlement;
* permanent blocking of auction participation;
* protocol or user fund loss beyond transaction gas;
* free or underpriced acquisition of auctioned assets;
* bypass of the intended auction price;
* violation of an explicit inventory-reservation guarantee;
* failure of a critical workflow that cannot recover by updating or replacing the order;
* economically profitable manipulation beyond ordinary auction participation.

Without such evidence, Informational / Known limitation is the most defensible classification.

In the context of the corresponding Code4rena audit, the report may also be considered an explicitly disclosed or known issue.

## Recommendation

If the shared first-come-first-served inventory model is intended, document clearly that CoW order quantities are not reserved and may become stale after a direct bid.

The off-chain workflow should listen for successful direct-bid events and update the CoW order immediately after the inventory changes.

For example, after observing an `AuctionBidSettled` event, the workflow should recompute:

```text
newSellAmount =
    IERC20(assetIn).balanceOf(address(auction))
```

Additional improvements may include:

* using shorter CoW order-validity windows;
* refreshing the contract balance immediately before settlement submission;
* publishing conservative order quantities instead of the complete inventory;
* invalidating superseded orders as soon as the inventory changes;
* ensuring solvers use partial fills whenever the remaining inventory allows them;
* adding an inventory version or nonce to identify stale off-chain orders.

The validation logic could also be reconsidered for partially fillable orders. Rather than always requiring:

```text
order.sellAmount <= currentInventory
```

the integration could allow execution against the remaining inventory when:

```text
remainingInventory > 0
```

and when the partial fill continues to satisfy the auction's price and minimum-size requirements.

If the protocol requires a strict guarantee that a published CoW order remains fully executable, stronger inventory reservation would be required:

```text
availableForDirectBids =
    totalInventory - reservedForCowOrders
```

Direct bids would only consume the unreserved balance, while CoW settlement would use the reserved balance.

However, reservation would reduce the flexibility of the intended permissionless auction and should only be introduced if guaranteed CoW settlement is a protocol requirement.

## References

* [Target repository](https://github.com/code-423n4/2026-03-chainlink)
* [Affected contract](https://github.com/code-423n4/2026-03-chainlink/blob/5317782e3855d9547412ab5a490257d7c5e51fac/src/GPV2CompatibleAuction.sol)
* [Inherited `BaseAuction.bid()` implementation](https://github.com/code-423n4/2026-03-chainlink/blob/5317782e3855d9547412ab5a490257d7c5e51fac/src/BaseAuction.sol#L405-L456)
* [Fixed source commit](https://github.com/code-423n4/2026-03-chainlink/commit/5317782e3855d9547412ab5a490257d7c5e51fac)
* [Project disclosure of concurrent order staleness](https://github.com/code-423n4/2026-03-chainlink/blob/5317782e3855d9547412ab5a490257d7c5e51fac/README.md#L327-L338)
* [Proof of Concept — Issue #8](https://github.com/HUODONGREN/front-run_0day/issues/8)
