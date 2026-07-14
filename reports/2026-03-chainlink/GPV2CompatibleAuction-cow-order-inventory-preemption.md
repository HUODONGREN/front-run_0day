# Public `bid()` can front-run CoW orders and invalidate settlement by consuming inventory

## Finding Metadata

| Field              | Value                                                                                                                      |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------- |
| Target project     | [Chainlink Payment Abstraction V2](https://github.com/code-423n4/2026-03-chainlink)                                        |
| Affected contract  | [`src/GPV2CompatibleAuction.sol`](https://github.com/code-423n4/2026-03-chainlink/blob/5317782e3855d9547412ab5a490257d7c5e51fac/src/GPV2CompatibleAuction.sol) |
| Related contract   | [`src/BaseAuction.sol`](https://github.com/code-423n4/2026-03-chainlink/blob/5317782e3855d9547412ab5a490257d7c5e51fac/src/BaseAuction.sol)                     |
| Vulnerability type | Front-running / shared-inventory preemption                                                                                |
| Severity           | Low-Medium / Medium                                                                                                        |
| Proof of concept   | [HUODONGREN/front-run_0day Issue #8](https://github.com/HUODONGREN/front-run_0day/issues/8)                                |

## Summary

`GPV2CompatibleAuction` supports CoW Protocol settlements through EIP-1271 order validation while inheriting the public `bid()` function from `BaseAuction`.

Both CoW orders and direct bidders use the same auctioned-token inventory held by the contract. A CoW order is valid only when the auction contract still holds enough `sellToken` to cover the order's `sellAmount`.

An attacker can observe a pending CoW settlement and front-run it by directly calling `bid()` first. If the attacker consumes all or enough of the shared inventory, the previously valid CoW order becomes invalid. When the settlement later calls `isValidSignature()`, validation reverts with `InsufficientAssetInBalance`.

## Vulnerable Code

`isValidSignature()` checks the CoW order against the contract's current token balance:

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

At the same time, `GPV2CompatibleAuction` inherits the public `bid()` function from `BaseAuction`.

The direct bid checks the same live inventory:

[`BaseAuction.sol#L437-L440`](https://github.com/code-423n4/2026-03-chainlink/blob/5317782e3855d9547412ab5a490257d7c5e51fac/src/BaseAuction.sol#L437-L440)

```solidity
uint256 availableBalance = IERC20(asset).balanceOf(address(this));

if (amount > availableBalance) {
    revert BidAmountTooHigh(amount, availableBalance);
}
```

After the check, the auctioned asset is transferred to the direct bidder:

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

CoW orders and direct bids share the same mutable auction inventory.

A CoW order is considered valid when:

```text
order.sellAmount <= auction token balance
```

However, an earlier direct bid reduces the same balance:

```text
balanceAfter = balanceBefore - directBidAmount
```

Therefore, the result depends on transaction ordering:

```text
CoW validation → Direct bid
    = order is valid

Direct bid → CoW validation
    = order may revert
```

There is no inventory reservation or isolation between pending CoW orders and public direct bids.

## Attack Steps

1. `GPV2CompatibleAuction` holds `1000e18` units of `assetIn`.
2. A CoW order is created with `sellAmount = 1000e18`.
3. The order is initially valid because the contract holds enough inventory.
4. A CoW solver submits a settlement transaction.
5. The attacker observes the pending settlement in the public mempool.
6. The attacker submits:

```solidity
bid(assetIn, 1000e18, "");
```

7. The attacker's transaction executes first.
8. The attacker pays the required `assetOut`.
9. The auction transfers all `1000e18` units of `assetIn` to the attacker.
10. The auction's remaining `assetIn` balance becomes zero.
11. The CoW settlement executes afterward.
12. `isValidSignature()` checks the unchanged order against the new balance.
13. Validation reverts with:

```text
InsufficientAssetInBalance(
    assetIn,
    1000e18,
    0
)
```

## Proof of Concept

The complete Foundry PoC is available at:

[PoC — `HUODONGREN/front-run_0day#8`](https://github.com/HUODONGREN/front-run_0day/issues/8)

The PoC contains the following tests:

```text
test_FrontRun_DirectBidInvalidatesCowOrder_OnFlattenedGPV2Auction
test_NoFrontRun_CowOrderIsValidIfInventoryStillAvailable_OnFlattenedGPV2Auction
```

The first test confirms that:

1. The CoW order is valid before the attack.
2. `isValidSignature()` returns the EIP-1271 magic value.
3. The attacker consumes all inventory through `bid()`.
4. Validation of the same CoW order subsequently reverts.

The second test confirms that the CoW order remains valid when no direct bidder consumes the inventory.

## Reproduction Steps

Create a Foundry project:

```bash
mkdir gpv2-compatible-auction-poc
cd gpv2-compatible-auction-poc

forge init --force
```

Install `forge-std`:

```bash
forge install foundry-rs/forge-std
```

Place the flattened contract at:

```text
src/GPV2CompatibleAuction_flattened.sol
```

Save the PoC from Issue #8 as:

```text
test/GPV2CompatibleAuctionExactFrontRun.t.sol
```

The test import should be:

```solidity
import "../src/GPV2CompatibleAuction_flattened.sol";
```

Configure `foundry.toml`:

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

Compile and run the tests:

```bash
forge clean
forge build

forge test \
  --match-contract GPV2CompatibleAuctionExactFrontRunTest \
  -vvvv
```

Expected result:

```text
[PASS] test_FrontRun_DirectBidInvalidatesCowOrder_OnFlattenedGPV2Auction()
[PASS] test_NoFrontRun_CowOrderIsValidIfInventoryStillAvailable_OnFlattenedGPV2Auction()
```

## PoC Result

Before the attacker executes the direct bid:

```text
auction assetIn balance:
1000000000000000000000

CoW order sellAmount:
1000000000000000000000
```

The order validation succeeds and returns the EIP-1271 magic value.

After the attacker's direct bid:

```text
auction assetIn balance:
0

attacker assetIn balance:
1000000000000000000000
```

Validation of the same CoW order then reverts with:

```text
InsufficientAssetInBalance(
    assetIn,
    1000000000000000000000,
    0
)
```

This confirms that the same CoW order changes from valid to invalid solely because the direct bid executes first.

## Impact

An attacker or competing bidder can invalidate a pending CoW settlement by consuming the shared auction inventory first.

This can cause:

* CoW settlement transactions to fail;
* solver gas to be wasted;
* valid orders to become stale before execution;
* auction settlement to be delayed;
* off-chain workflows to recreate and resubmit orders.

The attacker must still pay the required auction price and does not directly steal funds from the solver. The primary impact is settlement disruption and transaction failure.

## Severity

**Low-Medium / Medium**

The vulnerability can reliably invalidate a pending CoW settlement and waste solver resources.

The final severity depends on whether reliable CoW settlement is a core protocol requirement and whether repeated invalidation can materially disrupt auction execution.

The project documentation also acknowledges that independent bidders may make CoW order quantities stale. Therefore, the finding may be treated as an informational or known limitation in the corresponding audit context.

## Recommendation

Separate or coordinate the inventory used by CoW orders and direct bidders.

Possible mitigations include:

1. Refresh the CoW order quantity immediately after each successful direct bid.
2. Use shorter CoW order-validity periods.
3. Publish conservative order amounts instead of the complete inventory.
4. Allow partially fillable orders to settle against the remaining balance.
5. Add an inventory version or nonce so stale orders can be detected.
6. Reserve inventory for pending CoW orders if full settlement must be guaranteed.
7. Document clearly that direct bids can invalidate pending CoW settlements.

## References

* [Chainlink Payment Abstraction V2 repository](https://github.com/code-423n4/2026-03-chainlink)
* [`GPV2CompatibleAuction.sol`](https://github.com/code-423n4/2026-03-chainlink/blob/5317782e3855d9547412ab5a490257d7c5e51fac/src/GPV2CompatibleAuction.sol)
* [`BaseAuction.sol`](https://github.com/code-423n4/2026-03-chainlink/blob/5317782e3855d9547412ab5a490257d7c5e51fac/src/BaseAuction.sol)
* [CoW order balance validation](https://github.com/code-423n4/2026-03-chainlink/blob/5317782e3855d9547412ab5a490257d7c5e51fac/src/GPV2CompatibleAuction.sol#L141-L151)
* [Direct bid inventory check](https://github.com/code-423n4/2026-03-chainlink/blob/5317782e3855d9547412ab5a490257d7c5e51fac/src/BaseAuction.sol#L437-L440)
* [Direct bid asset transfer](https://github.com/code-423n4/2026-03-chainlink/blob/5317782e3855d9547412ab5a490257d7c5e51fac/src/BaseAuction.sol#L442-L456)
* [Foundry PoC — Issue #8](https://github.com/HUODONGREN/front-run_0day/issues/8)
