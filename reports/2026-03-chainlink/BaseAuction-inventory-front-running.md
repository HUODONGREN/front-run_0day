# Public `bid()` can be front-run to consume auction inventory and revert later bids

## Finding Metadata

| Field              | Value                                                                                                  |
| ------------------ | ------------------------------------------------------------------------------------------------------ |
| Target project     | [Chainlink Payment Abstraction V2](https://github.com/code-423n4/2026-03-chainlink)                    |
| Affected contract  | [`src/BaseAuction.sol`](https://github.com/code-423n4/2026-03-chainlink/blob/main/src/BaseAuction.sol) |
| Vulnerability type | Front-running / auction-inventory preemption                                                           |
| Severity           | Low-Medium / Medium                                                                                    |
| Proof of concept   | [HUODONGREN/front-run_0day Issue #7](https://github.com/HUODONGREN/front-run_0day/issues/7)            |

## Summary

`BaseAuction` exposes a public `bid()` function that allows any participant to purchase assets from a live auction.

A bid succeeds only when the requested amount does not exceed the auction contract's remaining token balance at execution time. Because pending bids do not reserve inventory, an attacker can observe another user's pending bid and submit an earlier transaction that purchases all or part of the same inventory.

If the attacker's transaction executes first, the victim's later bid observes a reduced balance and reverts with `BidAmountTooHigh`.

## Vulnerable Code

The function checks the requested amount against the auction contract's current token balance:

[`BaseAuction.sol#L437-L440`](https://github.com/code-423n4/2026-03-chainlink/blob/main/src/BaseAuction.sol#L437-L440)

```solidity
uint256 availableBalance = IERC20(asset).balanceOf(address(this));

if (amount > availableBalance) {
    revert BidAmountTooHigh(amount, availableBalance);
}
```

After the check, the requested auctioned asset is transferred to the currently executing bidder:

[`BaseAuction.sol#L442-L456`](https://github.com/code-423n4/2026-03-chainlink/blob/main/src/BaseAuction.sol#L442-L456)

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

`bid()` uses mutable execution-time inventory without reserving assets for pending transactions.

A bid is valid when:

```text
requestedAmount <= auction token balance
```

An earlier successful bid changes that balance:

```text
balanceAfter = balanceBefore - earlierBidAmount
```

Therefore, the result depends on transaction ordering:

```text
Victim bid → Attacker bid
    = victim succeeds

Attacker bid → Victim bid
    = victim may revert
```

There is no reservation, commitment, minimum-fill protection, or partial-fill handling for pending bids.

## Attack Steps

1. A live auction contains `1000e18` units of `assetIn`.
2. The victim submits:

```solidity
bid(assetIn, 1000e18, "");
```

3. The attacker observes the pending transaction in the public mempool.
4. The attacker submits the same bid with a higher execution priority.
5. The attacker's transaction executes first.
6. The attacker pays the required `assetOut`.
7. The auction transfers all `1000e18` units of `assetIn` to the attacker.
8. The auction's remaining `assetIn` balance becomes zero.
9. The victim's transaction executes afterward.
10. The balance check reads `availableBalance == 0`.
11. The victim's bid reverts with:

```text
BidAmountTooHigh(
    1000e18,
    0
)
```

## Proof of Concept

The complete Foundry PoC is available at:

[PoC — `HUODONGREN/front-run_0day#7`](https://github.com/HUODONGREN/front-run_0day/issues/7)

The PoC contains the following tests:

```text
test_FrontRun_AttackerBuysAllBeforeVictim_OnFlattenedBaseAuction
test_NoFrontRun_VictimCanBidIfExecutedFirst_OnFlattenedBaseAuction
```

The first test executes the attacker's bid before the victim's bid and confirms that the victim's transaction reverts because the auction inventory has already been consumed.

The second test executes the victim first and confirms that the same bid succeeds when sufficient inventory remains.

## Reproduction Steps

Create a Foundry project:

```bash
mkdir base-auction-front-run-poc
cd base-auction-front-run-poc

forge init --force
```

Install `forge-std`:

```bash
forge install foundry-rs/forge-std
```

Place the flattened contract at:

```text
src/BaseAuction_flattened.sol
```

Save the PoC from Issue #7 as:

```text
test/BaseAuctionExactFrontRun.t.sol
```

The test import should be:

```solidity
import "../src/BaseAuction_flattened.sol";
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
  --match-contract BaseAuctionExactFrontRunTest \
  -vvvv
```

Expected result:

```text
[PASS] test_FrontRun_AttackerBuysAllBeforeVictim_OnFlattenedBaseAuction()
[PASS] test_NoFrontRun_VictimCanBidIfExecutedFirst_OnFlattenedBaseAuction()
```

## PoC Result

Before the attacker's bid:

```text
auction assetIn balance:
1000000000000000000000
```

After the attacker's bid executes:

```text
auction assetIn balance:
0

attacker assetIn balance:
1000000000000000000000
```

The victim's later bid reverts because the requested amount exceeds the remaining auction balance.

The control test confirms that the victim receives the auctioned assets when the victim's transaction executes first.

## Impact

An attacker or competing bidder can invalidate a pending bid by consuming the shared auction inventory first.

This can cause:

* valid user bids to revert;
* users to waste transaction gas;
* auction-dependent workflows to fail;
* repeated transaction resubmission;
* temporary denial of access to the remaining inventory.

The attacker must still pay the required auction price and does not directly steal funds from the victim. The primary impact is bid invalidation and execution failure.

## Severity

**Low-Medium / Medium**

The issue can reliably cause a pending bid to fail when two participants compete for insufficient inventory.

The final severity depends on whether successful execution of submitted bids is expected and whether repeated front-running can materially disrupt auction participation.

If the auction is explicitly intended to operate on a first-come-first-served basis, the issue may be treated as an informational or design limitation.

## Recommendation

Add bidder-side execution protection.

Possible mitigations include:

1. Support partial fills when the requested amount exceeds the remaining inventory.
2. Add a `minFillAmount` parameter.
3. Add a `maxAssetOutAmount` parameter to limit acceptable payment.
4. Add a transaction deadline.
5. Use reservation or commitment logic if full execution must be guaranteed.
6. Use commit-reveal or batch-auction settlement when transaction-order fairness is required.
7. Clearly document that pending bids do not reserve inventory.

A possible interface is:

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

The function could fill the smaller of the desired amount and the remaining inventory, while reverting only when the actual fill is below `minFillAmount`.

## References

* [Chainlink Payment Abstraction V2 repository](https://github.com/code-423n4/2026-03-chainlink)
* [`BaseAuction.sol`](https://github.com/code-423n4/2026-03-chainlink/blob/main/src/BaseAuction.sol)
* [Auction inventory check](https://github.com/code-423n4/2026-03-chainlink/blob/main/src/BaseAuction.sol#L437-L440)
* [Auctioned-asset transfer and payment](https://github.com/code-423n4/2026-03-chainlink/blob/main/src/BaseAuction.sol#L442-L456)
* [Foundry PoC — Issue #7](https://github.com/HUODONGREN/front-run_0day/issues/7)
