# Pending yield between `settle()` and `distributeYield()` allows late stakers to snipe rewards

## Finding Metadata

| Field              | Value                                                                                                               |
| ------------------ | ------------------------------------------------------------------------------------------------------------------- |
| Target project     | [Monetrix](https://github.com/code-423n4/2026-04-monetrix)                                                          |
| Affected contract  | [`src/core/MonetrixVault.sol`](https://github.com/code-423n4/2026-04-monetrix/blob/3d94be1361ca01d959f9165a78f0d75c5657fe3e/src/core/MonetrixVault.sol) |
| Related contract   | [`src/tokens/sUSDM.sol`](https://github.com/code-423n4/2026-04-monetrix/blob/3d94be1361ca01d959f9165a78f0d75c5657fe3e/src/tokens/sUSDM.sol)             |
| Vulnerability type | Front-running / yield sniping                                                                                       |
| Severity           | Medium                                                                                                              |
| Proof of concept   | [HUODONGREN/front-run_0day Issue #9](https://github.com/HUODONGREN/front-run_0day/issues/9)                         |

## Summary

`MonetrixVault` separates yield realization from yield distribution.

When the operator calls `settle()`, realized USDC yield is transferred into `yieldEscrow`. However, this pending yield is not reflected in `sUSDM.totalAssets()` and therefore does not increase the sUSDM share price.

The yield is only reflected later when the operator calls `distributeYield()`, which pulls the pending yield, mints USDM, and calls `sUSDM.injectYield()`.

An attacker can deposit into sUSDM after `settle()` but before `distributeYield()`. Because shares are minted using the stale pre-yield exchange rate, the attacker receives shares without contributing to the historical yield. When the pending yield is distributed, the attacker receives a proportional share of yield generated before they became a staker.

## Vulnerable Code

`settle()` transfers realized yield into `yieldEscrow` without updating the sUSDM share price:

[`MonetrixVault.sol#L373-L382`](https://github.com/code-423n4/2026-04-monetrix/blob/3d94be1361ca01d959f9165a78f0d75c5657fe3e/src/core/MonetrixVault.sol#L373-L382)

```solidity
function settle(uint256 proposedYield)
    external
    onlyOperator
    requireWired
    nonReentrant
    whenNotPaused
    whenOperatorNotPaused
{
    require(proposedYield > 0, "zero yield");

    uint256 vaultBal = usdc.balanceOf(address(this));
    uint256 shortfall_ = IRedeemEscrow(redeemEscrow).shortfall();
    uint256 available = vaultBal > shortfall_
        ? vaultBal - shortfall_
        : 0;

    require(
        available >= proposedYield,
        "insufficient EVM USDC"
    );

    IMonetrixAccountant(accountant).settleDailyPnL(
        proposedYield
    );

    usdc.safeTransfer(yieldEscrow, proposedYield);

    emit YieldCollected(proposedYield);
}
```

The pending yield is only injected into sUSDM later through `distributeYield()`:

[`MonetrixVault.sol#L384-L408`](https://github.com/code-423n4/2026-04-monetrix/blob/3d94be1361ca01d959f9165a78f0d75c5657fe3e/src/core/MonetrixVault.sol#L384-L408)

```solidity
function distributeYield()
    external
    nonReentrant
    onlyOperator
    requireWired
    whenNotPaused
    whenOperatorNotPaused
{
    uint256 totalYield =
        IYieldEscrow(yieldEscrow).balance();

    require(totalYield > 0, "no yield");

    IYieldEscrow(yieldEscrow).pullForDistribution(
        totalYield
    );

    uint256 userShare =
        (totalYield * config.userYieldBps()) / 10000;

    if (userShare > 0) {
        usdm.mint(address(this), userShare);

        IERC20(address(usdm)).forceApprove(
            address(susdm),
            userShare
        );

        susdm.injectYield(userShare);
    }
}
```

`sUSDM.totalAssets()` only counts USDM already held by the sUSDM contract:

[`sUSDM.sol#L105-L107`](https://github.com/code-423n4/2026-04-monetrix/blob/3d94be1361ca01d959f9165a78f0d75c5657fe3e/src/tokens/sUSDM.sol#L105-L107)

```solidity
function totalAssets()
    public
    view
    override
    returns (uint256)
{
    return IERC20(asset()).balanceOf(address(this));
}
```

Therefore, USDC held in `yieldEscrow` is excluded from the exchange rate used to mint new sUSDM shares.

## Root Cause

Pending settled yield is not checkpointed into the sUSDM share price before new deposits are accepted.

After `settle()`:

```text
yieldEscrow balance > 0
```

but:

```text
sUSDM.totalAssets()
    = only USDM currently held by sUSDM
```

A new depositor therefore receives shares at the stale exchange rate:

```text
shares minted =
    deposit amount / pre-distribution share price
```

When `distributeYield()` later injects the historical yield, both existing and newly minted shares receive a proportional portion.

The result depends on transaction ordering:

```text
distributeYield() → attacker deposit
    = historical yield belongs to existing stakers

attacker deposit → distributeYield()
    = attacker receives part of historical yield
```

## Attack Steps

1. An existing staker deposits `1000e6` USDM into sUSDM.
2. The protocol realizes `700e6` USDC of yield.
3. The operator calls:

```solidity
vault.settle(700e6);
```

4. The `700e6` USDC is transferred into `yieldEscrow`.
5. `sUSDM.totalAssets()` remains `1000e6` because the pending yield has not been injected.
6. The attacker observes the settled-yield state or a pending `distributeYield()` transaction.
7. The attacker deposits `1000e6` USDC through `MonetrixVault` and receives `1000e6` USDM.
8. The attacker deposits the USDM into sUSDM before yield distribution.
9. The attacker receives shares at the stale pre-yield exchange rate.
10. The operator calls:

```solidity
vault.distributeYield();
```

11. The historical `700e6` yield is injected into sUSDM.
12. The attacker receives approximately half of the pending yield despite joining after it was realized.
13. The existing staker's reward is diluted.

## Proof of Concept

The complete Foundry PoC is available at:

[PoC — `HUODONGREN/front-run_0day#9`](https://github.com/HUODONGREN/front-run_0day/issues/9)

The PoC contains the following tests:

```text
test_FrontRun_LateStakerSnipesPendingYield_OnFlattenedMonetrixVault

test_NoFrontRun_OldStakerReceivesFullYieldIfNoLateDeposit_OnFlattenedMonetrixVault
```

The first test deposits the attacker's funds after `settle()` but before `distributeYield()` and confirms that the attacker captures part of the historical yield.

The second test distributes the yield without a late deposit and confirms that the original staker receives the full yield.

## Reproduction Steps

Create a Foundry project:

```bash
mkdir monetrix-vault-front-run-poc
cd monetrix-vault-front-run-poc

forge init --force
```

Install `forge-std`:

```bash
forge install foundry-rs/forge-std
```

Remove the default Foundry files:

```bash
rm -f src/Counter.sol
rm -f test/Counter.t.sol
rm -f script/Counter.s.sol
```

Place the flattened target contract at:

```text
src/MonetrixVault_flattened.sol
```

Save the PoC code from Issue #9 as:

```text
test/MonetrixVaultExactFrontRun.t.sol
```

The import in the test should be:

```solidity
import "../src/MonetrixVault_flattened.sol";
```

Configure `foundry.toml`:

```toml
[profile.default]
src = "src"
test = "test"
libs = ["lib"]

solc_version = "0.8.27"
optimizer = true
optimizer_runs = 200
via_ir = true
```

Compile the project:

```bash
forge clean
forge build
```

Run the complete PoC:

```bash
forge test \
  --match-contract MonetrixVaultExactFrontRunTest \
  -vvvv
```

Run only the attack test:

```bash
forge test \
  --match-test test_FrontRun_LateStakerSnipesPendingYield_OnFlattenedMonetrixVault \
  -vvvv
```

Run only the control test:

```bash
forge test \
  --match-test test_NoFrontRun_OldStakerReceivesFullYieldIfNoLateDeposit_OnFlattenedMonetrixVault \
  -vvvv
```

Expected result:

```text
[PASS] test_FrontRun_LateStakerSnipesPendingYield_OnFlattenedMonetrixVault()

[PASS] test_NoFrontRun_OldStakerReceivesFullYieldIfNoLateDeposit_OnFlattenedMonetrixVault()
```

## PoC Result

After `settle()`:

```text
Yield pending in yieldEscrow:
700000000

sUSDM totalAssets:
1000000000

Existing staker assets:
1000000000
```

The attacker then deposits:

```text
Attacker deposit:
1000000000

Attacker shares minted:
approximately equal to existing staker shares
```

After `distributeYield()`:

```text
sUSDM totalAssets:
2700000000

Existing staker assets:
approximately 1350000000

Attacker assets:
approximately 1350000000
```

The attacker captures approximately:

```text
350000000
```

of yield that accrued before the attacker's deposit.

Without the attacker, the existing staker would hold approximately:

```text
1700000000
```

after distribution.

The original staker therefore loses approximately `350e6` of expected historical yield because of dilution.

## Impact

A late staker can capture yield generated before they entered the sUSDM vault.

This can cause:

* direct dilution of existing sUSDM holders;
* transfer of historical yield to opportunistic depositors;
* repeated yield-sniping around each distribution;
* reduced returns for long-term stakers;
* economically profitable front-running of `distributeYield()`.

The attack can be repeated whenever there is a delay between `settle()` and `distributeYield()`.

## Severity

**Medium**

The vulnerability allows an attacker to capture a proportional share of previously accrued yield at the expense of existing stakers.

The attack does not require privileged access and can be performed by depositing immediately before pending yield is injected.

## Recommendation

Pending yield should be reflected in the share price before new sUSDM shares can be minted.

The preferred mitigation is to combine settlement and user-yield injection into a single atomic operation:

```solidity
function settleAndDistributeYield(
    uint256 proposedYield
) external onlyOperator {
    _settle(proposedYield);
    _distributeYield();
}
```

Alternative mitigations include:

1. Blocking `sUSDM.deposit()` and `mint()` while `yieldEscrow.balance() > 0`.
2. Checkpointing pending settled yield into `totalAssets()`.
3. Recording a share-price snapshot before yield settlement.
4. Tracking reward eligibility based on shares held before `settle()`.
5. Ensuring `settle()` and `distributeYield()` execute atomically in the same transaction.

## References

* [Monetrix repository](https://github.com/code-423n4/2026-04-monetrix)
* [`MonetrixVault.sol`](https://github.com/code-423n4/2026-04-monetrix/blob/3d94be1361ca01d959f9165a78f0d75c5657fe3e/src/core/MonetrixVault.sol)
* [`settle()`](https://github.com/code-423n4/2026-04-monetrix/blob/3d94be1361ca01d959f9165a78f0d75c5657fe3e/src/core/MonetrixVault.sol#L373-L382)
* [`distributeYield()`](https://github.com/code-423n4/2026-04-monetrix/blob/3d94be1361ca01d959f9165a78f0d75c5657fe3e/src/core/MonetrixVault.sol#L384-L408)
* [`sUSDM.sol`](https://github.com/code-423n4/2026-04-monetrix/blob/3d94be1361ca01d959f9165a78f0d75c5657fe3e/src/tokens/sUSDM.sol)
* [`sUSDM.totalAssets()`](https://github.com/code-423n4/2026-04-monetrix/blob/3d94be1361ca01d959f9165a78f0d75c5657fe3e/src/tokens/sUSDM.sol#L105-L107)
* [`sUSDM.injectYield()`](https://github.com/code-423n4/2026-04-monetrix/blob/3d94be1361ca01d959f9165a78f0d75c5657fe3e/src/tokens/sUSDM.sol#L205-L215)
* [Foundry PoC — Issue #9](https://github.com/HUODONGREN/front-run_0day/issues/9)
