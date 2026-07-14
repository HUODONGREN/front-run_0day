# Late deposits can front-run `injectYield()` and capture pending historical yield

## Finding Metadata

| Field              | Value                                                                                                   |
| ------------------ | ------------------------------------------------------------------------------------------------------- |
| Target project     | [Monetrix](https://github.com/code-423n4/2026-04-monetrix)                                              |
| Affected contract  | [`src/tokens/sUSDM.sol`](https://github.com/code-423n4/2026-04-monetrix/blob/3d94be1361ca01d959f9165a78f0d75c5657fe3e/src/tokens/sUSDM.sol) |
| Vulnerability type | Front-running / yield sniping                                                                           |
| Severity           | Medium                                                                                                  |
| Proof of concept   | [HUODONGREN/front-run_0day Issue #10](https://github.com/HUODONGREN/front-run_0day/issues/10)           |

## Summary

`sUSDM` is an ERC-4626 vault whose share price increases when the protocol injects USDM yield through `injectYield()`.

However, pending historical yield held outside the sUSDM contract is not included in `totalAssets()`. A late depositor can observe a pending yield-injection transaction and call `deposit()` before `injectYield()` executes.

The attacker receives shares at the stale pre-yield exchange rate. When the historical yield is subsequently injected, the attacker receives a proportional share of yield generated before they entered the vault, directly diluting existing sUSDM holders.

## Vulnerable Code

`totalAssets()` only counts the USDM already held by the sUSDM contract:

[`sUSDM.sol#L102-L104`](https://github.com/code-423n4/2026-04-monetrix/blob/3d94be1361ca01d959f9165a78f0d75c5657fe3e/src/tokens/sUSDM.sol#L102-L104)

```solidity
function totalAssets() public view override returns (uint256) {
    return IERC20(asset()).balanceOf(address(this));
}
```

New deposits and mints remain available and use the standard ERC-4626 exchange rate:

[`sUSDM.sol#L122-L128`](hhttps://github.com/code-423n4/2026-04-monetrix/blob/3d94be1361ca01d959f9165a78f0d75c5657fe3e/src/tokens/sUSDM.sol#L122-L128)

```solidity
function deposit(
    uint256 assets,
    address receiver
) public override nonReentrant whenNotPaused returns (uint256) {
    return super.deposit(assets, receiver);
}

function mint(
    uint256 shares,
    address receiver
) public override nonReentrant whenNotPaused returns (uint256) {
    return super.mint(shares, receiver);
}
```

The pending yield is added to `totalAssets()` only when `injectYield()` transfers the USDM into sUSDM:

[`sUSDM.sol#L205-L215`](https://github.com/code-423n4/2026-04-monetrix/blob/3d94be1361ca01d959f9165a78f0d75c5657fe3e/src/tokens/sUSDM.sol#L205-L215)

```solidity
function injectYield(
    uint256 usdmAmount
) external onlyVault nonReentrant {
    require(usdmAmount > 0, "sUSDM: zero yield");

    require(
        usdmAmount <= config.maxYieldPerInjection(),
        "sUSDM: yield exceeds max"
    );

    require(totalSupply() > 0, "sUSDM: no stakers");

    IERC20(asset()).safeTransferFrom(
        msg.sender,
        address(this),
        usdmAmount
    );

    totalYieldInjected += usdmAmount;
    lastCumulativeYield =
        (totalAssets() * 1e18) / totalSupply();

    emit YieldInjected(
        usdmAmount,
        totalAssets(),
        totalSupply()
    );
}
```

## Root Cause

Pending historical yield outside the sUSDM contract is not included in the share price before new shares are minted.

Before yield injection:

```text
sharePrice =
    sUSDM.totalAssets() / sUSDM.totalSupply()
```

Because `totalAssets()` excludes pending yield, a late depositor receives shares using the stale exchange rate.

The result depends on transaction ordering:

```text
injectYield() → attacker deposit
    = historical yield belongs to existing stakers

attacker deposit → injectYield()
    = attacker receives part of historical yield
```

There is no checkpoint, snapshot, or deposit restriction preventing newly minted shares from participating in previously generated yield.

## Attack Steps

1. An existing staker deposits `1000e6` USDM into sUSDM.
2. The existing staker receives sUSDM shares representing `1000e6` USDM.
3. The protocol realizes `700e6` USDM of historical yield.
4. The yield remains outside sUSDM while waiting for `injectYield()`.
5. `sUSDM.totalAssets()` still reports only `1000e6` USDM.
6. The attacker observes the pending yield-injection transaction.
7. The attacker front-runs it by calling:

```solidity
susdm.deposit(1000e6, attacker);
```

8. The attacker receives approximately the same number of shares as the original staker.
9. The vault subsequently calls:

```solidity
susdm.injectYield(700e6);
```

10. The sUSDM assets increase from `2000e6` to `2700e6`.
11. The injected yield is distributed across both the old and newly minted shares.
12. The attacker captures approximately `350e6` of historical yield.
13. The original staker loses approximately `350e6` compared with the no-attacker case.

## Proof of Concept

The complete Foundry PoC is available at:

[PoC — `HUODONGREN/front-run_0day#10`](https://github.com/HUODONGREN/front-run_0day/issues/10)

The PoC test contract is:

```text
SUSDMExactFrontRunTest
```

It contains the following tests:

```text
test_FrontRun_LateDepositorCapturesPendingYield_OnFlattenedSUSDM

test_NoFrontRun_OldStakerReceivesFullYieldIfNoLateDeposit_OnFlattenedSUSDM
```

The first test deposits the attacker's USDM before `injectYield()` and confirms that the attacker captures part of the pending historical yield.

The second test injects the yield without a late depositor and confirms that the original staker receives the complete yield.

## Reproduction Steps

Create a Foundry project:

```bash
mkdir susdm-front-run-poc
cd susdm-front-run-poc

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

Place the flattened contract at:

```text
src/sUSDM_flattened.sol
```

Save the PoC from Issue #10 as:

```text
test/SUSDMExactFrontRun.t.sol
```

The test import should be:

```solidity
import "../src/sUSDM_flattened.sol";
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
  --match-contract SUSDMExactFrontRunTest \
  -vvvv
```

Run only the attack test:

```bash
forge test \
  --match-test test_FrontRun_LateDepositorCapturesPendingYield_OnFlattenedSUSDM \
  -vvvv
```

Run only the control test:

```bash
forge test \
  --match-test test_NoFrontRun_OldStakerReceivesFullYieldIfNoLateDeposit_OnFlattenedSUSDM \
  -vvvv
```

Expected result:

```text
[PASS] test_FrontRun_LateDepositorCapturesPendingYield_OnFlattenedSUSDM()

[PASS] test_NoFrontRun_OldStakerReceivesFullYieldIfNoLateDeposit_OnFlattenedSUSDM()
```

## PoC Result

Before the attacker deposits:

```text
Pending historical yield:
700000000

sUSDM totalAssets:
1000000000

Existing staker assets:
1000000000
```

The attacker deposits:

```text
Attacker deposit:
1000000000

Attacker shares:
approximately equal to existing staker shares
```

Before yield injection:

```text
sUSDM totalAssets:
2000000000
```

After injecting `700e6` USDM:

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
350000000 USDM
```

of yield generated before the attacker's deposit.

Without the attacker, the original staker would hold approximately:

```text
1700000000 USDM
```

after the yield injection.

## Impact

A late depositor can capture yield accrued before they entered the sUSDM vault.

This causes:

* direct dilution of existing sUSDM holders;
* transfer of historical yield to opportunistic depositors;
* reduced returns for long-term stakers;
* profitable front-running of pending `injectYield()` transactions;
* repeated yield-sniping whenever yield is waiting to be injected.

## Severity

**Medium**

The attack allows an unprivileged depositor to extract part of previously accrued yield at the expense of existing stakers.

The attack can be performed whenever historical yield is held outside sUSDM and a deposit can execute before `injectYield()`.

## Recommendation

Prevent new shares from participating in yield accrued before those shares were minted.

Possible mitigations include:

1. Block `deposit()` and `mint()` while pending yield exists.
2. Inject pending yield before processing a new deposit.
3. Include pending protocol yield in the share-price calculation.
4. Use a snapshot to record shares eligible for each yield injection.
5. Track yield entitlement using time- or epoch-based accounting.
6. Execute yield realization and `injectYield()` atomically.

For example, deposits can be rejected while the vault reports pending yield:

```solidity
modifier noPendingYield() {
    require(
        IMonetrixVault(vault).pendingYield() == 0,
        "sUSDM: pending yield"
    );
    _;
}

function deposit(
    uint256 assets,
    address receiver
)
    public
    override
    nonReentrant
    whenNotPaused
    noPendingYield
    returns (uint256)
{
    return super.deposit(assets, receiver);
}
```

## References

* [Monetrix repository](https://github.com/code-423n4/2026-04-monetrix)
* [`sUSDM.sol`](https://github.com/code-423n4/2026-04-monetrix/blob/3d94be1361ca01d959f9165a78f0d75c5657fe3e/src/tokens/sUSDM.sol)
* [`totalAssets()`](https://github.com/code-423n4/2026-04-monetrix/blob/3d94be1361ca01d959f9165a78f0d75c5657fe3e/src/tokens/sUSDM.sol#L102-L104)
* [`deposit()` and `mint()`](https://github.com/code-423n4/2026-04-monetrix/blob/3d94be1361ca01d959f9165a78f0d75c5657fe3e/src/tokens/sUSDM.sol#L122-L128)
* [`injectYield()`](https://github.com/code-423n4/2026-04-monetrix/blob/3d94be1361ca01d959f9165a78f0d75c5657fe3e/src/tokens/sUSDM.sol#L205-L215)
* [Foundry PoC — Issue #10](https://github.com/HUODONGREN/front-run_0day/issues/10)
