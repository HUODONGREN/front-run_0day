# Public vault rebalancing can be front-run to force iTRY redemptions into the custodian path

## Finding Metadata

| Field              | Value                                                                                                                             |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------- |
| Target project     | [Brix Money](https://github.com/code-423n4/2025-11-brix-money)                                                                    |
| Affected contract  | [`src/protocol/iTryIssuer.sol`](https://github.com/code-423n4/2025-11-brix-money/blob/main/src/protocol/iTryIssuer.sol)           |
| Related contract   | [`src/protocol/FastAccessVault.sol`](https://github.com/code-423n4/2025-11-brix-money/blob/main/src/protocol/FastAccessVault.sol) |
| Vulnerability type | Front-running / redemption-path manipulation                                                                                      |
| Severity           | Medium                                                                                                                            |
| Proof of concept   | [HUODONGREN/front-run_0day Issue #6](https://github.com/HUODONGREN/front-run_0day/issues/6)                                       |

## Summary

`iTryIssuer` uses `FastAccessVault` as a liquidity buffer for instant iTRY redemptions.

When a user calls `redeemITRY()`, the issuer checks the vault's current DLF balance. If sufficient liquidity is available, the user receives DLF immediately from the buffer. Otherwise, the user's iTRY is burned and the redemption is routed through the slower custodian settlement path.

However, `FastAccessVault.rebalanceFunds()` is publicly callable. An attacker can observe a pending `redeemITRY()` transaction and front-run it by calling `rebalanceFunds()` first.

The rebalance transfers excess DLF from the vault to the custodian. This reduces the vault balance before the user's redemption executes and forces an otherwise instant redemption into the custodian path.

## Vulnerable Code

The redemption path is selected using the vault's execution-time balance:

[`iTryIssuer.sol#L354-L366`](https://github.com/code-423n4/2025-11-brix-money/blob/main/src/protocol/iTryIssuer.sol#L354-L366)

```solidity
_burn(msg.sender, iTRYAmount);

uint256 bufferBalance = liquidityVault.getAvailableBalance();

if (bufferBalance >= grossDlfAmount) {
    _redeemFromVault(recipient, netDlfAmount, feeAmount);
    fromBuffer = true;
} else {
    _redeemFromCustodian(recipient, netDlfAmount, feeAmount);
    fromBuffer = false;
}
```

The related `rebalanceFunds()` function is external and has no access-control modifier:

[`FastAccessVault.sol#L165-L181`](https://github.com/code-423n4/2025-11-brix-money/blob/main/src/protocol/FastAccessVault.sol#L165-L181)

```solidity
function rebalanceFunds() external {
    uint256 aumReferenceValue =
        _issuerContract.getCollateralUnderCustody();

    uint256 targetBalance =
        _calculateTargetBufferBalance(aumReferenceValue);

    uint256 currentBalance =
        _vaultToken.balanceOf(address(this));

    if (currentBalance > targetBalance) {
        uint256 excess = currentBalance - targetBalance;
        _vaultToken.transfer(custodian, excess);
    }
}
```

## Root Cause

`redeemITRY()` chooses the redemption path according to mutable vault liquidity:

```text
bufferBalance >= redemptionAmount
    → instant vault redemption

bufferBalance < redemptionAmount
    → custodian redemption
```

Because any address can call `rebalanceFunds()`, an attacker can reduce `bufferBalance` immediately before the user's transaction executes.

The result depends on transaction ordering:

```text
User redemption → Rebalance
    = instant redemption succeeds

Rebalance → User redemption
    = redemption is routed to custodian
```

The user cannot require the transaction to revert when the instant buffer path is no longer available.

## Attack Steps

1. The user holds `1000e18` iTRY.
2. `FastAccessVault` holds `1000e18` DLF.
3. The target buffer balance is `300e18` DLF.
4. The user submits:

```solidity
redeemITRY(800e18, 800e18);
```

5. At submission time, the vault has enough DLF to process the redemption instantly.
6. The attacker observes the pending redemption transaction.
7. The attacker submits a higher-priority call:

```solidity
liquidityVault.rebalanceFunds();
```

8. The attacker's transaction executes first.
9. The vault transfers `700e18` excess DLF to the custodian.
10. The vault balance decreases from `1000e18` to `300e18`.
11. The user's redemption executes afterward.
12. The issuer burns `800e18` iTRY from the user.
13. The issuer reads `bufferBalance == 300e18`.
14. Because the requested redemption is `800e18`, the buffer path is not used.
15. `fromBuffer` is set to `false`.
16. The user receives no DLF immediately, and the redemption is routed to the custodian path.

## Proof of Concept

The complete Foundry PoC is available at:

[PoC — `HUODONGREN/front-run_0day#6`](https://github.com/HUODONGREN/front-run_0day/issues/6)

The PoC contains the following tests:

```text
test_FrontRun_RebalanceForcesRedemptionIntoCustodianPath_OnFlattenedITryIssuer

test_NoFrontRun_RedeemUsesBufferWhenVaultHasEnoughLiquidity_OnFlattenedITryIssuer
```

The first test executes the attacker's public rebalance before the user's redemption and confirms that the redemption is routed to the custodian path.

The second test executes the redemption without a preceding rebalance and confirms that the same redemption succeeds immediately through the vault buffer.

## Reproduction Steps

Create a Foundry project:

```bash
mkdir itry-issuer-front-run-poc
cd itry-issuer-front-run-poc

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
src/iTryIssuer_flattened.sol
```

Save the PoC from Issue #6 as:

```text
test/iTryIssuerExactFrontRun.t.sol
```

The import in the test should be:

```solidity
import "../src/iTryIssuer_flattened.sol";
```

Configure `foundry.toml`:

```toml
[profile.default]
src = "src"
test = "test"
libs = ["lib"]

solc_version = "0.8.20"
optimizer = true
optimizer_runs = 200
```

Compile the project:

```bash
forge clean
forge build
```

Run the complete PoC:

```bash
forge test \
  --match-contract iTryIssuerExactFrontRunTest \
  -vvvv
```

Run only the attack test:

```bash
forge test \
  --match-test test_FrontRun_RebalanceForcesRedemptionIntoCustodianPath_OnFlattenedITryIssuer \
  -vvvv
```

Run only the control test:

```bash
forge test \
  --match-test test_NoFrontRun_RedeemUsesBufferWhenVaultHasEnoughLiquidity_OnFlattenedITryIssuer \
  -vvvv
```

Expected result:

```text
[PASS] test_FrontRun_RebalanceForcesRedemptionIntoCustodianPath_OnFlattenedITryIssuer()

[PASS] test_NoFrontRun_RedeemUsesBufferWhenVaultHasEnoughLiquidity_OnFlattenedITryIssuer()
```

## PoC Result

Initial state:

```text
User iTRY balance:
1000000000000000000000

Vault DLF balance:
1000000000000000000000

Custodian DLF balance:
0

Requested redemption:
800000000000000000000

Target buffer:
300000000000000000000
```

After the attacker calls `rebalanceFunds()`:

```text
DLF transferred to custodian:
700000000000000000000

Vault DLF balance:
300000000000000000000

Custodian DLF balance:
700000000000000000000
```

After the user's redemption:

```text
fromBuffer:
false

User iTRY balance:
200000000000000000000

User immediate DLF balance:
0

Vault DLF balance:
300000000000000000000
```

The control test confirms that without front-running:

```text
fromBuffer:
true

User immediate DLF balance:
800000000000000000000
```

This demonstrates that the attacker changes the redemption from an instant buffer withdrawal to delayed custodian settlement.

## Impact

An attacker can force otherwise valid instant iTRY redemptions into the slower custodian path.

This can cause:

* users to lose expected instant access to redeemed DLF;
* user iTRY to be burned without immediate DLF receipt;
* redemption settlement delays;
* additional reliance on off-chain custodian processing;
* griefing against users submitting large redemptions;
* inconsistent execution relative to the state visible when the transaction was submitted.

The attacker does not directly steal the user's funds. The impact is redemption-path manipulation and denial of the expected instant-redemption service.

## Severity

**Medium**

Any address can manipulate the liquidity state used to select the user's redemption path.

A user may submit a transaction while sufficient buffer liquidity exists but receive no DLF immediately because an attacker rebalances the vault first.

## Recommendation

Restrict `rebalanceFunds()` to the owner, issuer, or a trusted keeper:

```solidity
function rebalanceFunds() external onlyOwner {
    // Existing rebalancing logic
}
```

The redemption interface should also allow users to require instant buffer execution:

```solidity
function redeemITRY(
    uint256 iTRYAmount,
    uint256 minAmountOut,
    bool requireFromBuffer
) external returns (bool fromBuffer);
```

Before burning the user's iTRY, the function should revert when instant redemption is required but unavailable:

```solidity
uint256 bufferBalance = liquidityVault.getAvailableBalance();

if (requireFromBuffer && bufferBalance < grossDlfAmount) {
    revert InsufficientBufferLiquidity(
        grossDlfAmount,
        bufferBalance
    );
}
```

Additional protections may include:

1. Restricting excess-fund transfers to an authorized rebalancer.
2. Separating public top-up requests from privileged transfers to the custodian.
3. Checking buffer liquidity before burning the user's iTRY.
4. Adding a user-specified redemption-path preference.
5. Processing active redemptions before moving excess vault liquidity.

## References

* [Brix Money repository](https://github.com/code-423n4/2025-11-brix-money)
* [`iTryIssuer.sol`](https://github.com/code-423n4/2025-11-brix-money/blob/main/src/protocol/iTryIssuer.sol)
* [`redeemITRY()` redemption-path selection](https://github.com/code-423n4/2025-11-brix-money/blob/main/src/protocol/iTryIssuer.sol#L354-L366)
* [`FastAccessVault.sol`](https://github.com/code-423n4/2025-11-brix-money/blob/main/src/protocol/FastAccessVault.sol)
* [`rebalanceFunds()`](https://github.com/code-423n4/2025-11-brix-money/blob/main/src/protocol/FastAccessVault.sol#L165-L181)
* [Foundry PoC — Issue #6](https://github.com/HUODONGREN/front-run_0day/issues/6)
