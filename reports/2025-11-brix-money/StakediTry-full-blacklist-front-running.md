# Full blacklist can be front-run by transferring shares before restriction takes effect

## Finding Metadata

| Field              | Value                                                                                                                         |
| ------------------ | ----------------------------------------------------------------------------------------------------------------------------- |
| Target project     | [Brix Money](https://github.com/code-423n4/2025-11-brix-money)                                                                |
| Affected contract  | [`src/token/wiTRY/StakediTry.sol`](https://github.com/code-423n4/2025-11-brix-money/blob/c40317bcdefc0191e3a6457cdcd33da6b95c09b8/src/token/wiTRY/StakediTry.sol) |
| Vulnerability type | Front-running / blacklist preemption                                                                                          |
| Severity           | Medium                                                                                                                        |
| Proof of concept   | [HUODONGREN/front-run_0day Issue #4](https://github.com/HUODONGREN/front-run_0day/issues/4)                                   |

## Summary

`StakediTry` allows a blacklist manager to fully restrict a user by calling:

```solidity
addToBlacklist(user, true);
```

Once the user receives `FULL_RESTRICTED_STAKER_ROLE`, transfers from or to the restricted address are blocked. The administrator can later call `redistributeLockedAmount()` to move or burn the restricted user's wiTRY shares.

However, the blacklist transaction is publicly visible before confirmation. A targeted user can observe the pending transaction and front-run it by transferring all wiTRY shares to another address.

The blacklist is then applied to the original address after its balance has already been moved. Because `redistributeLockedAmount()` only redistributes the current balance of the restricted address, the administrator cannot recover the shares held by the escape address.

## Vulnerable Code

The blacklist role is granted only when `addToBlacklist()` executes:

[`StakediTry.sol#L124-L134`](https://github.com/code-423n4/2025-11-brix-money/blob/c40317bcdefc0191e3a6457cdcd33da6b95c09b8/src/token/wiTRY/StakediTry.sol#L124-L134)

```solidity
function addToBlacklist(address target, bool isFullBlacklisting)
    external
    onlyRole(BLACKLIST_MANAGER_ROLE)
    notOwner(target)
{
    bytes32 role = isFullBlacklisting
        ? FULL_RESTRICTED_STAKER_ROLE
        : SOFT_RESTRICTED_STAKER_ROLE;

    _grantRole(role, target);
}
```

Transfers are blocked only when the sender or recipient already has the full restriction role:

[`StakediTry.sol#L289-L299`](https://github.com/code-423n4/2025-11-brix-money/blob/c40317bcdefc0191e3a6457cdcd33da6b95c09b8/src/token/wiTRY/StakediTry.sol#L289-L299)

```solidity
function _beforeTokenTransfer(
    address from,
    address to,
    uint256
) internal virtual override {
    if (
        hasRole(FULL_RESTRICTED_STAKER_ROLE, from)
            && to != address(0)
    ) {
        revert OperationNotAllowed();
    }

    if (hasRole(FULL_RESTRICTED_STAKER_ROLE, to)) {
        revert OperationNotAllowed();
    }
}
```

`redistributeLockedAmount()` only reads and redistributes the target's current share balance:

[`StakediTry.sol#L168-L183`](https://github.com/code-423n4/2025-11-brix-money/blob/c40317bcdefc0191e3a6457cdcd33da6b95c09b8/src/token/wiTRY/StakediTry.sol#L168-L183)

```solidity
function redistributeLockedAmount(
    address from,
    address to
) external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE) {
    if (
        hasRole(FULL_RESTRICTED_STAKER_ROLE, from)
            && !hasRole(FULL_RESTRICTED_STAKER_ROLE, to)
    ) {
        uint256 amountToDistribute = balanceOf(from);
        uint256 iTryToVest = previewRedeem(amountToDistribute);

        _burn(from, amountToDistribute);
        _checkMinShares();

        if (to == address(0)) {
            _updateVestingAmount(iTryToVest);
        } else {
            _mint(to, amountToDistribute);
        }

        emit LockedAmountRedistributed(
            from,
            to,
            amountToDistribute
        );
    } else {
        revert OperationNotAllowed();
    }
}
```

## Root Cause

The blacklist and share redistribution process depends on the target address's execution-time role and balance.

Before the blacklist transaction is confirmed, the target does not yet have `FULL_RESTRICTED_STAKER_ROLE` and remains able to transfer shares.

The result therefore depends on transaction ordering:

```text
Blacklist → Transfer
    = transfer reverts

Transfer → Blacklist
    = shares escape before restriction
```

After the shares are transferred, `redistributeLockedAmount()` reads:

```text
balanceOf(restrictedAddress) == 0
```

and redistributes nothing.

## Attack Steps

1. The targeted user holds `1000e18` wiTRY shares.
2. The blacklist manager submits:

```solidity
addToBlacklist(victim, true);
```

3. The victim observes the pending blacklist transaction.
4. The victim submits a higher-priority transaction:

```solidity
transfer(escapeWallet, 1000e18);
```

5. The victim's transfer executes first.
6. The victim's balance becomes zero.
7. The escape wallet receives all `1000e18` shares.
8. The blacklist transaction executes afterward.
9. The victim receives `FULL_RESTRICTED_STAKER_ROLE`.
10. The restriction applies to the victim's now-empty address.
11. The administrator calls:

```solidity
redistributeLockedAmount(victim, treasury);
```

12. Because `balanceOf(victim) == 0`, no shares are transferred to the treasury.
13. The escaped shares remain controlled by `escapeWallet`.

## Proof of Concept

The complete Foundry PoC is available at:

[PoC — `HUODONGREN/front-run_0day#4`](https://github.com/HUODONGREN/front-run_0day/issues/4)

The PoC contains the following tests:

```text
test_FrontRun_FullBlacklist_ByTransferringBeforeBlacklist_OnFlattenedStakediTry

test_NoFrontRun_UserCannotTransferAfterFullBlacklist_OnFlattenedStakediTry
```

The first test executes the victim's transfer before the full blacklist transaction and confirms that all shares escape.

The second test applies the full blacklist first and confirms that the victim's later transfer reverts with `OperationNotAllowed`.

## Reproduction Steps

Create a Foundry project:

```bash
mkdir stakeditry-front-run-poc
cd stakeditry-front-run-poc

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
src/StakediTry_flattened.sol
```

Save the PoC code from Issue #4 as:

```text
test/StakediTryExactFrontRun.t.sol
```

The import in the test should be:

```solidity
import "../src/StakediTry_flattened.sol";
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
  --match-contract StakediTryExactFrontRunTest \
  -vvvv
```

Run only the front-running test:

```bash
forge test \
  --match-test test_FrontRun_FullBlacklist_ByTransferringBeforeBlacklist_OnFlattenedStakediTry \
  -vvvv
```

Run only the control test:

```bash
forge test \
  --match-test test_NoFrontRun_UserCannotTransferAfterFullBlacklist_OnFlattenedStakediTry \
  -vvvv
```

Expected result:

```text
[PASS] test_FrontRun_FullBlacklist_ByTransferringBeforeBlacklist_OnFlattenedStakediTry()

[PASS] test_NoFrontRun_UserCannotTransferAfterFullBlacklist_OnFlattenedStakediTry()
```

## PoC Result

Before the blacklist transaction:

```text
victim shares:
1000000000000000000000

escape wallet shares:
0
```

After the victim's front-running transfer:

```text
victim shares:
0

escape wallet shares:
1000000000000000000000
```

After the blacklist transaction:

```text
victim full restricted role:
true

victim shares:
0

escape wallet shares:
1000000000000000000000
```

After `redistributeLockedAmount(victim, treasury)`:

```text
treasury shares:
0

escape wallet final shares:
1000000000000000000000
```

The control test confirms that when the full blacklist executes first, the victim's subsequent transfer reverts with:

```text
OperationNotAllowed
```

## Impact

A targeted user can bypass the intended full-blacklist enforcement by moving all wiTRY shares before the blacklist transaction is confirmed.

This can:

* allow restricted shares to escape to another address;
* make the full blacklist apply only to an empty address;
* prevent `redistributeLockedAmount()` from recovering the escaped shares;
* weaken compliance and emergency asset-freezing mechanisms;
* require administrators to identify and blacklist additional recipient addresses.

## Severity

**Medium**

The vulnerability can prevent the protocol from reliably freezing and redistributing the shares of a targeted account.

The user does not bypass the restriction after it has already been applied. However, the public blacklist transaction creates an opportunity to move the complete balance before enforcement takes effect.

## Recommendation

Sensitive blacklist transactions should be submitted through a private transaction relay so that the targeted user cannot observe and front-run them.

The protocol should also provide an atomic administrative function that both restricts the address and redistributes its shares:

```solidity
function blacklistAndRedistribute(
    address from,
    address to
) external nonReentrant onlyRole(DEFAULT_ADMIN_ROLE) {
    _grantRole(FULL_RESTRICTED_STAKER_ROLE, from);

    uint256 amount = balanceOf(from);
    _burn(from, amount);

    if (to == address(0)) {
        _updateVestingAmount(previewRedeem(amount));
    } else {
        _mint(to, amount);
    }

    emit LockedAmountRedistributed(from, to, amount);
}
```

The atomic transaction should still be submitted privately because a publicly visible transaction can be front-run before it is mined.

## References

* [Brix Money repository](https://github.com/code-423n4/2025-11-brix-money)
* [`StakediTry.sol`](https://github.com/code-423n4/2025-11-brix-money/blob/c40317bcdefc0191e3a6457cdcd33da6b95c09b8/src/token/wiTRY/StakediTry.sol)
* [`addToBlacklist()`](https://github.com/code-423n4/2025-11-brix-money/blob/c40317bcdefc0191e3a6457cdcd33da6b95c09b8/src/token/wiTRY/StakediTry.sol#L124-L134)
* [`redistributeLockedAmount()`](https://github.com/code-423n4/2025-11-brix-money/blob/c40317bcdefc0191e3a6457cdcd33da6b95c09b8/src/token/wiTRY/StakediTry.sol#L168-L183)
* [Transfer restriction hook](https://github.com/code-423n4/2025-11-brix-money/blob/c40317bcdefc0191e3a6457cdcd33da6b95c09b8/src/token/wiTRY/StakediTry.sol#L289-L299)
* [Foundry PoC — Issue #4](https://github.com/HUODONGREN/front-run_0day/issues/4)
