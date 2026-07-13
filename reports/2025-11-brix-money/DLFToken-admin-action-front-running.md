# Admin blacklist, pause, and burn actions can be front-run by token holders

## Finding Metadata

| Field              | Value                                                                                                               |
| ------------------ | ------------------------------------------------------------------------------------------------------------------- |
| Target project     | [Brix Money](https://github.com/code-423n4/2025-11-brix-money)                                                      |
| Affected contract  | [`src/external/DLFToken.sol`](https://github.com/code-423n4/2025-11-brix-money/blob/main/src/external/DLFToken.sol) |
| Vulnerability type | Front-running / administrative-action preemption                                                                    |
| Severity           | Medium                                                                                                              |
| Proof of concept   | [HUODONGREN/front-run_0day Issue #1](https://github.com/HUODONGREN/front-run_0day/issues/1)                         |

## Summary

`DLFToken` allows the owner to pause token transfers, blacklist individual accounts, and forcibly burn tokens from a specified address.

However, these administrative actions are submitted as separate public transactions. Before an owner's `blacklist()`, `pause()`, or `burn()` transaction is confirmed, the targeted holder can observe it in the public mempool and submit a higher-priority `transfer()` transaction.

If the holder's transfer executes first, the tokens are moved to another unblacklisted address before the restriction takes effect. The later blacklist applies only to the now-empty address, the pause cannot reverse the completed transfer, and the burn may revert because the original account no longer holds enough tokens.

## Vulnerable Code

Transfers are restricted only according to the blacklist and pause state that exists when the transfer executes:

[`DLFToken.sol#L31-L35`](https://github.com/code-423n4/2025-11-brix-money/blob/main/src/external/DLFToken.sol#L31-L35)

```solidity
function _beforeTokenTransfer(
    address from,
    address to,
    uint256 amount
) internal override whenNotPaused {
    require(!_isBlacklisted[from], "ERC20: sender is blacklisted");
    require(!_isBlacklisted[to], "ERC20: recipient is blacklisted");

    super._beforeTokenTransfer(from, to, amount);
}
```

The administrative actions are performed through separate owner transactions:

[`DLFToken.sol#L23-L25`](https://github.com/code-423n4/2025-11-brix-money/blob/main/src/external/DLFToken.sol#L23-L25)

```solidity
function pause() public onlyOwner {
    _pause();
}
```

[`DLFToken.sol#L36-L39`](https://github.com/code-423n4/2025-11-brix-money/blob/main/src/external/DLFToken.sol#L36-L39)

```solidity
function blacklist(address account) public onlyOwner {
    require(account != address(0), "Blacklist: account is the zero address");
    _isBlacklisted[account] = true;
}
```

[`DLFToken.sol#L50-L52`](https://github.com/code-423n4/2025-11-brix-money/blob/main/src/external/DLFToken.sol#L50-L52)

```solidity
function burn(address from, uint256 amount) public onlyOwner {
    _burn(from, amount);
}
```

## Root Cause

The contract does not reserve or freeze a targeted balance before an administrative transaction is executed.

The success of the restriction therefore depends on transaction ordering:

```text
Admin action → User transfer
    = transfer blocked or balance burned

User transfer → Admin action
    = transfer succeeds before restriction
```

A pending administrative transaction does not change the token's on-chain state. Until the transaction is mined, the targeted holder remains able to transfer tokens under the previous state.

## Attack Steps

1. Alice holds `100e18` DLF tokens.
2. The owner submits `blacklist(alice)`, `pause()`, or `burn(alice, 100e18)`.
3. Alice observes the pending administrative transaction in the public mempool.
4. Alice submits `transfer(bob, 100e18)` with a higher execution priority.
5. Alice's transfer executes first.
6. Bob receives all `100e18` DLF tokens.
7. The owner's transaction executes afterward.
8. The blacklist applies to Alice's empty address, the pause takes effect only after the transfer, or the burn reverts because Alice's balance is zero.

## Proof of Concept

The complete Foundry PoC is available at:

[PoC — `HUODONGREN/front-run_0day#1`](https://github.com/HUODONGREN/front-run_0day/issues/1)

The PoC contains the following tests:

```text
test_FrontRunBlacklist_ByTransferringBeforeBlacklist
test_TransferFailsAfterBlacklist
test_FrontRunPause_ByTransferringBeforePause
test_FrontRunBurn_ByTransferringBeforeBurn
```

The front-running tests execute the holder's transfer before the corresponding administrative action.

The control test executes `blacklist(alice)` first and confirms that Alice's later transfer reverts with:

```text
ERC20: sender is blacklisted
```

This confirms that the result depends on transaction ordering.

## Reproduction Steps

Create a Foundry project:

```bash
mkdir dlf-token-front-run-poc
cd dlf-token-front-run-poc
forge init --force
```

Install `forge-std`:

```bash
forge install foundry-rs/forge-std
```

Place the flattened contract at:

```text
src/DLFToken_flattened_checked.sol
```

Save the PoC from Issue #1 as:

```text
test/DLFTokenFlattenedFrontRun.t.sol
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

Run the tests:

```bash
forge clean
forge build

forge test \
  --match-contract DLFTokenFlattenedFrontRunTest \
  -vvvv
```

Expected result:

```text
[PASS] test_FrontRunBlacklist_ByTransferringBeforeBlacklist()
[PASS] test_TransferFailsAfterBlacklist()
[PASS] test_FrontRunPause_ByTransferringBeforePause()
[PASS] test_FrontRunBurn_ByTransferringBeforeBurn()
```

## PoC Result

The blacklist front-running test produces the following final state:

```text
Alice blacklisted: true
Alice balance:     0
Bob balance:       100e18
Bob blacklisted:   false
```

The pause test confirms that Alice's transfer succeeds before `pause()` executes, while later transfers revert after the contract is paused.

The burn test confirms that Alice can transfer the complete balance first, causing the subsequent `burn(alice, 100e18)` transaction to revert with:

```text
ERC20: burn amount exceeds balance
```

## Impact

A targeted holder can move tokens away from the address named in a pending administrative transaction before the restriction becomes effective.

This can:

* bypass an intended account freeze;
* cause a forced-burn transaction to fail;
* allow tokens to escape immediately before an emergency pause;
* weaken compliance and emergency-response mechanisms;
* require the owner to identify and restrict the new recipient address.

The vulnerability is particularly relevant when blacklist or burn functionality is intended to contain malicious, compromised, or restricted accounts.

## Severity

**Medium**

The vulnerability does not bypass the owner's access control and does not directly steal another user's funds. However, it can prevent the owner from reliably enforcing blacklist, emergency-pause, and forced-burn actions against a targeted balance.

The final severity depends on whether these functions are used as core compliance or emergency-control mechanisms.

## Recommendation

Sensitive administrative actions should be submitted through a private transaction relay so that the target address and action are not exposed in the public mempool before execution.

Where blacklist and burn must occur together, provide an atomic function:

```solidity
function blacklistAndBurn(
    address account,
    uint256 amount
) external onlyOwner {
    _isBlacklisted[account] = true;
    _burn(account, amount);
}
```

The atomic transaction should still be submitted privately, because a publicly visible combined transaction can also be front-run before it is mined.

For emergency handling, submit `pause()` privately before broadcasting targeted blacklist or burn operations.

## References

* [Brix Money repository](https://github.com/code-423n4/2025-11-brix-money)
* [`DLFToken.sol`](https://github.com/code-423n4/2025-11-brix-money/blob/main/src/external/DLFToken.sol)
* [Transfer restriction logic](https://github.com/code-423n4/2025-11-brix-money/blob/main/src/external/DLFToken.sol#L31-L35)
* [Blacklist implementation](https://github.com/code-423n4/2025-11-brix-money/blob/main/src/external/DLFToken.sol#L36-L39)
* [Pause implementation](https://github.com/code-423n4/2025-11-brix-money/blob/main/src/external/DLFToken.sol#L23-L25)
* [Burn implementation](https://github.com/code-423n4/2025-11-brix-money/blob/main/src/external/DLFToken.sol#L50-L52)
* [Foundry PoC — Issue #1](https://github.com/HUODONGREN/front-run_0day/issues/1)
