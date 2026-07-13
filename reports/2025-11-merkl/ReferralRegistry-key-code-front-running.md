# Referral keys and referrer codes can be front-run and squatted by attackers

## Finding Metadata

| Field              | Value                                                                                                                    |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------ |
| Target project     | [Merkl](https://github.com/code-423n4/2025-11-merkl)                                                                     |
| Affected contract  | [`contracts/ReferralRegistry.sol`](https://github.com/code-423n4/2025-11-merkl/blob/main/contracts/ReferralRegistry.sol) |
| Vulnerability type | Front-running / referral identifier squatting                                                                            |
| Severity           | Medium                                                                                                                   |
| Proof of concept   | [HUODONGREN/front-run_0day Issue #11](https://github.com/HUODONGREN/front-run_0day/issues/11)                            |

## Summary

`ReferralRegistry` uses a first-come-first-served registration model for referral program keys and referrer codes.

Any caller can register an unused referral program key through `addReferralKey()`. Similarly, an eligible caller can register an unused referrer code through `becomeReferrer()`.

Because keys and codes are submitted in plaintext, an attacker can observe a pending registration transaction, copy the same identifier, and submit a higher-priority transaction.

If the attacker's transaction executes first, the key or code is assigned to the attacker. The legitimate user's later transaction then reverts with `KeyAlreadyUsed`.

For referrer codes, users who later acknowledge the hijacked code are bound to the attacker.

## Vulnerable Code

`addReferralKey()` only checks whether the key is unused at execution time and then assigns the supplied owner:

[`ReferralRegistry.sol#L70-L94`](https://github.com/code-423n4/2025-11-merkl/blob/main/contracts/ReferralRegistry.sol#L70-L94)

```solidity
function addReferralKey(
    string calldata key,
    uint256 _cost,
    bool _requiresRefererToBeSet,
    address _owner,
    bool _requiresAuthorization,
    address _paymentToken
) external payable {
    if (referralPrograms[key].owner != address(0)) {
        revert Errors.KeyAlreadyUsed();
    }

    if (msg.value < costReferralProgram) {
        revert Errors.NotEnoughPayment();
    }

    if (_cost != 0 && !_requiresRefererToBeSet) {
        revert Errors.InvalidParam();
    }

    referralKeys.push(key);

    referralPrograms[key] = ReferralProgram({
        owner: _owner,
        requiresAuthorization: _requiresAuthorization,
        cost: _cost,
        requiresRefererToBeSet: _requiresRefererToBeSet,
        paymentToken: _paymentToken
    });

    emit ReferralKeyAdded(key, referralPrograms[key]);
}
```

`becomeReferrer()` applies the same first-come-first-served rule to referrer codes:

[`ReferralRegistry.sol#L134-L156`](https://github.com/code-423n4/2025-11-merkl/blob/main/contracts/ReferralRegistry.sol#L134-L156)

```solidity
function becomeReferrer(
    string calldata key,
    string calldata referrerCode
) external payable {
    if (referralPrograms[key].owner == address(0)) {
        revert Errors.NotAllowed();
    }

    if (codeToReferrer[key][referrerCode] != address(0)) {
        revert Errors.KeyAlreadyUsed();
    }

    ReferralProgram storage program = referralPrograms[key];

    if (program.requiresAuthorization) {
        if (
            refererStatus[key][msg.sender]
                != ReferralStatus.Allowed
        ) {
            revert Errors.NotAllowed();
        }
    }

    refererStatus[key][msg.sender] = ReferralStatus.Set;
    referrerCodeMapping[key][msg.sender] = referrerCode;
    codeToReferrer[key][referrerCode] = msg.sender;

    emit ReferrerAdded(key, msg.sender);
}
```

Users acknowledging a code are bound to the address stored by the first successful registrant:

[`ReferralRegistry.sol#L186-L190`](https://github.com/code-423n4/2025-11-merkl/blob/main/contracts/ReferralRegistry.sol#L186-L190)

```solidity
function acknowledgeReferrerByKey(
    string calldata key,
    string calldata referrerCode
) external {
    address referrer =
        codeToReferrer[key][referrerCode];

    if (referrer == address(0)) {
        revert Errors.NotAllowed();
    }

    acknowledgeReferrer(key, referrer);
}
```

## Root Cause

Referral keys and referrer codes are registered directly from publicly visible plaintext values.

Uniqueness is enforced only against the state that exists when the transaction executes:

```text
referralPrograms[key].owner == address(0)
```

and:

```text
codeToReferrer[key][referrerCode] == address(0)
```

The result therefore depends on transaction ordering:

```text
Victim registration → Attacker registration
    = victim owns the identifier

Attacker registration → Victim registration
    = attacker owns the identifier
    = victim reverts with KeyAlreadyUsed
```

There is no commit-reveal mechanism, identifier reservation, or creator-bound authorization protecting pending registrations.

## Attack Steps

### Referral program key squatting

1. A legitimate project owner prepares:

```solidity
addReferralKey(
    "merkl-main",
    0,
    true,
    legitimateOwner,
    false,
    address(0)
);
```

2. The transaction is submitted through the public mempool.
3. The attacker observes the plaintext key `"merkl-main"`.
4. The attacker submits the same registration with themselves as `_owner`.
5. The attacker uses a higher execution priority.
6. The attacker's transaction executes first.
7. `referralPrograms["merkl-main"].owner` is set to the attacker.
8. The legitimate owner's transaction executes afterward.
9. The legitimate transaction reverts with:

```text
KeyAlreadyUsed()
```

### Referrer code squatting

1. A referral program named `"merkl-main"` already exists.
2. The legitimate referrer submits:

```solidity
becomeReferrer("merkl-main", "alice");
```

3. The attacker observes the pending transaction.
4. The attacker submits the same code with higher execution priority.
5. The attacker's transaction executes first.
6. The following mapping is recorded:

```text
codeToReferrer["merkl-main"]["alice"]
    = attacker
```

7. The victim's later registration reverts with:

```text
KeyAlreadyUsed()
```

8. A user subsequently calls:

```solidity
acknowledgeReferrerByKey(
    "merkl-main",
    "alice"
);
```

9. The user's referral relationship is assigned to the attacker.

## Proof of Concept

The complete Foundry PoC is available at:

[PoC — `HUODONGREN/front-run_0day#11`](https://github.com/HUODONGREN/front-run_0day/issues/11)

The PoC test contract is:

```text
ReferralRegistryFrontRunTest
```

It contains the following tests:

```text
test_FrontRun_AddReferralKey_AttackerSquatsProgramKey

test_FrontRun_BecomeReferrer_AttackerSquatsReferrerCode

test_NoFrontRun_VictimCanRegisterCodeIfExecutedFirst
```

The first test confirms that the attacker can register `"merkl-main"` first and become its stored owner.

The second test confirms that the attacker can register the `"alice"` referrer code first and receive a later user's referral binding.

The control test confirms that the legitimate referrer owns the code when their transaction executes first.

## Reproduction Steps

Create a Foundry project:

```bash
mkdir referral-registry-front-run-poc
cd referral-registry-front-run-poc

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
src/ReferralRegistry_flattened.sol
```

Save the PoC from Issue #11 as:

```text
test/ReferralRegistryFrontRun.t.sol
```

The test import should be:

```solidity
import "../src/ReferralRegistry_flattened.sol";
```

Configure `foundry.toml`:

```toml
[profile.default]
src = "src"
test = "test"
libs = ["lib"]

solc_version = "0.8.17"
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
  --match-contract ReferralRegistryFrontRunTest \
  -vvvv
```

Run only the referral-key attack:

```bash
forge test \
  --match-test test_FrontRun_AddReferralKey_AttackerSquatsProgramKey \
  -vvvv
```

Run only the referrer-code attack:

```bash
forge test \
  --match-test test_FrontRun_BecomeReferrer_AttackerSquatsReferrerCode \
  -vvvv
```

Run the control test:

```bash
forge test \
  --match-test test_NoFrontRun_VictimCanRegisterCodeIfExecutedFirst \
  -vvvv
```

Expected result:

```text
[PASS] test_FrontRun_AddReferralKey_AttackerSquatsProgramKey()

[PASS] test_FrontRun_BecomeReferrer_AttackerSquatsReferrerCode()

[PASS] test_NoFrontRun_VictimCanRegisterCodeIfExecutedFirst()
```

## PoC Result

### Referral program key

After the attacker's transaction executes:

```text
referral key:
merkl-main

registered program owner:
attacker
```

The legitimate project owner's later registration reverts with:

```text
KeyAlreadyUsed()
```

### Referrer code

After the attacker registers the code first:

```text
program key:
merkl-main

referrer code:
alice

code owner:
attacker
```

The legitimate referrer's later transaction reverts with:

```text
KeyAlreadyUsed()
```

When another user acknowledges the `"alice"` code:

```text
getReferrer("merkl-main", referredUser)
    == attacker
```

The control test confirms that without front-running:

```text
codeToReferrer["merkl-main"]["alice"]
    == victimReferrer
```

and the referred user is correctly bound to the victim referrer.

## Impact

An attacker can squat valuable referral program keys or referrer codes before their intended registrants.

This can:

* deny legitimate referral program registration;
* deny legitimate referrer-code registration;
* assign control of a referral program key to the attacker;
* redirect future referral relationships to the attacker;
* cause legitimate transactions to revert;
* waste victim transaction gas;
* force legitimate users to select different identifiers.

The referrer-code attack applies when the attacker is eligible to call `becomeReferrer()`, including referral programs that do not require prior authorization.

## Severity

**Medium**

The vulnerability allows an unprivileged or otherwise eligible attacker to permanently occupy valuable referral identifiers and redirect future code-based referral relationships.

## Recommendation

Use a commit-reveal registration mechanism.

For referral program keys, the commitment should bind the intended owner, key, parameters, and a random salt:

```solidity
bytes32 commitment = keccak256(
    abi.encode(
        msg.sender,
        key,
        owner,
        cost,
        requiresAuthorization,
        requiresReferrerToBeSet,
        paymentToken,
        salt
    )
);
```

For referrer codes, the commitment should bind the registrant:

```solidity
bytes32 commitment = keccak256(
    abi.encode(
        msg.sender,
        referralKey,
        referrerCode,
        salt
    )
);
```

After the commitment has been confirmed, the caller can reveal the plaintext value and complete registration.

Alternative mitigations include:

1. Require an EIP-712 signature from the intended referral program owner.
2. Bind `_owner` to `msg.sender` when third-party registration is unnecessary.
3. Allow referral program owners to pre-authorize specific referrer codes.
4. Add temporary key and code reservations.
5. Use private transaction submission for valuable registrations.

## References

* [Merkl repository](https://github.com/code-423n4/2025-11-merkl)
* [`ReferralRegistry.sol`](https://github.com/code-423n4/2025-11-merkl/blob/main/contracts/ReferralRegistry.sol)
* [`addReferralKey()`](https://github.com/code-423n4/2025-11-merkl/blob/main/contracts/ReferralRegistry.sol#L70-L94)
* [`becomeReferrer()`](https://github.com/code-423n4/2025-11-merkl/blob/main/contracts/ReferralRegistry.sol#L134-L156)
* [`acknowledgeReferrerByKey()`](https://github.com/code-423n4/2025-11-merkl/blob/main/contracts/ReferralRegistry.sol#L186-L190)
* [Foundry PoC — Issue #11](https://github.com/HUODONGREN/front-run_0day/issues/11)
