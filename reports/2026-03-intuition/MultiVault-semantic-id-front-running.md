# Atom and triple creation can be front-run to squat semantic vault IDs

## Finding Metadata

| Field              | Value                                                                                                                  |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| Target project     | [Intuition](https://github.com/code-423n4/2026-03-intuition)                                                           |
| Affected contract  | [`src/protocol/MultiVault.sol`](https://github.com/code-423n4/2026-03-intuition/blob/314b7d4d9ccbaf27e4484a6c0706af83d3f75f36/src/protocol/MultiVault.sol) |
| Vulnerability type | Front-running / deterministic identifier squatting                                                                     |
| Severity           | Medium                                                                                                                 |
| Proof of concept   | [HUODONGREN/front-run_0day Issue #12](https://github.com/HUODONGREN/front-run_0day/issues/12)                          |

## Summary

`MultiVault` allows users to permissionlessly create atoms and semantic triples.

An atom ID is deterministically derived from its submitted `data`. A triple ID is deterministically derived from its `subjectId`, `predicateId`, and `objectId`.

Because these values are submitted in plaintext, an attacker can observe a pending `createAtoms()` or `createTriples()` transaction, copy the same input, and submit it with higher execution priority.

The attacker's transaction executes first, creates the semantic vault, and receives the initial vault shares. The victim's later transaction then reverts because the same atom or triple already exists.

## Vulnerable Code

`createAtoms()` forwards the caller and public atom data into `_createAtom()`:

[`MultiVault.sol#L2809-L2832`](https://github.com/code-423n4/2026-03-intuition/blob/314b7d4d9ccbaf27e4484a6c0706af83d3f75f36/src/protocol/MultiVault.sol#L2809-L2832)

```solidity
function createAtoms(
    bytes[] calldata data,
    uint256[] calldata assets
)
    external
    payable
    whenNotPaused
    nonReentrant
    returns (bytes32[] memory)
{
    uint256 _amount = _validatePayment(assets);
    return _createAtoms(data, assets, _amount);
}
```

The atom ID is calculated directly from the public data. If the ID already exists, the later transaction reverts:

[`MultiVault.sol#L2907-L2936`](https://github.com/code-423n4/2026-03-intuition/blob/314b7d4d9ccbaf27e4484a6c0706af83d3f75f36/src/protocol/MultiVault.sol#L2907-L2936)

```solidity
function _createAtom(
    address sender,
    bytes calldata data,
    uint256 assets
) internal returns (bytes32 atomId) {
    uint256 length = data.length;

    if (length == 0) {
        revert MultiVault_NoAtomDataProvided();
    }

    if (length > generalConfig.atomDataMaxLength) {
        revert MultiVault_AtomDataTooLong();
    }

    atomId = _calculateAtomId(data);

    if (_atoms[atomId].length != 0) {
        revert MultiVault_AtomExists(data);
    }

    _atoms[atomId] = data;
```

The initial atom-vault shares are credited to the transaction sender:

[`MultiVault.sol#L2942-L2963`](https://github.com/code-423n4/2026-03-intuition/blob/314b7d4d9ccbaf27e4484a6c0706af83d3f75f36/src/protocol/MultiVault.sol#L2942-L2963)

```solidity
(
    uint256 sharesForReceiver,
    uint256 assetsAfterFixedFees,
    uint256 assetsAfterFees
) = _calculateAtomCreate(atomId, assets);

uint256 userSharesAfter = _updateVaultOnCreation(
    sender,
    atomId,
    curveId,
    assetsAfterFees,
    sharesForReceiver,
    VaultType.ATOM
);

emit AtomCreated(sender, atomId, data, atomWallet);
```

`createTriples()` similarly accepts the semantic tuple in plaintext:

[`MultiVault.sol#L2982-L3007`](https://github.com/code-423n4/2026-03-intuition/blob/314b7d4d9ccbaf27e4484a6c0706af83d3f75f36/src/protocol/MultiVault.sol#L2982-L3007)

```solidity
function createTriples(
    bytes32[] calldata subjectIds,
    bytes32[] calldata predicateIds,
    bytes32[] calldata objectIds,
    uint256[] calldata assets
)
    external
    payable
    whenNotPaused
    nonReentrant
    returns (bytes32[] memory)
{
    uint256 _amount = _validatePayment(assets);

    return _createTriples(
        subjectIds,
        predicateIds,
        objectIds,
        assets,
        _amount
    );
}
```

The triple ID is deterministically calculated and checked before initial shares are assigned to the first caller:

[`MultiVault.sol#L3103-L3157`](https://github.com/code-423n4/2026-03-intuition/blob/314b7d4d9ccbaf27e4484a6c0706af83d3f75f36/src/protocol/MultiVault.sol#L3103-L3157)

```solidity
function _createTriple(
    address sender,
    bytes32 subjectId,
    bytes32 predicateId,
    bytes32 objectId,
    uint256 assets
) internal returns (bytes32 tripleId) {
    tripleId = _calculateTripleId(
        subjectId,
        predicateId,
        objectId
    );

    _tripleExists(
        tripleId,
        subjectId,
        predicateId,
        objectId
    );

    _requireTermExists(subjectId);
    _requireTermExists(predicateId);
    _requireTermExists(objectId);

    // ...

    uint256 userSharesAfter = _updateVaultOnCreation(
        sender,
        tripleId,
        curveId,
        assetsAfterFees,
        sharesForReceiver,
        VaultType.TRIPLE
    );
```

## Root Cause

Atom and triple identifiers are deterministic and calculated from publicly visible transaction inputs.

```text
atomId = calculateAtomId(atomData)
```

```text
tripleId = calculateTripleId(
    subjectId,
    predicateId,
    objectId
)
```

The contract uses first-come-first-served creation without:

* commit-reveal protection;
* creator authorization;
* input reservation;
* creator-bound signatures;
* or recipient binding.

The result therefore depends on transaction ordering:

```text
Victim creation → Attacker creation
    = victim receives initial shares

Attacker creation → Victim creation
    = attacker receives initial shares
    = victim transaction reverts
```

## Attack Steps

### Atom creation

1. The victim prepares valuable atom data:

```solidity
bytes memory atomData =
    bytes("intuition://atom/project-alpha");
```

2. The victim submits `createAtoms()` with the atom data and creation assets.
3. The attacker observes the pending transaction in the public mempool.
4. The attacker copies the same `atomData`.
5. The attacker submits the same `createAtoms()` call with higher execution priority.
6. The attacker's transaction executes first.
7. The same deterministic `atomId` is created.
8. The attacker receives the initial atom-vault shares.
9. The victim's transaction executes afterward.
10. The victim's transaction reverts with:

```text
MultiVault_AtomExists(atomData)
```

### Triple creation

1. The subject, predicate, and object atoms already exist.
2. The victim prepares a triple using:

```text
subjectId
predicateId
objectId
```

3. The victim submits `createTriples()`.
4. The attacker observes and copies the same tuple.
5. The attacker submits a higher-priority `createTriples()` transaction.
6. The attacker's transaction executes first.
7. The attacker creates the deterministic triple ID.
8. The attacker receives the initial triple-vault shares.
9. The victim's later transaction reverts with:

```text
MultiVault_TripleExists(
    tripleId,
    subjectId,
    predicateId,
    objectId
)
```

## Proof of Concept

The complete Foundry PoC is available at:

[PoC — `HUODONGREN/front-run_0day#12`](https://github.com/HUODONGREN/front-run_0day/issues/12)

The PoC test contract is:

```text
MultiVaultFrontRunTest
```

It contains the following tests:

```text
test_FrontRun_CreateAtom_AttackerSquatsAtomData

test_FrontRun_CreateTriple_AttackerSquatsTripleId

test_NoFrontRun_VictimCanCreateAtomAndTripleIfExecutedFirst
```

The first test executes the attacker's atom creation before the victim's transaction.

The second test executes the attacker's triple creation before the victim's transaction.

The control test confirms that the victim successfully creates the semantic object and receives the initial shares when the victim executes first.

## Reproduction Steps

Create a Foundry project:

```bash
mkdir multivault-front-run-poc
cd multivault-front-run-poc

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
src/MultiVault_flattened.sol
```

Save the PoC from Issue #12 as:

```text
test/MultiVaultFrontRun.t.sol
```

The test import should be:

```solidity
import "../src/MultiVault_flattened.sol";
```

Configure `foundry.toml`:

```toml
[profile.default]
src = "src"
test = "test"
libs = ["lib"]

solc_version = "0.8.29"
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
  --match-contract MultiVaultFrontRunTest \
  -vvvv
```

Run only the atom front-running test:

```bash
forge test \
  --match-test test_FrontRun_CreateAtom_AttackerSquatsAtomData \
  -vvvv
```

Run only the triple front-running test:

```bash
forge test \
  --match-test test_FrontRun_CreateTriple_AttackerSquatsTripleId \
  -vvvv
```

Run the control test:

```bash
forge test \
  --match-test test_NoFrontRun_VictimCanCreateAtomAndTripleIfExecutedFirst \
  -vvvv
```

Expected result:

```text
[PASS] test_FrontRun_CreateAtom_AttackerSquatsAtomData()

[PASS] test_FrontRun_CreateTriple_AttackerSquatsTripleId()

[PASS] test_NoFrontRun_VictimCanCreateAtomAndTripleIfExecutedFirst()
```

## PoC Result

### Atom front-running

The attacker submits the same atom data first and receives:

```text
attacker atom shares:
9999999999999000000
```

The victim receives no shares:

```text
victim atom shares:
0
```

The victim's later `createAtoms()` call reverts with:

```text
MultiVault_AtomExists
```

### Triple front-running

The attacker submits the same subject, predicate, and object tuple first and receives:

```text
attacker triple shares:
19999999999998000000
```

The victim receives no shares:

```text
victim triple shares:
0
```

The victim's later `createTriples()` call reverts with:

```text
MultiVault_TripleExists
```

The control test confirms that the victim receives the initial shares when the victim's creation transaction executes first.

## Impact

An attacker can copy pending atom or triple creation data and become the first creator of the corresponding semantic vault.

This can:

* squat valuable semantic atom IDs;
* squat valuable semantic triple IDs;
* deny the intended creator's transaction;
* cause the victim to waste transaction gas;
* capture the initial vault-share position;
* associate the creation event with the attacker;
* force the victim to use a different semantic identifier or interact with the attacker's vault.

## Severity

**Medium**

The attack allows an unprivileged user to claim deterministic semantic identifiers and the associated initial vault shares before the legitimate creator.

The attack is practical whenever valuable atom or triple creation transactions are visible in the public mempool.

## Recommendation

Use a commit-reveal mechanism for atom and triple creation.

During the commit phase, the creator submits a hidden commitment:

```solidity
bytes32 commitment = keccak256(
    abi.encode(
        msg.sender,
        atomData,
        salt
    )
);
```

During the reveal phase, the contract verifies that the caller previously submitted the matching commitment before creating the atom.

For triples, the commitment should bind:

```solidity
bytes32 commitment = keccak256(
    abi.encode(
        msg.sender,
        subjectId,
        predicateId,
        objectId,
        salt
    )
);
```

Alternative protections include:

1. Signed creator authorization.
2. Temporary identifier reservations.
3. Binding creation rights to the intended receiver.
4. Using private transaction submission for valuable creations.
5. Allowing a creator to pre-register a commitment before revealing semantic data.

## References

* [Intuition repository](https://github.com/code-423n4/2026-03-intuition)
* [`MultiVault.sol`](https://github.com/code-423n4/2026-03-intuition/blob/314b7d4d9ccbaf27e4484a6c0706af83d3f75f36/src/protocol/MultiVault.sol)
* [`createAtoms()`](https://github.com/code-423n4/2026-03-intuition/blob/314b7d4d9ccbaf27e4484a6c0706af83d3f75f36/src/protocol/MultiVault.sol#L2809-L2832)
* [`_createAtom()`](https://github.com/code-423n4/2026-03-intuition/blob/314b7d4d9ccbaf27e4484a6c0706af83d3f75f36/src/protocol/MultiVault.sol#L2907-L2963)
* [`createTriples()`](https://github.com/code-423n4/2026-03-intuition/blob/314b7d4d9ccbaf27e4484a6c0706af83d3f75f36/src/protocol/MultiVault.sol#L2982-L3007)
* [`_createTriple()`](https://github.com/code-423n4/2026-03-intuition/blob/314b7d4d9ccbaf27e4484a6c0706af83d3f75f36/src/protocol/MultiVault.sol#L3103-L3176)
* [Foundry PoC — Issue #12](https://github.com/HUODONGREN/front-run_0day/issues/12)
