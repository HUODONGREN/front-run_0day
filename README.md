# Front-Running Vulnerability Research

This repository contains independently identified and reproduced
transaction-ordering and front-running risks in smart contracts.

A report does not necessarily indicate that the finding has been
acknowledged by the affected project. Some findings may concern
out-of-scope code, publicly known limitations, or design-dependent behavior.
## Vulnerability Reports

| Project | Contract | Finding | Severity | Report | PoC |
|---|---|---|---|---|---|
| Brix Money | DLFToken.sol | Admin blacklist, pause, and burn actions can be front-run by token holders | Medium | [Report](./reports/2025-11-brix-money/DLFToken-admin-action-front-running.md) | [Issue #1](https://github.com/HUODONGREN/front-run_0day/issues/1) |
| Brix Money | StakediTry.sol | Full blacklist can be bypassed by transferring shares before restriction | Medium | [Report](./reports/2025-11-brix-money/StakediTry-full-blacklist-front-running.md) | [Issue #4](https://github.com/HUODONGREN/front-run_0day/issues/4) |
| Brix Money | iTryIssuer.sol | Public vault rebalancing can force instant redemptions into the custodian path | Medium | [Report](./reports/2025-11-brix-money/iTryIssuer-redemption-path-front-running.md) | [Issue #6](https://github.com/HUODONGREN/front-run_0day/issues/6) |
| Merkl | DistributionCreator.sol | Campaign ID can be front-run and squatted with a lower reward amount | Medium | [Report](./reports/2025-11-merkl/DistributionCreator-campaign-id-front-running.md) | [Issue #2](https://github.com/HUODONGREN/front-run_0day/issues/2) |
| Merkl | ReferralRegistry.sol | Referral keys and referrer codes can be front-run and squatted | Medium | [Report](./reports/2025-11-merkl/ReferralRegistry-key-code-front-running.md) | [Issue #11](https://github.com/HUODONGREN/front-run_0day/issues/11) |
| Chainlink Payment Abstraction V2 | BaseAuction.sol | Auction inventory can be preempted by an earlier bid | 	Low-Medium / Medium | [Report](./reports/2026-03-chainlink/BaseAuction-inventory-front-running.md) | [Issue #7](https://github.com/HUODONGREN/front-run_0day/issues/7) |
| Chainlink Payment Abstraction V2 | GPV2CompatibleAuction.sol | Direct bids can consume shared inventory and invalidate pending CoW settlements | Low-Medium / Medium | [Report](./reports/2026-03-chainlink/GPV2CompatibleAuction-cow-order-front-running.md) | [Issue #8](https://github.com/HUODONGREN/front-run_0day/issues/8) |
| Intuition | MultiVault.sol | Atom and triple creation can be front-run to squat semantic vault IDs | Medium | [Report](./reports/2026-03-intuition/MultiVault-semantic-id-front-running.md) | [Issue #12](https://github.com/HUODONGREN/front-run_0day/issues/12) |
| Monetrix | MonetrixVault.sol | Late stakers can capture pending yield between settlement and distribution | Medium | [Report](./reports/2026-04-monetrix/MonetrixVault-pending-yield-front-running.md) | [Issue #9](https://github.com/HUODONGREN/front-run_0day/issues/9) |
| Monetrix | sUSDM.sol | Late deposits can front-run yield injection and capture historical yield | Medium | [Report](./reports/2026-04-monetrix/sUSDM-late-deposit-yield-front-running.md) | [Issue #10](https://github.com/HUODONGREN/front-run_0day/issues/10) |
