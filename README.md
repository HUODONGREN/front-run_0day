# front-run_0day
For security reasons, we disclose contracts that may be vulnerable to front-running exploits.
## Vulnerability Reports

| Project | Contract | Finding | Severity | Report | PoC |
|---|---|---|---|---|---|
| Chainlink Payment Abstraction V2 | BaseAuction.sol | Auction inventory can be preempted by an earlier bid | Low / Informational | [Report](./reports/2026-03-chainlink/BaseAuction-inventory-front-running.md) | [Issue #7](https://github.com/HUODONGREN/front-run_0day/issues/7) |
| Chainlink Payment Abstraction V2 | GPV2CompatibleAuction.sol | Direct bid can invalidate a CoW order by consuming shared inventory | Informational / Known limitation | [Report](./reports/2026-03-chainlink/GPV2CompatibleAuction-cow-order-inventory-preemption.md) | [PoC #8](https://github.com/HUODONGREN/front-run_0day/issues/8) |
