# Algorithm 1 Case Study: Onyx Protocol Exploit Analysis

## Background

**Attack Details**:
- **Total Loss**: ~$2M
- **Attack Transaction**: [0xf7c21600452939a81b599017ee24ee0dfd92aaaccd0a55d02819a7658a6ef635](https://etherscan.io/tx/0xf7c21600452939a81b599017ee24ee0dfd92aaaccd0a55d02819a7658a6ef635)
- **Attacker**: [0x085bdff2c522e8637d4154039db8746bb8642bff](https://etherscan.io/address/0x085bdff2c522e8637d4154039db8746bb8642bff)
- **Attack Contract**: [0x526e8e98356194b64eae4c2d443cc8aad367336f](https://etherscan.io/address/0x526e8e98356194b64eae4c2d443cc8aad367336f)

**PoC Complexity**:
- 1,200+ lines of Solidity code
- 3 main contracts (ContractTest, IntermediateContractETH, IntermediateContractToken)
- 15 external contracts involved
- 25 distinct addresses used
- 5-layer deep cross-contract calls
- Dynamic helper contract deployments
- Repeated exploit pattern across 6 different stablecoins

## Algorithm 1 Definition

```solidity
Algorithm 1: Exploit Logic Extraction
Input: PoC source code P
Output: Optimized exploit trace E, Helper functions H

1  A ← ExtractAddresses(P)
   F ← ExtractFunctionCalls(P)
2  InvoGraph ← BuildInvocationFlowGraph(P)
3  foreach node n in InvoGraph do
4    n.layer ← CalculateNestingDepth(n)
5    n.caller ← GetCallerAddress(n, A)
6  end
7  E ← ∅
8  H ← ∅
9  foreach node n in InvoGraph do
10   if n.layer = max({m.layer | m ∈ InvoGraph}) then
11     if n.caller = AttackerAddress then
12       E ← E ∪ {n}
13     else if n.caller ∈ ExternalAddresses then
14       H ← H ∪ {n}
15     end
16   end
17 end
18 return (E, H)
```

## Line-by-Line Algorithm Execution

### Line 1: Extract Addresses and Function Calls

**Extracted Addresses (A)**:
```solidity
// Core Protocol Addresses
AaveV3: 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2
Unitroller: 0x7D61ed92a6778f5ABf5c94085739f1EDAbec2800

// Token Addresses
WETH: 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2
PEPE: 0x6982508145454Ce325dDbE47a25d4ec3d2311933
USDC: 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
USDT: 0xdAC17F958D2ee523a2206206994597C13D831ec7
PAXG: 0x45804880De22913dAFE09f4980848ECE6EcbAf78
DAI: 0x6B175474E89094C44Da98b954EedeAC495271d0F
WBTC: 0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599
LINK: 0x514910771AF9Ca656af840dff83E8264EcF986CA

// Onyx Protocol cTokens
oPEPE: 0x5FdBcD61bC9bd4B6D3FD1F49a5D253165Ea11750
oETHER: 0x714bD93aB6ab2F0bcfD2aEaf46A46719991d0d79
oUSDC: 0x8f35113cFAba700Ed7a907D92B114B44421e412A
oUSDT: 0xbCed4e924f28f43a24ceEDec69eE21ed4D04D2DD
oPAXG: 0x0C19D213e9f2A5cbAA4eC6E8eAC55a22276b0641
oDAI: 0x830DAcD5D0a62afa92c9Bc6878461e9cD317B085
oBTC: 0x1933f1183C421d44d531Ed40A5D2445F6a91646d
oLINK: 0xFEe4428b7f403499C50a6DA947916b71D33142dC

// Uniswap V2 Pairs & Router
Router: 0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D
PEPE_WETH: 0xA43fe16908251ee70EF74718545e4FE6C5cCEc9f
... (7 more pairs)

// Dynamic Addresses (created during execution)
IntermediateContractETH: [Dynamic]
IntermediateContractToken: [Dynamic]
```

**Extracted Function Calls (F)**:
```solidity
// Flash Loan
AaveV3.flashLoanSimple(asset, amount, data, referralCode)

// Token Operations
oPEPE.mint(amount)
oPEPE.redeem(amount)
oPEPE.redeemUnderlying(amount)
oETHER.borrow(amount)
oETHER.liquidateBorrow(borrower, cTokenCollateral)

// DEX Operations
Router.swapExactTokensForTokens(amountIn, amountOutMin, path, to, deadline)


Unitroller.enterMarkets(cTokens)
Unitroller.liquidateCalculateSeizeTokens(cTokenBorrowed, cTokenCollateral, repayAmount)
```

### Line 2: Build Invocation Flow Graph

The transaction replay using Foundry's cast tool generates a 5,359-line invocation trace. The raw invocation trace can be found in `invocation_trace_raw.txt`.

### Steps 3-6: Calculate Nesting Depth and Caller Addresses

For each node in the invocation graph:

| Function Call | Layer | Caller | Caller Type |
|--------------|-------|---------|-------------|
| testExploit() | 0 | Test Framework | External |
| AaveV3.flashLoanSimple() | 1 | ContractTest | Attacker |
| executeOperation() | 2 | AaveV3 | External |
| WETHToPEPE() | 3 | ContractTest | Attacker |
| Router.swapExactTokensForTokens() | 4 | ContractTest | Attacker |
| new IntermediateContractETH() | 3 | ContractTest | Attacker |
| intermediateETH.start() | 3 | ContractTest | Attacker |
| oPEPE.mint(1e18) | 4 | IntermediateContractETH | Attacker |
| oETHER.borrow() | 4 | IntermediateContractETH | Attacker |
| Unitroller.enterMarkets() | 4 | IntermediateContractETH | Attacker |
| Unitroller.liquidateCalculateSeizeTokens() | 4 | IntermediateContractETH | Attacker |
| oETHER.liquidateBorrow() | 3 | ContractTest | Attacker |
| ...... | ...... | ...... | ...... |

### Line 7-17: Classify Functions into E (Exploit) and H (Helper)

The algorithm focuses on the outermost layer (Layer 5 in this case) to identify core exploit logic:

**Exploit Functions (E)** - Functions at max layer called by attacker-controlled addresses:
```javascript
E = {
    // Core manipulation functions
    {
        function: "oPEPE.mint(1e18)",
        layer: 4,
        caller: "IntermediateContractETH"
    },
    {
        function: "oPEPE.redeem(totalSupply - 2)",
        layer: 4,
        caller: "IntermediateContractETH"
    },
    {
        function: "oETHER.borrow(getCash - 1)",
        layer: 4,
        caller: "IntermediateContractETH"
    },
    {
        function: "oETHER.liquidateBorrow(intermediateETH, 1, oPEPE)",
        layer: 3,
        caller: "ContractTest"
    },
    {
        function: "oPEPE.mint(calculatedAmount)",
        layer: 4,
        caller: "IntermediateContractETH"
    },
   ......
}
```

**Helper Functions (H)** - Functions called by external addresses:
```javascript
H = {
    {
        function: "executeOperation()",
        layer: 2,
        caller: "AaveV3"
    },
    {
        function: "Unitroller.liquidateCalculateSeizeTokens()",
        layer: 5,
        caller: "Protocol"
    },
    {
        function: "oPEPE.getAccountSnapshot()",
        layer: 5,
        caller: "Protocol"
    },
   ......
}
```

## Optimization: Removing Redundant Patterns

The algorithm identifies repeated patterns across 6 different tokens:

### Repeated Pattern Structure
```solidity
// Pattern executed for each token (oUSDC, oUSDT, oPAXG, oDAI, oBTC, oLINK):
function exploitToken(ICErc20Delegate onyxToken) {
    1. Deploy IntermediateContractToken
    2. Transfer PEPE to intermediate contract
    3. Call intermediate.start(onyxToken)
    4. Liquidate position with minimal repayment
    5. Redeem inflated oPEPE balance
    6. Swap obtained tokens to WETH
}
```

## Final Optimized Output

### Optimized Exploit Trace (E)
```solidity
1. Flash loan 4000 WETH from Aave
2. Swap WETH → PEPE (acquire collateral)
3. Deploy IntermediateContractETH
4. Transfer PEPE to intermediate contract
5. Execute price manipulation:
   a. Mint minimal oPEPE (1e18)
   b. Redeem almost all liquidity (totalSupply - 2)
   c. Deposit PEPE when exchange rate is manipulated
   d. Enter oPEPE as collateral
   e. Borrow maximum ETH (getCash - 1)
6. Liquidate position with 1 wei repayment
7. Redeem inflated oPEPE balance
8. Swap PEPE → WETH
9. Repay flash loan + fee
```
