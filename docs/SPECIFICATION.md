# CIP-113 Programmable Tokens — Specification

## Overview

CIP-113 defines a framework for programmable token-like assets on Cardano. Unlike native tokens (which flow freely once minted), programmable tokens enforce custom transfer logic on every movement — enabling compliance controls, blacklists, transfer limits, royalties, and more.

**Key insight:** All programmable tokens share a single payment credential (`programmable_logic_base`), with ownership determined by per-holder stake credentials. This enables a central coordinator to enforce transfer rules without modifying the core framework.

**Reference implementations:**
- Cardano Foundation: [cip113-programmable-tokens](https://github.com/cardano-foundation/cip113-programmable-tokens) (Aiken + Java)
- IOG: [wsc-poc](https://github.com/input-output-hk/wsc-poc) (Plutarch + Lucid, CIP-143 variant)
- Community: [ruhil6789/CIP-0113](https://github.com/ruhil6789/CIP-0113) (Aiken)

**CIP numbering note:** Originally CIP-113, the IOG reference calls it CIP-143. Both refer to the same programmable token standard. We use CIP-113 to match the Cardano Foundation repo.

---

## Architecture

### Ownership Model: Shared Payment + Unique Stake

```
Cardano Address = Payment Credential    + Stake Credential
                  ─────────────────      ────────────────
                  programmable_logic_base  Unique per holder
                  (shared by ALL tokens)   (determines ownership)
```

- All programmable tokens live at addresses sharing the same payment credential
- Every spend triggers the same spending validator
- Ownership is determined by the stake credential (vkey or script hash)
- Transfers change the stake credential, not the payment credential

### Withdraw-Zero Pattern (Transaction-Level Coordination)

The spending validator (`programmable_logic_base`) is intentionally minimal — it just checks that the global coordinator is invoked:

```aiken
validator programmable_logic_base(stake_cred: Credential) {
  spend(_datum, _redeemer, _own_ref, tx: Transaction) {
    // Just verify the global validator is in the withdrawals
    has_key(tx.withdrawals, stake_cred)
  }
}
```

The heavy lifting happens in `programmable_logic_global` — a stake validator invoked via withdraw-zero. This runs **once per transaction** (not once per input), making multi-input transfers efficient.

A transfer transaction includes:
```
withdrawals:
  - (programmable_logic_global, 0 ADA)  → Core validation
  - (transfer_logic_script,    0 ADA)  → Token-specific rules
```

### Validator Architecture

| Validator | Type | Purpose |
|-----------|------|---------|
| `programmable_logic_base` | Spend | Custody of all programmable token UTxOs. Delegates to global. |
| `programmable_logic_global` | Withdraw | Core coordinator. Validates transfers, checks registry, invokes transfer logic. |
| `protocol_params_mint` | Mint | One-shot mint of protocol parameters NFT. |
| `registry_mint` | Mint | Manages sorted linked list of registered token policies. |
| `registry_spend` | Spend | Guards registry node UTxOs. |
| `issuance_mint` | Mint | Mints/burns programmable tokens (parameterized per token type). |
| `issuance_cbor_hex_mint` | Mint | One-shot mint of reference NFT holding issuance script template. |

**Substandard validators** (pluggable per token type):
- `transfer_logic` — Token-specific transfer rules (whitelist, limits, cooldowns)
- `third_party_transfer_logic` — Admin operations (freeze, seize, force transfer)
- `blacklist_mint`/`blacklist_spend` — Denylist management (freeze-and-seize substandard)

---

## On-Chain Registry

A **sorted linked list** of registered programmable token policies, enabling O(1) membership proofs.

### RegistryNode (inline datum on each node UTxO)

```aiken
type RegistryNode {
  key: ByteArray,                                  // Policy ID
  next: ByteArray,                                 // Next key (sorted order)
  transfer_logic_script: Credential,               // Transfer rules validator
  third_party_transfer_logic_script: Credential,   // Admin operations validator
  global_state_cs: ByteArray,                       // Optional global state NFT
}
```

### Membership Proofs

```aiken
type RegistryProof {
  TokenExists { node_idx: Int }         // node.key == policy_id
  TokenDoesNotExist { node_idx: Int }   // node.key < policy_id < node.next
}
```

- **TokenExists**: Points to the matching registry node via reference input index
- **TokenDoesNotExist**: Points to a "covering node" proving no entry exists (sorted list gap)

Non-programmable tokens in the same transaction use `TokenDoesNotExist` proofs — they pass through without validation.

---

## Types

### Protocol Parameters

```aiken
type ProgrammableLogicGlobalParams {
  registry_node_cs: PolicyId,    // Currency symbol of registry NFTs
  prog_logic_cred: Credential,   // Payment credential of programmable_logic_base
}
```

### Redeemers

**Global validator:**
```aiken
type ProgrammableLogicGlobalRedeemer {
  TransferAct { proofs: List<RegistryProof>, mint_proofs: List<RegistryProof> }
  ThirdPartyAct { registry_node_idx: Int, input_idxs: List<Int>,
                  outputs_start_idx: Int, length_input_idxs: Int }
}
```

**Issuance mint:**
```aiken
type SmartTokenMintingAction {
  minting_logic_cred: Credential,   // Credential of minting logic to invoke
}
```

**Registry operations:**
```aiken
type RegistryRedeemer {
  RegistryInit
  RegistryInsert { key: ByteArray, hashed_param: ByteArray }
}
```

---

## Transaction Flows

### Transfer

1. Build tx spending programmable token UTxOs (from `programmable_logic_base` address)
2. Include `withdraw 0` for `programmable_logic_global` with `TransferAct` redeemer
3. Include `withdraw 0` for the token's `transfer_logic_script`
4. Include registry nodes as reference inputs (for membership proofs)
5. Include protocol params NFT as reference input
6. Outputs at `programmable_logic_base` addresses (with new stake credentials)
7. Each input's stake credential must authorize (signature or script invocation)

**Invariant:** Total programmable token value in outputs ≥ total from authorized inputs

### Token Registration

1. Mint registry node NFT via `registry_mint` with `RegistryInsert` redeemer
2. Spend the covering node (where `covering.key < new_key < covering.next`)
3. Output two nodes: updated covering node + new node (maintaining sort order)
4. Validate policy ID matches issuance script template (`IssuanceCborHex`)

### Third-Party Action (Seize/Freeze)

1. Include `withdraw 0` for `programmable_logic_global` with `ThirdPartyAct`
2. Include `withdraw 0` for the token's `third_party_transfer_logic_script`
3. Specify input indices and output start index
4. Each output preserves the victim's address and datum, minus seized tokens
5. Balance invariant: total output tokens ≥ total input tokens (seized tokens stay in system)

---

## Security Properties

1. **NFT authenticity** — Every registry/denylist node authenticated by one-shot NFT
2. **Ownership enforcement** — ALL inputs from `prog_logic_cred` must be authorized by stake credential
3. **Value preservation** — Tokens cannot escape the programmable logic address
4. **Sorted list integrity** — `node.key < node.next` maintained across all operations
5. **One-shot policies** — Protocol params, registry, and template NFTs can only be minted once
6. **Anti-DDOS** — Third-party actions must actually change token balances (no-op prevention)

---

## CIP Dependencies

- **CIP-31** (Reference Inputs) — Registry nodes and protocol params read as reference inputs
- **CIP-32** (Inline Datums) — All node datums are inline for direct access
- **CIP-33** (Reference Scripts) — Can deploy validators as reference scripts for efficiency
- **Plutus V3** — Required for withdraw handler type and modern script features

---

## ADAvault Use Cases to Explore

### 1. SPO Loyalty Token
- Mint loyalty tokens to delegators proportional to delegation duration
- Transfer restrictions: only between ADAvault delegators
- Burn on undelegation (or cooldown period)
- Potential: tiered vault access based on loyalty token balance

### 2. Compliance-Gated Pool Token
- Represent pool shares as programmable tokens
- KYC/AML compliance via denylist (freeze-and-seize substandard)
- Dividend distribution via token balance snapshots
- Transfer only with operator approval

### 3. Vault Receipt Token
- Issue programmable receipt when ADA locked in vault
- Receipt tracks lock amount, timestamp, pool assignment
- Transfer restrictions prevent selling receipts without unlocking
- Automatic metadata updates on vault operations

---

## Implementation Plan

### Phase 1: Core Framework ✓
- [x] Implement types module (all shared types)
- [x] Implement `programmable_logic_base` (spend → delegate to global) — 3 tests
- [x] Implement `programmable_logic_global` (withdraw-zero coordinator) — 6 tests
- [x] Implement `protocol_params_mint` (one-shot bootstrap) — 5 tests
- [x] Bug fix: `validate_single_cs` for `TokenExists` now uses `expect` to enforce transfer logic

### Phase 2: Registry ✓
- [x] Implement `registry_mint` (init + insert with sorted linked list) — 7 tests
- [x] Implement `registry_spend` (guard nodes, delegates to mint policy) — 3 tests
- [x] Implement `issuance_mint` (parameterized per token) — 4 tests
- [x] Implement `issuance_cbor_hex_mint` (template reference NFT) — 5 tests

### Phase 3: Substandard — Transfer Logic ✓
- [x] Implement `transfer_logic` (open transfer with admin auth) — 3 tests
- [x] Implement `third_party_transfer_logic` (admin freeze/seize) — 4 tests

### Phase 4: Use Case — SPO Loyalty Token ✓
- [x] `loyalty_transfer_logic` — whitelist-based, scoped to loyalty policy — 5 tests
- [x] `loyalty_minting_logic` — admin-controlled minting — 3 tests
- [ ] E2E tests on preview testnet — future
- [ ] Off-chain integration (MeshJS) — future

### Phase 5: Skill Extension ✓
- [x] Document CIP-113 patterns in aiken-skill (patterns.md)
- [x] Document Aiken learnings in aiken-skill (gotchas.md)
- [ ] Add off-chain integration guide — future

**Total: 12 validators, 48 tests, 0 errors, 0 warnings**

---

## Open Questions

1. **Wallet integration** — How do wallets discover balances at shared script addresses? Need stake credential resolution.
2. **Gas costs** — How expensive are multi-proof transfers? Benchmark against direct token transfers.
3. **Registry scaling** — How does the sorted linked list perform with 100+ registered tokens? O(n) for traversal, O(1) for proof.
4. **Composability** — Can programmable tokens interact with DeFi protocols that expect native tokens?
5. **Migration** — Can existing native tokens be "wrapped" into programmable equivalents?
