use cardano/assets.{PolicyId}
use cardano/transaction.{Transaction, placeholder}
use programmable_tokens/utils.{has_currency_symbol}

/// CIP-113 Registry Spend
///
/// Guards registry node UTxOs. Allows spending only when the registry mint
/// policy is active in the transaction — the mint validator handles all
/// complex validation (sort order, datum integrity, etc.).
///
/// Parameterized by the registry mint policy ID.
validator registry_spend(registry_mint_cs: PolicyId) {
  spend(_datum: Option<Data>, _redeemer: Data, _own_ref: Data, tx: Transaction) {
    // Registry nodes can only be spent when a registry mint operation is active.
    // The mint validator ensures linked list invariants are maintained.
    has_currency_symbol(tx.mint, registry_mint_cs)
  }

  else(_) {
    fail
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const t_registry_cs =
  #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

test spend_succeeds_when_mint_active() {
  let tx =
    Transaction {
      ..placeholder,
      mint: assets.from_asset(t_registry_cs, "NewNode", 1),
    }
  registry_spend.spend(t_registry_cs, None, Void, Void, tx)
}

test spend_fails_without_mint() fail {
  registry_spend.spend(t_registry_cs, None, Void, Void, placeholder)
}

test spend_fails_with_wrong_policy() fail {
  let wrong_cs = #"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  let tx =
    Transaction {
      ..placeholder,
      mint: assets.from_asset(wrong_cs, "NewNode", 1),
    }
  registry_spend.spend(t_registry_cs, None, Void, Void, tx)
}
