use aiken/collection/list
use cardano/address.{Credential, Script}
use cardano/assets
use cardano/transaction.{Transaction, placeholder}
use programmable_tokens/types.{SmartTokenMintingAction}
use programmable_tokens/utils.{has_key}

/// CIP-113 Issuance Mint
///
/// Parameterized minting policy for programmable tokens. Each programmable
/// token type deploys its own instance of this validator.
///
/// Minting/burning requires the minting logic script to be invoked via
/// withdraw-zero — the minting logic validator enforces token-specific rules
/// (e.g., max supply, authorized minters, schedule constraints).
///
/// Parameterized by the programmable_logic_global stake credential, so that
/// the global coordinator can verify this policy against the registry.
validator issuance_mint(global_cred: Credential) {
  mint(
    redeemer: SmartTokenMintingAction,
    _policy_id: assets.PolicyId,
    tx: Transaction,
  ) {
    // Global coordinator must be invoked (ensures registry validation)
    let global_invoked =
      list.any(
        tx.withdrawals,
        fn(wdrl) {
          let Pair(cred, _amount) = wdrl
          cred == global_cred
        },
      )

    // Minting logic script must be invoked (token-specific rules)
    let minting_logic_invoked =
      has_key(tx.withdrawals, redeemer.minting_logic_cred)

    global_invoked? && minting_logic_invoked?
  }

  else(_) {
    fail
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const t_global_hash =
  #"11111111111111111111111111111111111111111111111111111111"

const t_minting_logic_hash =
  #"22222222222222222222222222222222222222222222222222222222"

const t_policy = #"33333333333333333333333333333333333333333333333333333333"

test mint_succeeds_with_both_withdrawals() {
  let tx =
    Transaction {
      ..placeholder,
      mint: assets.from_asset(t_policy, "Token", 1000),
      withdrawals: [
        Pair(Script(t_global_hash), 0),
        Pair(Script(t_minting_logic_hash), 0),
      ],
    }
  let redeemer =
    SmartTokenMintingAction { minting_logic_cred: Script(t_minting_logic_hash) }
  issuance_mint.mint(Script(t_global_hash), redeemer, t_policy, tx)
}

test mint_fails_without_global() fail {
  let tx =
    Transaction {
      ..placeholder,
      mint: assets.from_asset(t_policy, "Token", 1000),
      withdrawals: [Pair(Script(t_minting_logic_hash), 0)],
    }
  let redeemer =
    SmartTokenMintingAction { minting_logic_cred: Script(t_minting_logic_hash) }
  issuance_mint.mint(Script(t_global_hash), redeemer, t_policy, tx)
}

test mint_fails_without_minting_logic() fail {
  let tx =
    Transaction {
      ..placeholder,
      mint: assets.from_asset(t_policy, "Token", 1000),
      withdrawals: [Pair(Script(t_global_hash), 0)],
    }
  let redeemer =
    SmartTokenMintingAction { minting_logic_cred: Script(t_minting_logic_hash) }
  issuance_mint.mint(Script(t_global_hash), redeemer, t_policy, tx)
}

test burn_succeeds_with_both_withdrawals() {
  let tx =
    Transaction {
      ..placeholder,
      mint: assets.from_asset(t_policy, "Token", -500),
      withdrawals: [
        Pair(Script(t_global_hash), 0),
        Pair(Script(t_minting_logic_hash), 0),
      ],
    }
  let redeemer =
    SmartTokenMintingAction { minting_logic_cred: Script(t_minting_logic_hash) }
  issuance_mint.mint(Script(t_global_hash), redeemer, t_policy, tx)
}
