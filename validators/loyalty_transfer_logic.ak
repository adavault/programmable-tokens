/// SPO Loyalty Token — Whitelist Transfer Logic
///
/// Custom transfer logic for the ADAvault loyalty token.
/// Only whitelisted stake credentials (delegators) can hold or receive
/// loyalty tokens. The whitelist is stored as an inline datum on a
/// reference UTxO marked by the global_state_cs NFT.
///
/// Scoped: only checks addresses that actually hold loyalty tokens,
/// so other programmable tokens can transfer freely in the same tx.
///
/// Parameters:
///   loyalty_policy — the issuance policy ID for the loyalty token
///   whitelist_cs   — NFT policy marking the whitelist reference UTxO
///   prog_logic_cred — the shared programmable logic payment credential

use aiken/collection/list
use cardano/address
use cardano/address.{Address, Credential, Inline, Script, VerificationKey}
use cardano/assets
use cardano/assets.{PolicyId}
use cardano/transaction.{InlineDatum, Input, Output, Transaction, placeholder}
use programmable_tokens/utils.{expect_inline_datum, has_currency_symbol}

validator loyalty_transfer_logic(
  loyalty_policy: PolicyId,
  whitelist_cs: PolicyId,
  prog_logic_cred: Credential,
) {
  withdraw(_redeemer: Data, _account: Credential, tx: Transaction) {
    // Find whitelist in reference inputs
    expect Some(whitelist_ref) =
      list.find(
        tx.reference_inputs,
        fn(input) { has_currency_symbol(input.output.value, whitelist_cs) },
      )
    let datum = expect_inline_datum(whitelist_ref.output)
    expect approved: List<ByteArray> = datum

    // Inputs: loyalty token holders must be whitelisted
    let inputs_ok =
      list.all(
        tx.inputs,
        fn(input) {
          check_if_loyalty_holder(
            input.output.address,
            input.output.value,
            loyalty_policy,
            prog_logic_cred,
            approved,
          )
        },
      )

    // Outputs: loyalty token recipients must be whitelisted
    let outputs_ok =
      list.all(
        tx.outputs,
        fn(output) {
          check_if_loyalty_holder(
            output.address,
            output.value,
            loyalty_policy,
            prog_logic_cred,
            approved,
          )
        },
      )

    inputs_ok && outputs_ok
  }

  else(_) {
    fail
  }
}

/// Check if an address holding loyalty tokens has a whitelisted stake credential.
/// Returns True if:
///   - Address is not at prog_logic_cred (not a programmable token address), OR
///   - Address doesn't hold loyalty tokens (other programmable tokens are fine), OR
///   - Address has a whitelisted VK stake credential
fn check_if_loyalty_holder(
  addr: Address,
  value: assets.Value,
  loyalty_policy: PolicyId,
  prog_logic_cred: Credential,
  approved: List<ByteArray>,
) -> Bool {
  let at_prog_logic = addr.payment_credential == prog_logic_cred
  let has_loyalty = has_currency_symbol(value, loyalty_policy)
  if at_prog_logic && has_loyalty {
    // Must have a whitelisted VK stake credential
    expect Some(Inline(VerificationKey(pkh))) = addr.stake_credential
    list.has(approved, pkh)
  } else {
    True
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const t_loyalty_policy =
  #"44444444444444444444444444444444444444444444444444444444"

const t_whitelist_cs =
  #"55555555555555555555555555555555555555555555555555555555"

const t_prog_logic_hash =
  #"33333333333333333333333333333333333333333333333333333333"

const t_alice_pkh =
  #"aa111111111111111111111111111111111111111111111111111111"

const t_bob_pkh =
  #"bb222222222222222222222222222222222222222222222222222222"

const t_charlie_pkh =
  #"cc333333333333333333333333333333333333333333333333333333"

const t_own_hash =
  #"99999999999999999999999999999999999999999999999999999999"

fn t_prog_addr(pkh: ByteArray) -> Address {
  Address {
    payment_credential: Script(t_prog_logic_hash),
    stake_credential: Some(Inline(VerificationKey(pkh))),
  }
}

fn t_whitelist_ref(approved: List<ByteArray>) -> Input {
  Input {
    output_reference: transaction.OutputReference {
      transaction_id: #"0000000000000000000000000000000000000000000000000000000000000000",
      output_index: 0,
    },
    output: Output {
      address: address.from_verification_key(t_alice_pkh),
      value: assets.from_lovelace(2_000_000)
        |> assets.add(t_whitelist_cs, "Whitelist", 1),
      datum: InlineDatum(approved),
      reference_script: None,
    },
  }
}

fn t_loyalty_input(pkh: ByteArray, qty: Int) -> Input {
  Input {
    output_reference: transaction.OutputReference {
      transaction_id: #"0101010101010101010101010101010101010101010101010101010101010101",
      output_index: 0,
    },
    output: Output {
      address: t_prog_addr(pkh),
      value: assets.from_lovelace(2_000_000)
        |> assets.add(t_loyalty_policy, "LOYAL", qty),
      datum: transaction.NoDatum,
      reference_script: None,
    },
  }
}

fn t_loyalty_output(pkh: ByteArray, qty: Int) -> Output {
  Output {
    address: t_prog_addr(pkh),
    value: assets.from_lovelace(2_000_000)
      |> assets.add(t_loyalty_policy, "LOYAL", qty),
    datum: transaction.NoDatum,
    reference_script: None,
  }
}

// Alice and Bob are whitelisted, Charlie is not
fn t_approved() -> List<ByteArray> {
  [t_alice_pkh, t_bob_pkh]
}

test transfer_between_whitelisted_succeeds() {
  let tx =
    Transaction {
      ..placeholder,
      reference_inputs: [t_whitelist_ref(t_approved())],
      inputs: [t_loyalty_input(t_alice_pkh, 100)],
      outputs: [t_loyalty_output(t_bob_pkh, 100)],
    }
  loyalty_transfer_logic.withdraw(
    t_loyalty_policy,
    t_whitelist_cs,
    Script(t_prog_logic_hash),
    Void,
    Script(t_own_hash),
    tx,
  )
}

test transfer_to_non_whitelisted_fails() fail {
  let tx =
    Transaction {
      ..placeholder,
      reference_inputs: [t_whitelist_ref(t_approved())],
      inputs: [t_loyalty_input(t_alice_pkh, 100)],
      outputs: [t_loyalty_output(t_charlie_pkh, 100)],
    }
  loyalty_transfer_logic.withdraw(
    t_loyalty_policy,
    t_whitelist_cs,
    Script(t_prog_logic_hash),
    Void,
    Script(t_own_hash),
    tx,
  )
}

test transfer_from_non_whitelisted_fails() fail {
  let tx =
    Transaction {
      ..placeholder,
      reference_inputs: [t_whitelist_ref(t_approved())],
      inputs: [t_loyalty_input(t_charlie_pkh, 100)],
      outputs: [t_loyalty_output(t_alice_pkh, 100)],
    }
  loyalty_transfer_logic.withdraw(
    t_loyalty_policy,
    t_whitelist_cs,
    Script(t_prog_logic_hash),
    Void,
    Script(t_own_hash),
    tx,
  )
}

test non_loyalty_token_ignores_whitelist() {
  // An output at prog_logic_cred WITHOUT loyalty tokens is not checked
  let other_policy =
    #"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  let tx =
    Transaction {
      ..placeholder,
      reference_inputs: [t_whitelist_ref(t_approved())],
      inputs: [t_loyalty_input(t_alice_pkh, 100)],
      outputs: [
        t_loyalty_output(t_bob_pkh, 100),
        // Charlie gets OTHER tokens — not loyalty, so not checked
        Output {
          address: t_prog_addr(t_charlie_pkh),
          value: assets.from_lovelace(2_000_000)
            |> assets.add(other_policy, "OTHER", 50),
          datum: transaction.NoDatum,
          reference_script: None,
        },
      ],
    }
  loyalty_transfer_logic.withdraw(
    t_loyalty_policy,
    t_whitelist_cs,
    Script(t_prog_logic_hash),
    Void,
    Script(t_own_hash),
    tx,
  )
}

test transfer_fails_without_whitelist_ref() fail {
  let tx =
    Transaction {
      ..placeholder,
      reference_inputs: [],
      inputs: [t_loyalty_input(t_alice_pkh, 100)],
      outputs: [t_loyalty_output(t_bob_pkh, 100)],
    }
  loyalty_transfer_logic.withdraw(
    t_loyalty_policy,
    t_whitelist_cs,
    Script(t_prog_logic_hash),
    Void,
    Script(t_own_hash),
    tx,
  )
}
