use aiken/collection/dict
use aiken/collection/list
use cardano/address
use cardano/assets
use cardano/transaction.{InlineDatum, OutputReference, Transaction, placeholder}
use programmable_tokens/types.{IssuanceCborHex}

/// CIP-113 Issuance CBOR Hex Mint
///
/// One-shot minting policy for the reference NFT holding the issuance script
/// template. The output datum (IssuanceCborHex) contains the prefix and postfix
/// bytes of the parameterized issuance_mint script, allowing the registry_mint
/// validator to verify that a registered policy ID matches the expected template.
///
/// Parameterized by a UTxO reference (consumed during mint) to guarantee
/// exactly one instance can ever exist.
/// Token name for the issuance template reference NFT
const issuance_cbor_hex_tn = "IssuanceCborHex"

validator issuance_cbor_hex_mint(utxo_ref: OutputReference) {
  mint(_redeemer: Data, policy_id: assets.PolicyId, tx: Transaction) {
    // The parameterized UTxO must be consumed (one-shot guarantee)
    let utxo_consumed =
      list.any(tx.inputs, fn(input) { input.output_reference == utxo_ref })

    // Must mint exactly 1 token with the template token name
    let minted = assets.tokens(tx.mint, policy_id)
    let correct_mint = dict.to_pairs(minted) == [Pair(issuance_cbor_hex_tn, 1)]

    // Output must contain the NFT with a valid IssuanceCborHex inline datum
    let valid_output =
      list.any(
        tx.outputs,
        fn(output) {
          let has_token =
            dict.get(
              assets.tokens(output.value, policy_id),
              issuance_cbor_hex_tn,
            ) == Some(1)
          if has_token {
            // Verify datum is a valid IssuanceCborHex
            expect InlineDatum(datum) = output.datum
            expect _template: IssuanceCborHex = datum
            True
          } else {
            False
          }
        },
      )

    utxo_consumed? && correct_mint? && valid_output?
  }

  else(_) {
    fail
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const t_utxo_ref =
  OutputReference {
    transaction_id: #"0000000000000000000000000000000000000000000000000000000000000001",
    output_index: 0,
  }

const t_policy =
  #"aabbccddee112233445566778899001122334455667788990011223344556677"

const t_holder_pkh = #"11111111111111111111111111111111111111111111111111111111"

fn t_seed_input() -> transaction.Input {
  transaction.Input {
    output_reference: t_utxo_ref,
    output: transaction.Output {
      address: address.from_verification_key(t_holder_pkh),
      value: assets.from_lovelace(5_000_000),
      datum: transaction.NoDatum,
      reference_script: None,
    },
  }
}

fn t_template_datum() -> IssuanceCborHex {
  IssuanceCborHex {
    prefix_cbor_hex: #"aabbccdd",
    postfix_cbor_hex: #"eeff0011",
  }
}

fn t_template_output() -> transaction.Output {
  transaction.Output {
    address: address.from_verification_key(t_holder_pkh),
    value: assets.from_lovelace(2_000_000)
      |> assets.add(t_policy, issuance_cbor_hex_tn, 1),
    datum: InlineDatum(t_template_datum()),
    reference_script: None,
  }
}

test mint_issuance_cbor_hex_succeeds() {
  let tx =
    Transaction {
      ..placeholder,
      inputs: [t_seed_input()],
      outputs: [t_template_output()],
      mint: assets.from_asset(t_policy, issuance_cbor_hex_tn, 1),
    }
  issuance_cbor_hex_mint.mint(t_utxo_ref, Void, t_policy, tx)
}

test mint_without_utxo_consumed_fails() fail {
  let wrong_ref =
    OutputReference {
      transaction_id: #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      output_index: 0,
    }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [t_seed_input()],
      outputs: [t_template_output()],
      mint: assets.from_asset(t_policy, issuance_cbor_hex_tn, 1),
    }
  issuance_cbor_hex_mint.mint(wrong_ref, Void, t_policy, tx)
}

test mint_wrong_token_name_fails() fail {
  let tx =
    Transaction {
      ..placeholder,
      inputs: [t_seed_input()],
      outputs: [t_template_output()],
      mint: assets.from_asset(t_policy, "WrongName", 1),
    }
  issuance_cbor_hex_mint.mint(t_utxo_ref, Void, t_policy, tx)
}

test mint_without_datum_fails() fail {
  let bad_output =
    transaction.Output {
      address: address.from_verification_key(t_holder_pkh),
      value: assets.from_lovelace(2_000_000)
        |> assets.add(t_policy, issuance_cbor_hex_tn, 1),
      datum: transaction.NoDatum,
      reference_script: None,
    }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [t_seed_input()],
      outputs: [bad_output],
      mint: assets.from_asset(t_policy, issuance_cbor_hex_tn, 1),
    }
  issuance_cbor_hex_mint.mint(t_utxo_ref, Void, t_policy, tx)
}

test mint_quantity_two_fails() fail {
  let tx =
    Transaction {
      ..placeholder,
      inputs: [t_seed_input()],
      outputs: [t_template_output()],
      mint: assets.from_asset(t_policy, issuance_cbor_hex_tn, 2),
    }
  issuance_cbor_hex_mint.mint(t_utxo_ref, Void, t_policy, tx)
}
