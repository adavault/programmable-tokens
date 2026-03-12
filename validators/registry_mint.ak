use aiken/collection/dict
use aiken/collection/list
use cardano/address
use cardano/assets
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Transaction, placeholder,
}
use programmable_tokens/types.{
  RegistryInit, RegistryInsert, RegistryNode, RegistryRedeemer, origin_node_tn,
}
use programmable_tokens/utils.{
  bytearray_lt, expect_inline_datum, has_currency_symbol,
}

/// CIP-113 Registry Mint
///
/// Minting policy for the sorted linked list registry of programmable token policies.
/// Each registry node is a UTxO holding an NFT from this policy plus an inline RegistryNode datum.
///
/// Operations:
///   RegistryInit — Create the origin (sentinel) node. One-shot via UTxO ref.
///   RegistryInsert — Insert a new token policy. Splits a covering node.
///
/// Parameterized by a UTxO reference consumed during init (one-shot guarantee).
validator registry_mint(utxo_ref: OutputReference) {
  mint(redeemer: RegistryRedeemer, policy_id: assets.PolicyId, tx: Transaction) {
    when redeemer is {
      RegistryInit -> validate_init(utxo_ref, policy_id, tx)
      RegistryInsert { key, .. } -> validate_insert(policy_id, key, tx)
    }
  }

  else(_) {
    fail
  }
}

// ---------------------------------------------------------------------------
// Init — bootstrap the registry with a sentinel origin node
// ---------------------------------------------------------------------------

fn validate_init(
  utxo_ref: OutputReference,
  policy_id: assets.PolicyId,
  tx: Transaction,
) -> Bool {
  // One-shot: parameterized UTxO must be consumed
  let utxo_consumed =
    list.any(tx.inputs, fn(input) { input.output_reference == utxo_ref })

  // Must mint exactly 1 origin token
  let minted = assets.tokens(tx.mint, policy_id)
  let correct_mint = dict.to_pairs(minted) == [Pair(origin_node_tn, 1)]

  // No existing registry nodes should be spent
  let no_registry_inputs = count_registry_inputs(tx.inputs, policy_id) == 0

  // Output must have origin NFT with correct sentinel datum
  expect Some(origin_output) =
    find_output_with_token(tx.outputs, policy_id, origin_node_tn)
  let datum = expect_inline_datum(origin_output)
  expect origin_node: RegistryNode = datum
  let correct_datum = origin_node.key == #"" && origin_node.next == #""

  utxo_consumed? && correct_mint? && no_registry_inputs? && correct_datum?
}

// ---------------------------------------------------------------------------
// Insert — add a new token policy to the sorted linked list
// ---------------------------------------------------------------------------

fn validate_insert(
  policy_id: assets.PolicyId,
  key: ByteArray,
  tx: Transaction,
) -> Bool {
  // Must mint exactly 1 token with the new key as token name
  let minted = assets.tokens(tx.mint, policy_id)
  expect dict.to_pairs(minted) == [Pair(key, 1)]

  // Exactly 1 registry node must be spent (the covering node)
  expect count_registry_inputs(tx.inputs, policy_id) == 1

  // Find covering node: must have key < new_key, and either end-of-list or new_key < next
  let covering_node = find_covering_node(tx.inputs, policy_id, key)

  // Find outputs: updated covering node + new node
  expect Some(covering_output) =
    find_output_with_token(tx.outputs, policy_id, covering_node.key)
  expect Some(new_output) = find_output_with_token(tx.outputs, policy_id, key)

  // Covering node: only next pointer changes → points to new key
  let covering_datum = expect_inline_datum(covering_output)
  expect updated_covering: RegistryNode = covering_datum
  let expected_covering = RegistryNode { ..covering_node, next: key }
  expect updated_covering == expected_covering

  // New node: key + next = old covering.next (preserves sort order)
  let new_datum = expect_inline_datum(new_output)
  expect new_node: RegistryNode = new_datum
  expect new_node.key == key
  expect new_node.next == covering_node.next

  True
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Count inputs that hold a registry NFT.
fn count_registry_inputs(inputs: List<Input>, policy_id: assets.PolicyId) -> Int {
  list.count(
    inputs,
    fn(input) { has_currency_symbol(input.output.value, policy_id) },
  )
}

/// Find the covering node in inputs for a given key.
/// Covering node satisfies: node.key < key AND (node.next == "" OR key < node.next)
fn find_covering_node(
  inputs: List<Input>,
  policy_id: assets.PolicyId,
  key: ByteArray,
) -> RegistryNode {
  expect Some(input) =
    list.find(
      inputs,
      fn(input) {
        if has_currency_symbol(input.output.value, policy_id) {
          let datum = expect_inline_datum(input.output)
          expect node: RegistryNode = datum
          let key_ok = bytearray_lt(node.key, key)
          let next_ok = node.next == #"" || bytearray_lt(key, node.next)
          key_ok && next_ok
        } else {
          False
        }
      },
    )
  let datum = expect_inline_datum(input.output)
  expect node: RegistryNode = datum
  node
}

/// Find the first output containing a specific registry token.
fn find_output_with_token(
  outputs: List<Output>,
  policy_id: assets.PolicyId,
  token_name: ByteArray,
) -> Option<Output> {
  list.find(
    outputs,
    fn(output) {
      let tokens = assets.tokens(output.value, policy_id)
      dict.get(tokens, token_name) == Some(1)
    },
  )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const t_registry_policy =
  #"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

const t_utxo_ref =
  OutputReference {
    transaction_id: #"0000000000000000000000000000000000000000000000000000000000000001",
    output_index: 0,
  }

const t_holder_pkh = #"11111111111111111111111111111111111111111111111111111111"

const t_transfer_logic_hash =
  #"22222222222222222222222222222222222222222222222222222222"

const t_third_party_hash =
  #"33333333333333333333333333333333333333333333333333333333"

fn t_seed_input() -> transaction.Input {
  transaction.Input {
    output_reference: t_utxo_ref,
    output: Output {
      address: address.from_verification_key(t_holder_pkh),
      value: assets.from_lovelace(5_000_000),
      datum: transaction.NoDatum,
      reference_script: None,
    },
  }
}

fn t_origin_datum() -> RegistryNode {
  RegistryNode {
    key: #"",
    next: #"",
    transfer_logic_script: address.Script(t_transfer_logic_hash),
    third_party_transfer_logic_script: address.Script(t_third_party_hash),
    global_state_cs: #"",
  }
}

fn t_origin_output() -> Output {
  Output {
    address: address.from_verification_key(t_holder_pkh),
    value: assets.from_lovelace(2_000_000)
      |> assets.add(t_registry_policy, origin_node_tn, 1),
    datum: InlineDatum(t_origin_datum()),
    reference_script: None,
  }
}

test init_succeeds() {
  let tx =
    Transaction {
      ..placeholder,
      inputs: [t_seed_input()],
      outputs: [t_origin_output()],
      mint: assets.from_asset(t_registry_policy, origin_node_tn, 1),
    }
  registry_mint.mint(t_utxo_ref, RegistryInit, t_registry_policy, tx)
}

test init_fails_without_utxo() fail {
  let wrong_ref =
    OutputReference {
      transaction_id: #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      output_index: 0,
    }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [t_seed_input()],
      outputs: [t_origin_output()],
      mint: assets.from_asset(t_registry_policy, origin_node_tn, 1),
    }
  registry_mint.mint(wrong_ref, RegistryInit, t_registry_policy, tx)
}

test init_fails_with_wrong_datum() fail {
  let bad_output =
    Output {
      ..t_origin_output(),
      datum: InlineDatum(RegistryNode { ..t_origin_datum(), key: #"abcd" }),
    }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [t_seed_input()],
      outputs: [bad_output],
      mint: assets.from_asset(t_registry_policy, origin_node_tn, 1),
    }
  registry_mint.mint(t_utxo_ref, RegistryInit, t_registry_policy, tx)
}

// -- Insert tests --

const t_new_key = #"44444444444444444444444444444444444444444444444444444444"

fn t_covering_input() -> transaction.Input {
  transaction.Input {
    output_reference: OutputReference {
      transaction_id: #"0202020202020202020202020202020202020202020202020202020202020202",
      output_index: 0,
    },
    output: Output {
      address: address.from_verification_key(t_holder_pkh),
      value: assets.from_lovelace(2_000_000)
        |> assets.add(t_registry_policy, origin_node_tn, 1),
      datum: InlineDatum(t_origin_datum()),
      reference_script: None,
    },
  }
}

fn t_updated_covering_output() -> Output {
  Output {
    address: address.from_verification_key(t_holder_pkh),
    value: assets.from_lovelace(2_000_000)
      |> assets.add(t_registry_policy, origin_node_tn, 1),
    datum: InlineDatum(RegistryNode { ..t_origin_datum(), next: t_new_key }),
    reference_script: None,
  }
}

fn t_new_node_output() -> Output {
  Output {
    address: address.from_verification_key(t_holder_pkh),
    value: assets.from_lovelace(2_000_000)
      |> assets.add(t_registry_policy, t_new_key, 1),
    datum: InlineDatum(
      RegistryNode {
        key: t_new_key,
        next: #"",
        transfer_logic_script: address.Script(t_transfer_logic_hash),
        third_party_transfer_logic_script: address.Script(t_third_party_hash),
        global_state_cs: #"",
      },
    ),
    reference_script: None,
  }
}

fn t_insert_redeemer() -> RegistryRedeemer {
  RegistryInsert { key: t_new_key, hashed_param: #"" }
}

test insert_succeeds() {
  let tx =
    Transaction {
      ..placeholder,
      inputs: [t_covering_input()],
      outputs: [t_updated_covering_output(), t_new_node_output()],
      mint: assets.from_asset(t_registry_policy, t_new_key, 1),
    }
  registry_mint.mint(t_utxo_ref, t_insert_redeemer(), t_registry_policy, tx)
}

test insert_fails_wrong_sort_order() fail {
  // Try to insert a key that is LESS than the covering node's key
  // Origin has key="" and next="", so any non-empty key should work
  // But if covering has key="44..." and next="", a key < "44..." should fail
  let higher_covering =
    transaction.Input {
      output_reference: OutputReference {
        transaction_id: #"0303030303030303030303030303030303030303030303030303030303030303",
        output_index: 0,
      },
      output: Output {
        address: address.from_verification_key(t_holder_pkh),
        value: assets.from_lovelace(2_000_000)
          |> assets.add(t_registry_policy, t_new_key, 1),
        datum: InlineDatum(
          RegistryNode {
            key: t_new_key,
            next: #"",
            transfer_logic_script: address.Script(t_transfer_logic_hash),
            third_party_transfer_logic_script: address.Script(
              t_third_party_hash,
            ),
            global_state_cs: #"",
          },
        ),
        reference_script: None,
      },
    }
  // Try inserting key "11..." which is less than covering key "44..."
  let small_key = #"11111111111111111111111111111111111111111111111111111111"
  let tx =
    Transaction {
      ..placeholder,
      inputs: [higher_covering],
      outputs: [],
      mint: assets.from_asset(t_registry_policy, small_key, 1),
    }
  registry_mint.mint(
    t_utxo_ref,
    RegistryInsert { key: small_key, hashed_param: #"" },
    t_registry_policy,
    tx,
  )
}

test insert_fails_covering_node_not_updated() fail {
  // Covering output datum still has next="" instead of next=t_new_key
  let bad_covering_output =
    Output {
      address: address.from_verification_key(t_holder_pkh),
      value: assets.from_lovelace(2_000_000)
        |> assets.add(t_registry_policy, origin_node_tn, 1),
      datum: InlineDatum(t_origin_datum()),
      reference_script: None,
    }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [t_covering_input()],
      outputs: [bad_covering_output, t_new_node_output()],
      mint: assets.from_asset(t_registry_policy, t_new_key, 1),
    }
  registry_mint.mint(t_utxo_ref, t_insert_redeemer(), t_registry_policy, tx)
}

test insert_middle_succeeds() {
  // Origin → 44... → ""  becomes  Origin → 22... → 44... → ""
  let mid_key = #"22222222222222222222222222222222222222222222222222222222"
  // Covering node: origin with next=44...
  let origin_with_next = RegistryNode { ..t_origin_datum(), next: t_new_key }
  let covering =
    transaction.Input {
      output_reference: OutputReference {
        transaction_id: #"0202020202020202020202020202020202020202020202020202020202020202",
        output_index: 0,
      },
      output: Output {
        address: address.from_verification_key(t_holder_pkh),
        value: assets.from_lovelace(2_000_000)
          |> assets.add(t_registry_policy, origin_node_tn, 1),
        datum: InlineDatum(origin_with_next),
        reference_script: None,
      },
    }
  let updated_covering =
    Output {
      address: address.from_verification_key(t_holder_pkh),
      value: assets.from_lovelace(2_000_000)
        |> assets.add(t_registry_policy, origin_node_tn, 1),
      datum: InlineDatum(RegistryNode { ..origin_with_next, next: mid_key }),
      reference_script: None,
    }
  let new_node =
    Output {
      address: address.from_verification_key(t_holder_pkh),
      value: assets.from_lovelace(2_000_000)
        |> assets.add(t_registry_policy, mid_key, 1),
      datum: InlineDatum(
        RegistryNode {
          key: mid_key,
          next: t_new_key,
          transfer_logic_script: address.Script(t_transfer_logic_hash),
          third_party_transfer_logic_script: address.Script(t_third_party_hash),
          global_state_cs: #"",
        },
      ),
      reference_script: None,
    }
  let tx =
    Transaction {
      ..placeholder,
      inputs: [covering],
      outputs: [updated_covering, new_node],
      mint: assets.from_asset(t_registry_policy, mid_key, 1),
    }
  registry_mint.mint(
    t_utxo_ref,
    RegistryInsert { key: mid_key, hashed_param: #"" },
    t_registry_policy,
    tx,
  )
}
