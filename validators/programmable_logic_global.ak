/// CIP-113 Programmable Logic Global Stake Validator
///
/// The core coordinator for all programmable token operations.
/// Invoked via withdraw-zero pattern — runs ONCE per transaction,
/// not once per input (unlike spending validators).
///
/// Responsibilities:
/// 1. Look up protocol parameters from reference inputs
/// 2. Sum all authorized inputs from the programmable logic address
/// 3. For each token policy, check registry proofs and invoke transfer logic
/// 4. Verify output values preserve all programmable tokens
///
/// Parameterized by the protocol parameters NFT policy ID.

use aiken/collection/dict.{Dict}
use aiken/collection/dict/strategy
use aiken/collection/list
use cardano/address.{Address, Credential, Inline, Script, VerificationKey}
use cardano/assets.{AssetName, PolicyId}
use cardano/transaction.{InlineDatum, Input, NoDatum, Output, OutputReference,
  Transaction, placeholder}
use programmable_tokens/types.{
  ProgrammableLogicGlobalParams, ProgrammableLogicGlobalRedeemer, RegistryNode,
  RegistryProof, ThirdPartyAct, TokenDoesNotExist, TokenExists, TransferAct,
}
use programmable_tokens/utils.{
  bytearray_lt, elem_at, expect_inline_datum, has_currency_symbol, has_key,
  has_signatory,
}

validator programmable_logic_global(protocol_params_cs: PolicyId) {
  withdraw(
    redeemer: ProgrammableLogicGlobalRedeemer,
    _account: Credential,
    tx: Transaction,
  ) {
    // Step 1: Extract protocol parameters from reference inputs
    expect Some(params_ref) =
      list.find(
        tx.reference_inputs,
        fn(input) {
          has_currency_symbol(input.output.value, protocol_params_cs)
        },
      )
    let params_datum = expect_inline_datum(params_ref.output)
    expect params: ProgrammableLogicGlobalParams = params_datum
    let registry_node_cs = params.registry_node_cs
    let prog_logic_cred = params.prog_logic_cred

    when redeemer is {
      TransferAct { proofs, mint_proofs } ->
        validate_transfer(
          tx,
          prog_logic_cred,
          registry_node_cs,
          proofs,
          mint_proofs,
        )
      ThirdPartyAct {
        registry_node_idx,
        input_idxs,
        outputs_start_idx,
        length_input_idxs,
      } ->
        validate_third_party(
          tx,
          prog_logic_cred,
          registry_node_cs,
          registry_node_idx,
          input_idxs,
          outputs_start_idx,
          length_input_idxs,
        )
    }
  }

  else(_) {
    fail
  }
}

// ---------------------------------------------------------------------------
// Transfer validation
// ---------------------------------------------------------------------------

/// Validate a standard transfer of programmable tokens.
///
/// 1. Sum all inputs from prog_logic_cred (each must be authorized by stake cred)
/// 2. For each token policy, check registry proof and invoke transfer logic
/// 3. Verify outputs at prog_logic_cred contain >= all programmable token value
fn validate_transfer(
  tx: Transaction,
  prog_logic_cred: Credential,
  registry_node_cs: PolicyId,
  proofs: List<RegistryProof>,
  mint_proofs: List<RegistryProof>,
) -> Bool {
  // Sum authorized inputs from programmable logic address
  let input_value = get_signed_prog_value(tx, prog_logic_cred)

  // Check each token policy against registry proofs and filter to programmable tokens
  let prog_input_value =
    check_proofs_and_filter(
      input_value,
      proofs,
      tx,
      registry_node_cs,
    )

  // Check minted/burned programmable tokens against registry
  let mint_value = assets.to_dict(tx.mint)
  let prog_mint_value =
    check_proofs_and_filter(
      mint_value,
      mint_proofs,
      tx,
      registry_node_cs,
    )

  // Merge: expected output = input programmable tokens + minted tokens
  let expected_value = merge_values(prog_input_value, prog_mint_value)

  // Sum outputs at prog_logic_cred
  let output_value = sum_prog_outputs(tx.outputs, prog_logic_cred)

  // Output must contain at least all expected programmable tokens
  value_contains(output_value, expected_value)
}

// ---------------------------------------------------------------------------
// Third-party (seize/freeze) validation
// ---------------------------------------------------------------------------

/// Validate a third-party admin action (seize, freeze).
///
/// Each input/output pair must:
/// - Come from / go to the same address (preserving stake cred)
/// - Preserve all non-seized token values
/// - Actually change the seized policy value (anti-DDOS)
///
/// Balance invariant: total output tokens >= total input tokens for the policy
fn validate_third_party(
  tx: Transaction,
  prog_logic_cred: Credential,
  registry_node_cs: PolicyId,
  registry_node_idx: Int,
  input_idxs: List<Int>,
  outputs_start_idx: Int,
  length_input_idxs: Int,
) -> Bool {
  // Get registry node for this token policy
  let registry_ref_input = elem_at(tx.reference_inputs, registry_node_idx)

  // Validate authentic registry node
  expect has_currency_symbol(registry_ref_input.output.value, registry_node_cs)

  let registry_datum = expect_inline_datum(registry_ref_input.output)
  expect registry_node: RegistryNode = registry_datum
  let policy_id = registry_node.key

  // Third-party transfer logic must be invoked
  expect
    has_key(tx.withdrawals, registry_node.third_party_transfer_logic_script)

  // Count total prog_logic inputs — must equal length_input_idxs (no unauthorized inputs)
  let prog_input_count =
    list.count(
      tx.inputs,
      fn(input) { input.output.address.payment_credential == prog_logic_cred },
    )
  expect prog_input_count == length_input_idxs

  // Process each input/output pair, accumulate input tokens for balance check
  let total_input_tokens =
    process_third_party_pairs(
      tx,
      prog_logic_cred,
      policy_id,
      input_idxs,
      outputs_start_idx,
      0,
      dict.empty,
    )

  // Sum output tokens at prog_logic_cred for the seized policy
  let total_output_tokens =
    sum_policy_tokens_at_cred(tx.outputs, prog_logic_cred, policy_id)

  // Account for mints/burns in the balance
  let mint_tokens = get_policy_tokens(assets.to_dict(tx.mint), policy_id)
  let adjusted_input = merge_token_dicts(total_input_tokens, mint_tokens)

  // Balance invariant: output >= adjusted input for each token name
  check_token_balance(total_output_tokens, adjusted_input)
}

/// Process input/output pairs for third-party actions.
/// Returns accumulated input tokens for balance invariant.
fn process_third_party_pairs(
  tx: Transaction,
  prog_logic_cred: Credential,
  policy_id: PolicyId,
  input_idxs: List<Int>,
  outputs_start_idx: Int,
  pair_offset: Int,
  acc_tokens: Dict<AssetName, Int>,
) -> Dict<AssetName, Int> {
  when input_idxs is {
    [] -> acc_tokens
    [input_idx, ..rest] -> {
      let input = elem_at(tx.inputs, input_idx)
      let output = elem_at(tx.outputs, outputs_start_idx + pair_offset)

      // Must come from prog_logic_cred
      expect input.output.address.payment_credential == prog_logic_cred

      // Output must preserve address and datum
      expect output.address == input.output.address
      expect output.datum == input.output.datum

      let input_dict = assets.to_dict(input.output.value)
      let output_dict = assets.to_dict(output.value)

      // Non-policy assets must be unchanged
      expect
        dict.delete(input_dict, policy_id) == dict.delete(
          output_dict,
          policy_id,
        )

      // Policy tokens must actually change (anti-DDOS)
      let input_policy_tokens = get_policy_tokens(input_dict, policy_id)
      let output_policy_tokens = get_policy_tokens(output_dict, policy_id)
      expect input_policy_tokens != output_policy_tokens

      // Accumulate input tokens
      let new_acc = merge_token_dicts(acc_tokens, input_policy_tokens)

      process_third_party_pairs(
        tx,
        prog_logic_cred,
        policy_id,
        rest,
        outputs_start_idx,
        pair_offset + 1,
        new_acc,
      )
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Sum values from all authorized inputs at prog_logic_cred.
/// Each input's stake credential must be authorized:
/// - VerificationKey → must be in extra_signatories
/// - Script → must be in withdrawals (invoked via withdraw-zero)
fn get_signed_prog_value(
  tx: Transaction,
  prog_logic_cred: Credential,
) -> Dict<PolicyId, Dict<AssetName, Int>> {
  list.foldr(
    tx.inputs,
    dict.empty,
    fn(input, acc) {
      if input.output.address.payment_credential == prog_logic_cred {
        expect Some(Inline(stake_cred)) =
          input.output.address.stake_credential
        // Authorize based on stake credential type
        when stake_cred is {
          VerificationKey(pkh) -> {
            expect has_signatory(tx.extra_signatories, pkh)
            merge_values(acc, assets.to_dict(input.output.value))
          }
          Script(_hash) -> {
            expect has_key(tx.withdrawals, stake_cred)
            merge_values(acc, assets.to_dict(input.output.value))
          }
        }
      } else {
        acc
      }
    },
  )
}

/// Check registry proofs for each token policy and filter to programmable tokens.
/// Returns only the value of tokens that are registered in the registry.
fn check_proofs_and_filter(
  value: Dict<PolicyId, Dict<AssetName, Int>>,
  proofs: List<RegistryProof>,
  tx: Transaction,
  registry_node_cs: PolicyId,
) -> Dict<PolicyId, Dict<AssetName, Int>> {
  let pairs = dict.to_pairs(value)
  // Skip ADA (first entry in value dict)
  let token_pairs = skip_ada(pairs)
  let (remaining_proofs, filtered) =
    do_check_proofs(token_pairs, proofs, tx, registry_node_cs, dict.empty)
  // All proofs must be consumed
  expect [] == remaining_proofs
  filtered
}

/// Skip ADA entry (empty policy ID) from token pairs.
fn skip_ada(
  pairs: Pairs<PolicyId, Dict<AssetName, Int>>,
) -> Pairs<PolicyId, Dict<AssetName, Int>> {
  when pairs is {
    [Pair(cs, _), ..rest] ->
      if cs == "" {
        rest
      } else {
        pairs
      }
    _ -> pairs
  }
}

/// Iterate through token policies checking each against its proof.
fn do_check_proofs(
  pairs: Pairs<PolicyId, Dict<AssetName, Int>>,
  proofs: List<RegistryProof>,
  tx: Transaction,
  registry_node_cs: PolicyId,
  acc: Dict<PolicyId, Dict<AssetName, Int>>,
) -> (List<RegistryProof>, Dict<PolicyId, Dict<AssetName, Int>>) {
  when pairs is {
    [] -> (proofs, acc)
    [Pair(cs, tokens), ..rest] -> {
      expect [proof, ..remaining_proofs] = proofs
      let is_programmable =
        validate_single_cs(tx, cs, proof, registry_node_cs)
      let new_acc =
        if is_programmable {
          dict.insert(acc, cs, tokens)
        } else {
          acc
        }
      do_check_proofs(rest, remaining_proofs, tx, registry_node_cs, new_acc)
    }
  }
}

/// Validate a single currency symbol against its registry proof.
/// Returns True if programmable (TokenExists), False if not (TokenDoesNotExist).
/// Fails the transaction if the proof is invalid.
fn validate_single_cs(
  tx: Transaction,
  cs: PolicyId,
  proof: RegistryProof,
  registry_node_cs: PolicyId,
) -> Bool {
  when proof is {
    TokenExists { node_idx } -> {
      let node_input = elem_at(tx.reference_inputs, node_idx)
      // Must be authentic registry node
      expect has_currency_symbol(node_input.output.value, registry_node_cs)
      let node_datum = expect_inline_datum(node_input.output)
      expect node: RegistryNode = node_datum
      // Key must match the policy
      expect node.key == cs
      // Transfer logic MUST be invoked for registered tokens
      expect has_key(tx.withdrawals, node.transfer_logic_script)
      True
    }
    TokenDoesNotExist { node_idx } -> {
      let node_input = elem_at(tx.reference_inputs, node_idx)
      // Must be authentic registry node
      expect has_currency_symbol(node_input.output.value, registry_node_cs)
      let node_datum = expect_inline_datum(node_input.output)
      expect node: RegistryNode = node_datum
      // Covering node: key < cs < next (proves non-membership)
      expect bytearray_lt(node.key, cs)
      expect bytearray_lt(cs, node.next)
      // Not programmable — skip validation
      False
    }
  }
}

/// Merge two value dicts by summing token quantities per policy per token name.
fn merge_values(
  a: Dict<PolicyId, Dict<AssetName, Int>>,
  b: Dict<PolicyId, Dict<AssetName, Int>>,
) -> Dict<PolicyId, Dict<AssetName, Int>> {
  dict.union_with(
    a,
    b,
    fn(_policy, tokens_a, tokens_b, keep, _discard) {
      keep(dict.union_with(tokens_a, tokens_b, strategy.sum()))
    },
  )
}

/// Merge two token dicts (same policy) by summing quantities.
fn merge_token_dicts(
  a: Dict<AssetName, Int>,
  b: Dict<AssetName, Int>,
) -> Dict<AssetName, Int> {
  dict.union_with(a, b, strategy.sum())
}

/// Sum outputs at prog_logic_cred into a single value dict.
fn sum_prog_outputs(
  outputs: List<Output>,
  prog_logic_cred: Credential,
) -> Dict<PolicyId, Dict<AssetName, Int>> {
  list.foldr(
    outputs,
    dict.empty,
    fn(output, acc) {
      if output.address.payment_credential == prog_logic_cred {
        // Output must have a stake credential (inline)
        expect Some(Inline(_)) = output.address.stake_credential
        merge_values(acc, assets.to_dict(output.value))
      } else {
        acc
      }
    },
  )
}

/// Get tokens for a specific policy from a value dict.
fn get_policy_tokens(
  value_dict: Dict<PolicyId, Dict<AssetName, Int>>,
  policy: PolicyId,
) -> Dict<AssetName, Int> {
  when dict.get(value_dict, policy) is {
    Some(tokens) -> tokens
    None -> dict.empty
  }
}

/// Sum policy tokens from outputs at prog_logic_cred.
fn sum_policy_tokens_at_cred(
  outputs: List<Output>,
  prog_logic_cred: Credential,
  policy_id: PolicyId,
) -> Dict<AssetName, Int> {
  list.foldr(
    outputs,
    dict.empty,
    fn(output, acc) {
      if output.address.payment_credential == prog_logic_cred {
        let output_dict = assets.to_dict(output.value)
        let tokens = get_policy_tokens(output_dict, policy_id)
        merge_token_dicts(acc, tokens)
      } else {
        acc
      }
    },
  )
}

/// Check that `superset` contains at least as much of each token as `subset`.
fn value_contains(
  superset: Dict<PolicyId, Dict<AssetName, Int>>,
  subset: Dict<PolicyId, Dict<AssetName, Int>>,
) -> Bool {
  list.all(
    dict.to_pairs(subset),
    fn(pair) {
      let Pair(cs, expected_tokens) = pair
      when dict.get(superset, cs) is {
        None -> False
        Some(actual_tokens) -> check_token_balance(actual_tokens, expected_tokens)
      }
    },
  )
}

/// Check that for each token name, actual >= expected.
fn check_token_balance(
  actual: Dict<AssetName, Int>,
  expected: Dict<AssetName, Int>,
) -> Bool {
  list.all(
    dict.to_pairs(expected),
    fn(pair) {
      let Pair(name, expected_qty) = pair
      // Only check positive expected quantities (burns result in negative)
      if expected_qty <= 0 {
        True
      } else {
        when dict.get(actual, name) is {
          None -> False
          Some(actual_qty) -> actual_qty >= expected_qty
        }
      }
    },
  )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// Mock 28-byte hashes (56 hex chars)
const t_params_cs =
  #"11111111111111111111111111111111111111111111111111111111"

const t_registry_cs =
  #"22222222222222222222222222222222222222222222222222222222"

const t_prog_logic_hash =
  #"33333333333333333333333333333333333333333333333333333333"

const t_token_policy =
  #"44444444444444444444444444444444444444444444444444444444"

const t_transfer_logic_hash =
  #"55555555555555555555555555555555555555555555555555555555"

const t_holder_pkh =
  #"66666666666666666666666666666666666666666666666666666666"

const t_third_party_hash =
  #"77777777777777777777777777777777777777777777777777777777"

const t_recipient_pkh =
  #"88888888888888888888888888888888888888888888888888888888"

fn t_holder_addr() -> Address {
  Address {
    payment_credential: Script(t_prog_logic_hash),
    stake_credential: Some(Inline(VerificationKey(t_holder_pkh))),
  }
}

fn t_recipient_addr() -> Address {
  Address {
    payment_credential: Script(t_prog_logic_hash),
    stake_credential: Some(Inline(VerificationKey(t_recipient_pkh))),
  }
}

fn t_params_ref() -> Input {
  Input {
    output_reference: OutputReference {
      transaction_id: #"0000000000000000000000000000000000000000000000000000000000000000",
      output_index: 0,
    },
    output: Output {
      address: address.from_verification_key(t_holder_pkh),
      value: assets.from_lovelace(2_000_000)
        |> assets.add(t_params_cs, "ProtocolParams", 1),
      datum: InlineDatum(
        ProgrammableLogicGlobalParams {
          registry_node_cs: t_registry_cs,
          prog_logic_cred: Script(t_prog_logic_hash),
        },
      ),
      reference_script: None,
    },
  }
}

fn t_registry_ref() -> Input {
  Input {
    output_reference: OutputReference {
      transaction_id: #"0000000000000000000000000000000000000000000000000000000000000000",
      output_index: 1,
    },
    output: Output {
      address: address.from_verification_key(t_holder_pkh),
      value: assets.from_lovelace(2_000_000)
        |> assets.add(t_registry_cs, "RegistryNode", 1),
      datum: InlineDatum(
        RegistryNode {
          key: t_token_policy,
          next: #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
          transfer_logic_script: Script(t_transfer_logic_hash),
          third_party_transfer_logic_script: Script(t_third_party_hash),
          global_state_cs: #"",
        },
      ),
      reference_script: None,
    },
  }
}

fn t_holder_input() -> Input {
  Input {
    output_reference: OutputReference {
      transaction_id: #"0101010101010101010101010101010101010101010101010101010101010101",
      output_index: 0,
    },
    output: Output {
      address: t_holder_addr(),
      value: assets.from_lovelace(2_000_000)
        |> assets.add(t_token_policy, "Token", 100),
      datum: NoDatum,
      reference_script: None,
    },
  }
}

fn t_transfer_redeemer() -> ProgrammableLogicGlobalRedeemer {
  TransferAct { proofs: [TokenExists { node_idx: 1 }], mint_proofs: [] }
}

fn t_base_transfer_tx() -> Transaction {
  Transaction {
    ..placeholder,
    reference_inputs: [t_params_ref(), t_registry_ref()],
    inputs: [t_holder_input()],
    outputs: [
      Output {
        address: t_recipient_addr(),
        value: assets.from_lovelace(2_000_000)
          |> assets.add(t_token_policy, "Token", 100),
        datum: NoDatum,
        reference_script: None,
      },
    ],
    withdrawals: [Pair(Script(t_transfer_logic_hash), 0)],
    extra_signatories: [t_holder_pkh],
  }
}

test transfer_succeeds() {
  let tx = t_base_transfer_tx()
  programmable_logic_global.withdraw(
    t_params_cs,
    t_transfer_redeemer(),
    Script(t_prog_logic_hash),
    tx,
  )
}

test transfer_fails_without_signature() fail {
  let base = t_base_transfer_tx()
  let tx = Transaction { ..base, extra_signatories: [] }
  programmable_logic_global.withdraw(
    t_params_cs,
    t_transfer_redeemer(),
    Script(t_prog_logic_hash),
    tx,
  )
}

test transfer_fails_without_transfer_logic() fail {
  let base = t_base_transfer_tx()
  let tx = Transaction { ..base, withdrawals: [] }
  programmable_logic_global.withdraw(
    t_params_cs,
    t_transfer_redeemer(),
    Script(t_prog_logic_hash),
    tx,
  )
}

test transfer_fails_insufficient_output() fail {
  let base = t_base_transfer_tx()
  let tx =
    Transaction {
      ..base,
      outputs: [
        Output {
          address: t_recipient_addr(),
          value: assets.from_lovelace(2_000_000)
            |> assets.add(t_token_policy, "Token", 50),
          datum: NoDatum,
          reference_script: None,
        },
      ],
    }
  programmable_logic_global.withdraw(
    t_params_cs,
    t_transfer_redeemer(),
    Script(t_prog_logic_hash),
    tx,
  )
}

test third_party_seize_succeeds() {
  let tx =
    Transaction {
      ..placeholder,
      reference_inputs: [t_params_ref(), t_registry_ref()],
      inputs: [t_holder_input()],
      outputs: [
        // User output with reduced tokens (seized)
        Output {
          address: t_holder_addr(),
          value: assets.from_lovelace(2_000_000)
            |> assets.add(t_token_policy, "Token", 50),
          datum: NoDatum,
          reference_script: None,
        },
        // Admin output receiving seized tokens
        Output {
          address: t_recipient_addr(),
          value: assets.from_lovelace(2_000_000)
            |> assets.add(t_token_policy, "Token", 50),
          datum: NoDatum,
          reference_script: None,
        },
      ],
      withdrawals: [Pair(Script(t_third_party_hash), 0)],
    }
  let redeemer =
    ThirdPartyAct {
      registry_node_idx: 1,
      input_idxs: [0],
      outputs_start_idx: 0,
      length_input_idxs: 1,
    }
  programmable_logic_global.withdraw(
    t_params_cs,
    redeemer,
    Script(t_prog_logic_hash),
    tx,
  )
}

test third_party_fails_without_change() fail {
  let tx =
    Transaction {
      ..placeholder,
      reference_inputs: [t_params_ref(), t_registry_ref()],
      inputs: [t_holder_input()],
      outputs: [
        // Output with SAME tokens as input (anti-DDOS violation)
        Output {
          address: t_holder_addr(),
          value: assets.from_lovelace(2_000_000)
            |> assets.add(t_token_policy, "Token", 100),
          datum: NoDatum,
          reference_script: None,
        },
      ],
      withdrawals: [Pair(Script(t_third_party_hash), 0)],
    }
  let redeemer =
    ThirdPartyAct {
      registry_node_idx: 1,
      input_idxs: [0],
      outputs_start_idx: 0,
      length_input_idxs: 1,
    }
  programmable_logic_global.withdraw(
    t_params_cs,
    redeemer,
    Script(t_prog_logic_hash),
    tx,
  )
}
