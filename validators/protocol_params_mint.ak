/// CIP-113 Protocol Parameters Mint
///
/// One-shot minting policy for the protocol parameters NFT.
/// This NFT marks the UTxO containing ProgrammableLogicGlobalParams,
/// which is referenced by all programmable token transactions.
///
/// Parameterized by a UTxO reference (consumed during mint) to guarantee
/// exactly one instance can ever exist.

use aiken/collection/dict
use aiken/collection/list
use cardano/address
use cardano/assets
use cardano/transaction.{OutputReference, Transaction}
use programmable_tokens/types.{protocol_params_token}

validator protocol_params_mint(utxo_ref: OutputReference) {
  mint(_redeemer: Data, policy_id: assets.PolicyId, tx: Transaction) {

    // The parameterized UTxO must be consumed (one-shot guarantee)
    let utxo_consumed =
      list.any(
        tx.inputs,
        fn(input) { input.output_reference == utxo_ref },
      )

    // Must mint exactly 1 token with the protocol params token name
    let minted = assets.tokens(tx.mint, policy_id)
    let correct_mint =
      dict.to_pairs(minted) == [Pair(protocol_params_token, 1)]

    utxo_consumed? && correct_mint?
  }

  else(_) {
    fail
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const mock_utxo_ref =
  OutputReference {
    transaction_id: #"0000000000000000000000000000000000000000000000000000000000000001",
    output_index: 0,
  }

const mock_policy =
  #"aabbccddee112233445566778899001122334455667788990011223344556677"

fn mock_input() -> transaction.Input {
  transaction.Input {
    output_reference: mock_utxo_ref,
    output: transaction.Output {
      address: address.from_verification_key(
        #"112233445566778899aabbccddeeff00112233445566778899aabbcc",
      ),
      value: assets.from_lovelace(5_000_000),
      datum: transaction.NoDatum,
      reference_script: None,
    },
  }
}

test mint_protocol_params_succeeds() {
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [mock_input()],
      mint: assets.from_asset(mock_policy, protocol_params_token, 1),
    }
  protocol_params_mint.mint(mock_utxo_ref, Void, mock_policy, tx)
}

test mint_without_utxo_consumed_fails() fail {
  let wrong_ref =
    OutputReference {
      transaction_id: #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
      output_index: 0,
    }
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [mock_input()],
      mint: assets.from_asset(mock_policy, protocol_params_token, 1),
    }
  protocol_params_mint.mint(wrong_ref, Void, mock_policy, tx)
}

test mint_wrong_token_name_fails() fail {
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [mock_input()],
      mint: assets.from_asset(mock_policy, "WrongName", 1),
    }
  protocol_params_mint.mint(mock_utxo_ref, Void, mock_policy, tx)
}

test mint_multiple_tokens_fails() fail {
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [mock_input()],
      mint: assets.from_asset(mock_policy, protocol_params_token, 1)
        |> assets.add(mock_policy, "Extra", 1),
    }
  protocol_params_mint.mint(mock_utxo_ref, Void, mock_policy, tx)
}

test mint_quantity_two_fails() fail {
  let tx =
    Transaction {
      ..transaction.placeholder,
      inputs: [mock_input()],
      mint: assets.from_asset(mock_policy, protocol_params_token, 2),
    }
  protocol_params_mint.mint(mock_utxo_ref, Void, mock_policy, tx)
}
