/// CIP-113 Programmable Tokens — Utility Functions
///
/// Common helpers used across validators.

use aiken/builtin
use aiken/collection/dict
use aiken/collection/list
use cardano/address.{Credential}
use cardano/assets.{PolicyId}
use cardano/transaction.{InlineDatum, Output}

/// Check if a credential exists as a key in a pairs list (withdrawals, etc.)
pub fn has_key(pairs: Pairs<Credential, a>, cred: Credential) -> Bool {
  list.any(pairs, fn(pair) { pair.1st == cred })
}

/// Check if an output's value contains any token from a given policy.
pub fn has_currency_symbol(value: assets.Value, cs: PolicyId) -> Bool {
  let tokens = assets.tokens(value, cs)
  !dict.is_empty(tokens)
}

/// Check if a verification key hash is in the signatories list.
pub fn has_signatory(signatories: List<ByteArray>, pkh: ByteArray) -> Bool {
  list.has(signatories, pkh)
}

/// Extract inline datum from an output, failing if not inline.
pub fn expect_inline_datum(output: Output) -> Data {
  expect InlineDatum(datum) = output.datum
  datum
}

/// Safe element access at index in a list.
pub fn elem_at(xs: List<a>, idx: Int) -> a {
  when idx is {
    0 -> {
      expect [head, ..] = xs
      head
    }
    _ -> {
      expect [_, ..tail] = xs
      elem_at(tail, idx - 1)
    }
  }
}

/// Lexicographic less-than comparison for bytearrays.
pub fn bytearray_lt(a: ByteArray, b: ByteArray) -> Bool {
  builtin.less_than_bytearray(a, b)
}
