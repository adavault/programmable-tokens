/// CIP-113 Programmable Logic Base Validator
///
/// Custody of all programmable token UTxOs. Intentionally minimal —
/// delegates all validation to the global coordinator via withdraw-zero.
///
/// All programmable tokens live at addresses sharing this payment credential.
/// Ownership is determined by the per-holder stake credential.

use aiken/collection/list
use cardano/address.{Credential, Script}
use cardano/transaction.{Transaction}

validator programmable_logic_base(stake_cred: Credential) {
  spend(
    _datum: Option<Data>,
    _redeemer: Data,
    _own_ref: Data,
    tx: Transaction,
  ) {
    // The only job: verify the global coordinator is invoked in this tx.
    // The global validator (stake script) handles all actual validation.
    // This runs once PER INPUT but is O(1) — just a withdrawal lookup.
    list.any(
      tx.withdrawals,
      fn(wdrl) {
        let Pair(cred, _amount) = wdrl
        cred == stake_cred
      },
    )
  }

  else(_) {
    fail
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const mock_global_cred =
  Script(#"aabbccddee112233445566778899001122334455667788990011223344556677")

test spend_succeeds_when_global_in_withdrawals() {
  let tx =
    Transaction {
      ..transaction.placeholder,
      withdrawals: [Pair(mock_global_cred, 0)],
    }
  programmable_logic_base.spend(mock_global_cred, None, Void, Void, tx)
}

test spend_fails_without_global_withdrawal() fail {
  let tx =
    Transaction {
      ..transaction.placeholder,
      withdrawals: [],
    }
  programmable_logic_base.spend(mock_global_cred, None, Void, Void, tx)
}

test spend_fails_with_wrong_credential() fail {
  let wrong_cred =
    Script(#"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
  let tx =
    Transaction {
      ..transaction.placeholder,
      withdrawals: [Pair(wrong_cred, 0)],
    }
  programmable_logic_base.spend(mock_global_cred, None, Void, Void, tx)
}
