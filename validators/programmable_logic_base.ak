/// CIP-113 Programmable Logic Base Validator
///
/// Custody of all programmable token UTxOs. Intentionally minimal —
/// delegates all validation to the global coordinator via withdraw-zero.
///
/// All programmable tokens live at addresses sharing this payment credential.
/// Ownership is determined by the per-holder stake credential.

use aiken/collection/list
use cardano/address.{Credential}
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
