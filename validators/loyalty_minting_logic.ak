/// SPO Loyalty Token — Minting Logic
///
/// Controls minting and burning of the loyalty token.
/// Only the admin (ADAvault operator) can mint rewards or burn tokens.
///
/// Invoked via withdraw-zero by the issuance_mint validator.
/// The global coordinator verifies registry proof and value preservation.
///
/// Parameterized by the admin verification key hash.

use aiken/collection/list
use cardano/address.{Credential, Script}
use cardano/transaction.{Transaction, placeholder}

validator loyalty_minting_logic(admin_pkh: ByteArray) {
  withdraw(_redeemer: Data, _account: Credential, tx: Transaction) {
    // Only the admin can mint or burn loyalty tokens
    list.has(tx.extra_signatories, admin_pkh)?
  }

  else(_) {
    fail
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const t_admin_pkh =
  #"11111111111111111111111111111111111111111111111111111111"

const t_own_hash =
  #"22222222222222222222222222222222222222222222222222222222"

test minting_with_admin_sig_succeeds() {
  let tx =
    Transaction {
      ..placeholder,
      extra_signatories: [t_admin_pkh],
    }
  loyalty_minting_logic.withdraw(
    t_admin_pkh,
    Void,
    Script(t_own_hash),
    tx,
  )
}

test minting_without_admin_sig_fails() fail {
  loyalty_minting_logic.withdraw(
    t_admin_pkh,
    Void,
    Script(t_own_hash),
    placeholder,
  )
}

test minting_with_wrong_sig_fails() fail {
  let wrong_pkh =
    #"ffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  let tx =
    Transaction {
      ..placeholder,
      extra_signatories: [wrong_pkh],
    }
  loyalty_minting_logic.withdraw(
    t_admin_pkh,
    Void,
    Script(t_own_hash),
    tx,
  )
}
