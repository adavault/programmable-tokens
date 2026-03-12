use cardano/address.{Credential, Script, VerificationKey}
use cardano/transaction.{Transaction, placeholder}
use programmable_tokens/utils.{has_key, has_signatory}

/// CIP-113 Third-Party Transfer Logic — Freeze & Seize Substandard
///
/// Invoked via withdraw-zero for admin operations (freeze, seize, force transfer).
/// Requires the admin credential to authorize the action.
///
/// The global coordinator enforces:
/// - Address and datum preservation on each input/output pair
/// - Non-policy assets unchanged
/// - Anti-DDOS (tokens must actually change)
/// - Balance invariant (total output >= total input)
///
/// This validator only checks admin authorization.
/// Parameterized by the admin credential.
validator third_party_transfer_logic(admin_cred: Credential) {
  withdraw(_redeemer: Data, _account: Credential, tx: Transaction) {
    // Admin must authorize the third-party action
    when admin_cred is {
      VerificationKey(pkh) -> has_signatory(tx.extra_signatories, pkh)
      Script(hash) -> has_key(tx.withdrawals, Script(hash))
    }
  }

  else(_) {
    fail
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const t_admin_pkh = #"11111111111111111111111111111111111111111111111111111111"

const t_admin_script =
  #"22222222222222222222222222222222222222222222222222222222"

const t_own_hash = #"33333333333333333333333333333333333333333333333333333333"

test vk_admin_succeeds() {
  let tx = Transaction { ..placeholder, extra_signatories: [t_admin_pkh] }
  third_party_transfer_logic.withdraw(
    VerificationKey(t_admin_pkh),
    Void,
    Script(t_own_hash),
    tx,
  )
}

test vk_admin_fails_without_sig() fail {
  let tx = placeholder
  third_party_transfer_logic.withdraw(
    VerificationKey(t_admin_pkh),
    Void,
    Script(t_own_hash),
    tx,
  )
}

test script_admin_succeeds() {
  let tx =
    Transaction {
      ..placeholder,
      withdrawals: [Pair(Script(t_admin_script), 0)],
    }
  third_party_transfer_logic.withdraw(
    Script(t_admin_script),
    Void,
    Script(t_own_hash),
    tx,
  )
}

test script_admin_fails_without_withdrawal() fail {
  let tx = placeholder
  third_party_transfer_logic.withdraw(
    Script(t_admin_script),
    Void,
    Script(t_own_hash),
    tx,
  )
}
