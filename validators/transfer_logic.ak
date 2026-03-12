use cardano/address.{Credential, Script, VerificationKey}
use cardano/transaction.{Transaction, placeholder}
use programmable_tokens/utils.{has_signatory}

/// CIP-113 Transfer Logic — Open Transfer Substandard
///
/// Invoked via withdraw-zero on every programmable token transfer.
/// This is the simplest substandard: allows any transfer as long as
/// the global coordinator validates value preservation.
///
/// More restrictive variants would check whitelists, cooldowns,
/// transfer limits, KYC status, etc.
///
/// Parameterized by an admin credential for future governance.
validator transfer_logic(admin_cred: Credential) {
  withdraw(_redeemer: Data, _account: Credential, tx: Transaction) {
    // Open transfer: any transfer is allowed.
    // The global coordinator already enforces value preservation.
    // Admin signature required to prove policy is authorized.
    when admin_cred is {
      VerificationKey(pkh) -> has_signatory(tx.extra_signatories, pkh)
      Script(_hash) -> True
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

const t_script_hash =
  #"22222222222222222222222222222222222222222222222222222222"

test open_transfer_vk_admin_succeeds() {
  let tx = Transaction { ..placeholder, extra_signatories: [t_admin_pkh] }
  transfer_logic.withdraw(
    VerificationKey(t_admin_pkh),
    Void,
    Script(t_script_hash),
    tx,
  )
}

test open_transfer_vk_admin_fails_without_sig() fail {
  let tx = placeholder
  transfer_logic.withdraw(
    VerificationKey(t_admin_pkh),
    Void,
    Script(t_script_hash),
    tx,
  )
}

test open_transfer_script_admin_always_succeeds() {
  let tx = placeholder
  transfer_logic.withdraw(
    Script(t_script_hash),
    Void,
    Script(t_script_hash),
    tx,
  )
}
