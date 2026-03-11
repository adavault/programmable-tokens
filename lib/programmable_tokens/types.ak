/// CIP-113 Programmable Tokens — Shared Types
///
/// Core data types used across all programmable token validators.
/// Based on the Cardano Foundation reference implementation.

use cardano/address.{Credential}
use cardano/assets.{PolicyId}

// -- Constants --

/// Origin node token name (empty bytearray)
pub const origin_node_tn = #""

/// Protocol parameters NFT token name
pub const protocol_params_token = "ProtocolParams"

// -- Registry Types --

/// Registry node in the sorted linked list of registered programmable token policies.
/// Each node is a UTxO with an NFT marker and this inline datum.
pub type RegistryNode {
  /// Policy ID of the registered programmable token
  key: ByteArray,
  /// Next key in lexicographic order (sorted linked list pointer)
  next: ByteArray,
  /// Stake validator credential for transfer rules
  transfer_logic_script: Credential,
  /// Stake validator credential for admin/third-party operations
  third_party_transfer_logic_script: Credential,
  /// Optional NFT policy ID for global state (e.g., denylist root)
  global_state_cs: ByteArray,
}

/// Protocol parameters stored on-chain as inline datum.
/// Referenced by all programmable token transactions.
pub type ProgrammableLogicGlobalParams {
  /// Policy ID of the registry node NFTs
  registry_node_cs: PolicyId,
  /// Payment credential of the programmable_logic_base validator
  prog_logic_cred: Credential,
}

// -- Proof Types --

/// Proof that a token policy is (or is not) in the registry.
/// Used by the global validator to look up transfer logic.
pub type RegistryProof {
  /// Token exists: reference input at node_idx has node.key == policy_id
  TokenExists { node_idx: Int }
  /// Token does not exist: covering node proves node.key < policy_id < node.next
  TokenDoesNotExist { node_idx: Int }
}

// -- Redeemer Types --

/// Redeemer for the global programmable logic stake validator (withdraw-zero).
pub type ProgrammableLogicGlobalRedeemer {
  /// Standard transfer — one proof per non-ADA policy in inputs
  TransferAct {
    /// Proofs for each token policy in the transaction inputs
    proofs: List<RegistryProof>,
    /// Proofs for minted/burned programmable tokens
    mint_proofs: List<RegistryProof>,
  }
  /// Third-party admin action (freeze, seize, force transfer)
  ThirdPartyAct {
    /// Index of registry node in reference inputs
    registry_node_idx: Int,
    /// Indices of inputs to process
    input_idxs: List<Int>,
    /// Starting output index for processed outputs
    outputs_start_idx: Int,
    /// Length of input_idxs (for validation)
    length_input_idxs: Int,
  }
}

/// Redeemer for the issuance minting policy.
pub type SmartTokenMintingAction {
  /// Credential of the minting logic script that must be invoked
  minting_logic_cred: Credential,
}

/// Redeemer for registry minting policy (linked list operations).
pub type RegistryRedeemer {
  /// Initialize the registry with the origin node
  RegistryInit
  /// Insert a new programmable token policy into the registry
  RegistryInsert { key: ByteArray, hashed_param: ByteArray }
}

/// Issuance script template — prefix and postfix of the parameterized minting policy.
/// Used during registration to verify policy ID authenticity.
pub type IssuanceCborHex {
  /// Prefix bytes of the minting policy script
  prefix_cbor_hex: ByteArray,
  /// Postfix bytes of the minting policy script
  postfix_cbor_hex: ByteArray,
}
