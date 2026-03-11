/**
 * CIP-113 Programmable Tokens — Preview Testnet E2E Tests
 *
 * Phased testing:
 *   1. bootstrap  — Mint protocol params NFT + init registry + issuance template
 *   2. register   — Register loyalty token in registry
 *   3. mint       — Mint loyalty tokens to a holder
 *   4. transfer   — Transfer between whitelisted holders
 *
 * Prerequisites:
 *   - SSH tunnel: ssh -N -L 1337:localhost:1337 -L 1442:localhost:1442 cardano@vducdn59
 *   - Payment signing key at test/keys/payment.skey
 *   - aiken build (plutus.json must exist)
 *
 * Usage:
 *   npm test                     # Run bootstrap
 *   npm run test:bootstrap       # Mint protocol params + init registry
 *   npm run test:register        # Register token in registry
 *   npm run test:mint            # Mint loyalty tokens
 *   npm run test:transfer        # Transfer tokens
 */

import { readFileSync, writeFileSync, existsSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";
import WebSocket from "ws";

// Node.js 20 lacks global WebSocket — polyfill for Ogmios provider
(globalThis as any).WebSocket = WebSocket;

import {
  MintingBlueprint,
  SpendingBlueprint,
  MeshTxBuilder,
  KupoProvider,
  AppWallet,
  serializeRewardAddress,
} from "@meshsdk/core";
import { OgmiosProvider } from "@meshsdk/provider";
import { buildBaseAddress, CredentialType } from "@meshsdk/core-cst";

import { config, loadSigningKey, loadValidatorCompiledCode } from "./config.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const STATE_FILE = join(__dirname, "cip113-state.json");

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface Cip113State {
  // Bootstrap outputs
  protocolParamsPolicyId?: string;
  protocolParamsScriptCbor?: string;
  protocolParamsTxHash?: string;
  registryMintPolicyId?: string;
  registryMintScriptCbor?: string;
  registryInitTxHash?: string;
  issuanceCborHexPolicyId?: string;
  issuanceCborHexTxHash?: string;
  // Derived script hashes
  globalStakeHash?: string;
  globalScriptCbor?: string;
  progLogicHash?: string;
  progLogicScriptCbor?: string;
  registrySpendHash?: string;
  registrySpendScriptCbor?: string;
  // Token-specific
  issuancePolicyId?: string;
  issuanceScriptCbor?: string;
  loyaltyMintingLogicHash?: string;
  loyaltyMintingLogicCbor?: string;
  transferLogicHash?: string;
  transferLogicCbor?: string;
  thirdPartyLogicHash?: string;
  thirdPartyLogicCbor?: string;
  // Registration
  registerTxHash?: string;
  // Reference scripts deployment
  refScriptsTxHash?: string;
  globalRefUtxo?: { txHash: string; index: number };
  issuanceRefUtxo?: { txHash: string; index: number };
  mintingLogicRefUtxo?: { txHash: string; index: number };
  transferLogicRefUtxo?: { txHash: string; index: number };
  // Minting
  mintTxHash?: string;
  // Transfer
  transferTxHash?: string;
  // Stake registrations
  stakeRegTxHash?: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function log(msg: string) {
  console.log(`[cip113] ${msg}`);
}

function saveState(state: Cip113State) {
  writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

function loadState(): Cip113State {
  if (!existsSync(STATE_FILE)) return {};
  return JSON.parse(readFileSync(STATE_FILE, "utf-8"));
}

/**
 * Encode a Credential as Plutus Data JSON.
 * Script(hash) = constructor 1, fields [{ bytes: hash }]
 * VerificationKey(hash) = constructor 0, fields [{ bytes: hash }]
 */
function scriptCredJson(hash: string) {
  return { constructor: 1, fields: [{ bytes: hash }] };
}

function vkCredJson(hash: string) {
  return { constructor: 0, fields: [{ bytes: hash }] };
}

/**
 * Encode an OutputReference as Plutus Data JSON.
 */
function outputRefJson(txHash: string, index: number) {
  return {
    constructor: 0,
    fields: [{ bytes: txHash }, { int: index }],
  };
}

/**
 * Build a programmable logic base address: Script(progLogicHash) + VK stake credential.
 * This is the address format for all programmable token holders.
 */
function buildProgLogicAddress(progLogicHash: string, stakeVkHash: string, networkId: number): string {
  const addr = buildBaseAddress(
    networkId,
    progLogicHash,
    stakeVkHash,
    CredentialType.ScriptHash,
    CredentialType.KeyHash,
  );
  return addr.toAddress().toBech32();
}

async function waitForTx(kupo: KupoProvider, txHash: string, maxWait = 120000) {
  const start = Date.now();
  log(`Waiting for tx ${txHash.slice(0, 16)}... to appear on-chain`);
  while (Date.now() - start < maxWait) {
    try {
      const utxos = await kupo.fetchUTxOs(txHash);
      if (utxos.length > 0) {
        log(`Tx confirmed (${Math.round((Date.now() - start) / 1000)}s)`);
        return utxos;
      }
    } catch {
      // Not yet
    }
    await new Promise((r) => setTimeout(r, 5000));
  }
  throw new Error(`Tx ${txHash} not confirmed within ${maxWait / 1000}s`);
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

async function setup() {
  log("Connecting to preview testnet...");

  const ogmios = new OgmiosProvider(config.ogmiosUrl);
  const kupo = new KupoProvider(config.kupoUrl);

  const signingKey = loadSigningKey();
  const wallet = new AppWallet({
    networkId: config.networkId,
    fetcher: kupo,
    submitter: ogmios,
    key: { type: "cli", payment: signingKey },
  });
  await wallet.init();

  const walletAddress = wallet.getEnterpriseAddress();
  log(`Wallet: ${walletAddress}`);

  const utxos = await kupo.fetchAddressUTxOs(walletAddress);
  const totalLovelace = utxos.reduce((sum, u) => {
    const lovelace = u.output.amount.find((a) => a.unit === "lovelace");
    return sum + BigInt(lovelace?.quantity ?? "0");
  }, 0n);
  log(`UTxOs: ${utxos.length}, Balance: ${totalLovelace / 1_000_000n} tADA`);

  if (utxos.length === 0) {
    throw new Error("No UTxOs — wallet not funded or Kupo not synced");
  }

  // Extract key hash from enterprise address
  const usedAddr = wallet.getUsedAddress(0, 0, "enterprise");
  const addrHex = usedAddr.toBytes() as unknown as string;
  const keyHashHex = addrHex.slice(2, 58);

  return { ogmios, kupo, wallet, walletAddress, signingKey, keyHashHex, utxos };
}

// ---------------------------------------------------------------------------
// Phase 1: Bootstrap — Protocol Params + Registry Init + Issuance Template
// ---------------------------------------------------------------------------

async function bootstrap() {
  const ctx = await setup();
  const state = loadState();

  // --- Step 1: Resolve the full parameter dependency chain ---
  log("Resolving parameter dependency chain...");

  // We need 3 seed UTxOs for the one-shot mints
  if (ctx.utxos.length < 3) {
    throw new Error(`Need at least 3 UTxOs, have ${ctx.utxos.length}`);
  }

  const seedUtxo1 = ctx.utxos[0]; // protocol params
  const seedUtxo2 = ctx.utxos[1]; // registry
  const seedUtxo3 = ctx.utxos[2]; // issuance cbor hex

  // 1. protocol_params_mint(utxo_ref1) → pp_cs
  const ppMint = new MintingBlueprint("V3");
  ppMint.paramScript(
    loadValidatorCompiledCode("protocol_params_mint.protocol_params_mint.mint"),
    [outputRefJson(seedUtxo1.input.txHash, seedUtxo1.input.outputIndex)],
    "JSON"
  );
  const ppCs = ppMint.hash;
  log(`protocol_params_mint policy: ${ppCs}`);

  // 2. programmable_logic_global(pp_cs) → global_hash
  // This is a withdraw validator — but MintingBlueprint gives us the hash
  // The script hash is the same regardless of blueprint type
  const globalBlueprint = new MintingBlueprint("V3");
  globalBlueprint.paramScript(
    loadValidatorCompiledCode("programmable_logic_global.programmable_logic_global.withdraw"),
    [{ bytes: ppCs }],
    "JSON"
  );
  const globalHash = globalBlueprint.hash;
  log(`programmable_logic_global hash: ${globalHash}`);

  // 3. programmable_logic_base(Script(global_hash)) → prog_logic_hash
  const baseBlueprint = new SpendingBlueprint("V3");
  baseBlueprint.paramScript(
    loadValidatorCompiledCode("programmable_logic_base.programmable_logic_base.spend"),
    [scriptCredJson(globalHash)],
    "JSON"
  );
  const progLogicHash = baseBlueprint.hash;
  log(`programmable_logic_base hash: ${progLogicHash}`);

  // 4. registry_mint(utxo_ref2) → registry_cs
  const regMint = new MintingBlueprint("V3");
  regMint.paramScript(
    loadValidatorCompiledCode("registry_mint.registry_mint.mint"),
    [outputRefJson(seedUtxo2.input.txHash, seedUtxo2.input.outputIndex)],
    "JSON"
  );
  const registryCs = regMint.hash;
  log(`registry_mint policy: ${registryCs}`);

  // 5. registry_spend(registry_cs) → registry_spend_hash
  const regSpend = new SpendingBlueprint("V3");
  regSpend.paramScript(
    loadValidatorCompiledCode("registry_spend.registry_spend.spend"),
    [{ bytes: registryCs }],
    "JSON"
  );
  log(`registry_spend hash: ${regSpend.hash}`);

  // 6. issuance_cbor_hex_mint(utxo_ref3)
  const templateMint = new MintingBlueprint("V3");
  templateMint.paramScript(
    loadValidatorCompiledCode("issuance_cbor_hex_mint.issuance_cbor_hex_mint.mint"),
    [outputRefJson(seedUtxo3.input.txHash, seedUtxo3.input.outputIndex)],
    "JSON"
  );
  log(`issuance_cbor_hex_mint policy: ${templateMint.hash}`);

  // 7. issuance_mint(Script(global_hash)) → issuance_cs (loyalty token policy)
  const issuanceMint = new MintingBlueprint("V3");
  issuanceMint.paramScript(
    loadValidatorCompiledCode("issuance_mint.issuance_mint.mint"),
    [scriptCredJson(globalHash)],
    "JSON"
  );
  log(`issuance_mint policy (loyalty): ${issuanceMint.hash}`);

  // 8. loyalty_minting_logic(admin_pkh)
  const loyaltyMintLogic = new MintingBlueprint("V3");
  loyaltyMintLogic.paramScript(
    loadValidatorCompiledCode("loyalty_minting_logic.loyalty_minting_logic.withdraw"),
    [{ bytes: ctx.keyHashHex }],
    "JSON"
  );
  log(`loyalty_minting_logic hash: ${loyaltyMintLogic.hash}`);

  // 9. transfer_logic(VK(admin_pkh)) — using open transfer for simplicity
  const transferLogic = new MintingBlueprint("V3");
  transferLogic.paramScript(
    loadValidatorCompiledCode("transfer_logic.transfer_logic.withdraw"),
    [vkCredJson(ctx.keyHashHex)],
    "JSON"
  );
  log(`transfer_logic hash: ${transferLogic.hash}`);

  // 10. third_party_transfer_logic(VK(admin_pkh))
  const thirdPartyLogic = new MintingBlueprint("V3");
  thirdPartyLogic.paramScript(
    loadValidatorCompiledCode("third_party_transfer_logic.third_party_transfer_logic.withdraw"),
    [vkCredJson(ctx.keyHashHex)],
    "JSON"
  );
  log(`third_party_transfer_logic hash: ${thirdPartyLogic.hash}`);

  log("--- Dependency chain resolved ---");

  // Save all derived hashes
  state.protocolParamsPolicyId = ppCs;
  state.protocolParamsScriptCbor = ppMint.cbor;
  state.registryMintPolicyId = registryCs;
  state.registryMintScriptCbor = regMint.cbor;
  state.issuanceCborHexPolicyId = templateMint.hash;
  state.globalStakeHash = globalHash;
  state.globalScriptCbor = globalBlueprint.cbor;
  state.progLogicHash = progLogicHash;
  state.progLogicScriptCbor = baseBlueprint.cbor;
  state.registrySpendHash = regSpend.hash;
  state.registrySpendScriptCbor = regSpend.cbor;
  state.issuancePolicyId = issuanceMint.hash;
  state.issuanceScriptCbor = issuanceMint.cbor;
  state.loyaltyMintingLogicHash = loyaltyMintLogic.hash;
  state.loyaltyMintingLogicCbor = loyaltyMintLogic.cbor;
  state.transferLogicHash = transferLogic.hash;
  state.transferLogicCbor = transferLogic.cbor;
  state.thirdPartyLogicHash = thirdPartyLogic.hash;
  state.thirdPartyLogicCbor = thirdPartyLogic.cbor;

  // --- Step 2: Mint protocol params NFT ---
  log("\n=== Minting Protocol Params NFT ===");

  const ppDatum = {
    constructor: 0,
    fields: [
      { bytes: registryCs },              // registry_node_cs
      scriptCredJson(progLogicHash),       // prog_logic_cred
    ],
  };

  const txBuilder1 = new MeshTxBuilder({
    fetcher: ctx.kupo,
    submitter: ctx.ogmios,
    evaluator: ctx.ogmios,
  });

  const walletUtxos = await ctx.kupo.fetchAddressUTxOs(ctx.walletAddress);
  const ppTokenNameHex = Buffer.from("ProtocolParams").toString("hex");

  // Find a pure-ADA UTxO for collateral
  const collateral = walletUtxos.find(
    (u) => u.output.amount.length === 1 && u.output.amount[0].unit === "lovelace"
  );
  if (!collateral) throw new Error("No pure-ADA UTxO for collateral");

  await txBuilder1
    .txIn(seedUtxo1.input.txHash, seedUtxo1.input.outputIndex)
    .mintPlutusScriptV3()
    .mint("1", ppCs, ppTokenNameHex)
    .mintingScript(ppMint.cbor)
    .mintRedeemerValue("", "Mesh") // Unit redeemer
    .txOut(ctx.walletAddress, [
      { unit: "lovelace", quantity: "5000000" },
      { unit: ppCs + ppTokenNameHex, quantity: "1" },
    ])
    .txOutInlineDatumValue(ppDatum, "JSON")
    .txInCollateral(collateral.input.txHash, collateral.input.outputIndex)
    .selectUtxosFrom(walletUtxos)
    .changeAddress(ctx.walletAddress)
    .signingKey(ctx.signingKey)
    .complete();

  txBuilder1.completeSigning();
  const ppTxHash = await ctx.ogmios.submitTx(txBuilder1.txHex);
  log(`Protocol params minted! Tx: ${ppTxHash}`);
  log(`CardanoScan: https://preview.cardanoscan.io/transaction/${ppTxHash}`);

  state.protocolParamsTxHash = ppTxHash;
  saveState(state);

  // Wait for confirmation before registry init (needs different UTxOs)
  await waitForTx(ctx.kupo, ppTxHash);

  // --- Step 3: Init Registry (origin node) ---
  log("\n=== Initializing Registry ===");

  // Re-fetch UTxOs after protocol params mint
  const utxos2 = await ctx.kupo.fetchAddressUTxOs(ctx.walletAddress);

  // Find the seed UTxO for registry (seedUtxo2 might be spent as change, re-find it)
  const regSeedUtxo = utxos2.find(
    (u) => u.input.txHash === seedUtxo2.input.txHash &&
           u.input.outputIndex === seedUtxo2.input.outputIndex
  );

  if (!regSeedUtxo) {
    throw new Error("Registry seed UTxO not found — may have been consumed as fee input");
  }

  // Find a collateral UTxO (pure ADA, not the seed)
  const collateralUtxo = utxos2.find(
    (u) => u.input.txHash !== regSeedUtxo.input.txHash &&
           u.output.amount.length === 1 &&
           u.output.amount[0].unit === "lovelace"
  );

  if (!collateralUtxo) {
    throw new Error("No pure-ADA collateral UTxO available");
  }

  // Origin node datum: key="" next="" with placeholder transfer logic
  const originDatum = {
    constructor: 0,
    fields: [
      { bytes: "" },                           // key (empty = origin sentinel)
      { bytes: "" },                           // next (empty = end of list)
      scriptCredJson(transferLogic.hash),       // transfer_logic_script
      scriptCredJson(thirdPartyLogic.hash),     // third_party_transfer_logic_script
      { bytes: "" },                           // global_state_cs
    ],
  };

  // Registry redeemer: RegistryInit = constructor 0, no fields
  const registryInitRedeemer = { constructor: 0, fields: [] };

  const txBuilder2 = new MeshTxBuilder({
    fetcher: ctx.kupo,
    submitter: ctx.ogmios,
    evaluator: ctx.ogmios,
  });

  // Origin node token name is empty bytearray
  const originTn = "";

  await txBuilder2
    .txIn(regSeedUtxo.input.txHash, regSeedUtxo.input.outputIndex)
    .mintPlutusScriptV3()
    .mint("1", registryCs, originTn)
    .mintingScript(regMint.cbor)
    .mintRedeemerValue(registryInitRedeemer, "JSON")
    .txOut(ctx.walletAddress, [
      { unit: "lovelace", quantity: "2000000" },
      { unit: registryCs, quantity: "1" },
    ])
    .txOutInlineDatumValue(originDatum, "JSON")
    .txInCollateral(collateralUtxo.input.txHash, collateralUtxo.input.outputIndex)
    .changeAddress(ctx.walletAddress)
    .signingKey(ctx.signingKey)
    .complete();

  txBuilder2.completeSigning();
  const regTxHash = await ctx.ogmios.submitTx(txBuilder2.txHex);
  log(`Registry initialized! Tx: ${regTxHash}`);
  log(`CardanoScan: https://preview.cardanoscan.io/transaction/${regTxHash}`);

  state.registryInitTxHash = regTxHash;
  saveState(state);

  log("\n=== Bootstrap Complete ===");
  log(`Protocol params policy: ${ppCs}`);
  log(`Registry policy: ${registryCs}`);
  log(`Global stake hash: ${globalHash}`);
  log(`Prog logic hash: ${progLogicHash}`);
  log(`Issuance policy (loyalty): ${issuanceMint.hash}`);
}

// ---------------------------------------------------------------------------
// Phase 2: Register Stake Credentials + Token
// ---------------------------------------------------------------------------

async function registerToken() {
  const ctx = await setup();
  const state = loadState();

  if (!state.registryMintPolicyId || !state.registryInitTxHash) {
    throw new Error("Run bootstrap first");
  }

  // --- Step 1: Register stake credentials for withdraw-zero validators ---
  log("\n=== Registering Stake Credentials ===");

  const globalRewardAddr = serializeRewardAddress(state.globalStakeHash!, true, config.networkId);
  const transferRewardAddr = serializeRewardAddress(state.transferLogicHash!, true, config.networkId);
  const mintingRewardAddr = serializeRewardAddress(state.loyaltyMintingLogicHash!, true, config.networkId);

  log(`Global reward addr: ${globalRewardAddr}`);
  log(`Transfer reward addr: ${transferRewardAddr}`);
  log(`Minting reward addr: ${mintingRewardAddr}`);

  const walletUtxos = await ctx.kupo.fetchAddressUTxOs(ctx.walletAddress);
  const collateral = walletUtxos.find(
    (u) => u.output.amount.length === 1 && u.output.amount[0].unit === "lovelace"
  );
  if (!collateral) throw new Error("No pure-ADA UTxO for collateral");

  const regTxBuilder = new MeshTxBuilder({
    fetcher: ctx.kupo,
    submitter: ctx.ogmios,
    evaluator: ctx.ogmios,
  });

  // Conway: script stake registration is permissionless — no witness needed
  await regTxBuilder
    .registerStakeCertificate(globalRewardAddr)
    .registerStakeCertificate(transferRewardAddr)
    .registerStakeCertificate(mintingRewardAddr)
    .selectUtxosFrom(walletUtxos)
    .changeAddress(ctx.walletAddress)
    .signingKey(ctx.signingKey)
    .complete();

  regTxBuilder.completeSigning();
  const stakeRegTxHash = await ctx.ogmios.submitTx(regTxBuilder.txHex);
  log(`Stake credentials registered! Tx: ${stakeRegTxHash}`);
  log(`CardanoScan: https://preview.cardanoscan.io/transaction/${stakeRegTxHash}`);

  state.stakeRegTxHash = stakeRegTxHash;
  saveState(state);

  await waitForTx(ctx.kupo, stakeRegTxHash);

  // --- Step 2: Insert loyalty token into registry ---
  log("\n=== Registering Loyalty Token in Registry ===");

  const registryCs = state.registryMintPolicyId!;
  const issuanceCs = state.issuancePolicyId!;

  // Re-fetch UTxOs after stake registration
  const utxos2 = await ctx.kupo.fetchAddressUTxOs(ctx.walletAddress);

  // Find the origin node UTxO (has registry NFT with empty token name)
  const originUtxo = utxos2.find((u) =>
    u.output.amount.some((a) => a.unit === registryCs)
  );
  if (!originUtxo) throw new Error("Origin node UTxO not found");
  log(`Origin node UTxO: ${originUtxo.input.txHash}#${originUtxo.input.outputIndex}`);

  const collateral2 = utxos2.find(
    (u) => u.output.amount.length === 1 &&
           u.output.amount[0].unit === "lovelace" &&
           !(u.input.txHash === originUtxo.input.txHash && u.input.outputIndex === originUtxo.input.outputIndex)
  );
  if (!collateral2) throw new Error("No pure-ADA collateral UTxO");

  // Updated origin node: next → issuanceCs
  const updatedOriginDatum = {
    constructor: 0,
    fields: [
      { bytes: "" },                                       // key (still origin)
      { bytes: issuanceCs },                               // next → loyalty policy
      scriptCredJson(state.transferLogicHash!),             // transfer_logic_script
      scriptCredJson(state.thirdPartyLogicHash!),           // third_party_transfer_logic_script
      { bytes: "" },                                       // global_state_cs
    ],
  };

  // New node: loyalty token entry
  const newNodeDatum = {
    constructor: 0,
    fields: [
      { bytes: issuanceCs },                               // key = loyalty policy ID
      { bytes: "" },                                       // next = end of list
      scriptCredJson(state.transferLogicHash!),             // transfer_logic_script
      scriptCredJson(state.thirdPartyLogicHash!),           // third_party_transfer_logic_script
      { bytes: "" },                                       // global_state_cs (none for now)
    ],
  };

  // RegistryInsert redeemer: constructor 1, fields [key, hashed_param]
  const insertRedeemer = {
    constructor: 1,
    fields: [
      { bytes: issuanceCs },  // key
      { bytes: "" },          // hashed_param (not validated in our impl)
    ],
  };

  const txBuilder3 = new MeshTxBuilder({
    fetcher: ctx.kupo,
    submitter: ctx.ogmios,
    evaluator: ctx.ogmios,
  });

  await txBuilder3
    // Spend the origin node
    .txIn(originUtxo.input.txHash, originUtxo.input.outputIndex)
    // Mint new registry NFT with loyalty policy as token name
    .mintPlutusScriptV3()
    .mint("1", registryCs, issuanceCs)
    .mintingScript(state.registryMintScriptCbor!)
    .mintRedeemerValue(insertRedeemer, "JSON")
    // Output 1: Updated origin node (next → issuanceCs)
    .txOut(ctx.walletAddress, [
      { unit: "lovelace", quantity: "5000000" },
      { unit: registryCs, quantity: "1" },
    ])
    .txOutInlineDatumValue(updatedOriginDatum, "JSON")
    // Output 2: New loyalty token node
    .txOut(ctx.walletAddress, [
      { unit: "lovelace", quantity: "5000000" },
      { unit: registryCs + issuanceCs, quantity: "1" },
    ])
    .txOutInlineDatumValue(newNodeDatum, "JSON")
    .txInCollateral(collateral2.input.txHash, collateral2.input.outputIndex)
    .selectUtxosFrom(utxos2)
    .changeAddress(ctx.walletAddress)
    .signingKey(ctx.signingKey)
    .complete();

  txBuilder3.completeSigning();
  const regTokenTxHash = await ctx.ogmios.submitTx(txBuilder3.txHex);
  log(`Loyalty token registered! Tx: ${regTokenTxHash}`);
  log(`CardanoScan: https://preview.cardanoscan.io/transaction/${regTokenTxHash}`);

  state.registerTxHash = regTokenTxHash;
  saveState(state);

  log("\n=== Phase 2 Complete ===");
  log(`Stake credentials registered: ${stakeRegTxHash}`);
  log(`Token registered in registry: ${regTokenTxHash}`);
}

// ---------------------------------------------------------------------------
// Phase 2.5: Deploy Reference Scripts
// ---------------------------------------------------------------------------

async function deployRefScripts() {
  const ctx = await setup();
  const state = loadState();

  if (!state.globalScriptCbor || !state.issuanceScriptCbor) {
    throw new Error("Run bootstrap first");
  }

  log("\n=== Deploying Reference Scripts ===");
  log("Deploying 4 validators as reference scripts to reduce per-tx execution budget...");

  const walletUtxos = await ctx.kupo.fetchAddressUTxOs(ctx.walletAddress);

  // Deploy all 4 scripts as reference UTxOs in a single tx
  // Each output: min ADA + reference_script field
  const txBuilder = new MeshTxBuilder({
    fetcher: ctx.kupo,
    submitter: ctx.ogmios,
    evaluator: ctx.ogmios,
  });

  await txBuilder
    // Output 0: programmable_logic_global (~3.3KB → needs ~25 ADA min)
    .txOut(ctx.walletAddress, [{ unit: "lovelace", quantity: "30000000" }])
    .txOutReferenceScript(state.globalScriptCbor!, "V3")
    // Output 1: issuance_mint (~350B)
    .txOut(ctx.walletAddress, [{ unit: "lovelace", quantity: "10000000" }])
    .txOutReferenceScript(state.issuanceScriptCbor!, "V3")
    // Output 2: loyalty_minting_logic (~185B)
    .txOut(ctx.walletAddress, [{ unit: "lovelace", quantity: "10000000" }])
    .txOutReferenceScript(state.loyaltyMintingLogicCbor!, "V3")
    // Output 3: transfer_logic (~213B)
    .txOut(ctx.walletAddress, [{ unit: "lovelace", quantity: "10000000" }])
    .txOutReferenceScript(state.transferLogicCbor!, "V3")
    .selectUtxosFrom(walletUtxos)
    .changeAddress(ctx.walletAddress)
    .signingKey(ctx.signingKey)
    .complete();

  txBuilder.completeSigning();
  const deployTxHash = await ctx.ogmios.submitTx(txBuilder.txHex);
  log(`Reference scripts deployed! Tx: ${deployTxHash}`);
  log(`CardanoScan: https://preview.cardanoscan.io/transaction/${deployTxHash}`);

  // Save the UTxO locations for each script
  // Outputs are in the order we added them (0-3)
  state.refScriptsTxHash = deployTxHash;
  state.globalRefUtxo = { txHash: deployTxHash, index: 0 };
  state.issuanceRefUtxo = { txHash: deployTxHash, index: 1 };
  state.mintingLogicRefUtxo = { txHash: deployTxHash, index: 2 };
  state.transferLogicRefUtxo = { txHash: deployTxHash, index: 3 };
  saveState(state);

  await waitForTx(ctx.kupo, deployTxHash);

  log("\n=== Reference Scripts Deployed ===");
  log(`Global: ${deployTxHash}#0`);
  log(`Issuance: ${deployTxHash}#1`);
  log(`Minting logic: ${deployTxHash}#2`);
  log(`Transfer logic: ${deployTxHash}#3`);
}

// ---------------------------------------------------------------------------
// Fix Registry — Re-attach inline datum lost during deploy phase
// ---------------------------------------------------------------------------

async function fixRegistry() {
  const ctx = await setup();
  const state = loadState();

  if (!state.registryMintPolicyId || !state.issuancePolicyId) {
    throw new Error("Run bootstrap + register first");
  }

  log("\n=== Fixing Registry Node Datum ===");

  const registryCs = state.registryMintPolicyId!;
  const issuanceCs = state.issuancePolicyId!;

  const walletUtxos = await ctx.kupo.fetchAddressUTxOs(ctx.walletAddress);

  // Find the registry node UTxO (has registry NFT with token name = issuanceCs)
  const registryNodeUtxo = walletUtxos.find((u) =>
    u.output.amount.some((a) => a.unit === registryCs + issuanceCs)
  );
  if (!registryNodeUtxo) throw new Error("Registry node UTxO not found");
  log(`Registry node: ${registryNodeUtxo.input.txHash}#${registryNodeUtxo.input.outputIndex}`);

  // Re-create the RegistryNode inline datum (same as register phase)
  const registryDatum = {
    constructor: 0,
    fields: [
      { bytes: issuanceCs },                               // key = loyalty policy ID
      { bytes: "" },                                       // next = end of list
      scriptCredJson(state.transferLogicHash!),             // transfer_logic_script
      scriptCredJson(state.thirdPartyLogicHash!),           // third_party_transfer_logic_script
      { bytes: "" },                                       // global_state_cs
    ],
  };

  // Send the registry token back to wallet address WITH the datum
  const txBuilder = new MeshTxBuilder({
    fetcher: ctx.kupo,
    submitter: ctx.ogmios,
  });

  // Build output: registry token + any other tokens on the UTxO + 2 ADA
  const registryTokens = registryNodeUtxo.output.amount.filter(
    (a) => a.unit !== "lovelace"
  );

  await txBuilder
    .txIn(registryNodeUtxo.input.txHash, registryNodeUtxo.input.outputIndex)
    .txOut(ctx.walletAddress, [
      { unit: "lovelace", quantity: "2000000" },
      ...registryTokens,
    ])
    .txOutInlineDatumValue(registryDatum, "JSON")
    .selectUtxosFrom(walletUtxos)
    .changeAddress(ctx.walletAddress)
    .signingKey(ctx.signingKey)
    .complete();

  txBuilder.completeSigning();
  const fixTxHash = await ctx.ogmios.submitTx(txBuilder.txHex);
  log(`Registry datum fixed! Tx: ${fixTxHash}`);
  log(`CardanoScan: https://preview.cardanoscan.io/transaction/${fixTxHash}`);

  await waitForTx(ctx.kupo, fixTxHash);
  log("\n=== Registry Fix Complete ===");
}

// ---------------------------------------------------------------------------
// Phase 3: Mint Loyalty Tokens
// ---------------------------------------------------------------------------

async function mintTokens() {
  const ctx = await setup();
  const state = loadState();

  if (!state.issuancePolicyId || !state.registerTxHash) {
    throw new Error("Run bootstrap + register first");
  }

  log("\n=== Minting Loyalty Tokens ===");

  const issuanceCs = state.issuancePolicyId!;
  const registryCs = state.registryMintPolicyId!;
  const ppCs = state.protocolParamsPolicyId!;
  const ppTokenNameHex = Buffer.from("ProtocolParams").toString("hex");

  // Build the programmable logic address for the recipient (our wallet as stake VK)
  const progLogicAddr = buildProgLogicAddress(
    state.progLogicHash!,
    ctx.keyHashHex,
    config.networkId,
  );
  log(`Programmable logic address: ${progLogicAddr}`);

  // Fetch UTxOs
  const walletUtxos = await ctx.kupo.fetchAddressUTxOs(ctx.walletAddress);

  // Find protocol params NFT UTxO (reference input)
  const ppUtxo = walletUtxos.find((u) =>
    u.output.amount.some((a) => a.unit === ppCs + ppTokenNameHex)
  );
  if (!ppUtxo) throw new Error("Protocol params NFT UTxO not found");
  log(`Protocol params ref: ${ppUtxo.input.txHash}#${ppUtxo.input.outputIndex}`);

  // Find loyalty registry node UTxO (reference input)
  // The loyalty node has token name = issuanceCs
  const registryNodeUtxo = walletUtxos.find((u) =>
    u.output.amount.some((a) => a.unit === registryCs + issuanceCs)
  );
  if (!registryNodeUtxo) throw new Error("Loyalty registry node UTxO not found");
  log(`Registry node ref: ${registryNodeUtxo.input.txHash}#${registryNodeUtxo.input.outputIndex}`);

  // Exclude reference inputs + reference script UTxOs from selection pool.
  // If input selector consumes a UTxO with a reference script, the node sees
  // that script as "available" and our inline copy becomes extraneous (error 3104).
  const excludedIds = new Set([
    `${ppUtxo.input.txHash}#${ppUtxo.input.outputIndex}`,
    `${registryNodeUtxo.input.txHash}#${registryNodeUtxo.input.outputIndex}`,
  ]);
  // Also exclude reference script UTxOs if they exist
  if (state.refScriptsTxHash) {
    for (let i = 0; i < 5; i++) {
      excludedIds.add(`${state.refScriptsTxHash}#${i}`);
    }
  }
  const selectableUtxos = walletUtxos.filter(
    (u) => !excludedIds.has(`${u.input.txHash}#${u.input.outputIndex}`)
  );
  log(`Excluded ${excludedIds.size} UTxOs from selection, ${selectableUtxos.length} selectable`);

  // Collateral: prefer pure-ADA, but accept any UTxO with sufficient ADA (Conway supports collateral return)
  const collateral = selectableUtxos.find(
    (u) => u.output.amount.length === 1 && u.output.amount[0].unit === "lovelace"
  ) || selectableUtxos.reduce((best, u) => {
    const ada = BigInt(u.output.amount.find((a) => a.unit === "lovelace")?.quantity || "0");
    const bestAda = BigInt(best.output.amount.find((a) => a.unit === "lovelace")?.quantity || "0");
    return ada > bestAda ? u : best;
  }, selectableUtxos[0]);
  if (!collateral) throw new Error("No collateral UTxO");
  log(`Collateral: ${collateral.input.txHash}#${collateral.input.outputIndex} (${collateral.output.amount.map(a => a.unit === "lovelace" ? `${Number(a.quantity)/1e6} ADA` : a.unit.slice(0,8)+"...").join(", ")})`);

  // Reward addresses for withdraw-zero
  const globalRewardAddr = serializeRewardAddress(state.globalStakeHash!, true, config.networkId);
  const mintingRewardAddr = serializeRewardAddress(state.loyaltyMintingLogicHash!, true, config.networkId);
  const transferRewardAddr = serializeRewardAddress(state.transferLogicHash!, true, config.networkId);

  // Token name for loyalty tokens
  const loyaltyTokenName = Buffer.from("LOYAL").toString("hex");
  const mintQty = 1000;

  // --- Redeemers ---

  // issuance_mint redeemer: SmartTokenMintingAction { minting_logic_cred: Script(hash) }
  const issuanceRedeemer = {
    constructor: 0,
    fields: [scriptCredJson(state.loyaltyMintingLogicHash!)],
  };

  // programmable_logic_global redeemer: TransferAct { proofs: [], mint_proofs: [TokenExists { node_idx }] }
  // Reference inputs are sorted lexicographically by tx hash:
  //   registry node (0e94...) sorts before protocol params (2a4d...)
  // Determine the correct index dynamically
  const refInputsSorted = [
    { hash: ppUtxo.input.txHash, idx: ppUtxo.input.outputIndex, type: "pp" },
    { hash: registryNodeUtxo.input.txHash, idx: registryNodeUtxo.input.outputIndex, type: "registry" },
  ].sort((a, b) => {
    if (a.hash < b.hash) return -1;
    if (a.hash > b.hash) return 1;
    return a.idx - b.idx;
  });
  const registryNodeIdx = refInputsSorted.findIndex((r) => r.type === "registry");
  log(`Reference inputs sorted: registry at index ${registryNodeIdx}`);

  const globalRedeemer = {
    constructor: 0, // TransferAct
    fields: [
      { list: [] },                                    // proofs (no programmable token inputs)
      { list: [{ constructor: 0, fields: [{ int: registryNodeIdx }] }] }, // mint_proofs: [TokenExists]
    ],
  };

  log(`Minting ${mintQty} LOYAL tokens to programmable logic address...`);

  // Manual execution budgets — no evaluator, explicit per-redeemer exUnits.
  // Protocol limit: 16.5M mem / 10B steps total across all scripts.
  // Inline scripts avoid the MeshTxBuilder withdrawalTxInReference() crash.
  const exBudget = {
    issuanceMint:     { mem: 3_000_000, steps: 1_500_000_000 },  // ~350B script
    globalWithdraw:   { mem: 8_000_000, steps: 4_000_000_000 },  // ~3.3KB script (biggest)
    mintingWithdraw:  { mem: 2_000_000, steps: 1_000_000_000 },  // ~185B script
    transferWithdraw: { mem: 2_000_000, steps: 1_000_000_000 },  // ~213B script
    // Total:          15M mem,          7.5B steps — within limits
  };
  log(`ExUnits budget: ${JSON.stringify(exBudget)}`);

  const txBuilder = new MeshTxBuilder({
    fetcher: ctx.kupo,
    submitter: ctx.ogmios,
    // No evaluator — using explicit exUnits to stay within 16.5M mem limit
  });

  await txBuilder
    // Reference inputs: protocol params + registry node
    .readOnlyTxInReference(ppUtxo.input.txHash, ppUtxo.input.outputIndex)
    .readOnlyTxInReference(registryNodeUtxo.input.txHash, registryNodeUtxo.input.outputIndex)
    // Mint loyalty tokens via issuance_mint (inline)
    .mintPlutusScriptV3()
    .mint(String(mintQty), issuanceCs, loyaltyTokenName)
    .mintingScript(state.issuanceScriptCbor!)
    .mintRedeemerValue(issuanceRedeemer, "JSON", exBudget.issuanceMint)
    // Withdraw-zero: programmable_logic_global (inline — largest script)
    .withdrawalPlutusScriptV3()
    .withdrawal(globalRewardAddr, "0")
    .withdrawalScript(state.globalScriptCbor!)
    .withdrawalRedeemerValue(globalRedeemer, "JSON", exBudget.globalWithdraw)
    // Withdraw-zero: loyalty_minting_logic (inline)
    .withdrawalPlutusScriptV3()
    .withdrawal(mintingRewardAddr, "0")
    .withdrawalScript(state.loyaltyMintingLogicCbor!)
    .withdrawalRedeemerValue("", "Mesh", exBudget.mintingWithdraw)
    // Withdraw-zero: transfer_logic (inline)
    .withdrawalPlutusScriptV3()
    .withdrawal(transferRewardAddr, "0")
    .withdrawalScript(state.transferLogicCbor!)
    .withdrawalRedeemerValue("", "Mesh", exBudget.transferWithdraw)
    // Output: loyalty tokens at programmable logic address
    .txOut(progLogicAddr, [
      { unit: "lovelace", quantity: "5000000" },
      { unit: issuanceCs + loyaltyTokenName, quantity: String(mintQty) },
    ])
    // Required signer (admin = our wallet)
    .requiredSignerHash(ctx.keyHashHex)
    // Collateral (with return for non-ADA tokens)
    .txInCollateral(collateral.input.txHash, collateral.input.outputIndex)
    .setTotalCollateral("5000000")
    .setCollateralReturnAddress(ctx.walletAddress)
    .selectUtxosFrom(selectableUtxos)
    .changeAddress(ctx.walletAddress)
    .signingKey(ctx.signingKey)
    .complete();

  txBuilder.completeSigning();
  const mintTxHash = await ctx.ogmios.submitTx(txBuilder.txHex);
  log(`Loyalty tokens minted! Tx: ${mintTxHash}`);
  log(`CardanoScan: https://preview.cardanoscan.io/transaction/${mintTxHash}`);

  state.mintTxHash = mintTxHash;
  saveState(state);

  log("\n=== Phase 3 Complete ===");
  log(`${mintQty} LOYAL tokens minted at programmable logic address`);
  log(`Policy: ${issuanceCs}`);
}

// ---------------------------------------------------------------------------
// Phase 4: Transfer
// ---------------------------------------------------------------------------

async function transferTokens() {
  const ctx = await setup();
  const state = loadState();

  if (!state.mintTxHash) {
    throw new Error("Run mint first");
  }

  log("\n=== Transferring Loyalty Tokens ===");

  const issuanceCs = state.issuancePolicyId!;
  const registryCs = state.registryMintPolicyId!;
  const ppCs = state.protocolParamsPolicyId!;
  const ppTokenNameHex = Buffer.from("ProtocolParams").toString("hex");
  const loyaltyTokenName = Buffer.from("LOYAL").toString("hex");

  // Source: programmable logic address with OUR stake VK
  const progLogicAddr = buildProgLogicAddress(
    state.progLogicHash!,
    ctx.keyHashHex,
    config.networkId,
  );
  log(`Programmable logic address: ${progLogicAddr}`);

  // The LOYAL tokens UTxO — track latest location (moves each transfer).
  // After mint: at mintTxHash#0. After each transfer: at transferTxHash#0.
  const loyaltyTxHash = state.transferTxHash || state.mintTxHash!;
  const loyaltyUtxo = {
    txHash: loyaltyTxHash,
    outputIndex: 0,
    amount: [
      { unit: "lovelace", quantity: "5000000" },
      { unit: issuanceCs + loyaltyTokenName, quantity: "1000" },
    ],
    address: progLogicAddr,
  };
  log(`LOYAL UTxO: ${loyaltyUtxo.txHash}#${loyaltyUtxo.outputIndex}`);

  // Fetch wallet UTxOs for fees + collateral + reference inputs
  const walletUtxos = await ctx.kupo.fetchAddressUTxOs(ctx.walletAddress);

  // Protocol params NFT (reference input)
  const ppUtxo = walletUtxos.find((u) =>
    u.output.amount.some((a) => a.unit === ppCs + ppTokenNameHex)
  );
  if (!ppUtxo) throw new Error("Protocol params NFT not found");
  log(`Protocol params ref: ${ppUtxo.input.txHash}#${ppUtxo.input.outputIndex}`);

  // Registry node (reference input)
  const registryNodeUtxo = walletUtxos.find((u) =>
    u.output.amount.some((a) => a.unit === registryCs + issuanceCs)
  );
  if (!registryNodeUtxo) throw new Error("Registry node not found");
  log(`Registry node ref: ${registryNodeUtxo.input.txHash}#${registryNodeUtxo.input.outputIndex}`);

  // Exclude data UTxOs + reference script UTxOs from selection
  const excludedIds = new Set([
    `${ppUtxo.input.txHash}#${ppUtxo.input.outputIndex}`,
    `${registryNodeUtxo.input.txHash}#${registryNodeUtxo.input.outputIndex}`,
  ]);
  if (state.refScriptsTxHash) {
    for (let i = 0; i < 5; i++) {
      excludedIds.add(`${state.refScriptsTxHash}#${i}`);
    }
  }
  const selectableUtxos = walletUtxos.filter(
    (u) => !excludedIds.has(`${u.input.txHash}#${u.input.outputIndex}`)
  );
  log(`Excluded ${excludedIds.size} UTxOs, ${selectableUtxos.length} selectable`);

  // Collateral
  const collateral = selectableUtxos.find(
    (u) => u.output.amount.length === 1 && u.output.amount[0].unit === "lovelace"
  ) || selectableUtxos.reduce((best, u) => {
    const ada = BigInt(u.output.amount.find((a) => a.unit === "lovelace")?.quantity || "0");
    const bestAda = BigInt(best.output.amount.find((a) => a.unit === "lovelace")?.quantity || "0");
    return ada > bestAda ? u : best;
  }, selectableUtxos[0]);
  if (!collateral) throw new Error("No collateral UTxO");
  log(`Collateral: ${collateral.input.txHash}#${collateral.input.outputIndex}`);

  // Reward addresses for withdraw-zero
  const globalRewardAddr = serializeRewardAddress(state.globalStakeHash!, true, config.networkId);
  const transferRewardAddr = serializeRewardAddress(state.transferLogicHash!, true, config.networkId);

  // Reference input sort order for registry node index
  const refInputsSorted = [
    { hash: ppUtxo.input.txHash, idx: ppUtxo.input.outputIndex, type: "pp" },
    { hash: registryNodeUtxo.input.txHash, idx: registryNodeUtxo.input.outputIndex, type: "registry" },
  ].sort((a, b) => {
    if (a.hash < b.hash) return -1;
    if (a.hash > b.hash) return 1;
    return a.idx - b.idx;
  });
  const registryNodeIdx = refInputsSorted.findIndex((r) => r.type === "registry");
  log(`Registry at reference input index ${registryNodeIdx}`);

  // --- Redeemers ---

  // programmable_logic_base redeemer: any Data (validator ignores it)
  // We'll use Unit (constructor 0, no fields)
  const baseRedeemer = { constructor: 0, fields: [] };

  // programmable_logic_global redeemer: TransferAct { proofs, mint_proofs }
  // proofs: one TokenExists per non-ADA policy in inputs (just issuanceCs)
  // mint_proofs: empty (no minting)
  const globalRedeemer = {
    constructor: 0, // TransferAct
    fields: [
      { list: [{ constructor: 0, fields: [{ int: registryNodeIdx }] }] }, // proofs: [TokenExists]
      { list: [] },                                                        // mint_proofs: []
    ],
  };

  // Manual exUnits — 3 scripts (spend + 2 withdrawals), well within 16.5M
  const exBudget = {
    baseSpend:        { mem: 2_000_000, steps: 1_000_000_000 },  // tiny validator
    globalWithdraw:   { mem: 8_000_000, steps: 4_000_000_000 },  // complex
    transferWithdraw: { mem: 2_000_000, steps: 1_000_000_000 },  // simple
    // Total:          12M mem,          6B steps
  };
  log(`ExUnits budget: ${JSON.stringify(exBudget)}`);

  // Transfer: send all 1000 LOYAL back to the same programmable logic address.
  // This proves the spend→validate→output flow without needing a second key pair.
  log(`Transferring 1000 LOYAL tokens (round-trip to same address)...`);

  const txBuilder = new MeshTxBuilder({
    fetcher: ctx.kupo,
    submitter: ctx.ogmios,
    // No evaluator — manual exUnits
  });

  await txBuilder
    // Reference inputs: protocol params + registry node
    .readOnlyTxInReference(ppUtxo.input.txHash, ppUtxo.input.outputIndex)
    .readOnlyTxInReference(registryNodeUtxo.input.txHash, registryNodeUtxo.input.outputIndex)
    // Script input: LOYAL tokens at programmable logic address
    .spendingPlutusScriptV3()
    .txIn(loyaltyUtxo.txHash, loyaltyUtxo.outputIndex, loyaltyUtxo.amount, loyaltyUtxo.address, 0)
    .txInInlineDatumPresent()
    .txInScript(state.progLogicScriptCbor!)
    .spendingReferenceTxInRedeemerValue(baseRedeemer, "JSON", exBudget.baseSpend)
    // Withdraw-zero: programmable_logic_global (validates transfer)
    .withdrawalPlutusScriptV3()
    .withdrawal(globalRewardAddr, "0")
    .withdrawalScript(state.globalScriptCbor!)
    .withdrawalRedeemerValue(globalRedeemer, "JSON", exBudget.globalWithdraw)
    // Withdraw-zero: transfer_logic (checks admin signature)
    .withdrawalPlutusScriptV3()
    .withdrawal(transferRewardAddr, "0")
    .withdrawalScript(state.transferLogicCbor!)
    .withdrawalRedeemerValue("", "Mesh", exBudget.transferWithdraw)
    // Output: LOYAL tokens back to programmable logic address
    .txOut(progLogicAddr, [
      { unit: "lovelace", quantity: "5000000" },
      { unit: issuanceCs + loyaltyTokenName, quantity: "1000" },
    ])
    // Required signer: our wallet (for input authorization + transfer_logic admin check)
    .requiredSignerHash(ctx.keyHashHex)
    // Collateral
    .txInCollateral(collateral.input.txHash, collateral.input.outputIndex)
    .setTotalCollateral("5000000")
    .setCollateralReturnAddress(ctx.walletAddress)
    .selectUtxosFrom(selectableUtxos)
    .changeAddress(ctx.walletAddress)
    .signingKey(ctx.signingKey)
    .complete();

  txBuilder.completeSigning();
  const transferTxHash = await ctx.ogmios.submitTx(txBuilder.txHex);
  log(`Tokens transferred! Tx: ${transferTxHash}`);
  log(`CardanoScan: https://preview.cardanoscan.io/transaction/${transferTxHash}`);

  state.transferTxHash = transferTxHash;
  saveState(state);

  log("\n=== Phase 4 Complete ===");
  log(`1000 LOYAL tokens transferred (round-trip) at programmable logic address`);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

const command = process.argv[2] || "bootstrap";

try {
  switch (command) {
    case "bootstrap":
      await bootstrap();
      break;
    case "register":
      await registerToken();
      break;
    case "deploy":
      await deployRefScripts();
      break;
    case "fix-registry":
      await fixRegistry();
      break;
    case "mint":
      await mintTokens();
      break;
    case "transfer":
      await transferTokens();
      break;
    default:
      log(`Unknown command: ${command}`);
      log("Usage: npm test [bootstrap|register|deploy|mint|transfer]");
      process.exit(1);
  }
} catch (err: any) {
  console.error("[cip113] ERROR:", JSON.stringify(err, null, 2));
  process.exit(1);
}
