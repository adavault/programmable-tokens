/**
 * CIP-113 Programmable Tokens — Test Configuration
 *
 * Providers:
 *   - Ogmios (tx evaluation + submission): localhost:1337 via SSH tunnel
 *   - Kupo (UTxO fetcher): localhost:1442 via SSH tunnel
 *
 * SSH tunnels (run before testing):
 *   ssh -N -L 1337:localhost:1337 -L 1442:localhost:1442 cardano@vducdn59
 *
 * Wallet:
 *   Uses preview testnet wallet keys from vducdn59.
 *   Copy payment.skey to test/keys/ (gitignored).
 */

import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));

export const config = {
  network: "preview" as const,
  networkId: 0,

  ogmiosUrl: "http://localhost:1337",
  kupoUrl: "http://localhost:1442",

  paymentSkeyPath: join(__dirname, "keys", "payment.skey"),

  blueprintPath: join(__dirname, "..", "plutus.json"),
};

/**
 * Load the payment signing key from the key file.
 */
export function loadSigningKey(): string {
  const raw = readFileSync(config.paymentSkeyPath, "utf-8");
  try {
    const envelope = JSON.parse(raw);
    const cborHex: string = envelope.cborHex;
    if (cborHex.startsWith("5820")) {
      return cborHex.slice(4);
    }
    return cborHex;
  } catch {
    return raw.trim();
  }
}

/**
 * Load a validator's compiled code from the blueprint by title.
 * Titles follow: "module.validator_name.handler"
 */
export function loadValidatorCompiledCode(title: string): string {
  const blueprint = JSON.parse(
    readFileSync(config.blueprintPath, "utf-8")
  );
  const validator = blueprint.validators.find(
    (v: { title: string }) => v.title === title
  );
  if (!validator) {
    const available = blueprint.validators.map((v: { title: string }) => v.title).join(", ");
    throw new Error(`${title} not found in blueprint. Available: ${available}`);
  }
  return validator.compiledCode;
}
