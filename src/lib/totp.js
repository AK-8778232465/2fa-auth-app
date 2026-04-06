import { decodeBase32 } from "./base32.js";

const DEFAULT_ALGORITHM = "SHA-1";
const SUPPORTED_ALGORITHMS = new Set(["SHA-1", "SHA-256", "SHA-512"]);

function normalizeAlgorithm(algorithm = DEFAULT_ALGORITHM) {
  const normalized = algorithm.toUpperCase().replace(/^SHA(\d+)$/, "SHA-$1");
  if (!SUPPORTED_ALGORITHMS.has(normalized)) {
    throw new Error(`Unsupported algorithm: ${algorithm}`);
  }

  return normalized;
}

function formatCode(code, digits) {
  if (digits === 6) {
    return `${code.slice(0, 3)} ${code.slice(3)}`;
  }

  if (digits === 8) {
    return `${code.slice(0, 4)} ${code.slice(4)}`;
  }

  return code;
}

function padSecret(secret) {
  return secret.toUpperCase().replace(/[\s-]/g, "");
}

export function parseOtpInput(rawValue) {
  const trimmed = rawValue.trim();

  if (!trimmed) {
    throw new Error("Secret is required.");
  }

  if (!trimmed.toLowerCase().startsWith("otpauth://")) {
    return {
      label: "",
      username: "",
      secret: padSecret(trimmed),
      algorithm: DEFAULT_ALGORITHM,
      digits: 6,
      period: 30
    };
  }

  const url = new URL(trimmed);
  if (url.protocol !== "otpauth:" || url.hostname.toLowerCase() !== "totp") {
    throw new Error("Only otpauth://totp URIs are supported.");
  }

  const labelPart = decodeURIComponent(url.pathname.replace(/^\//, ""));
  const [issuerFromLabel, accountFromLabel] = labelPart.includes(":")
    ? labelPart.split(/:(.+)/, 2)
    : ["", labelPart];

  const secret = url.searchParams.get("secret");
  if (!secret) {
    throw new Error("The OTP URI does not contain a secret.");
  }

  const issuer = url.searchParams.get("issuer") || issuerFromLabel || "";
  const algorithm = normalizeAlgorithm(url.searchParams.get("algorithm") || DEFAULT_ALGORITHM);
  const digits = Number.parseInt(url.searchParams.get("digits") || "6", 10);
  const period = Number.parseInt(url.searchParams.get("period") || "30", 10);

  return {
    label: issuer || accountFromLabel || "Imported Account",
    username: accountFromLabel && issuer ? accountFromLabel : accountFromLabel || "",
    secret: padSecret(secret),
    algorithm,
    digits,
    period
  };
}

async function createHmac(counter, secret, algorithm) {
  const key = await crypto.subtle.importKey(
    "raw",
    decodeBase32(secret),
    { name: "HMAC", hash: normalizeAlgorithm(algorithm) },
    false,
    ["sign"]
  );

  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setBigUint64(0, BigInt(counter));

  return crypto.subtle.sign("HMAC", key, buffer);
}

export async function generateTotp({
  secret,
  period = 30,
  digits = 6,
  algorithm = DEFAULT_ALGORITHM,
  timestamp = Date.now()
}) {
  if (!secret) {
    throw new Error("Secret is required.");
  }

  if (!Number.isInteger(period) || period < 1) {
    throw new Error("Period must be a positive integer.");
  }

  if (![6, 8].includes(digits)) {
    throw new Error("Digits must be 6 or 8.");
  }

  const counter = Math.floor(timestamp / 1000 / period);
  const hmac = new Uint8Array(await createHmac(counter, secret, algorithm));
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const otp = String(binary % (10 ** digits)).padStart(digits, "0");
  const nowInSeconds = Math.floor(timestamp / 1000);
  const expiresIn = period - (nowInSeconds % period);

  return {
    code: otp,
    formattedCode: formatCode(otp, digits),
    expiresIn,
    progress: (period - expiresIn) / period
  };
}

export function sanitizeAccountPayload(input) {
  const parsed = parseOtpInput(input.secretInput);
  const period = Number.parseInt(input.period ?? parsed.period, 10);
  const digits = Number.parseInt(input.digits ?? parsed.digits, 10);
  const algorithm = normalizeAlgorithm(input.algorithm ?? parsed.algorithm);
  const label = (input.label || parsed.label || "").trim();
  const username = (input.username || parsed.username || "").trim();

  if (!label) {
    throw new Error("Account name is required.");
  }

  if (period < 30 || period > 300 || period % 30 !== 0) {
    throw new Error("Timer interval must be between 30 and 300 seconds in 30 second steps.");
  }

  decodeBase32(parsed.secret);

  return {
    label,
    username,
    secret: parsed.secret,
    digits,
    period,
    algorithm
  };
}

export function serializeAccountsForBackup(accounts) {
  return {
    version: 1,
    exportedAt: new Date().toISOString(),
    accounts: accounts.map((account) => ({
      label: account.label,
      username: account.username,
      secret: account.secret,
      digits: account.digits,
      period: account.period,
      algorithm: account.algorithm,
      createdAt: account.createdAt,
      updatedAt: account.updatedAt
    }))
  };
}
