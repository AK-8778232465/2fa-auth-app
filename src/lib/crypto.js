const encoder = new TextEncoder();
const decoder = new TextDecoder();

function encodeBase64(bytes) {
  let output = "";
  for (const byte of bytes) {
    output += String.fromCharCode(byte);
  }

  return btoa(output);
}

function decodeBase64(value) {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }

  return bytes;
}

async function deriveKey(password, salt) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 250000,
      hash: "SHA-256"
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function deriveBits(password, salt) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  return crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 250000,
      hash: "SHA-256"
    },
    baseKey,
    256
  );
}

export async function encryptBackup(payload, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(JSON.stringify(payload))
  );

  return {
    version: 1,
    cipher: "AES-GCM",
    kdf: {
      name: "PBKDF2",
      hash: "SHA-256",
      iterations: 250000
    },
    salt: encodeBase64(salt),
    iv: encodeBase64(iv),
    data: encodeBase64(new Uint8Array(encrypted))
  };
}

export async function decryptBackup(encryptedPayload, password) {
  const salt = decodeBase64(encryptedPayload.salt);
  const iv = decodeBase64(encryptedPayload.iv);
  const encryptedData = decodeBase64(encryptedPayload.data);
  const key = await deriveKey(password, salt);

  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      encryptedData
    );

    return JSON.parse(decoder.decode(decrypted));
  } catch (error) {
    throw new Error("Backup password is invalid or the file is corrupted.");
  }
}

export async function createPasswordRecord(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const verifier = new Uint8Array(await deriveBits(password, salt));

  return {
    version: 1,
    salt: encodeBase64(salt),
    verifier: encodeBase64(verifier)
  };
}

export async function verifyPassword(password, record) {
  const salt = decodeBase64(record.salt);
  const derived = new Uint8Array(await deriveBits(password, salt));

  return encodeBase64(derived) === record.verifier;
}
