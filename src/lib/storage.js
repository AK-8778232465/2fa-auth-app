const STORAGE_KEYS = {
  legacyAccounts: "totp_accounts",
  vault: "totp_vault",
  auth: "totp_auth"
};

function getStorageArea() {
  if (globalThis.chrome?.storage?.local) {
    return globalThis.chrome.storage.local;
  }

  throw new Error("Chrome storage API is not available.");
}

export async function getStoredState() {
  const storage = getStorageArea();
  const result = await storage.get(Object.values(STORAGE_KEYS));

  return {
    legacyAccounts: Array.isArray(result[STORAGE_KEYS.legacyAccounts]) ? result[STORAGE_KEYS.legacyAccounts] : [],
    vault: result[STORAGE_KEYS.vault] ?? null,
    auth: result[STORAGE_KEYS.auth] ?? null
  };
}

export async function saveVault(vault) {
  const storage = getStorageArea();
  await storage.set({ [STORAGE_KEYS.vault]: vault });
}

export async function saveAuthConfig(auth) {
  const storage = getStorageArea();
  await storage.set({ [STORAGE_KEYS.auth]: auth });
}

export async function clearLegacyAccounts() {
  const storage = getStorageArea();
  await storage.remove(STORAGE_KEYS.legacyAccounts);
}
