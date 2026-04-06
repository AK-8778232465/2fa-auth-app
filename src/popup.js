import {
  createPasswordRecord,
  decryptBackup,
  encryptBackup,
  verifyPassword
} from "./lib/crypto.js";
import { readOtpUriFromImage } from "./lib/qr.js";
import { clearLegacyAccounts, getStoredState, saveAuthConfig, saveVault } from "./lib/storage.js";
import {
  generateTotp,
  parseOtpInput,
  sanitizeAccountPayload,
  serializeAccountsForBackup
} from "./lib/totp.js";

const PERIOD_OPTIONS = Array.from({ length: 10 }, (_, index) => (index + 1) * 30);

const state = {
  accounts: [],
  auth: null,
  importFileText: null,
  masterPassword: null,
  vaultReady: false
};

const elements = {
  lockScreen: document.querySelector("#lock-screen"),
  vaultShell: document.querySelector("#vault-shell"),
  lockTitle: document.querySelector("#lock-title"),
  lockDescription: document.querySelector("#lock-description"),
  unlockForm: document.querySelector("#unlock-form"),
  unlockPasswordInput: document.querySelector("#unlock-password-input"),
  unlockPasswordConfirmInput: document.querySelector("#unlock-password-confirm-input"),
  unlockConfirmField: document.querySelector("#unlock-confirm-field"),
  unlockSubmitButton: document.querySelector("#unlock-submit-button"),
  unlockFormError: document.querySelector("#unlock-form-error"),
  accountCount: document.querySelector("#account-count"),
  accountsList: document.querySelector("#accounts-list"),
  statusBanner: document.querySelector("#status-banner"),
  emptyStateTemplate: document.querySelector("#empty-state-template"),
  accountCardTemplate: document.querySelector("#account-card-template"),
  importFileInput: document.querySelector("#import-file-input"),
  qrFileInput: document.querySelector("#qr-file-input"),
  addAccountButton: document.querySelector("#add-account-button"),
  importButton: document.querySelector("#import-button"),
  exportButton: document.querySelector("#export-button"),
  changePasswordButton: document.querySelector("#change-password-button"),
  lockButton: document.querySelector("#lock-button"),
  accountDialog: document.querySelector("#account-dialog"),
  exportDialog: document.querySelector("#export-dialog"),
  importDialog: document.querySelector("#import-dialog"),
  passwordDialog: document.querySelector("#password-dialog"),
  accountForm: document.querySelector("#account-form"),
  exportForm: document.querySelector("#export-form"),
  importForm: document.querySelector("#import-form"),
  passwordForm: document.querySelector("#password-form"),
  accountDialogTitle: document.querySelector("#account-dialog-title"),
  accountId: document.querySelector("#account-id"),
  labelInput: document.querySelector("#label-input"),
  usernameInput: document.querySelector("#username-input"),
  secretInput: document.querySelector("#secret-input"),
  periodInput: document.querySelector("#period-input"),
  digitsInput: document.querySelector("#digits-input"),
  algorithmInput: document.querySelector("#algorithm-input"),
  scanQrButton: document.querySelector("#scan-qr-button"),
  deleteAccountButton: document.querySelector("#delete-account-button"),
  accountFormError: document.querySelector("#account-form-error"),
  exportPasswordInput: document.querySelector("#export-password-input"),
  exportPasswordConfirmInput: document.querySelector("#export-password-confirm-input"),
  exportFormError: document.querySelector("#export-form-error"),
  importFileName: document.querySelector("#import-file-name"),
  importPasswordInput: document.querySelector("#import-password-input"),
  replaceExistingInput: document.querySelector("#replace-existing-input"),
  importFormError: document.querySelector("#import-form-error"),
  currentPasswordInput: document.querySelector("#current-password-input"),
  newPasswordInput: document.querySelector("#new-password-input"),
  newPasswordConfirmInput: document.querySelector("#new-password-confirm-input"),
  passwordFormError: document.querySelector("#password-form-error")
};

function uid() {
  return crypto.randomUUID();
}

function showBanner(message, type = "success") {
  elements.statusBanner.textContent = message;
  elements.statusBanner.className = `status-banner ${type}`;
  clearTimeout(showBanner.timeoutId);
  showBanner.timeoutId = setTimeout(() => {
    elements.statusBanner.className = "status-banner hidden";
  }, 3200);
}

function setFormError(element, message) {
  element.textContent = message;
  element.classList.toggle("hidden", !message);
}

function fillPeriodOptions() {
  elements.periodInput.innerHTML = PERIOD_OPTIONS
    .map((value) => `<option value="${value}">${value} seconds</option>`)
    .join("");
}

function openDialog(dialog) {
  if (!dialog.open) {
    dialog.showModal();
  }
}

function closeDialog(dialog) {
  if (dialog.open) {
    dialog.close();
  }
}

function setLockedUi(isLocked) {
  elements.lockScreen.classList.toggle("hidden", !isLocked);
  elements.vaultShell.classList.toggle("hidden", isLocked);
}

function configureLockScreen(isSetupMode) {
  elements.lockTitle.textContent = isSetupMode ? "Create Master Password" : "Unlock 2FA Auth App";
  elements.lockDescription.textContent = isSetupMode
    ? "Create a master password to encrypt your authenticator vault inside Chrome storage."
    : "Enter your master password to decrypt your saved accounts.";
  elements.unlockSubmitButton.textContent = isSetupMode ? "Create Vault" : "Unlock Vault";
  elements.unlockConfirmField.classList.toggle("hidden", !isSetupMode);
  elements.unlockPasswordConfirmInput.required = isSetupMode;
}

function resetAccountForm() {
  elements.accountForm.reset();
  elements.accountId.value = "";
  elements.periodInput.value = "30";
  elements.digitsInput.value = "6";
  elements.algorithmInput.value = "SHA-1";
  elements.accountDialogTitle.textContent = "Add Account";
  elements.deleteAccountButton.classList.add("hidden");
  setFormError(elements.accountFormError, "");
}

function populateAccountForm(account) {
  elements.accountId.value = account.id;
  elements.labelInput.value = account.label;
  elements.usernameInput.value = account.username;
  elements.secretInput.value = account.secret;
  elements.periodInput.value = String(account.period);
  elements.digitsInput.value = String(account.digits);
  elements.algorithmInput.value = account.algorithm;
  elements.accountDialogTitle.textContent = "Edit Account";
  elements.deleteAccountButton.classList.remove("hidden");
  setFormError(elements.accountFormError, "");
}

function applyOtpInputToForm(rawValue) {
  elements.secretInput.value = rawValue;

  try {
    const parsed = parseOtpInput(rawValue);

    if (parsed.label && !elements.labelInput.value.trim()) {
      elements.labelInput.value = parsed.label;
    }

    if (parsed.username && !elements.usernameInput.value.trim()) {
      elements.usernameInput.value = parsed.username;
    }

    elements.periodInput.value = String(parsed.period);
    elements.digitsInput.value = String(parsed.digits);
    elements.algorithmInput.value = parsed.algorithm;
    setFormError(elements.accountFormError, "");
  } catch (error) {
    setFormError(elements.accountFormError, error.message);
  }
}

function normalizeAccount(account) {
  return {
    id: account.id || uid(),
    label: account.label,
    username: account.username || "",
    secret: account.secret,
    digits: account.digits || 6,
    period: account.period || 30,
    algorithm: account.algorithm || "SHA-1",
    createdAt: account.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
}

async function persistVault(accounts = state.accounts) {
  if (!state.masterPassword || !state.auth) {
    throw new Error("Unlock the vault before saving changes.");
  }

  state.accounts = accounts
    .map(normalizeAccount)
    .sort((left, right) => left.label.localeCompare(right.label));

  const payload = serializeAccountsForBackup(state.accounts);
  const encryptedVault = await encryptBackup(payload, state.masterPassword);
  await saveVault(encryptedVault);
  renderAccounts();
}

function resetTransientState() {
  state.accounts = [];
  state.masterPassword = null;
  state.vaultReady = false;
  renderAccounts();
}

async function unlockVaultWithPassword(password) {
  const stored = await getStoredState();
  state.auth = stored.auth;

  if (!stored.auth) {
    const authRecord = await createPasswordRecord(password);
    const emptyVault = await encryptBackup(serializeAccountsForBackup([]), password);

    await saveAuthConfig(authRecord);
    await saveVault(emptyVault);

    state.auth = authRecord;
    state.masterPassword = password;
    state.accounts = [];
    state.vaultReady = true;

    if (stored.legacyAccounts.length) {
      const migratedAccounts = stored.legacyAccounts.map(normalizeAccount);
      await persistVault(migratedAccounts);
      await clearLegacyAccounts();
      showBanner("Legacy accounts moved into your encrypted vault.");
    }

    return;
  }

  const passwordValid = await verifyPassword(password, stored.auth);
  if (!passwordValid) {
    throw new Error("Master password is incorrect.");
  }

  const decryptedVault = stored.vault
    ? await decryptBackup(stored.vault, password)
    : serializeAccountsForBackup([]);

  state.auth = stored.auth;
  state.masterPassword = password;
  state.accounts = Array.isArray(decryptedVault.accounts) ? decryptedVault.accounts.map(normalizeAccount) : [];
  state.vaultReady = true;

  if (stored.legacyAccounts.length) {
    const migratedAccounts = [...state.accounts, ...stored.legacyAccounts.map(normalizeAccount)];
    await persistVault(migratedAccounts);
    await clearLegacyAccounts();
    showBanner("Legacy accounts moved into your encrypted vault.");
  }
}

function accountToCardElement(account) {
  const fragment = elements.accountCardTemplate.content.cloneNode(true);
  const card = fragment.querySelector(".account-card");
  const label = fragment.querySelector(".account-label");
  const username = fragment.querySelector(".account-username");
  const code = fragment.querySelector(".otp-code");
  const copyButton = fragment.querySelector(".otp-code-button");
  const editButton = fragment.querySelector(".account-edit-button");
  const seconds = fragment.querySelector(".progress-seconds");
  const interval = fragment.querySelector(".interval-label");
  const ringProgress = fragment.querySelector(".ring-progress");

  card.dataset.accountId = account.id;
  label.textContent = account.label;
  username.textContent = account.username || "No username";
  interval.textContent = `${account.period}s interval`;

  editButton.addEventListener("click", () => {
    populateAccountForm(account);
    openDialog(elements.accountDialog);
  });

  copyButton.addEventListener("click", async () => {
    try {
      const result = await generateTotp(account);
      await navigator.clipboard.writeText(result.code);
      showBanner(`Copied code: ${result.code}`);
    } catch (error) {
      showBanner(error.message, "error");
    }
  });

  const renderCode = async () => {
    try {
      const result = await generateTotp(account);
      code.textContent = result.formattedCode;
      seconds.textContent = `${result.expiresIn}s`;
      ringProgress.style.setProperty("--progress", String(result.progress));
    } catch (error) {
      code.textContent = "Invalid";
      seconds.textContent = "--";
      ringProgress.style.setProperty("--progress", "0");
    }
  };

  renderCode();
  const intervalId = setInterval(renderCode, 1000);
  card.cleanup = () => clearInterval(intervalId);

  return card;
}

function renderAccounts() {
  const existingCards = elements.accountsList.querySelectorAll(".account-card");
  existingCards.forEach((card) => {
    if (typeof card.cleanup === "function") {
      card.cleanup();
    }
  });

  elements.accountsList.innerHTML = "";
  elements.accountCount.textContent = String(state.accounts.length);

  if (!state.accounts.length) {
    elements.accountsList.appendChild(elements.emptyStateTemplate.content.cloneNode(true));
    return;
  }

  for (const account of state.accounts) {
    elements.accountsList.appendChild(accountToCardElement(account));
  }
}

async function handleUnlock(event) {
  event.preventDefault();
  setFormError(elements.unlockFormError, "");

  const password = elements.unlockPasswordInput.value;
  const confirmPassword = elements.unlockPasswordConfirmInput.value;
  const isSetupMode = !state.auth;

  if (password.length < 8) {
    setFormError(elements.unlockFormError, "Master password must be at least 8 characters.");
    return;
  }

  if (isSetupMode && password !== confirmPassword) {
    setFormError(elements.unlockFormError, "Passwords do not match.");
    return;
  }

  try {
    await unlockVaultWithPassword(password);
    elements.unlockForm.reset();
    setLockedUi(false);
    renderAccounts();
    showBanner(isSetupMode ? "Master password created and vault encrypted." : "Vault unlocked.");
  } catch (error) {
    setFormError(elements.unlockFormError, error.message);
  }
}

async function handleAccountSubmit(event) {
  event.preventDefault();
  setFormError(elements.accountFormError, "");

  try {
    const payload = sanitizeAccountPayload({
      label: elements.labelInput.value,
      username: elements.usernameInput.value,
      secretInput: elements.secretInput.value,
      period: elements.periodInput.value,
      digits: elements.digitsInput.value,
      algorithm: elements.algorithmInput.value
    });

    const existingId = elements.accountId.value;
    const updatedAccounts = existingId
      ? state.accounts.map((account) => (
        account.id === existingId
          ? { ...account, ...payload, updatedAt: new Date().toISOString() }
          : account
      ))
      : [...state.accounts, {
        id: uid(),
        ...payload,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      }];

    await persistVault(updatedAccounts);
    closeDialog(elements.accountDialog);
    resetAccountForm();
    showBanner(existingId ? "Account updated." : "Account added.");
  } catch (error) {
    setFormError(elements.accountFormError, error.message);
  }
}

async function handleDeleteAccount() {
  const accountId = elements.accountId.value;
  if (!accountId) {
    return;
  }

  await persistVault(state.accounts.filter((account) => account.id !== accountId));
  closeDialog(elements.accountDialog);
  resetAccountForm();
  showBanner("Account deleted.");
}

async function handleExport(event) {
  event.preventDefault();
  setFormError(elements.exportFormError, "");

  const password = elements.exportPasswordInput.value;
  const confirm = elements.exportPasswordConfirmInput.value;

  if (password !== confirm) {
    setFormError(elements.exportFormError, "Passwords do not match.");
    return;
  }

  if (!state.accounts.length) {
    setFormError(elements.exportFormError, "Add at least one account before exporting.");
    return;
  }

  try {
    const payload = serializeAccountsForBackup(state.accounts);
    const encrypted = await encryptBackup(payload, password);
    const blob = new Blob([JSON.stringify(encrypted, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `2fa-auth-backup-${new Date().toISOString().slice(0, 10)}.json`;
    anchor.click();
    URL.revokeObjectURL(url);

    closeDialog(elements.exportDialog);
    elements.exportForm.reset();
    showBanner("Encrypted backup downloaded.");
  } catch (error) {
    setFormError(elements.exportFormError, error.message);
  }
}

async function handleImportFileSelected(event) {
  const [file] = event.target.files || [];
  if (!file) {
    return;
  }

  state.importFileText = await file.text();
  elements.importFileName.textContent = file.name;
  setFormError(elements.importFormError, "");
  openDialog(elements.importDialog);
}

async function handleImport(event) {
  event.preventDefault();
  setFormError(elements.importFormError, "");

  if (!state.importFileText) {
    setFormError(elements.importFormError, "Choose a backup file first.");
    return;
  }

  try {
    const encrypted = JSON.parse(state.importFileText);
    const decrypted = await decryptBackup(encrypted, elements.importPasswordInput.value);
    const importedAccounts = Array.isArray(decrypted.accounts) ? decrypted.accounts.map((account) => {
      const sanitized = sanitizeAccountPayload({
        label: account.label,
        username: account.username || "",
        secretInput: account.secret,
        period: account.period || 30,
        digits: account.digits || 6,
        algorithm: account.algorithm || "SHA-1"
      });

      return {
        id: uid(),
        ...sanitized,
        createdAt: account.createdAt || new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };
    }) : [];

    if (!importedAccounts.length) {
      throw new Error("The backup file does not contain any accounts.");
    }

    const accounts = elements.replaceExistingInput.checked
      ? importedAccounts
      : [...state.accounts, ...importedAccounts];

    await persistVault(accounts);
    closeDialog(elements.importDialog);
    elements.importForm.reset();
    elements.importFileInput.value = "";
    state.importFileText = null;
    elements.importFileName.textContent = "None";
    showBanner(`Imported ${importedAccounts.length} account${importedAccounts.length === 1 ? "" : "s"}.`);
  } catch (error) {
    setFormError(elements.importFormError, error.message);
  }
}

async function handleQrSelection(event) {
  const [file] = event.target.files || [];
  if (!file) {
    return;
  }

  try {
    const otpUri = await readOtpUriFromImage(file);
    applyOtpInputToForm(otpUri);
    showBanner("QR code loaded. Review the details and save the account.");
  } catch (error) {
    setFormError(elements.accountFormError, error.message);
  } finally {
    elements.qrFileInput.value = "";
  }
}

async function handlePasswordChange(event) {
  event.preventDefault();
  setFormError(elements.passwordFormError, "");

  const currentPassword = elements.currentPasswordInput.value;
  const newPassword = elements.newPasswordInput.value;
  const confirmPassword = elements.newPasswordConfirmInput.value;

  if (currentPassword !== state.masterPassword) {
    setFormError(elements.passwordFormError, "Current password is incorrect.");
    return;
  }

  if (newPassword.length < 8) {
    setFormError(elements.passwordFormError, "New password must be at least 8 characters.");
    return;
  }

  if (newPassword !== confirmPassword) {
    setFormError(elements.passwordFormError, "New passwords do not match.");
    return;
  }

  try {
    const authRecord = await createPasswordRecord(newPassword);
    const encryptedVault = await encryptBackup(serializeAccountsForBackup(state.accounts), newPassword);

    await saveAuthConfig(authRecord);
    await saveVault(encryptedVault);

    state.auth = authRecord;
    state.masterPassword = newPassword;
    closeDialog(elements.passwordDialog);
    elements.passwordForm.reset();
    showBanner("Master password updated.");
  } catch (error) {
    setFormError(elements.passwordFormError, error.message);
  }
}

function handleLockNow() {
  closeDialog(elements.accountDialog);
  closeDialog(elements.exportDialog);
  closeDialog(elements.importDialog);
  closeDialog(elements.passwordDialog);
  elements.unlockForm.reset();
  setFormError(elements.unlockFormError, "");
  resetTransientState();
  state.auth = state.auth;
  configureLockScreen(false);
  setLockedUi(true);
}

function wireEvents() {
  fillPeriodOptions();
  resetAccountForm();

  elements.unlockForm.addEventListener("submit", handleUnlock);
  elements.addAccountButton.addEventListener("click", () => {
    resetAccountForm();
    openDialog(elements.accountDialog);
  });
  elements.importButton.addEventListener("click", () => elements.importFileInput.click());
  elements.exportButton.addEventListener("click", () => {
    setFormError(elements.exportFormError, "");
    openDialog(elements.exportDialog);
  });
  elements.changePasswordButton.addEventListener("click", () => {
    elements.passwordForm.reset();
    setFormError(elements.passwordFormError, "");
    openDialog(elements.passwordDialog);
  });
  elements.lockButton.addEventListener("click", handleLockNow);
  elements.scanQrButton.addEventListener("click", () => elements.qrFileInput.click());
  elements.accountForm.addEventListener("submit", handleAccountSubmit);
  elements.deleteAccountButton.addEventListener("click", handleDeleteAccount);
  elements.exportForm.addEventListener("submit", handleExport);
  elements.importForm.addEventListener("submit", handleImport);
  elements.passwordForm.addEventListener("submit", handlePasswordChange);
  elements.importFileInput.addEventListener("change", handleImportFileSelected);
  elements.qrFileInput.addEventListener("change", handleQrSelection);

  elements.secretInput.addEventListener("blur", () => {
    const value = elements.secretInput.value.trim();
    if (value.toLowerCase().startsWith("otpauth://")) {
      applyOtpInputToForm(value);
    }
  });

  document.querySelectorAll("[data-close-dialog]").forEach((button) => {
    button.addEventListener("click", () => {
      const dialog = document.getElementById(button.dataset.closeDialog);
      closeDialog(dialog);
    });
  });
}

async function initialize() {
  wireEvents();
  const stored = await getStoredState();
  state.auth = stored.auth;
  configureLockScreen(!stored.auth);
  setLockedUi(true);
}

initialize().catch((error) => {
  showBanner(error.message, "error");
});
