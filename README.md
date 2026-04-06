# 2FA Auth App Chrome Extension

Offline Chrome extension for managing TOTP accounts with:

- Master password lock screen on open
- Encrypted vault storage for saved accounts
- Custom timer intervals from `30` to `300` seconds
- Manual Base32 secret entry
- `otpauth://totp/...` URI parsing
- QR image import using Chromium's built-in barcode detector
- Encrypted JSON backup export/import using `AES-GCM` + `PBKDF2`
- Local-only storage with `chrome.storage.local`

## Load in Chrome

1. Open `chrome://extensions`
2. Enable `Developer mode`
3. Click `Load unpacked`
4. Select this folder: `chrome-2fa-auth-app`

## Notes

- Backup files are encrypted with the password you choose during export.
- The master password is used to encrypt the local vault and is verified before the popup unlocks.
- Imported backups can either merge into current accounts or replace them completely.
- All code generation happens locally in the browser; no server is required.
