# Passkey (Biometric) Security Module for WHMCS
### 🛡️ Next-Gen Passwordless Authentication by eHostPK Private Limited

[![WHMCS Compatibility](https://img.shields.io/badge/WHMCS-8.x%20|%209.x-blue.svg)](https://www.whmcs.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Security-AES--256--GCM-red.svg)](#)

Secure your WHMCS Admin and Client areas using native device biometrics. Eliminate the need for insecure passwords and clunky SMS OTPs with high-speed, encrypted WebAuthn authentication.

---

## 🚀 Key Features

* **Biometric Login:** Supports Apple TouchID, FaceID, Windows Hello, and Android Fingerprint.
* **AES-256-GCM Encryption:** All biometric credential IDs are encrypted before being stored in the database.
* **Smart Multi-Session:** Automatically detects and prioritizes Admin vs. Client sessions.
* **CSRF Protected:** Built-in security tokens to prevent Cross-Site Request Forgery.
* **Auto-Trigger UI:** Fast 500ms auto-popup for a seamless "Scan & Login" experience.
* **Dynamic Identity:** Displays `Full Name ( Email )` directly on the biometric prompt for clarity.
* **Sub-folder Ready:** Automatically detects WHMCS installation paths (e.g., `/billing/` or `/whmcs/`).

---

## 🛠️ Installation

1.  **Upload Files:**
    Upload the `passkey` folder to your WHMCS directory:
    `/modules/security/passkey/`

2.  **Activate Module:**
    * Login to WHMCS Admin Area.
    * Navigate to **System Settings** > **Two-Factor Authentication**.
    * Find **Passkey (Biometric)** and click **Activate**.

3.  **Database Setup:**
    The module will automatically create the `mod_passkeys` table upon activation.

---

## 🔒 Security Architecture

This module follows a strict security protocol to ensure user data remains private:

* **Encryption:** Uses `openssl_encrypt` with `aes-256-gcm` using the WHMCS system hash.
* **WebAuthn Standard:** Implements the FIDO2/WebAuthn protocol for hardware-backed security.
* **Origin Validation:** Restricts authentication to your specific domain (RP ID) to prevent phishing.

---

## 📂 Folder Structure

```text
passkey/
├── passkey.php      # Main WHMCS Module Logic & UI
├── process.php      # Secure AJAX Backend (Registration/Verification)
├── whmcs.json       # Module Metadata
└── logo.png         # Module Icon (Optional)
