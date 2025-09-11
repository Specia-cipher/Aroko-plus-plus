# 🛡️ Aroko++ CLI Command Reference

This document defines the command syntax, subcommands, flags, and arguments for the Aroko++ hybrid encryption tool.

---

## 🔑 Key Management

- **Generate RSA/ECC key pair**
  ```
  aroko++ keygen --type rsa|ecc --out <key_folder> [--password <passphrase>]
  ```

- **Import an existing key**
  ```
  aroko++ import-key --file <key_file> --type rsa|ecc [--password <passphrase>]
  ```

- **Export a key**
  ```
  aroko++ export-key --type rsa|ecc --out <key_file> [--password <passphrase>]
  ```

---

## 🔒 Encryption

- **Encrypt a file for a recipient**
  ```
  aroko++ encrypt --file <input_file> --recipient <pubkey_file> --out <output_file> [--symbolic <message>] [--scrub-metadata] [--progress]
  ```

- **Encrypt a text message**
  ```
  aroko++ encrypt --message "<text>" --recipient <pubkey_file> --out <output_file> [--symbolic] [--progress]
  ```

---

## 🔓 Decryption

- **Decrypt a file**
  ```
  aroko++ decrypt --file <encrypted_file> --private-key <privkey_file> --out <output_file> [--password <passphrase>] [--progress]
  ```

- **Decrypt a text message**
  ```
  aroko++ decrypt --message <encrypted_message_file> --private-key <privkey_file> [--password <passphrase>]
  ```

---

## 📝 Symbolic Messaging (Aroko Mode)

- **Send a symbolic encrypted message**
  ```
  aroko++ aroko --message "<text>" --recipient <pubkey_file> --out <output_file>
  ```

- **Extract symbolic message from output**
  ```
  aroko++ extract-aroko --file <input_file>
  ```

---

## 🧹 File Privacy Utilities

- **Scrub sensitive metadata**
  ```
  aroko++ scrub --file <input_file> --out <output_file>
  ```

- **Securely delete original file**
  ```
  aroko++ delete --file <input_file> --secure
  ```

---

## 🚦 Other Features

- **Show encryption progress**
  ```
  aroko++ encrypt ... --progress
  aroko++ decrypt ... --progress
  ```

- **Show help**
  ```
  aroko++ --help
  ```

---

## 📝 Notes

- `[--symbolic <message>]` embeds an encrypted symbolic message within the output.
- `[--scrub-metadata]` removes metadata from files before encryption.
- `[--progress]` enables progress indicators for large file operations.
- `[--password <passphrase>]` protects private keys with a passphrase.

---

**This reference is a living document and will evolve as Aroko++ development progresses.**
