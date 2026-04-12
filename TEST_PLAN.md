# Comprehensive Test Plan

This document outlines every test that needs to be written across the libenclaveapp ecosystem. Current state: 737 tests. Target: exhaustive coverage of all code paths, plus Miri validation and fuzz testing for security-critical parsers.

## 1. libenclaveapp — enclaveapp-software (currently 14 tests, target ~60)

### 1.1 key_storage.rs
- [ ] generate_and_save creates .key, .pub, .meta files
- [ ] generate_and_save sets 0600 permissions on .key (Unix)
- [ ] generate_and_save rejects duplicate label
- [ ] generate_and_save with invalid label returns error
- [ ] load_secret_key roundtrip (save then load)
- [ ] load_secret_key nonexistent returns KeyNotFound
- [ ] load_public_key returns 65-byte SEC1 point starting with 0x04
- [ ] load_public_key falls back to deriving from secret key when .pub missing
- [ ] list_labels returns sorted list
- [ ] list_labels empty dir returns empty vec
- [ ] delete_key removes .key, .pub, .meta files
- [ ] delete_key nonexistent returns KeyNotFound
- [ ] delete_key then regenerate same label succeeds
- [ ] keyring encryption format: version byte 0x01, nonce 12 bytes, ciphertext+tag
- [ ] keyring encrypted file decrypts correctly with correct KEK
- [ ] keyring encrypted file fails to decrypt with wrong KEK
- [ ] unencrypted key file (raw 32 bytes) loads correctly (backward compat)
- [ ] encrypted key file without keyring feature returns descriptive error

### 1.2 sign.rs
- [ ] generate signing key returns valid 65-byte pubkey
- [ ] generate encryption key type rejected
- [ ] sign produces valid DER-encoded ECDSA signature (starts with 0x30)
- [ ] sign is deterministic for same key but varies with different data
- [ ] signature verifies against the public key (use p256::ecdsa::VerifyingKey)
- [ ] sign nonexistent key returns KeyNotFound
- [ ] public_key returns same bytes as generate returned
- [ ] list_keys after generate includes the label
- [ ] delete_key then sign returns KeyNotFound
- [ ] is_available returns true
- [ ] with_keys_dir uses custom directory

### 1.3 encrypt.rs
- [ ] generate encryption key returns valid 65-byte pubkey
- [ ] generate signing key type rejected
- [ ] encrypt then decrypt roundtrip (various sizes: 0, 1, 100, 10000, 100000 bytes)
- [ ] ciphertext format: starts with 0x01, then 65-byte ephemeral pub, 12-byte nonce, ciphertext, 16-byte tag
- [ ] ciphertext is different each time (random nonce)
- [ ] decrypt with wrong key returns error
- [ ] decrypt truncated ciphertext returns error
- [ ] decrypt wrong version byte returns error
- [ ] decrypt corrupted ciphertext returns error (flip a byte)
- [ ] encrypt nonexistent key returns KeyNotFound
- [ ] is_available returns true

## 2. libenclaveapp — enclaveapp-apple (currently 0 tests, target ~10)

Hardware tests gated behind `ENCLAVEAPP_TEST_SE=1`:
- [ ] is_available returns true on macOS hardware
- [ ] generate signing key + sign + verify roundtrip
- [ ] generate encryption key + encrypt + decrypt roundtrip
- [ ] generate with duplicate label fails
- [ ] delete key then regenerate succeeds
- [ ] public_key matches what generate returned

Non-hardware tests (pure Rust, always run):
- [ ] KeychainConfig::new sets correct app_name
- [ ] KeychainConfig::with_keys_dir overrides path
- [ ] keys_dir returns correct default path

## 3. libenclaveapp — enclaveapp-windows (currently 27 tests, target ~40)

The 27 existing tests are all in convert.rs (P1363/DER/ECCPUBLIC_BLOB). Add:

### 3.1 convert.rs additions
- [ ] p1363_to_der with 1-byte r and 32-byte s
- [ ] der_to_p1363 with leading zero stripping edge cases
- [ ] eccpublic_blob_to_sec1 with real-world TPM blob bytes
- [ ] sec1_to_eccpublic_blob roundtrip with random points

### 3.2 Hardware tests (gated behind `ENCLAVEAPP_TEST_TPM=1`, Windows only)
- [ ] is_available returns true on Windows with TPM
- [ ] generate signing key + sign + verify roundtrip
- [ ] generate encryption key + encrypt + decrypt roundtrip
- [ ] list_keys returns generated keys
- [ ] delete_key removes from TPM

## 4. libenclaveapp — enclaveapp-linux-tpm (currently 0 tests, target ~15)

### 4.1 Non-hardware tests
- [ ] DER signature encoding roundtrip (sign.rs has internal helpers)
- [ ] extract_public_key from a mock ECC Public structure
- [ ] TpmConfig::new and with_keys_dir path handling
- [ ] save_key_blobs / load_key_blobs roundtrip in temp dir
- [ ] delete_key_blobs removes files
- [ ] is_available returns false on macOS/Windows (stub behavior)

### 4.2 Hardware tests (gated behind `ENCLAVEAPP_TEST_TPM=1`, Linux only)
- [ ] is_available returns true
- [ ] generate signing key + sign + verify
- [ ] generate encryption key + encrypt + decrypt roundtrip
- [ ] key persistence: generate, drop context, reopen, load, sign

## 5. libenclaveapp — enclaveapp-wsl (currently 47 tests, target ~65)

### 5.1 shell_config.rs additions
- [ ] install_block with content containing special characters ($, \, `)
- [ ] uninstall_block preserves content before and after block exactly
- [ ] multiple different app blocks in same file (sshenc + awsenc)
- [ ] install then update (remove old, install new) pattern

### 5.2 install.rs additions
- [ ] decode_wsl_output with real UTF-16LE BOM bytes
- [ ] decode_wsl_output with plain UTF-8
- [ ] configure_distro creates backup file
- [ ] unconfigure_distro removes block but not backup

### 5.3 shell_init.rs additions
- [ ] generate bash output contains trap chaining
- [ ] generate zsh output contains add-zsh-hook
- [ ] generate fish output contains commandline check
- [ ] generate powershell output (when enabled)
- [ ] generate unknown shell returns error
- [ ] export_patterns appear in generated output
- [ ] command name appears in generated output
- [ ] helper function appears in bash output when configured

## 6. libenclaveapp — enclaveapp-bridge (currently 11 tests, target ~20)

- [ ] BridgeRequest with all methods (init, encrypt, decrypt, destroy)
- [ ] BridgeResponse success with empty result
- [ ] BridgeResponse error preserves message
- [ ] encode_data / decode_data with binary data containing null bytes
- [ ] encode_data / decode_data with large data (1MB)
- [ ] decode_data with invalid base64 returns error
- [ ] decode_data with empty string returns empty vec
- [ ] BridgeParams default values
- [ ] find_bridge returns None on macOS (no bridge binary)

## 7. libenclaveapp — enclaveapp-test-support (currently 31 tests, target ~40)

- [ ] generate then list returns sorted labels
- [ ] delete all keys then list returns empty
- [ ] sign with data larger than 1MB
- [ ] encrypt with empty plaintext returns valid ciphertext
- [ ] encrypt with 1MB plaintext roundtrips
- [ ] concurrent generate from 20 threads (stress test)
- [ ] concurrent sign from 10 threads with same key
- [ ] MockKeyBackend::default() works (derive Default)
- [ ] different MockKeyBackend instances are independent

## 8. sshenc — sshenc-core (currently 76 tests, target ~90)

### 8.1 pubkey.rs additions
- [ ] from_sec1_bytes with exactly 65 bytes, wrong prefix (0x02) — error
- [ ] from_sec1_bytes with 64 bytes — error
- [ ] to_wire_format produces correct SSH blob structure
- [ ] from_openssh_line with extra whitespace variations
- [ ] from_openssh_line with no comment
- [ ] from_openssh_line with empty base64 — error

### 8.2 fingerprint.rs additions
- [ ] fingerprint_sha256 matches ssh-keygen output for known key
- [ ] fingerprint_md5 matches ssh-keygen output for known key

### 8.3 ssh_config.rs additions
- [ ] install_block with empty file (creates new)
- [ ] install_block preserves exact file permissions
- [ ] uninstall_block with multiple blank lines around block
- [ ] is_installed with partial marker (BEGIN but no END) — still returns true

### 8.4 config.rs additions
- [ ] Config with all fields set serializes/deserializes
- [ ] Config with host_identities roundtrip
- [ ] Platform-conditional socket path (Unix vs Windows)

## 9. sshenc — sshenc-se (currently 0 tests, target ~20)

### 9.1 compat.rs
- [ ] load_sshenc_meta with old format (comment, auth_policy int, git_name, git_email)
- [ ] load_sshenc_meta with new format (key_type, access_policy string, app_specific)
- [ ] load_sshenc_meta with missing file returns default
- [ ] load_sshenc_meta old format git_name/git_email migrate to app_specific
- [ ] load_sshenc_meta old format auth_policy 0 → AccessPolicy::None
- [ ] load_sshenc_meta old format auth_policy 1 → AccessPolicy::Any

### 9.2 Backend tests (using MockKeyBackend or test fixtures)
- [ ] SecureEnclaveBackend/TpmBackend/LinuxBackend implement KeyBackend trait
- [ ] KeyInfo has correct fingerprints for known public key bytes
- [ ] find_pub_file returns correct path for "default" label
- [ ] find_pub_file returns correct path for custom label
- [ ] find_pub_file returns None when file doesn't exist

## 10. sshenc — sshenc-agent-proto (currently 39 tests, target ~55)

### 10.1 message.rs additions
- [ ] parse_request with SSH_AGENTC_REQUEST_IDENTITIES
- [ ] parse_request with SSH_AGENTC_SIGN_REQUEST including flags
- [ ] parse_request with unknown message type
- [ ] serialize_response IdentitiesAnswer with 0, 1, 5 identities
- [ ] serialize_response SignResponse with known signature bytes
- [ ] serialize_response Failure

### 10.2 signature.rs additions
- [ ] der_to_ssh_signature with known DER bytes produces expected SSH format
- [ ] der_to_ssh_signature with minimum-length DER signature
- [ ] der_to_ssh_signature with maximum-length P-256 DER signature
- [ ] parse_der_signature with invalid DER (wrong tag) — error
- [ ] parse_der_signature with truncated DER — error

### 10.3 wire.rs additions
- [ ] read_message_frame with exactly max size (256KB)
- [ ] read_message_frame with size > 256KB — error
- [ ] read_message_frame with size 0 — error
- [ ] write_message_frame roundtrip with various sizes

## 11. sshenc — sshenc-cli (currently 0 tests, target ~15)

Integration tests (run the compiled binary):
- [ ] `sshenc --version` exits 0 and prints version
- [ ] `sshenc --help` exits 0 and prints help text
- [ ] `sshenc list --json` with no keys outputs `[]`
- [ ] `sshenc completions bash` produces valid bash completion script
- [ ] `sshenc completions zsh` produces valid zsh completion script
- [ ] `sshenc config path` prints a path ending in config.toml

## 12. sshenc — sshenc-pkcs11 (currently 0 tests, target ~8)

- [ ] C_Initialize succeeds first time
- [ ] C_Initialize second time returns CKR_CRYPTOKI_ALREADY_INITIALIZED
- [ ] C_Finalize succeeds after initialize
- [ ] C_Finalize without initialize returns CKR_CRYPTOKI_NOT_INITIALIZED
- [ ] C_GetInfo fills in manufacturer and description
- [ ] C_GetSlotList returns 0 slots
- [ ] C_GetFunctionList returns non-null pointer
- [ ] C_GetFunctionList entries match expected function pointers

## 13. sshenc — sshenc-gitenc (currently 7 tests, target ~12)

- [ ] parse_args with --config and label
- [ ] parse_args with --config --label label
- [ ] parse_args with --label only (pass-through mode)
- [ ] parse_args with no args (default mode)
- [ ] parse_args with -- separator handles ssh args

## 14. awsenc test gaps (currently 178 tests)

### 14.1 awsenc-secure-storage
- [ ] platform_storage returns a working backend on macOS (gated)
- [ ] encrypt/decrypt roundtrip through platform_storage (gated)
- [ ] mock storage encrypt/decrypt roundtrip

### 14.2 awsenc-core/cache.rs additions
- [ ] cache file with corrupted magic bytes returns None
- [ ] cache file with truncated header returns None
- [ ] cache file expiration check at boundary

## 15. sso-jwt test gaps (currently 181 tests)

### 15.1 sso-jwt-lib/secure_storage
- [ ] platform_storage on macOS returns working backend (gated)
- [ ] encrypt/decrypt roundtrip through platform_storage (gated)

### 15.2 sso-jwt-lib/oauth.rs additions
- [ ] authenticate with mock server (full device code flow)
- [ ] poll_for_token slow_down doubles interval
- [ ] poll_for_token timeout returns error

## 16. Miri tests

Miri validates memory safety of unsafe code. Target the FFI boundaries:

### 16.1 enclaveapp-core
- [ ] All metadata file operations (no unsafe, but validates allocations)
- [ ] KeyMeta serialization/deserialization under Miri

### 16.2 enclaveapp-windows/convert.rs
- [ ] p1363_to_der under Miri (byte manipulation)
- [ ] der_to_p1363 under Miri
- [ ] eccpublic_blob_to_sec1 under Miri
- [ ] sec1_to_eccpublic_blob under Miri

### 16.3 sshenc-agent-proto
- [ ] All wire format parsing under Miri
- [ ] DER signature parsing under Miri
- [ ] Message frame read/write under Miri

Note: Miri cannot run FFI code (CryptoKit, NCrypt, tss-esapi). Only pure Rust code.

## 17. Fuzz tests (cargo-fuzz / libfuzzer)

Security-critical parsers that accept untrusted input:

### 17.1 sshenc-agent-proto
- [ ] fuzz parse_request (agent protocol messages from SSH clients)
- [ ] fuzz parse_der_signature (DER from Secure Enclave)
- [ ] fuzz read_ssh_string (SSH wire format)

### 17.2 enclaveapp-windows/convert.rs
- [ ] fuzz der_to_p1363 (DER signature parsing)
- [ ] fuzz eccpublic_blob_to_sec1 (TPM blob parsing)

### 17.3 sso-jwt-lib
- [ ] fuzz parse_claims (JWT base64 + JSON parsing)
- [ ] fuzz DeviceCodeResponse deserialization

## Summary

| Area | Current | Target | New tests needed |
|------|---------|--------|-----------------|
| enclaveapp-software | 14 | ~60 | ~46 |
| enclaveapp-apple | 0 | ~10 | ~10 |
| enclaveapp-windows | 27 | ~40 | ~13 |
| enclaveapp-linux-tpm | 0 | ~15 | ~15 |
| enclaveapp-wsl | 47 | ~65 | ~18 |
| enclaveapp-bridge | 11 | ~20 | ~9 |
| enclaveapp-test-support | 31 | ~40 | ~9 |
| sshenc-core | 76 | ~90 | ~14 |
| sshenc-se | 0 | ~20 | ~20 |
| sshenc-agent-proto | 39 | ~55 | ~16 |
| sshenc-cli | 0 | ~15 | ~15 |
| sshenc-pkcs11 | 0 | ~8 | ~8 |
| sshenc-gitenc | 7 | ~12 | ~5 |
| awsenc | 178 | ~185 | ~7 |
| sso-jwt | 181 | ~190 | ~9 |
| Miri | 0 | ~20 | ~20 |
| Fuzz harnesses | 0 | ~7 | ~7 |
| **Total** | **737** | **~1000** | **~263** |
