# Running Miri Tests

Miri validates memory safety of pure-Rust code, catching undefined behavior,
out-of-bounds access, use-after-free, and other memory safety violations.

## Prerequisites

```sh
rustup toolchain install nightly
rustup +nightly component add miri
```

## sshenc

Run all Miri-compatible tests across the workspace:

```sh
MIRIFLAGS="-Zmiri-disable-isolation" rustup run nightly cargo miri test -p sshenc-core --lib
MIRIFLAGS="-Zmiri-disable-isolation" rustup run nightly cargo miri test -p sshenc-agent-proto --lib
MIRIFLAGS="-Zmiri-disable-isolation" rustup run nightly cargo miri test -p sshenc-pkcs11 --lib
MIRIFLAGS="-Zmiri-disable-isolation" rustup run nightly cargo miri test -p sshenc-test-support --lib
```

### What runs under Miri

| Crate | Passed | Ignored | Notes |
|-------|--------|---------|-------|
| sshenc-core | 65 | 26 | config (dirs::home_dir FFI), ssh_config (libc::chmod) ignored |
| sshenc-agent-proto | 56 | 0 | All tests pass (pure wire format parsing) |
| sshenc-pkcs11 | 11 | 3 | C_Initialize tests ignored (dirs::home_dir FFI) |
| sshenc-test-support | 22 | 1 | File I/O test ignored |

### What is NOT tested

Tests marked `#[cfg_attr(miri, ignore)]` use platform FFI that Miri cannot interpret:

- `dirs::home_dir()` calls `getpwuid_r` (POSIX FFI)
- `libc::chmod` / `libc::umask` (POSIX FFI)
- File I/O with `mkdir` under Miri isolation mode

These tests still run normally under `cargo test`.

## libenclaveapp

```sh
cd /path/to/libenclaveapp
MIRIFLAGS="-Zmiri-disable-isolation" rustup run nightly cargo miri test -p enclaveapp-core --lib
MIRIFLAGS="-Zmiri-disable-isolation" rustup run nightly cargo miri test -p enclaveapp-windows --lib
```

| Crate | Passed | Ignored | Notes |
|-------|--------|---------|-------|
| enclaveapp-core | 37 | 22 | config + metadata file I/O tests ignored |
| enclaveapp-windows | 31 | 0 | All tests pass (pure byte manipulation) |

## Notes

- `--lib` is required to skip doc-tests, which have toolchain compatibility issues with Miri.
- `-Zmiri-disable-isolation` is needed because `SystemTime::now()` requires clock access.
- `cargo +nightly` syntax requires rustup proxy; use `rustup run nightly cargo` instead if it fails.
