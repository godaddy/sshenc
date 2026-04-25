// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `sshenc -Y sign` edge-data scenarios — beyond the default
//! "small ASCII payload" the existing sign tests use:
//!
//! - empty file (zero-byte data)
//! - large file (5 MiB) — well above any small-payload buffer
//!   sweet spot, but well below the agent's 256 KiB *frame* limit
//!   (signing isn't framed; the data is hashed before transit)
//! - binary file with all 256 byte values
//! - file path containing spaces and unicode
//!
//! All sign-then-verify with real `ssh-keygen -Y verify`.

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, run, shared_enclave_pubkey, SshencEnv, SHARED_ENCLAVE_LABEL};
use std::io::Write;
use std::path::Path;
use std::process::Stdio;

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

const PRINCIPAL: &str = "signer@sign-edge.test";

fn setup() -> (SshencEnv, std::path::PathBuf, std::path::PathBuf) {
    let mut env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");

    let pub_path = env.ssh_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    std::fs::write(&pub_path, format!("{enclave}\n")).expect("write pub");

    let allowed = env.ssh_dir().join("allowed_signers");
    std::fs::write(&allowed, format!("{PRINCIPAL} {enclave}\n")).expect("write allowed_signers");

    (env, pub_path, allowed)
}

fn ssh_sign(env: &SshencEnv, pub_path: &Path, data: &Path) -> sshenc_e2e::RunOutcome {
    run(env
        .sshenc_cmd()
        .expect("sshenc")
        .arg("-Y")
        .arg("sign")
        .arg("-n")
        .arg("git")
        .arg("-f")
        .arg(pub_path)
        .arg(data))
    .expect("sshenc -Y sign")
}

fn ssh_keygen_verify(env: &SshencEnv, allowed: &Path, sig: &Path, data: &Path) -> bool {
    let data_bytes = std::fs::read(data).expect("read data");
    let mut child = env
        .scrubbed_command("ssh-keygen")
        .arg("-Y")
        .arg("verify")
        .arg("-f")
        .arg(allowed)
        .arg("-I")
        .arg(PRINCIPAL)
        .arg("-n")
        .arg("git")
        .arg("-s")
        .arg(sig)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn ssh-keygen");
    {
        let mut stdin = child.stdin.take().expect("stdin");
        stdin.write_all(&data_bytes).expect("write data");
    }
    child.wait().expect("ssh-keygen wait").success()
}

/// Empty file → empty payload → still gets a valid sig that
/// verifies. Exercises the "0-byte data" boundary, which can
/// trip parsers that assume non-empty inputs.
#[test]
#[ignore = "requires docker"]
fn sign_zero_byte_file_round_trips() {
    if skip_if_no_docker("sign_zero_byte_file_round_trips") {
        return;
    }
    let (env, pub_path, allowed) = setup();
    let data = env.home().join("empty.bin");
    std::fs::write(&data, b"").expect("write empty");

    let sign = ssh_sign(&env, &pub_path, &data);
    assert!(sign.succeeded(), "sign empty file failed: {}", sign.stderr);
    let sig = data.with_extension("bin.sig");
    assert!(sig.exists(), "sigfile missing for empty data");
    assert!(
        ssh_keygen_verify(&env, &allowed, &sig, &data),
        "ssh-keygen verify failed on empty-data sig"
    );
}

/// Large file (5 MiB of pseudo-random bytes) round-trips. The
/// agent hashes the data before transit so the result must be
/// length-independent — tests there's no implicit max-data cap
/// at the CLI or the agent's API surface.
#[test]
#[ignore = "requires docker"]
fn sign_large_file_round_trips() {
    if skip_if_no_docker("sign_large_file_round_trips") {
        return;
    }
    let (env, pub_path, allowed) = setup();
    let data = env.home().join("big.bin");
    // Deterministic 5 MiB pseudo-random fill (xorshift). Avoids
    // pulling rand into sshenc-e2e for one buffer.
    let mut state: u64 = 0xDEAD_BEEF_CAFE_BABE;
    let mut bytes = vec![0_u8; 5 * 1024 * 1024];
    for chunk in bytes.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        for (i, b) in chunk.iter_mut().enumerate() {
            *b = (state >> (i * 8)) as u8;
        }
    }
    std::fs::write(&data, &bytes).expect("write large file");

    let sign = ssh_sign(&env, &pub_path, &data);
    assert!(sign.succeeded(), "sign large file failed: {}", sign.stderr);
    let sig = data.with_extension("bin.sig");
    assert!(
        ssh_keygen_verify(&env, &allowed, &sig, &data),
        "ssh-keygen verify failed on 5 MiB data sig"
    );
}

/// File whose content covers all 256 byte values. The agent
/// hashes input as opaque bytes; this catches any accidental
/// UTF-8 / null-byte truncation in the CLI → agent path.
#[test]
#[ignore = "requires docker"]
fn sign_all_byte_values_round_trips() {
    if skip_if_no_docker("sign_all_byte_values_round_trips") {
        return;
    }
    let (env, pub_path, allowed) = setup();
    let data = env.home().join("all-bytes.bin");
    let bytes: Vec<u8> = (0..=255_u8).collect();
    std::fs::write(&data, &bytes).expect("write all-bytes");

    let sign = ssh_sign(&env, &pub_path, &data);
    assert!(
        sign.succeeded(),
        "sign all-bytes file failed: {}",
        sign.stderr
    );
    let sig = data.with_extension("bin.sig");
    assert!(
        ssh_keygen_verify(&env, &allowed, &sig, &data),
        "ssh-keygen verify failed on all-byte-values sig"
    );
}

/// File path containing spaces and a unicode component. Exercises
/// the sshenc CLI's argument handling — neither side should
/// shell-escape the path or assume ASCII.
#[test]
#[ignore = "requires docker"]
fn sign_file_with_spaces_and_unicode_path() {
    if skip_if_no_docker("sign_file_with_spaces_and_unicode_path") {
        return;
    }
    let (env, pub_path, allowed) = setup();
    // Mix: spaces, unicode, mixed case. The dot+ext convention
    // still applies because sshenc -Y sign appends `.sig`.
    let data = env.home().join("spaced — 日本 file.txt");
    std::fs::write(&data, b"path with spaces and unicode\n").expect("write spaced unicode file");

    let sign = ssh_sign(&env, &pub_path, &data);
    assert!(
        sign.succeeded(),
        "sign with unicode/spaces in path failed; stderr:\n{}",
        sign.stderr
    );
    let sig_name = format!("{}.sig", data.file_name().unwrap().to_string_lossy());
    let sig = data.with_file_name(sig_name);
    assert!(
        sig.exists(),
        "sigfile missing for unicode-path data; expected: {}",
        sig.display()
    );
    assert!(
        ssh_keygen_verify(&env, &allowed, &sig, &data),
        "ssh-keygen verify failed on unicode-path sig"
    );
}
