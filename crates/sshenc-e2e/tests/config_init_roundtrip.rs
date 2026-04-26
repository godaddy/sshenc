// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! `sshenc config init` writes a default config file. This test
//! verifies the file it writes is **self-consistent** — i.e.,
//! reading it back via `sshenc config show` (which goes through
//! `Config::load_default`) succeeds and produces all the
//! documented top-level fields.
//!
//! `lifecycle.rs::sshenc_config_init_path_show_roundtrip` does a
//! superficial init→path→show check; this one verifies the
//! actual *contents* round-trip:
//!
//! - all documented fields are present in the init output
//! - the agent boots cleanly when pointed at the init-generated
//!   file (proves the values are valid for the runtime, not just
//!   the parser)
//! - `config init` errors cleanly on a second run rather than
//!   silently overwriting

#![cfg(unix)]
#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{docker_skip_reason, run, SshencEnv};

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

/// `sshenc config init` followed by `sshenc config show` reflects
/// every documented top-level Config field. Pins the default
/// config schema as a public contract.
#[test]
#[ignore = "requires docker"]
fn config_init_then_show_reflects_documented_fields() {
    if skip_if_no_docker("config_init_then_show_reflects_documented_fields") {
        return;
    }
    let env = SshencEnv::new().expect("env");

    let init =
        run(env.sshenc_cmd().expect("sshenc").args(["config", "init"])).expect("config init");
    // First-time init may report success or "already exists" if a
    // prior test left state behind; show is what we actually
    // assert against.
    if !init.succeeded() {
        assert!(
            init.stderr.contains("already exists"),
            "config init failed unexpectedly: {}",
            init.stderr
        );
    }

    let show =
        run(env.sshenc_cmd().expect("sshenc").args(["config", "show"])).expect("config show");
    assert!(show.succeeded(), "config show failed: {}", show.stderr);

    // Every documented Config field must appear. Names mirror the
    // pub fields in `crates/sshenc-core/src/config.rs::Config`.
    let required_fields = [
        "socket_path",
        "allowed_labels",
        "prompt_policy",
        "pub_dir",
        "log_level",
        "wrapping_key_cache_ttl_secs",
    ];
    for field in &required_fields {
        assert!(
            show.stdout.contains(field),
            "config show output missing documented field `{field}`; got:\n{}",
            show.stdout
        );
    }

    // The default-config TOML must parse back via toml::from_str.
    // We can't easily import sshenc-core into the e2e crate (it'd
    // pull non-test code into the test compile graph); instead we
    // verify it's at least valid TOML.
    let parsed: toml::Value = toml::from_str(&show.stdout).unwrap_or_else(|e| {
        panic!(
            "config show output isn't valid TOML: {e}\noutput:\n{}",
            show.stdout
        )
    });
    drop(parsed);
}

/// `sshenc config init` against an already-initialized config
/// errors out with a "already exists" message rather than
/// silently overwriting. Without this, a re-init would clobber
/// user customizations.
#[test]
#[ignore = "requires docker"]
fn config_init_twice_errors_with_already_exists() {
    if skip_if_no_docker("config_init_twice_errors_with_already_exists") {
        return;
    }
    let env = SshencEnv::new().expect("env");

    // First init — may already exist from a prior test, that's
    // fine. We just need *some* config to exist before the
    // second invocation.
    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["config", "init"])));

    // Second init must report exists.
    let again =
        run(env.sshenc_cmd().expect("sshenc").args(["config", "init"])).expect("config init #2");
    assert!(
        !again.succeeded(),
        "second config init should fail; stdout:\n{}\nstderr:\n{}",
        again.stdout,
        again.stderr
    );
    assert!(
        again.stderr.contains("already exists") || again.stderr.contains("exists"),
        "expected 'already exists' message; got stderr:\n{}",
        again.stderr
    );
}

/// The TOML written by `config init` is acceptable to the agent's
/// `--config` loader. Boots the agent against the freshly-emitted
/// file; the agent must come up cleanly. Catches a regression
/// where `init` writes a value the runtime can't accept (path
/// expansion mismatch, enum tag rename, etc.).
#[test]
#[ignore = "requires docker"]
fn agent_boots_against_init_generated_config() {
    if skip_if_no_docker("agent_boots_against_init_generated_config") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");

    // Emit the default config via init+show, then write it to a
    // path the agent can use. We can't pass --config to point at
    // the user's default-path config because the agent's CLI
    // expects an explicit file path; emitting and re-saving is
    // simpler.
    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["config", "init"])));
    let show =
        run(env.sshenc_cmd().expect("sshenc").args(["config", "show"])).expect("config show");
    assert!(show.succeeded(), "config show: {}", show.stderr);

    // Rewrite socket_path / pub_dir to land inside the test's
    // tempdir HOME. The init file uses ~ which expands to the
    // tempdir already (HOME is set via scrubbed_command), but
    // verifying the agent loads the file we just wrote is what
    // matters; rewriting to absolute paths keeps the test
    // deterministic.
    let mut parsed: toml::Value = toml::from_str(&show.stdout).expect("show output is TOML");
    if let Some(t) = parsed.as_table_mut() {
        t.insert(
            "socket_path".into(),
            toml::Value::String(env.socket_path().display().to_string()),
        );
        t.insert(
            "pub_dir".into(),
            toml::Value::String(env.ssh_dir().display().to_string()),
        );
    }
    let config_path = env.home().join("init-roundtrip-config.toml");
    std::fs::write(&config_path, toml::to_string_pretty(&parsed).unwrap())
        .expect("write rewritten config");

    env.start_agent_with_config(Some(&config_path))
        .expect("agent must boot against init-generated config");

    let listed = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("ssh-add -L");
    assert!(
        listed.succeeded(),
        "ssh-add -L against init-config-bound agent failed; stderr:\n{}",
        listed.stderr
    );
}
