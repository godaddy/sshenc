// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! CLI lifecycle / config-surface e2e coverage.
//!
//! Exercises the day-to-day sshenc commands that aren't ssh/agent-auth:
//! `sshenc list`, `inspect`, `delete`, `install`/`uninstall` round-trip
//! and repair, the standalone `sshenc-keygen` binary, `openssh
//! print-config`, `config init`/`path`/`show`, and the
//! `allowed_labels` filtering on the agent.
//!
//! The tests that create fresh enclave keys (`delete`, `sshenc-keygen`,
//! `allowed_labels`) are gated behind `SSHENC_E2E_EXTENDED=1` in SE
//! mode because each new key costs one macOS keychain prompt per
//! binary per rebuild. Software mode (`SSHENC_E2E_SOFTWARE=1`) has no
//! prompt cost; all scenarios are safe to run.

#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, extended_enabled, run, shared_enclave_pubkey, software_mode, workspace_bin,
    SshdContainer, SshencEnv, SHARED_ENCLAVE_LABEL,
};

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

/// Skip tests that need to create fresh enclave keys unless either
/// extended mode is on (accepts extra prompts on macOS SE) or software
/// mode is on (no prompts).
fn skip_unless_key_creation_cheap(test_name: &str) -> bool {
    if extended_enabled() || software_mode() {
        return false;
    }
    eprintln!(
        "skip {test_name}: needs to create enclave keys; set SSHENC_E2E_EXTENDED=1 (SE, costs prompts) \
         or SSHENC_E2E_SOFTWARE=1 (software, free)"
    );
    true
}

/// sshenc list shows the shared enclave key (and the `--json` form
/// parses as an array).
#[test]
#[ignore = "requires docker"]
fn sshenc_list_shows_keys_in_text_and_json() {
    if skip_if_no_docker("sshenc_list_shows_keys_in_text_and_json") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared enclave"));

    let text = run(env.sshenc_cmd().expect("sshenc").arg("list")).expect("list");
    assert!(text.succeeded(), "list failed: {}", text.stderr);
    assert!(
        text.stdout.contains(SHARED_ENCLAVE_LABEL),
        "expected label in text output:\n{}",
        text.stdout
    );

    let json_out =
        run(env.sshenc_cmd().expect("sshenc").args(["list", "--json"])).expect("list --json");
    assert!(
        json_out.succeeded(),
        "list --json failed: {}",
        json_out.stderr
    );
    let parsed: serde_json::Value =
        serde_json::from_str(&json_out.stdout).expect("list --json is not valid JSON");
    assert!(parsed.is_array(), "list --json must be a JSON array");
    let labels: Vec<String> = parsed
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|item| {
            item.get("metadata")
                .and_then(|m| m.get("label"))
                .and_then(|l| l.as_str())
                .map(String::from)
        })
        .collect();
    assert!(
        labels.iter().any(|l| l == SHARED_ENCLAVE_LABEL),
        "expected {SHARED_ENCLAVE_LABEL} in JSON labels: {labels:?}"
    );
}

/// sshenc inspect emits the label, fingerprint, and the correct
/// key-type tokens.
#[test]
#[ignore = "requires docker"]
fn sshenc_inspect_shows_key_details() {
    if skip_if_no_docker("sshenc_inspect_shows_key_details") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let pubkey = shared_enclave_pubkey(&env).expect("shared enclave");

    let outcome = run(env
        .sshenc_cmd()
        .expect("sshenc")
        .arg("inspect")
        .arg(SHARED_ENCLAVE_LABEL))
    .expect("inspect");
    assert!(outcome.succeeded(), "inspect failed: {}", outcome.stderr);
    assert!(
        outcome.stdout.contains(SHARED_ENCLAVE_LABEL),
        "expected label in inspect; got:\n{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("SHA256"),
        "expected SHA256 fingerprint line in inspect; got:\n{}",
        outcome.stdout
    );
    // inspect --show-pub should include the real OpenSSH pubkey line.
    let with_pub = run(env.sshenc_cmd().expect("sshenc").args([
        "inspect",
        SHARED_ENCLAVE_LABEL,
        "--show-pub",
    ]))
    .expect("inspect --show-pub");
    assert!(
        with_pub.succeeded(),
        "inspect --show-pub failed: {}",
        with_pub.stderr
    );
    let trimmed_pub = pubkey
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    assert!(
        with_pub.stdout.contains(&trimmed_pub),
        "expected pubkey line in --show-pub output; got:\n{}",
        with_pub.stdout
    );
}

/// sshenc delete removes a throwaway key. Creates `e2e-delete-me`,
/// confirms list shows it, deletes it, confirms list no longer shows
/// it. Gated because it creates a fresh enclave key.
#[test]
#[ignore = "requires docker"]
fn sshenc_delete_removes_key() {
    if skip_if_no_docker("sshenc_delete_removes_key") {
        return;
    }
    if skip_unless_key_creation_cheap("sshenc_delete_removes_key") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let label = "e2e-delete-me";

    // Ensure any prior remnant is gone.
    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", label, "-y"])));

    let gen_out = run(env.sshenc_cmd().expect("sshenc").args([
        "keygen",
        "--label",
        label,
        "--auth-policy",
        "none",
        "--no-pub-file",
    ]))
    .expect("keygen");
    assert!(gen_out.succeeded(), "keygen failed: {}", gen_out.stderr);

    let listed = run(env.sshenc_cmd().expect("sshenc").arg("list")).expect("list before delete");
    assert!(
        listed.stdout.contains(label),
        "label should appear before delete:\n{}",
        listed.stdout
    );

    let del = run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", label, "-y"]))
    .expect("delete");
    assert!(del.succeeded(), "delete failed: {}", del.stderr);

    let listed_after =
        run(env.sshenc_cmd().expect("sshenc").arg("list")).expect("list after delete");
    assert!(
        !listed_after.stdout.contains(label),
        "label should not appear after delete:\n{}",
        listed_after.stdout
    );
}

/// `sshenc install` is idempotent: running it twice leaves the managed
/// block unchanged. Second run should not corrupt the config file.
#[test]
#[ignore = "requires docker"]
fn sshenc_install_idempotent() {
    if skip_if_no_docker("sshenc_install_idempotent") {
        return;
    }
    let env = SshencEnv::new().expect("env");

    let first = run(env.sshenc_cmd().expect("sshenc").arg("install")).expect("install #1");
    assert!(first.succeeded(), "install #1 failed: {}", first.stderr);
    let config_path = env.ssh_dir().join("config");
    let content_a = std::fs::read_to_string(&config_path).expect("read config");
    assert!(content_a.contains("IdentityAgent"), "managed block missing");

    let second = run(env.sshenc_cmd().expect("sshenc").arg("install")).expect("install #2");
    assert!(second.succeeded(), "install #2 failed: {}", second.stderr);
    let content_b = std::fs::read_to_string(&config_path).expect("read config");

    // The managed block should be stable. Allow the repair path to rewrite
    // the file when the rendered dylib path changes, but the
    // IdentityAgent directive must still be present exactly once.
    let occurrences = content_b.matches("IdentityAgent").count();
    assert_eq!(
        occurrences, 1,
        "IdentityAgent directive should appear exactly once after two installs:\n{content_b}"
    );
    // Begin/end markers must balance.
    assert_eq!(
        content_b.matches("# BEGIN sshenc managed block").count(),
        1,
        "should be exactly one BEGIN marker:\n{content_b}"
    );
    assert_eq!(
        content_b.matches("# END sshenc managed block").count(),
        1,
        "should be exactly one END marker:\n{content_b}"
    );

    // content_a preserved here so a future reader can diff against
    // content_b if the idempotency assumption ever changes; no runtime
    // assertion on it.
    drop(content_a);
}

/// install → uninstall removes the managed block and leaves the rest of
/// `~/.ssh/config` intact.
#[test]
#[ignore = "requires docker"]
fn sshenc_install_uninstall_roundtrip() {
    if skip_if_no_docker("sshenc_install_uninstall_roundtrip") {
        return;
    }
    let env = SshencEnv::new().expect("env");

    let config_path = env.ssh_dir().join("config");
    std::fs::write(&config_path, "Host preexisting\n    User me\n").expect("write config seed");

    let install = run(env.sshenc_cmd().expect("sshenc").arg("install")).expect("install");
    assert!(install.succeeded(), "install failed: {}", install.stderr);
    let after_install = std::fs::read_to_string(&config_path).expect("read config");
    assert!(
        after_install.contains("IdentityAgent"),
        "managed block missing after install"
    );
    assert!(
        after_install.contains("Host preexisting"),
        "preexisting content lost after install"
    );

    let uninstall = run(env.sshenc_cmd().expect("sshenc").arg("uninstall")).expect("uninstall");
    assert!(
        uninstall.succeeded(),
        "uninstall failed: {}",
        uninstall.stderr
    );
    let after_uninstall = std::fs::read_to_string(&config_path).expect("read config");
    assert!(
        !after_uninstall.contains("IdentityAgent"),
        "managed block still present after uninstall:\n{after_uninstall}"
    );
    assert!(
        !after_uninstall.contains("# BEGIN sshenc managed block"),
        "BEGIN marker still present after uninstall"
    );
    assert!(
        after_uninstall.contains("Host preexisting"),
        "preexisting content lost during uninstall:\n{after_uninstall}"
    );
}

/// The `sshenc-keygen` standalone binary creates a key visible to
/// `sshenc list`, proving its behavior is consistent with the
/// `sshenc keygen` subcommand.
#[test]
#[ignore = "requires docker"]
fn sshenc_keygen_standalone_binary_creates_listable_key() {
    if skip_if_no_docker("sshenc_keygen_standalone_binary_creates_listable_key") {
        return;
    }
    if skip_unless_key_creation_cheap("sshenc_keygen_standalone_binary_creates_listable_key") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let label = "e2e-keygen-standalone";

    // Pre-clean.
    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", label, "-y"])));

    let bin = workspace_bin("sshenc-keygen").expect("sshenc-keygen bin");
    // sshenc-keygen has a narrower flag set than `sshenc keygen`;
    // no --auth-policy, just --require-user-presence (omitted to
    // keep the test non-interactive).
    let gen_out = run(env
        .scrubbed_command(&bin)
        .args(["--label", label, "--no-pub-file"]))
    .expect("sshenc-keygen");
    assert!(
        gen_out.succeeded(),
        "sshenc-keygen failed: stdout:\n{}\nstderr:\n{}",
        gen_out.stdout,
        gen_out.stderr
    );

    let listed = run(env.sshenc_cmd().expect("sshenc").arg("list")).expect("list");
    assert!(
        listed.stdout.contains(label),
        "standalone keygen's label should appear in list:\n{}",
        listed.stdout
    );

    // Cleanup.
    drop(run(env
        .sshenc_cmd()
        .expect("sshenc")
        .args(["delete", label, "-y"])));
}

/// `sshenc openssh print-config <label> <host>` emits a valid Host
/// block for the named key.
#[test]
#[ignore = "requires docker"]
fn sshenc_openssh_print_config_outputs_expected_block() {
    if skip_if_no_docker("sshenc_openssh_print_config_outputs_expected_block") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    drop(shared_enclave_pubkey(&env).expect("shared enclave"));

    let outcome = run(env.sshenc_cmd().expect("sshenc").args([
        "openssh",
        "print-config",
        "--label",
        SHARED_ENCLAVE_LABEL,
        "--host",
        "example.test",
    ]))
    .expect("openssh print-config");
    assert!(
        outcome.succeeded(),
        "openssh print-config failed: {}",
        outcome.stderr
    );
    assert!(
        outcome.stdout.contains("Host example.test"),
        "expected Host block; got:\n{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("IdentityAgent"),
        "expected IdentityAgent directive; got:\n{}",
        outcome.stdout
    );
    assert!(
        outcome.stdout.contains("IdentitiesOnly yes"),
        "expected IdentitiesOnly yes; got:\n{}",
        outcome.stdout
    );
}

/// `sshenc config init` → `path` → `show` round-trip. Writes a default
/// config, reports where it is, and re-reads it.
#[test]
#[ignore = "requires docker"]
fn sshenc_config_init_path_show_roundtrip() {
    if skip_if_no_docker("sshenc_config_init_path_show_roundtrip") {
        return;
    }
    let env = SshencEnv::new().expect("env");

    // `config init` may error if a config already exists from a prior
    // flow (none expected in a fresh tempdir HOME, but be defensive).
    let init =
        run(env.sshenc_cmd().expect("sshenc").args(["config", "init"])).expect("config init");
    // Either it succeeded, or it reported "already exists" without
    // crashing; both are acceptable outcomes of `init`.
    if !init.succeeded() {
        assert!(
            init.stderr.contains("already exists"),
            "config init failed unexpectedly: {}",
            init.stderr
        );
    }

    let path =
        run(env.sshenc_cmd().expect("sshenc").args(["config", "path"])).expect("config path");
    assert!(path.succeeded(), "config path failed: {}", path.stderr);
    assert!(
        path.stdout.contains("config.toml"),
        "expected config.toml in path; got:\n{}",
        path.stdout
    );

    let show =
        run(env.sshenc_cmd().expect("sshenc").args(["config", "show"])).expect("config show");
    assert!(show.succeeded(), "config show failed: {}", show.stderr);
    // Show prints toml content — sanity check it has a key we know.
    assert!(
        show.stdout.contains("socket_path"),
        "expected socket_path in config show output; got:\n{}",
        show.stdout
    );
}

/// Agent `allowed_labels` filters identity enumeration so only the
/// named keys are served. Verified against a live ssh connection: the
/// filtered-out key should be invisible through the agent, and
/// `sshenc ssh` should not be able to authenticate using it.
#[test]
#[ignore = "requires docker"]
fn agent_allowed_labels_filters_identities() {
    if skip_if_no_docker("agent_allowed_labels_filters_identities") {
        return;
    }
    if skip_unless_key_creation_cheap("agent_allowed_labels_filters_identities") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let shared = shared_enclave_pubkey(&env).expect("shared enclave");
    // Reuse the persistent `e2e-shared-b` key already created by the
    // multi-label extended scenario instead of creating yet another
    // persistent SE key. This keeps the SE-mode prompt budget to the
    // existing extended keys (e2e-shared, e2e-shared-b, default).
    let second_label = "e2e-shared-b";
    let second =
        sshenc_e2e::ensure_persistent_enclave_key(&env, second_label).expect("second enclave");
    assert_ne!(shared, second, "distinct pubkeys expected");

    // Write a sshenc config.toml that restricts the agent to the
    // shared label only. Path resolution via `dirs::config_dir()` is
    // platform-dependent (~/Library/Application Support on macOS, etc.),
    // so we pass the path to the agent explicitly via `--config`.
    let config_path = env.home().join("sshenc-config.toml");
    std::fs::write(
        &config_path,
        format!(
            "socket_path = \"{sock}\"\n\
             pub_dir = \"{pub_dir}\"\n\
             allowed_labels = [\"{SHARED_ENCLAVE_LABEL}\"]\n\
             prompt_policy = \"never\"\n\
             log_level = \"info\"\n",
            sock = env.socket_path().display(),
            pub_dir = env.ssh_dir().display(),
        ),
    )
    .expect("write config");

    env.start_agent_with_config(Some(&config_path))
        .expect("agent start with config");

    // Verify ssh-add -l shows only the shared label.
    let listed = run(env
        .scrubbed_command("ssh-add")
        .env("SSH_AUTH_SOCK", env.socket_path())
        .arg("-L"))
    .expect("ssh-add -L");
    assert!(listed.succeeded(), "ssh-add -L failed: {}", listed.stderr);
    assert!(
        listed
            .stdout
            .contains(&shared.split_whitespace().nth(1).unwrap().to_string()),
        "agent should expose shared pubkey; got:\n{}",
        listed.stdout
    );
    let second_key_body = second.split_whitespace().nth(1).unwrap().to_string();
    assert!(
        !listed.stdout.contains(&second_key_body),
        "agent should NOT expose filtered-out pubkey; got:\n{}",
        listed.stdout
    );

    // Spin up a container that trusts the filtered-out key, confirm
    // sshenc ssh cannot authenticate against it via the agent.
    let container = SshdContainer::start(&[&second]).expect("container trusting filtered key");
    let mut cmd = env.sshenc_cmd().expect("sshenc");
    cmd.arg("ssh").arg("--");
    SshencEnv::apply_ssh_isolation(&mut cmd, container.host_port, &env.known_hosts());
    cmd.arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("sshtest@127.0.0.1")
        .arg("true");
    let outcome = run(&mut cmd).expect("sshenc ssh");
    assert!(
        !outcome.succeeded(),
        "ssh should fail because the only trusted key is filtered out of the agent; \
         stdout:\n{}\nstderr:\n{}",
        outcome.stdout,
        outcome.stderr
    );

    // `second_label` is the shared persistent `e2e-shared-b` used by
    // the multi-label extended scenario — do not delete it.
    let _ = second_label;
}
