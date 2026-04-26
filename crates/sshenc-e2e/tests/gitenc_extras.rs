// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Additional gitenc / git-operation coverage.
//!
//! `gitenc.rs` covers push / clone / signed-commit. This file
//! covers the operations users hit on their day-to-day:
//!
//! - `git tag -s` produces a signed tag whose signature
//!   `git tag --verify` accepts.
//! - `git fetch` with an upstream that has new commits pulls
//!   them in via the agent-backed `GIT_SSH_COMMAND`.
//! - `git ls-remote` enumerates refs through the same channel.
//! - `git submodule add` + `git submodule update --init` works
//!   when the submodule URL is itself a sshenc-mediated SSH
//!   remote.
//!
//! All scenarios are docker-gated (they need the test SSH server)
//! and reuse the persistent shared enclave key.

#![allow(clippy::panic, clippy::unwrap_used, clippy::print_stderr)]

use sshenc_e2e::{
    docker_skip_reason, run, shared_enclave_pubkey, SshdContainer, SshencEnv, SHARED_ENCLAVE_LABEL,
};
use std::process::Stdio;

fn skip_if_no_docker(test_name: &str) -> bool {
    if let Some(reason) = docker_skip_reason() {
        eprintln!("skip {test_name}: {reason}");
        return true;
    }
    false
}

/// Build `SSHENC_SSH_EXTRA_ARGS` so indirect `gitenc` → `sshenc ssh
/// --` → ssh inherits the tempdir-scoped known_hosts and skips the
/// user's real ssh_config.
fn ssh_extra_args(env: &SshencEnv) -> String {
    format!(
        "-F /dev/null -o StrictHostKeyChecking=accept-new \
         -o UserKnownHostsFile={known} -o ConnectTimeout=10 \
         -o NumberOfPasswordPrompts=0 -o PreferredAuthentications=publickey",
        known = env.known_hosts().display(),
    )
}

/// Initialize a bare repo on the test container at `/home/sshtest/<name>`
/// and return its ssh:// URL. Mirrors the helper in `gitenc.rs` —
/// duplicated to keep this test file independent.
fn init_bare_repo(env: &SshencEnv, container: &SshdContainer, repo_name: &str) -> String {
    let cmd = format!(
        "mkdir -p /home/sshtest/{repo_name} && \
         git init --bare -b main /home/sshtest/{repo_name} >/dev/null"
    );
    let outcome = run(env
        .ssh_cmd(container)
        .arg("-o")
        .arg(format!("IdentityAgent={}", env.socket_path().display()))
        .arg("-i")
        .arg(env.ssh_dir().join("id_ed25519"))
        .arg("sshtest@127.0.0.1")
        .arg(cmd))
    .expect("ssh init bare");
    assert!(
        outcome.succeeded(),
        "remote git init failed; stderr:\n{}",
        outcome.stderr
    );
    format!(
        "ssh://sshtest@127.0.0.1:{port}/home/sshtest/{repo_name}",
        port = container.host_port
    )
}

/// Configure a fresh local repo via `gitenc --config <label>` so it
/// will use the enclave key for SSH auth and commit signing.
/// Returns the repo path.
fn make_signed_repo(env: &SshencEnv, name: &str, enclave_pub: &str) -> std::path::PathBuf {
    // Write pub file gitenc --config references.
    let pub_path = env.ssh_dir().join(format!("{SHARED_ENCLAVE_LABEL}.pub"));
    std::fs::create_dir_all(env.ssh_dir()).expect("mkdir ssh dir");
    std::fs::write(&pub_path, format!("{enclave_pub}\n")).expect("write pub");

    // Plant the meta file at the path gitenc reads from
    // ($HOME/.sshenc/keys), mirroring gitenc_edge.rs's pattern —
    // sshenc identity writes to SSHENC_KEYS_DIR but gitenc reads
    // via dirs::home_dir().
    let gitenc_meta_dir = env.home().join(".sshenc").join("keys");
    std::fs::create_dir_all(&gitenc_meta_dir).expect("mkdir gitenc meta dir");
    std::fs::write(
        gitenc_meta_dir.join(format!("{SHARED_ENCLAVE_LABEL}.meta")),
        serde_json::to_string_pretty(&serde_json::json!({
            "app_specific": {
                "git_name": "e2e signer",
                "git_email": "signer@gitenc-extras.test",
            }
        }))
        .unwrap(),
    )
    .expect("write meta");

    let repo = env.home().join(name);
    std::fs::create_dir_all(&repo).expect("mkdir local repo");
    let status = env
        .git_cmd()
        .current_dir(&repo)
        .args(["init", "-q", "-b", "main"])
        .status()
        .expect("git init");
    assert!(status.success());

    let cfg = run(env
        .gitenc_cmd()
        .expect("gitenc cmd")
        .current_dir(&repo)
        .args(["--config", SHARED_ENCLAVE_LABEL]))
    .expect("gitenc --config");
    assert!(
        cfg.succeeded(),
        "gitenc --config failed; stderr:\n{}",
        cfg.stderr
    );
    repo
}

fn make_initial_commit(env: &SshencEnv, repo: &std::path::Path, content: &str) {
    std::fs::write(repo.join("README.md"), content.as_bytes()).expect("write README");
    let add = run(env.git_cmd().current_dir(repo).args(["add", "README.md"])).expect("git add");
    assert!(add.succeeded(), "git add failed: {}", add.stderr);
    let commit = run(env
        .git_cmd()
        .current_dir(repo)
        .args(["commit", "-q", "-m", "initial"]))
    .expect("git commit");
    assert!(commit.succeeded(), "git commit failed: {}", commit.stderr);
}

/// `git tag -s` signs an annotated tag using the same SSH-key
/// signing path as `git commit -S`. After tagging,
/// `git tag --verify` should accept the signature.
#[test]
#[ignore = "requires docker"]
fn gitenc_signs_annotated_tag_via_y_sign() {
    if skip_if_no_docker("gitenc_signs_annotated_tag_via_y_sign") {
        return;
    }
    let env = SshencEnv::new().expect("env");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    let repo = make_signed_repo(&env, "tagged", &enclave);
    make_initial_commit(&env, &repo, "tag me\n");

    // Sign an annotated tag.
    let tag =
        run(env
            .git_cmd()
            .current_dir(&repo)
            .args(["tag", "-s", "v0.1.0", "-m", "release v0.1.0"]))
        .expect("git tag -s");
    assert!(
        tag.succeeded(),
        "git tag -s failed; stdout:\n{}\nstderr:\n{}",
        tag.stdout,
        tag.stderr
    );

    // Verify via git tag --verify. Output goes to stderr; both the
    // command success and the "Good signature" string must be present.
    let verify = env
        .git_cmd()
        .current_dir(&repo)
        .args(["tag", "--verify", "v0.1.0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("git tag --verify");
    let stderr = String::from_utf8_lossy(&verify.stderr);
    let stdout = String::from_utf8_lossy(&verify.stdout);
    let combined = format!("{stdout}\n{stderr}");
    assert!(
        verify.status.success(),
        "git tag --verify failed; output:\n{combined}"
    );
    assert!(
        combined.contains("Good \"git\" signature") || combined.contains("Good ssh signature"),
        "expected good ssh signature on tag; got:\n{combined}"
    );
}

/// `gitenc fetch` against an upstream that gained new commits
/// pulls them in. Auth flows through the agent the same way push /
/// clone do, but fetch hits a slightly different code path inside
/// git (refspec walk vs. full clone).
#[test]
#[ignore = "requires docker"]
fn gitenc_fetch_pulls_new_remote_commits() {
    if skip_if_no_docker("gitenc_fetch_pulls_new_remote_commits") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let on_disk = sshenc_e2e::generate_on_disk_ed25519(&env, "on-disk@e2e").expect("on-disk");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave, &on_disk]).expect("sshd container");
    let remote = init_bare_repo(&env, &container, "fetch-target.git");

    // Local "publisher" repo: push the first commit so the bare
    // remote has an initial state.
    let pub_repo = env.home().join("publisher");
    std::fs::create_dir_all(&pub_repo).expect("mkdir publisher");
    assert!(env
        .git_cmd()
        .current_dir(&pub_repo)
        .args(["init", "-q", "-b", "main"])
        .status()
        .unwrap()
        .success());
    assert!(env
        .git_cmd()
        .current_dir(&pub_repo)
        .args(["remote", "add", "origin", &remote])
        .status()
        .unwrap()
        .success());
    std::fs::write(pub_repo.join("seed.txt"), b"seed\n").expect("write seed");
    assert!(env
        .git_cmd()
        .current_dir(&pub_repo)
        .args(["add", "seed.txt"])
        .status()
        .unwrap()
        .success());
    assert!(env
        .git_cmd()
        .current_dir(&pub_repo)
        .args(["commit", "-q", "-m", "seed"])
        .status()
        .unwrap()
        .success());
    let extras = ssh_extra_args(&env);
    assert!(run(env
        .gitenc_cmd()
        .expect("gitenc")
        .env("SSHENC_SSH_EXTRA_ARGS", &extras)
        .current_dir(&pub_repo)
        .args(["push", "-u", "origin", "main"]))
    .expect("publisher push")
    .succeeded());

    // "Subscriber": clone, then have the publisher push another
    // commit, then `gitenc fetch` and verify the new commit is
    // visible in `origin/main`.
    let sub = env.home().join("subscriber");
    let clone = run(env
        .gitenc_cmd()
        .expect("gitenc")
        .env("SSHENC_SSH_EXTRA_ARGS", &extras)
        .arg("clone")
        .arg(&remote)
        .arg(&sub))
    .expect("gitenc clone");
    assert!(clone.succeeded(), "subscriber clone: {}", clone.stderr);

    // Publisher: add a second commit and push.
    std::fs::write(pub_repo.join("update.txt"), b"second commit\n").expect("write update");
    assert!(env
        .git_cmd()
        .current_dir(&pub_repo)
        .args(["add", "update.txt"])
        .status()
        .unwrap()
        .success());
    assert!(env
        .git_cmd()
        .current_dir(&pub_repo)
        .args(["commit", "-q", "-m", "second"])
        .status()
        .unwrap()
        .success());
    assert!(run(env
        .gitenc_cmd()
        .expect("gitenc")
        .env("SSHENC_SSH_EXTRA_ARGS", &extras)
        .current_dir(&pub_repo)
        .args(["push"]))
    .expect("publisher push 2")
    .succeeded());

    // Subscriber: fetch via gitenc.
    let fetch = run(env
        .gitenc_cmd()
        .expect("gitenc")
        .env("SSHENC_SSH_EXTRA_ARGS", &extras)
        .current_dir(&sub)
        .args(["fetch", "origin"]))
    .expect("gitenc fetch");
    assert!(
        fetch.succeeded(),
        "gitenc fetch failed; stderr:\n{}",
        fetch.stderr
    );

    // The second commit must be visible to the subscriber via
    // `git log origin/main` even before merging.
    let log = run(env
        .git_cmd()
        .current_dir(&sub)
        .args(["log", "--oneline", "origin/main"]))
    .expect("git log");
    assert!(log.succeeded(), "git log failed: {}", log.stderr);
    assert!(
        log.stdout.contains("second"),
        "fetched ref should include 'second' commit; got:\n{}",
        log.stdout
    );
}

/// `git ls-remote` against an SSH remote — same auth path as
/// fetch, but it doesn't transfer pack data; just enumerates refs.
/// Catches regressions that break ref enumeration but not data
/// transfer.
#[test]
#[ignore = "requires docker"]
fn gitenc_ls_remote_enumerates_refs() {
    if skip_if_no_docker("gitenc_ls_remote_enumerates_refs") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let on_disk = sshenc_e2e::generate_on_disk_ed25519(&env, "on-disk@e2e").expect("on-disk");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave, &on_disk]).expect("sshd container");
    let remote = init_bare_repo(&env, &container, "ls-remote-target.git");

    // Seed the remote with a single commit so it has a HEAD ref.
    let seed = env.home().join("ls-seed");
    std::fs::create_dir_all(&seed).expect("mkdir");
    assert!(env
        .git_cmd()
        .current_dir(&seed)
        .args(["init", "-q", "-b", "main"])
        .status()
        .unwrap()
        .success());
    std::fs::write(seed.join("x"), b"x\n").expect("write");
    assert!(env
        .git_cmd()
        .current_dir(&seed)
        .args(["add", "x"])
        .status()
        .unwrap()
        .success());
    assert!(env
        .git_cmd()
        .current_dir(&seed)
        .args(["commit", "-q", "-m", "seed"])
        .status()
        .unwrap()
        .success());
    let extras = ssh_extra_args(&env);
    assert!(run(env
        .gitenc_cmd()
        .expect("gitenc")
        .env("SSHENC_SSH_EXTRA_ARGS", &extras)
        .current_dir(&seed)
        .args(["remote", "add", "origin", &remote]))
    .expect("remote add")
    .succeeded());
    assert!(run(env
        .gitenc_cmd()
        .expect("gitenc")
        .env("SSHENC_SSH_EXTRA_ARGS", &extras)
        .current_dir(&seed)
        .args(["push", "-u", "origin", "main"]))
    .expect("seed push")
    .succeeded());

    // ls-remote should enumerate at least main + HEAD.
    let ls = run(env
        .gitenc_cmd()
        .expect("gitenc")
        .env("SSHENC_SSH_EXTRA_ARGS", &extras)
        .args(["ls-remote", &remote]))
    .expect("gitenc ls-remote");
    assert!(
        ls.succeeded(),
        "gitenc ls-remote failed; stderr:\n{}",
        ls.stderr
    );
    assert!(
        ls.stdout.contains("refs/heads/main"),
        "ls-remote output should include refs/heads/main; got:\n{}",
        ls.stdout
    );
    assert!(
        ls.stdout.contains("HEAD"),
        "ls-remote output should include HEAD; got:\n{}",
        ls.stdout
    );
}

/// `git submodule add` + `git submodule update --init` against an
/// SSH submodule URL. `git submodule update` runs a separate
/// `git fetch` internally, which goes through the same SSH agent
/// chain — this is the integration check for that nested flow.
#[test]
#[ignore = "requires docker"]
fn gitenc_submodule_init_and_update() {
    if skip_if_no_docker("gitenc_submodule_init_and_update") {
        return;
    }
    let mut env = SshencEnv::new().expect("env");
    let on_disk = sshenc_e2e::generate_on_disk_ed25519(&env, "on-disk@e2e").expect("on-disk");
    let enclave = shared_enclave_pubkey(&env).expect("shared enclave");
    env.start_agent().expect("start agent");
    let container = SshdContainer::start(&[&enclave, &on_disk]).expect("sshd container");
    let parent_url = init_bare_repo(&env, &container, "submod-parent.git");
    let child_url = init_bare_repo(&env, &container, "submod-child.git");

    let extras = ssh_extra_args(&env);

    // Seed the child repo with one commit.
    let child_local = env.home().join("submod-child-src");
    std::fs::create_dir_all(&child_local).expect("mkdir");
    assert!(env
        .git_cmd()
        .current_dir(&child_local)
        .args(["init", "-q", "-b", "main"])
        .status()
        .unwrap()
        .success());
    std::fs::write(child_local.join("payload.txt"), b"child payload\n").expect("write");
    assert!(env
        .git_cmd()
        .current_dir(&child_local)
        .args(["add", "payload.txt"])
        .status()
        .unwrap()
        .success());
    assert!(env
        .git_cmd()
        .current_dir(&child_local)
        .args(["commit", "-q", "-m", "child seed"])
        .status()
        .unwrap()
        .success());
    assert!(run(env
        .gitenc_cmd()
        .expect("gitenc")
        .env("SSHENC_SSH_EXTRA_ARGS", &extras)
        .current_dir(&child_local)
        .args(["remote", "add", "origin", &child_url]))
    .expect("child remote add")
    .succeeded());
    assert!(run(env
        .gitenc_cmd()
        .expect("gitenc")
        .env("SSHENC_SSH_EXTRA_ARGS", &extras)
        .current_dir(&child_local)
        .args(["push", "-u", "origin", "main"]))
    .expect("child push")
    .succeeded());

    // Set up the parent: add child as a submodule and push.
    let parent_local = env.home().join("submod-parent-src");
    std::fs::create_dir_all(&parent_local).expect("mkdir");
    assert!(env
        .git_cmd()
        .current_dir(&parent_local)
        .args(["init", "-q", "-b", "main"])
        .status()
        .unwrap()
        .success());
    // Allow file:// — but here we're using ssh:// child_url so
    // not relevant. submodule.url is whatever git records.
    let submod_add = run(env
        .gitenc_cmd()
        .expect("gitenc")
        .env("SSHENC_SSH_EXTRA_ARGS", &extras)
        .current_dir(&parent_local)
        .args(["-c", "protocol.ssh.allow=always"])
        .args(["submodule", "add", &child_url, "child"]))
    .expect("submodule add");
    assert!(
        submod_add.succeeded(),
        "submodule add failed; stderr:\n{}",
        submod_add.stderr
    );
    // Commit the .gitmodules + child gitlink.
    assert!(env
        .git_cmd()
        .current_dir(&parent_local)
        .args(["commit", "-q", "-m", "add child submodule"])
        .status()
        .unwrap()
        .success());
    assert!(run(env
        .gitenc_cmd()
        .expect("gitenc")
        .env("SSHENC_SSH_EXTRA_ARGS", &extras)
        .current_dir(&parent_local)
        .args(["remote", "add", "origin", &parent_url]))
    .expect("parent remote add")
    .succeeded());
    assert!(run(env
        .gitenc_cmd()
        .expect("gitenc")
        .env("SSHENC_SSH_EXTRA_ARGS", &extras)
        .current_dir(&parent_local)
        .args(["push", "-u", "origin", "main"]))
    .expect("parent push")
    .succeeded());

    // Fresh clone of the parent without submodule init — then
    // `gitenc submodule update --init`. The update step is what
    // actually exercises the SSH chain for the submodule URL.
    let consumer = env.home().join("submod-consumer");
    let clone = run(env
        .gitenc_cmd()
        .expect("gitenc")
        .env("SSHENC_SSH_EXTRA_ARGS", &extras)
        .arg("clone")
        .arg(&parent_url)
        .arg(&consumer))
    .expect("consumer clone");
    assert!(clone.succeeded(), "consumer clone: {}", clone.stderr);

    let submod_update = run(env
        .gitenc_cmd()
        .expect("gitenc")
        .env("SSHENC_SSH_EXTRA_ARGS", &extras)
        .current_dir(&consumer)
        .args(["-c", "protocol.ssh.allow=always"])
        .args(["submodule", "update", "--init"]))
    .expect("submodule update --init");
    assert!(
        submod_update.succeeded(),
        "submodule update --init failed; stderr:\n{}",
        submod_update.stderr
    );

    let payload = consumer.join("child").join("payload.txt");
    let content = std::fs::read_to_string(&payload).expect("read submodule child file post-update");
    assert!(
        content.contains("child payload"),
        "submodule child file content unexpected: {content:?}"
    );
}
