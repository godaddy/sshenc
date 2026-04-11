// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! gitenc: Git wrapper that selects sshenc Secure Enclave identities.
//!
//! Usage:
//!   gitenc --label NAME [git args...]    # use a specific SE key
//!   gitenc [git args...]                 # use default (agent picks)
//!
//! Examples:
//!   gitenc --label github-work clone git@github.com:org/repo.git
//!   gitenc --label github-personal push origin main
//!   gitenc pull                          # no label, default key selection

use std::os::unix::process::CommandExt;
use std::process::Command;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let (label, git_args) = parse_args(&args);

    let ssh_command = match &label {
        Some(l) => format!("sshenc ssh --label {} --", l),
        None => "sshenc ssh --".to_string(),
    };

    let err = Command::new("git")
        .args(&git_args)
        .env("GIT_SSH_COMMAND", &ssh_command)
        .exec();

    // exec() only returns on error
    eprintln!("gitenc: failed to exec git: {err}");
    std::process::exit(1);
}

/// Parse --label NAME from the front of the args, return (label, remaining git args).
fn parse_args(args: &[String]) -> (Option<String>, Vec<String>) {
    if args.len() >= 2 && (args[0] == "--label" || args[0] == "-l") {
        (Some(args[1].clone()), args[2..].to_vec())
    } else {
        (None, args.to_vec())
    }
}
