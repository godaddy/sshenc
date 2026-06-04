// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

#[allow(clippy::print_stderr)]
fn main() {
    hardware_enclave::process::harden_process();

    let mut server = hardware_enclave::bridge_server::BridgeServer::new("sshenc", "default");
    if let Err(e) = server.run_stdio() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
