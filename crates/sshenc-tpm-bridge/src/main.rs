// Copyright 2026 Jay Gowdy
// SPDX-License-Identifier: MIT

#[allow(clippy::print_stderr)]
fn main() {
    hardware_enclave::process::harden_process();

    let mut server = enclaveapp_tpm_bridge::BridgeServer::new("sshenc", "default");
    if let Err(e) = server.run_stdio() {
        eprintln!("{e}");
        std::process::exit(1);
    }
}
