#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the SSH wire format string reader.
    // This parses untrusted input embedded in SSH protocol messages.
    let _ = sshenc_core::pubkey::read_ssh_string(data);
});
