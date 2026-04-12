#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the DER signature parser.
    // This parses signatures from the Secure Enclave / TPM.
    let _ = sshenc_agent_proto::signature::der_to_ssh_signature(data);
});
