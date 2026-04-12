#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the SSH agent protocol request parser.
    // This parses untrusted input from SSH clients.
    let _ = sshenc_agent_proto::message::parse_request(data);
});
