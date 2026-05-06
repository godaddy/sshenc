#![no_main]
use libfuzzer_sys::fuzz_target;

use std::io::Cursor;

// Mirror the bridge client's per-line cap. If the constant in the
// bridge crate changes, update this — fuzzing past the real cap
// would explore allocations the real client never makes.
const MAX_BRIDGE_RESPONSE_BYTES: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    // Fuzz the WSL → Windows bridge response path. The bridge is a
    // child process speaking JSON-RPC over stdin/stdout; the client
    // reads one line per response, capped at MAX_BRIDGE_RESPONSE_BYTES,
    // then attempts serde_json deserialization into BridgeResponse.
    //
    // The harness exercises both halves end-to-end:
    //   1. read_line_bounded against arbitrary fuzz input
    //   2. serde_json::from_str::<BridgeResponse>(line) when a line
    //      is produced
    //
    // libfuzzer asserts no panic. We additionally assert the post-read
    // buffer never exceeds the cap; that's the property B2 added.
    let mut cursor = Cursor::new(data);
    let mut reader = std::io::BufReader::new(&mut cursor);
    if let Ok(Some(line)) = enclaveapp_core::timeout::read_line_bounded(
        &mut reader,
        MAX_BRIDGE_RESPONSE_BYTES,
    ) {
        // Hard invariant: read_line_bounded never returns a string
        // larger than the cap (plus 1 for the newline byte that's
        // included per BufRead::read_line semantics).
        assert!(line.len() <= MAX_BRIDGE_RESPONSE_BYTES);
        // Best-effort: feed the line to the same deserializer the
        // production code uses. We don't care whether it succeeds;
        // we only care that it doesn't panic.
        let _ = serde_json::from_str::<enclaveapp_bridge::BridgeResponse>(&line);
    }
});
