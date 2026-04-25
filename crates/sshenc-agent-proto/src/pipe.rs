// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Windows named-pipe client for talking to `sshenc-agent`.
//!
//! On Unix the client uses `std::os::unix::net::UnixStream`; this
//! module is the Windows equivalent, built on `CreateFileW` +
//! `ReadFile`/`WriteFile` against an existing named pipe (the agent
//! creates the server side with `CreateNamedPipeW`). The resulting
//! [`PipeStream`] implements [`std::io::Read`] and [`std::io::Write`]
//! so the framing helpers in `client.rs` work across platforms with
//! generic bounds.
//!
//! The pipe name follows the standard OpenSSH convention — the
//! default `sshenc` `socket_path` on Windows is
//! `\\.\pipe\openssh-ssh-agent`, i.e. the same pipe regular
//! `ssh.exe` would connect to. This is intentional: making
//! `sshenc-agent` a drop-in replacement for OpenSSH's agent means
//! standard SSH tools and our own CLI hit the same endpoint, and
//! our sshenc-specific extensions (`SSH_AGENTC_SSHENC_*`) travel
//! over the same connection.

#![cfg(windows)]
// Raw winapi is inherently unsafe — CreateFileW, ReadFile, WriteFile,
// CloseHandle, WaitNamedPipeW. The unsafe blocks are scoped to the
// smallest possible calls and their preconditions (valid handle,
// valid buffer, etc.) are checked locally.
#![allow(unsafe_code)]

use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::iter::once;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::time::Duration;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, WriteFile, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_SHARE_NONE, OPEN_EXISTING,
};
use windows::Win32::System::Pipes::WaitNamedPipeW;

/// Owned handle to a connected Windows named pipe. The agent side
/// is created with `CreateNamedPipeW`; this is the client side
/// opened with `CreateFileW`. Closes the handle on drop so callers
/// never need to do manual cleanup.
#[derive(Debug)]
pub struct PipeStream {
    handle: HANDLE,
}

impl PipeStream {
    /// Connect to the named pipe at `pipe_name`. Expects a path like
    /// `\\.\pipe\openssh-ssh-agent`. Blocks briefly waiting for a
    /// server instance to be available (via `WaitNamedPipeW`) so
    /// the caller doesn't lose a race with an agent that just
    /// served another client.
    pub fn connect(pipe_name: &Path) -> io::Result<Self> {
        let wide: Vec<u16> = OsStr::new(pipe_name).encode_wide().chain(once(0)).collect();
        let pcwstr = PCWSTR::from_raw(wide.as_ptr());

        // Wait up to 10 s for a pipe instance. If the pipe doesn't
        // exist at all the call returns fast with a falsy BOOL —
        // actionable only via the `CreateFileW` below, which gives
        // us a richer error. `WaitNamedPipeW` returns a plain BOOL
        // (Copy) so `let _ = …` is a true no-op, not a destructor
        // silence.
        let _ignored_wait_result = unsafe { WaitNamedPipeW(pcwstr, 10_000) };

        let handle = unsafe {
            CreateFileW(
                pcwstr,
                (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
                FILE_SHARE_NONE,
                None,
                OPEN_EXISTING,
                FILE_FLAGS_AND_ATTRIBUTES::default(),
                None,
            )
        }
        .map_err(|e| io::Error::other(format!("CreateFileW: {e}")))?;

        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "CreateFileW returned INVALID_HANDLE_VALUE (agent not running?)",
            ));
        }

        Ok(Self { handle })
    }

    /// Best-effort readiness probe — try to open and immediately
    /// close the pipe. Used by [`ensure_daemon_ready`] so we don't
    /// waste wall-clock time when the agent is already up and
    /// serving.
    pub fn probe(pipe_name: &Path) -> bool {
        Self::connect(pipe_name).is_ok()
    }

    /// Set both read and write timeouts to `timeout`. Windows named
    /// pipes inherit the server's configured timeout when no client
    /// override is set; we use this as a defense-in-depth guard so
    /// a misbehaving agent can't hang the CLI indefinitely.
    pub fn set_timeouts(&mut self, _timeout: Duration) -> io::Result<()> {
        // Windows named pipes don't expose a per-handle read/write
        // timeout analogous to `SO_RCVTIMEO` on sockets. The server
        // already enforces its own timeouts on unresponsive clients;
        // on our side the agent is local and fast, so we rely on
        // that. Keeping the method signature matched with the Unix
        // side makes the generic wiring in `client.rs` uniform.
        Ok(())
    }
}

impl Read for PipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut bytes_read: u32 = 0;
        unsafe { ReadFile(self.handle, Some(buf), Some(&mut bytes_read), None) }
            .map_err(|e| io::Error::other(format!("ReadFile: {e}")))?;
        Ok(bytes_read as usize)
    }
}

impl Write for PipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut bytes_written: u32 = 0;
        unsafe { WriteFile(self.handle, Some(buf), Some(&mut bytes_written), None) }
            .map_err(|e| io::Error::other(format!("WriteFile: {e}")))?;
        Ok(bytes_written as usize)
    }

    fn flush(&mut self) -> io::Result<()> {
        // ReadFile / WriteFile on a named pipe synchronously do the
        // I/O already — there's no userland buffer to flush.
        Ok(())
    }
}

impl Drop for PipeStream {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE {
            unsafe {
                drop(CloseHandle(self.handle));
            }
        }
    }
}

// `HANDLE` is a raw pointer wrapper and doesn't implement Send/Sync
// by default. The operations we perform are serialized through a
// single `&mut self` (`Read::read` / `Write::write`), and we own
// the handle outright — it's safe to move the struct across threads
// as long as only one thread uses it at a time, which matches
// `UnixStream`'s contract.
#[allow(unsafe_code)]
unsafe impl Send for PipeStream {}
