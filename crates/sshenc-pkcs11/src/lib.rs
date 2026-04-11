// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! PKCS#11 agent launcher for sshenc.
//!
//! This dynamic library exists solely to start the sshenc-agent when SSH
//! loads it. It reports zero keys through PKCS#11 — all actual key serving
//! and signing happens through the agent via IdentityAgent.
//!
//! In ~/.ssh/config, both entries work together:
//!
//!     Host *
//!         PKCS11Provider /path/to/libsshenc_pkcs11.dylib
//!         IdentityAgent ~/.sshenc/agent.sock
//!
//! SSH loads the dylib first (starting the agent), then talks to the
//! agent for authentication. The dylib is just a boot hook.

mod agent_client;
pub mod types;

use types::*;

/// PKCS#11 return value type.
#[allow(non_camel_case_types)]
pub type CK_RV = u64;

pub const CKR_OK: CK_RV = 0x00000000;
pub const CKR_SLOT_ID_INVALID: CK_RV = 0x00000003;
pub const CKR_GENERAL_ERROR: CK_RV = 0x00000005;
pub const CKR_ARGUMENTS_BAD: CK_RV = 0x00000007;
pub const CKR_FUNCTION_NOT_SUPPORTED: CK_RV = 0x00000054;
pub const CKR_BUFFER_TOO_SMALL: CK_RV = 0x00000150;
pub const CKR_CRYPTOKI_NOT_INITIALIZED: CK_RV = 0x00000190;
pub const CKR_CRYPTOKI_ALREADY_INITIALIZED: CK_RV = 0x00000191;

use std::sync::atomic::{AtomicBool, Ordering};

static INITIALIZED: AtomicBool = AtomicBool::new(false);

// ─── Library lifecycle ───────────────────────────────────────────

/// # Safety
/// Called from C code via PKCS#11 interface.
#[no_mangle]
pub unsafe extern "C" fn C_Initialize(_init_args: *mut std::ffi::c_void) -> CK_RV {
    if INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }

    // Start the agent if it's not running. We don't care if this fails —
    // the agent might already be running, or it'll be started another way.
    let _ = agent_client::ensure_agent_running();

    CKR_OK
}

/// # Safety
/// Called from C code via PKCS#11 interface.
#[no_mangle]
pub unsafe extern "C" fn C_Finalize(_reserved: *mut std::ffi::c_void) -> CK_RV {
    if !INITIALIZED.swap(false, Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    CKR_OK
}

// ─── Info functions ──────────────────────────────────────────────

/// # Safety
/// Called from C code via PKCS#11 interface.
#[no_mangle]
pub unsafe extern "C" fn C_GetInfo(info: *mut CK_INFO) -> CK_RV {
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let info = &mut *info;
    info.cryptoki_version.major = 2;
    info.cryptoki_version.minor = 40;
    copy_padded(&mut info.manufacturer_id, b"sshenc");
    info.flags = 0;
    copy_padded(&mut info.library_description, b"sshenc agent launcher");
    info.library_version.major = 0;
    info.library_version.minor = 1;
    CKR_OK
}

/// Report 0 slots — we don't serve keys, just launch the agent.
///
/// # Safety
/// Called from C code via PKCS#11 interface.
#[no_mangle]
pub unsafe extern "C" fn C_GetSlotList(
    _token_present: u8,
    _slot_list: *mut u64,
    count: *mut u64,
) -> CK_RV {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    *count = 0;
    CKR_OK
}

// ─── Function list ───────────────────────────────────────────────

/// PKCS#11 function list. OpenSSH requires C_GetFunctionList as the entry point.
#[repr(C)]
#[allow(non_snake_case, dead_code)]
pub struct CK_FUNCTION_LIST {
    pub version: CK_VERSION,
    pub C_Initialize: Option<unsafe extern "C" fn(*mut std::ffi::c_void) -> CK_RV>,
    pub C_Finalize: Option<unsafe extern "C" fn(*mut std::ffi::c_void) -> CK_RV>,
    pub C_GetInfo: Option<unsafe extern "C" fn(*mut CK_INFO) -> CK_RV>,
    pub C_GetFunctionList: Option<unsafe extern "C" fn(*mut *const CK_FUNCTION_LIST) -> CK_RV>,
    pub C_GetSlotList: Option<unsafe extern "C" fn(u8, *mut u64, *mut u64) -> CK_RV>,
    // All remaining function pointers are NULL — we only need the above.
    _padding: [Option<unsafe extern "C" fn() -> CK_RV>; 63],
}

static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION {
        major: 2,
        minor: 40,
    },
    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(C_GetSlotList),
    _padding: [None; 63],
};

/// # Safety
/// Called from C code via PKCS#11 interface.
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(
    pp_function_list: *mut *const CK_FUNCTION_LIST,
) -> CK_RV {
    if pp_function_list.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    *pp_function_list = &FUNCTION_LIST;
    CKR_OK
}

// ─── Helpers ─────────────────────────────────────────────────────

fn copy_padded(dest: &mut [u8], src: &[u8]) {
    dest.fill(b' ');
    let len = src.len().min(dest.len());
    dest[..len].copy_from_slice(&src[..len]);
}
