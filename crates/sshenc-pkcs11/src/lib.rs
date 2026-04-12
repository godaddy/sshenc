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
//! ```text
//! Host *
//!     PKCS11Provider /path/to/libsshenc_pkcs11.dylib
//!     IdentityAgent ~/.sshenc/agent.sock
//! ```
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
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Initialize(_init_args: *mut std::ffi::c_void) -> CK_RV {
    if INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }

    // Start the agent if it's not running. We don't care if this fails —
    // the agent might already be running, or it'll be started another way.
    drop(agent_client::ensure_agent_running());

    CKR_OK
}

/// # Safety
/// Called from C code via PKCS#11 interface.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn C_Finalize(_reserved: *mut std::ffi::c_void) -> CK_RV {
    if !INITIALIZED.swap(false, Ordering::SeqCst) {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    CKR_OK
}

// ─── Info functions ──────────────────────────────────────────────

/// # Safety
/// Called from C code via PKCS#11 interface.
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
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
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
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
#[allow(non_snake_case, dead_code, unsafe_code, missing_debug_implementations)]
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

#[allow(unsafe_code)]
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
#[allow(unsafe_code)]
#[unsafe(no_mangle)]
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, unsafe_code)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Serialize all PKCS#11 tests since they share global INITIALIZED state.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Reset the global INITIALIZED state so each test starts fresh.
    fn reset_state() {
        INITIALIZED.store(false, Ordering::SeqCst);
    }

    #[test]
    #[cfg_attr(miri, ignore)] // C_Initialize calls dirs::home_dir() -> FFI
    fn c_initialize_succeeds_first_time() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_state();

        // Safety: calling PKCS#11 C functions in a test context with a null pointer.
        let rv = unsafe { C_Initialize(std::ptr::null_mut()) };
        assert_eq!(rv, CKR_OK);

        // Cleanup
        unsafe { C_Finalize(std::ptr::null_mut()) };
    }

    #[test]
    #[cfg_attr(miri, ignore)] // C_Initialize calls dirs::home_dir() -> FFI
    fn c_initialize_second_time_returns_already_initialized() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_state();

        // Safety: calling PKCS#11 C functions in test context.
        unsafe {
            let rv = C_Initialize(std::ptr::null_mut());
            assert_eq!(rv, CKR_OK);

            let rv2 = C_Initialize(std::ptr::null_mut());
            assert_eq!(rv2, CKR_CRYPTOKI_ALREADY_INITIALIZED);

            C_Finalize(std::ptr::null_mut());
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)] // C_Initialize calls dirs::home_dir() -> FFI
    fn c_finalize_succeeds_after_initialize() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_state();

        // Safety: calling PKCS#11 C functions in test context.
        unsafe {
            C_Initialize(std::ptr::null_mut());
            let rv = C_Finalize(std::ptr::null_mut());
            assert_eq!(rv, CKR_OK);
        }
    }

    #[test]
    fn c_finalize_without_initialize_returns_not_initialized() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_state();

        // Safety: calling PKCS#11 C functions in test context.
        let rv = unsafe { C_Finalize(std::ptr::null_mut()) };
        assert_eq!(rv, CKR_CRYPTOKI_NOT_INITIALIZED);
    }

    #[test]
    fn c_get_info_fills_fields() {
        let _guard = TEST_LOCK.lock().unwrap();
        reset_state();

        let mut info = CK_INFO {
            cryptoki_version: CK_VERSION { major: 0, minor: 0 },
            manufacturer_id: [0_u8; 32],
            flags: 99,
            library_description: [0_u8; 32],
            library_version: CK_VERSION { major: 0, minor: 0 },
        };

        // Safety: calling C_GetInfo with a valid pointer to our stack-allocated struct.
        let rv = unsafe { C_GetInfo(&mut info) };
        assert_eq!(rv, CKR_OK);
        assert_eq!(info.cryptoki_version.major, 2);
        assert_eq!(info.cryptoki_version.minor, 40);
        assert_eq!(info.flags, 0);
        assert_eq!(info.library_version.major, 0);
        assert_eq!(info.library_version.minor, 1);

        // manufacturer_id should start with "sshenc" padded with spaces
        let mfr = String::from_utf8_lossy(&info.manufacturer_id);
        assert!(
            mfr.starts_with("sshenc"),
            "expected manufacturer_id to start with 'sshenc', got: {mfr}"
        );

        // library_description should start with "sshenc agent launcher"
        let desc = String::from_utf8_lossy(&info.library_description);
        assert!(
            desc.starts_with("sshenc agent launcher"),
            "expected library_description to start with 'sshenc agent launcher', got: {desc}"
        );
    }

    #[test]
    fn c_get_info_null_pointer_returns_bad_args() {
        let _guard = TEST_LOCK.lock().unwrap();

        // Safety: testing null pointer handling.
        let rv = unsafe { C_GetInfo(std::ptr::null_mut()) };
        assert_eq!(rv, CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn c_get_slot_list_returns_zero_slots() {
        let _guard = TEST_LOCK.lock().unwrap();

        let mut count: u64 = 42;
        // Safety: calling C_GetSlotList with valid pointer.
        let rv = unsafe { C_GetSlotList(0, std::ptr::null_mut(), &mut count) };
        assert_eq!(rv, CKR_OK);
        assert_eq!(count, 0);
    }

    #[test]
    fn c_get_slot_list_null_count_returns_bad_args() {
        let _guard = TEST_LOCK.lock().unwrap();

        // Safety: testing null pointer handling.
        let rv = unsafe { C_GetSlotList(0, std::ptr::null_mut(), std::ptr::null_mut()) };
        assert_eq!(rv, CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn c_get_function_list_returns_valid_pointer() {
        let _guard = TEST_LOCK.lock().unwrap();

        let mut func_list: *const CK_FUNCTION_LIST = std::ptr::null();
        // Safety: calling C_GetFunctionList with a valid pointer to our pointer variable.
        let rv = unsafe { C_GetFunctionList(&mut func_list) };
        assert_eq!(rv, CKR_OK);
        assert!(!func_list.is_null());

        // Verify function list has expected version
        // Safety: we just verified the pointer is non-null.
        let fl = unsafe { &*func_list };
        assert_eq!(fl.version.major, 2);
        assert_eq!(fl.version.minor, 40);

        // Verify function pointers are set
        assert!(fl.C_Initialize.is_some());
        assert!(fl.C_Finalize.is_some());
        assert!(fl.C_GetInfo.is_some());
        assert!(fl.C_GetFunctionList.is_some());
        assert!(fl.C_GetSlotList.is_some());
    }

    #[test]
    fn c_get_function_list_null_pointer_returns_bad_args() {
        let _guard = TEST_LOCK.lock().unwrap();

        // Safety: testing null pointer handling.
        let rv = unsafe { C_GetFunctionList(std::ptr::null_mut()) };
        assert_eq!(rv, CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn copy_padded_short_source() {
        let mut dest = [0_u8; 10];
        copy_padded(&mut dest, b"abc");
        assert_eq!(&dest, b"abc       ");
    }

    #[test]
    fn copy_padded_exact_fit() {
        let mut dest = [0_u8; 5];
        copy_padded(&mut dest, b"hello");
        assert_eq!(&dest, b"hello");
    }

    #[test]
    fn copy_padded_source_longer_than_dest() {
        let mut dest = [0_u8; 3];
        copy_padded(&mut dest, b"hello world");
        assert_eq!(&dest, b"hel");
    }

    #[test]
    fn copy_padded_empty_source() {
        let mut dest = [0_u8; 5];
        copy_padded(&mut dest, b"");
        assert_eq!(&dest, b"     ");
    }
}
