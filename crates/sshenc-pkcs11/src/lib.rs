// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! PKCS#11 provider for sshenc.
//!
//! Exposes Secure Enclave keys and legacy SSH keys from `~/.ssh/` to
//! applications via the PKCS#11 interface. OpenSSH loads this as a
//! dynamic library via `PKCS11Provider` in `~/.ssh/config`.
//!
//! ## How OpenSSH uses PKCS#11
//!
//! 1. `C_Initialize` → init the library
//! 2. `C_GetSlotList` → get slot IDs
//! 3. `C_GetTokenInfo` → check the token
//! 4. `C_OpenSession` → open a session
//! 5. `C_FindObjectsInit` / `C_FindObjects` / `C_FindObjectsFinal` → enumerate keys
//! 6. `C_GetAttributeValue` → read public key attributes (key type, EC params, EC point, modulus, exponent)
//! 7. `C_SignInit` + `C_Sign` → sign authentication challenges
//! 8. `C_CloseSession` → cleanup
//!
//! ## Object model
//!
//! Each key produces two PKCS#11 objects: a private key (odd handle) and
//! a public key (even handle). Handles are: key_index * 2 + 1 (private),
//! key_index * 2 + 2 (public).

mod keystore;
#[allow(dead_code)]
mod session;
pub mod types;

use keystore::KeyStore;
use session::SessionManager;
use std::sync::Mutex;
use types::*;

/// PKCS#11 return value type.
#[allow(non_camel_case_types)]
pub type CK_RV = u64;

// PKCS#11 return codes
pub const CKR_OK: CK_RV = 0x00000000;
pub const CKR_SLOT_ID_INVALID: CK_RV = 0x00000003;
pub const CKR_GENERAL_ERROR: CK_RV = 0x00000005;
pub const CKR_ARGUMENTS_BAD: CK_RV = 0x00000007;
pub const CKR_FUNCTION_NOT_SUPPORTED: CK_RV = 0x00000054;
pub const CKR_OBJECT_HANDLE_INVALID: CK_RV = 0x00000082;
pub const CKR_OPERATION_NOT_INITIALIZED: CK_RV = 0x00000091;
pub const CKR_BUFFER_TOO_SMALL: CK_RV = 0x00000150;
pub const CKR_CRYPTOKI_NOT_INITIALIZED: CK_RV = 0x00000190;
pub const CKR_CRYPTOKI_ALREADY_INITIALIZED: CK_RV = 0x00000191;
pub const CKR_SESSION_HANDLE_INVALID: CK_RV = 0x000000B3;

const SSHENC_SLOT_ID: u64 = 0;
const SSHENC_MAX_SESSIONS: usize = 16;

/// Global provider state.
static PROVIDER: Mutex<Option<ProviderState>> = Mutex::new(None);

struct ProviderState {
    sessions: SessionManager,
    keys: KeyStore,
    /// Per-session find operation state: list of matching handles to return.
    find_state: Vec<Option<Vec<u64>>>,
    /// Per-session sign operation state: (key_handle, mechanism).
    sign_state: Vec<Option<u64>>,
}

impl ProviderState {
    fn new() -> Self {
        let keys = keystore::load_keys();
        ProviderState {
            sessions: SessionManager::new(SSHENC_MAX_SESSIONS),
            keys,
            find_state: vec![None; SSHENC_MAX_SESSIONS],
            sign_state: vec![None; SSHENC_MAX_SESSIONS],
        }
    }

    fn session_idx(&self, handle: u64) -> Option<usize> {
        let idx = handle as usize;
        if idx == 0 || idx > SSHENC_MAX_SESSIONS {
            return None;
        }
        if self.sessions.is_valid(handle) {
            Some(idx - 1)
        } else {
            None
        }
    }
}

// ─── Library lifecycle ───────────────────────────────────────────

/// # Safety
/// Called from C code via PKCS#11 interface.
#[no_mangle]
pub unsafe extern "C" fn C_Initialize(_init_args: *mut std::ffi::c_void) -> CK_RV {
    let mut provider = match PROVIDER.lock() {
        Ok(p) => p,
        Err(_) => return CKR_GENERAL_ERROR,
    };
    if provider.is_some() {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    *provider = Some(ProviderState::new());
    CKR_OK
}

/// # Safety
/// Called from C code via PKCS#11 interface.
#[no_mangle]
pub unsafe extern "C" fn C_Finalize(_reserved: *mut std::ffi::c_void) -> CK_RV {
    let mut provider = match PROVIDER.lock() {
        Ok(p) => p,
        Err(_) => return CKR_GENERAL_ERROR,
    };
    if provider.is_none() {
        return CKR_CRYPTOKI_NOT_INITIALIZED;
    }
    *provider = None;
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
    copy_padded(
        &mut info.library_description,
        b"sshenc Secure Enclave PKCS#11",
    );
    info.library_version.major = 0;
    info.library_version.minor = 1;
    CKR_OK
}

/// # Safety
/// Called from C code via PKCS#11 interface.
#[no_mangle]
pub unsafe extern "C" fn C_GetSlotList(
    _token_present: u8,
    slot_list: *mut u64,
    count: *mut u64,
) -> CK_RV {
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if slot_list.is_null() {
        *count = 1;
        return CKR_OK;
    }
    if *count < 1 {
        *count = 1;
        return CKR_BUFFER_TOO_SMALL;
    }
    *slot_list = SSHENC_SLOT_ID;
    *count = 1;
    CKR_OK
}

/// # Safety
/// Called from C code via PKCS#11 interface.
#[no_mangle]
pub unsafe extern "C" fn C_GetSlotInfo(slot_id: u64, info: *mut CK_SLOT_INFO) -> CK_RV {
    if slot_id != SSHENC_SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let info = &mut *info;
    copy_padded(&mut info.slot_description, b"macOS Secure Enclave");
    copy_padded(&mut info.manufacturer_id, b"Apple");
    info.flags = 0x01 | 0x04; // CKF_TOKEN_PRESENT | CKF_HW_SLOT
    info.hardware_version.major = 1;
    info.hardware_version.minor = 0;
    info.firmware_version.major = 1;
    info.firmware_version.minor = 0;
    CKR_OK
}

/// # Safety
/// Called from C code via PKCS#11 interface.
#[no_mangle]
pub unsafe extern "C" fn C_GetTokenInfo(slot_id: u64, info: *mut CK_TOKEN_INFO) -> CK_RV {
    if slot_id != SSHENC_SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    if info.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let info = &mut *info;
    copy_padded(&mut info.label, b"sshenc Secure Enclave");
    copy_padded(&mut info.manufacturer_id, b"Apple");
    copy_padded(&mut info.model, b"Secure Enclave");
    copy_padded(&mut info.serial_number, b"0001");
    info.flags = 0x0400 | 0x0002; // CKF_TOKEN_INITIALIZED | CKF_WRITE_PROTECTED
    info.max_session_count = SSHENC_MAX_SESSIONS as u64;
    info.session_count = 0;
    info.max_rw_session_count = 0;
    info.rw_session_count = 0;
    info.max_pin_len = 0;
    info.min_pin_len = 0;
    info.total_public_memory = u64::MAX;
    info.free_public_memory = u64::MAX;
    info.total_private_memory = u64::MAX;
    info.free_private_memory = u64::MAX;
    info.hardware_version.major = 1;
    info.hardware_version.minor = 0;
    info.firmware_version.major = 1;
    info.firmware_version.minor = 0;
    copy_padded(&mut info.utc_time, b"                ");
    CKR_OK
}

// ─── Session management ──────────────────────────────────────────

/// # Safety
/// Called from C code via PKCS#11 interface.
#[no_mangle]
pub unsafe extern "C" fn C_OpenSession(
    slot_id: u64,
    _flags: u64,
    _application: *mut std::ffi::c_void,
    _notify: *mut std::ffi::c_void,
    session_handle: *mut u64,
) -> CK_RV {
    if slot_id != SSHENC_SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    if session_handle.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut provider = match PROVIDER.lock() {
        Ok(p) => p,
        Err(_) => return CKR_GENERAL_ERROR,
    };
    let state = match provider.as_mut() {
        Some(s) => s,
        None => return CKR_CRYPTOKI_NOT_INITIALIZED,
    };
    match state.sessions.open() {
        Some(handle) => {
            *session_handle = handle;
            CKR_OK
        }
        None => CKR_GENERAL_ERROR,
    }
}

/// # Safety
/// Called from C code via PKCS#11 interface.
#[no_mangle]
pub unsafe extern "C" fn C_CloseSession(session_handle: u64) -> CK_RV {
    let mut provider = match PROVIDER.lock() {
        Ok(p) => p,
        Err(_) => return CKR_GENERAL_ERROR,
    };
    let state = match provider.as_mut() {
        Some(s) => s,
        None => return CKR_CRYPTOKI_NOT_INITIALIZED,
    };
    if let Some(idx) = state.session_idx(session_handle) {
        state.find_state[idx] = None;
        state.sign_state[idx] = None;
    }
    if state.sessions.close(session_handle) {
        CKR_OK
    } else {
        CKR_SESSION_HANDLE_INVALID
    }
}

/// # Safety
/// Called from C code via PKCS#11 interface.
#[no_mangle]
pub unsafe extern "C" fn C_CloseAllSessions(slot_id: u64) -> CK_RV {
    if slot_id != SSHENC_SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    let mut provider = match PROVIDER.lock() {
        Ok(p) => p,
        Err(_) => return CKR_GENERAL_ERROR,
    };
    let state = match provider.as_mut() {
        Some(s) => s,
        None => return CKR_CRYPTOKI_NOT_INITIALIZED,
    };
    state.sessions.close_all();
    state.find_state.fill(None);
    state.sign_state.fill(None);
    CKR_OK
}

// ─── Object search ───────────────────────────────────────────────

/// # Safety
/// Called from C code via PKCS#11 interface.
#[no_mangle]
pub unsafe extern "C" fn C_FindObjectsInit(
    session_handle: u64,
    template: *mut CK_ATTRIBUTE,
    count: u64,
) -> CK_RV {
    let mut provider = match PROVIDER.lock() {
        Ok(p) => p,
        Err(_) => return CKR_GENERAL_ERROR,
    };
    let state = match provider.as_mut() {
        Some(s) => s,
        None => return CKR_CRYPTOKI_NOT_INITIALIZED,
    };
    let idx = match state.session_idx(session_handle) {
        Some(i) => i,
        None => return CKR_SESSION_HANDLE_INVALID,
    };

    // Parse template to find class filter
    let mut class_filter: Option<u64> = None;
    if !template.is_null() && count > 0 {
        let attrs = std::slice::from_raw_parts(template, count as usize);
        for attr in attrs {
            if attr.attr_type == CKA_CLASS && attr.value_len >= 8 && !attr.value.is_null() {
                class_filter = Some(std::ptr::read_unaligned(attr.value as *const u64));
            }
        }
    }

    let handles = state.keys.find_objects(class_filter);
    state.find_state[idx] = Some(handles);
    CKR_OK
}

/// # Safety
/// Called from C code via PKCS#11 interface.
#[no_mangle]
pub unsafe extern "C" fn C_FindObjects(
    session_handle: u64,
    objects: *mut u64,
    max_count: u64,
    count: *mut u64,
) -> CK_RV {
    if objects.is_null() || count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let mut provider = match PROVIDER.lock() {
        Ok(p) => p,
        Err(_) => return CKR_GENERAL_ERROR,
    };
    let state = match provider.as_mut() {
        Some(s) => s,
        None => return CKR_CRYPTOKI_NOT_INITIALIZED,
    };
    let idx = match state.session_idx(session_handle) {
        Some(i) => i,
        None => return CKR_SESSION_HANDLE_INVALID,
    };

    let handles = match state.find_state[idx].as_mut() {
        Some(h) => h,
        None => return CKR_OPERATION_NOT_INITIALIZED,
    };

    let to_return = std::cmp::min(max_count as usize, handles.len());
    let returned: Vec<u64> = handles.drain(..to_return).collect();

    for (i, &h) in returned.iter().enumerate() {
        *objects.add(i) = h;
    }
    *count = returned.len() as u64;

    CKR_OK
}

/// # Safety
/// Called from C code via PKCS#11 interface.
#[no_mangle]
pub unsafe extern "C" fn C_FindObjectsFinal(session_handle: u64) -> CK_RV {
    let mut provider = match PROVIDER.lock() {
        Ok(p) => p,
        Err(_) => return CKR_GENERAL_ERROR,
    };
    let state = match provider.as_mut() {
        Some(s) => s,
        None => return CKR_CRYPTOKI_NOT_INITIALIZED,
    };
    let idx = match state.session_idx(session_handle) {
        Some(i) => i,
        None => return CKR_SESSION_HANDLE_INVALID,
    };
    state.find_state[idx] = None;
    CKR_OK
}

// ─── Attribute queries ───────────────────────────────────────────

/// # Safety
/// Called from C code via PKCS#11 interface.
#[no_mangle]
pub unsafe extern "C" fn C_GetAttributeValue(
    session_handle: u64,
    object: u64,
    template: *mut CK_ATTRIBUTE,
    count: u64,
) -> CK_RV {
    if template.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    let provider = match PROVIDER.lock() {
        Ok(p) => p,
        Err(_) => return CKR_GENERAL_ERROR,
    };
    let state = match provider.as_ref() {
        Some(s) => s,
        None => return CKR_CRYPTOKI_NOT_INITIALIZED,
    };
    if state.session_idx(session_handle).is_none() {
        return CKR_SESSION_HANDLE_INVALID;
    }

    let key = match state.keys.key_for_handle(object) {
        Some(k) => k,
        None => return CKR_OBJECT_HANDLE_INVALID,
    };

    let is_private = state.keys.is_private_key(object);
    let attrs = std::slice::from_raw_parts_mut(template, count as usize);

    for attr in attrs.iter_mut() {
        match attr.attr_type {
            CKA_CLASS => {
                let val = if is_private {
                    CKO_PRIVATE_KEY
                } else {
                    CKO_PUBLIC_KEY
                };
                write_attr_value(attr, &val.to_ne_bytes());
            }
            CKA_KEY_TYPE => {
                let val = key.key_type();
                write_attr_value(attr, &val.to_ne_bytes());
            }
            CKA_TOKEN => {
                write_attr_value(attr, &[CK_TRUE]);
            }
            CKA_SIGN => {
                let val = if is_private { CK_TRUE } else { CK_FALSE };
                write_attr_value(attr, &[val]);
            }
            CKA_ID => {
                let id = key.key_id();
                write_attr_value(attr, &id);
            }
            CKA_LABEL => {
                let label = key.label().as_bytes();
                write_attr_value(attr, label);
            }
            CKA_EC_PARAMS => {
                if let Some(params) = key.ec_params_der() {
                    write_attr_value(attr, &params);
                } else {
                    attr.value_len = u64::MAX; // attribute not available
                }
            }
            CKA_EC_POINT => {
                if let Some(point) = key.ec_point_der() {
                    write_attr_value(attr, &point);
                } else {
                    attr.value_len = u64::MAX;
                }
            }
            CKA_MODULUS => {
                if let Some((modulus, _)) = key.rsa_params() {
                    write_attr_value(attr, &modulus);
                } else {
                    attr.value_len = u64::MAX;
                }
            }
            CKA_PUBLIC_EXPONENT => {
                if let Some((_, exponent)) = key.rsa_params() {
                    write_attr_value(attr, &exponent);
                } else {
                    attr.value_len = u64::MAX;
                }
            }
            _ => {
                attr.value_len = u64::MAX; // attribute not available
            }
        }
    }

    CKR_OK
}

/// Write data into a CK_ATTRIBUTE value buffer.
/// If value is null, just set value_len (size query).
/// If buffer is too small, set value_len and return.
unsafe fn write_attr_value(attr: &mut CK_ATTRIBUTE, data: &[u8]) {
    attr.value_len = data.len() as u64;
    if !attr.value.is_null() {
        std::ptr::copy_nonoverlapping(data.as_ptr(), attr.value, data.len());
    }
}

// ─── Signing ─────────────────────────────────────────────────────

/// # Safety
/// Called from C code via PKCS#11 interface.
#[no_mangle]
pub unsafe extern "C" fn C_SignInit(
    session_handle: u64,
    _mechanism: *mut CK_MECHANISM,
    key: u64,
) -> CK_RV {
    let mut provider = match PROVIDER.lock() {
        Ok(p) => p,
        Err(_) => return CKR_GENERAL_ERROR,
    };
    let state = match provider.as_mut() {
        Some(s) => s,
        None => return CKR_CRYPTOKI_NOT_INITIALIZED,
    };
    let idx = match state.session_idx(session_handle) {
        Some(i) => i,
        None => return CKR_SESSION_HANDLE_INVALID,
    };

    // Must be a private key handle
    if !state.keys.is_private_key(key) {
        return CKR_OBJECT_HANDLE_INVALID;
    }
    if state.keys.key_for_handle(key).is_none() {
        return CKR_OBJECT_HANDLE_INVALID;
    }

    state.sign_state[idx] = Some(key);
    CKR_OK
}

/// # Safety
/// Called from C code via PKCS#11 interface.
#[no_mangle]
pub unsafe extern "C" fn C_Sign(
    session_handle: u64,
    data: *mut u8,
    data_len: u64,
    signature: *mut u8,
    signature_len: *mut u64,
) -> CK_RV {
    if data.is_null() || signature_len.is_null() {
        return CKR_ARGUMENTS_BAD;
    }

    let mut provider = match PROVIDER.lock() {
        Ok(p) => p,
        Err(_) => return CKR_GENERAL_ERROR,
    };
    let state = match provider.as_mut() {
        Some(s) => s,
        None => return CKR_CRYPTOKI_NOT_INITIALIZED,
    };
    let idx = match state.session_idx(session_handle) {
        Some(i) => i,
        None => return CKR_SESSION_HANDLE_INVALID,
    };

    let key_handle = match state.sign_state[idx] {
        Some(h) => h,
        None => return CKR_OPERATION_NOT_INITIALIZED,
    };

    let key = match state.keys.key_for_handle(key_handle) {
        Some(k) => k,
        None => return CKR_OBJECT_HANDLE_INVALID,
    };

    let input = std::slice::from_raw_parts(data, data_len as usize);

    let sig_bytes = match key.sign(input) {
        Ok(s) => s,
        Err(_) => return CKR_GENERAL_ERROR,
    };

    // Size query: if signature is null, return required length
    if signature.is_null() {
        *signature_len = sig_bytes.len() as u64;
        return CKR_OK;
    }

    if (*signature_len as usize) < sig_bytes.len() {
        *signature_len = sig_bytes.len() as u64;
        return CKR_BUFFER_TOO_SMALL;
    }

    std::ptr::copy_nonoverlapping(sig_bytes.as_ptr(), signature, sig_bytes.len());
    *signature_len = sig_bytes.len() as u64;

    // Clear sign state (single-shot operation)
    state.sign_state[idx] = None;

    CKR_OK
}

// ─── Login stubs (no PIN needed) ─────────────────────────────────

/// # Safety
/// Called from C code via PKCS#11 interface.
#[no_mangle]
pub unsafe extern "C" fn C_Login(
    _session: u64,
    _user_type: u64,
    _pin: *mut u8,
    _pin_len: u64,
) -> CK_RV {
    // No authentication needed — SE uses biometric, legacy keys are unencrypted
    CKR_OK
}

/// # Safety
/// Called from C code via PKCS#11 interface.
#[no_mangle]
pub unsafe extern "C" fn C_Logout(_session: u64) -> CK_RV {
    CKR_OK
}

// ─── Unsupported stubs ───────────────────────────────────────────

/// # Safety
/// Called from C code via PKCS#11 interface.
#[no_mangle]
pub unsafe extern "C" fn C_GetMechanismList(
    slot_id: u64,
    mechanism_list: *mut u64,
    count: *mut u64,
) -> CK_RV {
    if slot_id != SSHENC_SLOT_ID {
        return CKR_SLOT_ID_INVALID;
    }
    if count.is_null() {
        return CKR_ARGUMENTS_BAD;
    }
    if mechanism_list.is_null() {
        *count = 2;
        return CKR_OK;
    }
    if *count < 2 {
        *count = 2;
        return CKR_BUFFER_TOO_SMALL;
    }
    *mechanism_list = CKM_ECDSA;
    *mechanism_list.add(1) = CKM_RSA_PKCS;
    *count = 2;
    CKR_OK
}

/// # Safety
/// Called from C code via PKCS#11 interface.
#[no_mangle]
pub unsafe extern "C" fn C_SeedRandom(_session: u64, _seed: *mut u8, _seed_len: u64) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// # Safety
/// Called from C code via PKCS#11 interface.
#[no_mangle]
pub unsafe extern "C" fn C_GenerateRandom(_session: u64, _data: *mut u8, _len: u64) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// ─── Helpers ─────────────────────────────────────────────────────

/// Copy bytes into a fixed-size padded buffer (space-padded, no null terminator).
fn copy_padded(dest: &mut [u8], src: &[u8]) {
    dest.fill(b' ');
    let len = src.len().min(dest.len());
    dest[..len].copy_from_slice(&src[..len]);
}
