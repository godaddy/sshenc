// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! PKCS#11 provider for sshenc.
//!
//! This dynamic library is loaded by OpenSSH via `PKCS11Provider` in
//! `~/.ssh/config`. On first use it starts the sshenc-agent if needed,
//! then proxies all key enumeration and signing through the agent.
//!
//! The agent persists in the background, so passphrases for encrypted
//! legacy keys are only entered once per agent lifetime.
//!
//! ## How it works
//!
//! 1. SSH loads this dylib and calls `C_Initialize`
//! 2. We connect to the sshenc-agent (starting it if needed)
//! 3. `C_FindObjects` asks the agent for identities
//! 4. `C_Sign` asks the agent to sign
//! 5. Agent stays running after SSH exits

mod agent_client;
#[allow(dead_code)]
mod session;
pub mod types;

use agent_client::AgentConnection;
use session::SessionManager;
use sshenc_agent_proto::message::Identity;
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
    agent: AgentConnection,
    /// Cached identities from the agent.
    identities: Vec<Identity>,
    /// Per-session find operation state.
    find_state: Vec<Option<Vec<u64>>>,
    /// Per-session sign operation state: key object handle.
    sign_state: Vec<Option<u64>>,
}

impl ProviderState {
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

    fn identity_for_handle(&self, handle: u64) -> Option<&Identity> {
        if handle == 0 {
            return None;
        }
        let idx = ((handle - 1) / 2) as usize;
        self.identities.get(idx)
    }

    fn is_private_key(handle: u64) -> bool {
        handle >= 1 && (handle % 2) == 1
    }

    fn object_count(&self) -> usize {
        self.identities.len() * 2
    }

    fn is_valid_handle(&self, handle: u64) -> bool {
        handle >= 1 && handle <= self.object_count() as u64
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

    let mut agent = match AgentConnection::connect() {
        Ok(a) => a,
        Err(_) => return CKR_GENERAL_ERROR,
    };

    // Only expose key types that PKCS#11 supports (ECDSA, RSA).
    // Ed25519 keys are not supported by OpenSSH's PKCS#11 implementation
    // and cause "invalid attribute length" errors.
    let all_identities = agent.request_identities().unwrap_or_default();
    let identities: Vec<_> = all_identities
        .into_iter()
        .filter(|id| {
            extract_key_type(&id.key_blob)
                .as_deref()
                .is_some_and(|t| t.contains("ecdsa") || t.contains("rsa"))
        })
        .collect();

    *provider = Some(ProviderState {
        sessions: SessionManager::new(SSHENC_MAX_SESSIONS),
        agent,
        identities,
        find_state: vec![None; SSHENC_MAX_SESSIONS],
        sign_state: vec![None; SSHENC_MAX_SESSIONS],
    });
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
    info.flags = 0x01 | 0x04;
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
    info.flags = 0x0400 | 0x0002;
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

    let mut class_filter: Option<u64> = None;
    if !template.is_null() && count > 0 {
        let attrs = std::slice::from_raw_parts(template, count as usize);
        for attr in attrs {
            if attr.attr_type == CKA_CLASS && attr.value_len >= 8 && !attr.value.is_null() {
                class_filter = Some(std::ptr::read_unaligned(attr.value as *const u64));
            }
        }
    }

    let mut handles = Vec::new();
    for i in 0..state.identities.len() {
        let priv_handle = (i as u64) * 2 + 1;
        let pub_handle = (i as u64) * 2 + 2;
        match class_filter {
            Some(CKO_PRIVATE_KEY) => handles.push(priv_handle),
            Some(CKO_PUBLIC_KEY) => handles.push(pub_handle),
            None => {
                handles.push(priv_handle);
                handles.push(pub_handle);
            }
            _ => {}
        }
    }

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
    if !state.is_valid_handle(object) {
        return CKR_OBJECT_HANDLE_INVALID;
    }

    let identity = match state.identity_for_handle(object) {
        Some(id) => id,
        None => return CKR_OBJECT_HANDLE_INVALID,
    };
    let is_private = ProviderState::is_private_key(object);

    let key_type_str = extract_key_type(&identity.key_blob);
    let is_ec = key_type_str.as_deref().is_some_and(|s| s.contains("ecdsa"));
    let is_rsa = key_type_str.as_deref().is_some_and(|s| s.contains("rsa"));

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
                let val = if is_rsa { CKK_RSA } else { CKK_EC };
                write_attr_value(attr, &val.to_ne_bytes());
            }
            CKA_TOKEN => write_attr_value(attr, &[CK_TRUE]),
            CKA_SIGN => {
                let val = if is_private { CK_TRUE } else { CK_FALSE };
                write_attr_value(attr, &[val]);
            }
            CKA_ID => write_attr_value(attr, identity.comment.as_bytes()),
            CKA_LABEL => write_attr_value(attr, identity.comment.as_bytes()),
            CKA_EC_PARAMS => {
                if is_ec {
                    let params = if key_type_str.as_deref() == Some("ecdsa-sha2-nistp384") {
                        P384_OID_DER
                    } else {
                        P256_OID_DER
                    };
                    write_attr_value(attr, params);
                } else {
                    attr.value_len = 0;
                }
            }
            CKA_EC_POINT => {
                if is_ec {
                    if let Some(point) = extract_ec_point(&identity.key_blob) {
                        let wrapped = der_octet_string(&point);
                        write_attr_value(attr, &wrapped);
                    } else {
                        attr.value_len = 0;
                    }
                } else {
                    attr.value_len = 0;
                }
            }
            CKA_MODULUS => {
                if is_rsa {
                    if let Some((n, _)) = extract_rsa_params(&identity.key_blob) {
                        write_attr_value(attr, &n);
                    } else {
                        attr.value_len = 0;
                    }
                } else {
                    attr.value_len = 0;
                }
            }
            CKA_PUBLIC_EXPONENT => {
                if is_rsa {
                    if let Some((_, e)) = extract_rsa_params(&identity.key_blob) {
                        write_attr_value(attr, &e);
                    } else {
                        attr.value_len = 0;
                    }
                } else {
                    attr.value_len = 0;
                }
            }
            _ => attr.value_len = 0,
        }
    }
    CKR_OK
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
    if !ProviderState::is_private_key(key) || !state.is_valid_handle(key) {
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

    // Extract what we need under the lock, then DROP IT before signing.
    // OpenSSH may call other C_* functions (like C_GetAttributeValue) during
    // the signing flow, which would deadlock if we held the mutex.
    let (key_blob, input_vec) = {
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
        let identity = match state.identity_for_handle(key_handle) {
            Some(id) => id.clone(),
            None => return CKR_OBJECT_HANDLE_INVALID,
        };
        state.sign_state[idx] = None; // single-shot
        (
            identity.key_blob,
            std::slice::from_raw_parts(data, data_len as usize).to_vec(),
        )
    };
    // Mutex is now released

    // Sign via a fresh agent connection
    let sig_blob =
        match AgentConnection::connect().and_then(|mut conn| conn.sign(&key_blob, &input_vec, 0)) {
            Ok(s) => s,
            Err(_) => return CKR_GENERAL_ERROR,
        };

    // Agent returns SSH signature blob: string(algo) + string(inner).
    // For ECDSA, inner = mpint(r) + mpint(s).
    // PKCS#11 expects raw r || s (each zero-padded to 32 bytes for P-256).
    let raw_sig = match extract_ecdsa_rs(&sig_blob) {
        Some(rs) => rs,
        None => {
            // Fallback: try extracting raw bytes for non-ECDSA
            extract_raw_signature(&sig_blob).unwrap_or(sig_blob)
        }
    };

    if signature.is_null() {
        *signature_len = raw_sig.len() as u64;
        return CKR_OK;
    }
    if (*signature_len as usize) < raw_sig.len() {
        *signature_len = raw_sig.len() as u64;
        return CKR_BUFFER_TOO_SMALL;
    }

    std::ptr::copy_nonoverlapping(raw_sig.as_ptr(), signature, raw_sig.len());
    *signature_len = raw_sig.len() as u64;
    CKR_OK
}

// ─── Login stubs ─────────────────────────────────────────────────

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn C_Login(
    _session: u64,
    _user_type: u64,
    _pin: *mut u8,
    _pin_len: u64,
) -> CK_RV {
    CKR_OK
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn C_Logout(_session: u64) -> CK_RV {
    CKR_OK
}

/// # Safety
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
#[no_mangle]
pub unsafe extern "C" fn C_SeedRandom(_session: u64, _seed: *mut u8, _seed_len: u64) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

/// # Safety
#[no_mangle]
pub unsafe extern "C" fn C_GenerateRandom(_session: u64, _data: *mut u8, _len: u64) -> CK_RV {
    CKR_FUNCTION_NOT_SUPPORTED
}

// ─── Function list (PKCS#11 dispatch table) ─────────────────────

/// PKCS#11 function list structure. OpenSSH loads the provider by calling
/// C_GetFunctionList to get this table, then calls functions through it.
#[repr(C)]
pub struct CK_FUNCTION_LIST {
    pub version: types::CK_VERSION,
    // Function pointers — OpenSSH only uses a subset, but we fill in what we have
    // and null the rest. The order matches the PKCS#11 v2.40 spec.
    pub C_Initialize: Option<unsafe extern "C" fn(*mut std::ffi::c_void) -> CK_RV>,
    pub C_Finalize: Option<unsafe extern "C" fn(*mut std::ffi::c_void) -> CK_RV>,
    pub C_GetInfo: Option<unsafe extern "C" fn(*mut types::CK_INFO) -> CK_RV>,
    pub C_GetFunctionList: Option<unsafe extern "C" fn(*mut *const CK_FUNCTION_LIST) -> CK_RV>,
    pub C_GetSlotList: Option<unsafe extern "C" fn(u8, *mut u64, *mut u64) -> CK_RV>,
    pub C_GetSlotInfo: Option<unsafe extern "C" fn(u64, *mut types::CK_SLOT_INFO) -> CK_RV>,
    pub C_GetTokenInfo: Option<unsafe extern "C" fn(u64, *mut types::CK_TOKEN_INFO) -> CK_RV>,
    pub C_GetMechanismList: Option<unsafe extern "C" fn(u64, *mut u64, *mut u64) -> CK_RV>,
    pub C_GetMechanismInfo: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_InitToken: Option<unsafe extern "C" fn() -> CK_RV>,        // stub
    pub C_InitPIN: Option<unsafe extern "C" fn() -> CK_RV>,          // stub
    pub C_SetPIN: Option<unsafe extern "C" fn() -> CK_RV>,           // stub
    pub C_OpenSession: Option<
        unsafe extern "C" fn(
            u64,
            u64,
            *mut std::ffi::c_void,
            *mut std::ffi::c_void,
            *mut u64,
        ) -> CK_RV,
    >,
    pub C_CloseSession: Option<unsafe extern "C" fn(u64) -> CK_RV>,
    pub C_CloseAllSessions: Option<unsafe extern "C" fn(u64) -> CK_RV>,
    pub C_GetSessionInfo: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_GetOperationState: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_SetOperationState: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_Login: Option<unsafe extern "C" fn(u64, u64, *mut u8, u64) -> CK_RV>,
    pub C_Logout: Option<unsafe extern "C" fn(u64) -> CK_RV>,
    pub C_CreateObject: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_CopyObject: Option<unsafe extern "C" fn() -> CK_RV>,   // stub
    pub C_DestroyObject: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_GetObjectSize: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_GetAttributeValue:
        Option<unsafe extern "C" fn(u64, u64, *mut types::CK_ATTRIBUTE, u64) -> CK_RV>,
    pub C_SetAttributeValue: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_FindObjectsInit:
        Option<unsafe extern "C" fn(u64, *mut types::CK_ATTRIBUTE, u64) -> CK_RV>,
    pub C_FindObjects: Option<unsafe extern "C" fn(u64, *mut u64, u64, *mut u64) -> CK_RV>,
    pub C_FindObjectsFinal: Option<unsafe extern "C" fn(u64) -> CK_RV>,
    pub C_EncryptInit: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_Encrypt: Option<unsafe extern "C" fn() -> CK_RV>,     // stub
    pub C_EncryptUpdate: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_EncryptFinal: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_DecryptInit: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_Decrypt: Option<unsafe extern "C" fn() -> CK_RV>,     // stub
    pub C_DecryptUpdate: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_DecryptFinal: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_DigestInit: Option<unsafe extern "C" fn() -> CK_RV>,  // stub
    pub C_Digest: Option<unsafe extern "C" fn() -> CK_RV>,      // stub
    pub C_DigestUpdate: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_DigestKey: Option<unsafe extern "C" fn() -> CK_RV>,   // stub
    pub C_DigestFinal: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_SignInit: Option<unsafe extern "C" fn(u64, *mut types::CK_MECHANISM, u64) -> CK_RV>,
    pub C_Sign: Option<unsafe extern "C" fn(u64, *mut u8, u64, *mut u8, *mut u64) -> CK_RV>,
    pub C_SignUpdate: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_SignFinal: Option<unsafe extern "C" fn() -> CK_RV>,  // stub
    pub C_SignRecoverInit: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_SignRecover: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_VerifyInit: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_Verify: Option<unsafe extern "C" fn() -> CK_RV>,     // stub
    pub C_VerifyUpdate: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_VerifyFinal: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_VerifyRecoverInit: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_VerifyRecover: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_DigestEncryptUpdate: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_DecryptDigestUpdate: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_SignEncryptUpdate: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_DecryptVerifyUpdate: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_GenerateKey: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_GenerateKeyPair: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_WrapKey: Option<unsafe extern "C" fn() -> CK_RV>,    // stub
    pub C_UnwrapKey: Option<unsafe extern "C" fn() -> CK_RV>,  // stub
    pub C_DeriveKey: Option<unsafe extern "C" fn() -> CK_RV>,  // stub
    pub C_SeedRandom: Option<unsafe extern "C" fn(u64, *mut u8, u64) -> CK_RV>,
    pub C_GenerateRandom: Option<unsafe extern "C" fn(u64, *mut u8, u64) -> CK_RV>,
    pub C_GetFunctionStatus: Option<unsafe extern "C" fn() -> CK_RV>, // stub
    pub C_CancelFunction: Option<unsafe extern "C" fn() -> CK_RV>,    // stub
    pub C_WaitForSlotEvent: Option<unsafe extern "C" fn() -> CK_RV>,  // stub
}

static FUNCTION_LIST: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: types::CK_VERSION {
        major: 2,
        minor: 40,
    },
    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: Some(C_GetFunctionList),
    C_GetSlotList: Some(C_GetSlotList),
    C_GetSlotInfo: Some(C_GetSlotInfo),
    C_GetTokenInfo: Some(C_GetTokenInfo),
    C_GetMechanismList: Some(C_GetMechanismList),
    C_GetMechanismInfo: None,
    C_InitToken: None,
    C_InitPIN: None,
    C_SetPIN: None,
    C_OpenSession: Some(C_OpenSession),
    C_CloseSession: Some(C_CloseSession),
    C_CloseAllSessions: Some(C_CloseAllSessions),
    C_GetSessionInfo: None,
    C_GetOperationState: None,
    C_SetOperationState: None,
    C_Login: Some(C_Login),
    C_Logout: Some(C_Logout),
    C_CreateObject: None,
    C_CopyObject: None,
    C_DestroyObject: None,
    C_GetObjectSize: None,
    C_GetAttributeValue: Some(C_GetAttributeValue),
    C_SetAttributeValue: None,
    C_FindObjectsInit: Some(C_FindObjectsInit),
    C_FindObjects: Some(C_FindObjects),
    C_FindObjectsFinal: Some(C_FindObjectsFinal),
    C_EncryptInit: None,
    C_Encrypt: None,
    C_EncryptUpdate: None,
    C_EncryptFinal: None,
    C_DecryptInit: None,
    C_Decrypt: None,
    C_DecryptUpdate: None,
    C_DecryptFinal: None,
    C_DigestInit: None,
    C_Digest: None,
    C_DigestUpdate: None,
    C_DigestKey: None,
    C_DigestFinal: None,
    C_SignInit: Some(C_SignInit),
    C_Sign: Some(C_Sign),
    C_SignUpdate: None,
    C_SignFinal: None,
    C_SignRecoverInit: None,
    C_SignRecover: None,
    C_VerifyInit: None,
    C_Verify: None,
    C_VerifyUpdate: None,
    C_VerifyFinal: None,
    C_VerifyRecoverInit: None,
    C_VerifyRecover: None,
    C_DigestEncryptUpdate: None,
    C_DecryptDigestUpdate: None,
    C_SignEncryptUpdate: None,
    C_DecryptVerifyUpdate: None,
    C_GenerateKey: None,
    C_GenerateKeyPair: None,
    C_WrapKey: None,
    C_UnwrapKey: None,
    C_DeriveKey: None,
    C_SeedRandom: Some(C_SeedRandom),
    C_GenerateRandom: Some(C_GenerateRandom),
    C_GetFunctionStatus: None,
    C_CancelFunction: None,
    C_WaitForSlotEvent: None,
};

/// C_GetFunctionList — the PKCS#11 entry point. OpenSSH calls this first.
///
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

unsafe fn write_attr_value(attr: &mut CK_ATTRIBUTE, data: &[u8]) {
    attr.value_len = data.len() as u64;
    if !attr.value.is_null() {
        std::ptr::copy_nonoverlapping(data.as_ptr(), attr.value, data.len());
    }
}

const P256_OID_DER: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const P384_OID_DER: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];

fn der_octet_string(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + data.len());
    out.push(0x04);
    if data.len() < 128 {
        out.push(data.len() as u8);
    } else if data.len() < 256 {
        out.push(0x81);
        out.push(data.len() as u8);
    } else {
        out.push(0x82);
        out.push((data.len() >> 8) as u8);
        out.push(data.len() as u8);
    }
    out.extend_from_slice(data);
    out
}

fn extract_key_type(blob: &[u8]) -> Option<String> {
    if blob.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([blob[0], blob[1], blob[2], blob[3]]) as usize;
    if blob.len() < 4 + len {
        return None;
    }
    String::from_utf8(blob[4..4 + len].to_vec()).ok()
}

fn extract_ec_point(blob: &[u8]) -> Option<Vec<u8>> {
    let (_, rest) = read_ssh_string(blob)?;
    let (_, rest) = read_ssh_string(rest)?;
    let (point, _) = read_ssh_string(rest)?;
    Some(point.to_vec())
}

fn extract_rsa_params(blob: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let (_, rest) = read_ssh_string(blob)?;
    let (e, rest) = read_ssh_string(rest)?;
    let (n, _) = read_ssh_string(rest)?;
    Some((n.to_vec(), e.to_vec()))
}

fn extract_raw_signature(blob: &[u8]) -> Option<Vec<u8>> {
    let (_, rest) = read_ssh_string(blob)?;
    let (sig, _) = read_ssh_string(rest)?;
    Some(sig.to_vec())
}

fn read_ssh_string(buf: &[u8]) -> Option<(&[u8], &[u8])> {
    if buf.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let buf = &buf[4..];
    if buf.len() < len {
        return None;
    }
    Some((&buf[..len], &buf[len..]))
}

/// Extract ECDSA r and s from an SSH signature blob and return raw r || s.
/// SSH ECDSA sig: string(algo) + string(mpint(r) + mpint(s))
/// PKCS#11 wants: r || s, each zero-padded to 32 bytes (for P-256).
fn extract_ecdsa_rs(blob: &[u8]) -> Option<Vec<u8>> {
    let (algo, rest) = read_ssh_string(blob)?;
    let algo_str = std::str::from_utf8(algo).ok()?;
    if !algo_str.contains("ecdsa") {
        return None;
    }
    let (inner, _) = read_ssh_string(rest)?;

    // inner = mpint(r) + mpint(s)
    let (r_mpint, rest) = read_ssh_string(inner)?;
    let (s_mpint, _) = read_ssh_string(rest)?;

    // Strip leading zeros from mpints and zero-pad to 32 bytes
    let r = normalize_integer(r_mpint, 32);
    let s = normalize_integer(s_mpint, 32);

    let mut result = Vec::with_capacity(64);
    result.extend_from_slice(&r);
    result.extend_from_slice(&s);
    Some(result)
}

/// Normalize a big-endian integer to exactly `size` bytes:
/// strip leading zeros, then left-pad with zeros to `size`.
fn normalize_integer(data: &[u8], size: usize) -> Vec<u8> {
    // Strip leading zeros
    let stripped = data
        .iter()
        .position(|&b| b != 0)
        .map(|i| &data[i..])
        .unwrap_or(&[0]);

    if stripped.len() >= size {
        stripped[stripped.len() - size..].to_vec()
    } else {
        let mut padded = vec![0u8; size - stripped.len()];
        padded.extend_from_slice(stripped);
        padded
    }
}
