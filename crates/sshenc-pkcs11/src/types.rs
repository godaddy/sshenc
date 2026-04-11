// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! PKCS#11 C type definitions.
//!
//! These mirror the PKCS#11 v2.40 C header types needed for our provider.

#![allow(non_camel_case_types, dead_code)]

/// PKCS#11 version structure.
#[repr(C)]
pub struct CK_VERSION {
    pub major: u8,
    pub minor: u8,
}

/// CK_INFO — General library information.
#[repr(C)]
pub struct CK_INFO {
    pub cryptoki_version: CK_VERSION,
    pub manufacturer_id: [u8; 32],
    pub flags: u64,
    pub library_description: [u8; 32],
    pub library_version: CK_VERSION,
}

/// CK_SLOT_INFO — Slot information.
#[repr(C)]
pub struct CK_SLOT_INFO {
    pub slot_description: [u8; 64],
    pub manufacturer_id: [u8; 32],
    pub flags: u64,
    pub hardware_version: CK_VERSION,
    pub firmware_version: CK_VERSION,
}

/// CK_TOKEN_INFO — Token information.
#[repr(C)]
pub struct CK_TOKEN_INFO {
    pub label: [u8; 32],
    pub manufacturer_id: [u8; 32],
    pub model: [u8; 16],
    pub serial_number: [u8; 16],
    pub flags: u64,
    pub max_session_count: u64,
    pub session_count: u64,
    pub max_rw_session_count: u64,
    pub rw_session_count: u64,
    pub max_pin_len: u64,
    pub min_pin_len: u64,
    pub total_public_memory: u64,
    pub free_public_memory: u64,
    pub total_private_memory: u64,
    pub free_private_memory: u64,
    pub hardware_version: CK_VERSION,
    pub firmware_version: CK_VERSION,
    pub utc_time: [u8; 16],
}

/// CK_ATTRIBUTE — Object attribute.
#[repr(C)]
#[derive(Debug)]
pub struct CK_ATTRIBUTE {
    pub attr_type: u64,
    pub value: *mut u8,
    pub value_len: u64,
}

/// CK_MECHANISM — Mechanism specification.
#[repr(C)]
pub struct CK_MECHANISM {
    pub mechanism: u64,
    pub parameter: *mut u8,
    pub parameter_len: u64,
}

// Object classes
pub const CKO_PUBLIC_KEY: u64 = 0x02;
pub const CKO_PRIVATE_KEY: u64 = 0x03;

// Key types
pub const CKK_EC: u64 = 0x03;
pub const CKK_RSA: u64 = 0x00;

// Attribute types
pub const CKA_CLASS: u64 = 0x00;
pub const CKA_TOKEN: u64 = 0x01;
pub const CKA_PRIVATE: u64 = 0x02;
pub const CKA_LABEL: u64 = 0x03;
pub const CKA_KEY_TYPE: u64 = 0x100;
pub const CKA_ID: u64 = 0x102;
pub const CKA_SIGN: u64 = 0x108;
pub const CKA_MODULUS: u64 = 0x120;
pub const CKA_PUBLIC_EXPONENT: u64 = 0x122;
pub const CKA_EC_PARAMS: u64 = 0x180;
pub const CKA_EC_POINT: u64 = 0x181;

// Mechanism types
pub const CKM_ECDSA: u64 = 0x1041;
pub const CKM_RSA_PKCS: u64 = 0x01;

// Boolean values
pub const CK_TRUE: u8 = 1;
pub const CK_FALSE: u8 = 0;
