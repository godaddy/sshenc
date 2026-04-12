// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Minimal PKCS#11 C type definitions for the launcher dylib.

#![allow(non_camel_case_types, dead_code)]

#[repr(C)]
#[derive(Debug)]
pub struct CK_VERSION {
    pub major: u8,
    pub minor: u8,
}

#[repr(C)]
#[derive(Debug)]
pub struct CK_INFO {
    pub cryptoki_version: CK_VERSION,
    pub manufacturer_id: [u8; 32],
    pub flags: u64,
    pub library_description: [u8; 32],
    pub library_version: CK_VERSION,
}
