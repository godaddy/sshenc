// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

//! Build script for sshenc-ffi-apple.
//! Compiles the Swift CryptoKit bridge into a static library and links it.

use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    // Only build Swift bridge on macOS
    if env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() != "macos" {
        return;
    }

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let swift_src = "swift/sshenc_se_bridge.swift";
    let lib_path = out_dir.join("libsshenc_se_bridge.a");

    let target_arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_else(|_| "arm64".into());
    let swift_target = match target_arch.as_str() {
        "aarch64" => "arm64-apple-macos14.0",
        "x86_64" => "x86_64-apple-macos14.0",
        _ => "arm64-apple-macos14.0",
    };

    // Find the macOS SDK path
    let sdk_output = Command::new("xcrun")
        .args(["--show-sdk-path", "--sdk", "macosx"])
        .output()
        .unwrap_or_else(|e| panic!("failed to run xcrun: {e}"));
    let sdk_path = String::from_utf8(sdk_output.stdout)
        .unwrap_or_else(|e| panic!("invalid xcrun output: {e}"))
        .trim()
        .to_string();

    // Compile Swift to object file
    let obj_path = out_dir.join("sshenc_se_bridge.o");
    let status = Command::new("swiftc")
        .args([
            "-emit-object",
            "-target",
            swift_target,
            "-sdk",
            &sdk_path,
            "-O",
            "-parse-as-library",
            "-o",
        ])
        .arg(&obj_path)
        .arg(swift_src)
        .status()
        .unwrap_or_else(|e| panic!("failed to run swiftc: {e}"));

    if !status.success() {
        panic!("swiftc compilation failed");
    }

    // Create static library from object file
    let status = Command::new("ar")
        .args(["rcs"])
        .arg(&lib_path)
        .arg(&obj_path)
        .status()
        .unwrap_or_else(|e| panic!("failed to run ar: {e}"));

    if !status.success() {
        panic!("ar failed to create static library");
    }

    // Find the Swift runtime library path for linking
    let swift_lib_output = Command::new("xcrun")
        .args(["--show-sdk-path", "--sdk", "macosx"])
        .output()
        .unwrap_or_else(|e| panic!("failed to find swift lib path: {e}"));
    let swift_lib_dir = format!(
        "{}/usr/lib/swift",
        String::from_utf8(swift_lib_output.stdout)
            .unwrap_or_else(|e| panic!("invalid xcrun output for swift lib: {e}"))
            .trim()
    );

    // Also need the toolchain's swift lib dir for the runtime
    let toolchain_output = Command::new("xcrun")
        .args(["--find", "swiftc"])
        .output()
        .unwrap_or_else(|e| panic!("failed to find swiftc: {e}"));
    let swiftc_path = String::from_utf8(toolchain_output.stdout)
        .unwrap_or_else(|e| panic!("invalid xcrun output for swiftc path: {e}"))
        .trim()
        .to_string();
    let swiftc_pb = PathBuf::from(&swiftc_path);
    let toolchain_lib = swiftc_pb
        .parent()
        .and_then(|p| p.parent())
        .unwrap_or_else(|| {
            panic!("unexpected swiftc path structure (expected .../bin/swiftc): {swiftc_path}")
        })
        .join("lib")
        .join("swift")
        .join("macosx");

    // Link directives
    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=sshenc_se_bridge");
    println!("cargo:rustc-link-search=native={swift_lib_dir}");
    println!("cargo:rustc-link-search=native={}", toolchain_lib.display());
    println!("cargo:rustc-link-lib=dylib=swiftCore");
    println!("cargo:rustc-link-lib=dylib=swiftFoundation");
    println!("cargo:rustc-link-lib=framework=CryptoKit");
    println!("cargo:rustc-link-lib=framework=Security");
    println!("cargo:rustc-link-lib=framework=LocalAuthentication");

    println!("cargo:rerun-if-changed={swift_src}");
    println!("cargo:rerun-if-changed=build.rs");
}
