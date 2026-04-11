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
        .expect("failed to run xcrun");
    let sdk_path = String::from_utf8(sdk_output.stdout)
        .expect("invalid xcrun output")
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
        .expect("failed to run swiftc");

    if !status.success() {
        panic!("swiftc compilation failed");
    }

    // Create static library from object file
    let status = Command::new("ar")
        .args(["rcs"])
        .arg(&lib_path)
        .arg(&obj_path)
        .status()
        .expect("failed to run ar");

    if !status.success() {
        panic!("ar failed to create static library");
    }

    // Find the Swift runtime library path for linking
    let swift_lib_output = Command::new("xcrun")
        .args(["--show-sdk-path", "--sdk", "macosx"])
        .output()
        .expect("failed to find swift lib path");
    let swift_lib_dir = format!(
        "{}/usr/lib/swift",
        String::from_utf8(swift_lib_output.stdout).unwrap().trim()
    );

    // Also need the toolchain's swift lib dir for the runtime
    let toolchain_output = Command::new("xcrun")
        .args(["--find", "swiftc"])
        .output()
        .expect("failed to find swiftc");
    let swiftc_path = String::from_utf8(toolchain_output.stdout)
        .unwrap()
        .trim()
        .to_string();
    let toolchain_lib = PathBuf::from(&swiftc_path)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
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
