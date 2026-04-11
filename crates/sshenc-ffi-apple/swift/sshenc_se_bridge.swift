// Copyright 2024 Jay Gowdy
// SPDX-License-Identifier: MIT

// CryptoKit Secure Enclave bridge for sshenc.
//
// Exposes C functions callable from Rust for SE key lifecycle:
// - Generate a new P-256 key
// - Load a key from its persisted data representation
// - Extract the public key (raw X/Y coordinates)
// - Sign data
//
// Keys are persisted via CryptoKit's dataRepresentation, which is an opaque
// blob containing a handle to the SE key. The actual private key material
// never leaves the Secure Enclave.

import CryptoKit
import Foundation

// MARK: - Result codes

let SE_OK: Int32 = 0
let SE_ERR_GENERATE: Int32 = 1
let SE_ERR_LOAD: Int32 = 2
let SE_ERR_SIGN: Int32 = 3
let SE_ERR_BUFFER_TOO_SMALL: Int32 = 4
let SE_ERR_NOT_AVAILABLE: Int32 = 5

// MARK: - Check availability

@_cdecl("sshenc_se_available")
public func sshenc_se_available() -> Int32 {
    return SecureEnclave.isAvailable ? 1 : 0
}

// MARK: - Generate key

/// Generate a new Secure Enclave P-256 key.
/// Returns the data representation (opaque blob for persistence) and raw public key.
///
/// - pub_key_out: buffer for 65-byte uncompressed public key (0x04 || X || Y)
/// - pub_key_len: in/out, must be >= 65
/// - data_rep_out: buffer for data representation
/// - data_rep_len: in/out, must be large enough (typically ~300 bytes)
@_cdecl("sshenc_se_generate")
public func sshenc_se_generate(
    _ pub_key_out: UnsafeMutablePointer<UInt8>,
    _ pub_key_len: UnsafeMutablePointer<Int32>,
    _ data_rep_out: UnsafeMutablePointer<UInt8>,
    _ data_rep_len: UnsafeMutablePointer<Int32>
) -> Int32 {
    guard SecureEnclave.isAvailable else {
        return SE_ERR_NOT_AVAILABLE
    }

    do {
        let key = try SecureEnclave.P256.Signing.PrivateKey()

        // Public key: CryptoKit gives raw 64-byte (X || Y), we need uncompressed 65-byte (0x04 || X || Y)
        let rawPub = key.publicKey.rawRepresentation
        let uncompressedLen: Int32 = 65
        if pub_key_len.pointee < uncompressedLen {
            pub_key_len.pointee = uncompressedLen
            return SE_ERR_BUFFER_TOO_SMALL
        }
        pub_key_out[0] = 0x04
        rawPub.copyBytes(to: pub_key_out + 1, count: 64)
        pub_key_len.pointee = uncompressedLen

        // Data representation for persistence
        let dataRep = key.dataRepresentation
        let dataRepCount = Int32(dataRep.count)
        if data_rep_len.pointee < dataRepCount {
            data_rep_len.pointee = dataRepCount
            return SE_ERR_BUFFER_TOO_SMALL
        }
        dataRep.copyBytes(to: data_rep_out, count: dataRep.count)
        data_rep_len.pointee = dataRepCount

        return SE_OK
    } catch {
        return SE_ERR_GENERATE
    }
}

// MARK: - Get public key from data representation

/// Extract the public key from a persisted data representation.
///
/// - data_rep: the persisted data representation bytes
/// - data_rep_len: length of data_rep
/// - pub_key_out: buffer for 65-byte uncompressed public key
/// - pub_key_len: in/out, must be >= 65
@_cdecl("sshenc_se_public_key")
public func sshenc_se_public_key(
    _ data_rep: UnsafePointer<UInt8>,
    _ data_rep_len: Int32,
    _ pub_key_out: UnsafeMutablePointer<UInt8>,
    _ pub_key_len: UnsafeMutablePointer<Int32>
) -> Int32 {
    do {
        let data = Data(bytes: data_rep, count: Int(data_rep_len))
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: data)

        let rawPub = key.publicKey.rawRepresentation
        let uncompressedLen: Int32 = 65
        if pub_key_len.pointee < uncompressedLen {
            pub_key_len.pointee = uncompressedLen
            return SE_ERR_BUFFER_TOO_SMALL
        }
        pub_key_out[0] = 0x04
        rawPub.copyBytes(to: pub_key_out + 1, count: 64)
        pub_key_len.pointee = uncompressedLen

        return SE_OK
    } catch {
        return SE_ERR_LOAD
    }
}

// MARK: - Sign (message - hashes internally)

/// Sign a message using a key loaded from its data representation.
/// CryptoKit hashes the message with SHA-256 internally.
/// Returns a DER-encoded ECDSA signature.
///
/// - data_rep: the persisted data representation bytes
/// - data_rep_len: length of data_rep
/// - message: data to sign
/// - message_len: length of message
/// - sig_out: buffer for DER-encoded signature
/// - sig_len: in/out, should be >= 72 (max DER ECDSA sig for P-256)
@_cdecl("sshenc_se_sign")
public func sshenc_se_sign(
    _ data_rep: UnsafePointer<UInt8>,
    _ data_rep_len: Int32,
    _ message: UnsafePointer<UInt8>,
    _ message_len: Int32,
    _ sig_out: UnsafeMutablePointer<UInt8>,
    _ sig_len: UnsafeMutablePointer<Int32>
) -> Int32 {
    do {
        let keyData = Data(bytes: data_rep, count: Int(data_rep_len))
        let key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: keyData)

        let msgData = Data(bytes: message, count: Int(message_len))
        let signature = try key.signature(for: msgData)

        // Return DER-encoded signature
        let derSig = signature.derRepresentation
        let derCount = Int32(derSig.count)
        if sig_len.pointee < derCount {
            sig_len.pointee = derCount
            return SE_ERR_BUFFER_TOO_SMALL
        }
        derSig.copyBytes(to: sig_out, count: derSig.count)
        sig_len.pointee = derCount

        return SE_OK
    } catch {
        return SE_ERR_SIGN
    }
}

