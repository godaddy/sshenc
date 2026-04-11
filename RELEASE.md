# Release Checklist

## Pre-release

- [ ] All tests pass: `cargo test --workspace`
- [ ] Clippy clean: `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] Format clean: `cargo fmt --all -- --check`
- [ ] Update version in `Cargo.toml` workspace section
- [ ] Update `CHANGELOG.md` (if maintained)
- [ ] Update Homebrew formula SHA256 hash and version URL
- [ ] Test `make install` on a clean system
- [ ] Test `sshenc install` / `sshenc uninstall` roundtrip
- [ ] Test key generation and signing with Secure Enclave hardware
- [ ] Test legacy key loading (encrypted and unencrypted)
- [ ] Test PKCS#11 provider via `ssh -v` with `PKCS11Provider`

## Release

- [ ] Create and push git tag: `git tag v0.x.x && git push --tags`
- [ ] Create GitHub release with notes
- [ ] Attach release binaries (sshenc, sshenc-keygen, sshenc-agent, libsshenc_pkcs11.dylib)
- [ ] Update Homebrew formula with release tarball SHA256

## Post-release

- [ ] Verify `brew install` works from tap
- [ ] Verify `make install` works from release tarball

## Release Notes Template

```
## vX.Y.Z

### Added
- 

### Changed
- 

### Fixed
- 

### Removed
- 
```
