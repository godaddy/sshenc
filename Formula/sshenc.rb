class Sshenc < Formula
  desc "macOS Secure Enclave-backed SSH key management"
  homepage "https://github.com/jgowdy/sshenc"
  version "0.2.5"
  license "MIT"

  on_arm do
    url "https://github.com/jgowdy/sshenc/releases/download/v0.2.5/sshenc-aarch64-apple-darwin.tar.gz"
    sha256 "1a541f354b90ba4adeeb09f9ca2dd6c0f11c138ad609baaeb7c042e47d1ce860"
  end

  on_intel do
    url "https://github.com/jgowdy/sshenc/releases/download/v0.2.5/sshenc-x86_64-apple-darwin.tar.gz"
    sha256 "9f479df6fc41ebe55d36cd9e409b23653e3571532185b53b12109df264b771a0"
  end

  depends_on :macos

  def install
    bin.install "sshenc"
    bin.install "sshenc-keygen"
    bin.install "sshenc-agent"
    bin.install "gitenc"
    lib.install "libsshenc_pkcs11.dylib"
  end

  def caveats
    <<~EOS
      To configure SSH to use sshenc for all connections:

        sshenc install

      The agent starts automatically when SSH needs it.

      To generate a new Secure Enclave key:

        sshenc keygen --label my-key

      To remove the SSH configuration:

        sshenc uninstall
    EOS
  end

  test do
    assert_match "sshenc", shell_output("#{bin}/sshenc --version")
  end
end
