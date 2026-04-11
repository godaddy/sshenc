class Sshenc < Formula
  desc "macOS Secure Enclave-backed SSH key management"
  homepage "https://github.com/jgowdy/sshenc"
  url "https://github.com/jgowdy/sshenc/archive/refs/tags/v0.1.0.tar.gz"
  sha256 "PLACEHOLDER"
  license "MIT"

  depends_on :macos
  depends_on "rust" => :build

  def install
    system "cargo", "build", "--workspace", "--release"
    bin.install "target/release/sshenc"
    bin.install "target/release/sshenc-keygen"
    bin.install "target/release/sshenc-agent"
    lib.install "target/release/libsshenc_pkcs11.dylib"
  end

  def caveats
    <<~EOS
      To configure SSH to use sshenc for all connections:

        sshenc install

      This adds a PKCS11Provider entry to ~/.ssh/config. No daemon needed —
      SSH loads the sshenc library on demand.

      To generate a new Secure Enclave key:

        sshenc keygen --label my-key -C "you@host"

      To remove the SSH configuration:

        sshenc uninstall
    EOS
  end

  test do
    assert_match "sshenc", shell_output("#{bin}/sshenc --version")
  end
end
