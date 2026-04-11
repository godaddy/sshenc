class Sshenc < Formula
  desc "macOS Secure Enclave-backed SSH key management"
  homepage "https://github.com/jgowdy/sshenc"
  version "0.1.0"
  license "MIT"

  on_arm do
    url "https://github.com/jgowdy/sshenc/releases/download/v0.1.0/sshenc-aarch64-apple-darwin.tar.gz"
    sha256 "59f48400120df56d3ef8865d2de573c57fd4c96fa3829275118992f8e2b2e5c2"
  end

  on_intel do
    url "https://github.com/jgowdy/sshenc/releases/download/v0.1.0/sshenc-x86_64-apple-darwin.tar.gz"
    sha256 "83c198a2c124e99891ad8f92bc5dfcd153a8284a975939c342444b631776663f"
  end

  depends_on :macos

  def install
    bin.install "sshenc"
    bin.install "sshenc-keygen"
    bin.install "sshenc-agent"
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
