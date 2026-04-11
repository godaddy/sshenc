class Sshenc < Formula
  desc "macOS Secure Enclave-backed SSH key management"
  homepage "https://github.com/jgowdy/sshenc"
  version "0.2.8"
  license "MIT"

  on_arm do
    url "https://github.com/jgowdy/sshenc/releases/download/v0.2.8/sshenc-aarch64-apple-darwin.tar.gz"
    sha256 "2b4eabecb85612a6f9a7a7acc5c8862a64ddbe8e09f1221904d3f8e126b74718"
  end

  on_intel do
    url "https://github.com/jgowdy/sshenc/releases/download/v0.2.8/sshenc-x86_64-apple-darwin.tar.gz"
    sha256 "86c72ee9ce1e1bcc539a3cb5f306d4b4a534430f6c66f9056f8e84d04cf12abe"
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
