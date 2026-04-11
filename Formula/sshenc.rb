class Sshenc < Formula
  desc "macOS Secure Enclave-backed SSH key management"
  homepage "https://github.com/jgowdy/sshenc"
  version "0.2.7"
  license "MIT"

  on_arm do
    url "https://github.com/jgowdy/sshenc/releases/download/v0.2.7/sshenc-aarch64-apple-darwin.tar.gz"
    sha256 "3bcc7cda480b2f0487c50ec3ad57a9435ae0a659a3acd6a0907cdceb3515f45c"
  end

  on_intel do
    url "https://github.com/jgowdy/sshenc/releases/download/v0.2.7/sshenc-x86_64-apple-darwin.tar.gz"
    sha256 "1da72af943aeaa3234644b383284cd95f57b5f6015f3bf23916ebb1f7f7bfd7f"
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
