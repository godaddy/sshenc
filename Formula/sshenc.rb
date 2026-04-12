class Sshenc < Formula
  desc "macOS Secure Enclave-backed SSH key management"
  homepage "https://github.com/jgowdy/sshenc"
  version "0.3.0"
  license "MIT"

  on_arm do
    url "https://github.com/jgowdy/sshenc/releases/download/v0.3.0/sshenc-aarch64-apple-darwin.tar.gz"
    sha256 "95cd294487c2c64984bafd512c250b6ef18150fb1a2f02c93fe3eac975ad921c"
  end

  on_intel do
    url "https://github.com/jgowdy/sshenc/releases/download/v0.3.0/sshenc-x86_64-apple-darwin.tar.gz"
    sha256 "5f6b9514ab0ad8d3b81df03c48543e3434796cbe08895e4c74c3c5ec4a1c1dd9"
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
