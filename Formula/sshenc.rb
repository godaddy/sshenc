class Sshenc < Formula
  desc "macOS Secure Enclave-backed SSH key management"
  homepage "https://github.com/jgowdy/sshenc"
  version "0.2.6"
  license "MIT"

  on_arm do
    url "https://github.com/jgowdy/sshenc/releases/download/v0.2.6/sshenc-aarch64-apple-darwin.tar.gz"
    sha256 "3828969d3f975d04023769220ef585da85d356f1058ab14fef423020f0d4ad6d"
  end

  on_intel do
    url "https://github.com/jgowdy/sshenc/releases/download/v0.2.6/sshenc-x86_64-apple-darwin.tar.gz"
    sha256 "5ee99c7067dafdb831715c3573363a128243928dc89f8e7c4ebb744cc025045f"
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
