class Sshenc < Formula
  desc "macOS Secure Enclave-backed SSH key management"
  homepage "https://github.com/jgowdy/sshenc"
  version "0.2.0"
  license "MIT"

  on_arm do
    url "https://github.com/jgowdy/sshenc/releases/download/v0.2.0/sshenc-aarch64-apple-darwin.tar.gz"
    sha256 "91c26ad41982885ce130f9d283661432b1549707d9b49840100c1882b4ff56f9"
  end

  on_intel do
    url "https://github.com/jgowdy/sshenc/releases/download/v0.2.0/sshenc-x86_64-apple-darwin.tar.gz"
    sha256 "514c05fe6999b71f73b98bd0a64d128a3eb2195447594ee102e73023220fb084"
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
