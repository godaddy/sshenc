class Sshenc < Formula
  desc "macOS Secure Enclave-backed SSH key management"
  homepage "https://github.com/jgowdy/sshenc"
  version "0.2.2"
  license "MIT"

  on_arm do
    url "https://github.com/jgowdy/sshenc/releases/download/v0.2.2/sshenc-aarch64-apple-darwin.tar.gz"
    sha256 "0c85327bacbbc21a95769ad113030ff0b1fca0d9a4331e231f4a3dbd47faa3d2"
  end

  on_intel do
    url "https://github.com/jgowdy/sshenc/releases/download/v0.2.2/sshenc-x86_64-apple-darwin.tar.gz"
    sha256 "997f3a06e2330b6bda2013b37c20cec5a93493dadbf10adf0eaa3422ffe44c45"
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
