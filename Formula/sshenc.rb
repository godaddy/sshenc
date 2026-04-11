class Sshenc < Formula
  desc "macOS Secure Enclave-backed SSH key management"
  homepage "https://github.com/jgowdy/sshenc"
  version "0.2.1"
  license "MIT"

  on_arm do
    url "https://github.com/jgowdy/sshenc/releases/download/v0.2.1/sshenc-aarch64-apple-darwin.tar.gz"
    sha256 "d0fcf5ce0f673884848aa4d75f88652e732f9184f6f0ad1073231f95648130bb"
  end

  on_intel do
    url "https://github.com/jgowdy/sshenc/releases/download/v0.2.1/sshenc-x86_64-apple-darwin.tar.gz"
    sha256 "28bfb48220311ff7300115dd95388df3ab82010df5d8d6d8597476b4ce47b610"
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
