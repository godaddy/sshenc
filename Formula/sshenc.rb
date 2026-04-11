class Sshenc < Formula
  desc "macOS Secure Enclave-backed SSH key management"
  homepage "https://github.com/jgowdy/sshenc"
  version "0.2.4"
  license "MIT"

  on_arm do
    url "https://github.com/jgowdy/sshenc/releases/download/v0.2.4/sshenc-aarch64-apple-darwin.tar.gz"
    sha256 "d030006555293e72e9863cd205c5f679f47b82a883805568a7cd2c4b7a994ef7"
  end

  on_intel do
    url "https://github.com/jgowdy/sshenc/releases/download/v0.2.4/sshenc-x86_64-apple-darwin.tar.gz"
    sha256 "999776fc8270d21e26e75e28bdb1c064bba3aad7142c5697b6505b23d474f282"
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
