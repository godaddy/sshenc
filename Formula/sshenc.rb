class Sshenc < Formula
  desc "macOS Secure Enclave-backed SSH key management"
  homepage "https://github.com/jgowdy/sshenc"
  version "0.1.0"
  license "MIT"

  on_arm do
    url "https://github.com/jgowdy/sshenc/releases/download/v0.1.0/sshenc-aarch64-apple-darwin.tar.gz"
    sha256 "beac65cdb377e8031adb87d68f77ef570e88eb9a0feab8d7fa0264784f75d8b4"
  end

  on_intel do
    url "https://github.com/jgowdy/sshenc/releases/download/v0.1.0/sshenc-x86_64-apple-darwin.tar.gz"
    sha256 "9b0abf767b2d42ddd7035f722ef4fd52f09b74ee2ccb0fc6e2784b71c6420b70"
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
