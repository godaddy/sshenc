class Sshenc < Formula
  desc "macOS Secure Enclave-backed SSH key management"
  homepage "https://github.com/jgowdy/sshenc"
  version "0.2.3"
  license "MIT"

  on_arm do
    url "https://github.com/jgowdy/sshenc/releases/download/v0.2.3/sshenc-aarch64-apple-darwin.tar.gz"
    sha256 "24bb348a22d3f0f0c14729ea307016992c34ee17f3e5c4370f3883b0ed27fdb1"
  end

  on_intel do
    url "https://github.com/jgowdy/sshenc/releases/download/v0.2.3/sshenc-x86_64-apple-darwin.tar.gz"
    sha256 "f5be25c4afcef6844ae8f63889530fb96064115412cce967067433fa5a1b4c51"
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
