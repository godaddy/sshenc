PREFIX ?= /usr/local
BINDIR = $(PREFIX)/bin
LIBDIR = $(PREFIX)/lib

BINS = sshenc sshenc-keygen sshenc-agent
DYLIB = libsshenc_pkcs11.dylib

.PHONY: build install uninstall clean

build:
	cargo build --workspace --release

install: build
	install -d $(BINDIR) $(LIBDIR)
	install -m 755 target/release/sshenc $(BINDIR)/sshenc
	install -m 755 target/release/sshenc-keygen $(BINDIR)/sshenc-keygen
	install -m 755 target/release/sshenc-agent $(BINDIR)/sshenc-agent
	install -m 644 target/release/$(DYLIB) $(LIBDIR)/$(DYLIB)
	@echo ""
	@echo "Installed:"
	@echo "  $(BINDIR)/sshenc"
	@echo "  $(BINDIR)/sshenc-keygen"
	@echo "  $(BINDIR)/sshenc-agent"
	@echo "  $(LIBDIR)/$(DYLIB)"
	@echo ""
	@echo "Run 'sshenc install' to configure SSH to use sshenc."

uninstall:
	rm -f $(BINDIR)/sshenc
	rm -f $(BINDIR)/sshenc-keygen
	rm -f $(BINDIR)/sshenc-agent
	rm -f $(LIBDIR)/$(DYLIB)
	@echo "Uninstalled sshenc binaries and library."
	@echo "Run 'sshenc uninstall' first if you haven't already (to clean ~/.ssh/config)."

clean:
	cargo clean
