# sshenc Diagrams

This directory contains text-maintainable architecture diagrams for the
`sshenc` workspace. The diagrams are written in Mermaid so changes can be
reviewed as normal source diffs.

## Diagram Index

- [Workspace context](workspace-context.mmd) - how the `sshenc`, `gitenc`,
  agent, PKCS#11 launcher, libenclaveapp, and platform backends fit together.
- [Architecture diagram](architecture.png) - rendered draw.io architecture
  diagram with embedded source, suitable for Security review artifacts and
  Confluence linking.
- [Data flow diagram](data-flow-diagram.mmd) - Confluence threat-model DFD
  showing external entities, processes, data stores, trust boundaries, and
  labeled SSH/Git/signing flows.
- [Key lifecycle](key-lifecycle-flow.mmd) - generation, metadata, public-key
  cache, signing, and deletion through the agent-backed storage model.
- [SSH agent signing](ssh-agent-signing-flow.mmd) - OpenSSH agent protocol
  requests through `sshenc-agent` into the platform crypto backend.
- [Install and autostart](install-autostart-flow.mmd) - what `sshenc install`
  wires into SSH, shell environments, Windows, and WSL.
- [Platform backend selection](platform-backend-flow.mmd) - high-level backend
  routing through libenclaveapp without zooming into libenclaveapp internals.
- [gitenc repository configuration](gitenc-config-flow.mmd) - `gitenc --config`
  and one-shot `gitenc --label` behavior.
- [Git SSH transport](git-ssh-transport-flow.mmd) - how Git reaches sshenc for
  authentication over SSH.
- [Git commit signing](git-commit-signing-flow.mmd) - Git's SSH signing path
  through `sshenc -Y sign` and `sshenc-agent`.
- [Trust boundaries](trust-boundaries.mmd) - where secrets, public metadata,
  local IPC, and external tools sit relative to the hardware-backed key.

## Rendering

Render any diagram with Mermaid CLI:

```sh
mmdc -i docs/diagrams/workspace-context.mmd -o /tmp/workspace-context.svg
```

On macOS, if Mermaid CLI cannot find its bundled browser, point Puppeteer at
the system Chrome binary:

```sh
printf '{"executablePath":"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome","args":["--no-sandbox"]}\n' >/tmp/puppeteer.json
mmdc -p /tmp/puppeteer.json -i docs/diagrams/workspace-context.mmd -o /tmp/workspace-context.svg
```
