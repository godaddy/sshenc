# sshenc Threat Model

By Jay Gowdy

## Review Metadata

| Field | Value |
|---|---|
| Status | NOT STARTED |
| Product Security Engineer | TBD |
| Contributors | Jay Gowdy |
| Jira tickets | TBD |
| Readiness Review | TBD |
| AWS account numbers | N/A. `sshenc` is a local developer CLI/agent and does not own AWS-hosted production infrastructure. |
| Incident Response Sharepoint Link | TBD |
| Cat | TBD |

## Abstract

This threat modeling document gives security considerations for `sshenc` based
on the current architecture and implementation. It covers security assumptions,
security features built into the design, threats and mitigations, external
dependencies, and residual risks accepted by the engineering team.

`sshenc` provides Secure Enclave / TPM-backed SSH key management, a standard SSH
agent, OpenSSH integration, and `gitenc` integration for per-repository SSH
identity and SSH-key commit signing.

## Overview

`sshenc` generates hardware-bound ECDSA P-256 keys and serves them through an
SSH-agent-compatible daemon. Private key material is non-exportable on hardware
backends. `gitenc` configures Git repositories to use selected `sshenc`
identities for SSH transport and SSH commit signing.

| Field | Value |
|---|---|
| Product State | In-Production |
| Application Prod URL | N/A. Local CLI/agent. |
| Application Dev/Test URL | N/A. |
| Source Code | https://github.com/godaddy/sshenc |
| Exposure | Local workstation tool. Not externally hosted. |
| Network zones deployed in | Developer workstations; user-selected SSH/Git destinations. |
| People/groups with access to production servers | N/A. No `sshenc` production servers are operated by this repository. |

## Security Guarantee

`sshenc` aims to provide the following guarantees:

- Hardware-backed SSH private keys cannot be exported from Secure Enclave or
  TPM hardware.
- The SSH agent returns public keys and signatures, never private key material.
- `sshenc-agent` is the sole process that calls platform crypto APIs; CLI
  binaries route write-side operations through the agent.
- Agent sockets and named pipes are owner-restricted.
- Per-key user-presence policies can require Touch ID, Windows Hello/SK, or
  platform UI where supported.
- `gitenc --config` can bind a repository to a chosen hardware-backed key for
  SSH transport and SSH commit signing.
- Traditional file-based SSH keys are not modified and can continue to work
  alongside `sshenc` keys.

The tool is used on developer workstations by OpenSSH, Git, scp, sftp, and Git
commit signing workflows.

Regulatory/legal requirements are inherited from the systems accessed with the
SSH keys. The repository itself does not directly process customer data.

Misuse that must be prevented or bounded:

- Private key extraction from disk, memory, backups, or phishing.
- Silent cross-user use of the local agent.
- Misleading users about which key is hardware-backed.
- Git repository misconfiguration that signs or authenticates with the wrong
  key.
- Windows named-pipe hijack by the Microsoft OpenSSH agent or another process.
- WSL bridge replacement through user-writable paths.

## In-Scope

- Key generation, listing, inspection, deletion, export of public keys, and
  metadata handling.
- `sshenc-agent` SSH agent protocol implementation and local IPC endpoints.
- OpenSSH integration through `IdentityAgent` and PKCS#11 launcher.
- Windows named-pipe, Git Bash, and WSL bridge behavior.
- `gitenc` one-shot and repository configuration behavior.
- SSH commit signing through `sshenc -Y sign`.
- Platform backend selection through `libenclaveapp`.
- Local storage of key handles, metadata, public keys, and trust anchors.

## Out of Scope

- Security of remote SSH servers, GitHub, Git remotes, or OpenSSH itself.
- Kernel, hypervisor, firmware, root/admin compromise, or hardware side-channel
  attacks.
- Availability attacks such as deleting keys, corrupting metadata, killing the
  agent, or blocking prompts.
- SSH agent forwarding to untrusted remote hosts after the user intentionally
  enables forwarding.
- User mistakes when copying public keys to remote services.
- Security of traditional file-based SSH keys outside `sshenc`.
- Build-system and dependency supply-chain compromise beyond repository
  controls.

## Attack assumptions

The following assumptions relate to attackers and their available resources:

- A same-UID local attacker may run code as the developer and can attempt to
  connect to same-user sockets, manipulate environment variables, edit Git
  config, or read public metadata.
- A different local user may attempt to connect to the agent socket or named
  pipe.
- A root/admin attacker can bypass local file permissions, replace binaries,
  attach debuggers, and manipulate agent endpoints.
- A remote attacker may try to phish, steal, or replay SSH private keys.
- A malicious Git repository or local tool may try to alter `gitenc` config or
  signing behavior.
- A WSL attacker may control user-writable Linux paths and environment
  variables.

## Architectural Assumptions

- `sshenc-agent` is the only process that calls platform crypto APIs. CLIs use
  `AgentProxyBackend` and local IPC for generate, sign, delete, and rename.
- Read-only CLI operations may read `.meta` and `.pub` files directly but do not
  touch private key material.
- Hardware-backed private keys are non-exportable on macOS Secure Enclave and
  Windows TPM. Linux TPM protects key material but does not enforce biometric
  presence at sign time.
- Linux software/keyring fallback is intentionally weaker than hardware.
- OpenSSH honors `IdentityAgent` and `PKCS11Provider` according to platform
  support. Git for Windows requires `GIT_SSH_COMMAND` to bypass MINGW SSH for
  named-pipe support.
- macOS live secure-storage testing uses signed installed binaries; unsigned
  local builds must not touch the user's production Keychain/secure-storage
  state.
- `gitenc` writes repository-local Git config; a same-UID attacker who can edit
  that repository config remains in scope as a residual local compromise risk.

## Architectural Diagrams

Relevant diagrams are maintained under:

- Diagram folder: https://github.com/godaddy/sshenc/tree/main/docs/diagrams

Key diagrams for review:

- Architecture diagram (PNG with embedded draw.io source): https://github.com/godaddy/sshenc/blob/main/docs/diagrams/architecture.png
- Data flow diagram: https://github.com/godaddy/sshenc/blob/main/docs/diagrams/data-flow-diagram.mmd
- Workspace context: https://github.com/godaddy/sshenc/blob/main/docs/diagrams/workspace-context.mmd
- Key lifecycle: https://github.com/godaddy/sshenc/blob/main/docs/diagrams/key-lifecycle-flow.mmd
- SSH agent signing: https://github.com/godaddy/sshenc/blob/main/docs/diagrams/ssh-agent-signing-flow.mmd
- Install and autostart: https://github.com/godaddy/sshenc/blob/main/docs/diagrams/install-autostart-flow.mmd
- Platform backend selection: https://github.com/godaddy/sshenc/blob/main/docs/diagrams/platform-backend-flow.mmd
- `gitenc` repository configuration: https://github.com/godaddy/sshenc/blob/main/docs/diagrams/gitenc-config-flow.mmd
- Git SSH transport: https://github.com/godaddy/sshenc/blob/main/docs/diagrams/git-ssh-transport-flow.mmd
- Git commit signing: https://github.com/godaddy/sshenc/blob/main/docs/diagrams/git-commit-signing-flow.mmd
- Trust boundaries: https://github.com/godaddy/sshenc/blob/main/docs/diagrams/trust-boundaries.mmd

Architecture guidance mapping:

| Question | Answer for `sshenc` |
|---|---|
| Hosting location | Developer workstation plus user-selected SSH/Git remotes. No AWS account, region, VPC, subnet, AZ, or datacenter deployment is owned by this repo. |
| Major resources | Local CLI, SSH-agent-compatible daemon, OpenSSH integration, PKCS#11 launcher, Git wrapper, local key metadata/cache files, platform secure storage. |
| Global / region / VPC resources | N/A for this repository. Remote Git/SSH services own their own hosting architecture. |
| Ingress points | Unix socket, Windows named pipe, Windows AF_UNIX compatibility socket. No network-facing listener. |
| Egress points | OpenSSH connections to user-selected SSH/Git remotes; optional HTTPS for install/upgrade distribution flows. |
| Interface protection | Owner-only socket/pipe permissions, Unix peer UID checks, Windows pipe DACL, `allowed_labels`, platform user-presence policy where configured. |
| AuthN/AuthZ methods | SSH public-key protocol, local IPC permissions, platform access policy, Git repository-local config for `gitenc`. |
| Deployment architecture | Installed local CLI/agent model. No hot/hot, hot/warm, or autoscaled hosted service in this repo. |
| Expected traffic | Human developer interactive SSH/Git traffic; request volume is per workstation and generally low. |

## Network ACLs

`sshenc` does not operate hosted servers and does not own AWS security groups,
Illumio policy, iptables rules, or inbound network ACLs. It exposes host-local
IPC only.

### INBOUND FLOWS

| ACL Type | Allow / Block | Source CIDR / hosts | Destination CIDR / hosts | Port(s) | Notes |
|---|---|---|---|---|---|
| Unix socket | Allow | Same OS user | `~/.sshenc/agent.sock` or configured socket path | N/A | Owner-only socket and parent directory on Unix. |
| Windows named pipe | Allow | Current user and SYSTEM | `\\.\pipe\openssh-ssh-agent` | N/A | Explicit DACL restricts access to creator-owner and SYSTEM. |
| AF_UNIX compatibility socket on Windows | Allow | Same OS user | `~/.sshenc/agent.sock` | N/A | Used for Git Bash/MINGW compatibility. |
| Network | Block / N/A | External hosts | Developer workstation | All | No network-facing listener is exposed by `sshenc`. |

### OUTBOUND FLOWS

| ACL Type | Allow / Block | Source CIDR / hosts | Destination CIDR / hosts | Port(s) | Notes |
|---|---|---|---|---|---|
| SSH | Allow | Developer workstation | User-selected SSH servers and Git remotes | TCP/22 or configured SSH port | OpenSSH uses `sshenc-agent` for key signatures. |
| HTTPS | Allow | Developer workstation | GitHub release/package endpoints when installing/upgrading | TCP/443 | Distribution and update paths, not runtime key use. |
| Local stdio / named pipe bridge | Allow | WSL client process | Windows bridge / named pipe | N/A | WSL bridge to Windows TPM or SSH agent. |

## Data Flow Diagram

Primary DFD: https://github.com/godaddy/sshenc/blob/main/docs/diagrams/data-flow-diagram.mmd

Agent signing DFD: https://github.com/godaddy/sshenc/blob/main/docs/diagrams/ssh-agent-signing-flow.mmd

Git commit signing DFD: https://github.com/godaddy/sshenc/blob/main/docs/diagrams/git-commit-signing-flow.mmd

Data processed or transmitted:

| Data type | Processed | Transmitted | Notes |
|---|---|---|---|
| SSH private key material | Yes | No export on hardware backends | Created and used inside Secure Enclave/TPM where supported. |
| SSH public keys | Yes | Yes | Exported to users/remotes; not secret. |
| SSH signing challenges | Yes | Yes | Received from OpenSSH/Git and signed by agent/backend. |
| Key metadata | Yes | Local only | Labels, comments, access policy, git identity, public-key path. |
| Git author identity | Yes | Local Git config | `gitenc` may write `user.name` and `user.email` from key metadata. |
| PII Data | Limited | Limited | Git name/email may be stored in metadata and Git config. No customer PII is intentionally processed. |

## Critical Components

### `sshenc` CLI

Type: process

Use case: User-facing key management, SSH wrapper, install/uninstall, config,
and SSH signing compatibility entry point.

Input: CLI args, local config, key metadata/public files.

Output: Agent RPCs, OpenSSH launches, config edits, public key output.

### `sshenc-agent`

Type: local IPC daemon

Use case: SSH-agent-compatible identity enumeration and signing.

Input: SSH agent protocol frames over Unix socket or Windows named pipe.

Output: Identity lists and SSH-format signatures.

### `sshenc-se`

Type: library/backend boundary

Use case: Implements direct backend in the agent and proxy backend in CLIs.

Input: Generate, sign, delete, rename, list, and inspect requests.

Output: Platform signing operations and key sidecar updates.

### `libenclaveapp`

Type: external library dependency

Use case: Platform backend selection and Secure Enclave/TPM/keyring operations.

Input: Key labels, access policy, signing payloads.

Output: Public keys, signatures, and platform errors.

### `sshenc-pkcs11`

Type: OpenSSH launcher shim

Use case: Starts the agent automatically when OpenSSH loads the configured
PKCS#11 provider.

Input: OpenSSH PKCS#11 load event.

Output: Running `sshenc-agent`.

### `gitenc`

Type: Git wrapper/configurator

Use case: Selects per-repo SSH identity and configures SSH-key commit signing.

Input: Git args, optional label, repository-local Git config.

Output: `GIT_SSH_COMMAND`, repository config entries, and Git subprocess.

## Trust Levels

| Name | Description | Trust details |
|---|---|---|
| Developer | Interactive user running SSH/Git/sshenc | Trusted to select keys, approve prompts, and upload correct public keys. |
| Same-UID local process | Any process running as the developer | Limited trust. Can often reach same-user IPC and edit user config. Hardware user presence is the main defense for prompted keys. |
| Different local user | Another OS account | Not trusted. Socket permissions, peer UID checks, DACLs, and directory permissions should block access. |
| Root/admin | Privileged local actor | Not trusted and out of scope for preventing key use or memory inspection. |
| `sshenc-agent` | Local signing daemon | Trusted boundary for platform crypto calls. |
| OpenSSH / Git | External local tools | Trusted to use configured agent/signing interfaces correctly. |
| `gitenc` | Local Git wrapper | Trusted to write intended repo-local config. |
| `libenclaveapp` | Secure storage/signing dependency | Trusted for platform hardware/keyring operations. |
| Remote SSH/Git server | External endpoint | Not trusted beyond standard SSH protocol verification. |

## External Dependencies

| Name | Type | Use case |
|---|---|---|
| OpenSSH | Local tool/protocol | SSH authentication, agent protocol, scp/sftp, commit signing compatibility. |
| Git | Local tool | SSH transport and SSH-key commit signing. |
| libenclaveapp | Library | Platform Secure Enclave/TPM/keyring signing backend. |
| Apple CryptoKit / Keychain | Platform API | macOS Secure Enclave keys and wrapping/tag storage. |
| Windows CNG / WebAuthn / TPM | Platform API | Windows TPM-backed signing and user presence. |
| Linux TPM / Secret Service | Platform API/service | Linux TPM or keyring/software fallback. |
| npiperelay / socat | Local tools | WSL bridge for SSH agent/named pipe compatibility. |
| GitHub or other Git remote | External service | SSH authentication and commit-signature verification. |

## APIs/Interfaces

| API Endpoint / Interface | Mutating | authN | authZ | External Facing |
|---|---|---|---|---|
| SSH agent `RequestIdentities` | No | Local IPC access | Socket/DACL, allowed labels | No |
| SSH agent `SignRequest` | No | Local IPC access | Socket/DACL, allowed labels, platform prompt policy | No |
| sshenc generate/delete/rename extension RPCs | Yes | Local IPC access | Socket/DACL and CLI policy | No |
| `sshenc -Y sign` compatibility interface | No | Local process invocation | Git config and agent key matching | No |
| `gitenc --config` | Yes | Local process invocation | Repository write permissions | No |
| OpenSSH `IdentityAgent` | No | Local OpenSSH process | SSH config | No |
| PKCS#11 provider load | Yes | OpenSSH load path | Installed library path | No |
| WSL bridge | Yes | Local bridge process | Fixed path / OS permissions | No |

## Authentication / Authorization

`sshenc` does not authenticate users to a web service. It relies on local OS
identity, local IPC permissions, SSH protocol authentication, and platform
hardware/keyring access controls.

Authorization controls include:

- Unix socket parent directory mode 0700 and socket mode 0600.
- Unix peer UID verification where available.
- Windows named pipe DACL granting access to creator-owner and SYSTEM.
- Optional `allowed_labels` to limit exposed keys.
- Platform user-presence/access policy for keys created with non-`None`
  policies.
- Git repository-local config written by `gitenc` for selected identity and
  commit signing.

## Source Code

- Product repository: https://github.com/godaddy/sshenc
- Design: https://github.com/godaddy/sshenc/blob/main/DESIGN.md
- Diagrams: https://github.com/godaddy/sshenc/tree/main/docs/diagrams
- Secure-storage dependency: https://github.com/godaddy/libenclaveapp

## Monitoring/Alerting

`sshenc` is a local CLI/agent and does not operate a central production service
with on-call alerting from this repository.

| Question | Answer |
|---|---|
| Active alerting to on-call? | N/A for the local CLI/agent. |
| OS security logs stored where? | Developer workstation OS policy. |
| Security relevant app logs stored where? | Local agent/CLI logs when debug logging is enabled. |
| Retention | Local workstation policy. |
| Centralized logging | N/A from this repository. |

## Where are secrets / client certs / credentials etc stored?

| Secret / credential | Storage location | Protection |
|---|---|---|
| Hardware SSH private key | Secure Enclave or TPM | Non-exportable on hardware backends. |
| Linux software fallback private key | `~/.sshenc/keys/<label>.handle` or backend-specific file | Encrypted/wrapped by software/keyring backend; weaker than hardware. |
| macOS handle | `~/.sshenc/keys/<label>.handle` | Opaque handle wrapped under Keychain-held key through `libenclaveapp`. |
| Public key bytes | `~/.sshenc/keys/<label>.pub` | Public data; used for lookup and display. |
| OpenSSH public key | `~/.ssh/<label>.pub` or configured path | Public data; uploaded to remote services. |
| Metadata | `~/.sshenc/keys/<label>.meta` | Contains label, comment, access policy, and git identity; protected by metadata integrity mechanisms where implemented. |
| Agent socket / named pipe | `~/.sshenc/agent.sock` or `\\.\pipe\openssh-ssh-agent` | Owner-only socket or restricted pipe DACL. |
| Client certificates | N/A | No client certificates are stored by `sshenc`. |

## Threats (To be filled out by Dev/Eng team and reviewed by Security)

| Threat ID | Threat Description | Affected Resource ID | Mitigated | Mitigation Details | Mitigation Verified |
|---|---|---|---|---|---|
| SSH-T01 | Malware or phishing steals the SSH private key. | Hardware private key | Yes | Hardware backends do not export private key material; agent returns signatures only. | TBD |
| SSH-T02 | Same-UID malware uses the agent to sign. | `sshenc-agent` | Partially | User-presence keys require platform prompt where supported; `AccessPolicy::None` keys remain usable by same-user processes. | TBD |
| SSH-T03 | Different local user connects to agent. | Agent IPC | Yes / Partially | Unix permissions and peer UID checks; Windows named pipe DACL. Windows has less defense in depth than Unix because peer-SID/rate-limit checks are not yet equivalent. | TBD |
| SSH-T04 | Root/admin compromises host and uses keys. | All local resources | No | Privileged compromise is out of scope. Hardware still blocks export but not all key use. | TBD |
| SSH-T05 | Public key substitution causes user to upload attacker's key. | Public key export | Partially | `inspect` and fingerprint output support verification; user must verify before uploading if host is suspect. | TBD |
| SSH-T06 | User confuses software/file keys with hardware-backed keys. | User workflow | Partially | `sshenc list/inspect` show backend; generated configs can use `IdentitiesOnly yes`. Public keys themselves cannot prove hardware origin. | TBD |
| SSH-T07 | Prompt fatigue leads user to approve malicious signing. | User-presence prompt | Partially | Prompt policy is configurable; users can reserve prompted keys for sensitive targets. Platform prompts may not show SSH destination context. | TBD |
| SSH-T08 | Windows named-pipe hijack or Microsoft OpenSSH agent conflict. | Windows named pipe | Yes / Partially | `sshenc install` disables conflicting service where possible; `first_pipe_instance(true)` and restrictive DACL reduce hijack risk. Admin can still replace/hijack. | TBD |
| SSH-T09 | Metadata tamper changes labels, policy display, or git identity. | `.meta` files | Yes / Partially | Platform policy is hardware-bound on macOS/Windows; metadata HMAC/trust anchors detect tamper where implemented. Linux limitations documented. | TBD |
| SSH-T10 | `SSH_AUTH_SOCK` or `IdentityAgent` redirection bypasses `sshenc`. | SSH client config/env | No / Accepted | Same-user config/env tamper can redirect clients to another agent. Users should inspect environment/config for high-risk workflows. | TBD |
| SSH-T11 | `gitenc` config tamper signs with wrong key or verifies against malicious allowed signers. | Git repo config | No / Accepted | Same-UID attacker with repository write access can edit Git config. `gitenc` validates labels/emails when writing but cannot protect later edits. | TBD |
| SSH-T12 | PKCS#11 dylib or agent binary is replaced. | Installed binaries | Partially | Trusted binary discovery avoids PATH search in critical places; recommended distribution uses controlled installers. User-writable install locations remain weaker. | TBD |
| SSH-T13 | WSL bridge response inflation or replacement affects signing. | WSL bridge | Partially | Bridge response size and fixed-path discovery are inherited from `libenclaveapp`; Windows admin replacement remains out of scope. | TBD |
| SSH-T14 | SSH agent forwarding exposes signing oracle on remote host. | Forwarded agent | No / User-controlled | Agent forwarding is a user choice; remote host can request signatures while forwarding is live. | TBD |
