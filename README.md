# vps-secure-init

An interactive Python tool for securely initializing and hardening VPS instances running Ubuntu or Debian.

It combines SSH hardening, per-host credential generation, **1Password-backed credential storage**, UFW, Fail2ban, immutable execution plans, recovery workflows, and audit reports. The project is under active development; review the generated plan and test on a non-production host before using it for critical infrastructure.

## What it does

- Supports Ubuntu 22.04, 24.04, and 26.04, plus Debian 12 and 13.
- Generates a dedicated managed user, password, Ed25519 key pair, key passphrase, and SSH port for every host.
- Keeps an initial password in process memory only and prompts for it with `getpass`.
- Uses 1Password as the system of record for generated long-term credentials.
- Applies staged remote payloads for preflight checks, user bootstrap, SSH hardening, UFW, Fail2ban, and finalization.
- Preserves a rescue SSH route until the new login and firewall configuration have been verified.
- Freezes a hash-verified execution plan before remote changes are made.
- Produces JSON and Markdown audit reports after initialization.

## Requirements

- macOS or another controller system with Python 3.11 or later.
- OpenSSH client tools, including `ssh`, `scp`, and `ssh-keygen`.
- Access to the target VPS using an initial SSH key or password.
- A 1Password account, an existing vault for this project, and the [1Password CLI](https://developer.1password.com/docs/cli/) (`op`) installed and signed in. 1Password is a core dependency of the supported provisioning workflow.

## 1Password is the credential system of record

This project deliberately does not treat the repository, local YAML files, or execution plans as a secret store. For every managed VPS, it generates a separate username, password, SSH key pair, key passphrase, and SSH port. It then uses the `op` CLI to create and retain the long-lived credentials in the selected 1Password vault.

During credential generation, the project creates two linked records in 1Password:

- A native **SSH Key** item containing the private key, public key, fingerprint, key type, and passphrase.
- A **Server** item containing the host address, managed username, managed password, SSH port, local key path, and the linked SSH Key item ID.

The local controller keeps only the minimum non-secret metadata required to resume work: the SSH port, local private-key path, and 1Password item ID. When a recovery workflow needs credentials, it reads only the needed fields from 1Password and never prints their values.

Before running the menu, verify that the CLI can access your account and that the configured vault already exists:

```bash
op account list
```

Set `onepassword_vault` in your local `config/policy.yaml` to that vault's name. The example policy uses `VPS`. If `op` is missing, signed out, locked, or cannot access the vault, credential generation stops rather than falling back to an insecure local secret store.

## Quick start

```bash
git clone git@github.com:YOUR_ACCOUNT/vps-secure-init.git
cd vps-secure-init

python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .

cp config/hosts.example.yaml config/hosts.yaml
cp config/policy.example.yaml config/policy.yaml
# Set onepassword_vault in config/policy.yaml, then verify the session.
op account list
vpsctl --menu
```

Edit `config/hosts.yaml` locally before starting. It is intentionally ignored by Git.

```yaml
hosts:
  - id: example-vps
    address: 203.0.113.11 # Documentation-only address; replace locally.
    initial_port: 22
    initial_user: root
    initial_auth: key
    initial_key: ~/.ssh/your_provider_key
    platform: auto
    profile: standard
```

The interactive menu lets you inspect hosts, adjust a single host's permitted settings, generate credentials, preview and freeze an execution plan, initialize a host, and run an audit.

## Security model

The controller is designed to keep secrets out of repository files and persistent execution artifacts:

- Passwords and private-key passphrases are not written to `hosts.yaml`, plans, state files, or reports.
- `config/credentials.json` contains only non-secret references such as a port, private-key path, and 1Password item ID; it is local-only and ignored by Git.
- Generated private keys are stored under the local SSH directory and uploaded to 1Password as separate SSH Key items.
- 1Password vault access is required to retrieve managed credentials during recovery; it is not replaced by a plaintext backup in this repository.
- Plans contain credential references and hashes, never passwords, private keys, or passphrases.
- Reports use masked addresses by default and reject secret-bearing fields.

Do not add real hosts, policy files, credentials, state, logs, reports, private keys, certificates, `.env` files, or password-manager exports to Git.

## Configuration

Use the versioned example files as starting points:

- [`config/hosts.example.yaml`](config/hosts.example.yaml) defines the inventory format.
- [`config/policy.example.yaml`](config/policy.example.yaml) defines the global policy, supported platforms, profiles, firewall rules, and report settings.

The supplied policy provides `standard` and `web` profiles. Host-level overrides are validated and limited to credential, SSH, firewall, Fail2ban, and sudo settings.

## Safety notes

- Verify cloud-provider security groups and recovery-console access independently; the tool cannot fully validate external cloud firewall policy.
- Review the plan before confirming it. A frozen plan is tied to the target host, payload hashes, and resolved policy.
- Keep a tested backup and out-of-band recovery route for every production VPS.
- Rotate credentials immediately if they are ever committed, copied into an issue, or exposed in a log.

## Testing

```bash
pytest -q
```
