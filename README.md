# aifence

[![PyPI](https://img.shields.io/pypi/v/aifence)](https://pypi.org/project/aifence/)
[![Python](https://img.shields.io/pypi/pyversions/aifence)](https://pypi.org/project/aifence/)
[![Downloads](https://img.shields.io/pypi/dm/aifence)](https://pypistats.org/packages/aifence)
[![License](https://img.shields.io/pypi/l/aifence)](https://github.com/Crack525/aifence/blob/main/LICENSE)

Two kinds of secret leakage happen in AI coding sessions:

1. **File reads** — the AI tool reads your `.env`, SSH keys, or credentials from disk
2. **Prompt leakage** — you accidentally paste a token into the chat

**aifence** blocks both.

![Before and after aifence init](visuals/problem-solution.excalidraw.png)

```shell
$ aifence init

Scanning for sensitive files...
  Found: .env, config/secrets.yaml, certs/server.pem, .npmrc

  Claude Code (detected):
    ✓ permissions.deny — 26 Read rules added
    ✓ sandbox.denyRead — 26 patterns added
    ⚠ Sandbox not enabled — run /sandbox in Claude Code for OS-level Bash protection

  Cursor (detected):
    ✓ .cursorignore — 26 patterns added

  Copilot (not detected):
    ✓ .copilotignore — 26 patterns added

$ aifence prompt-guard install

Installing prompt-guard hooks (global: ~/.claude/settings.json) ...
  ✓ Hooks installed: UserPromptSubmit, PreToolUse, PostToolUse
```

## Install

```shell
pipx install aifence
```

Or with pip:

```shell
pip install aifence
```

## Usage

```shell
# Protect your workspace files from AI file reads
aifence init

# Protect your Claude Code prompts from accidental secret leakage
aifence prompt-guard install

# Audit only — no files modified
aifence scan
```

---

## Part 1 — File protection (`aifence init`)

### The problem

AI coding tools can read any file your user account can access. Most developers have `.env` files, SSH keys, and credentials sitting in their project directories.

- **Claude Code** can read files via its Read tool *and* via `cat .env` in Bash
- **Cursor** indexes files for AI context automatically
- **Copilot** Agent mode runs shell commands with full file access
- **Gemini CLI** has no file access restrictions at all

### What's generated

| Tool | What's generated | Protection level |
|---|---|---|
| **Claude Code** | `permissions.deny` (Read rules) + `sandbox.filesystem.denyRead` | Full — OS-level when sandbox enabled |
| **Cursor** | `.cursorignore` | Partial — blocks AI reads, not shell |
| **Copilot** | `.copilotignore` | Partial — completions only, not Agent mode |
| **Windsurf** | `.windsurfignore` | Partial — enforcement depth unverified |
| **Gemini CLI** | Nothing | None — no mechanism exists |

### Claude Code: the full picture

Claude Code is the only tool with OS-level protection via its sandbox. aifence generates two layers:

1. **`permissions.deny`** — blocks the Read tool from accessing sensitive files
2. **`sandbox.filesystem.denyRead`** — blocks *all* processes (including `cat`, `grep`, `python`) from reading those files at the OS level (Seatbelt on macOS, bubblewrap on Linux)

> Enable the sandbox yourself: run `/sandbox` in Claude Code. aifence adds the rules; enabling is your decision.

### Default protected patterns

```
.env, .env.*, *.pem, *.key, *.p12, *.pfx, *.jks, *.keystore,
credentials, credentials.*, secrets.json, secrets.yaml, secrets.yml,
.secrets, .npmrc, .pypirc, id_rsa, id_ed25519, id_ecdsa,
service-account*.json, *.tfvars, *.tfvars.json, kubeconfig,
.netrc, token.json, .htpasswd
```

---

## Part 2 — Prompt guard (`aifence prompt-guard`)

### The problem

Even with file protection in place, a single accidental paste — a `.env` dump into the chat, a `curl` command with a live Bearer token, a stack trace containing a Stripe key — sends credentials directly to the AI provider's servers.

### How it works

`aifence prompt-guard install` wires three Claude Code hooks that run **before any data leaves your machine**:

| Hook | What it does |
|---|---|
| `UserPromptSubmit` | Scans every prompt. Blocks and asks you to resubmit if a secret is found. |
| `PreToolUse` | Redacts secrets from tool inputs (Bash commands, file writes, web fetches) before execution. The tool still runs — with `[REDACTED:aws-access-key]` in place of the real value. |
| `PostToolUse` | Warns Claude not to repeat secrets that appeared in tool output (e.g. `aws configure list`). |

### What gets detected

| Detector | Examples caught |
|---|---|
| `aws-access-key` | `AKIAIOSFODNN7EXAMPLE` |
| `aws-secret-key` | `AWS_SECRET_ACCESS_KEY=wJalrXUtn...` |
| `github-token` | `ghp_`, `gho_`, `ghs_`, `github_pat_` |
| `private-key-pem` | `-----BEGIN RSA PRIVATE KEY-----` |
| `jwt-token` | `eyJ...` three-part tokens |
| `stripe-key` | `sk_live_`, `pk_live_` |
| `anthropic-key` | `sk-ant-api03-...` |
| `openai-key` | `sk-proj-...` |
| `gcp-api-key` | `AIzaSy...` |
| `pypi-token` | `pypi-AgEI...` |
| `slack-token` | `xoxb-...` |
| `azure-storage-key` | `DefaultEndpointsProtocol=https;AccountName=...;AccountKey=...` |
| `bearer-token` | `Authorization: Bearer <token>` |
| `db-connection-string` | `postgresql://user:pass@host/db` |
| `basic-auth-url` | `https://user:pass@host` |
| `private-key-assignment` | `SECRET_KEY = "..."`, `api_secret = "..."` |

### Custom rules

No code changes or reinstall required. Add your own patterns — or silence noisy built-ins — in `~/.aifence/prompt_guard.toml`:

```toml
# Silence a built-in that causes false positives
disable = ["jwt-token"]

# Add a company-specific secret pattern
[[rules]]
id = "vault-token"
description = "HashiCorp Vault service token"
pattern = '''hvs\.[A-Za-z0-9_-]{90,}'''
```

Manage via CLI:

```shell
aifence prompt-guard rules list
aifence prompt-guard rules add --id doppler-token --description "Doppler token" --pattern "dp\.st\.[A-Za-z0-9_-]{40,}"
aifence prompt-guard rules disable --id jwt-token
aifence prompt-guard rules enable  --id jwt-token
aifence prompt-guard rules remove  --id doppler-token
```

### Fail-closed design

- **4-second internal timeout** fires before Claude Code's 5-second kill — ensures the hook exits with code 2 (block) rather than silently timing out
- **Any unhandled exception** exits 2 — a crash never degrades to fail-open
- **Malformed JSON input** exits 0 — a broken hook packet itself contains no secret

### Honest limits

The following bypass techniques are not caught (by design — they require runtime/AST analysis):

- `base64.b64encode(secret)` — encoding destroys the recognisable pattern
- Key split across lines or with spaces inserted
- Runtime string concatenation (`"AKIA" + "IOSFODNN7EXAMPLE"`)
- Hex encoding

These require deliberate obfuscation. The guard is designed to stop accidental leakage, which covers 99% of real incidents.

---

## Safe by design

- **Pattern-based only** — aifence never reads file contents, only matches filenames and text patterns
- **Merge, never overwrite** — existing configs are preserved
- **Idempotent** — running any command twice produces the same result
- **No network calls** — everything runs locally

## License

MIT
