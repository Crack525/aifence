# Your AI Coding Assistant Can Read Your .env Files. Right Now.

I was publishing a Python package last week. Asked GitHub Copilot Agent to help set up the workflow. It ran `cat .env` without asking — and there was my PyPI token, sitting in the chat window.

![Copilot reading .env file without warning](../problem.png)

No permission prompt. No warning. It just read it.

I'd been using AI coding tools daily for months. It never occurred to me that they could — and would — read my secrets unprompted.

## The scope of the problem

I started testing every AI coding tool I use. The results were worse than I expected.

**Claude Code** can read files two ways: its built-in Read tool, and by running shell commands like `cat .env` through Bash. Two attack surfaces, not one.

**Cursor** automatically indexes project files for AI context. Your `.env` gets pulled into the model's context window whether you asked or not.

**GitHub Copilot** in Agent mode runs shell commands with your full user permissions. `.copilotignore` exists, but Agent mode ignores it entirely — it only works for code completions.

**Gemini CLI** has no file access restrictions at all. No ignore file, no permission system, nothing.

**Windsurf** has `.windsurfignore`, but the enforcement depth is unverified — nobody I've found has confirmed exactly what it blocks.

So: five major AI coding tools, five different security models, and the only one with real OS-level protection is Claude Code — if you manually enable its sandbox.

## What's actually at risk

Think about what's sitting in your project directories right now:

- `.env` files with API keys, database URLs, auth tokens
- `*.pem` and `*.key` files — TLS certificates, SSH keys
- `credentials.json`, `secrets.yaml` — cloud service accounts
- `.npmrc`, `.pypirc` — package registry tokens
- `id_rsa`, `id_ed25519` — SSH private keys

These files exist because that's how development works. You need them locally. And every AI tool you've installed can read all of them.

The uncomfortable truth: your AI coding assistant has the same file access as a malicious script running under your user account. The difference is you invited it in.

## Every tool has different protection — and most of it is partial

I spent a weekend reading docs for all five tools. Here's what actually works:

| Tool | Protection mechanism | What it actually blocks |
|---|---|---|
| Claude Code | `permissions.deny` + `sandbox.denyRead` | Full — OS-level when sandbox enabled |
| Cursor | `.cursorignore` | AI context only — not shell commands |
| Copilot | `.copilotignore` | Completions only — Agent mode ignores it |
| Windsurf | `.windsurfignore` | Unclear — enforcement unverified |
| Gemini CLI | Nothing | Nothing at all |

Claude Code is the only tool that can actually prevent file access at the OS level. Its sandbox uses Seatbelt on macOS and bubblewrap on Linux to block *all* processes — including `cat`, `grep`, `python` — from reading protected files. But you have to enable it yourself, and you have to know exactly which config keys to set.

For everything else, you're relying on ignore files that block AI context but can't stop shell commands. If the AI decides to run `cat .env`, the ignore file won't help.

## What I built

I got tired of reading four different docs every time I started a new project. So I built [aifence](https://github.com/Crack525/aifence) — one command that generates the strongest available protection for every AI tool in your project.

```shell
$ aifence init

Scanning for sensitive files...
  Found: .env, config/secrets.yaml, certs/server.pem, .npmrc

  Claude Code (detected):
    ✓ permissions.deny — 20 Read rules added
    ✓ sandbox.denyRead — 20 patterns added
    ⚠ Sandbox not enabled — run /sandbox in Claude Code for OS-level Bash protection

  Cursor (detected):
    ✓ .cursorignore — 20 patterns added
    ⚠ Shell commands (cat .env) not blocked — Cursor limitation

  Copilot (not detected):
    ✓ .copilotignore — 20 patterns added
    ⚠ Agent mode ignores .copilotignore — completions context only

  Windsurf (not detected):
    ✓ .windsurfignore — 20 patterns added
    ⚠ Enforcement depth unverified

  Gemini CLI (not detected):
    ✗ No protection mechanism available
```

It scans your workspace for sensitive files, detects which AI tools you're using, and generates the right config for each one. Every warning you see is real — aifence tells you exactly what it can and can't protect against.

## The honest parts

A few things I want to be upfront about.

**aifence can't fix every tool.** Gemini CLI has zero protection mechanisms. Copilot Agent mode ignores its own ignore file. These are tool-level limitations that no external tool can solve. aifence generates what it can and warns about the rest.

**Sandbox is the only real protection for Claude Code, and aifence doesn't enable it for you.** Enabling the sandbox changes how Bash permissions work — that's a workflow decision. aifence adds the deny rules so that when you do enable it, your files are already protected.

**Ignore files are context barriers, not security boundaries.** For Cursor, Copilot, and Windsurf, the ignore files prevent the AI from pulling your secrets into its context window. That's useful — it stops accidental exposure during normal coding. But if the AI runs a shell command, the ignore file won't stop it.

**aifence never reads your file contents.** It only matches filenames against patterns. It doesn't know if your `.env` contains API keys or grocery lists. It just knows `.env` files are sensitive by convention.

## How it works under the hood

For Claude Code, aifence generates two layers of protection:

1. `permissions.deny` rules — blocks the Read tool with recursive patterns like `Read(**/.env)` so it catches `.env` files in any subdirectory
2. `sandbox.filesystem.denyRead` patterns — blocks all processes at the OS level when sandbox is enabled

For Cursor, Copilot, and Windsurf, it generates ignore files with the same 20 patterns, merging with any existing rules (never overwriting).

The whole thing is idempotent. Run `aifence init` twice and you get the same result. Run it on a project with existing configs and it appends without duplicating.

```shell
pip install aifence
aifence init
```

That's it. About 10 seconds.

## The bigger question

Why don't AI coding tools ship with this protection by default?

Every tool could prompt you on first run: "We found `.env` files in your project. Want to exclude them from AI access?" None of them do.

Claude Code comes closest — it has the sandbox infrastructure and the permission system. But you have to discover it, configure it, and enable it yourself. The other tools don't even have the infrastructure.

Until that changes, the burden is on developers to protect their own secrets from the tools they use every day. That shouldn't be the case, but it is.

```shell
pip install aifence
aifence init
```

[GitHub](https://github.com/Crack525/aifence) | [PyPI](https://pypi.org/project/aifence/)

---

*I built aifence after watching Copilot read my PyPI token. If you've had a similar experience — or if you've found protection mechanisms I missed — [open an issue](https://github.com/Crack525/aifence/issues).*
