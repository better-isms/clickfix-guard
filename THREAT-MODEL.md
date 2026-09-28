# Threat model

## The attack

1. An agent reads something an attacker wrote: an email it is triaging, an issue or PR it was asked to fix, a README in a repo it cloned, a web page it fetched, an MCP tool result.
2. The text contains setup or fix instructions: "run this to install the SDK", "the build fails until you run", "paste this in Terminal to verify your account". This is ClickFix, the same trick macOS stealers use on people.
3. The agent, being helpful, runs it. In bypass or auto mode nobody sees the command before it runs.

The realistic payload is a one-liner (`curl ... | bash`), a script or installer delivered as a download or attachment, or a step that strips macOS quarantine so Gatekeeper stays quiet.

## What clickfix-guard does

A PreToolUse hook that reads every shell command before it runs and refuses the download-and-run moves listed in the README. A PostToolUse hook records files the agent downloaded with curl or wget, so running them later in the session is refused too. On macOS it checks the quarantine flag of any file about to run, which catches browser and mail downloads wherever they were copied or extracted.

## What it assumes

- The attacker does not know clickfix-guard is installed, or does not bother to evade it. Most injected instructions are copy-paste one-liners written for humans.
- The agent does not rewrite the command to evade the guard after a block. In our smoke tests (Claude Code and Codex CLI) the agent stopped and reported the block; the block message tells it the user can run the command themselves. A determined agent could rephrase the command into one of the known bypasses.
- The hook runs. If `jq` is missing it degrades to raw matching and says so; if the agent harness fails open on hook timeout (Grok does, after 5 seconds by default) a very slow machine could skip it.

## What it does not cover

See [KNOWN-BYPASSES.md](KNOWN-BYPASSES.md). In short: variables, encoded payloads, scripts the agent writes itself, clone-then-build, package managers, anything fetched inside a script. Also out of scope: credential phishing, data exfiltration, fraudulent payments, and malicious code the agent writes into your project.

## Layering

| Layer | What it adds |
|---|---|
| clickfix-guard | Deterministic refusal of the common download-and-run moves, even in bypass mode |
| Agent sandbox (Claude Code `/sandbox`, Codex sandbox) | Limits filesystem and network access for everything, including what the guard misses |
| Auto mode / permission prompts | A model or human looks at risky commands |
| Not reading untrusted input with a privileged agent | Split the agent that reads mail from the agent that has shell access |
| Code review before merge | Catches malicious or vulnerable code that lands in the repo (this is what Aevral does) |

## False-positive benchmark

BENCHMARK_PLACEHOLDER
