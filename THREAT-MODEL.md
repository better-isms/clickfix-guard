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
- The hook runs. If `jq` is missing or the event is not valid JSON, it degrades to raw matching and says so. Commands over 64 KB are refused, not checked, so a padded command cannot outrun the hook timeout (checking takes under a second at 64 KB). Harnesses that fail open on hook timeout (Grok, after 5 seconds by default) could still skip it on a badly overloaded machine.
- The tracker's state lives in `~/.local/state/clickfix-guard/` (mode 700). If that directory or a state file is a symlink or not owned by you, tracking switches off with a warning rather than writing through it. The check-then-append is not atomic; exploiting that needs write access to your own 0700 directory, which already means game over.

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

Method: every unique shell command an agent ran in two weeks of real, heavy daily use on one developer's Mac (Claude Code sessions: email triage, coding, releases, audits), replayed through the guard in `block` mode, the strictest setting. Commands are not published; only the counts.

| | Commands | Refused | Legitimate commands refused |
|---|---|---|---|
| clickfix-guard 1.0 | 32,385 | 2 | 1 (a 111 KB heredoc writing a file, refused as too large to check) |

The other refusal was a deliberate test that ran a script from Downloads. For comparison, the private prototype this grew from refused 6 legitimate commands on the same set, mostly searches whose pattern contained installer or pipe-to-shell text; quoted text is now treated as data unless it is handed to `sh -c`, `-e` or `eval`.

The workload contains no real attacks, so this measures false positives only. Detection is covered by the test suite and KNOWN-BYPASSES.md.
