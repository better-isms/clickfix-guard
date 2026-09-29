# Known bypasses

clickfix-guard reads the command line. These get past it today. Each one is pinned in `tests/run.sh` as a case that currently passes through, so fixing one flips its test on purpose. Contributions welcome.

| Bypass | Example | Why it gets through | What would close it |
|---|---|---|---|
| Variables and indirection | `c=curl; $c -s URL \| bash`, `D=~/Downloads; bash $D/x.sh` | The hook does not evaluate shell variables | A shell parser, or a sandbox |
| Encoded payloads with no download on the line | `echo <base64> \| base64 -d \| sh` | Nothing on the line comes from the network | A sandbox; out of scope for a command-line check |
| Unusual stdin runners | `curl URL \| sh -c sh`, `\| xargs sh -c`, `\| awk '{system($0)}'` | Too many shapes to enumerate without false positives | More rules, case by case |
| Clone then run | `git clone URL && cd x && ./install.sh` | Cloning and running a build script is normal developer work | Tracking cloned paths (planned, opt-in) |
| Package managers | `npx pkg`, `pip install pkg`, `brew install tap/x` | Installing packages is normal work | A package allowlist or a sandbox |
| Extract or copy, then run, in one command | `unzip x.zip -d /tmp/x && /tmp/x/run.sh`, `cp ~/Downloads/fix.sh /tmp/f.sh && bash /tmp/f.sh` | The files do not exist yet when the hook checks; a later command running them is caught if the zip was flagged | Tracking extracted paths (planned) |
| Other downloaders | `aria2c URL -d /tmp && bash /tmp/x.sh` | Only curl, wget and xh are recognised | Add downloaders as they show up |
| Scripts written by the agent | The agent writes `/tmp/x.sh` with its file tool, then runs it | The hook sees `bash /tmp/x.sh`, which is ordinary | Tracking file-tool writes (planned, opt-in) |
| Downloads from an earlier session | `curl -o x` in one session, `bash x` in the next | The session tracker is per session | Longer-lived tracking |
| Non-macOS "downloaded" flag | A browser download on Linux | Linux has no quarantine flag | Downloads-folder rules cover the common case |
| Quoted paths with spaces, outside Downloads | `open "/tmp/Setup Tool.dmg"` | Quoted text is treated as data for the installer rules, so searches for these strings are not blocked | Quarantine still applies to browser downloads run by path; a shell parser would close it |
| An agent that knows the rules | Anything creative | It is a seatbelt | A sandbox |

## Quarantine coverage (macOS)

| How the file arrived | Flagged? | Blocked when run? | Verified |
|---|---|---|---|
| Safari, Chrome, Firefox download | yes | yes | Apple documented behaviour |
| Mail attachment saved to disk | yes | yes | Apple documented behaviour |
| `cp` or `mv` of a flagged file | yes | yes | tested (macOS 26) |
| `unzip`, `ditto -x -k`, `tar -xf` of a flagged archive | yes, on extracted files | yes, in a later command | tested (macOS 26) |
| `curl`, `wget`, `git clone` | no | curl/wget outputs via the session tracker only | tested |

The quarantine check applies to runnable files. Opening a quarantined PDF or document is allowed.
