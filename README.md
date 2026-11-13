# Orko Watch (owatch) [README SUBJECT TO CHANGE]
## Updated as of August 29, 2026

![Orko Watch][logo]

[logo]: /images/orkowatchv2.png "Orko Watch Logo"

A host and network vulnerability scanner developed under Project Orko
by Purple Packet Eaters. Orko Watch performs cross-platform host-level
enumeration and security auditing across Linux, Unix, macOS, and Windows.

---

## Current Status

`owatch` is currently pre-MVP. Every command below runs and produces real
results, but the following gaps exist today and will close as development
continues. This section will be trimmed as each item is resolved; if something
below isn't true anymore, treat the code's actual behavior as authoritative
and open an issue against this doc.

- **Windows audit findings may be incomplete or inaccurate.** Permissions
  checking doesn't yet default to `C:\` with full recursive traversal, the
  users check has known false negatives on Microsoft accounts, some scans
  return zero findings when findings are expected, and some failures fail
  silently instead of surfacing an error. Identity resolution is local-only:
  user enumeration reads the local SAM, so accounts supplied by Active
  Directory are never seen; ACL checks match the English literal `Everyone`
  and find nothing on a localized Windows; and files owned by a SID that no
  longer resolves go undetected. Tracked as a single fix (#111). Linux/Unix
  audit checks are not affected.
- **`--enrich` currently has no effect.** No CVE/CWE enrichment adapter
  (NVD, CISA KEV, EPSS, GHSA) is wired yet. The flag is accepted and does
  nothing; findings are not annotated with CVE data.
- **`--mitre` does not exist yet.** MITRE ATT&CK mapping is planned but not
  implemented; passing it will fail as an unknown flag.
- **macOS and BSD are implemented but not yet fully verified.** The Unix
  checkers carry macOS, FreeBSD, and OpenBSD code paths, and the registry
  ships finding definitions for each, but no result has been confirmed against
  real hardware on those platforms. Dedicated runners are tracked in #97 through
  #100; treat output there as unproven rather than trusted.
- **Filename and report structure may still change.** The naming convention
  and JSON/YAML report shape are considered stable for the fields that exist
  today, but new segments (enrichment, MITRE) will be added as those features
  land.
- **No log capture, listener enumeration, or history modules yet.** Only OS
  fingerprinting, software inventory, and the four audit checks (SSH,
  firewall, users, permissions) exist today.
- **No automated test suite yet.** Every package reports no test files;
  verification is manual against a Linux and a Windows host. Test
  infrastructure design is tracked in #94 through #98.

---

## Commands

| Command | Description |
|---|---|
| `owatch osinfo` | Gather OS fingerprint information |
| `owatch software` | List installed software packages |
| `owatch audit` | Run security audit checks |
| `owatch all` | Run all available scans |
| `owatch completion` | Generate shell completion scripts (see Shell Completion below) |
| `owatch help` | Show the full command menu (equivalent to `-h`/`--help`) |
| `owatch version` | Display current version |

> `-V`/`--version` on any invocation is equivalent to running `owatch version`.
> `owatch help` alone is equivalent to `owatch --help`/`-h`. `owatch help
> <command>` (e.g. `owatch help audit`) is equivalent to `owatch <command>
> --help`.

## Quick Start

```bash
# See all available commands and flags
owatch --help

# Display current version
owatch version

# Gather OS information
owatch osinfo

# List installed software
owatch software

# Run a full security audit with verbose output
owatch audit -v

# Run specific security checks
owatch audit --ssh
owatch audit --fwall
owatch audit --users
owatch audit --fperms /path/to/check

# Run all scans and save report as JSON to a directory (filename is generated automatically)
owatch all -o json --report-file /path/to/reports

# Skip specific modules when running all scans
owatch all --skip-modules software,audit

# Skip specific audit checks (composes with --skip-modules)
owatch all --skip-checks permissions

# Filter findings to HIGH severity and above
owatch all --min-severity HIGH
```

## Audit Flags (`owatch audit`, alias `owatch security_audit`)

`audit` runs one or more checks directly, selected explicitly via boolean flags.
With no check flags given, all checks run by default.

| Flag | Description | Default |
|---|---|---|
| `--ssh` | Run SSH configuration check | false |
| `--fwall` | Run firewall configuration check | false |
| `--users` | Run user accounts check | false |
| `--fperms` | Check permissions of specified path | — |
| `--skip-checks` | Comma-separated checks to skip (ssh, firewall, users, permissions) | — |
| `-o, --output` | Output format: text, json, yaml | text |
| `--report-file` | Save report to directory; filename is generated automatically | — |
| `--min-severity` | Minimum severity to report: LOW, MEDIUM, HIGH, CRITICAL | LOW |
| `--timeout` | Maximum audit duration | 10m |
| `--enrich, -e` | Query external sources to annotate findings with CVEs mapped to referenced CWEs | false |
| `--allow-elevated-write` | Permit an elevated write outside the allowlisted directories or into a directory other users control | false |
| `-v, --verbose` | Show progress while checks run; does not change report content | false |

## `all` Flags (`owatch all`)

`all` runs every module (osinfo, software, audit) in one consolidated report.
There's no way to invoke multiple modules explicitly and select others — the
underlying CLI framework doesn't support that yet — so composition happens by
skipping what you don't want, in either direction: skip whole modules, or skip
individual audit checks within the audit module, or both together.

| Flag | Description | Default |
|---|---|---|
| `--skip-modules` | Comma-separated modules to skip (osinfo, software, audit) | — |
| `--skip-checks` | Comma-separated audit checks to skip (ssh, firewall, users, permissions); composes with `--skip-modules` | — |
| `-o, --output` | Output format: text, json, yaml | text |
| `--report-file` | Save report to directory; filename is generated automatically | — |
| `--min-severity` | Minimum severity to report: LOW, MEDIUM, HIGH, CRITICAL | LOW |
| `--timeout` | Maximum time to run all scans | 30m |
| `--enrich, -e` | Query external sources to annotate findings with CVEs mapped to referenced CWEs | false |
| `--allow-elevated-write` | Permit an elevated write outside the allowlisted directories or into a directory other users control | false |
| `-v, --verbose` | Show module and check progress while scanning; does not change report content | false |

There is no individual audit check flag (`--ssh`, `--fwall`, etc.) on `all` —
to run only specific checks as part of a full scan, skip the others instead:

```bash
# Equivalent to running only the SSH check, but as part of the all pipeline
owatch all --skip-checks firewall,users,permissions
```

## Skips and Partial Runs

Skipping is recorded, not hidden. A check excluded with `--skip-checks` appears in
the report with status `SKIPPED` and is counted in the summary's `Skipped` total,
so a report always accounts for every check in the canonical set. Under `owatch
all`, a module excluded with `--skip-modules` is likewise reported in the `Modules`
block as `SKIPPED` rather than being silently absent.

Skipping every check, or every module, is rejected rather than producing an empty
report. Use `--skip-modules audit` to omit the audit module entirely.

A run that exceeds `--timeout` prints the results collected so far, marks the checks
that did not finish as `ERROR`, and then reports the timeout naming which checks to
exclude or allow more time for. A check that completes but could not read part of the
filesystem reports `WARNING` with the number of unreadable paths, rather than
reporting success on partial coverage.

## Report Output

`--report-file` accepts a destination **directory**, not a file path. `owatch`
generates the filename automatically:

```text
owatch-<hostname>-m.<module_codes>-c.<check_codes>-e.<enrichment_codes>-<flag_codes>-<timestamp>.<ext>
```

- Segments are omitted entirely when empty — there are never double hyphens.
- Format resolution: an explicit `-o/--output` value always wins; if
  `--report-file` is given without `-o`, JSON is used; if neither is given,
  output goes to stdout as text.

### `m.` — Modules

| Letter | Module | Status |
|---|---|---|
| `h` | Shell/terminal history | reserved, not yet implemented |
| `l` | Log capture (syslog, Event Log, unified logging) | reserved, not yet implemented |
| `n` | Local listener enumeration | reserved, not yet implemented |
| `o` | OS fingerprint | implemented |
| `r` | Remote network scanning | reserved, not yet implemented |
| `s` | Software inventory | implemented |

The audit module itself has a reserved letter (`a`) used only to validate
`--skip-modules audit`; it never appears in a filename. Whether the audit
module ran is shown entirely through the presence or absence of the `c.`
segment below — a module code would be redundant with that.

### `c.` — Audit checks

| Letter | Check | Status |
|---|---|---|
| `f` | Firewall configuration | implemented |
| `p` | File permissions | implemented |
| `s` | SSH configuration | implemented |
| `u` | User accounts | implemented |

### `e.` — Enrichment adapters

| Letter | Adapter | Status |
|---|---|---|
| `g` | GHSA advisories | reserved, not yet implemented |
| `k` | CISA KEV | reserved, not yet implemented |
| `n` | NVD (CVE lookup) | reserved, not yet implemented |
| `p` | EPSS scoring | reserved, not yet implemented |

No `e.` segment appears in any filename yet, since no adapter is wired.

### Composing flags

| Letter | Flag | Status |
|---|---|---|
| `m` | `--mitre` (MITRE ATT&CK mapping) | reserved, not yet implemented |

This segment is unprefixed and always terminal when present. It will not
appear in any filename until `--mitre` lands.

Note: c.s (SSH check) and m.s (software module) share the same letter — that's intentional and safe, since each category is its own namespace (the registry only enforces uniqueness within a category, not across all four). This distinction is worth stating explicitly so it doesn't read as a typo when someone's staring at `m.os-c.fpsu` for the first time.

## Shell Completion

`owatch` can generate shell completion scripts via the `completion` subcommand.
Completion scripts are sourced into the shell session, not executed directly.

### bash
```bash
source <(owatch completion bash)
```

### zsh
```zsh
source <(owatch completion zsh)
```

### fish
```fish
owatch completion fish | source
```

### PowerShell
```powershell
owatch completion powershell | Out-String | Invoke-Expression
```

> **Note:** Shell completion requires `owatch` to be installed and available
> in PATH. It does not work with `go run` during development.

## Demo

> Coming soon — a recorded demo will be added after the first release tag.

---

## Downloads

### Windows
- [`install.ps1`][win-install]
- [`update.ps1`][win-update]
- [`uninstall.ps1`][win-uninstall]

[win-install]: https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/windows/install.ps1
[win-update]: https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/windows/update.ps1
[win-uninstall]: https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/windows/uninstall.ps1

### Linux
- [`install.sh`][linux-install]
- [`update.sh`][linux-update]
- [`uninstall.sh`][linux-uninstall]

[linux-install]: https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/linux/install.sh
[linux-update]: https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/linux/update.sh
[linux-uninstall]: https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/linux/uninstall.sh

### macOS
- [`install.sh`][macos-install]
- [`update.sh`][macos-update]
- [`uninstall.sh`][macos-uninstall]

> macOS scripts are not yet fully implemented. See [scripts/macos/](scripts/macos/) for current status.

[macos-install]: https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/macos/install.sh
[macos-update]: https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/macos/update.sh
[macos-uninstall]: https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/macos/uninstall.sh

---

## System Requirements

### Windows
- PowerShell 5.1 or higher
- Administrator privileges

### Linux
- Bash 4.0+
- sudo privileges

### macOS
- Bash 4.0+
- sudo privileges
- Full installation support coming in a future release

> **Note:** Go is not required for end users. The install scripts
> download pre-built binaries directly from GitHub Releases.
> Go 1.23+ is only required if building from source.

---

## Installation

### Windows
```powershell
# Download and run as Administrator
curl -o install.ps1 https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/windows/install.ps1
Set-ExecutionPolicy RemoteSigned -Scope Process
.\install.ps1
```

### Linux
```bash
curl -O https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/linux/install.sh
chmod +x install.sh
./install.sh
```

### Build from Source
```bash
git clone https://github.com/papa0four/orkowatch.git
cd orkowatch
make install
```

---

## Updating

### Windows
```powershell
curl -o update.ps1 https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/windows/update.ps1
.\update.ps1
```

### Linux
```bash
curl -O https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/linux/update.sh
chmod +x update.sh
./update.sh
```

---

## Uninstalling

### Windows
```powershell
curl -o uninstall.ps1 https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/windows/uninstall.ps1
.\uninstall.ps1
```

### Linux
```bash
curl -O https://raw.githubusercontent.com/papa0four/orkowatch/main/scripts/linux/uninstall.sh
chmod +x uninstall.sh
./uninstall.sh
```

---

## Troubleshooting

### Windows
- Unblock scripts after download:
```powershell
  Unblock-File .\install.ps1
```
- Run PowerShell as Administrator
- If `owatch` is not found after install, open a new terminal to
  reload PATH

### Linux / macOS
- Ensure script is executable: `chmod +x install.sh`
- Verify sudo access: `sudo -v`
- If `owatch` is not found after install: `source /etc/profile`
  or open a new terminal
- Check PATH includes `/usr/local/bin`: `echo $PATH`

---

## Support
For issues or questions, please open a [GitHub Issue][issues].

[issues]: https://github.com/papa0four/orkowatch/issues

---

## License
This project is licensed under the Apache License 2.0 with Commons Clause.

You are free to use, modify, and distribute this software for
non-commercial purposes. Commercial use, resale, or offering this
software as a paid service requires explicit written permission.

See [LICENSE](LICENSE) for full terms.