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
- **There is no `--mitre` flag.** MITRE ATT&CK® mapping is registry data shown
  by default; see MITRE ATT&CK below. Passing `--mitre` fails as an unknown flag.
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
| `owatch browse [report-file]` | Open a saved report in the results browser; reads any format that holds the whole report (JSON, YAML) |
| `owatch completion` | Generate shell completion scripts (see Shell Completion below) |
| `owatch help` | Show the full command menu (equivalent to `-h`/`--help`) |
| `owatch notices` | Print the third-party notices for the MITRE data owatch carries |
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
| `-o, --output` | Format of the full report, wherever it goes (`--plain`, `--report-file`, or `t` in the browser): text, json, yaml. Unspecified, a report file is JSON and anything else is text | text |
| `--report-file` | Save report to directory; filename is generated automatically | — |
| `--min-severity` | Minimum severity to report: NONE, LOW, MEDIUM, HIGH, CRITICAL | NONE |
| `--timeout` | Maximum audit duration | 10m |
| `--enrich, -e` | Query external sources to annotate findings with CVEs mapped to referenced CWEs | false |
| `--allow-elevated-write` | Permit an elevated write outside the allowlisted directories or into a directory other users control | false |
| `-v, --verbose` | Add the live findings feed to the progress display, or print progress lines when output is not a terminal; does not change report content | false |
| `-y, --yes` | Do not ask before a permissions check that scans the entire filesystem | false |
| `--plain` | Print the report to the terminal instead of opening the results browser; the format is text unless `-o` names another | false |

## `osinfo` and `software` Flags

`owatch osinfo` and `owatch software` each run one module and deliver it as `all`
does: the results browser on a terminal, with the System or Software source
filled and the others saying they were not collected.

| Flag | Description | Default |
|---|---|---|
| `-o, --output` | Format of the full report, wherever it goes (`--plain`, `--report-file`, or `t` in the browser): text, json, yaml. Unspecified, a report file is JSON and anything else is text | text |
| `--report-file` | Save report to directory; filename is generated automatically | — |
| `--allow-elevated-write` | Permit an elevated write outside the allowlisted directories or into a directory other users control | false |
| `--plain` | Print the report to the terminal instead of opening the results browser; the format is text unless `-o` names another | false |

The saved report is an `all` report holding that one module, so `owatch browse`
opens it.

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
| `-o, --output` | Format of the full report, wherever it goes (`--plain`, `--report-file`, or `t` in the browser): text, json, yaml. Unspecified, a report file is JSON and anything else is text | text |
| `--report-file` | Save report to directory; filename is generated automatically | — |
| `--min-severity` | Minimum severity to report: NONE, LOW, MEDIUM, HIGH, CRITICAL | NONE |
| `--timeout` | Maximum time to run all scans | 30m |
| `--enrich, -e` | Query external sources to annotate findings with CVEs mapped to referenced CWEs | false |
| `--allow-elevated-write` | Permit an elevated write outside the allowlisted directories or into a directory other users control | false |
| `-v, --verbose` | Add the live findings feed to the progress display; does not change report content | false |
| `-y, --yes` | Do not ask before a permissions check that scans the entire filesystem | false |
| `--plain` | Print the report to the terminal instead of opening the results browser; the format is text unless `-o` names another | false |

There is no individual audit check flag (`--ssh`, `--fwall`, etc.) on `all` —
to run only specific checks as part of a full scan, skip the others instead:

```bash
# Equivalent to running only the SSH check, but as part of the all pipeline
owatch all --skip-checks firewall,users,permissions
```

## Progress Display

When standard output is a terminal, `owatch audit` and `owatch all` show their
progress while they run: one row per check or module with its state, an overall
bar counting completed tasks, and the time elapsed. Each row ends with the task's
result and finding count; the permissions row also shows how many entries the scan
has read. `-v` adds a feed of findings as they arrive. When the display finishes,
the results open in the results browser (see below).

Press ctrl+c to stop a run. Checks still running are asked to stop, whatever
finished is reported, and the command exits with an error naming what did not
complete.

A permissions check with no `--fperms` path reads the entire filesystem, so on a
terminal `owatch` asks before starting one. Answer `y` to proceed, pass `--yes`
to skip the question, or narrow the scan with `--fperms <path>`.

When output is piped or redirected there is no display and no question, and the
run proceeds as it would from a script.

## Results Browser

On a terminal, `owatch audit`, `owatch osinfo`, `owatch software` and `owatch all`
end in an interactive results browser instead of printing the report, because a
whole-filesystem scan produces far more lines than a terminal keeps. Every
command opens the same layout. The left pane lists the sources, each with the
key that opens it, above the findings filters and the run's summary; it scrolls
when it is taller than the window, and a window too narrow for it shows the
sources as a bar along the top. The filters and the summary belong to findings,
so they read n/a on a source that has none. The browser has a source for each
part of the run: Findings lists each finding with its severity and shows the selected one in
full with what triggered it (the rule that failed, what it found, the severity the registry
gives it, the techniques it is mapped to) and its evidence; System shows the host's fingerprint; Software lists the
installed packages and can be searched; MITRE ATT&CK® groups the findings by the
technique each makes available, with the finding, rule and evidence behind each. A source a command did not run, or a module
that was skipped or failed, is still listed and says so. A run opens on
Findings when the audit ran, and otherwise on the first module that did, so
`owatch osinfo`, or `owatch all --skip-modules audit`, opens on System. The complete plain report is one key away.

| Key | Action |
|---|---|
| `f`, `o`, `s`, `m` | Switch to the Findings, System, Software or MITRE ATT&CK tab from any pane; each tab's letter is shown in the left pane |
| `[`, `]`, `1` to `9` | Step to the previous or next tab, or go to a tab by its number |
| `tab`, `shift+tab` | Move between the left, list and detail panes |
| up/down, pgup/pgdn, home/end | Move through the focused pane |
| left/right | Pan the detail pane or the full report sideways |
| `enter` | In the left pane, open a source or apply a filter; in the list, open the selected item in the detail pane |
| `/` | Search the active tab: on Findings, titles, rule keys, descriptions, references and evidence, and the detail pane then shows only the matching evidence lines; on Software, package names and versions. `enter` keeps the search, `esc` clears it, and each tab keeps its own |
| `a` | On Findings, show every evaluated rule, not only findings and rules that could not be evaluated |
| `x` | On Findings, load all of a finding's evidence when only the first 500 lines are shown |
| `t` | Show the complete plain report; `t` or `esc` returns |
| `esc` | Return from the detail pane to the list |
| `q`, ctrl+c | Quit |

## Output Formats

`-o` chooses the format of the full report, wherever the report goes. Where it goes
is chosen separately: the results browser by default on a terminal, the terminal
with `--plain`, or a file with `--report-file`.

| Command | Result |
|---|---|
| `owatch audit` | The results browser; `t` shows the full report as text |
| `owatch audit -o json` | The results browser; `t` shows the full report as JSON |
| `owatch audit --plain` | The report printed to the terminal as text |
| `owatch audit --plain -o yaml` | The report printed as YAML |
| `owatch audit --report-file dir` | A JSON file |
| `owatch audit -o text --report-file dir` | A text file |
| A pipe or a redirect | The report, as text or as the format `-o` names |

Every other part of the browser, its tabs, lists and detail panes, is plain text
whatever `-o` says, for readability. Omitting `-o` gives the defaults above and
naming it forces that format even when it is the default; the difference shows only
in a report file, which is JSON when `-o` is omitted and text with `-o text`.
Scripts and pipelines are not a terminal, so they always get the report in the
format asked for.

JSON and YAML are lossless: they hold the whole report, including the system block,
the software inventory, the module results and every check, whether or not it had
findings. Text is a rendering of a report and holds less. `owatch browse` reads the
lossless formats, takes the format from the file's extension, and shows exactly
what the run that wrote the report showed; `-o` there picks the format of the full
report under `t`, as it does for a live run. It refuses any other input format and
says why.

A report saved as JSON or YAML can be reopened in the browser later:

```bash
# Open the newest owatch report in the current directory
owatch browse

# Open a specific report
owatch browse /path/to/reports/owatch-host-SFUP-20261114T120000Z.json

# Open a report whose extension does not name its format
owatch browse --input-format yaml /path/to/reports/last-scan.out

# Show the full report under t as JSON
owatch browse -o json /path/to/reports/owatch-host-SFUP-20261114T120000Z.json
```

## MITRE ATT&CK

Findings that make a known MITRE ATT&CK® technique available carry it: the technique's
identifier, name and tactics, and the mitigations the ATT&CK site lists for it,
appear under the finding in the text report, in the finding's detail in the
browser, as an `attack` list on the finding in JSON and YAML, and as the MITRE
ATT&CK tab. The mapping is static data bundled in the binary, read
from the ATT&CK site, so it needs no flag and no network. It says what an adversary
can do because of the condition, not that anyone has done it. A technique is
attached to a finding only when three things hold: the Center for Threat-Informed
Defense's published mapping of NIST SP 800-53 to ATT&CK links a control the finding
cites to the technique, the technique applies to the platform the finding is for,
and the technique's ATT&CK description states the condition the finding reports.
Each technique on a finding states its basis, so the association can be checked:
the NIST control the finding cites that the mapping links to the technique, or the
finding's weakness through a CAPEC attack pattern that CAPEC maps to it. A finding
with no sound mapping carries none.

## References

Each finding cites its sources: the weakness it maps to (CWE), the NIST SP 800-53
controls it bears on, and, where one applies, a vendor or distribution document.
A citation is shown only after it has been checked against its source. NIST
controls are checked when owatch starts against the bundled SP 800-53 Rev 5.2.0
catalog, which supplies the title shown, so a citation cannot name a control that
does not exist. Pages record the edition they were checked against and the date. A
citation that has not been checked is kept in the data and withheld from every
report, JSON and YAML output and the results browser. The CIS Benchmark
citations are withheld in this way until each is checked against the benchmark.

A finding also states its weakness and its CVSS score. The weakness is a CWE entry
from the bundled MITRE catalog, shown with its name, MITRE's description and MITRE's
own guidance on mapping to it (`weakness` in JSON and YAML). The registry refuses to
load a definition that maps to an entry MITRE marks Discouraged or Prohibited. Where
no entry describes a finding, which is the case for a disabled SELinux, the finding
says so and gives the reason (`no_weakness`) rather than naming a weakness that does
not fit. The CVSS score (`cvss`) is labelled with FIRST's nomenclature: CVSS-B is a
base score, here the registry's baseline for the condition in general, and the label
says it is not measured on the host the finding was raised on.

## Third-Party Notices

owatch carries MITRE ATT&CK® data, references the Common Weakness Enumeration
(CWE™), and cites identifiers from the Common Attack Pattern Enumeration and
Classification (CAPEC™). MITRE's terms for each grant a royalty-free license for
commercial use on the condition that any copy reproduces MITRE's copyright
designation and the license. owatch also names the Center for Threat-Informed
Defense's mapping of NIST SP 800-53 to ATT&CK (Apache License 2.0, copyright
MITRE) as the basis for technique links, bundles NIST SP 800-53 control titles
(public domain), and carries a port of FIRST's CVSS v4.0 scoring code (BSD
2-Clause, copyright FIRST.ORG, Inc., Red Hat, and contributors). `owatch notices` prints every notice and license; it is embedded
in the binary, so a bare copy of owatch carries it, and it is kept in
[`internal/notices/THIRD_PARTY_NOTICES.md`](internal/notices/THIRD_PARTY_NOTICES.md).
MITRE ATT&CK and ATT&CK are registered trademarks, and CWE and CAPEC are trademarks,
of The MITRE Corporation.

## Skips and Partial Runs

Skipping is recorded, not hidden. A check excluded with `--skip-checks` appears in
the report with result `notselected` and is counted under that result in the
summary, so a report always accounts for every check in the canonical set. Under
`owatch all`, a module excluded with `--skip-modules` is likewise reported in the
`Modules` block as `notselected` rather than being silently absent.

Skipping every check, or every module, is rejected rather than producing an empty
report. Use `--skip-modules audit` to omit the audit module entirely.

A run that exceeds `--timeout` prints the results collected so far, marks the checks
that did not finish as `error`, and then reports the timeout naming which checks to
exclude or allow more time for. A rule that could not be evaluated in full, such as
a filesystem scan that could not read some paths, reports `error` with the reason
rather than `pass` on partial coverage.

## Results and Evidence

Every check reports the rules it evaluated as conditions, each with one of the
XCCDF 1.2 result values: `pass`, `fail`, `error`, `unknown`, `notapplicable`,
`notchecked`, `notselected` or `informational`. A result other than `pass` or
`fail` always carries a reason. `error` means the evaluation could not complete,
typically for want of privilege; `unknown` means a tool's output was not
recognized. A check's own result is the aggregate of its conditions.

A finding is a condition that failed. It carries the rule key, the registry
description, and the evidence that caused it: the files, accounts or settings
the rule failed on, each with the facts observed about it. In JSON and YAML the
evidence sits inside its condition. A finding below `--min-severity` is left out
together with its evidence; conditions that are not findings are always shown.

The summary counts checks and conditions by result and findings by severity.

## Report Output

`--report-file` accepts a destination **directory**, not a file path. `owatch`
generates the filename automatically:

```text
owatch-<hostname>-m.<module_codes>-c.<check_codes>-e.<enrichment_codes>-<timestamp>.<ext>
```

- Segments are omitted entirely when empty — there are never double hyphens.
- Format resolution: an explicit `-o/--output` value always wins; if
  `--report-file` is given without `-o`, JSON is used; if neither is given,
  the full report is text, which on a terminal is shown under `t` in the results
  browser.

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

Note: c.s (SSH check) and m.s (software module) share the same letter — that's intentional and safe, since each category is its own namespace (the registry only enforces uniqueness within a category, not across all three). This distinction is worth stating explicitly so it doesn't read as a typo when someone's staring at `m.os-c.fpsu` for the first time.

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