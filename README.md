# NetScaler IR triage collector

`ns_ir_collect.sh` v1.1 collects metadata and heuristic findings from a NetScaler root shell. It is an **experimental live-response aid**, not a disk imager, vulnerability scanner, or proof that an appliance is clean.

Version 1.1 fixes the archive-loss and misleading-success defects found in v1.0. See [validation results](VALIDATION.md). Metadata-mode collection has completed on the local NetScaler 14.1 build 73.30 lab with a documented missing-utility partial status. Production-load acceptance and full sensitive-mode appliance collection remain unverified.

## Usage and data handling

```sh
# On the appliance, from the root shell:
sh /var/tmp/ns_ir_collect.sh -C INC-2026-0412

# Explicitly authorize raw sensitive forensic collection:
sh /var/tmp/ns_ir_collect.sh -S -C INC-2026-0412
```

**Default mode does not copy source files, full configuration, raw log lines, histories, process arguments, account records, or session IDs.** It collects process names, network metadata, a filesystem timeline, path/hash inventories, version output, and aggregate heuristic results. It reads configuration and logs to produce those results. Paths, hostnames, addresses, case IDs, and executable names remain potentially sensitive metadata; attacker-controlled names are not an arbitrary-secret redaction boundary.

**`-S` explicitly permits sensitive data, including private keys.** This mode can copy raw configuration, suspicious files, histories and logs, and capture detailed process and CLI output. It does not promise to exclude keys or credentials. Every source-file copy passes one final mode gate. Collection is selective, not a complete filesystem backup. Store sensitive output under your evidence-handling policy; the script sets `umask 077` but does not encrypt archives.

The script does not enable traffic features, alter authentication policy, create packet-engine core dumps, or intentionally reboot the appliance. Live reads and commands have a forensic footprint, including atime updates and appliance command/audit logging. Timeline capture occurs before bulk scanning, but after script hashing and volatile/CLI collection.

| Option | Meaning | Default |
| --- | --- | --- |
| `-o DIR` | Existing output parent | `/var/tmp` |
| `-C ID` | Case ID: letters, digits, dot, underscore, hyphen | `unspecified` |
| `-d DAYS` | Recent-file ctime lookback, 0–36500 | `120` |
| `-S` | Permit raw sensitive forensic collection | Off |
| `-c` | Include core files; requires `-S` | Off |
| `-n` | Include performance logs; requires `-S` | Off |
| `-b` | Hash additional binary directories | Off |
| `-k` | Keep staging after successful/partial verified packaging | Off |
| `-t SECONDS` | Whole-run deadline, 1–86400 | `900` |
| `-m MAX_MB` | Total output limit in MiB | `512` |
| `-r RESERVE_MB` | Required remaining free space in MiB | `64` |
| `-h` | Help | |

`-m` and `-r` are sampled once per second and checked again before staging cleanup. They are **not filesystem quotas**: a fast writer can temporarily overshoot them. The monitored footprint includes staging, the outer archive and packaging sidecars; full mode temporarily holds both inner and outer archives and a per-file verification buffer. Budget for these duplicate bytes. SIGKILL, power loss, uninterruptible kernel I/O and exhausted storage can defeat normal cleanup/status reporting.

## Requirements and collection stages

Use a NetScaler root shell with native FreeBSD `stat -f` or an installed Python 3 at a supported appliance location, `tar` supporting `--null -T` and `-xO`, a compatible `timeout` with `-k`, `realpath`, `mktemp`, and a SHA-256 utility (`sha256`, `sha256sum`, or OpenSSL). Build 73.30 lacks `stat`; the collector uses its installed Python 3 `os.lstat` adapter and records that backend in metadata. Missing mandatory utilities fail before substantive collection. Each wrapped command has a 60-second timeout in addition to the whole-run deadline. Missing optional commands produce partial status.

1. Volatile system metadata; raw process arguments only with `-S`.
2. NetScaler version; extended read-only CLI queries only with `-S`.
3. Filesystem timeline and post-boot change review.
4. Persistence, accounts, SUID/SGID and configuration heuristics.
5. Webshell patterns, staged keys/configuration, image magic and temporary executables.
6. Log/core inventory; raw copies only with `-S`.
7. Log heuristics. Default output omits raw lines, usernames and session IDs.
8. Live-source hash inventories; these are not an atomic filesystem snapshot.
9. Optional raw evidence tar, captured-content hashes, verified outer archive and checksum.

Filesystem names containing non-printable/non-ASCII bytes or `|` are omitted and mark the run partial. Spaces are supported. Names beginning `nsir_` are pruned to avoid collecting this run, other concurrent runs and older collections. This deliberately creates a coverage gap for unrelated files with that prefix; inspect such paths separately during an investigation. Hardlink/symlink-directory aliases are represented in a mapping when multiple candidates refer to the same captured inode; leaf symlinks are not copied as regular evidence files.

## Output and completion

Each run uses an exclusively created, randomly suffixed staging directory. Concurrent runs cannot share the same staging name.

```text
nsir_<host>_<UTC>.<random>/
  00_metadata.txt
  00_stage_status.tsv       # aggregate stage status
  00_stage_events.tsv       # individual errors and deliberate skips
  00_TRIAGE_FLAGS.txt
  00_collection.log
  system/ netscaler_cli/ timeline/ checks/ logs_analysis/ hashes/
  files/                   # raw evidence only with -S
```

| Exit | Meaning |
| --- | --- |
| `0` | Collection complete within the selected scope; deliberate privacy/option skips remain recorded |
| `2` | A verified archive exists, but collection is partial; inspect stage events |
| `1` | Fatal failure or resource limit; staging is preserved |
| `124` | Whole-run deadline expired; staging is preserved |
| `128 + signal` | Interrupted, or timeout's forced kill; staging is preserved when possible |

Heuristic findings do not change the exit code. Stage summaries distinguish `success`, `success_with_skips`, and `partial`; detailed events also record `failed` when a fatal error occurs. On fatal failure, the aggregate summary may not have been finalized: inspect preserved stage events and console output.

Packaging failures never intentionally delete staging. Temporary archives are verified before final rename, and hashes must be valid. With `-S`, `files/evidence_files.sha256` hashes the **captured payloads**. `files/source_before.sha256` identifies their pre-capture sources. Differences mark the collection partial; the captured evidence is retained. This detects the tested live-file change but cannot provide snapshot consistency or detect every possible race.

Retrieve the `.tgz` and `.tgz.sha256` files, then verify from their containing directory:

```sh
sha256sum -c nsir_<host>_<UTC>.<random>.tgz.sha256
```

A valid outer hash proves transport integrity, not complete collection. Always inspect stage status. Remove the specific run's files after verified retrieval according to your case procedure; record that action. Do not blindly retry a failed run until its staged evidence and disk usage are understood.

## Interpreting findings

HIGH, MEDIUM and LOW are investigation priorities, not compromise verdicts. Correlate against a clean appliance of the same build, change records, disk evidence and off-box logs. A HIGH hit does not by itself justify an automatic rebuild. No hits do not prove absence of compromise.

Session comparisons normalize IPv4 and IPv6, including bracketed IPv6 endpoints. Different unbracketed IPv6 source strings are ambiguous when ports are present: the script records partial coverage instead of stripping the last hextet. IPv4-embedded IPv6 forms are currently unrecognized and reported as partial. The many-users check groups by the **connection Source** address; NAT can explain matches. Actual gateway log-format coverage still requires representative appliance logs.

Shipped PNG/GIF/JPEG/ICO signatures are recognized regardless of filename extension. Literal PEM header lines are distinguished from key-header strings embedded in library code. Writable-path process and SUID metadata checks are MEDIUM baseline-review leads.

The AAA heuristic checks bytes 128–255 in rejection-message lines; ASCII controls/DEL alone are not matched. It is an attempt indicator, not evidence of successful memory disclosure or session theft. Endpoint hits and filesystem patterns do not determine which CVE, if any, was exploited.

## Development and validation

```sh
dash -n ns_ir_collect.sh
bash -n ns_ir_collect.sh
shellcheck -s sh ns_ir_collect.sh
# Linux, Bubblewrap installed and user namespaces enabled:
NSIR_TEST_RESULTS=tests/results.json python3 tests/test_collector.py
```

The test runner executes the real script in a private synthetic filesystem and network namespace. FreeBSD and appliance commands are shimmed; these tests do not establish native compatibility. It exercises privacy defaults, opt-in raw collection, selected indicators, command failures, packaging/corruption/hash failures, unusual names, live-file changes, IPv6 handling, limits, interruption and concurrent runs. No fixture webshell or SUID marker is executed.

Before production use, validate the exact artifact on each target build, check clean-baseline findings, test all optional flags, and measure CPU, memory, disk use and duration under realistic load. Preserve disks and off-box logs as your incident-response procedure requires.

## References

- [Citrix CTX694799: suspected compromise response](https://support.citrix.com/external/article/CTX694799/steps-to-take-if-netscaler-adc-is-suspec.html)
- [NetScaler CVE-2025-5777 log guidance](https://www.netscaler.com/blog/news/evaluating-netscaler-logs-for-indicators-of-attempted-exploitation-of-cve-2025-5777/)
- [Original defensive guide](NETSCALER-DEFENSIVE-GUIDE.md): background research, not a verified compatibility or CVE-coverage guarantee for this collector.

## Changelog

- **1.1 (2026-09-27):** metadata default, explicit sensitive mode, failure-safe packaging, captured-payload verification, aggregate statuses, bounded supervision, address parsing corrections and executable regression tests.
- **1.0 (2026-09-27):** initial release; validation found evidence-loss and secret-exclusion defects. Do not rely on its completion banner or private-key exclusion claim.
