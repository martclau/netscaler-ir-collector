# NetScaler IR triage collector

`ns_ir_collect.sh` v1.4 collects metadata and heuristic findings from a NetScaler root shell. It is an **experimental live-response aid**, not a disk imager, vulnerability scanner, or proof that an appliance is clean.

Version 1.4 adds an early native-integrity preflight, signed-manifest inventories, MAC_Veriexec analysis, deleted-executable process detection, link counts in the timeline, and selected FreeBSD/NetScaler boot, kernel, account, cron and history metadata. See [validation results](VALIDATION.md). Metadata mode and a bounded `-S -d 0` workflow completed on the isolated NetScaler 14.1 build 73.37 appliance. The scoped sensitive run required a 700 MiB budget because staging and the compressed outer archive coexist; a 512 MiB run stopped safely at its configured limit. Broad sensitive-mode performance and production-load acceptance remain unverified.

## Usage and data handling

```sh
# On the appliance, from the root shell:
sh /var/tmp/ns_ir_collect.sh -C INC-2026-0412

# Explicitly authorize raw sensitive forensic collection:
sh /var/tmp/ns_ir_collect.sh -S -C INC-2026-0412

# Correlate runtime IPv4/IPv6 indicators without embedding them in the script:
sh /var/tmp/ns_ir_collect.sh -i /var/tmp/case-iocs.txt -C INC-2026-0412
```

**With neither `-S` nor `--support-bundle`, default mode does not copy source files, full configuration, raw log lines, histories, process arguments, account records, or session IDs.** It collects process names, network metadata, a filesystem timeline, path/hash inventories, version output, and aggregate heuristic results. Raw `dmesg` and scoped `sysctl` text is also gated by `-S`; default mode records each command's exit status, output size/line count and SHA-256 instead. It reads configuration and logs to produce those results. Paths, hostnames, addresses, case IDs, and executable names remain potentially sensitive metadata; attacker-controlled names are not an arbitrary-secret redaction boundary.

**`-S` explicitly permits sensitive data, including private keys.** This mode can copy raw configuration, suspicious files, histories and logs, and capture detailed process and CLI output. It does not promise to exclude keys or credentials. Raw IR source-file copies require `-S`; the vendor archive has its separate explicit opt-in. Collection is selective, not a complete filesystem backup. Store sensitive output under your evidence-handling policy; the script sets `umask 077` but does not encrypt archives.

The script does not enable traffic features, alter authentication policy, create packet-engine core dumps, or intentionally reboot the appliance. Live reads and commands have a forensic footprint, including atime updates and appliance command/audit logging. Timeline capture occurs before bulk scanning, but after script hashing and volatile/CLI collection.

| Option | Meaning | Default |
| --- | --- | --- |
| `-o DIR` | Existing output parent | `/var/tmp` |
| `-C ID` | Case ID: letters, digits, dot, underscore, hyphen | `unspecified` |
| `-d DAYS` | Recent-file ctime lookback, 0–36500 | `120` |
| `-i IOC_FILE` | Runtime IPv4/IPv6 list, one address per line; blank lines and `#` comments allowed | Off |
| `--support-bundle` | Include a sensitive vendor support archive; independent of `-S` | Off |
| `--support-timeout=SECONDS` | Vendor generation deadline, 1–86400; whole-run deadline still applies | `600` |
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

The IOC file is resolved and validated before correlation. Its source and normalized SHA-256 values plus normalized address count are recorded, and source changes are detected, but its values are not embedded in the collector or repeated in default IOC-result files/flags. Existing volatile network outputs and the filesystem timeline can still contain the same addresses or IOC-file path because addresses and paths are part of the collector's documented metadata scope. With `-S`, matching source lines are retained. The supplied IOC file itself is excluded from the raw evidence tar. IPv6 matching is textual after lowercasing; provide alternate textual forms when the source logs may use a different valid compression.

## Vendor support bundle

```sh
# Vendor diagnostics plus metadata/aggregate IR collection:
sh /var/tmp/ns_ir_collect.sh --support-bundle --support-timeout=600 -t 1200 -m 2048 -C INC-2026-0412
```

`--support-bundle` explicitly permits sensitive vendor data without enabling the additional raw IR collection controlled by `-S`. Add `-S` only if both are wanted. The wrapper invokes the installed `/netscaler/showtechsupport.pl -scope NODE` directly so its timeout supervises the actual collector. It does not request upload. This integration requires that executable and the standard `/var/tmp/support/support.tgz` output link; other layouts produce a partial result.

Vendor diagnostics run after IR evidence capture. They can change diagnostic state (the inspected build includes `clearconfigtimings`) and generate audit records. Vendor filtering is not a guarantee that secrets have been removed. Treat the outer archive, vendor command log, member list, and remaining vendor files as sensitive.

The wrapper rejects pre-existing archive paths, copies the new archive, compares source-before, captured, and source-after SHA-256 values, and verifies its tar listing. The included `support_bundle/bundle.tar.gz` has its own checksum, installed-collector digest, provenance/status, and member list. Verification establishes captured-byte integrity, not that every vendor diagnostic succeeded. Explicit top-level error messages mark collection partial.

A vendor timeout, missing collector/archive, failed command, invalid archive, or changed source records a partial result while IR packaging continues. The whole-run `-t` deadline and resource limits still stop the entire run. Set `-t` above the vendor deadline with time for IR collection and packaging. The size budget includes existing and new files in `/var/tmp/support` and `/flash/support`, plus our staging and archive; free space is checked on the output, `/var/tmp`, and `/flash` filesystems. These remain sampled limits, not quotas. Output inside the vendor support directories is rejected.

Vendor workspaces and archives remain in their original locations, including after failures; the wrapper never deletes vendor evidence. Review and remove the specific generated files under your evidence-handling procedure. Avoid concurrent vendor support collections. On this build filenames have minute precision; an overwritten pre-existing path is conservatively rejected as not new. A default collector retry does not reuse an earlier bundle.

## Requirements and collection stages

Use a NetScaler root shell with native FreeBSD `stat -f` or an installed Python 3 at a supported appliance location, `tar` supporting `--null -T` and `-xO`, a compatible `timeout` with `-k`, `realpath`, `mktemp`, and a SHA-256 utility (`sha256`, `sha256sum`, or OpenSSL). Build 73.30 lacks `stat`; the collector uses its installed Python 3 `os.lstat` adapter and records that backend in metadata. Missing mandatory utilities fail before substantive collection. Each wrapped command has a 60-second timeout in addition to the whole-run deadline. Missing optional commands produce partial status.

1. Native integrity preflight before broad reads: signed-executable manifests, vendor `sigchk`, portal checksum manifests and the portal checksum checker. Raw tool output and manifest copies require `-S`.
2. Volatile system metadata, targeted process-chain counts, deleted-executable PIDs and optional IOC correlation; broad raw process arguments only with `-S`.
3. NetScaler version and an aggregate Enhanced ISN query; extended read-only CLI queries only with `-S`.
4. Filesystem timeline, hard-link counts and post-boot change review.
5. Persistence, accounts, SUID/SGID, live/persistent HTTP configuration comparison, boot-loader inventory, unified-configuration account counts and aggregate exposure/precondition counts.
6. Webshell patterns, staged keys/configuration, image magic and temporary executables.
7. Log/core inventory; raw copies only with `-S`.
8. Rotated `ns.log`, `messages`, `nsvpn`, HTTP access/VPN/error and shell-log heuristics, including MAC_Veriexec failures. Default heuristic output omits raw lines, usernames and session IDs.
9. Live-source hash inventories; these are not an atomic filesystem snapshot.
10. Optional raw evidence tar and captured-content hashes.
11. Optional vendor support bundle, followed by verified outer packaging and checksum.

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
  support_bundle/          # sensitive vendor output only with --support-bundle
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

HTTP checks cover `/etc/httpd*.conf`, `/nsconfig/httpd*.conf`, and `/flash/nsconfig/httpd*.conf`. Alternate PHP extensions remain MEDIUM because clean same-build configurations can contain them. Explicit `php_flag engine on` and non-PHP `Files`/`FilesMatch` scopes using a PHP handler are HIGH investigation leads. Alias mismatches and live/persistent differences require baseline and change-record review.

The native integrity stage records tool and manifest SHA-256 values, command status and aggregate output in default mode. `sigchk check` labels reported paths as **unverified**, not necessarily modified: the clean 14.1-73.37 lab baseline reported 36 such vendor/VMware paths while verifying 1,177 of 1,213 checked binaries. Treat the path list as INFO and compare the same build. Exact MAC_Veriexec `no fingerprint` or `fingerprint does not match loaded value` messages are stronger HIGH investigation leads, but still require provenance and baseline review. With `-S`, raw tool/log lines and at most 25 implicated regular files of at most 20 MiB each enter the evidence workflow; automatic process memory dumping is never attempted.

The exposure summary counts configured gateway/authentication virtual servers; HTTP, SSL and HTTP_QUIC LB/CS/CR virtual servers; DTLS enablement; Oracle/FTP entries; and DNS64/LSN/NAT64 entries. These counts and the Enhanced ISN result identify configuration prerequisites only—they do not establish reachability, affected-version status, exploitation or compromise.

## Development and validation

```sh
dash -n ns_ir_collect.sh
bash -n ns_ir_collect.sh
shellcheck -s sh ns_ir_collect.sh
# Linux, Bubblewrap installed and user namespaces enabled:
NSIR_TEST_RESULTS=tests/results.json python3 tests/test_collector.py
```

The test runner executes the real script in a private synthetic filesystem and network namespace. FreeBSD and appliance commands are shimmed; these tests do not establish native compatibility. It exercises privacy defaults, opt-in raw collection, HTTP configuration variants, process/log chain markers, runtime IOC handling, aggregate exposure output, selected indicators, command failures, packaging/corruption/hash failures, unusual names, live-file changes, IPv6 handling, limits, interruption and concurrent runs. No fixture webshell or SUID marker is executed.

Before production use, validate the exact artifact on each target build, check clean-baseline findings, test all optional flags, and measure CPU, memory, disk use and duration under realistic load. Preserve disks and off-box logs as your incident-response procedure requires.

## References

- [Citrix CTX694799: suspected compromise response](https://support.citrix.com/external/article/CTX694799/steps-to-take-if-netscaler-adc-is-suspec.html)
- [NetScaler CVE-2025-5777 log guidance](https://www.netscaler.com/blog/news/evaluating-netscaler-logs-for-indicators-of-attempted-exploitation-of-cve-2025-5777/)
- [Original defensive guide](NETSCALER-DEFENSIVE-GUIDE.md): background research, not a verified compatibility or CVE-coverage guarantee for this collector.

## Changelog

- **1.4 (2026-09-28):** early NetScaler integrity checks and signed-manifest inventory, rotated MAC_Veriexec analysis, deleted-executable process metadata, timeline hard-link counts, and expanded boot/kernel/persistence collection.
- **1.3 (2026-09-28):** live and persistent HTTP configuration analysis, expanded rotated-log and process-chain detections, runtime IOC correlation, Enhanced ISN collection, and aggregate vulnerable-feature precondition counts.
- **1.2 (2026-09-27):** opt-in vendor support-bundle collection with bounded execution, provenance, integrity checks, and failure classification.
- **1.1 (2026-09-27):** metadata default, explicit sensitive mode, failure-safe packaging, captured-payload verification, aggregate statuses, bounded supervision, address parsing corrections and executable regression tests.
- **1.0 (2026-09-27):** initial release; validation found evidence-loss and secret-exclusion defects. Do not rely on its completion banner or private-key exclusion claim.
