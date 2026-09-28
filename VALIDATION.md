# Collector validation

## Collector v1.4 validation

Assessed 2026-09-28. The native-integrity, MAC_Veriexec, deleted-executable, hard-link timeline and expanded platform/persistence additions pass the isolated regression suite and focused native acceptance on NetScaler 14.1 build 73.37. This remains experimental and does not establish production-load or cross-build compatibility.

### Artifact and synthetic regression

- [Collector](ns_ir_collect.sh) v1.4 SHA-256: `0086588cfebbdfd31f81a2caca2a6a98243e022b332d3fd64ca11a4b3192ac99` on the host and guest.
- [Regression suite](tests/test_collector.py): 32 test methods and 36 fixture executions passed in 27.8 seconds. [Results](tests/results.json) identify the tested script hash.
- `sh -n` and `git diff --check` passed. ShellCheck was not installed, so no v1.4 ShellCheck result is claimed.
- Fixtures now cover signed-manifest hashing/copy gating, `sigchk` summary and path handling, portal-check output, rotated Veriexec failures, bounded implicated-file capture, orphan-process metadata, loader and unified-configuration collection, twelve-field timelines with `st_nlink`, and both native-stat and Python fallback formats.

The tests retain raw native-integrity command output, matching log lines, manifests, loader configuration, unified configuration and implicated files only with `-S`. Default fixtures retain summaries and paths but not raw command/log content. No fixture process is dumped.

### Native NetScaler 14.1-73.37 result

Target: `NetScaler-VPX-14.1-73.37-fresh`, UUID `e487f2ff-64ed-4e26-83d5-f4cfe966909e`, 4,096 MB RAM, 2 vCPUs and one host-only `vboxnet0` adapter. SSH reported **NetScaler NS14.1 build 73.37.nc**, dated September 25, 2026. No traffic feature, authentication policy or appliance configuration was changed.

The first native attempt exposed two FreeBSD 11 awk parser incompatibilities: a slash inside an awk character class in the existing process-marker check and a slash inside the new Veriexec helper-path expression. Both were rewritten without those character classes. The full synthetic suite passed again, and neither error appeared in the final native runs.

Metadata invocation:

```sh
sh /var/tmp/ns_ir_collect_v1.4.sh -o /var/tmp \
  -C V14_1_73_37_V14_NATIVE_FIXED -d 0 -k -t 600 -m 512
```

| Check | Observed |
| --- | --- |
| Duration / result | 52.5 seconds; exit 2 only because `kldstat` was absent (127) |
| Outer archive | 3,033,169 bytes; SHA-256 `c54943d3e31f6273accf5cb56675fb6d71fa197cb71264b2c58930aebf22f510`; independent readback matched |
| Timeline | 61,947 rows; 12 fields; native link count present and numeric |
| Signed manifests | `/netscaler`, `/var/python` and `/var/perl5` manifests present; SHA-256, byte count and line count recorded |
| Vendor `sigchk` | Exit 0; summary: 1,177 of 1,213 checked binaries verified; 36 paths reported as unverified |
| Portal checker | Exit 0; three output lines; zero failure-keyword lines |
| MAC_Veriexec | Zero matching integrity-failure log lines |
| Deleted executables | Zero `kern.proc.pathname` orphan PIDs |
| Platform metadata | `dmesg`, `sysctl security`, `sysctl netscaler` and `sysctl hw` all exited 0; default members retained only digest/count summaries |
| Persistence | Loader configuration hash/size recorded; unified configuration contained one system-account entry |
| Raw evidence | Absent, as required in metadata mode |

The 36 `sigchk` paths included boot, HSM and VMware components on this fresh appliance. They are therefore classified as INFO baseline-comparison leads, not integrity failures. The exact set is build/deployment dependent and is not promoted to an allowlist. The three signed-manifest hashes and loader hash are recorded in the native output but are not vendor attestations.

### Scoped sensitive validation

The first `-S -d 0` pass used the default 512 MiB limit. Stage 9 produced a structurally valid approximately 438 MiB evidence tar, but staging plus the growing compressed outer archive exceeded the combined monitored budget. The collector stopped, returned fatal resource-limit status and preserved staging. Its exact generated paths were removed after inspection.

The final pass increased only the output budget:

```sh
sh /var/tmp/ns_ir_collect_v1.4.sh -o /var/tmp \
  -C V14_1_73_37_V14_SENSITIVE_700 -S -d 0 -t 600 -m 700
```

| Check | Observed |
| --- | --- |
| Duration / result | 76.3 seconds; verified archive published with truthful partial status |
| Outer archive | 216,282,320 bytes; SHA-256 `bfd15b0688f475d19444ab5f0d86262ce18ec5a1cc32af3a023462cd535c1d0e`; independent readback matched |
| Structure | Outer gzip/tar valid; 144 outer members; staging removed after verified packaging |
| New raw outputs | Raw `sigchk`, portal-check, Veriexec, `dmesg` and scoped sysctl members present only under `-S` |
| New copied sources | All three signed manifests, `/flash/boot/loader.conf` and `/flash/nsconfig/unified.conf` present in the evidence tar |
| Inner evidence | Tar listing validated; source-before and captured hashes differed for one changing live file, correctly producing `evidence_changed_during_capture` |
| Expected partials | Missing `kldstat`; unlicensed/unconfigured CLI objects; absent crontabs; source files over the 20 MiB per-file cap; one changing source |

`lastlogin`, `lastcomm` and `atq` were unavailable on this appliance and were explicitly skipped. Automatic `gcore`, memory dumping and configuration changes were not attempted. The guest clock reported September 24 while the host assessment date was September 28, so guest-derived timestamps do not establish wall-clock UTC.

After recording these sanitized measurements, all task-generated staging directories, outer/partial archives, checksum sidecars, the temporary member list and the transferred collector were removed by exact path. No raw appliance evidence was exported or retained. The VM was powered off with its host-only network unchanged.

### Remaining v1.4 limits

`sigchk` reports unverified rather than necessarily modified files and requires a clean same-build comparison. Veriexec path extraction deliberately ignores malformed/concatenated records. Deleted-executable detection depends on the FreeBSD 11 `procstat` diagnostic format and records metadata only. Optional account/history commands vary by build. `-S` can require substantially more than the nominal evidence-tar size because both inner and outer archives coexist; size limits are sampled rather than hard quotas. The prior 120-day performance limitation, live-snapshot races, textual IPv6 limitations and lack of representative busy/HA/MPX/SDX validation remain.

## Collector v1.3 validation

Assessed 2026-09-28. The incident-response additions pass the isolated synthetic regression suite and native metadata plus scoped-sensitive acceptance on NetScaler 14.1 build 73.37. Broad 120-day sensitive collection exposed a performance limit described below. This remains experimental, not production-certified.

### Current artifact and tests

- [Collector](ns_ir_collect.sh) v1.3 SHA-256: `0c3f7cb6baa94a706c9743e957aea185cb779f94e407f32f58dc0bbfa4fbbb74`.
- [Regression suite](tests/test_collector.py): 32 test methods passed, comprising 36 fixture executions including failure subcases. [Results](tests/results.json) identify the tested script hash.
- `dash -n`, `bash -n`, and `git diff --check` passed. ShellCheck was not installed in this validation environment, so no v1.3 ShellCheck result is claimed.

New positive and negative fixtures exercise:

- `/etc`, `/nsconfig`, and `/flash/nsconfig` HTTP configuration inventory/copy coverage; active `php_flag engine on`; alternate PHP extensions; non-PHP `Files`/`FilesMatch` PHP handlers; static-looking aliases; and live/persistent differences.
- Process-chain counts for `ns_monuploadd_err.pl -WR`, decoder/IFS/staging markers, and descendant shells, while retaining raw matching arguments only with `-S`.
- Rotated `messages`, `nsvpn`, HTTP access/VPN/error and existing log families; packet-engine parser/crash sequences; command-stage markers; CSS receiver requests; Base64-like User-Agents; and HTTP daemon reloads.
- Runtime IPv4/IPv6 IOC-file validation and active-connection/log correlation. Mixed valid/invalid input fails closed. Default dedicated IOC results and flags contain counts rather than values; `-S` contains raw matching source lines. The supplied IOC file is excluded from the evidence tar.
- Aggregate Enhanced ISN, virtual-server, DTLS, Oracle, FTP, DNS64, LSN and NAT64 precondition output.
- The earlier clean-fixture behavior still passes, including the existing MEDIUM-only treatment of alternate PHP extensions and the default secret-exclusion regression.

The Linux test runner uses Bubblewrap with FreeBSD and NetScaler CLI shims. Native testing below adds evidence for one VPX build, not every appliance build or representative production workload.

### Native NetScaler 14.1-73.37 result

Target: `NetScaler-VPX-14.1-73.37-fresh`, UUID `e487f2ff-64ed-4e26-83d5-f4cfe966909e`, 4,096 MB RAM, 2 vCPUs, one host-only adapter on `vboxnet0`, management IP `192.168.56.10`. SSH reported **NetScaler NS14.1 build 73.37.nc**, dated September 25, 2026. No traffic feature, authentication policy, or appliance configuration was changed. The VM was powered off after cleanup.

The guest clock reported September 24 while the host assessment date was September 28. Guest-derived timestamps below therefore do not establish wall-clock UTC.

Metadata invocation:

```sh
sh /var/tmp/ns_ir_collect.sh -C V13-NATIVE-META \
  -i /var/tmp/nsir-test-iocs.txt -k -t 300 -m 512
```

| Check | Observed |
| --- | --- |
| Exact script hash | `0c3f7cb6baa94a706c9743e957aea185cb779f94e407f32f58dc0bbfa4fbbb74` on host and guest |
| Duration / result | 41 seconds; exit 2 only because `kldstat` was absent (127) |
| Outer archive | 3,445,159 bytes; SHA-256 `355f943ff032517c3b1fe9cc96de59a973f70cfbe8651c74905e1a04bc879492`; independent readback matched |
| Staging | 24,404 KiB; raw evidence tar absent as required |
| IOC input | One synthetic documentation-range IPv4 address; zero connection/log matches; source and normalized hashes recorded |
| HTTP configuration | One configuration inventoried; one alternate PHP-extension MEDIUM baseline; zero engine-on, non-PHP `Files` handler, suspicious alias, or live/persistent-difference hits |
| Processes and HTTP stages | Zero `-WR`, decoder/staging, descendant-shell, CSS receiver, Base64 User-Agent, or command-stage matches |
| Preconditions | Enhanced ISN disabled; all collected gateway/authentication, HTTP/SSL/HTTP_QUIC, DTLS, Oracle, FTP, DNS64, LSN, and NAT64 counts were zero |
| Baseline log signals | Three packet-engine parser/crash-chain lines (LOW) and seven HTTP reload lines (INFO); both require correlation |

Scoped sensitive invocation:

```sh
sh /var/tmp/ns_ir_collect.sh -S -d 0 -C V13-NATIVE-SENSITIVE-D0 \
  -i /var/tmp/nsir-test-iocs.txt -k -t 300 -m 1024
```

This completed in 55 seconds with exit 2. The verified outer archive was 212,096,262 bytes with SHA-256 `fe3fa0d9ff4fb0351c3ad93bba7f017a93dcd63039e0c595b3c9917b6da3a4d7`; staging was 455,414 KiB. It contained 252 evidence members, including the active HTTP configuration, and excluded the supplied IOC file. One live source changed during capture, so the pre-capture and captured-payload manifests differed and `evidence_changed_during_capture` was correctly recorded. Other partials were missing/feature-dependent CLI commands, unavailable root crontab, and files over the 20 MiB per-file evidence cap.

The new read-only CLI calls behaved as follows on this unlicensed clean appliance: `show ns tcpparam`, `show service`, `show serviceGroup`, and the DNS64 action/policy queries returned 0; CR and LSN queries returned 1 and were truthfully marked partial. Raw configuration, logs, evidence tar, and CLI output were not exported from the guest.

### Native defects found and corrected

Two initial native runs terminated in the appliance shell with signal 11. The first isolated a new `for ... | sort` HTTP-path pipeline; the second isolated grouped log-reader pipelines. v1.3 now uses temporary-file enumeration and named reader functions instead. Native awk also rejected an unescaped slash in a character class; that expression was corrected. All three changes pass the full synthetic suite and the final native runs above.

The initial staging-marker regex also matched legitimate `http*` log paths. It now requires a boundary after `/var/log/htt`; the final clean native run produced zero process staging-marker matches. Because the clean appliance itself contained packet-engine heartbeat/death and HTTP reload entries, standalone severity was calibrated to LOW and INFO respectively. Stronger command, HTTP-stage, process, and IOC matches remain independently HIGH.

### Remaining v1.3 limits

A default 120-day `-S` run reached its 600-second deadline during stage 9 and preserved staging as designed. The fresh image presented roughly 20,000 recent `/var/netscaler` and `/var/python` candidates; per-file source hashing did not finish within the deadline. `-S -d 0` validates sensitive capture and packaging but is not a substitute for optimizing or load-testing the broad default scope.

Textual IPv6 IOC matching does not canonicalize equivalent spellings. Configuration counts do not establish external reachability, and HIGH heuristic hits remain investigation leads rather than compromise verdicts. Native support-bundle integration was not repeated for v1.3. After sanitized results were recorded, all six run directories, published archives, partial packaging data, console logs, transferred scripts/helpers, and the synthetic IOC file were removed by exact path. No raw appliance collection was retained or exported.

## Collector v1.2 validation

Assessed 2026-09-27. The opt-in vendor support-bundle integration passed synthetic regressions and an end-to-end run on the isolated NetScaler 14.1 build 73.30 appliance. This remains experimental; production load and other deployment types are not validated.

## Current artifact and tests

- [Collector](ns_ir_collect.sh) v1.2 SHA-256: `1a5893abf71101af6b72329703ce2f59a35f3547e268cf86bda45aa4064f8ed6`.
- [Regression suite](tests/test_collector.py): 28 test methods passed, comprising 32 fixture executions including failure subcases. [Results](tests/results.json) identify the tested script hash.
- `dash -n`, `bash -n`, and ShellCheck 0.9.0 (`-s sh`) passed; `git diff --check` passed.
- New coverage: default non-invocation, independent sensitive opt-in, inner digest/content verification, unavailable collector, failed command, stale/missing/corrupt/out-of-directory archive, vendor timeout with continued packaging, invalid timeout, and vendor workspace size-limit enforcement.

The integration invokes `/netscaler/showtechsupport.pl -scope NODE` directly, with a separate generation timeout and explicit child termination on wrapper failure. It includes a newly generated, structurally checked vendor archive with checksum and provenance. Vendor data has its own opt-in and is not covered by the default metadata-only privacy contract. Existing vendor files are counted toward the support-mode resource budget and are never automatically deleted by the collector.

## Native support-bundle result

The same isolated appliance described in the historical baseline below was used. Final invocation from its shell:

```sh
sh /var/tmp/ns_ir_collect_support_test.sh --support-bundle --support-timeout=240 -t 420 -m 2048 -C SUPPORT-FINAL
```

[Sanitized native results](tests/native-support-result.json) record hashes, sizes, stage statuses, and counts. Raw archives, configuration, command output, and member names were not exported.

| Check | Observed |
| --- | --- |
| Installed vendor collector SHA-256 | `e5d44dd00990f15a6922f072f3b576c2b5d61eafe19505c5b297920633cb5d61` |
| Vendor command | Exit 0; support-bundle stage success |
| Vendor archive | 3,078,063 bytes; 265 tar entries |
| Vendor SHA-256 | `6f0800b4a6fe1d55a11a06cd2424b52f952e77b73abff1870ab56266c4c63b99` |
| Outer archive | 6,294,169 bytes |
| Outer SHA-256 | `03f58c3d46a383703dfe7dc72522fbda420b34661925c4e72f7ef0b58ebacbe7` |
| Independent readback | Outer checksum matched; nested bundle checksum and original vendor archive matched |
| IR raw evidence tar | Absent, because `-S` was not selected |
| Overall exit | 2; only partial event was missing `kldstat` (exit 127) |
| Guest collection timestamps | 06:18:18–06:19:11 on 2026-07-27, before final packaging; guest clock differs from host date |

Native long-option parsing also passed. An initial end-to-end integration run succeeded before the final missing-file classification and timeout-child cleanup refinements; the final run above exercised the revised artifact. Timeout/failure behavior is covered by synthetic tests, not a forced interruption of the native vendor collector. Archive integrity does not establish that every internal vendor diagnostic succeeded on the unlicensed appliance.

After verification, both runs' exact inventoried outer archives, vendor archives, generated links, logs, and transferred helpers were removed from the guest. No raw bundle was exported. Only sanitized validation metadata is retained.

## Remaining limits

Vendor filenames on this build have minute precision; pre-existing paths are rejected even if overwritten. Avoid concurrent vendor collections. Support generation can alter diagnostic state and retain sensitive vendor files; wrapper resource monitoring is sampled and includes the standard support directories. Other appliance builds, output layouts, HA/cluster orchestration, hardware platforms, busy workloads, and full `-S` plus support-bundle operation remain unverified. Default metadata behavior and the earlier failure regressions continue to pass.

## Collector v1.1 implementation and validation

Assessed on 2026-09-27. **The v1.0 defects have been fixed and regression-tested. Metadata-mode collection has completed on the local NetScaler VPX. This remains experimental, not production-certified.**

### Artifact

- [ns_ir_collect.sh](ns_ir_collect.sh), v1.1.
- SHA-256: `c73c861a7a58a68605406590d2731789e6429060f3bea8c72ee80b66e45b562a`.
- Previous v1.0 hash: `5ff4c397b76edbc37fb92d14b86e2a0d7b2ba95926928c554f5f28630e9bd78f`.
- [Original v1.0 assessment](../netscaler-2/validation_artifacts/collector-validation-20260927/VALIDATION.md) remains historical evidence; its defect reproductions are not acceptance tests for v1.1.

### Implemented changes

| Area | Result |
| --- | --- |
| Packaging | Inner and outer tar failures, corrupt archives and digest failures return fatal status and preserve staging. Final archive names are published only after verification. |
| Privacy | Default collection contains metadata/aggregate findings and no source evidence tar. `-S` is an explicit opt-in for raw sensitive material, including keys. `-c`/`-n` require it. |
| Completeness | Per-command errors and semantic CLI errors feed durable stage events and aggregate status. Empty/invalid timelines, unavailable commands and unrecognized address formats cannot silently pass. |
| Capture integrity | Captured-content hashes are distinct from pre-capture source hashes. Changes produce partial status. Inode aliases are recorded without duplicate hardlink payloads. |
| Operational limits | Exclusive staging names, whole-run deadline, per-command timeouts, sampled size/free-space monitoring, final capacity check and interruption preservation. Collector/child core dumps are disabled. |
| Detection | IPv4/IPv6 normalization, no blind IPv6 port stripping, actual Source-based user grouping, exact non-ASCII range, image signature/extension tolerance, anchored key headers and more cautious location-based flags. |
| Compatibility | Native Python 3 lstat adapter for the missing `stat` utility; shell-loop rewrites avoid constructs that reproduced a crash in this appliance's `/bin/sh`. Batched grep avoids one process per scanned file. |

### Automated regression evidence

The historical v1.1 regression run covered 21 cases, all passing against the v1.1 hash above. The linked test files and results now reflect the expanded v1.2 suite. `dash -n`, `bash -n` and ShellCheck 0.9.0 (`-s sh`) passed for the collector.

The unchanged collector entry point is run inside a Bubblewrap filesystem/network namespace using synthetic data. FreeBSD stat/sysctl and appliance commands are mocked; one case exercises the real embedded Python stat adapter. Host configuration, logs, home directories and process filesystems are not mounted. Fixture roots are deleted after each case.

Coverage includes:

- Default exclusion of a synthetic secret across configuration, SSL key, staged key, logs, history and persistence text.
- Explicit sensitive collection and independent verification of each captured payload hash.
- Seven HIGH detections from inert positive controls, with the generic writable-SUID lead separately classified MEDIUM.
- Final tar, inner tar, corrupt tar and final-hash failures.
- Empty timeline, absent CLI, and CLI errors returned with process exit 0.
- Equivalent IPv6 spellings, bracketed endpoints, ambiguous forms and actual Source-based grouping.
- Unsupported filenames, filenames with spaces and changes during capture.
- Global deadline, explicit interruption, output-size limit, free-space reserve, retained staging and concurrent runs.
- Library key-header strings and valid image signatures under a different extension do not reproduce the original false positives.

These fixtures do not prove coverage of every malicious filename, file race, disk failure, log format or intrusion technique.

### Native NetScaler run

Target: `NetScaler-VPX-14.1-73.30-fresh`, UUID `ef0a8395-4a0d-4ab8-a687-3361078604d2`, 4,096 MB RAM, 2 vCPUs, one host-only adapter on `vboxnet0`. SSH reported **NetScaler NS14.1 build 73.30.nc**, dated July 27, 2026. Management IP `192.168.56.10/24` was saved and activated by the appliance-requested reboot. No traffic features or authentication policy were changed.

Recovery snapshot: `collector-prevalidation-20260927`, UUID `249628a9-3dfb-41f9-903f-87eb3af97b1e`, taken before collector execution (after saving the management IP, before that reboot). Snapshot restoration was not exercised in this task.

Command from the appliance root shell:

```sh
/usr/bin/time -l sh /var/tmp/ns_ir_collect.sh -C LAB-VALIDATION -k -t 300 -m 512
```

| Measurement | Observed |
| --- | --- |
| Exit status | `2` — accurately reported partial collection |
| Partial reason | `kldstat` absent; `system/kldstat.txt` recorded exit 127 |
| Other stages | Successful, with explicit default-mode privacy skips |
| Wall / user / system time | 38.07 / 9.35 / 7.40 seconds |
| Maximum RSS reported by `time -l` | 24,668 KB; not an aggregate process-tree memory ceiling |
| Timeline | 60,015 rows; native boottime parsed |
| Staging disk usage | 23,900 KiB |
| Outer archive | 3,245,944 bytes, mode 0600 |
| Archive SHA-256 | `3f701bfacbf6db80abce4fa71367038ed9c3024581287367a799a05864837ef4` |
| Digest readback | Matched the generated checksum file |
| Raw source evidence tar | Absent, as required by default mode |
| Baseline flags | 0 HIGH, 6 MEDIUM, 1 INFO |

The guest clock read July 27, 2026 while the host validation date was September 27. The archive basename was `nsir_ns_20260727T053638Z.5Bd8Gb.tgz`. No claim is made that its guest-derived timestamp matches wall-clock UTC. Clock synchronization was not changed.

The six MEDIUM leads were a shipped writable-path `nsgslbautosync` process, writable SUID metadata on `nsprofmgmt.pid`, alternate PHP handler extensions, missing `auth.conf`, cron commands and temporary executable/archive paths. Test transport/diagnostic files can contribute to the final category. These observations establish this particular fresh lab baseline, not a universal allowlist or vendor assurance of benignness.

Earlier native attempts safely preserved staging after the missing-stat preflight and reproducible shell crashes. The stat adapter and affected loops were corrected. An intentionally stopped pre-batching run returned 143 and preserved staging. The final run above completed all stages. No packet-engine crash, exploit payload or deliberate availability test was used; the shell failures were collector-process failures. No collector `sh.core` was found at the checked standard candidate locations.

#### Additional native checks

[Native packaging check](tests/native_primitives.sh): NUL-separated tar input, an evidence filename with spaces, `tar -xO`, `cmp` and independent captured-payload SHA-256 all passed using harmless generated text.

[Native CLI check](tests/native_cli_check.sh): 29 read-only commands were exercised with output streamed into a status classifier; raw configuration/session output was not saved. Twenty-one returned 0. Eight returned 1 with feature-not-licensed warnings: IPv6PT, SSLVPN-related objects, LB, CS, RESPONDER and REWRITE. Full mode will report those queries as partial on this lab, rather than claiming their data was collected. Licensed gateway/HA/data-plane behavior remains untested.

### Cleanup

After recording sanitized stage summaries, counts, timings and digests, the task-generated appliance archives, staging directories, debug traces and transferred scripts were removed by their inventoried paths. A follow-up inventory found no remaining `nsir_*` entries in `/var/tmp`. No raw appliance collection was exported. The recovery snapshot and running isolated appliance were retained.

### Limits and release decision

The implemented reliability/privacy defects are covered by passing tests, and the selected metadata workflow is usable on this lab with a truthful missing-utility partial result. **Do not treat this as full production acceptance.**

- No full `-S` appliance collection was retained or exported; raw sensitive mode is tested with synthetic inputs. Native tar primitives and extended CLI status checks add compatibility evidence but do not replace an end-to-end full-mode run.
- Optional `-b`, `-c`, and `-n` have not been load-tested on the appliance. No busy gateway, large-log workload, HA pair, MPX or SDX was tested.
- Resource limits are sampled, not hard quotas; uninterruptible I/O, SIGKILL, power loss and extreme disk exhaustion remain outside the demonstrated recovery guarantee.
- Timeline/digests are live observations, not an atomic snapshot. The race test demonstrates one change-detection case, not all races.
- Actual gateway IPv6/session log-format coverage needs representative production-like fixtures. Ambiguous or unsupported formats deliberately produce partial status.
- No broad CVE fact-check or new vulnerability scan of the defensive guide was performed.

The collector's [README](README.md) documents the revised contract, exit statuses, limitations and operational prerequisites. Keep the experimental label until realistic-load and selected full-mode acceptance are completed under the relevant evidence-handling authorization.
