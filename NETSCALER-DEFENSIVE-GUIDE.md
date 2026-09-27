# Hunting for Compromise on Citrix NetScaler (ADC / Gateway): A Practical Defensive Guide

## TL;DR
- **Patching is necessary but never sufficient.** Every major NetScaler intrusion class since 2023 — CVE-2023-3519 webshells, CVE-2023-4966 / CVE-2025-5777 / CVE-2026-3055 "CitrixBleed" memory leaks, and the 2025–2026 RCE chain (CVE-2025-6543, CVE-2025-7775, CVE-2026-8452, CVE-2026-19490) — leaves persistence (webshells, stolen session tokens, rogue accounts) that survives the patch and reboot. You must run a dedicated compromise assessment, not just verify the build number.
- **Use the authoritative toolchain in this order:** Fox-IT's `iocitrix.py` (offline Dissect triage of forensic disk images), the NCSC-NL `citrix-2025` live-host bash checks, the NetScaler Console built-in IoC detection, and the Mandiant CVE-2023-3519 IOC scanner for legacy cases — corroborated with `ns.log`/syslog analysis in your SIEM for session-hijack ("Client_ip ≠ Source") and memory-leak (non-ASCII bytes in AAA log lines) patterns.
- **If you find a webshell, rogue account, or hijacked session, treat the appliance as fully compromised:** isolate, preserve evidence (VPX snapshot + NSPPE core dump), rebuild from a clean image on latest firmware, rotate every secret the box touched (LDAP/RADIUS/OAuth/SAML, KEK, certificates, `nsroot`), and hunt laterally into AD/Entra ID for the identities that transited the gateway. Because these are internet-facing edge devices at a bank, assume attacker interest is high and prioritise accordingly.

---

## Key Findings

### The threat model: what drives NetScaler compromise hunting
NetScaler ADC/Gateway appliances sit at the network edge, terminate VPN/ICA/AAA authentication, and store credentials for back-end directories — making them a perennial top target.\[1\] Two distinct compromise classes dominate:

1. **Remote code execution → webshell/backdoor persistence.** The attacker executes code as root (`nobody`→root), drops a PHP webshell in a web-served directory, and often adds SUID shells, cron jobs or `rc.netscaler` modifications. Patching does **not** remove these. This is the CVE-2023-3519, CVE-2025-6543, CVE-2025-7775, and CVE-2026-8452 pattern.
2. **Memory disclosure → session-token theft → session hijack / MFA bypass.** The attacker repeatedly hits a pre-auth endpoint that leaks process memory, harvests valid session tokens/cookies, and replays them to ride authenticated sessions past MFA. This is the "CitrixBleed" family: CVE-2023-4966, CVE-2025-5777 (CitrixBleed 2), and CVE-2026-3055 (widely called "CitrixBleed 3"), plus the SAML-parser overread CVE-2026-8451.\[2\] These leave almost no on-box forensic trace, so detection shifts to logs and downstream systems.

A crucial, repeatedly-proven fact: after CVE-2023-3519, Fox-IT/NCC Group and DIVD reported (Aug 15, 2023, "Approximately 2000 Citrix NetScalers backdoored in mass-exploitation campaign") that as of August 14th, 1828 NetScalers remained backdoored and of those 1248 were already patched for CVE-2023-3519 — i.e. approximately 69% of the NetScalers that contained a backdoor were no longer vulnerable to CVE-2023-3519. Administrators fixed the CVE but never checked for the backdoor. That is the single most important behavioural lesson for a defender.

### The exploited CVEs and their defender artifacts

| CVE | Nickname / type | Config precondition | Primary defender artifacts to hunt |
|---|---|---|---|
| **CVE-2023-3519** | Unauth RCE (CVSS 9.8) | Gateway (VPN/ICA/CVPN/RDP) or AAA vserver | PHP webshells (e.g. `logouttm.php`); TGZ dropped to `/var/tmp`; data staged as image e.g. `cp /var/tmp/test.tar.gz /netscaler/ns_gui/vpn/medialogininit.png`; `/flash/nsconfig/rc.netscaler` appended with `chmod u+s /bin/sh` + `echo "<?php ... @eval($_REQUEST[...]) ?>"`; access to `/nsconfig/ns.conf` and `/flash/nsconfig/keys/updated/*`; deletion of `/etc/auth.conf` |
| **CVE-2023-4966** | CitrixBleed (info disclosure) | Gateway or AAA vserver | Session hijack: `ns.log` TCPCONNSTAT events with mismatched `Client_ip` vs `Source`; one source IP hitting many accounts; Citrix VDA registry `Evidence\ClientName`/`ClientIP`; NSPPE core-dump strings with 120,000+ chars of mostly "0"; WAF logs to `/oauth/idp/.well-known/openid-configuration` with oversized Host header |
| **CVE-2025-5777** | CitrixBleed 2 (out-of-bounds read, CVSS 9.3) | Gateway or AAA vserver | Non-ASCII/binary bytes inside `AAA Message`/"Authentication is rejected for" lines in `ns.log`; malformed POST to `/p/u/doAuthentication.do` with a bare `login` (no `=`); session token reuse across IPs; sessions existing with no corresponding login event |
| **CVE-2025-6543** | Unauth RCE (CVSS 9.2), zero-day | Gateway or AAA vserver | Unexpected `.php`/`.xhtml` files in `/var/netscaler/` (outside `admin_ui`); duplicate filenames with different extensions; anomalous file creation dates; new/elevated admin accounts; SUID `/var/tmp/sh`; `NSPPE*` core dumps; `python` in `/flash/nsconfig/rc.netscaler`; log wiping |
| **CVE-2025-7775** | Unauth RCE/DoS (CVSS 9.2), zero-day | Gateway/AAA, or LB HTTP/SSL/HTTP_QUIC bound to IPv6 services, or CR vserver type HDX | Post-exploit webshells; same file-system IOCs as 6543; Citrix published no IOCs, so rely on NCSC-NL/Fox-IT tooling |
| **CVE-2025-7776 / CVE-2025-8424 / CVE-2025-5349** | DoS / mgmt-interface access-control | Various (7776 needs PCoIP profile; 8424/5349 need mgmt-IP access) | Patched alongside the criticals; hunt mgmt-interface exposure and access anomalies |
| **CVE-2026-3055** | "CitrixBleed 3" memory overread (CVSS 9.3) | SAML Identity Provider (IdP) | Oversized Base64 `NSC_TASS` response cookie (legit < ~512 bytes; leak can exceed 4 KB); requests to `/saml/login` omitting `AssertionConsumerServiceURL`; `/wsfed/passive?wctx` with a valueless `wctx`; recon GETs to `/cgi/GetAuthMethods`; correlate with downstream IdP (Entra/Okta) credential reuse |
| **CVE-2026-8451** | Pre-auth SAML memory overread (CVSS 8.8) | SAML IdP | Crafted Base64 SAML `AuthnRequest` to `/saml/login`; leaked session cookies/memory; exploited within 24h of the June 30 2026 disclosure |
| **CVE-2026-8452** | SAML PrefixList heap overflow → pre-auth RCE (Citrix CVSS 8.8 / some feeds 9.8) | Gateway or AAA vserver (SAML SP/IdP flow) | Webshells `x.php` and `z.php` in `/var/vpn/theme/`; discovery commands `id`, `echo`, `uname -a`; oversized SAML `PrefixList` (>512 bytes) to `/saml/login` or `/cgi/samlauth`; `nsppe` crash / `signal 10`/`11` in `ns.log`, fresh `NSPPE-*` core in `/var/core/<n>/` |
| **CVE-2026-19490** | Authentication bypass, alternate path (CVSS 9.3) | Gateway or AAA vserver; SAML action on newer builds | Requests to `/cgi/samlauth`; `RelayState` base64 beginning with `ctx=`; probes to `/vpn/index.html`; treat as pre-auth foothold and hunt for follow-on webshells/accounts |

### Are the 2025 hunting scripts current for 2026?
As of late September 2026, the two most authoritative community tools had **not been formally refreshed** for the newest CVEs, but remain useful: the NCSC-NL `citrix-2025` repo was last updated in September 2025\[3\] (built for the 2025 campaign), and Fox-IT `citrix-netscaler-triage` was last updated November 17, 2025 with CVE tags stopping at the 2025 set.\[4\] Importantly, Fox-IT's `iocitrix.py` webshell path list already covers `/var/vpn/`, `/var/netscaler/ns_gui/` and `/var/netscaler/logon/`,\[5\] so it would very likely still flag the 2026 `x.php`/`z.php` drops in `/var/vpn/theme/` even without a 2026-specific update. Citrix's **NetScaler Console built-in IoC detection** feature does have dedicated 2026 remediation pages for CVE-2026-8452 and CVE-2026-19490.\[6\]

---

## Recommended tools and scripts

### 1. Fox-IT / NCC Group `citrix-netscaler-triage` (offline, forensically sound — preferred)
- **Repo:** `github.com/fox-it/citrix-netscaler-triage`. Two scripts:
  - **`iocitrix.py`** —\[7\]\[8\] a Dissect-based triage that runs against a **forensic disk image**, not the live box. Checks for: known webshell strings, suspicious PHP file permissions/contents (e.g. `array_filter(` in `/var/vpn/config.php`), timestomped files, suspicious cronjobs, and unknown SUID binaries (e.g. `/tmp/python/bash`). Emits confidence-rated hits (high/medium).
  - **`scan-citrix-netscaler-version.py`** — remote HTTP(S) version fingerprint that maps the build to vulnerable CVEs (covers CVE-2025-5349/5777/6543/7775/7776/8424), with JSON/CSV output.
- **How to run:**\[7\] image both block devices over SSH — `/dev/da0` (persistent `/var` + `/flash`) and `/dev/md0` (the volatile RAM root disk), e.g. `ssh nsroot@<IP> shell dd if=/dev/da0 bs=10M | tail -c +7 | head -c -6 > da0.img`, then `python3 iocitrix.py md0.img+da0.img`. Imaging `/dev/md0` is optional but recommended (it holds volatile IOCs). Install with\[9\] `pip install -r requirements.txt` plus `pip install --upgrade --pre dissect.volume dissect.target`.
- **Limitations:**\[7\]\[9\] Fox-IT explicitly warns it can produce false positives and false negatives — cross-check results. Requires the ability to image the appliance (best done on VPX via hypervisor snapshot).

### 2. NCSC-NL `citrix-2025` (live-host and image/core-dump checks)
- **Repo:** `github.com/NCSC-NL/citrix-2025`.\[10\] The live-host script (`live-host-bash-check/TLPCLEAR_check_script_cve-2025-6543-v1.8.sh`, v1.8.3) is deliberately **not CVE-specific** and includes post-compromise checks.\[11\] It logs:\[11\] PHP and XHTML files under `/var/netscaler/` (excluding `/var/netscaler/gui/admin_ui/`), a setuid shell at `/var/tmp/sh`, root-owned SUID files under `/var`, `NSPPE*` core dumps in `/var/core/` (low-confidence),\[11\] `python` references in `/flash/nsconfig/rc.netscaler`, and `httpd.conf` tampering (commented-out `Require all denied` / `php_flag engine off`, and alternate PHP handler extensions). The repo also contains `core-dump-checks` and `disk-image-checks` sets, plus YARA content.
- **How to run:** copy to the appliance and run in the shell; output goes to a timestamped `/var/log/custom_checks_*.log`. Kevin Beaumont confirmed NCSC-NL updated this script so it also detects webshells planted via the newer 2025 Citrix flaws.
- **Limitations:** running on the live host mutates the system slightly (writes a log) and is subject to attacker anti-forensics (they have been observed wiping traces). A "clean" result is not proof of innocence.

### 3. NetScaler Console IoC detection (vendor, built-in)
- Citrix's NetScaler Console (ADM) has an **Indicators of Compromise detection** feature with dedicated remediation pages for the 2026 CVEs (including CVE-2026-8452 and CVE-2026-19490).\[12\] It returns states such as *Potentially Compromised / No Compromise Detected / Skipped / Failed to Execute*. Citrix notes the detection logic is updated as new indicators emerge, so "No Compromise Detected" is not an absolute guarantee.

### 4. Mandiant IOC Scanner for CVE-2023-3519 (legacy, still valid for that vector)
- **Repo:** `github.com/mandiant/citrix-ioc-scanner-cve-2023-3519` (archived April 2026, read-only but usable). Bash scanner developed with Citrix; identifies known-malware file paths, post-exploitation shell-history activity, malicious terms and unexpected modifications in NetScaler directories, unexpected crontab entries and processes. Runs live (as root via `shell`) or against a mounted image.
- **Critical usage note:** download the **standalone build from the Releases tab** — do **not** clone the repo onto the NetScaler or you will generate false positives. Prefer offline analysis against a `dd` image. It does a best-effort job only: it will *not* catch every compromise and does *not* tell you if a device is vulnerable.

### 5. External version / vulnerability checks and PoC-based detectors
- **Nuclei templates (ProjectDiscovery):** `CVE-2025-5777.yaml` and `CVE-2026-3055.yaml` exist (both KEV-tagged, community-curated with watchTowr co-authorship); useful for fleet-wide *vulnerable/patched* fingerprinting. Note the project has iterated to reduce CVE-2025-5777 false positives — keep templates updated.
- **watchTowr "Detection Artifact Generator" scripts:** `watchtowrlabs/watchTowr-vs-Netscaler-CVE-2026-8451` and `watchtowrlabs/watchTowr-vs-Citrix-Netscaler-PreAuth-RCE-CVE-2026-8452` safely confirm exploitability (the 8452 tool actually writes a benign webshell at `/vpn/theme/x.php` and runs `uname -a;id` — use only with authorisation and clean up afterwards). Bishop Fox published safe external patch-state probes for CVE-2026-8452 and CVE-2026-19490.
- **`ns_log_scanner.py`** (RickGeex): detects non-text/binary bytes in `ns.log` files — a lightweight CitrixBleed-2 log triage aid.
- **CVE-2026-3055 scanners** (community + a Metasploit auxiliary module `scanner/http/citrix_netscaler_cve_2026_3055`) that\[13\] hit `/wsfed/passive?wctx` and inspect `NSC_TASS` for leaked `SESSID`/`NITRO_SK`/`NSC_AAAC` cookies.
- **Caution on all PoC-derived tools:** many "IOC/Sigma/WAF-rule" write-ups circulating for the 2026 CVEs are AI-generated aggregator content marked `experimental`; validate before deploying. Prefer vendor/CERT/Bishop Fox/watchTowr/Mandiant primary sources.

---

## Details: on-box forensic process

### Preserve evidence first (order matters)
Follow Citrix's own KB CTX694799 ("Steps to Take if NetScaler ADC is Suspected to be Compromised"):
1. \[14\]**Document** system time, timezone and NTP config before you touch anything; preserve remote syslog and NetScaler Console logs (local logs are small and rotate fast).
2. **VPX:**\[14\] take a hypervisor **snapshot** for forensics. **MPX/SDX:**\[14\] work with IR to power down after memory preservation, pull disks, and make bit-for-bit images with a write-blocker; keep two copies and a chain of custody.
3. **Generate a Packet Engine (NSPPE) core dump** *before* any reboot (for CitrixBleed-type memory analysis) and a **technical support bundle** (captures config, processes). Note: generating the core triggers a warm restart; copy dumps from `/var/core/<highest-N>/`, files begin `NSPPE-`. Citrix does not perform forensic investigations for you.

### Key file-system locations to collect and review
- **Web-served directories (webshell hunting):** `/netscaler/ns_gui/` (esp. `/vpn/`), `/var/netscaler/logon/LogonPoint/`, `/var/vpn/` and `/var/vpn/theme/` (2026 `x.php`/`z.php`), `/var/netscaler/` PHP/XHTML outside `admin_ui`. Any `.php` in these paths is inherently suspicious on an appliance.
- **Persistence:** `/flash/nsconfig/rc.netscaler` (boot autostart — look for `python`, `chmod u+s`, echoed PHP), cron/`crontab`, `/etc/rc*`.
- **Config & secrets:** `/nsconfig/ns.conf` (review for unexpected users, bindings, hidden connectivity), `/flash/nsconfig/keys/updated/*`, `.F1.key`/`.F2.key` (all three of ns.conf+F1+F2 together allow password decryption — watch for them being concatenated into one file, e.g. into `/var/vpn/themes/insight-new-min.js`), deletion of `/etc/auth.conf`.
- **Staging/scratch:** `/var/tmp` (TGZ payloads, `/var/tmp/sh` setuid), `/var/python`, `/tmp/python`.
- **Logs:** `/var/log/ns.log*`, `/var/log/*`, shell history, `nsbackup`, and `/var/core/` NSPPE dumps.

### What to look for
- **Webshells:** PHP files in web dirs; small one-liners using `eval($_REQUEST[...])`, `array_filter(`, `assert`, base64 blobs; world-readable perms (0644) on PHP that shouldn't exist; files whose mtime is timestomped or clusters around the intrusion window.
- **Modified/rogue binaries & SUID:** root-owned SUID files under `/var` (`find /var \( -perm -4001 -o \( -perm -4010 -group nobody \) \) -user root`), `/var/tmp/sh`, `/bin/sh` with SUID bit set.
- **New accounts / privilege changes:** unexpected admin/system accounts in `ns.conf`; accounts with elevated command policies.
- **Suspicious processes / network:** processes running as `nobody` spawning shells/interpreters; unexpected listeners or outbound C2; audit active TCP connections.
- **Memory / core-dump analysis (CitrixBleed):** collect `NSPPE-*` cores *before reboot*; Mandiant's one-liner `strings NSPPE-* | awk '{print length, $0}' | sort -n -r -s | cut -d" " -f2-` surfaces the abnormally long (120,000+ char, ~99% "0") strings from the leaked OAuth response, and FQDN placeholders replaced by long junk indicate exploitation. For CVE-2026-8452, cores contain long runs of a repeated letter followed by digits (leftover `PrefixList` payload) tying the crash to the bug.
- **Bishop Fox caveat for CVE-2026-8452:**\[15\]\[16\] a warm restart / new core does **not** by itself distinguish successful from failed exploitation (a failed attempt produced identical restart artifacts). Triage on **file-system evidence**, not on whether the box rebooted.

---

## Details: log-based and off-box detection

### `ns.log` / syslog analysis
NetScaler writes syslog to `/var/log/ns.log`.\[17\] Defaults are tiny (25 files × 100 KB ≈ 2.5 MB total per log type), so **externally collected syslog is essential** — on-box logs may only cover a few days, and attackers wipe them. Forward to your SIEM and retain.

- **CitrixBleed 2 (CVE-2025-5777) — memory-leak signature (NetScaler official guidance):** search for lines containing `"Authentication is rejected for"` AND `AAA Message` AND non-ASCII bytes (0x80–0xFF). Local one-liner:\[18\] `zcat ns.log.*.gz | awk -v FS='Authentication is rejected for ' '{if($1~/AAA Message/ && $2~/[\x80-\xff]/) print}'`. Non-ASCII bytes here indicate exploit attempts. Huntress corroborated this pattern in "Seven Steps to Ransomware: CitrixBleed 2 Weaponized by Initial Access Brokers" — one appliance's ns.log contained 5,937 AAA `LOGIN_FAILED` events sourced from the operator's IP addresses over a single ~5-hour window, every one carrying a bizarre, unprintable `User` value that was not nonsense but leaked heap memory. The reliable discriminator is\[19\] a **session that exists with no corresponding successful login**.
- **Session hijack (CVE-2023-4966 & CitrixBleed 2) — the canonical detection:** in `SSLVPN TCPCONNSTAT` events, compare `Client_ip` (IP that created the session) with `Source` (IP of the connection being logged). A mismatch, especially where the `Source` ASN/geo is suspicious, indicates session theft. Also flag\[17\] one source IP touching many user accounts within hours. Mandiant's caveat:\[17\] IP changes can be legitimate (Wi-Fi↔VPN), so enrich with ASN/geo and known-good baselines, and check whether the appliance logs true client IPs vs NAT.
- **CVE-2023-4966 endpoint:**\[17\] the vulnerable endpoint `/oauth/idp/.well-known/openid-configuration` is **not logged by the appliance's own webserver** — you need a WAF/reverse proxy/network probe in front to see the oversized-Host-header requests. (Citrix's WAF\[20\] did **not** detect CVE-2025-5777 exploitation, per Beaumont.)
- **CVE-2026-3055 / SAML overreads:** hunt WAF/syslog for\[21\] POSTs to `/saml/login` missing `AssertionConsumerServiceURL`; GETs to `/wsfed/passive?wctx` with a valueless `wctx`; recon to `/cgi/GetAuthMethods`; and **anomalously large `NSC_TASS` cookies** in responses (legit < ~512 bytes, leak > 4 KB). Pair NetScaler access logs with Entra ID/Okta sign-in logs to catch credential reuse within minutes of a suspected leak.

### SIEM query patterns
- **Splunk (session hijack, many accounts per source IP):**\[22\] Splunk's Security team published dedicated CitrixBleed 2 detections in "CitrixBleed 2: When Memory Leaks Become Session Hijacks" using exactly this "user accessing NetScaler from multiple distinct IPs" logic: `rex field=_raw "Client_ip\s+(?<client_ip>\d+\.\d+\.\d+\.\d+)" | stats count as auth_attempts, values(username) as users by client_ip | where auth_attempts > 10`, which Splunk describes as "the most direct evidence of active CitrixBleed 2 exploitation." Add a companion search comparing `Client_ip` vs `Source` per SessionId.
- **Microsoft Sentinel / KQL:** ingest NetScaler CEF/syslog, then correlate a NetScaler gateway sign-in with an Entra ID interactive/non-interactive sign-in for the same user from a different IP/ASN within a short window; alert on impossible travel and on gateway sessions with no preceding MFA challenge. (Community KQL exists; validate against your CEF field mapping.)
- **IDS/network:** flag NetScaler responses whose `<InitialValue>` tag or `NSC_TASS` cookie carries binary/oversized payloads; NetScaler published a Fortigate custom IPS signature concept matching bare `login` on `/p/u/doAuthentication.do`.

### Downstream / lateral-movement telemetry
Because memory-leak exploitation leaves little on the box, Mandiant scopes these investigations off-box:
- Review **Citrix VDA Windows registry** (`HKLM\SOFTWARE\Policies\Citrix\<session#>\Evidence\ClientName`/`ClientIP`, `BrokeringUserSid`) to recover the attacker's originating hostname (per\[17\] Mandiant, this can add confidence to suspicious sessions — e.g. when the recorded client hostname is a default Windows hostname like `DESKTOP-########`) and local IP, then pivot to Windows event logs (4624,\[17\] and Citrix 21/23/24/25).
- Correlate authentication/logon events from VDI/published systems against geo/ASN baselines, and\[23\] hunt logons where a successful MFA challenge was **not** logged.
- ReliaQuest and Huntress observed the post-hijack playbook. ReliaQuest ("Threat Spotlight: CVE-2025-5777: Citrix Bleed 2 Opens Old Wounds") assessed with medium confidence that attackers are actively exploiting the flaw for initial access, observing multiple instances of the `ADExplorer64.exe` tool querying domain-level groups and connecting to multiple domain controllers, and Citrix sessions originating from data-center-hosting IP addresses including those associated with DataCamp (consumer-VPN use). Huntress observed rogue local admin accounts (a fake "Citrix" admin), RMM tools (ScreenConnect, Zoho Assist), privilege escalation to SYSTEM, and DragonForce ransomware — CitrixBleed 2 is being weaponised by an initial-access broker feeding ransomware.

---

## Recommendations: incident response workflow

### Sequencing: patch, forensics, session-kill
1. **Restrict ingress immediately** to trusted source ranges; ensure the management interface (NSIP) is **not** internet-exposed (a\[14\] recurring root cause).
2. **Preserve evidence before remediation** if compromise is plausible (snapshot + NSPPE core + support bundle + off-box logs) — rebuilding destroys the memory/artifacts you need for scoping and for AD blast-radius analysis.
3. **Upgrade** all appliances in the HA pair/cluster to the fixed build.
4. **Kill sessions after upgrading the whole HA pair/cluster** (order matters — do it once all nodes are patched, or you re-expose). Review first with `show icaconnection` / PCoIP connections, then terminate:
   ```
   kill icaconnection -all
   kill rdp connection -all
   kill pcoipConnection -all
   kill aaa session -all
   clear lb persistentSessions
   ```
   Mandiant's Charles Carmakal stresses\[24\] killing sessions is essential after patching; Beaumont advises also clearing RDP/SSH/Telnet/Conn session types. (CVE-2025-6543 remediation adds the same session-kill set.)

### Credential rotation (assume everything the box touched is burned)
Because exploitation leaves scant logs, rotate as a precaution even without proof:\[12\] all **service-account passwords/secrets stored on the NetScaler** (LDAP bind, RADIUS shared secrets, OAuth tokens, API keys, SNMP community strings), all **user accounts that authenticated through** the Gateway/AAA vserver, and **revoke certificates + private keys** stored on the appliance. If SFA remote access exists anywhere, widen the rotation scope. After restoring a clean config, also change all local NetScaler passwords, rotate the **Key Encryption Keys (KEK)**, and replace the restored SSL certificates.

### When to rebuild vs. clean-in-place
If any webshell/backdoor/rogue account is found, **do not attempt surgical cleanup — rebuild.**\[14\]\[23\] Per Citrix CTX694799 and Mandiant: isolate → preserve → **rebuild from a clean-source image on the latest firmware** → restore only a **known-good config backup that pre-dates the compromise** (review the backup for backdoors first) → rotate restored secrets → harden per the NetScaler Secure Deployment Guide → **monitor closely for at least 90 days.** For VPX, replace/redeploy the instance; for MPX, follow the official wipe-and-reinstall; for SDX, remediate the affected VPX guests.

### Post-compromise lateral-movement hunt (internal network)
Treat the gateway as an initial-access point and pivot inward:
- Enumerate every identity provisioned to authenticate via the appliance; force password reset + re-registration of MFA where session/token theft is plausible.
- Hunt AD/Entra ID for: reconnaissance (`ADExplorer64.exe`, `net`, `nltest`, subnet-wide DNS/curl sweeps), new local/domain admin accounts, anomalous sign-ins lacking MFA, RMM tool installs, and lateral movement toward domain controllers.
- Investigate every back-end system the NetScaler connected to (auth servers, jump hosts, VDI, web tier). Correlate VDA registry evidence and Windows Event IDs 4624/21/23/24/25 to trace attacker sessions.

---

## Step-by-step hunting checklist

**A. Scope & inventory**
1. Enumerate all NetScaler ADC/Gateway instances and exact builds; map each to KEV CVEs (use `scan-citrix-netscaler-version.py` or Nuclei).
2. Identify config exposure per CVE: Gateway/AAA vserver? SAML IdP configured (`add authentication samlIdPProfile`/`samlAction`)? LB vserver bound to IPv6? Mgmt interface exposed?

**B. Preserve (if compromise plausible)**
3. Record time/NTP; pull off-box syslog + Console logs.
4. Snapshot VPX / image MPX-SDX; generate NSPPE core **before reboot**; grab support bundle.

**C. On-box / image triage**
5. Run `iocitrix.py` against the disk image (preferred), and/or the NCSC-NL live-host script; for legacy 3519 cases run the Mandiant scanner (standalone build, offline).
6. Manually check web dirs for PHP/XHTML (`/var/vpn/theme/`, `/netscaler/ns_gui/vpn/`, `/var/netscaler/logon/`); `/var/vpn/theme/x.php`,`z.php`.
7. Check `rc.netscaler`, cron, SUID files, `/var/tmp/sh`, `httpd.conf` tampering, new accounts in `ns.conf`, deleted `/etc/auth.conf`, concatenated ns.conf+F1+F2 key files.
8. Analyse NSPPE cores for CitrixBleed leak strings.

**D. Log / off-box hunt**
9. In SIEM: `Client_ip`≠`Source` mismatches; one IP → many users; sessions without logins; non-ASCII in AAA/"Authentication is rejected for" lines; oversized `NSC_TASS`; requests to `/oauth/idp/.well-known/openid-configuration`, `/p/u/doAuthentication.do`, `/saml/login`, `/wsfed/passive?wctx`, `/cgi/samlauth`, `/cgi/GetAuthMethods`.
10. Correlate gateway sessions with Entra ID/Okta/AD sign-ins (geo/ASN, missing MFA); check Citrix VDA registry + Windows 4624/21/23/24/25.

**E. Respond**
11. Restrict ingress; patch whole HA pair/cluster; kill all session types; rotate every secret; rebuild if any backdoor found; hunt laterally; monitor 90 days.

---

## Caveats, false positives and false negatives
- **Patched ≠ clean.**\[25\] The defining lesson of every NetScaler campaign: fixing the CVE does not evict an established webshell or a stolen, still-valid session token.
- **Memory-leak CVEs leave almost no on-box trace.**\[23\] Mandiant found no reliable on-appliance log of CVE-2023-4966 exploitation; detection depends on WAF/network logs and downstream systems. Absence of on-box evidence is not absence of compromise.
- **Log rotation & anti-forensics.** Tiny default `ns.log` sizes plus active trace-wiping (documented\[26\] by NCSC-NL for CVE-2025-6543) mean off-box syslog retention is often your only durable evidence.\[27\]
- **Tool limitations are explicit.** Fox-IT warns of false positives/negatives; Mandiant's scanner is best-effort and\[28\] will miss tampered/rebooted/rootkitted hosts, and cloning its repo onto the appliance *creates* false positives; Citrix Console "No Compromise Detected" is not a guarantee.
- **Session-IP heuristics cut both ways.** `Client_ip`≠`Source` and "many users per IP" both have legitimate explanations (roaming users, NAT, corporate egress) — enrich with ASN/geo and baselines to avoid false positives, but don't dismiss true positives.
- **2026 tooling lag.** The NCSC-NL and Fox-IT scripts had not been formally updated for the newest 2026 CVEs at the time of writing; they still catch the observed webshell drops by path, but verify you're on the latest revisions and supplement with vendor Console IoC checks.
- **PoC/AI-generated detections.** Much circulating 2026 Sigma/WAF/IOC content is unofficial and `experimental`; prefer Citrix, CISA, NCSC-NL, CERT-EU, Mandiant, Fox-IT, watchTowr and Bishop Fox primary sources, and validate rules before production.
- **Danish context (CFCS).** No CFCS (Center for Cybersikkerhed) advisory specifically covering the newest 2026 NetScaler CVEs was located as of late September 2026; for a Danish bank, rely on CISA KEV, NCSC-NL, CERT-EU and vendor advisories, and treat "no CFCS notice found" as provisional — check CFCS/FinansCERT channels directly.

## Sources

1. [CVE-2026-8452: Critical Citrix NetScaler Vulnerability Explained](https://thecybersecguru.com/news/cve-2026-8452-netscaler-vulnerability/)
2. [Citrix NetScaler Flaw CVE-2026-8451: 24-Hour Exploit](https://tech-insider.org/citrix-netscaler-cve-2026-8451/)
3. [Nationaal Cyber Security Centrum (NCSC-NL) · GitHub](https://github.com/NCSC-NL)
4. [citrix · GitHub Topics · GitHub](https://github.com/topics/citrix)
5. [citrix-netscaler-triage/iocitrix.py at main · fox-it/citrix-netscaler-triage](https://github.com/fox-it/citrix-netscaler-triage/blob/main/iocitrix.py)
6. [Indicators of Compromise detection in NetScaler Console](https://docs.netscaler.com/en-us/netscaler-console-service/instance-advisory/ioc.html)
7. [GitHub - fox-it/citrix-netscaler-triage: Dissect triage scripts for Citrix NetScaler devices · GitHub](https://github.com/fox-it/citrix-netscaler-triage)
8. [fox-it Exploits and Proofs of Concept - Exploit Intel](https://exploit-intel.com/author/5562100564302495)
9. [citrix-netscaler-triage/README.md at main · fox-it/citrix-netscaler-triage](https://github.com/fox-it/citrix-netscaler-triage/blob/main/README.md)
10. [GitHub - NCSC-NL/citrix-2025 · GitHub](https://github.com/NCSC-NL/citrix-2025)
11. [citrix-2025/live-host-bash-check/TLPCLEAR\_check\_script\_cve-2025-6543-v1.8.sh at main · NCSC-NL/citrix-2025](https://github.com/NCSC-NL/citrix-2025/blob/main/live-host-bash-check/TLPCLEAR_check_script_cve-2025-6543-v1.8.sh)
12. [NetScaler CVE-2026-8452: Affected Builds and Patch Check](https://thepulsesignal.com/updates/netscaler-cve-2026-8452/)
13. [CVE-2026-3055: Insufficient input validation leading to memory overread](https://exploit-intel.com/vuln/CVE-2026-3055)
14. [Steps to Take if NetScaler ADC is Suspected to be Compromised](https://support.citrix.com/external/article/CTX694799/steps-to-take-if-netscaler-adc-is-suspec.html)
15. [CVE-2026-8452](https://arcticwolf.com/resources/blog/citrix-netscaler-adc-gateway-critical-rce-vulnerability-cve-2026-8452/)
16. [Previously patched Citrix NetScaler flaw exploited in the wild (CVE-2026-8452) - Help Net Security](https://www.helpnetsecurity.com/2026/08/27/netscaler-adc-gateway-cve-2026-8452/)
17. [Investigation of Session Hijacking via Citrix NetScaler ADC and Gateway Vulnerability (CVE-2023-4966) | Google Cloud Blog](https://cloud.google.com/blog/topics/threat-intelligence/session-hijacking-citrix-cve-2023-4966/)
18. [Evaluating NetScaler logs for indicators of attempted exploitation of CVE-2025-5777](https://www.netscaler.com/blog/news/evaluating-netscaler-logs-for-indicators-of-attempted-exploitation-of-cve-2025-5777/)
19. [CitrixBleed 2 (CVE-2025-5777) 7Steps to Dragonforce Ransomware](https://www.huntress.com/blog/citrixbleed-2-dragonforce-ransomware)
20. [Citrix Bleed 2: A Critical Vulnerability Exposed Weeks Before Public Disclosure](https://ethicalhackingnews.substack.com/p/citrix-bleed-2-a-critical-vulnerability)
21. [Citrix NetScaler CVE-2026-3055 Memory Leak Threat](https://fyntralink.com/en/blog/cve-2026-3055-citrix-netscaler-saml-memory-leak-financial-gateways/)
22. [CitrixBleed 2: When Memory Leaks Become Session Hijacks](https://www.splunk.com/en_us/blog/security/citrixbleed-vulnerability-detection-mitigation.html)
23. [Security Advisory 2023-075](https://cert.europa.eu/publications/security-advisories/2023-075/)
24. [New 'CitrixBleed 2' NetScaler flaw let hackers hijack sessions](https://www.bleepingcomputer.com/news/security/new-citrixbleed-2-netscaler-flaw-let-hackers-hijack-sessions/)
25. [Critical Vulnerabilities in Citrix Netscaler ADC and Netscaler Gateway](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2023-097/)
26. [Netherlands: Citrix Netscaler flaw CVE-2025-6543 exploited to breach orgs](https://www.bleepingcomputer.com/news/security/netherlands-citrix-netscaler-flaw-cve-2025-6543-exploited-to-breach-orgs/)
27. [NCSC: Citrix NetScaler Flaw (CVE-2025-6543) is Being Actively Exploited to Breach Organizations](https://gbhackers.com/ncsc-citrix-netscaler-flaw-cve-2025-6543/)
28. [GitHub - mandiant/citrix-ioc-scanner-cve-2023-3519](https://github.com/mandiant/citrix-ioc-scanner-cve-2023-3519)
