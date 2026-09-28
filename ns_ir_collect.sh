#!/bin/sh
# ns_ir_collect.sh - experimental NetScaler IR triage collector v1.4
# Usage: sh ns_ir_collect.sh [-o DIR] [-C CASE] [-d DAYS] [-i IOC_FILE] [-k] [-S] [-cnb]
#        [-t SECONDS] [-m MAX_MB] [-r RESERVE_MB]
#        [--support-bundle] [--support-timeout=SECONDS]
# --support-bundle permits a sensitive vendor archive independently of -S.
# Vendor diagnostics have side effects; files remain in vendor support dirs.
# --support-timeout=SECONDS: vendor deadline (default 600); -t still applies.
# Default: metadata and aggregate findings; no raw source files or log lines.
# -S explicitly permits sensitive forensic data, INCLUDING private keys,
# configuration, histories, process arguments and session material.
# -i accepts one IPv4/IPv6 indicator per line; values are not embedded in source.
# -c cores / -n performance logs require -S. -b hashes binary directories.
# -k keeps staging even after verified packaging. -h prints this help.
# Limits: 900 seconds, 512 MiB total output, 64 MiB free-space reserve.
# Total size/free-space checks are sampled every second, not hard quotas.
# Exit: 0 complete within selected scope, 2 partial, 1 fatal, 124 deadline.
# Signals return 128+signal. Failures preserve staging; no automatic retry.
# File reads can change atimes. Timeline precedes bulk content scanning,
# but follows script hashing and volatile/CLI collection. Not disk imaging.
# HIGH flags are investigation leads, not proof of successful compromise.

PATH=/sbin:/bin:/usr/sbin:/usr/bin:/usr/local/sbin:/usr/local/bin:/netscaler
export PATH
LC_ALL=C
export LC_ALL
umask 077
# Do not leave collector/child core dumps containing in-memory source data.
# shellcheck disable=SC3045 # FreeBSD sh and supported test shells provide -c.
ulimit -c 0
VERSION=1.4
OUTPARENT=/var/tmp
CASEID=unspecified
DAYS=120
COPY_CORES=0
COPY_NSLOG=0
HASH_BINS=0
KEEP_STAGING=0
SENSITIVE=0
SUPPORT_BUNDLE=0
SUPPORT_SECONDS=600
MAX_SECONDS=900
MAX_MB=512
RESERVE_MB=64
IOC_FILE=''
usage() { sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }
while getopts 'o:C:d:t:m:r:i:Scnbkh-:' opt; do
    case "$opt" in
        -) case "$OPTARG" in
            support-bundle) SUPPORT_BUNDLE=1;;
            support-timeout=*) SUPPORT_SECONDS=${OPTARG#*=};;
            *) echo "ERROR: unknown option --$OPTARG" >&2; exit 1;;
           esac;;
        o) OUTPARENT=$OPTARG;; C) CASEID=$OPTARG;; d) DAYS=$OPTARG;;
        t) MAX_SECONDS=$OPTARG;; m) MAX_MB=$OPTARG;; r) RESERVE_MB=$OPTARG;;
        i) IOC_FILE=$OPTARG;;
        S) SENSITIVE=1;; c) COPY_CORES=1;; n) COPY_NSLOG=1;;
        b) HASH_BINS=1;; k) KEEP_STAGING=1;; h) usage 0;; *) usage 1;;
    esac
done
# Keep the original argv for the supervised worker.
[ "$OPTIND" -gt "$#" ] || { echo 'ERROR: unexpected positional argument' >&2; exit 1; }
number() {
    case "$2" in ''|*[!0-9]*|?????????*) echo "ERROR: invalid $1" >&2; exit 1;; esac
    if [ "$2" -lt "$3" ] || [ "$2" -gt "$4" ]; then echo "ERROR: $1 out of range" >&2; exit 1; fi
}
number days "$DAYS" 0 36500
number seconds "$MAX_SECONDS" 1 86400
number support_seconds "$SUPPORT_SECONDS" 1 86400
# shellcheck disable=SC2003
SUPPORT_SECONDS=$(expr "$SUPPORT_SECONDS" + 0)
number max_mb "$MAX_MB" 1 1048576
number reserve_mb "$RESERVE_MB" 1 1048576
# Decimal normalization also avoids shell arithmetic treating 08 as octal.
# shellcheck disable=SC2003 # expr deliberately normalizes leading-zero decimal input.
DAYS=$(expr "$DAYS" + 0)
# shellcheck disable=SC2003
MAX_SECONDS=$(expr "$MAX_SECONDS" + 0)
# shellcheck disable=SC2003
MAX_MB=$(expr "$MAX_MB" + 0)
# shellcheck disable=SC2003
RESERVE_MB=$(expr "$RESERVE_MB" + 0)
if [ "$SENSITIVE" -eq 0 ] && { [ "$COPY_CORES" -eq 1 ] || [ "$COPY_NSLOG" -eq 1 ]; }; then
    echo 'ERROR: -c and -n require explicit sensitive collection (-S)' >&2; exit 1
fi
[ "$(id -u)" -eq 0 ] || { echo "ERROR: run as root from the NetScaler shell." >&2; exit 1; }
case "$CASEID" in *[!a-zA-Z0-9._-]*|'') echo 'ERROR: case ID must use letters, digits, dot, underscore or hyphen' >&2; exit 1;; esac
if [ -n "$IOC_FILE" ]; then
    [ -f "$IOC_FILE" ] || { echo 'ERROR: IOC file must be a readable regular file' >&2; exit 1; }
    IOC_FILE=$(realpath "$IOC_FILE") || { echo 'ERROR: cannot resolve IOC file' >&2; exit 1; }
    case "$IOC_FILE" in *[!\ -~]*|*'|'*) echo 'ERROR: unsupported IOC file path' >&2; exit 1;; esac
fi
case "$0" in /*) SELF=$0;; *) SELF=$(pwd)/$0;; esac
SELFBASE=$(basename "$SELF")
for tool in chmod realpath timeout mktemp tar awk find xargs sort grep sed tr wc df du sleep date cp mv rm cmp expr gzip; do
    command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: required utility missing: $tool" >&2; exit 1; }
done
timeout -k 1 1 sh -c ':' >/dev/null 2>&1 || { echo 'ERROR: compatible timeout utility required' >&2; exit 1; }
if command -v sha256 >/dev/null 2>&1; then HASHCMD='sha256 -r'
elif command -v sha256sum >/dev/null 2>&1; then HASHCMD=sha256sum
elif command -v openssl >/dev/null 2>&1; then HASHCMD='openssl dgst -sha256 -r'
else echo 'ERROR: SHA-256 utility required' >&2; exit 1
fi
hash1() {
    # Intentional splitting: HASHCMD is selected above, never user input.
    # shellcheck disable=SC2086
    _hash=$($HASHCMD "$1" 2>/dev/null) || return 1
    _hash=${_hash%% *}
    case "$_hash" in *[!0-9a-fA-F]*|'') return 1;; esac
    [ "${#_hash}" -eq 64 ] || return 1
    printf '%s\n' "$_hash"
}
# Include vendor workspace/archive bytes, even existing bundles, in the budget.
# These fixed locations can be on different filesystems from OUTPARENT.
resource_kb() {
    du -sk "$OUT" "$OUT.partial.tgz" "$ARCHIVE" "$OUT.packaging.log" "$OUT.members" 2>/dev/null
    if [ "$SUPPORT_BUNDLE" -eq 1 ]; then
        du -sk /var/tmp/support /flash/support 2>/dev/null
    fi
    return 0
}
free_kb() { if [ "$SUPPORT_BUNDLE" -eq 1 ]; then
        df -Pk "$OUTPARENT" /var/tmp /flash 2>/dev/null | awk 'NR>1 && $4 ~ /^[0-9]+$/ {if (!n++ || $4<m) m=$4} END {if(n==3) print m}'
    else
        df -Pk "$OUTPARENT" 2>/dev/null | awk 'END {if ($4 ~ /^[0-9]+$/) print $4}'
    fi; }
if [ -z "${NSIR_WORKDIR:-}" ]; then
    [ -d "$OUTPARENT" ] || { echo 'ERROR: output parent must already exist' >&2; exit 1; }
    OUTPARENT=$(cd "$OUTPARENT" && pwd -P) || exit 1
    if [ "$SUPPORT_BUNDLE" -eq 1 ]; then
        case "$OUTPARENT/" in /var/tmp/support/*|/flash/support/*)
            echo 'ERROR: choose an output parent outside vendor support directories' >&2; exit 1;;
        esac
    fi
    # Paths are metadata, but control bytes/delimiters would break manifests.
    case "$OUTPARENT" in *[!\ -~]*|*'|'*) echo 'ERROR: unsupported output path' >&2; exit 1;; esac
    HOST=$(hostname 2>/dev/null | tr -cd 'a-zA-Z0-9._-')
    TS=$(date -u +%Y%m%dT%H%M%SZ)
    OUT=$(mktemp -d "$OUTPARENT/nsir_${HOST:-unknown}_${TS}.XXXXXX") || exit 1
    ARCHIVE=$OUT.tgz
    printf 'Staging: %s\n' "$OUT" >&2
    AVAIL=$(free_kb)
    if [ -z "$AVAIL" ] || [ "$AVAIL" -lt "$((RESERVE_MB * 1024))" ]; then
        echo 'ERROR: cannot establish free-space reserve; staging preserved' >&2; exit 1
    fi
    NSIR_WORKDIR=$OUT timeout -k 5 "$MAX_SECONDS" sh "$SELF" "$@" &
    RUNNER=$!
    # shellcheck disable=SC2317 # Called by signal traps.
    stop() {
        trap '' INT TERM HUP
        kill -TERM "$RUNNER" 2>/dev/null || :
        [ -z "${MONITOR:-}" ] || kill "$MONITOR" 2>/dev/null || :
        wait "$RUNNER" 2>/dev/null || :
        echo "Interrupted; staging preserved: $OUT" >&2
        exit "$1"
    }
    trap 'stop 130' INT
    trap 'stop 143' TERM
    trap 'stop 129' HUP
    (
        while kill -0 "$RUNNER" 2>/dev/null; do
            USED=$(resource_kb | awk '{n += $1} END {print n+0}')
            AVAIL=$(free_kb)
            REASON=''
            if [ "$USED" -gt "$((MAX_MB * 1024))" ]; then REASON=output_size_limit
            elif [ -z "$AVAIL" ] || [ "$AVAIL" -lt "$((RESERVE_MB * 1024))" ]; then REASON=free_space_limit; fi
            if [ -n "$REASON" ]; then
                printf '%s\n' "$REASON" > "$OUT.limit"
                kill -TERM "$RUNNER" 2>/dev/null || :
                break
            fi
            sleep 1
        done
    ) &
    MONITOR=$!
    wait "$RUNNER"; RESULT=$?
    kill "$MONITOR" 2>/dev/null || :
    wait "$MONITOR" 2>/dev/null || :
    trap - INT TERM HUP
    # Catch a run that exceeded a size/reserve limit between monitor samples.
    USED=$(resource_kb | awk '{n += $1} END {print n+0}')
    AVAIL=$(free_kb)
    if [ "$USED" -gt "$((MAX_MB * 1024))" ] || [ -z "$AVAIL" ] || [ "$AVAIL" -lt "$((RESERVE_MB * 1024))" ]; then
        printf '%s\n' final_resource_limit > "$OUT.limit"
    fi
    if [ -f "$OUT.limit" ]; then
        echo "ERROR: resource limit reached; staging preserved: $OUT" >&2; exit 1
    fi
    case "$RESULT" in
        0|2)
            if [ ! -f "$ARCHIVE" ] || [ ! -s "$ARCHIVE.sha256" ]; then echo "ERROR: missing final output; staging preserved: $OUT" >&2; exit 1; fi
            [ "$KEEP_STAGING" -eq 1 ] || rm -rf -- "$OUT"
            [ -s "$OUT.packaging.log" ] || rm -f -- "$OUT.packaging.log"
            ;;
        *) echo "ERROR: collection stopped (exit $RESULT); staging preserved: $OUT" >&2;;
    esac
    exit "$RESULT"
fi
OUT=$NSIR_WORKDIR
unset NSIR_WORKDIR
[ -d "$OUT" ] && [ ! -L "$OUT" ] || exit 1
NAME=$(basename "$OUT")
OUTPARENT=$(dirname "$OUT")
ARCHIVE=$OUT.tgz
HOST=$(hostname 2>/dev/null || echo unknown)
for d in system netscaler_cli timeline hashes checks logs_analysis files; do mkdir "$OUT/$d" || exit 1; done
LOG=$OUT/00_collection.log
FLAGS=$OUT/00_TRIAGE_FLAGS.txt
COPYLIST=$OUT/.copylist
EVENTS=$OUT/00_stage_events.tsv
ERRORS=$OUT/.partial
STAGE=preflight
: > "$FLAGS"; : > "$COPYLIST"; : > "$ERRORS"; : > "$EVENTS"
status() { printf '%s\t%s\t%s\n' "$STAGE" "$1" "$2" >> "$EVENTS" || exit 1; }
partial() { printf '%s\t%s\n' "$STAGE" "$1" >> "$ERRORS" || exit 1; status partial "$1"; }
SUPPORT_RUNNER=''
fatal() {
    if [ -n "$SUPPORT_RUNNER" ]; then
        kill -TERM "$SUPPORT_RUNNER" 2>/dev/null || :
        wait "$SUPPORT_RUNNER" 2>/dev/null || :
        SUPPORT_RUNNER=''
    fi
    status failed "$1"; printf 'ERROR: %s; staging preserved: %s\n' "$1" "$OUT" >&2; exit 1; }
trap 'fatal interrupted_TERM' TERM
trap 'fatal interrupted_INT' INT
trap 'fatal interrupted_HUP' HUP
log() { printf '%s  %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" >> "$LOG" || exit 1; printf '[*] %s\n' "$*" >&2; }
flag() { printf '[%s] %s\n' "$1" "$2" >> "$FLAGS" || exit 1; }
stage() {
    [ "$STAGE" = preflight ] || status finished 'see events for completeness'
    STAGE=$1
    log "$*"
    status started "$1"
}
# Commands run independently. No unchecked multi-command pipelines in run().
run() {
    _rel=$1; shift
    _f=$OUT/$_rel
    { printf '# cmd: %s\n' "$*"; printf '# utc: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"; } > "$_f" || fatal output_write
    timeout -k 2 60 sh -c "$*" < /dev/null >> "$_f" 2>&1
    _rc=$?
    printf '\n# exit: %s\n' "$_rc" >> "$_f" || fatal output_write
    if [ "$_rc" -ne 0 ]; then partial "command_failed:$_rel:$_rc"; fi
    case "$_rel" in netscaler_cli/*)
        if grep -qiE '^[[:space:]]*(ERROR:|ERROR |Invalid command|Permission denied|Access denied)' "$_f"; then partial "cli_error:$_rel"; fi;;
    esac
}
# Run platform commands while preserving the default privacy boundary. Default
# mode retains provenance and a digest/count summary; -S retains command text.
run_platform() {
    _rel=$1; shift
    _f=$OUT/$_rel
    _raw=$OUT/.platform_command_raw
    timeout -k 2 60 sh -c "$*" < /dev/null > "$_raw" 2>&1
    _rc=$?
    {
        printf '# cmd: %s\n' "$*"
        printf '# utc: %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
        if [ "$SENSITIVE" -eq 1 ]; then
            cat "$_raw"
        else
            _rh=$(hash1 "$_raw") || _rh=unavailable
            printf 'output_sha256=%s\n' "$_rh"
            printf 'output_bytes=%s\n' "$(wc -c < "$_raw" 2>/dev/null || echo unavailable)"
            printf 'output_lines=%s\n' "$(wc -l < "$_raw" 2>/dev/null || echo unavailable)"
        fi
        printf '\n# exit: %s\n' "$_rc"
    } > "$_f" || fatal output_write
    rm -f "$_raw"
    if [ "$_rc" -ne 0 ]; then partial "command_failed:$_rel:$_rc"; fi
}
# grep's no-match is normal; operational errors are not. Used in pipelines too.
checked_grep() { grep "$@"; _grc=$?; [ "$_grc" -le 1 ] || partial grep_failed; return "$_grc"; }
# Scan only representable names; report omitted names separately before scans.
# Prune all collector runs, including concurrent/previous collections.
fx() {
    _d=$1; shift
    [ -e "$_d" ] || return 0
    find -H "$_d" -xdev \( -name 'nsir_*' -o -name '*[! -~]*' -o -name '*|*' \) -prune -o "$@"
    _frc=$?
    [ "$_frc" -eq 0 ] || partial find_failed
    return "$_frc"
}
add_copy_lines() {
    [ "$SENSITIVE" -eq 1 ] || return 0
    [ -s "$1" ] || return 0
    while IFS= read -r _p; do
        case "$_p" in /*) ;; *) partial invalid_copy_path; continue;; esac
        case "$_p" in *[!\ -~]*|*'|'*) partial unsupported_copy_path; continue;; esac
        if [ ! -f "$_p" ] || [ -L "$_p" ]; then continue; fi
        _sz=$(wc -c < "$_p" 2>/dev/null) || { partial copy_stat_failed; continue; }
        if [ "$_sz" -le 20971520 ]; then printf '%s\0' "$_p" >> "$COPYLIST" || fatal output_write
        else partial evidence_file_over_20MiB; fi
    done < "$1"
}
catlog() {
    case "$1" in *.gz) gzip -dc "$1" 2>/dev/null;; *) cat "$1" 2>/dev/null;; esac
    _crc=$?
    [ "$_crc" -eq 0 ] || partial log_read_failed
    return "$_crc"
}
# Default sinks retain counts, never raw log/config/history lines.
content_sink() {
    if [ "$SENSITIVE" -eq 1 ]; then cat; else awk 'END {print "matching_lines=" NR}'; fi
}
ioc_filter() {
    [ -n "$IOC_FILE" ] || return 0
    awk -v list="$OUT/.iocs_normalized" '
        BEGIN { while ((getline v < list) > 0) wanted[v] = 1; close(list) }
        {
            line = tolower($0)
            for (v in wanted) {
                boundary = index(v, ":") ? "[0-9a-f:.]" : "[0-9.]"
                start = 1
                while ((at = index(substr(line, start), v)) > 0) {
                    at += start - 1
                    before = at > 1 ? substr(line, at - 1, 1) : ""
                    after = substr(line, at + length(v), 1)
                    if (before !~ boundary && after !~ boundary) { print; next }
                    start = at + length(v)
                }
            }
        }'
}

if [ -n "$IOC_FILE" ]; then
    IOC_SOURCE_HASH=$(hash1 "$IOC_FILE") || fatal ioc_hash_failed
    awk '
        function ipv6(s, sides,n,l,r,a,b,i) {
            n = split(s, sides, "::"); if (n > 2) return 0
            l = sides[1] == "" ? 0 : split(sides[1], a, ":")
            r = n == 2 && sides[2] != "" ? split(sides[2], b, ":") : 0
            if ((n == 1 && l != 8) || (n == 2 && l + r >= 8)) return 0
            for (i = 1; i <= l; i++) if (a[i] == "" || length(a[i]) > 4 || a[i] !~ /^[0-9a-f]+$/) return 0
            for (i = 1; i <= r; i++) if (b[i] == "" || length(b[i]) > 4 || b[i] !~ /^[0-9a-f]+$/) return 0
            return 1
        }
        {
            bad = 0
            sub(/\r$/, ""); sub(/^[[:space:]]+/, ""); sub(/[[:space:]]+$/, "")
            if ($0 == "" || $0 ~ /^#/) next
            v = tolower($0)
            if (v ~ /^[0-9.]+$/) {
                n = split(v, a, ".")
                if (n != 4) bad = 1
                for (i = 1; i <= n; i++)
                    if (a[i] !~ /^[0-9]+$/ || length(a[i]) > 3 || a[i] + 0 > 255) bad = 1
            } else if (v ~ /^[0-9a-f:]+$/ && v ~ /:/) {
                if (!ipv6(v)) bad = 1
            } else bad = 1
            if (!bad) print v
            else { print "invalid IOC at line " NR > "/dev/stderr"; exit 2 }
        }' "$IOC_FILE" > "$OUT/.iocs_unsorted" || fatal invalid_ioc_file
    sort -u "$OUT/.iocs_unsorted" > "$OUT/.iocs_normalized" || fatal ioc_sort_failed
    rm -f "$OUT/.iocs_unsorted"
    [ -s "$OUT/.iocs_normalized" ] || fatal empty_ioc_file
    IOC_HASH_AFTER=$(hash1 "$IOC_FILE") || fatal ioc_hash_failed
    [ "$IOC_SOURCE_HASH" = "$IOC_HASH_AFTER" ] || fatal ioc_file_changed_during_load
    IOC_NORMALIZED_HASH=$(hash1 "$OUT/.iocs_normalized") || fatal ioc_hash_failed
fi
log "NetScaler IR collector v$VERSION -> $OUT (sensitive=$SENSITIVE)"
{
    echo "collector_version=$VERSION"
    echo "case_id=$CASEID"
    echo "hostname=$HOST"
    echo "utc_start=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "script_sha256=$(hash1 "$SELF")"
    echo "lookback_days=$DAYS"
    echo "sensitive=$SENSITIVE"
    echo "support_bundle=$SUPPORT_BUNDLE support_timeout_seconds=$SUPPORT_SECONDS"
    echo "limits_seconds=$MAX_SECONDS output_MiB=$MAX_MB reserve_MiB=$RESERVE_MB"
    echo "options=cores:$COPY_CORES nslog:$COPY_NSLOG hashbins:$HASH_BINS"
    if [ -n "$IOC_FILE" ]; then
        echo "ioc_file_sha256=$IOC_SOURCE_HASH"
        echo "ioc_normalized_sha256=$IOC_NORMALIZED_HASH"
        echo "ioc_count=$(wc -l < "$OUT/.iocs_normalized" | tr -d ' ')"
    else
        echo "ioc_count=0"
    fi
} > "$OUT/00_metadata.txt" || fatal metadata_write
hash1 "$SELF" >/dev/null || fatal script_hash_failed

# -------------------------------------- 0. native integrity preflight --
# Run vendor integrity tools before broad filesystem reads, hashing or copies.
# Some NetScaler builds emit Veriexec messages when executables are read.
stage integrity "native integrity preflight"
: > "$OUT/checks/native_signed_manifests.txt"
: > "$OUT/.native_manifest_paths"
for manifest in /netscaler/.signedexe.manifest /var/python/.signedexe.manifest /var/perl5/.signedexe.manifest; do
    if [ -f "$manifest" ] && [ ! -L "$manifest" ]; then
        mh=$(hash1 "$manifest") || { partial native_manifest_hash_failed; continue; }
        mb=$(wc -c < "$manifest" 2>/dev/null) || { partial native_manifest_size_failed; continue; }
        ml=$(wc -l < "$manifest" 2>/dev/null) || { partial native_manifest_count_failed; continue; }
        printf '%s\tsha256=%s\tbytes=%s\tlines=%s\n' "$manifest" "$mh" "$mb" "$ml" \
            >> "$OUT/checks/native_signed_manifests.txt" || fatal output_write
        printf '%s\n' "$manifest" >> "$OUT/.native_manifest_paths" || fatal output_write
    else
        printf '%s\tpresent=0\n' "$manifest" >> "$OUT/checks/native_signed_manifests.txt" || fatal output_write
    fi
done
add_copy_lines "$OUT/.native_manifest_paths"

: > "$OUT/checks/native_integrity_tools.txt"
native_integrity_check() {
    _label=$1; _tool=$2; _arg=${3:-}; _raw=$OUT/.$_label.raw
    if [ ! -x "$_tool" ]; then
        printf 'present=0\n' > "$OUT/checks/$_label.txt" || fatal output_write
        status skipped "native integrity tool unavailable:$_tool"
        return 0
    fi
    _th=$(hash1 "$_tool") || { partial "native_tool_hash_failed:$_label"; _th=unavailable; }
    printf '%s\tsha256=%s\n' "$_tool" "$_th" >> "$OUT/checks/native_integrity_tools.txt" || fatal output_write
    if [ -n "$_arg" ]; then
        timeout -k 2 120 "$_tool" "$_arg" < /dev/null > "$_raw" 2>&1
    else
        timeout -k 2 120 "$_tool" < /dev/null > "$_raw" 2>&1
    fi
    _rc=$?
    _lines=$(wc -l < "$_raw" 2>/dev/null || echo 0)
    _paths=$(awk '/^\// {n++} END {print n+0}' "$_raw")
    _fail=$(grep -aiEc 'mismatch|failed|invalid|corrupt|not[[:space:]]+match|error' "$_raw" 2>/dev/null || :)
    {
        echo 'present=1'
        echo "tool_sha256=$_th"
        echo "exit=$_rc"
        echo "output_lines=${_lines:-0}"
        echo "absolute_path_lines=${_paths:-0}"
        echo "failure_keyword_lines=${_fail:-0}"
    } > "$OUT/checks/$_label.txt" || fatal output_write
    if [ "$_label" = sigchk_check ]; then
        grep -aE '^summary:' "$_raw" | tail -n 1 >> "$OUT/checks/$_label.txt" 2>/dev/null || :
        awk '/^\// && $0 !~ /[|[:cntrl:]]/ {print}' "$_raw" | sort -u \
            > "$OUT/checks/sigchk_unverified_paths.txt" || fatal output_write
    fi
    if [ "$SENSITIVE" -eq 1 ]; then
        mv "$_raw" "$OUT/checks/${_label}_raw.txt" || fatal output_write
    else
        rm -f "$_raw"
    fi
    if [ "$_rc" -ne 0 ]; then partial "native_integrity_command_failed:$_label:$_rc"; fi
}

native_integrity_check sigchk_check /netscaler/sigchk check
[ -f "$OUT/checks/sigchk_unverified_paths.txt" ] || : > "$OUT/checks/sigchk_unverified_paths.txt"
SIGCHK_HITS=$(wc -l < "$OUT/checks/sigchk_unverified_paths.txt" | tr -d ' ')
[ "${SIGCHK_HITS:-0}" -eq 0 ] || flag INFO "$SIGCHK_HITS path(s) are unverified according to vendor sigchk; compare a clean same-build baseline - checks/sigchk_unverified_paths.txt"

: > "$OUT/checks/portal_checksum_manifests.txt"
: > "$OUT/.portal_manifest_paths"
for portal_manifest in /var/netscaler/logon/LogonPoint/checksum_*.txt; do
    [ -f "$portal_manifest" ] && [ ! -L "$portal_manifest" ] || continue
    ph=$(hash1 "$portal_manifest") || { partial portal_manifest_hash_failed; continue; }
    pb=$(wc -c < "$portal_manifest" 2>/dev/null) || { partial portal_manifest_size_failed; continue; }
    printf '%s\tsha256=%s\tbytes=%s\n' "$portal_manifest" "$ph" "$pb" \
        >> "$OUT/checks/portal_checksum_manifests.txt" || fatal output_write
    printf '%s\n' "$portal_manifest" >> "$OUT/.portal_manifest_paths" || fatal output_write
done
add_copy_lines "$OUT/.portal_manifest_paths"
native_integrity_check portal_core_checksum_check /netscaler/portal_core_checksum_check.pl
PORTAL_FAIL=$(sed -n 's/^failure_keyword_lines=//p' "$OUT/checks/portal_core_checksum_check.txt")
[ "${PORTAL_FAIL:-0}" -eq 0 ] || flag MEDIUM "$PORTAL_FAIL portal checksum result line(s) contain failure keywords; inspect raw output with -S"

# Some ADC builds omit stat. Use an isolated Python 3 lstat adapter when available.
STAT=$(command -v stat 2>/dev/null || :)
if [ -z "$STAT" ]; then
    PYTHON=''
    for candidate in /var/python/bin/python3 /usr/local/bin/python3 /usr/bin/python3; do
        if [ -x "$candidate" ]; then PYTHON=$candidate; break; fi
    done
    [ -n "$PYTHON" ] || fatal stat_and_python3_unavailable
    STAT=$OUT/.stat-helper
    printf '#!%s -I\n' "$PYTHON" > "$STAT" || fatal stat_adapter_write
    cat >> "$STAT" <<'PY_STAT'
import os
import stat
import sys
if len(sys.argv) < 4 or sys.argv[1] != '-f':
    sys.exit(1)
fmt = sys.argv[2]
rc = 0
for path in sys.argv[3:]:
    try:
        st = os.lstat(path)
        if fmt == '%d:%i':
            print('%d:%d' % (st.st_dev, st.st_ino))
        elif fmt == '%m':
            print(int(st.st_mtime))
        elif fmt == '0|%N|%i|%l|%Sp|%u|%g|%z|%a|%m|%c|%B':
            print('|'.join(map(str, [0, path, st.st_ino, st.st_nlink,
                stat.filemode(st.st_mode), st.st_uid, st.st_gid, st.st_size, int(st.st_atime),
                int(st.st_mtime), int(st.st_ctime), int(getattr(st, 'st_birthtime', 0))])))
        else:
            rc = 1
    except OSError:
        rc = 1
sys.exit(rc)
PY_STAT
    chmod 700 "$STAT" || fatal stat_adapter_permissions
    echo 'stat_backend=python3_lstat' >> "$OUT/00_metadata.txt"
else
    echo 'stat_backend=native_stat' >> "$OUT/00_metadata.txt"
fi
# Reject unsupported native stat before interpreting timeline fields.
"$STAT" -f '0|%N|%i|%l|%Sp|%u|%g|%z|%a|%m|%c|%B' "$SELF" > "$OUT/.stat_probe" 2>/dev/null || fatal incompatible_stat
awk -F'|' 'NF != 12 || $3 !~ /^[0-9]+$/ || $4 !~ /^[0-9]+$/ {bad=1} END {exit bad || NR == 0}' "$OUT/.stat_probe" || fatal incompatible_stat
rm "$OUT/.stat_probe"

scan_pattern() {
    # Batch paths; one grep per file is prohibitively expensive on a VPX.
    # shellcheck disable=SC2016 # Expansion belongs to the child shell.
    xargs -0 sh -c '
        pattern=$1; events=$2; errors=$3; stage=$4; shift 4
        [ "$#" -gt 0 ] || exit 0
        grep -lIE "$pattern" -- "$@"
        rc=$?
        if [ "$rc" -gt 1 ]; then
            printf "%s\tgrep_failed\n" "$stage" >> "$errors" || exit 1
            printf "%s\tpartial\tgrep_failed\n" "$stage" >> "$events" || exit 1
        fi
        exit 0
    ' sh "$1" "$EVENTS" "$ERRORS" "$STAGE" || partial pattern_scan_failed
}

# ------------------------------------------------ 1. volatile system state --
stage 1 "volatile system state"
run system/date.txt "date -u"
run system/uptime.txt "uptime"
run system/boottime.txt "sysctl kern.boottime"
run_platform system/dmesg.txt "dmesg"
run_platform system/sysctl_security.txt "sysctl security"
run_platform system/sysctl_netscaler.txt "sysctl netscaler"
run_platform system/sysctl_hw.txt "sysctl hw"
if [ "$SENSITIVE" -eq 1 ]; then
    run system/ps_full.txt "ps auxwwww"
    run system/ps_tree.txt "ps -axwwo pid,ppid,user,lstart,etime,state,command"
else
    run system/ps_metadata.txt "ps -axwwo pid,ppid,user,lstart,etime,state,comm"
    status skipped 'raw process arguments excluded by default'
fi
run system/procstat_bin.txt  "procstat -b -a"
run system/sockstat.txt      "sockstat -46"
run system/sockstat_listen.txt "sockstat -46l"
run system/netstat_an.txt    "netstat -an"
run system/netstat_rn.txt    "netstat -rn"
run system/arp.txt           "arp -an"
run system/ifconfig.txt      "ifconfig -a"
run system/logged_in.txt "who"
run system/last.txt "last -n 2000"
run system/fstat.txt         "fstat"
run system/kldstat.txt       "kldstat -v"
run system/mount.txt "mount"
run system/df.txt "df -h"
run system/ntp.txt "ntpq -pn"
if [ "$SENSITIVE" -eq 1 ]; then
    run system/ntp_config.txt "cat /etc/ntp.conf"
    for optional_cmd in lastlogin lastcomm atq; do
        if command -v "$optional_cmd" >/dev/null 2>&1; then
            run "system/${optional_cmd}.txt" "$optional_cmd"
        else
            status skipped "optional command unavailable:$optional_cmd"
        fi
    done
else
    status skipped 'lastlogin, lastcomm and atq output excluded by default'
fi

# Interpreters / shells / network tools running as the web server user.
ps -axwwo user,pid,ppid,comm 2>/dev/null | awk '
    NR > 1 && $1 == "nobody" {
        n = split($4, p, "/"); b = p[n]; sub(/^-/, "", b)
        if (b ~ /^(sh|bash|csh|tcsh|zsh|python[0-9.]*|perl[0-9.]*|php|nc|ncat|socat|curl|wget|fetch|telnet)$/) print
    }' > "$OUT/checks/procs_nobody_interpreters.txt"
[ -s "$OUT/checks/procs_nobody_interpreters.txt" ] && \
    flag HIGH "Shell/interpreter/network tool running as 'nobody' (web user) - checks/procs_nobody_interpreters.txt"

checked_grep -E '[[:space:]](/var/tmp|/tmp|/var/vpn|/var/netscaler|/netscaler/ns_gui)/' \
    "$OUT/system/procstat_bin.txt" > "$OUT/checks/procs_from_writable_paths.txt" 2>/dev/null
[ -s "$OUT/checks/procs_from_writable_paths.txt" ] && \
    flag MEDIUM "Process executing from a writable/web path; compare same-build baseline - checks/procs_from_writable_paths.txt"

# procstat reports a kern.proc.pathname error when a running executable has
# been deleted or is otherwise no longer retrievable. Preserve PIDs/metadata;
# never attempt automatic process memory dumping.
awk '
    {
        line=$0
        while (match(line, /kern\.proc\.pathname: [0-9][0-9]*:/)) {
            hit=substr(line, RSTART, RLENGTH)
            sub(/^.*: /, "", hit); sub(/:$/, "", hit)
            print hit
            line=substr(line, RSTART + RLENGTH)
        }
    }' "$OUT/system/procstat_bin.txt" | sort -nu > "$OUT/checks/orphan_executable_pids.txt"
ORPHAN_COUNT=$(wc -l < "$OUT/checks/orphan_executable_pids.txt" | tr -d ' ')
: > "$OUT/checks/orphan_executable_process_metadata.txt"
if [ "${ORPHAN_COUNT:-0}" -gt 0 ]; then
    ps -axwwo pid,ppid,user,lstart,etime,state,comm 2>/dev/null | \
        awk 'NR==FNR {wanted[$1]=1; next} FNR==1 || ($1 in wanted)' \
        "$OUT/checks/orphan_executable_pids.txt" - \
        > "$OUT/checks/orphan_executable_process_metadata.txt"
    flag MEDIUM "$ORPHAN_COUNT running process(es) have no retrievable executable pathname - checks/orphan_executable_process_metadata.txt"
fi

# Inspect arguments for a narrow set of high-signal execution-chain markers.
# Default output is a count only; -S retains matching process records.
ps -axwwo pid,ppid,user,command 2>/dev/null | awk '
    NR > 1 {
        line = $0; low = tolower(line)
        if (low ~ /ns_monuploadd_err\.pl/ && low ~ /(^|[[:space:]])-wr([[:space:]]|$)/) print line
    }' | content_sink > "$OUT/checks/procs_monuploadd_wr.txt"
if [ "$SENSITIVE" -eq 1 ]; then PROC_WR=$(wc -l < "$OUT/checks/procs_monuploadd_wr.txt")
else PROC_WR=$(sed 's/^matching_lines=//' "$OUT/checks/procs_monuploadd_wr.txt"); fi
[ "${PROC_WR:-0}" -eq 0 ] || flag HIGH "$PROC_WR ns_monuploadd_err.pl -WR process(es) observed - checks/procs_monuploadd_wr.txt"

ps -axwwo pid,ppid,user,command 2>/dev/null | awk '
    NR > 1 {
        line = $0; low = tolower(line)
        if (low ~ /b64decode|\$\{ifs\}|\/var\/log\/htt(\/|[[:space:]]|$)/) print line
    }' | content_sink > "$OUT/checks/procs_decoder_or_staging_markers.txt"
if [ "$SENSITIVE" -eq 1 ]; then PROC_STAGE=$(wc -l < "$OUT/checks/procs_decoder_or_staging_markers.txt")
else PROC_STAGE=$(sed 's/^matching_lines=//' "$OUT/checks/procs_decoder_or_staging_markers.txt"); fi
[ "${PROC_STAGE:-0}" -eq 0 ] || flag HIGH "$PROC_STAGE process(es) contain decoder/IFS/staging markers - checks/procs_decoder_or_staging_markers.txt"

ps -axwwo pid,ppid,user,command 2>/dev/null | awk '
    NR > 1 {
        pid = $1; parent[pid] = $2; user[pid] = $3
        cmd = ""; for (i = 4; i <= NF; i++) cmd = cmd (i == 4 ? "" : " ") $i
        command[pid] = cmd; low = tolower(cmd)
        if (low ~ /ns_monuploadd_err\.pl/ && low ~ /(^|[[:space:]])-wr([[:space:]]|$)/) runner[pid] = 1
    }
    END {
        for (pid in command) {
            first = command[pid]; sub(/[[:space:]].*$/, "", first); sub(/^.*\//, "", first); sub(/^-/, "", first)
            if (tolower(first) !~ /^(sh|bash|csh|tcsh|zsh)$/) continue
            p = parent[pid]; depth = 0
            while (p != "" && p != "0" && depth++ < 64) {
                if (runner[p]) { print pid, parent[pid], user[pid], command[pid]; break }
                p = parent[p]
            }
        }
    }' | content_sink > "$OUT/checks/procs_wr_descendant_shells.txt"
if [ "$SENSITIVE" -eq 1 ]; then PROC_CHILD=$(wc -l < "$OUT/checks/procs_wr_descendant_shells.txt")
else PROC_CHILD=$(sed 's/^matching_lines=//' "$OUT/checks/procs_wr_descendant_shells.txt"); fi
[ "${PROC_CHILD:-0}" -eq 0 ] || flag HIGH "$PROC_CHILD shell process(es) descend from ns_monuploadd_err.pl -WR - checks/procs_wr_descendant_shells.txt"

if [ -n "$IOC_FILE" ]; then
    cat "$OUT/system/sockstat.txt" "$OUT/system/netstat_an.txt" 2>/dev/null | ioc_filter | content_sink \
        > "$OUT/checks/ioc_active_connection_hits.txt"
    if [ "$SENSITIVE" -eq 1 ]; then IOC_ACTIVE=$(wc -l < "$OUT/checks/ioc_active_connection_hits.txt")
    else IOC_ACTIVE=$(sed 's/^matching_lines=//' "$OUT/checks/ioc_active_connection_hits.txt"); fi
    [ "${IOC_ACTIVE:-0}" -eq 0 ] || flag HIGH "$IOC_ACTIVE active-connection line(s) matched the runtime IOC file - checks/ioc_active_connection_hits.txt"
fi

# ------------------------------------------------------ 2. NetScaler CLI --
stage 2 "NetScaler CLI state"
CLI_CMDS='ns_version|show ns version
ns_hardware|show ns hardware
ns_hostname|show ns hostName
ns_config|show ns config
ha_node|show ha node
ns_ip|show ns ip
ns_ip6|show ns ip6
running_config|show ns runningConfig
diff_running_vs_saved|diff ns config
ns_features|show ns feature
ns_modes|show ns mode
ns_tcpparam|show ns tcpparam
system_users|show system user
system_groups|show system group
system_cmdpolicies|show system cmdPolicy
system_sessions|show system session
aaa_sessions|show aaa session
vpn_vservers|show vpn vserver
vpn_ica_connections|show vpn icaConnection
auth_vservers|show authentication vserver
saml_idp_profiles|show authentication samlIdPProfile
saml_actions|show authentication samlAction
lb_vservers|show lb vserver
cs_vservers|show cs vserver
cr_vservers|show cr vserver
services|show service
service_groups|show serviceGroup
dns64_actions|show dns action64
dns64_policies|show dns policy64
lsn_parameters|show lsn parameter
lsn_groups|show lsn group
lsn_nat64_stats|stat lsn nat64
responder_policies|show responder policy
rewrite_policies|show rewrite policy
ssl_certkeys|show ssl certKey
syslog_actions|show audit syslogAction
nslog_actions|show audit nslogAction
ntp_servers|show ntp server'

if [ "$SENSITIVE" -eq 0 ]; then
    CLI_CMDS='ns_version|show ns version'
    status skipped 'configuration, sessions and other raw CLI output excluded by default'
fi
printf '%s\n' "$CLI_CMDS" | awk -F'|' '{print $2}' > "$OUT/netscaler_cli/REMOTE_COMMANDS.txt"
if command -v nscli >/dev/null 2>&1; then
    printf '%s\n' "$CLI_CMDS" | while IFS='|' read -r fname cmd; do
        run "netscaler_cli/$fname.txt" "nscli -U '%%:.:.' \"$cmd\""
    done
    checked_grep -qiE 'netscaler|build' "$OUT/netscaler_cli/ns_version.txt" || partial cli_version_unrecognized
else
    partial nscli_unavailable
fi

# The Enhanced ISN setting is a vulnerability precondition in current CERT
# guidance. Retain only an aggregate in default mode.
if command -v nscli >/dev/null 2>&1; then
    timeout -k 2 60 nscli -U '%%:.:.' 'show ns tcpparam' < /dev/null > "$OUT/.tcpparam_raw" 2>&1
    TCP_RC=$?
    if [ "$TCP_RC" -ne 0 ] || grep -qiE '^[[:space:]]*(ERROR:|ERROR |Invalid command|Permission denied|Access denied)' "$OUT/.tcpparam_raw"; then
        partial tcpparam_query_failed
    fi
    awk '
        BEGIN { found = 0; enabled = 0; disabled = 0 }
        { low = tolower($0) }
        low ~ /enhanced[[:space:]_-]*isn|enhancedisngeneration/ {
            found++
            if (low ~ /enabled|[[:space:]]on([[:space:]]|$)|[[:space:]]yes([[:space:]]|$)/) enabled++
            if (low ~ /disabled|[[:space:]]off([[:space:]]|$)|[[:space:]]no([[:space:]]|$)/) disabled++
        }
        END {
            print "enhanced_isn_setting_lines=" found
            print "enhanced_isn_enabled_lines=" enabled
            print "enhanced_isn_disabled_lines=" disabled
        }' "$OUT/.tcpparam_raw" > "$OUT/checks/tcpparam_precondition.txt"
    ENHANCED_ISN=$(sed -n 's/^enhanced_isn_enabled_lines=//p' "$OUT/checks/tcpparam_precondition.txt")
    [ "${ENHANCED_ISN:-0}" -eq 0 ] || flag INFO "Enhanced ISN generation is enabled; review applicable CVE preconditions - checks/tcpparam_precondition.txt"
    rm -f "$OUT/.tcpparam_raw"
fi

# ------------------------------------------------- 3. filesystem timeline --
stage 3 "filesystem timeline (bodyfile) - before bulk content scanning"
BODY="$OUT/timeline/bodyfile.txt"
: > "$BODY"
for d in / /var /flash /tmp; do
    [ -e "$d" ] || continue
    find -H "$d" -xdev -name 'nsir_*' -prune -o \( -name '*[! -~]*' -o -name '*|*' \) -print0 > "$OUT/.unsupported" 2>/dev/null || partial name_inventory_failed
    [ ! -s "$OUT/.unsupported" ] || partial unsupported_filenames_omitted
    fx "$d" -print0 > "$OUT/.timeline_paths" 2>/dev/null
    [ -s "$OUT/.timeline_paths" ] || continue
    xargs -0 "$STAT" -f '0|%N|%i|%l|%Sp|%u|%g|%z|%a|%m|%c|%B' < "$OUT/.timeline_paths" >> "$BODY" 2>/dev/null || partial timeline_stat_failed
done
rm -f "$OUT/.unsupported" "$OUT/.timeline_paths"
if ! awk -F'|' 'NF != 12 {bad=1} {for(i=3;i<=12;i++) if(i!=5 && $i !~ /^[0-9]+$/) bad=1} END {exit bad || NR == 0}' "$BODY"; then
    partial invalid_or_empty_timeline
    # Never derive copy paths or heuristic results from malformed fields.
    : > "$BODY"
fi
log "   bodyfile lines: $(wc -l < "$BODY" | tr -d ' ')  (analyse: mactime -b bodyfile.txt -d)"

NOW=$(date +%s)
CUTOFF=$((NOW - DAYS * 86400))
{
    echo "# ctime_epoch|mtime_epoch|path   (ctime within ${DAYS}d, newest first; logs/cores excluded)"
    echo "# convert: date -r <epoch>.  ctime is much harder to fake than mtime (timestomping)."
    awk -F'|' -v c="$CUTOFF" '
        $11 >= c && $5 !~ /^d/ && $2 !~ /^\/var\/(log|nslog|core|nstrace)\// { print $11 "|" $10 "|" $2 }' "$BODY" | \
        sort -t'|' -k1,1nr
} > "$OUT/timeline/recently_changed_ctime.txt"

# The root filesystem (incl. /netscaler) is a ramdisk rebuilt at boot, so
# files there changed well after boot are suspicious.
BOOT=$(sysctl -n kern.boottime 2>/dev/null | sed -n 's/^{ sec = \([0-9]*\),.*/\1/p')
if [ -n "$BOOT" ]; then
    awk -F'|' -v b="$((BOOT + 900))" '
        $11 > b && $5 !~ /^d/ && $2 ~ /^\/(netscaler|bin|sbin|lib|libexec|usr\/bin|usr\/sbin|usr\/lib|usr\/libexec)\// { print $2 }' \
        "$BODY" | sort -u > "$OUT/checks/ramdisk_changed_after_boot.txt"
    [ -s "$OUT/checks/ramdisk_changed_after_boot.txt" ] && \
        flag MEDIUM "$(wc -l < "$OUT/checks/ramdisk_changed_after_boot.txt" | tr -d ' ') ramdisk file(s) (/netscaler, binaries) changed >15 min after boot - checks/ramdisk_changed_after_boot.txt"
    add_copy_lines "$OUT/checks/ramdisk_changed_after_boot.txt"
else
    partial boottime_unavailable
    flag INFO "Could not read kern.boottime - post-boot ramdisk change check skipped"
fi

# ------------------------------------------ 4. config and persistence --
stage 4 "configuration and persistence"
if [ "$SENSITIVE" -eq 1 ]; then
for f in /nsconfig/ns.conf* /flash/nsconfig/ns.conf* /flash/nsconfig/rc.netscaler* \
         /nsconfig/unified.conf* /flash/nsconfig/unified.conf* /flash/boot/loader.conf \
         /flash/nsconfig/rc.conf* /etc/rc.conf /etc/rc.local /etc/crontab /etc/passwd \
         /etc/group /etc/auth.conf /etc/httpd*.conf /etc/httpd.conf* \
         /nsconfig/httpd*.conf /nsconfig/httpd.conf* \
         /flash/nsconfig/httpd*.conf /flash/nsconfig/httpd.conf* /etc/ssh/sshd_config \
         /etc/syslog.conf /etc/newsyslog.conf /etc/hosts /etc/resolv.conf; do
    [ -f "$f" ] && printf '%s\0' "$f" >> "$COPYLIST"
done
fx /var/cron -type f -print0 >> "$COPYLIST" 2>/dev/null
fx /etc/cron.d -type f -print0 >> "$COPYLIST" 2>/dev/null
run system/crontab_root.txt "crontab -l -u root"
run system/crontab_nsroot.txt "crontab -l -u nsroot"
run system/crontab_nobody.txt "crontab -l -u nobody"
run system/keys_listing.txt "ls -laT /flash/nsconfig/keys /flash/nsconfig/keys/updated /nsconfig/ssl"
run system/dir_listings.txt "ls -laT /var/core /var/nsinstall /var/ns_sys_backup /var/nslog"

if [ -f /etc/master.passwd ]; then
    awk -F: 'BEGIN { OFS = ":" } /^#/ { print; next } { $2 = "[REDACTED]"; print }' \
        /etc/master.passwd > "$OUT/system/master.passwd.redacted"
fi

else
    status skipped 'raw configuration, cron, account records and source files excluded by default'
fi

: > "$OUT/checks/boot_loader_conf.txt"
if [ -f /flash/boot/loader.conf ] && [ ! -L /flash/boot/loader.conf ]; then
    LOADER_HASH=$(hash1 /flash/boot/loader.conf) || { partial loader_conf_hash_failed; LOADER_HASH=unavailable; }
    LOADER_BYTES=$(wc -c < /flash/boot/loader.conf 2>/dev/null || echo unavailable)
    printf 'path=/flash/boot/loader.conf\nsha256=%s\nbytes=%s\n' "$LOADER_HASH" "$LOADER_BYTES" \
        > "$OUT/checks/boot_loader_conf.txt" || fatal output_write
else
    echo 'present=0' > "$OUT/checks/boot_loader_conf.txt" || fatal output_write
fi

: > "$OUT/checks/ssh_keys_and_histories.txt"
for d in / /var /flash /tmp; do
    fx "$d" -type f \( -name 'authorized_keys*' -o -name '.*history' -o -name '.*_history' \
        -o -name 'history.txt.*' \) -print 2>/dev/null
done | sort -u > "$OUT/checks/ssh_keys_and_histories.txt"
add_copy_lines "$OUT/checks/ssh_keys_and_histories.txt"
checked_grep 'authorized_keys' "$OUT/checks/ssh_keys_and_histories.txt" > "$OUT/.authorized_paths"
while IFS= read -r k; do
    [ -s "$k" ] && flag MEDIUM "Non-empty SSH authorized_keys: $k - confirm every key is authorised"
done < "$OUT/.authorized_paths"
rm -f "$OUT/.authorized_paths"

RC=/flash/nsconfig/rc.netscaler
if [ -f "$RC" ]; then
    if checked_grep -lE '<\?php|@eval|chmod[[:space:]]+([ugoa]*\+s|[0-7]*[4-7][0-7]{3})|base64' "$RC" \
        > "$OUT/checks/rc_netscaler_high.txt"; then
        flag HIGH "rc.netscaler contains PHP/SUID/base64 content (CVE-2023-3519/2025-6543 TTP) - checks/rc_netscaler_high.txt"
    fi
    if checked_grep -lE 'python|perl|curl|wget|fetch[[:space:]]|nc[[:space:]]|/var/tmp|/tmp/|echo[[:space:]].*>' "$RC" \
        > "$OUT/checks/rc_netscaler_review.txt"; then
        flag MEDIUM "rc.netscaler contains interpreter/download/redirect commands - review checks/rc_netscaler_review.txt"
    fi
fi

for d in / /var /flash /tmp; do
    fx "$d" -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null
done | sort -u > "$OUT/checks/suid_sgid_all.txt"
checked_grep -E '^(/var|/tmp|/flash)/' "$OUT/checks/suid_sgid_all.txt" > "$OUT/checks/suid_in_writable.txt"
[ -s "$OUT/checks/suid_in_writable.txt" ] && \
    flag MEDIUM "SUID/SGID metadata on writable filesystems; compare same-build baseline - checks/suid_in_writable.txt"
add_copy_lines "$OUT/checks/suid_in_writable.txt"
for s in /bin/sh /bin/bash /usr/local/bin/bash; do
    [ -u "$s" ] && flag HIGH "$s has the SUID bit set (known NetScaler backdoor TTP)"
done
[ -e /var/tmp/sh ] && flag HIGH "/var/tmp/sh exists (NCSC-NL CVE-2025-6543 IOC)"

: > "$OUT/.httpd_paths"
: > "$OUT/.httpd_paths_unsorted"
for f in /etc/httpd*.conf /etc/httpd.conf* \
         /nsconfig/httpd*.conf /nsconfig/httpd.conf* \
         /flash/nsconfig/httpd*.conf /flash/nsconfig/httpd.conf*; do
    [ -f "$f" ] && printf '%s\n' "$f" >> "$OUT/.httpd_paths_unsorted"
done
sort -u "$OUT/.httpd_paths_unsorted" > "$OUT/.httpd_paths" || fatal httpd_path_sort_failed
rm -f "$OUT/.httpd_paths_unsorted"
add_copy_lines "$OUT/.httpd_paths"

: > "$OUT/checks/httpd_conf_inventory.txt"
: > "$OUT/checks/httpd_conf_disabled_protections.txt"
: > "$OUT/checks/httpd_conf_php_extensions.txt"
: > "$OUT/checks/httpd_conf_php_engine_on.txt"
: > "$OUT/checks/httpd_conf_files_php_handler.txt"
: > "$OUT/checks/httpd_conf_static_aliases.txt"
while IFS= read -r f; do
    [ -f "$f" ] || continue
    h=$(hash1 "$f") || { partial httpd_config_hash_failed; continue; }
    printf '%s  %s\n' "$h" "$f" >> "$OUT/checks/httpd_conf_inventory.txt"
    checked_grep -lE '^[[:space:]]*#.*(Require[[:space:]]+all[[:space:]]+denied|php_flag[[:space:]]+engine[[:space:]]+off)' "$f" | \
        sed "s|^|$f:|" >> "$OUT/checks/httpd_conf_disabled_protections.txt"
    awk -v f="$f" '
        {
            low = tolower($0)
            if (low ~ /^[[:space:]]*#/ || low !~ /^[[:space:]]*(addtype|addhandler)[[:space:]]/ || low !~ /php/) next
            for (i = 3; i <= NF; i++) {
                ext = tolower($i)
                if (ext ~ /^\./ && ext !~ /^\.(php|phtml|pht|xhtml)$/)
                    print f ":" NR ": alternate PHP extension"
            }
        }' "$f" \
        >> "$OUT/checks/httpd_conf_php_extensions.txt"
    awk -v f="$f" '
        {
            low = tolower($0)
            if (low !~ /^[[:space:]]*#/ && low ~ /^[[:space:]]*php_flag[[:space:]]+engine[[:space:]]+on([[:space:]]|$)/)
                print f ":" NR ": PHP engine enabled"
        }' "$f" >> "$OUT/checks/httpd_conf_php_engine_on.txt"
    awk -v f="$f" '
        {
            low = tolower($0)
            if (low ~ /^[[:space:]]*<(files|filesmatch)[[:space:]]/) {
                inside = 1; start = NR
                selector = low
                nonphp = selector !~ /\.(php|phtml|pht|xhtml)([^a-z]|$)/
            }
            if (inside && nonphp && low !~ /^[[:space:]]*#/ && low ~ /sethandler[[:space:]]+.*(x-httpd-php|php-script)/)
                print f ":" start ": non-PHP Files block uses PHP handler"
            if (low ~ /^[[:space:]]*<\/(files|filesmatch)>/) { inside = 0; nonphp = 0 }
        }' "$f" >> "$OUT/checks/httpd_conf_files_php_handler.txt"
    awk -v f="$f" '
        {
            low = tolower($0)
            if (low ~ /^[[:space:]]*#/ || low !~ /^[[:space:]]*(alias|aliasmatch)[[:space:]]/) next
            url = tolower($2); target = tolower($3)
            if (url ~ /\.(css|js|png|gif|jpg|jpeg|ico)([[:space:]"'\''>]|$)/ &&
                (target ~ /(^|\/)\.[^\/]+$/ || target !~ /\.(css|js|png|gif|jpg|jpeg|ico)([[:space:]"'\''>]|$)/))
                print f ":" NR ": static-looking URL aliases to non-static/hidden target"
        }' "$f" >> "$OUT/checks/httpd_conf_static_aliases.txt"
done < "$OUT/.httpd_paths"

: > "$OUT/checks/httpd_conf_live_persistent_differences.txt"
for live in /etc/httpd*.conf /etc/httpd.conf*; do
    [ -f "$live" ] || continue
    base=$(basename "$live")
    for persistent in "/nsconfig/$base" "/flash/nsconfig/$base"; do
        [ -f "$persistent" ] || continue
        cmp -s "$live" "$persistent"
        cmp_rc=$?
        if [ "$cmp_rc" -eq 1 ]; then
            printf '%s|%s\n' "$live" "$persistent" >> "$OUT/checks/httpd_conf_live_persistent_differences.txt"
        elif [ "$cmp_rc" -gt 1 ]; then partial httpd_config_compare_failed
        fi
    done
done
sort -u "$OUT/checks/httpd_conf_live_persistent_differences.txt" \
    > "$OUT/.httpd_differences" && mv "$OUT/.httpd_differences" "$OUT/checks/httpd_conf_live_persistent_differences.txt"
[ -s "$OUT/checks/httpd_conf_disabled_protections.txt" ] && \
    flag HIGH "httpd.conf has commented-out 'Require all denied' / 'php_flag engine off' - checks/httpd_conf_disabled_protections.txt"
[ -s "$OUT/checks/httpd_conf_php_extensions.txt" ] && \
    flag MEDIUM "HTTP configuration maps PHP handler to alternate extensions; compare a clean same-build baseline - checks/httpd_conf_php_extensions.txt"
[ -s "$OUT/checks/httpd_conf_php_engine_on.txt" ] && \
    flag HIGH "HTTP configuration explicitly enables the PHP engine - checks/httpd_conf_php_engine_on.txt"
[ -s "$OUT/checks/httpd_conf_files_php_handler.txt" ] && \
    flag HIGH "Non-PHP Files/FilesMatch scope uses a PHP handler - checks/httpd_conf_files_php_handler.txt"
[ -s "$OUT/checks/httpd_conf_static_aliases.txt" ] && \
    flag MEDIUM "Static-looking HTTP aliases map to hidden/non-static targets - checks/httpd_conf_static_aliases.txt"
[ -s "$OUT/checks/httpd_conf_live_persistent_differences.txt" ] && \
    flag MEDIUM "Live and persistent HTTP configurations differ - checks/httpd_conf_live_persistent_differences.txt"
rm -f "$OUT/.httpd_paths"

[ -e /etc/auth.conf ] || \
    flag MEDIUM "/etc/auth.conf missing (deleted in CVE-2023-3519 intrusions) - verify against clean same-build appliance"

{
    [ "$SENSITIVE" -eq 0 ] || cat "$OUT/system/crontab_root.txt" 2>/dev/null
    cat /etc/crontab 2>/dev/null
    fx /var/cron -type f -exec cat {} + 2>/dev/null
} | checked_grep -vE '^[[:space:]]*#' | \
    checked_grep -E '/var/tmp|/tmp/|python|perl|curl|wget|fetch[[:space:]]|php|nc[[:space:]]|base64|sh[[:space:]]+-c' \
    | awk 'END {if (NR) print "matching_entries=" NR}' > "$OUT/checks/cron_suspicious.txt"
[ -s "$OUT/checks/cron_suspicious.txt" ] && \
    flag MEDIUM "Cron entries referencing temp paths/interpreters/downloaders - checks/cron_suspicious.txt"

NSCONF=/flash/nsconfig/ns.conf
[ -f /nsconfig/ns.conf ] && NSCONF=/nsconfig/ns.conf
if [ -f "$NSCONF" ]; then
    if [ "$SENSITIVE" -eq 1 ]; then
        checked_grep -E '^(add|set|bind) system (user|group)' "$NSCONF" > "$OUT/checks/nsconf_system_accounts.txt"
    else
        awk '/^(add|set|bind) system (user|group)/ {n++} END {print "account_entries=" n+0}' "$NSCONF" > "$OUT/checks/nsconf_system_accounts.txt"
    fi
    USERS=$(awk '$1 == "add" && $2 == "system" && $3 == "user" && $4 != "nsroot" {n++} END {print n+0}' "$NSCONF")
    [ "$USERS" -eq 0 ] || flag INFO "Local system users besides nsroot: $USERS (review authorized access)"
    flag INFO "Saved ns.conf mtime epoch: $("$STAT" -f '%m' "$NSCONF" 2>/dev/null) - compare netscaler_cli/diff_running_vs_saved.txt"
    awk '
        BEGIN { vpn=auth=lb_http=lb_ssl=lb_http_quic=cs_http=cs_ssl=cr_http=cr_ssl=oracle=ftp=dtls=dns64=lsn=nat64=0 }
        {
            low = tolower($0)
            if (low ~ /^add[[:space:]]+vpn[[:space:]]+vserver[[:space:]]/) vpn++
            if (low ~ /^add[[:space:]]+authentication[[:space:]]+vserver[[:space:]]/) auth++
            if (low ~ /^add[[:space:]]+lb[[:space:]]+vserver[[:space:]]/) {
                type = toupper($5)
                if (type == "HTTP") lb_http++
                else if (type == "SSL") lb_ssl++
                else if (type == "HTTP_QUIC") lb_http_quic++
                else if (type == "ORACLE") oracle++
                else if (type == "FTP") ftp++
            }
            if (low ~ /^add[[:space:]]+cs[[:space:]]+vserver[[:space:]]/) {
                type = toupper($5)
                if (type == "HTTP") cs_http++
                else if (type == "SSL") cs_ssl++
            }
            if (low ~ /^add[[:space:]]+cr[[:space:]]+vserver[[:space:]]/) {
                type = toupper($5)
                if (type == "HTTP") cr_http++
                else if (type == "SSL") cr_ssl++
            }
            if (low ~ /-dtls[[:space:]]+(on|enabled|yes)/) dtls++
            if (low ~ /-dns64[[:space:]]+enabled/ || low ~ /^add[[:space:]]+dns[[:space:]]+(action64|policy64)/) dns64++
            if (low ~ /^(add|set|bind)[[:space:]]+lsn[[:space:]]/) lsn++
            if (low ~ /nat64/) nat64++
            if (low ~ /^add[[:space:]]+(service|servicegroup)[[:space:]]/ && low ~ /[[:space:]]oracle([[:space:]]|$)/) oracle++
            if (low ~ /^add[[:space:]]+(service|servicegroup)[[:space:]]/ && low ~ /[[:space:]]ftp([[:space:]]|$)/) ftp++
        }
        END {
            print "vpn_vservers=" vpn
            print "authentication_vservers=" auth
            print "lb_http_vservers=" lb_http
            print "lb_ssl_vservers=" lb_ssl
            print "lb_http_quic_vservers=" lb_http_quic
            print "cs_http_vservers=" cs_http
            print "cs_ssl_vservers=" cs_ssl
            print "cr_http_vservers=" cr_http
            print "cr_ssl_vservers=" cr_ssl
            print "dtls_enabled_entries=" dtls
            print "oracle_entries=" oracle
            print "ftp_entries=" ftp
            print "dns64_entries=" dns64
            print "lsn_entries=" lsn
            print "nat64_entries=" nat64
        }' "$NSCONF" > "$OUT/checks/cve_precondition_summary.txt"
fi

UNIFIED=/flash/nsconfig/unified.conf
[ -f /nsconfig/unified.conf ] && UNIFIED=/nsconfig/unified.conf
if [ -f "$UNIFIED" ]; then
    if [ "$SENSITIVE" -eq 1 ]; then
        checked_grep -H -E '^(add|set|bind) system (user|group)' "$UNIFIED" \
            > "$OUT/checks/unified_conf_system_accounts.txt"
    else
        awk '/^(add|set|bind) system (user|group)/ {n++} END {print "account_entries=" n+0}' "$UNIFIED" \
            > "$OUT/checks/unified_conf_system_accounts.txt"
    fi
    UUSERS=$(awk '$1 == "add" && $2 == "system" && $3 == "user" && $4 != "nsroot" {n++} END {print n+0}' "$UNIFIED")
    [ "$UUSERS" -eq 0 ] || flag INFO "Unified configuration contains $UUSERS local system-user entrie(s) besides nsroot"
else
    echo 'present=0' > "$OUT/checks/unified_conf_system_accounts.txt"
fi

# --------------------------------------------- 5. web dirs / webshells --
stage 5 "web directories and webshell heuristics"
WEBDIRS="/netscaler/ns_gui /var/netscaler /var/vpn"

for d in /var/netscaler /var/vpn /var/python /var/tmp /tmp; do
    fx "$d" -type f \( -name '*.php*' -o -name '*.phtml' -o -name '*.pht' -o -name '*.xhtml' \) \
        ! -path '/var/netscaler/gui/admin_ui/*' -print 2>/dev/null
done | checked_grep -v "/$SELFBASE\$" | sort -u > "$OUT/checks/php_outside_expected.txt"
if [ -s "$OUT/checks/php_outside_expected.txt" ]; then
    flag HIGH "$(wc -l < "$OUT/checks/php_outside_expected.txt" | tr -d ' ') PHP/XHTML file(s) outside expected dirs (e.g. /var/vpn/theme/x.php) - checks/php_outside_expected.txt"
fi
add_copy_lines "$OUT/checks/php_outside_expected.txt"

# shellcheck disable=SC2016 # Literal PHP variable names in regex.
PAT_HIGH='@eval[[:space:]]*\(|eval[[:space:]]*\([[:space:]]*\$_(REQUEST|POST|GET|COOKIE|SERVER)|assert[[:space:]]*\([[:space:]]*\$_|(eval|assert)[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13)|array_filter[[:space:]]*\([^)]*\$_(REQUEST|POST|GET|COOKIE)|(system|passthru|shell_exec|exec|popen|proc_open)[[:space:]]*\([[:space:]]*\$_(REQUEST|POST|GET|COOKIE)'
# shellcheck disable=SC2016
PAT_REVIEW='base64_decode|gzinflate|shell_exec|passthru|proc_open|fsockopen|\$_REQUEST'
PAT_SECRETS='^[[:space:]]*-----BEGIN (RSA |EC |ENCRYPTED |OPENSSH )?PRIVATE KEY-----[[:space:]]*$|^add ns ip |^set ns config|^set ns hostName|^add system user'

for d in $WEBDIRS /var/tmp /tmp /var/python; do
    fx "$d" -type f -size -5M -print0 2>/dev/null
done > "$OUT/.webfiles0"

scan_pattern "$PAT_HIGH" < "$OUT/.webfiles0" 2>/dev/null | checked_grep -v "/$SELFBASE\$" | \
    sort -u > "$OUT/checks/webshell_code_patterns.txt"
[ -s "$OUT/checks/webshell_code_patterns.txt" ] && \
    flag HIGH "Webshell-style code (eval/assert/exec on request data) - checks/webshell_code_patterns.txt"
add_copy_lines "$OUT/checks/webshell_code_patterns.txt"

scan_pattern "$PAT_REVIEW" < "$OUT/.webfiles0" 2>/dev/null | checked_grep -v "/$SELFBASE\$" | \
    sort -u > "$OUT/checks/review_code_patterns_INFO.txt"

: > "$OUT/.web_only0"
for d in $WEBDIRS; do fx "$d" -type f -size -5M -print0 2>/dev/null; done > "$OUT/.web_only0"
scan_pattern "$PAT_SECRETS" < "$OUT/.web_only0" 2>/dev/null | \
    sort -u > "$OUT/checks/config_or_keys_in_web_dirs.txt"
[ -s "$OUT/checks/config_or_keys_in_web_dirs.txt" ] && \
    flag HIGH "ns.conf / private-key material inside web-served dirs (exfil staging) - checks/config_or_keys_in_web_dirs.txt"
add_copy_lines "$OUT/checks/config_or_keys_in_web_dirs.txt"

for d in $WEBDIRS; do
    fx "$d" -type f \( -name '*.png' -o -name '*.gif' -o -name '*.jpg' -o -name '*.jpeg' -o -name '*.ico' \) -print 2>/dev/null
done | while IFS= read -r f; do
    m=$(od -An -tx1 -N4 "$f" 2>/dev/null | tr -d ' \n')
    # Shipped assets can use a different image extension from their real format.
    # Accept supported image signatures regardless of the filename suffix.
    case "$m" in 89504e47*|47494638*|ffd8ff*|00000100*|00000200*) continue;; esac
    printf '%s\t%s\n' "$m" "$f"
done > "$OUT/checks/image_magic_mismatch.txt"
if [ -s "$OUT/checks/image_magic_mismatch.txt" ]; then
    flag HIGH "Image-named file(s) with unrecognized image signatures (gzip magic 1f8b = staged archive, CVE-2023-3519 TTP) - checks/image_magic_mismatch.txt"
    cut -f2 "$OUT/checks/image_magic_mismatch.txt" > "$OUT/.imgpaths"
    add_copy_lines "$OUT/.imgpaths"
fi

for d in /var/tmp /tmp; do
    fx "$d" -type f \( -perm -100 -o -name '*.sh' -o -name '*.py' -o -name '*.pl' -o -name '*.so' \
        -o -name '*.tar' -o -name '*.tgz' -o -name '*.gz' -o -name '*.zip' -o -name '*.bin' \) -print 2>/dev/null
done | checked_grep -v "/$SELFBASE\$" | sort -u > "$OUT/checks/tmp_executables_archives.txt"
[ -s "$OUT/checks/tmp_executables_archives.txt" ] && \
    flag MEDIUM "Executables/scripts/archives in /var/tmp or /tmp (support bundles are normal) - checks/tmp_executables_archives.txt"
add_copy_lines "$OUT/checks/tmp_executables_archives.txt"

checked_grep -v '^#' "$OUT/timeline/recently_changed_ctime.txt" | cut -d'|' -f3 | \
    checked_grep -E '^/(var/netscaler|var/vpn|var/python|var/tmp|tmp|flash/nsconfig)/' | \
    checked_grep -v '^/flash/nsconfig/keys/' | checked_grep -v "/$SELFBASE\$" > "$OUT/.recent_web"
add_copy_lines "$OUT/.recent_web"

# ------------------------------------------------------------- 6. logs --
stage 6 "logs"
if [ "$SENSITIVE" -eq 1 ]; then
    fx /var/log -type f -size -500M -print0 >> "$COPYLIST" 2>/dev/null
else
    status skipped 'raw logs excluded by default; aggregate heuristics retained'
fi
NSPPE_CORES=$(find /var/core -type f -name 'NSPPE*' 2>/dev/null | wc -l | tr -d ' ')
[ "${NSPPE_CORES:-0}" -gt 0 ] && \
    flag LOW "$NSPPE_CORES NSPPE core dump(s) in /var/core - crashes can accompany exploit attempts (CVE-2025-6543, CVE-2026-8452); correlate timestamps"
[ "$COPY_CORES" -eq 1 ] && fx /var/core -type f -print0 >> "$COPYLIST" 2>/dev/null
[ "$COPY_NSLOG" -eq 1 ] && fx /var/nslog -type f -print0 >> "$COPYLIST" 2>/dev/null

# ---------------------------------------------------- 7. log heuristics --
stage 7 "log heuristics"
nslog_cat() {
    for f in /var/log/ns.log*; do [ -f "$f" ] && catlog "$f"; done
}
messages_cat() {
    for f in /var/log/messages*; do [ -f "$f" ] && catlog "$f"; done
}
vpnlog_cat() {
    for f in /var/log/nsvpn.log*; do [ -f "$f" ] && catlog "$f"; done
}
httperror_cat() {
    for f in /var/log/httperror.log*; do [ -f "$f" ] && catlog "$f"; done
}

# NetScaler MAC_Veriexec reports unsigned or changed executables in messages.
# Extract a path only when the complete "file=... fsid=" structure is present;
# aggressively concatenated log records are intentionally not parsed.
: > "$OUT/.veriexec_raw"
: > "$OUT/.veriexec_paths"
messages_cat | awk -v paths="$OUT/.veriexec_paths" -v self="$SELF" '
    /MAC\/veriexec: (no fingerprint|fingerprint does not match loaded value) \(file=/ {
        if (index($0, ")MAC/veriexec:") > 0) next
        start=index($0, "(file=")
        rest=substr($0, start + 6)
        stop=index(rest, " fsid=")
        if (!start || !stop) next
        path=substr(rest, 1, stop - 1)
        helper=(length(path) >= 13 && substr(path, length(path) - 12) == "/.stat-helper" && index(path, "/nsir_") > 0)
        if (path == self || helper) next
        print path >> paths
        print
    }' > "$OUT/.veriexec_raw"
sort -u "$OUT/.veriexec_paths" > "$OUT/logs_analysis/veriexec_failed_paths.txt" || fatal output_write
VERIEXEC_HITS=$(wc -l < "$OUT/.veriexec_raw" | tr -d ' ')
printf 'matching_lines=%s\n' "${VERIEXEC_HITS:-0}" > "$OUT/logs_analysis/veriexec_failures.txt" || fatal output_write
if [ "$SENSITIVE" -eq 1 ]; then
    mv "$OUT/.veriexec_raw" "$OUT/logs_analysis/veriexec_failures_raw.txt" || fatal output_write
else
    rm -f "$OUT/.veriexec_raw"
fi
rm -f "$OUT/.veriexec_paths"
[ "${VERIEXEC_HITS:-0}" -eq 0 ] || flag HIGH "$VERIEXEC_HITS MAC_Veriexec integrity-failure line(s) found - logs_analysis/veriexec_failed_paths.txt"

# Preserve no more than 25 implicated files, and only under explicit sensitive
# collection. The list combines vendor sigchk and log-derived paths.
cat "$OUT/checks/sigchk_unverified_paths.txt" "$OUT/logs_analysis/veriexec_failed_paths.txt" 2>/dev/null | \
    awk '/^\// && $0 !~ /[|[:cntrl:]]/ {print}' | sort -u | head -n 25 \
    > "$OUT/.native_integrity_copy_paths"
add_copy_lines "$OUT/.native_integrity_copy_paths"

if [ ! -s /var/log/ns.log ]; then
    flag MEDIUM "/var/log/ns.log missing or empty - possible log wiping; rely on off-box syslog"
fi
for f in /var/log/ns.log* /var/log/messages* /var/log/nsvpn.log* \
         /var/log/httpaccess.log* /var/log/httpaccess-vpn.log* \
         /var/log/httperror.log* /var/log/bash.log*; do
    [ -f "$f" ] || continue
    printf '%s\n' "$f"
done > "$OUT/logs_analysis/log_coverage.txt"
# Coverage lists file paths only. Raw first/last lines can contain session data.

NONASCII=$(printf '[\200-\377]')
# Non-ASCII bytes (128-255), matching the vendor's attempt indicator.
# ASCII controls/DEL alone are not this indicator. Store only a count by default.
nslog_cat | checked_grep -a 'Authentication is rejected for' | checked_grep -a 'AAA Message' | \
    checked_grep -a "$NONASCII" | content_sink > "$OUT/logs_analysis/cb2_nonprintable_aaa.txt"
if [ "$SENSITIVE" -eq 1 ]; then CB2=$(wc -l < "$OUT/logs_analysis/cb2_nonprintable_aaa.txt")
else CB2=$(sed 's/^matching_lines=//' "$OUT/logs_analysis/cb2_nonprintable_aaa.txt"); fi
[ "${CB2:-0}" -eq 0 ] || flag HIGH "$CB2 AAA log line(s) with non-ASCII bytes; possible exploit attempts, not proof of compromise"

# Address-only session analysis. No user names, session IDs or log lines retained.
: > "$OUT/logs_analysis/ips_with_many_users.txt"
nslog_cat | awk -v issues="$OUT/.session_issues" -v counts="$OUT/logs_analysis/ips_with_many_users.txt" '
function ipv4(s, a,n,i,r) {
    n=split(s,a,"."); if(n!=4) return ""
    r=""; for(i=1;i<=4;i++) {if(a[i]!~/^[0-9]+$/ || length(a[i])>3 || a[i]+0>255) return ""; r=r (i>1?".":"") (a[i]+0)}
    return r
}
function ipv6(s, sides,n,l,r,a,b,i,k,out,z) {
    s=tolower(s); if(s !~ /^[0-9a-f:]+$/) return ""
    n=split(s,sides,"::"); if(n>2) return ""
    l=sides[1]==""?0:split(sides[1],a,":")
    r=n==2 && sides[2]!=""?split(sides[2],b,":"):0
    if((n==1 && l!=8) || (n==2 && l+r>=8)) return ""
    out=""
    for(i=1;i<=8;i++) {
        if(i<=l) z=a[i]; else if(i>8-r) z=b[i-(8-r)]; else z="0"
        if(z=="" || length(z)>4 || z !~ /^[0-9a-f]+$/) return ""
        while(length(z)<4) z="0" z
        out=out (i>1?":":"") z
    }
    return out
}
function endpoint(s,src, p,addr,port,n,a) {
    bare=0
    if(substr(s,1,1)=="[") {
        p=index(s,"]"); if(!p) return ""
        addr=substr(s,2,p-2); port=substr(s,p+1)
        if(port!="" && (port !~ /^:[0-9]+$/ || substr(port,2)+0>65535)) return ""
        return ipv6(addr)
    }
    if(index(s,".")>0) {
        n=split(s,a,":"); if(n>2 || (n==2 && (a[2]!~/^[0-9]+$/ || a[2]+0>65535))) return ""
        return ipv4(a[1])
    }
    bare=src; return ipv6(s)
}
/TCPCONNSTAT/ {
    client=""; source=""; user=""
    for(i=1;i<NF;i++) {
        if($i=="Client_ip") client=$(i+1)
        if($i=="Source") source=$(i+1)
        if($i=="User") user=$(i+1)
    }
    if(client=="" && source=="") next
    ci=endpoint(client,0); src=endpoint(source,1); isbare=bare
    if(ci=="" || src=="" || (isbare && ci!=src)) { print "unrecognized_or_ambiguous" >> issues; next }
    if(ci!=src && !((ci SUBSEP src) in pairs)) {pairs[ci SUBSEP src]=1; print ci "|" src}
    if(user!="" && !((src SUBSEP user) in seen)) {seen[src SUBSEP user]=1; users[src]++}
}
END {for(ip in users) if(users[ip]>=10) print users[ip],ip > counts}

' > "$OUT/logs_analysis/session_ip_mismatch.txt"
[ ! -s "$OUT/.session_issues" ] || partial ambiguous_or_invalid_session_addresses
MIS=$(wc -l < "$OUT/logs_analysis/session_ip_mismatch.txt")
[ "$MIS" -eq 0 ] || flag MEDIUM "$MIS distinct client/source address pair(s) differ; roaming/NAT can explain this"
[ ! -s "$OUT/logs_analysis/ips_with_many_users.txt" ] || flag MEDIUM "Connection source address(es) associated with >=10 users; NAT can explain this"
rm -f "$OUT/.session_issues"

nslog_cat | checked_grep -aiE 'nsppe.*(signal|crash|core)|signal (10|11)|core dumped' \
    | awk 'END {if (NR) print "matching_lines=" NR}' > "$OUT/logs_analysis/crash_indicators.txt"
[ -s "$OUT/logs_analysis/crash_indicators.txt" ] && \
    flag LOW "Packet-engine crash indicators in ns.log - logs_analysis/crash_indicators.txt"

PAT_URI='/cgi/samlauth|/saml/login|/wsfed/passive|/oauth/idp/\.well-known|/p/u/doAuthentication\.do|/cgi/GetAuthMethods'
PAT_PHPREQ='(GET|POST)[^"]*/(vpn|logon|theme|themes)/[^" ?]*\.(php|xhtml|phtml)'
http_cat() {
    for f in /var/log/httpaccess.log* /var/log/httpaccess-vpn.log*; do
        [ ! -f "$f" ] || catlog "$f"
    done
}
security_log_cat() {
    nslog_cat
    messages_cat
    vpnlog_cat
}
all_ir_log_cat() {
    security_log_cat
    http_cat
    httperror_cat
}
http_cat | checked_grep -aE "$PAT_URI" | content_sink > "$OUT/logs_analysis/http_exploit_endpoint_hits.txt"
http_cat | checked_grep -aE "$PAT_PHPREQ" | content_sink > "$OUT/logs_analysis/http_php_requests_in_vpn_logon.txt"
for check in http_exploit_endpoint_hits http_php_requests_in_vpn_logon; do
    if [ "$SENSITIVE" -eq 1 ]; then hits=$(wc -l < "$OUT/logs_analysis/$check.txt")
    else hits=$(sed 's/^matching_lines=//' "$OUT/logs_analysis/$check.txt"); fi
    [ "${hits:-0}" -eq 0 ] || flag INFO "$check: $hits request(s); review with off-box logs"
done

# Correlate parser/crash and command-stage markers across rotated system/VPN
# logs. These are investigation leads; default mode retains counts only.
security_log_cat | checked_grep -aiE 'pitboss.*ppe.*(missed too many heartbeats|unexpectedly died).*nsppe|nsppe.*(missed too many heartbeats|unexpectedly died)' \
    | content_sink > "$OUT/logs_analysis/nsppe_parser_crash_chain.txt"
if [ "$SENSITIVE" -eq 1 ]; then PARSER_HITS=$(wc -l < "$OUT/logs_analysis/nsppe_parser_crash_chain.txt")
else PARSER_HITS=$(sed 's/^matching_lines=//' "$OUT/logs_analysis/nsppe_parser_crash_chain.txt"); fi
[ "${PARSER_HITS:-0}" -eq 0 ] || flag LOW "$PARSER_HITS packet-engine parser/crash-chain log line(s) found; clean startup can contain these, so correlate with command/HTTP/IOC stages - logs_analysis/nsppe_parser_crash_chain.txt"

security_log_cat | checked_grep -aE '\$\{IFS\}|b64decode|/var/log/htt([/[:space:]]|$)|ns_monuploadd_err\.pl.*(^|[[:space:]])-WR([[:space:]]|$)' \
    | content_sink > "$OUT/logs_analysis/command_stage_markers.txt"
if [ "$SENSITIVE" -eq 1 ]; then COMMAND_HITS=$(wc -l < "$OUT/logs_analysis/command_stage_markers.txt")
else COMMAND_HITS=$(sed 's/^matching_lines=//' "$OUT/logs_analysis/command_stage_markers.txt"); fi
[ "${COMMAND_HITS:-0}" -eq 0 ] || flag HIGH "$COMMAND_HITS command-stage marker line(s) found in system/VPN logs - logs_analysis/command_stage_markers.txt"

http_cat | checked_grep -aiE '(GET|POST)[^"]*/[^" ?]*(receiver|ctxs)[^" ?]*\.css([?[:space:]]|$)' \
    | content_sink > "$OUT/logs_analysis/http_css_receiver_requests.txt"
if [ "$SENSITIVE" -eq 1 ]; then CSS_HITS=$(wc -l < "$OUT/logs_analysis/http_css_receiver_requests.txt")
else CSS_HITS=$(sed 's/^matching_lines=//' "$OUT/logs_analysis/http_css_receiver_requests.txt"); fi
[ "${CSS_HITS:-0}" -eq 0 ] || flag HIGH "$CSS_HITS CSS receiver-stage request(s) found - logs_analysis/http_css_receiver_requests.txt"

http_cat | checked_grep -aE 'User-Agent:[[:space:]]*[A-Za-z0-9+/]{80,}={0,2}([[:space:]]|$)' \
    | content_sink > "$OUT/logs_analysis/http_base64_user_agents.txt"
if [ "$SENSITIVE" -eq 1 ]; then UA_HITS=$(wc -l < "$OUT/logs_analysis/http_base64_user_agents.txt")
else UA_HITS=$(sed 's/^matching_lines=//' "$OUT/logs_analysis/http_base64_user_agents.txt"); fi
[ "${UA_HITS:-0}" -eq 0 ] || flag MEDIUM "$UA_HITS request(s) contain a long Base64-like User-Agent - logs_analysis/http_base64_user_agents.txt"

httperror_cat | checked_grep -aiE 'sighup|signal[[:space:]]+1|graceful restart' \
    | content_sink > "$OUT/logs_analysis/httpd_reload_indicators.txt"
if [ "$SENSITIVE" -eq 1 ]; then RELOAD_HITS=$(wc -l < "$OUT/logs_analysis/httpd_reload_indicators.txt")
else RELOAD_HITS=$(sed 's/^matching_lines=//' "$OUT/logs_analysis/httpd_reload_indicators.txt"); fi
[ "${RELOAD_HITS:-0}" -eq 0 ] || flag INFO "$RELOAD_HITS HTTP daemon reload/restart line(s) found; common during startup, correlate with configuration mtimes - logs_analysis/httpd_reload_indicators.txt"

if [ -n "$IOC_FILE" ]; then
    all_ir_log_cat | ioc_filter | content_sink > "$OUT/logs_analysis/ioc_log_hits.txt"
    if [ "$SENSITIVE" -eq 1 ]; then IOC_LOG=$(wc -l < "$OUT/logs_analysis/ioc_log_hits.txt")
    else IOC_LOG=$(sed 's/^matching_lines=//' "$OUT/logs_analysis/ioc_log_hits.txt"); fi
    [ "${IOC_LOG:-0}" -eq 0 ] || flag HIGH "$IOC_LOG log line(s) matched the runtime IOC file - logs_analysis/ioc_log_hits.txt"
fi

checked_grep -v 'authorized_keys' "$OUT/checks/ssh_keys_and_histories.txt" > "$OUT/.history_paths"
PAT_CMD='wget |curl |fetch |base64|python[0-9.]* -c|perl -e|nc -|chmod [ugoa]*\+s|chmod [0-7]*[4-7][0-7]{3}|/flash/nsconfig/keys|\.F[12]\.key|whoami|/var/tmp/sh'
: > "$OUT/.command_counts"
for f in /var/log/bash.log*; do
    if [ -f "$f" ]; then
        catlog "$f" | checked_grep -aE "$PAT_CMD" | awk 'END {print NR}' >> "$OUT/.command_counts"
    fi
done
while IFS= read -r h; do
    checked_grep -aE "$PAT_CMD" "$h" 2>/dev/null | awk 'END {print NR}' >> "$OUT/.command_counts"
done < "$OUT/.history_paths"
awk '{n += $1} END {if(n) print "matching_lines=" n}' "$OUT/.command_counts" > "$OUT/logs_analysis/shell_command_hits.txt"
rm -f "$OUT/.command_counts"
rm -f "$OUT/.history_paths"
[ -s "$OUT/logs_analysis/shell_command_hits.txt" ] && \
    flag MEDIUM "Attacker-typical commands in bash.log / shell histories - logs_analysis/shell_command_hits.txt"
if [ -n "$IOC_FILE" ]; then
    IOC_HASH_AFTER=$(hash1 "$IOC_FILE") || { partial ioc_hash_failed; IOC_HASH_AFTER=''; }
    [ -z "$IOC_HASH_AFTER" ] || [ "$IOC_SOURCE_HASH" = "$IOC_HASH_AFTER" ] || partial ioc_file_changed_during_collection
fi
rm -f "$OUT/.iocs_normalized"

# --------------------------------------------------- 8. hash manifests --
stage 8 "hash manifests"
hash_tree() {
    _o="$OUT/hashes/$1"; shift
    : > "$OUT/.hash_paths"
    for _d in "$@"; do fx "$_d" -type f -print0 2>/dev/null; done > "$OUT/.hash_paths"
    : > "$_o"
    if [ -s "$OUT/.hash_paths" ]; then
        # shellcheck disable=SC2086
        xargs -0 $HASHCMD < "$OUT/.hash_paths" > "$_o" 2>/dev/null || partial hash_tree_failed
    fi
    rm -f "$OUT/.hash_paths"
}
hash_tree web_config_tmp.sha256 /netscaler /var/netscaler /var/vpn /var/python /flash/nsconfig \
    /etc /root /var/tmp /tmp /var/cron
[ "$HASH_BINS" -eq 1 ] && hash_tree system_binaries.sha256 /bin /sbin /lib /libexec \
    /usr/bin /usr/sbin /usr/lib /usr/libexec /usr/local


stage 9 'copying evidence and verifying packaging'
PACKLOG=$OUT.packaging.log
: > "$PACKLOG" || fatal packaging_log_write
# All candidates must pass this final gate, including directly discovered logs.
# Default mode never creates a raw evidence archive or copies source content.
if [ "$SENSITIVE" -eq 1 ]; then
    tr '\0' '\n' < "$COPYLIST" | sort -u > "$OUT/.copylines" || fatal copylist_sort
    : > "$OUT/.accepted0"
    : > "$OUT/.accepted"
    : > "$OUT/files/source_before.sha256"
    : > "$OUT/.identities"
    : > "$OUT/files/hardlink_aliases.tsv"
    while IFS= read -r p; do
        case "$p" in /*) ;; *) partial invalid_copy_path; continue;; esac
        case "$p" in *[!\ -~]*|*'|'*) partial unsupported_copy_path; continue;; esac
        if [ ! -f "$p" ] || [ -L "$p" ]; then partial evidence_source_not_regular; continue; fi
        original=$p
        p=$(realpath "$p") || { partial evidence_realpath_failed; continue; }
        if [ -n "$IOC_FILE" ] && [ "$p" = "$IOC_FILE" ]; then continue; fi
        identity=$("$STAT" -f '%d:%i' "$p") || { partial evidence_stat_failed; continue; }
        case "$identity" in *[!0-9:]*|'') partial evidence_stat_invalid; continue;; esac
        prior=$(awk -F '\t' -v id="$identity" '$1==id {print $2; exit}' "$OUT/.identities")
        if [ -n "$prior" ]; then
            printf '%s\t%s\n' "$original" "$prior" >> "$OUT/files/hardlink_aliases.tsv" || fatal manifest_write
            continue
        fi
        printf '%s\t%s\n' "$identity" "$p" >> "$OUT/.identities" || fatal manifest_write
        h=$(hash1 "$p") || { partial source_hash_failed; continue; }
        printf '%s  %s\n' "$h" "${p#/}" >> "$OUT/files/source_before.sha256" || fatal manifest_write
        printf '%s\0' "$p" >> "$OUT/.accepted0" || fatal copylist_write
        printf '%s\n' "$p" >> "$OUT/.accepted" || fatal copylist_write
    done < "$OUT/.copylines"
    tar -cf "$OUT/files/evidence_files.tar" --null -T "$OUT/.accepted0" 2>> "$PACKLOG" || fatal evidence_tar_failed
    tar -tf "$OUT/files/evidence_files.tar" > "$OUT/files/evidence_files_listing.txt" 2>> "$PACKLOG" || fatal evidence_tar_invalid
    : > "$OUT/files/evidence_files.sha256"
    while IFS= read -r p; do
        # Digest the captured bytes, never label a live-source digest as captured.
        tar -xOf "$OUT/files/evidence_files.tar" -- "${p#/}" > "$OUT/.verify" 2>> "$PACKLOG" || fatal evidence_extract_failed
        h=$(hash1 "$OUT/.verify") || fatal evidence_hash_failed
        printf '%s  %s\n' "$h" "${p#/}" >> "$OUT/files/evidence_files.sha256" || fatal manifest_write
    done < "$OUT/.accepted"
    if ! cmp -s "$OUT/files/source_before.sha256" "$OUT/files/evidence_files.sha256"; then
        partial evidence_changed_during_capture
    fi
    rm -f "$OUT/.identities" "$OUT/.verify" "$OUT/.accepted" "$OUT/.accepted0" "$OUT/.copylines"
else
    status skipped 'source copies excluded by selected metadata scope'
fi
# Run after IR evidence capture so vendor workspace does not enter its timeline.
stage support_bundle 'optional vendor support bundle'
collect_support_bundle() {
    SUPPORT_DIR=$OUT/support_bundle
    mkdir "$SUPPORT_DIR" || fatal support_directory_write
    if [ ! -x /netscaler/showtechsupport.pl ]; then
        partial support_collector_unavailable; return
    fi
    # Record pre-existing paths, including broken symlinks. Never accept one as new.
    : > "$SUPPORT_DIR/before_paths.txt" || fatal support_inventory_write
    for sb_path in /var/tmp/support/collector_*.tar.gz /flash/support/collector_*.tar.gz; do
        if [ -e "$sb_path" ] || [ -L "$sb_path" ]; then
            printf '%s\n' "$sb_path" >> "$SUPPORT_DIR/before_paths.txt" || fatal support_inventory_write
        fi
    done
    hash1 /netscaler/showtechsupport.pl > "$SUPPORT_DIR/collector.sha256" || { partial support_collector_hash_failed; return; }
    printf '%s\n' 'command=/netscaler/showtechsupport.pl -scope NODE' > "$SUPPORT_DIR/status.txt" || fatal support_status_write
    timeout -k 5 "$SUPPORT_SECONDS" /netscaler/showtechsupport.pl -scope NODE < /dev/null > "$SUPPORT_DIR/command.log" 2>&1 &
    SUPPORT_RUNNER=$!
    wait "$SUPPORT_RUNNER"
    sb_rc=$?
    SUPPORT_RUNNER=''
    printf 'command_exit=%s\n' "$sb_rc" >> "$SUPPORT_DIR/status.txt" || fatal support_status_write
    if [ "$sb_rc" -ne 0 ]; then partial "support_command_failed:$sb_rc"; return; fi
    if grep -qiE '^[[:space:]]*(ERROR:|ERROR |Invalid command|Permission denied|Access denied)' "$SUPPORT_DIR/command.log"; then
        partial support_command_reported_errors
    fi
    [ -e /var/tmp/support/support.tgz ] || { partial support_archive_missing; return; }
    sb_source=$(realpath /var/tmp/support/support.tgz 2>/dev/null) || { partial support_archive_missing; return; }
    case "$sb_source" in
        /var/tmp/support/collector_*.tar.gz|/flash/support/collector_*.tar.gz) ;;
        *) partial support_archive_unexpected_path; return;;
    esac
    # Reject nested paths/control characters, even within an allowed prefix.
    sb_base=${sb_source##*/}
    case "$sb_base" in *[!a-zA-Z0-9._:-]*) partial support_archive_invalid_name; return;; esac
    [ "$sb_source" = "/var/tmp/support/$sb_base" ] || [ "$sb_source" = "/flash/support/$sb_base" ] || { partial support_archive_unexpected_path; return; }
    if grep -Fx "$sb_source" "$SUPPORT_DIR/before_paths.txt" >/dev/null; then
        partial support_archive_not_new; return
    fi
    if [ ! -f "$sb_source" ] || [ -L "$sb_source" ] || [ ! -s "$sb_source" ]; then
        partial support_archive_missing; return
    fi
    printf 'source=%s\n' "$sb_source" >> "$SUPPORT_DIR/status.txt" || fatal support_status_write
    sb_hash=$(hash1 "$sb_source") || { partial support_source_hash_failed; return; }
    sb_copy=$SUPPORT_DIR/bundle.partial.tar.gz
    if ! cp "$sb_source" "$sb_copy"; then
        rm -f "$sb_copy"; partial support_copy_failed; return
    fi
    sb_captured=$(hash1 "$sb_copy") || sb_captured=''
    sb_after=$(hash1 "$sb_source") || sb_after=''
    if [ "$sb_hash" != "$sb_captured" ] || [ "$sb_hash" != "$sb_after" ]; then
        rm -f "$sb_copy"; partial support_archive_changed; return
    fi
    if ! tar -tzf "$sb_copy" > "$SUPPORT_DIR/members.txt" 2>> "$SUPPORT_DIR/command.log" || [ ! -s "$SUPPORT_DIR/members.txt" ]; then
        rm -f "$sb_copy"; partial support_archive_invalid; return
    fi
    mv "$sb_copy" "$SUPPORT_DIR/bundle.tar.gz" || fatal support_finalize
    printf '%s  bundle.tar.gz\n' "$sb_captured" > "$SUPPORT_DIR/bundle.tar.gz.sha256" || fatal support_checksum_write
    status success 'new vendor archive captured and verified; internal diagnostic completeness not asserted'
}
if [ "$SUPPORT_BUNDLE" -eq 1 ]; then
    log 'Sensitive vendor bundle enabled; vendor diagnostics and external workspace are included'
    collect_support_bundle
else
    status skipped 'vendor support bundle not requested'
fi
stage packaging 'final archive'
rm -f "$OUT/.stat-helper" "$COPYLIST" "$OUT/.webfiles0" "$OUT/.web_only0" "$OUT/.imgpaths" "$OUT/.recent_web" \
    "$OUT/.native_manifest_paths" "$OUT/.portal_manifest_paths" "$OUT/.native_integrity_copy_paths"
[ -s "$FLAGS" ] || printf '%s\n' '[INFO] No heuristic hits; this is not proof of a clean device.' > "$FLAGS"
RESULT=0
if [ -s "$ERRORS" ]; then RESULT=2; fi
printf 'utc_end=%s\ncollection_exit=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$RESULT" >> "$OUT/00_metadata.txt" || fatal metadata_write
status success 'packaging inputs prepared'
# Materialize stage summaries; any partial/failed event takes precedence.
awk -F '\t' '
{seen[$1]=1; if($2=="partial" || $2=="failed") bad[$1]=1; if($2=="skipped") skipped[$1]=1}
END {for(s in seen) print s "\t" (bad[s]?"partial":(skipped[s]?"success_with_skips":"success"))}
' "$EVENTS" | sort > "$OUT/00_stage_status.tsv" || fatal status_write
rm -f "$ERRORS"
# Required members are mode-aware; a selected-scope skip is not a hidden error.
for required in 00_metadata.txt 00_stage_status.tsv 00_TRIAGE_FLAGS.txt timeline/bodyfile.txt; do
    [ -f "$OUT/$required" ] || fatal missing_required_member
done
[ "$SENSITIVE" -eq 0 ] || [ -f "$OUT/files/evidence_files.tar" ] || fatal missing_evidence_tar
log 'Finalizing archive; packaging diagnostics remain alongside staging on failure'
# Do not write to files inside OUT while tar is reading them.
tar -czf "$OUT.partial.tgz" -C "$OUTPARENT" "$NAME" 2>> "$PACKLOG" || fatal final_tar_failed
tar -tzf "$OUT.partial.tgz" > "$OUT.members" 2>> "$PACKLOG" || fatal final_tar_invalid
for required in 00_metadata.txt 00_stage_status.tsv 00_TRIAGE_FLAGS.txt timeline/bodyfile.txt; do
    grep -Fx "$NAME/$required" "$OUT.members" >/dev/null || fatal missing_archive_member
done
if [ "$SENSITIVE" -eq 1 ]; then grep -Fx "$NAME/files/evidence_files.tar" "$OUT.members" >/dev/null || fatal missing_archive_evidence; fi
ARCH_HASH=$(hash1 "$OUT.partial.tgz") || fatal archive_hash_failed
printf '%s  %s.tgz\n' "$ARCH_HASH" "$NAME" > "$OUT.partial.sha256" || fatal checksum_write
# Final names are inside the exclusively allocated run namespace.
mv "$OUT.partial.tgz" "$ARCHIVE" || fatal archive_finalize
mv "$OUT.partial.sha256" "$ARCHIVE.sha256" || fatal checksum_finalize
rm -f "$OUT.members"
if [ "$RESULT" -eq 0 ]; then echo 'Collection complete within selected scope.' >&2
else echo 'Collection PARTIAL: inspect 00_stage_status.tsv and 00_stage_events.tsv.' >&2; fi
printf 'Archive: %s\nSHA-256: %s\nHeuristic flags require investigation; they do not prove compromise.\n' "$ARCHIVE" "$ARCH_HASH" >&2
exit "$RESULT"
