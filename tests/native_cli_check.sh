#!/bin/sh
# Stream CLI output into an aggregate validator; never persist raw config/sessions.
# shellcheck disable=SC3045 # Native FreeBSD sh supports core limits.
ulimit -c 0
while IFS='|' read -r name command; do
    { timeout -k 2 20 nscli -U '%%:.:.' "$command" 2>/dev/null; printf '\n__NSIR_RC__%s\n' "$?"; } |
        awk -v name="$name" '/^__NSIR_RC__/ {rc=substr($0,12); next}
            /^[[:space:]]*(ERROR:|ERROR |Invalid command|Permission denied|Access denied)/ {error=1}
            END {printf "%s\texit=%s\tsemantic_error=%d\n", name,rc,error}'
done <<'CMDS'
ns_version|show ns version
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
responder_policies|show responder policy
rewrite_policies|show rewrite policy
ssl_certkeys|show ssl certKey
syslog_actions|show audit syslogAction
nslog_actions|show audit nslogAction
ntp_servers|show ntp server
CMDS
