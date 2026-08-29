/*
    SentinelAI — YARA Signature Rules for NSL-KDD Network Events (Phase 13)

    IMPORTANT — ILLUSTRATIVE RULES, NOT THREAT-INTEL SOURCED:
        These rules are original, written specifically for SentinelAI's
        NSL-KDD feature set.  They match on serialized event fields
        (key=value text), NOT on raw binary payloads.  They demonstrate
        the hybrid detection architecture (signatures + ML anomaly detection)
        for the dissertation, and are NOT sourced from or intended to
        replicate real-world malware YARA repositories.

    Each rule targets a specific suspicious network pattern visible in the
    NSL-KDD feature space.
*/


rule FTP_Failed_Connection
{
    meta:
        description = "FTP connection with failed status (S0 flag) — may indicate scanning or failed exploit attempts against FTP services"
        author = "SentinelAI Phase 13"
        severity = "medium"

    strings:
        $service = "service=ftp"
        $flag    = "flag=S0"

    condition:
        $service and $flag
}


rule ICMP_Unusual_Bytes
{
    meta:
        description = "ICMP traffic with non-trivial src_bytes — ping sweep or ICMP tunnel-like pattern"
        author = "SentinelAI Phase 13"
        severity = "medium"

    strings:
        $proto     = "protocol_type=icmp"
        $high_src  = /src_bytes=(5\d{2}|[6-9]\d{2}|\d{4,})/

    condition:
        $proto and $high_src
}


rule Telnet_Root_Access
{
    meta:
        description = "Telnet session with root shell obtained — critical indicator of remote compromise"
        author = "SentinelAI Phase 13"
        severity = "critical"

    strings:
        $service    = "service=telnet"
        $root_shell = "root_shell=1"

    condition:
        $service and $root_shell
}


rule SYN_Flood_Pattern
{
    meta:
        description = "High SYN-error rate connection — characteristic of SYN flood DoS or port scanning"
        author = "SentinelAI Phase 13"
        severity = "high"

    strings:
        $flag       = "flag=S0"
        $high_serr  = /serror_rate=0\.(8|9)\d*/
        $full_serr  = "serror_rate=1.0"

    condition:
        $flag and ($high_serr or $full_serr)
}


rule SSH_Brute_Force
{
    meta:
        description = "SSH service with multiple failed logins — brute-force credential attack pattern"
        author = "SentinelAI Phase 13"
        severity = "high"

    strings:
        $service    = "service=ssh"
        $fail2      = "num_failed_logins=2"
        $fail3      = "num_failed_logins=3"
        $fail4      = "num_failed_logins=4"
        $fail5      = "num_failed_logins=5"
        $fail_high  = /num_failed_logins=([6-9]|\d{2,})/

    condition:
        $service and ($fail2 or $fail3 or $fail4 or $fail5 or $fail_high)
}


rule Large_Outbound_Transfer
{
    meta:
        description = "Very large src_bytes with minimal dst_bytes — potential data exfiltration or C2 data upload"
        author = "SentinelAI Phase 13"
        severity = "high"

    strings:
        $big_src   = /src_bytes=\d{6,}/
        $small_dst = /dst_bytes=[0-9]{1,3}\b/

    condition:
        $big_src and $small_dst
}


rule HTTP_Privilege_Escalation
{
    meta:
        description = "HTTP session with su_attempted — web-based privilege escalation attempt"
        author = "SentinelAI Phase 13"
        severity = "critical"

    strings:
        $service  = "service=http"
        $su       = "su_attempted=1"
        $su2      = "su_attempted=2"

    condition:
        $service and ($su or $su2)
}


rule Multi_Host_Reconnaissance
{
    meta:
        description = "Connection with very high diff_srv_rate and low duration — network reconnaissance / port sweep"
        author = "SentinelAI Phase 13"
        severity = "medium"

    strings:
        $short_dur  = "duration=0"
        $high_diff  = /diff_srv_rate=0\.(6|7|8|9)\d*/
        $full_diff  = "diff_srv_rate=1.0"

    condition:
        $short_dur and ($high_diff or $full_diff)
}
