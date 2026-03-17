# Scenario 04: New User Account Creation Detection

**Date:** 2026-03-17
**MITRE ATT&CK:** T1136.001 — Create Account: Local Account
**Severity:** High

## Lab Setup
- Attacker: Kali Linux (ATTACKER_IP)
- Victim: Ubuntu Server (VICTIM_IP)
- SIEM: Splunk Enterprise (Free)

## Attack Executed
```bash
# Simulate attacker creating backdoor account
sudo useradd -m hacker123
sudo passwd hacker123
```

## Why Attackers Do This
Attackers create new user accounts to:
- Maintain persistent access to compromised systems
- Avoid detection by using legitimate-looking accounts
- Escalate privileges by adding accounts to sudo group

## Detection SPL Query
```splunk
index=main 
((sourcetype=linux_secure "new user") OR 
(sourcetype=linux_audit key=user_modification))
| eval detection_source=sourcetype
| table _time, host, user, cmd, detection_source, _raw
| sort -_time
```

## Findings
- Events detected across both linux_secure and linux_audit
- New account creation visible in both log sources
- Dual source detection ensures no blind spots

## MITRE ATT&CK Mapping
- Tactic: Persistence
- Technique: T1136.001 — Create Account: Local Account

##Screenshot
![New User Creation Detection](../../screenshots/04-new-user-creation.png)

## Response Steps
1. Immediately disable the newly created account
2. Investigate who created the account and when
3. Check if account was added to sudo/admin groups
4. Review all actions taken by the new account
5. Investigate how attacker gained access to create account
6. Check for other persistence mechanisms
EOF
