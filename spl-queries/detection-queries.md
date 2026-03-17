# 🔍 SPL Detection Queries

## 01 — SSH Brute Force (T1110.001)
```splunk
index=main sourcetype=linux_secure failed
| stats count by src_ip, user
| where count > 5
| sort -count
```

## 02 — Nmap Recon (T1046)
```splunk
index=main sourcetype=syslog
| timechart count span=10s
| where count > 50
```

## 03 — Reverse Shell (T1059.004)
```splunk
index=main sourcetype=linux_audit
| search "dev/tcp" OR "bash -i" OR "/bin/bash"
| table _time, host, comm, exe, cmd
| sort -_time
```

## 04 — New User Created (T1136.001)
```splunk
index=main 
((sourcetype=linux_secure "new user") OR 
(sourcetype=linux_audit key=user_modification))
| eval detection_source=sourcetype
| table _time, host, user, cmd, detection_source
| sort -_time
```

## 05 — Sudo Abuse (T1548.003)
```splunk
index=main sourcetype=linux_secure sudo
| stats count by user, host
| sort -count
```
