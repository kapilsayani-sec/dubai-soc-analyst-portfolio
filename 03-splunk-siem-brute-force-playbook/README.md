# Lab 03: SIEM SSH Brute-Force Detection & Incident Response Playbook

## 1. Executive Summary
This lab simulates a Tier-1/Tier-2 SOC investigation of an external SSH brute-force attack (`MITRE ATT&CK T1110`) targeting a Dubai production Linux host (`dubai-prod-web01`), resulting in account compromise (`deploy`) and root privilege escalation (`T1548`). Log triage and correlation were performed using Linux CLI SIEM parsing pipelines and equivalent Splunk SPL detection rules.

## 2. Regulatory & Compliance Alignment (Dubai / UAE)
* **Dubai Electronic Security Center (DESC) ISR:**
  * **Domain 11 (Information Security Incident Management):** Rapid triage, containment, and root-cause documentation of unauthorized access.
  * **Domain 10 (Communications & Operations Management):** Centralized audit logging, clock synchronization, and log retention for authentication events.
* **UAE Information Assurance (IA) Standards (Control M5.2 & M5.3):** Continuous monitoring of privileged account activity (`root` / `sudo`) and automated alerting on repeated authentication failures.
* **UAE Federal Decree-Law No. 34 of 2021 (Combating Rumors and Cybercrimes):** Article 2 & Article 3 evidentiary preservation of unauthorized system access and privilege elevation attempts.

## 3. Investigation Findings (`siem_triage_report.txt`)
* **Primary Attacker IP:** `185.220.101.42` (8 failed SSH attempts within 15 seconds, followed by 1 successful password login).
* **Secondary Scanner IP:** `91.240.118.172` (2 failed SSH attempts against `root`).
* **Compromised Account:** `deploy` (authenticated via password at `09:01:29` from `185.220.101.42`).
* **Privilege Escalation:** `deploy` executed `sudo /bin/bash` at `09:02:05` to gain an interactive `root` shell.

## 4. Splunk SPL Equivalent Detection Query
```spl
index=linux_auth sourcetype=linux_secure ("Failed password" OR "Accepted password")
| stats count(eval(match(_raw, "Failed password"))) as failed_attempts,
        count(eval(match(_raw, "Accepted password"))) as successful_logins,
        values(user) as targeted_users by src_ip, host
| where failed_attempts >= 5 AND successful_logins >= 1
```

## 5. Containment & Remediation Playbook
1. **Immediate Containment:** Block `185.220.101.42` and `91.240.118.172` at the perimeter firewall / cloud Security Group and kill active sessions for `deploy`.
2. **Credential & Key Reset:** Force password rotation for `deploy`, revoke active SSH keys, and audit `/root/.ssh/authorized_keys` and `crontab` for persistence.
3. **Hardening (DESC ISR Access Control):** Disable SSH password authentication (`PasswordAuthentication no`), enforce key-based authentication with MFA, and restrict `PermitRootLogin no`.

## 6. Evidence Artifacts
* `linux_auth_security.log` — Raw authentication and privilege escalation telemetry.
* `siem_triage_report.txt` — Extracted IOCs, attacker frequency counts, and breach timeline.
* `siem-bruteforce-triage.png` — Terminal execution and triage verification screenshot.
