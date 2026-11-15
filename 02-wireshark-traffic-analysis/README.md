# Lab 02: Wireshark Packet Inspection & Cleartext Protocol Audit

**Analyst:** Kapil Sayani | **Location:** Dubai, UAE  
**Framework Alignment:** Dubai Electronic Security Center (DESC ISR Cryptographic Controls) • DIFC Data Protection Law (Law No. 5 of 2020) • UAE Cybersecurity Council IA Standards  
**Legal Compliance:** Conducted strictly within an isolated virtual lab environment / authorized sample packet capture in compliance with **UAE Federal Decree-Law No. 34 of 2021**.

---

## 1. Executive Summary
A deep packet inspection (DPI) and network traffic analysis was conducted using **Wireshark** to identify unencrypted protocols, cleartext credential transmissions, and suspicious network anomalies. Under **DESC ISR Cryptographic Controls** and **DIFC Data Protection Law**, transmitting sensitive data or authentication credentials over cleartext protocols (`HTTP`, `FTP`, `Telnet`) represents a critical compliance violation and exposes the organization to credential harvesting and Man-in-the-Middle (MitM) interception.

## 2. Wireshark Display Filters Applied
* `http.request.method == "POST"` — Isolated unencrypted HTTP form submissions and cleartext login payloads.
* `ftp.request.command == "USER" || ftp.request.command == "PASS"` — Detected cleartext FTP authentication sequences.
* `arp.duplicate-address-detected` — Checked for potential ARP spoofing / Layer 2 MitM anomalies.
* `tcp.flags.syn == 1 && tcp.flags.ack == 0` — Monitored anomalous outbound/inbound TCP SYN connection spikes.

## 3. Key Findings & Compliance Risk Assessment

| Protocol / Indicator | Wireshark Evidence | SOC Severity | Dubai / UAE Framework Violation |
| :--- | :--- | :--- | :--- |
| **Cleartext HTTP (`80/TCP`)** | Unencrypted `POST` request payload & session cookies visible via *Follow TCP Stream*. | **High** | Violates **DESC ISR Cryptographic Controls** (Data-in-Transit Encryption) & **DIFC Data Protection Law**. |
| **Legacy Unencrypted Services** | Plaintext credential exchange observed without TLS handshake protection. | **High** | Fails **UAE IA Standards** baseline network transport security requirements. |
| **Layer 2 / ARP Baseline** | Verified MAC-to-IP mappings for anomalous Gratuitous ARP broadcasts. | **Medium** | Requires Dynamic ARP Inspection (DAI) per **DESC ISR Domain 4**. |

## 4. Packet Capture & Investigation Evidence
![Wireshark Traffic Analysis](./wireshark-capture.png)

* Packet Capture File: [`traffic_capture.pcapng`](./traffic_capture.pcapng) *(update filename if yours differs)*

## 5. Remediation & SOC Playbook Actions
1. **Enforce TLS 1.2 / TLS 1.3:** Decommission cleartext `HTTP` and `FTP` endpoints immediately; enforce HTTPS with HSTS and SFTP/FTPS across all internal and external interfaces.
2. **Switch Port Hardening:** Enable **Dynamic ARP Inspection (DAI)** and **DHCP Snooping** on enterprise switches to block Layer 2 Man-in-the-Middle (MitM) interception.
3. **Credential Rotation & Alerting:** Reset any credentials exposed in cleartext captures and configure SIEM/IDS signatures (Suricata/Snort) to alert Tier 1 SOC analysts on cleartext authentication traffic.
