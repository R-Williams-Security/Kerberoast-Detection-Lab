# Active Directory SOAR: Automated Kerberoast Mitigation

> **MITRE ATT&CK T1558.003 · Wazuh Cloud v4.14.4 · Sysmon v15.15 · Windows Server 2019 · Impacket · PowerShell**

---

## Overview

A complete **Attack → Detect → Respond** security pipeline engineered against a self-hosted Windows Server 2019 Active Directory environment. The lab simulates a real-world Kerberoasting credential-theft attack using the Impacket framework, detects it with a precision custom Wazuh SIEM rule built to isolate RC4 encryption anomalies from legitimate Kerberos traffic, and closes the loop automatically via a PowerShell Active Response script that disables the compromised service account — no human intervention required.

The telemetry bridges the gap between passive monitoring and active defense: structured telemetry ingestion via Sysmon v15.15 and Windows Security Auditing, high-fidelity detection logic scoped to a specific cryptographic anomaly, full MITRE ATT&CK framework alignment, and automated remediation tied directly to alert severity — reducing Mean Time to Remediate (MTTR) from hours of manual analyst review to seconds of automated action.

---

## Why Kerberoasting Is High Priority

This attack directly threatens the Confidentiality of service account credentials and the Integrity of the domain's authentication boundary.

Kerberoasting is dangerous precisely because the most damaging phase of the attack happens **entirely offline**, after the attacker has already left the network undetected.

Any authenticated domain identity user — regardless of privilege level — can request a Kerberos service ticket for any account registered with a Service Principal Name (SPN). The returned ticket is encrypted with that service account's password hash. The attacker saves the ticket and disconnects. There is no further network interaction — no brute-force traffic, no repeated authentication attempts, nothing for a perimeter tool or DLP system to flag.

Service accounts are the highest-value targets: they frequently hold elevated privileges, rarely have password rotation enforced, and are seldom monitored for lateral movement. Offline cracking tools can recover weak service account passwords in seconds to minutes.

**The critical detection constraint:** the only viable window to catch this attack is the ticket request itself — Windows Security Event ID 4769. Once the ticket leaves the Domain Controller, the opportunity is closed. This is why the detection rule must filter precisely on the cryptographic anomaly, and the response must be automated — not queued for a human analyst.

---

## Architecture

```
┌─────────────────────┐    ┌────────────────────────────────────┐    ┌──────────────────────────────┐
│  ATTACKER           │    │  VICTIM — DC01                     │    │  SIEM — Wazuh Cloud v4.14.4  │
│  Kali Linux         │    │  Windows Server 2019               │    │  LAB-DC01 · US East (N.VA)   │
│  192.168.220.140    │    │  attacklab.local                   │    │                              │
│                     │    │  192.168.220.130                   │    │                              │
│  impacket-          │    │                                    │    │  Rule 100002 matches:        │
│  GetUserSPNs  ──────┼───►│  Kerberos issues RC4 TGS ticket    │───►│  EventID  = 4769             │
│  jdoe:Password123!  │    │  Event ID 4769 generated           │    │  EncType  = 0x17             │
│  -request           │    │  EncryptionType: 0x17              │    │                              │
│  sql_service        │    │                                    │    │  ALERT Level 12              │
│                     │    │  Sysmon v15.15 captures            │    │  T1558.003                   │
│                     │    │  process + network telemetry       │    │  Credential Access           │
│                     │    │                                    │    │                              │
│                     │    │  WazuhSvc (Agent 001) forwards     │    │  Active Response triggers    │
│                     │    │  events to Wazuh Cloud             │◄───┤  kerb-block.ps1 via stdin    │
│                     │    │                                    │    │                              │
│                     │    │  kerb-block.ps1 executes:          │    └──────────────────────────────┘
│                     │    │  Disable-ADAccount sql_service     │
│                     │    │  C:\Security\SOAR.log written      │
└─────────────────────┘    └────────────────────────────────────┘
```

---

## Lab Environment

| Component | Detail |
|---|---|
| Hypervisor | VMware Workstation 17.5 |
| Domain Controller | Windows Server 2019 Standard Evaluation · DC01 |
| OS Build | 10.0.17763.3650 |
| Domain | attacklab.local |
| DC IP Address | 192.168.220.130 |
| Wazuh Agent IP | 192.168.220.133 |
| Attacker VM | Kali Linux · 192.168.220.140 |
| Network | NAT — both VMs on shared subnet |
| SIEM | Wazuh Cloud v4.14.4 · Agent ID 001 · Status: Active |
| Endpoint Telemetry | Sysmon v15.15 · custom sysmonconfig.xml |
| Attack Framework | Impacket — GetUserSPNs |

---

## Repository Contents

| File | Description |
|---|---|
| `local_rules.xml` | Custom Wazuh detection rule 100002 — filters Event ID 4769 for RC4 encryption type `0x17` |
| `kerb-block.ps1` | Active Response SOAR script — disables compromised account via `Disable-ADAccount`, writes timestamped audit entry to `C:\Security\SOAR.log` |
| `kerberoast_alert.json` | Raw Wazuh alert — fired rule, MITRE T1558.003 mapping, attacker IP, targeted account, full event context |
| `windows_raw_log.xml` | Raw Windows Security Event ID 4769 from DC01 — source telemetry confirming `TicketEncryptionType: 0x17` |
| `README.md` | This file |

---

## Detection Logic

**Rule ID:** `100002` · **Alert Level:** `12` · **MITRE:** `T1558.003`

Modern Active Directory environments negotiate AES encryption (types `0x11` / `0x12`) for Kerberos service tickets. Kerberoasting tools — including Impacket's `GetUserSPNs` and Rubeus — force a downgrade to legacy RC4-HMAC (`0x17`) by default, because RC4 hashes are significantly faster to crack offline than AES-encrypted material.

Filtering exclusively on `0x17` means the rule ignores the continuous high-volume legitimate AES Kerberos traffic on the Domain Controller and fires only on the cryptographic anomaly. This makes the rule low-noise, high-fidelity, and requires no additional tuning.

```xml
<group name="kerberoast_detection">

  <!-- Kerberoasting: service ticket requested using RC4 encryption (0x17)    -->
  <!-- RC4 is legacy and only used by attacker tools like Impacket by default -->
  <!-- Legitimate modern requests use AES (0x11 or 0x12)                      -->

  <rule id="100002" level="12">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4769$</field>
    <field name="win.eventdata.ticketEncryptionType">^0x17$</field>
    <description>Kerberoasting Attack: RC4 service ticket request detected (T1558.003)</description>
    <mitre>
      <id>T1558.003</id>
    </mitre>
  </rule>

</group>
```

Alert level `12` is required for Wazuh Active Response eligibility — the automated response only fires at or above the threshold defined in `ossec.conf`.

---

## SOAR Automated Response

On alert fire, Wazuh Active Response executes `kerb-block.ps1` on DC01 via stdin — the correct Wazuh data channel for Windows agents. The Active Response configuration in `ossec.conf`:

```xml
<command>
  <n>win-disable-user</n>
  <executable>kerb-block.ps1</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <command>win-disable-user</command>
  <location>local</location>
  <rules_id>100002</rules_id>
</active-response>
```

The script parses the alert JSON received via stdin, extracts the targeted service account name, calls `Disable-ADAccount` via the RSAT Active Directory PowerShell module installed on DC01, and writes a timestamped audit entry to `C:\Security\SOAR.log`.

**Verification on DC01:**

```powershell
Get-ADUser sql_service | Select-Object Name, Enabled
# Enabled : False

Get-Content C:\Security\SOAR.log
# 2026-03-28 15:54:xx - SUCCESS: Disabled account: sql_service
```

---

## Confirmed Evidence

All values drawn directly from `kerberoast_alert.json` and `windows_raw_log.xml`. Nothing approximated.

| Field | Confirmed Value | Source |
|---|---|---|
| Requesting account | jdoe@ATTACKLAB.LOCAL | kerberoast_alert.json |
| Attacker IP | 192.168.220.140 | kerberoast_alert.json |
| Attacker port | 50974 | kerberoast_alert.json |
| DC01 agent IP | 192.168.220.133 | kerberoast_alert.json |
| Service targeted | sql_service | windows_raw_log.xml |
| Service SID | S-1-5-21-2251009163-3126931792-3784047572-1103 | windows_raw_log.xml |
| SPN registered | MSSQLSvc/DC01.attacklab.local:1433 | Active Directory |
| Encryption type | **0x17 — RC4-HMAC (anomalous)** | windows_raw_log.xml |
| Windows Event ID | 4769 | windows_raw_log.xml |
| Event Record ID | 5275 | windows_raw_log.xml |
| Event timestamp | 2026-03-28T15:54:18.588788300Z | windows_raw_log.xml |
| Wazuh rule fired | 100002 · Level 12 | kerberoast_alert.json |
| MITRE technique | **T1558.003 · Credential Access · Kerberoasting** | kerberoast_alert.json |
| Wazuh alert ID | 1774702436.0 | kerberoast_alert.json |
| Wazuh cluster node | wazuh-manager-master-0 | kerberoast_alert.json |
| Account status post-response | sql_service · Enabled: False | kerb-block.ps1 output |

---

## Key Setup Steps

### Kerberos Audit Policy — Group Policy Configuration

Enabled via Group Policy Management Console on DC01:

```
Computer Configuration → Policies → Windows Settings → Security Settings
→ Advanced Audit Policy Configuration → Account Logon
→ Audit Kerberos Service Ticket Operations → Success and Failure
```

Enforced and verified at the command line:

```powershell
gpupdate /force
# Computer Policy update has completed successfully.
# User Policy update has completed successfully.

auditpol /get /subcategory:"Kerberos Service Ticket Operations"
# Kerberos Service Ticket Operations    Success and Failure
```

This is the foundational telemetry control. Without this policy, Event ID 4769 is never generated — the detection pipeline has nothing to act on.

### SPN Registration — The Attack Surface Condition

```powershell
Get-ADUser sql_service -Properties ServicePrincipalNames
# ServicePrincipalNames : {MSSQLSvc/DC01.attacklab.local:1433}
```

Any authenticated domain user can request a Kerberos service ticket for any SPN-registered account — no elevated privileges required. The SPN registered on `sql_service` is the architectural condition that exposed it as a valid Kerberoast target.

### Sysmon v15.15 Deployment

```powershell
cd C:\Sysmon
.\Sysmon64.exe -i sysmonconfig.xml -accepteula
# System Monitor v15.15
# Sysmon schema version: 4.90
# Sysmon64 installed.
# SysmonDrv installed.
# Sysmon64 started.

Get-Service sysmon64
# Status   Name       DisplayName
# ------   ----       -----------
# Running  Sysmon64   sysmon64
```

Sysmon telemetry confirmed ingested by Wazuh — `Microsoft-Windows-Sysmon` events (including rule IDs 92052, 92031, 92201) visible in Wazuh Threat Hunting view alongside Windows Security Auditing events, providing full process-level and network-level visibility on DC01.

### Wazuh Agent Deployment

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.4-1.msi `
  -OutFile $env:tmp\wazuh-agent
msiexec /i $env:tmp\wazuh-agent /q `
  WAZUH_MANAGER='qd4m612yop1t.cloud.wazuh.com' `
  WAZUH_AGENT_NAME='DC01'

NET START WazuhSvc
Get-Service WazuhSvc
# Status   Name       DisplayName
# ------   ----       -----------
# Running  WazuhSvc   Wazuh
```

---

## MITRE ATT&CK Mapping

| | |
|---|---|
| Tactic | Credential Access |
| Technique | T1558 — Steal or Forge Kerberos Tickets |
| Sub-technique | **T1558.003 — Kerberoasting** |
| Detection Source | Windows Security Log · Event ID 4769 |
| Telemetry Layer | Sysmon v15.15 · Microsoft-Windows-Security-Auditing provider |
| Response | Wazuh Active Response · kerb-block.ps1 · Disable-ADAccount (RSAT) |

---

## Future Hardening — Reactive to Proactive

The SOAR pipeline neutralises active threats at the moment of detection. Long-term reduction of the Kerberoasting attack surface requires architectural controls applied at the domain level:

**Enforce AES Encryption via GPO** — Disable legacy RC4 encryption types across the domain, forcing AES-128 and AES-256 for all Kerberos tickets. This removes the downgrade path entirely — without RC4 availability, there is no crackable hash.

**Fine-Grained Password Policies (FGPP)** — Apply strict complexity and rotation requirements specifically to SPN-registered service accounts. Even if a ticket is intercepted, high-entropy passwords make offline cracking computationally unfeasible.

**Group Managed Service Accounts (gMSA)** — Transition critical services to gMSA. Windows automates password management for gMSA accounts — 120-character randomly generated passwords rotated automatically — eliminating static credentials entirely and removing the attack surface at its root.

---

## Tools & Skills Demonstrated

**Platform & Infrastructure**
VMware Workstation 17.5 · Windows Server 2019 · Active Directory Domain Services (AD DS) · Domain Controller deployment · NAT network configuration

**Identity & Access Management**
Active Directory user provisioning · Service Principal Name (SPN) registration · `New-ADUser` · `Disable-ADAccount` · `Get-ADUser` · RSAT (Remote Server Administration Tools) · Fine-Grained Password Policy (FGPP) · Group Managed Service Accounts (gMSA) · Least Privilege enforcement

**Audit & Group Policy**
Group Policy Management Console (GPMC) · Advanced Audit Policy Configuration · Audit Kerberos Service Ticket Operations · `gpupdate /force` · `auditpol` · Domain-wide policy enforcement

**Threat Detection & SIEM**
Wazuh Cloud v4.14.4 · Custom detection rule authoring · Windows Security Event Log · Event ID 4769 · RC4 encryption downgrade detection (`TicketEncryptionType 0x17`) · Wazuh Threat Hunting · Alert severity classification (Level 12) · High-fidelity low-noise rule design

**Endpoint Telemetry**
Sysmon v15.15 · custom `sysmonconfig.xml` · Process creation monitoring (Event ID 1) · Network connection monitoring (Event ID 3) · `Microsoft-Windows-Security-Auditing` provider · `Microsoft-Windows-Sysmon` provider

**Offensive Techniques (Simulated)**
Kerberoasting (T1558.003) · Impacket — `GetUserSPNs` · RC4 ticket request · Credential Access · Living-off-the-land (LotL) technique simulation · Attack surface identification

**SOAR & Automated Response**
Wazuh Active Response · `ossec.conf` configuration · `kerb-block.ps1` · PowerShell scripting · Automated account lockout · MTTR reduction · Security Orchestration, Automation and Response (SOAR)

**Frameworks & Standards**
MITRE ATT&CK T1558.003 · Zero Trust principles · Attack Surface Reduction · Least Privilege · NIST Cybersecurity Framework · Domain hardening

**Languages & Scripting**
PowerShell · XML (Wazuh rule and ossec.conf authoring)

---

Note: All IP addresses (192.168.220.x) and hostnames displayed are part of a logically isolated, private NAT laboratory environment. No production infrastructure or PII is exposed.

> **Portfolio:** [williamsransom-portfolio — Active Directory SOAR: Automated Kerberoast Mitigation](https://sites.google.com/view/williamsransom-portfolio/project-page/active-directory-soar-automated-kerberoast-mitigation)
> **Contact:** williamsransom4@gmail.com