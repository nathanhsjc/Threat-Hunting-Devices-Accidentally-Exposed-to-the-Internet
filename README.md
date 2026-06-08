


<img width="1604" height="730" alt="image" src="https://github.com/user-attachments/assets/b9a4eb8c-b5bc-473d-be85-02988003b53e" />




## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)




# Threat Hunt: Devices Accidentally Exposed to the Internet
 
**Tools:** Microsoft Defender for Endpoint · KQL · MITRE ATT&CK  
**Environment:** Azure · Windows Server VM (`windows-target-1`)  
**Outcome:** No successful brute force confirmed — NSG hardening recommended
 
---
 
## Scenario
 
During routine maintenance, the security team was tasked with investigating VMs in the shared services cluster (handling DNS, Domain Services, DHCP) that had been mistakenly exposed to the public internet. The goal: identify misconfigured VMs and determine whether any external brute force login attempts had succeeded.
 
Because some older devices lacked account lockout policies, a successful brute force compromise was considered a realistic possibility.
 
---
 
## Hypothesis
 
> "One or more internet-exposed VMs in the shared services cluster may have been successfully brute-forced by an external actor, given the absence of account lockout controls and prolonged public exposure."
 
---
 
## Tools & Data Sources
 
| Source | Purpose |
|---|---|
| `DeviceInfo` | Identify internet-facing VMs |
| `DeviceLogonEvents` | Analyze failed and successful logon attempts |
| Microsoft Defender for Endpoint | Advanced Hunting (KQL) |
| MITRE ATT&CK Framework | TTP mapping |
 
---
 
## Hunt Walkthrough
 
### Step 1 — Identify Internet-Facing Devices
 
Queried `DeviceInfo` to find VMs flagged as internet-facing:
 
```kql
DeviceInfo
| where DeviceName == "windows-target-"
| where IsInternetFacing == "true"
| order by Timestamp desc
```

<img width="1038" height="472" alt="image" src="https://github.com/user-attachments/assets/6e2090f2-728a-426e-a75a-0027ec5519c5" />


 
**Finding:** `windows-target-` confirmed as internet-facing, with recent timestamps indicating ongoing exposure.
 
---
 
### Step 2 — Enumerate Failed Logon Attempts
 
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts desc
```

<img width="1035" height="312" alt="image" src="https://github.com/user-attachments/assets/bb79b210-0c2c-4c50-bf3f-55ecd1154ea3" />


---------
 
**Top offenders:**
 
| RemoteIP | Attempts |
|---|---|
| 45.238.132.30 | 32 |
| 3.65.40.162 | 12 |
| 188.246.226.124 | 7 |
| 54.151.176.0 | 7 |
| 51.178.174.31 | 6 |
| 95.213.184.95 | 6 |
| 135.125.90.97 | 4 |
| 185.151.241.134 | 4 |
 
24 unique external IPs attempted logons — consistent with automated scanning and credential stuffing bots.
 
---
 
### Step 3 — Check Whether Top Offenders Succeeded
 
Took the top 7 IPs by failure count and queried for any successful logons:
 
```kql
let RemoteIPsInQuestion = dynamic(["45.238.132.30","3.65.40.162","188.246.226.124","54.151.176.0","51.178.174.31","95.213.184.95","135.125.90.97"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

<img width="1040" height="207" alt="image" src="https://github.com/user-attachments/assets/89c653ff-43a3-4be5-9df0-2178b26d5bd4" />

--
 
**Finding:** No successful logons from any of the top attacking IPs. ✅
 
---
 
### Step 4 — Correlate Failed + Successful Logons Across All IPs
 
Ran a broader join to catch any IP that had both failed and successful logons — the classic brute force success pattern:
 
```kql
let FailedLogons = DeviceLogonEvents
| where DeviceName == "windows-target-"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize FailedAttempts = count() by RemoteIP, DeviceName;
 
let SuccessfulLogons = DeviceLogonEvents
| where DeviceName == "windows-target-"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| summarize SuccessfulLogons = count() by RemoteIP, DeviceName, AccountName;
 
FailedLogons
| join kind=inner SuccessfulLogons on RemoteIP
| project RemoteIP, DeviceName, FailedAttempts, SuccessfulLogons, AccountName
| order by FailedAttempts desc
```
 
**Finding:** No IP appeared in both failed and successful logon sets. No brute force success detected. ✅
 
---
 
## MITRE ATT&CK Mapping
 
| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Exploit Public-Facing Application | T1190 |
| Initial Access | External Remote Services | T1133 |
| Credential Access | Brute Force — Password Guessing | T1110.001 |
| Credential Access | Brute Force — Password Spraying | T1110.003 |
| Lateral Movement | Remote Services — RDP | T1021.001 |
| Defense Evasion | Valid Accounts | T1078 |
| Reconnaissance | Active Scanning | T1595 |
| Reconnaissance | Gather Victim Host Information | T1592 |
 
---
 
## Outcome
 
The hunt confirmed the VM was actively targeted by external actors using automated brute force tools, but **no successful compromise was identified**. The absence of account lockout policies on this device remains an unacceptable risk — brute force success was a matter of time and luck, not a hardened defense.
 
---
 
## Hypothetical Incident Response (If Breach Had Occurred)
 
Had a brute force success been confirmed — i.e., an external IP appearing in both `LogonFailed` and `LogonSuccess` — the response would have followed NIST 800-61 phases:
 
**Containment**
- Immediately isolate the VM using MDE's "Isolate Device" response action to cut off lateral movement
- Block the offending IP(s) at the NSG level
**Eradication**
- Review all activity on the machine during and after the successful logon: new accounts created, processes spawned, files modified, outbound connections made
- Terminate any unauthorized sessions and revoke compromised credentials
- Scan for persistence mechanisms (scheduled tasks, new local admin accounts, registry run keys)
**Recovery**
- Restore from a known-good snapshot if tampering was confirmed
- Re-onboard to MDE and verify telemetry is clean post-restore
**Post-Incident**
- Document the full timeline from first failed logon to successful compromise
- Brief stakeholders on the misconfiguration that enabled exposure
- Apply hardening measures (see below) before bringing the VM back online
---
 
## Recommendations
 
| Control | Implementation |
|---|---|
| **Account Lockout Policy** | Lock accounts after 5 failed attempts via Group Policy (`secpol.msc`) |
| **NSG Hardening** | Restrict RDP (port 3389) to specific trusted IP ranges only — remove any 0.0.0.0/0 inbound rules |
| **MFA on Remote Access** | Enforce MFA for all RDP/remote sessions |
| **Just-In-Time VM Access** | Enable JIT access in Microsoft Defender for Cloud to open RDP only on-demand |
| **Alert Rule** | Create a Sentinel scheduled query rule to alert on >10 failed logons from a single remote IP within 5 minutes |
 
---
 
## What I Would Improve
 
- **Automate the hunt** — the correlation query (failed + successful join) could be packaged as a recurring Sentinel analytics rule rather than a manual hunt
- **Enrich IPs with threat intel** — pipe the offending IPs through AbuseIPDB or Microsoft Sentinel Threat Intelligence to contextualize which are known malicious infrastructure vs. opportunistic scanners
- **Expand scope** — the hunt focused on `windows-target-` specifically; a fleet-wide version of the query would surface any other exposed VMs in the environment simultaneously
- **Add AccountName analysis** — tracking which usernames were targeted most frequently reveals whether attackers are doing username enumeration or spraying common accounts like `Administrator`
---
 
## References
 
- [MITRE ATT&CK — T1110 Brute Force](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK — T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- [NIST SP 800-61 Rev. 2 — Incident Handling Guide](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- [Microsoft Docs — DeviceLogonEvents schema](https://learn.microsoft.com/en-us/microsoft-365/security/defender/advanced-hunting-devicelogonevents-table)
