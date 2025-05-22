

# ⚔️ Threat Hunting Lab: Devices Accidentally Exposed to the Internet

## 🧪 Scenario Summary

During routine maintenance, the security team was tasked with investigating any virtual machines (VMs) in the shared services cluster (handling DNS, Domain Services, DHCP, etc.) that were mistakenly exposed to the public internet. The focus was on identifying misconfigurations and investigating brute-force login attempts.

---

## 🧭 Lab Setup

- **Target VM**: `windows-target-1`
- **Exposure Duration**: > 7 days
- **Log Source Tables**: `DeviceInfo`, `DeviceLogonEvents`
- **Threat Hypothesis**: Public exposure of VMs without lockout policies could lead to successful brute-force login attempts.

---

## 🔍 Phase 1: Data Collection

**Confirm internet exposure**:
```kql
DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == true
| order by Timestamp desc
```

---

## 📊 Phase 2: Data Analysis

### 🔒 Check Most Failed Logon Attempts
```kql
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by ActionType, RemoteIP, DeviceName
| order by Attempts desc
```

### 🎯 Investigate if Any of Those IPs Succeeded
```kql
let RemoteIPsInQuestion = dynamic(["119.42.115.235", "183.81.169.238", "74.39.190.50", "121.30.214.172", "83.222.191.62", "45.41.204.12", "192.109.240.116"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

### 🧠 Correlate Failed and Successful Logons
```kql
let FailedLogons = DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize FailedLogonAttempts = count() by RemoteIP, DeviceName;

let SuccessfulLogons = DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where isnotempty(RemoteIP)
| summarize SuccessfulLogons = count() by RemoteIP, DeviceName, AccountName;

FailedLogons
| join kind=inner (SuccessfulLogons) on RemoteIP
| project RemoteIP, DeviceName, FailedLogonAttempts, SuccessfulLogons, AccountName
```

---

## 📌 Timeline Summary & Findings

- **Internet Exposure Confirmed**:
```kql
DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == true
| order by Timestamp desc
```

- **Exposure Detected As Of**: `2025-05-21T05:07:28Z`

- **Action Type Distribution**:
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| summarize count() by ActionType
| order by count_ desc
```

- **Multiple Remote IPs Attempted Unauthorized Access**:
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by RemoteIP, DeviceName
| order by Attempts desc
```

- **Top Offending IPs Had No Successful Logons**:
```kql
let RemoteIPsInQuestion = dynamic(["45.227.254.130", "197.210.194.240", "194.180.49.123", "185.156.73.226", "38.55.247.6", "185.39.19.57", "122.11.143.53"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```
> ✅ No results returned — no successful logons from suspicious IPs.

---

## ✅ Verified Legitimate Logons

Only two successful remote logons were detected in the last 30 days:

```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
```

- **Account**: `labuser`  
- **Failed logons**: `0`  
- **IP origin**: Verified authorized

---

## 🔐 Mapped MITRE ATT&CK TTPs

| ID          | Technique                                 |
|-------------|--------------------------------------------|
| T1595.001   | Active Scanning: Scanning IP Blocks       |
| T1110.001   | Brute Force: Password Guessing            |
| T1078       | Valid Accounts                            |

---

## 🧯 Response & Recommendations

- ✅ **No unauthorized access** was confirmed.
- 🔒 Harden NSG to restrict RDP to trusted IPs only.
- 🔐 Enforce **account lockout** policies for repeated failed attempts.
- 🔐 Implement **Multi-Factor Authentication (MFA)** for all remote access.

---

## 🧠 Lessons Learned

- Use security group rules to reduce exposure of critical services.
- Monitor `DeviceLogonEvents` for early signs of brute-force activity.
- Combine detection with ATT&CK mapping for contextual response.
- Validate and document successful logons to eliminate false positives.
