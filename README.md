
# ⚔️ Threat Hunting Lab: Devices Accidentally Exposed to the Internet

## 🧪 Scenario Summary

During routine maintenance, the security team was tasked with investigating virtual machines (VMs) in the shared services cluster that may have been mistakenly exposed to the public internet. The goal was to identify misconfigured devices and determine if any brute-force login attempts or successes occurred.

---

## 🧭 Lab Setup

- **Target VM**: `windows-target-1`
- **Duration of Exposure**: At least 7 days
- **Log Sources Used**:
  - `DeviceInfo`
  - `DeviceLogonEvents`
- **Hypothesis**: Publicly exposed VMs without account lockout policies are vulnerable to brute-force login attacks.

---

## 🔍 Phase 1: Data Collection

Check for internet-facing devices:
```kql
DeviceInfo
| where DeviceName == "windows-target-1"
| where IsInternetFacing == true
| order by Timestamp desc
```

Check logon actions on the target device:
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| summarize count() by ActionType
| order by count_ desc
```

---

## 📊 Phase 2: Data Analysis

Identify failed logon attempts from remote IPs:
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonFailed"
| where isnotempty(RemoteIP)
| summarize Attempts = count() by RemoteIP, DeviceName
| order by Attempts desc
```
## 🔐 Top Failed Logon Attempts

![Top Failed Logon Attempts](./TopFailedLogon.png)


Check if any of the top offending IPs succeeded:
```kql
let RemoteIPsInQuestion = dynamic(["45.227.254.130","197.210.194.240", "194.180.49.123", "185.156.73.226", "38.55.247.6", "185.39.19.57", "122.11.143.53"]);
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

## ✅ No results were returned, indicating NO successful logons from these IPs.

Check for Any Successful Logons 
```kql
DeviceLogonEvents
| where LogonType has_any("Network", "Interactive", "RemoteInteractive", "Unlock")
| where ActionType == "LogonSuccess"
| where RemoteIP has_any(RemoteIPsInQuestion)
```

## ✅ Verified Only 2 Successful Logins During 7 Day Internet Exposure

---

Check Valid Logons by Known Account:
```kql
DeviceLogonEvents
| where DeviceName == "windows-target-1"
| where LogonType == "Network"
| where ActionType == "LogonSuccess"
| where AccountName == "labuser"
```
## ✅ Successful Logons by Account

![Successful Logon Events](./SuccessfulLogonDevice.png)

- Both successful logon events were from same authorized user
- Account: `labuser`
- Number of failed logons: 0
- IP address origin was verified and authorized

## 🌐 Successful IP Address Origin

![Successful IP Location](./SuccessfulIP.png)

> ✅ The IP address was clicked and correlated with an authorized user account and confirmed as the source of both valid logon events.
---

## 🧠 MITRE ATT&CK TTP Mapping

| ID          | Technique                                 |
|-------------|--------------------------------------------|
| T1595.001   | Active Scanning: Scanning IP Blocks       |
| T1110.001   | Brute Force: Password Guessing            |
| T1078       | Valid Accounts                            |

---

## 🧯 Response Actions

- Restrict RDP traffic using NSG rules to trusted IPs only
- Implement account lockout policies
- Enforce multi-factor authentication (MFA)

---

## 📝 Conclusion

Although `windows-target-1` was internet-facing for at least 7 days and received numerous brute-force login attempts, no evidence of unauthorized access was found. All successful logons were tied to a known account (`labuser`) from an authorized location.

---

## 🔄 Lessons Learned

- Restrict access to public services whenever possible
- Monitor remote logon events for patterns of brute-force attempts
- Implement and regularly review MFA and account lockout policies
