<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage

---

- [Scenario Creation](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser


### Scenario:

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

---

## High-Level TOR-related IoC Discovery Plan:

- Check `DeviceFileEvents` for any `tor(.exe)` or `firefox(.exe)` file events  
- Check `DeviceProcessEvents` for any signs of installation or usage  
- Check `DeviceNetworkEvents` for any signs of outgoing connections over known TOR ports  

---

## Steps Taken

### 🔍 Step 1: Search `DeviceFileEvents` for files with "tor"

Discovered that user `tlab1` downloaded a TOR installer and copied many TOR-related files to the desktop. These events began at:

**Timestamp:** `2025-04-06T23:33:21.1492138Z`

**Query used:**

```kusto
DeviceFileEvents
| where DeviceName contains "Threat-Hunt-Lab"
| where FileName contains "tor"  // Focus on files related to the Tor browser
| where InitiatingProcessAccountName == "tlab1"
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessAccountName
```

<img width="678" alt="image" src="https://github.com/user-attachments/assets/df775f77-339a-4463-a27b-83c596e8c700" />

---

### 🔍 Step 2: Search `DeviceFileEvents` for installer execution

Found that `tor.exe` was created at `7:33:21 PM` on April 6, 2025, in the path:

`C:\Users\TLab1\Desktop\Tor Browser\Browser\TorBrowser\Tor`

**Query used:**

```kusto
DeviceFileEvents
| where InitiatingProcessAccountName == "tlab1"
| where DeviceName contains "Threat-Hunt-Lab"
| where FileName contains "tor"
| where FileName endswith ".exe"
```
<img width="678" alt="image" src="https://github.com/user-attachments/assets/f1966dff-6cae-4184-a706-0ef5a61226d7" />

---

### 🔍 Step 3: Search `DeviceProcessEvents` for TOR execution

Found that the TOR browser was opened at `7:35:22 PM`. Several instances of `firefox.exe` (used by TOR) and `tor.exe` were spawned.

**Query used:**

```kusto
DeviceProcessEvents
| where DeviceName == "Threat-Hunt-Lab"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, InitiatingProcessAccountName
```
<img width="699" alt="image" src="https://github.com/user-attachments/assets/5faa1d79-66eb-46ed-970e-e40416c207e0" />

---

### 🔍 Step 4: Search `DeviceNetworkEvents` for TOR usage

Confirmed that user `tlab1` began using the TOR browser around `7:36:22 PM`.

**Query used:**

```kusto
DeviceNetworkEvents
| where DeviceName contains "Threat-Hunt-Lab" 
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150, 80, 443) 
| where InitiatingProcessAccountName == "tlab1" 
| where Timestamp > datetime(2025-04-06T23:33:21.1492138Z)  
| project Timestamp, DeviceName, ActionType, InitiatingProcessAccountName, RemotePort, RemoteIP
```
<img width="689" alt="image" src="https://github.com/user-attachments/assets/cdecc217-0ac0-4274-894e-7e9593ce6ae9" />

---

## 📜 Chronological Events

---

### 🕒 Step 1: Tor Installer Downloaded  
**Timestamp:** 7:33:21 PM EST  
**Details:**  
User `tlab1` downloaded the file:  
`tor-browser-windows-x86_64-portable-14.0.9.exe`  
to folder:  
`C:\Users\TLab1\Downloads\`

---

### 🕒 Step 2: Tor Executable Created  
**Timestamp:** 7:33:21 PM EST  
**Details:**  
The file `tor.exe` was created in:  
`C:\Users\TLab1\Desktop\Tor Browser\Browser\TorBrowser\Tor`  
This marked the beginning of the installation.

---

### 🕒 Step 3: Silent Installation Executed  
**Timestamp:** 7:33:45 PM EST  
**Details:**  
The `tor.exe` file was executed by `tlab1`, triggering a silent install.

---

### 🕒 Step 4: Initial Network Activity Detected  
**Timestamp Range:** 7:33:52 PM – 7:34:13 PM EST  
**Details:**  
Outbound network connections initiated on ports:  
**443, 9150**  
**Remote IPs:** 82.149.227.126, 127.0.0.1

---

### 🕒 Step 5: Tor Browser Launched  
**Timestamp:** 7:35:22 PM EST  
**Details:**  
`firefox.exe` (TOR GUI) launched by `tor.exe` process.

---

### 🕒 Step 6: Confirmed Tor Network Usage  
**Timestamp:** 7:36:22 PM EST and onward  
**Details:**  
Continued traffic from `tlab1` to known TOR ports confirms active TOR usage.

---

## 📝 Summary

User `tlab1` intentionally downloaded and installed the TOR browser on the `Threat-Hunt-Lab` device. They initiated a silent installation, launched the application, and successfully connected to the TOR network. This activity suggests an intentional attempt to anonymize internet usage, possibly violating acceptable use policies.

---

## 🚨 Response Taken

TOR usage was **confirmed** on endpoint `Threat-Hunt-Lab`.  
The device was **isolated**, and the user’s **manager was notified**.

---

