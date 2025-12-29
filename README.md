<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Fredrick387/Tor-Browser-Usage/blob/main/Scenario%20Creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2025-12-29T03:37:43.1381518Z`. These events began at `2025-12-29T03:20:07.4482477Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "fredrick-vm-27-"
| where FileName contains "tor"
| where InitiatingProcessAccountName == "fredrickwilson"
| where Timestamp >= datetime(2025-12-29T03:20:07.4482477Z)
| order by Timestamp desc 
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1509" height="659" alt="image" src="https://github.com/user-attachments/assets/c77e51fa-cd9b-4033-9f34-094df129fa79" />


---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2025-12-29T03:23:25.1653478Z`, an employee on the "fredrick-VM-27-" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "fredrick-vm-27-"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.3.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, Command = ProcessCommandLine
```
<img width="1491" height="549" alt="image" src="https://github.com/user-attachments/assets/5cfade43-6772-482d-820f-96fe5d2547dc" />


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "fredrickwilson" actually opened the TOR browser. There was evidence that they did open it at `2025-12-29T03:30:15.8552181Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "fredrick-vm-27-"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, Command = ProcessCommandLine
| order by Timestamp desc 
```
<img width="1495" height="617" alt="image" src="https://github.com/user-attachments/assets/97c8f5d3-2ca9-4d1c-8017-195ed0f073c9" />


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2025-12-29T03:31:01.8586524Z`, an employee on the "fredrick-vm-27-" device successfully established a connection to the remote IP address `85.30.131.60` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\fredrickwilson\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `9001`. 

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "fredrick-vm-27-"
| where InitiatingProcessAccountName != "system"
| where RemotePort in ("9001", "9030", "9040", "9050", "9051")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
```
<img width="1507" height="466" alt="image" src="https://github.com/user-attachments/assets/14228249-ceac-41c0-a876-56dd6795444a" />


---

## Chronological Event Timeline 

### Chronological Event Timeline

All events occurred on **December 29, 2025** on device **fredrick-vm-27-** by user **fredrickwilson**.

| Timestamp          | Event Type       | Description                                                                                                      |
|--------------------|------------------|------------------------------------------------------------------------------------------------------------------|
| 10:20:07 AM        | File Event       | TOR Browser installer renamed: `tor-browser-windows-x86_64-portable-15.0.3.exe` in `C:\Users\FredrickWilson\Downloads\` |
| 10:22:28 AM        | Process Event    | TOR Browser installer process started (`tor-browser-windows-x86_64-portable-15.0.3.exe`)                          |
| 10:22:28 AM        | File Event       | TOR Browser installer deleted from Downloads folder after execution                                              |
| 10:23:25 AM        | Process Event    | Silent installation executed: `tor-browser-windows-x86_64-portable-15.0.3.exe /S`                                |
| 10:23:45 AM        | File Event       | TOR license files created (`tor.txt`, `Torbutton.txt`, `Tor-Launcher.txt`) in `...\Tor Browser\Browser\TorBrowser\Docs\Licenses\` |
| 10:23:47 AM        | File Event       | `tor.exe` created at `C:\Users\FredrickWilson\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`                 |
| 10:23:54 AM        | File Event       | TOR Browser shortcut created: `Tor Browser.lnk` on Desktop                                                       |
| 10:25:30 AM        | File Event       | Cached image file created (likely during setup)                                                                   |
| 10:30:15 AM        | Process Event    | Main `firefox.exe` process launched (TOR Browser started)                                                        |
| 10:30:16 AM        | Process Event    | GPU process of `firefox.exe` spawned                                                                              |
| 10:30:20 AM        | Process Event    | Additional `firefox.exe` content processes spawned                                                                |
| 10:30:24 AM        | Process Event    | Multiple `firefox.exe` content processes (tab, RDD, etc.) spawned                                                 |
| 10:30:27 AM        | Process Event    | `tor.exe` process created – TOR client started (SOCKS port 9150 configured)                                       |
| 10:30:30 AM        | Process Event    | Additional `firefox.exe` content processes spawned                                                                |
| 10:30:19 AM        | File Event       | TOR Browser storage file created: `storage.sqlite`                                                               |
| 10:30:33 AM        | File Event       | TOR Browser storage file created: `storage-sync-v2.sqlite`                                                       |
| 10:30:57 AM        | Network Event    | Successful connection to TOR entry node `82.165.21.136:9001` initiated by `tor.exe`                                |
| 10:31:01 AM        | Network Event    | Successful connections to TOR entry nodes `85.30.131.60:9001` and `185.86.104.143:9001`                            |
| 10:31:01 AM        | Network Event    | TOR circuit used to access `.onion` sites: `https://www.om2de7jyx3h3e2wd3ru.com` and `https://www.6khbaeaobczzhilp25.com` |
| 10:31:13 AM – 10:31:53 AM | Process Event | Multiple additional `firefox.exe` content processes (tabs) spawned as user browsed                                |
| 10:32:04 AM        | Network Event    | Additional TOR connection to `82.165.21.136:9001` with URL `https://www.y75uy5veezkab73iqy2.com`                   |
| 10:37:43 AM        | File Event       | File `tor shopping list.txt` created on Desktop                                                                  |
| 10:37:43 AM        | File Event       | Shortcut `tor shopping list.lnk` created in Recent items                                                         |



### Conclusion: 
User fredrickwilson downloaded, silently installed, launched, and actively used TOR Browser on December 29, 2025 between approximately 10:20 AM and 10:37 AM. Evidence includes TOR process execution, connections to known TOR entry nodes on port 9001, and access to multiple `.onion` addresses. A file named `tor shopping list.txt` was created on the desktop, indicating potential intent related to anonymous browsing activity. This constitutes unauthorized TOR usage.


---

## Response Taken

TOR usage was confirmed on the endpoint `fredrick-vm-27-` by the user `fredrickwilson`. The device was isolated, and the user's direct manager was notified.

---
