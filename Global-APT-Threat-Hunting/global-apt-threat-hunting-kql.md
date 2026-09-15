# 🌐 Global APT Threat Hunting Reference — KQL for Microsoft Sentinel & Defender XDR

> **Maintainer:** Detection Engineering | **Stack:** Microsoft Sentinel · Defender XDR · KQL  
> **Coverage:** 50+ APT Groups | North Korea · China · Russia · Iran · Middle East · Others  
> **Last Updated:** June 2026  
> **MITRE ATT&CK Version:** v15  

---

## 📋 Table of Contents

1. [How to Use This Playbook](#how-to-use)
2. [Universal Hunt Foundations](#universal-foundations)
3. [🇰🇵 North Korean APTs](#north-korea)
   - Lazarus Group (APT38)
   - Kimsuky (APT43)
   - Andariel
   - BlueNoroff
   - ScarCruft (APT37)
4. [🇨🇳 Chinese APTs](#china)
   - APT41 (Winnti / Double Dragon)
   - APT40 (Bronze Mohawk / TEMP.Periscope)
   - APT10 (Stone Panda / MenuPass)
   - APT31 (Zirconium / BRONZE VINEWOOD)
   - Volt Typhoon
   - Salt Typhoon
   - Flax Typhoon
   - APT27 (Emissary Panda)
   - APT3 (Gothic Panda)
5. [🇷🇺 Russian APTs](#russia)
   - APT29 (Cozy Bear / Midnight Blizzard)
   - APT28 (Fancy Bear / Forest Blizzard)
   - Sandworm (Voodoo Bear)
   - Turla (Snake / Venomous Bear)
   - Gamaredon (Primitive Bear)
   - FIN7 / Carbanak
   - NOBELIUM
6. [🇮🇷 Iranian APTs](#iran)
   - APT33 (Elfin / Refined Kitten)
   - APT34 (OilRig / Helix Kitten)
   - APT35 (Charming Kitten / Phosphorus)
   - MuddyWater (SeedWorm)
   - Tortoiseshell
   - Agrius
7. [🇸🇦 Middle East / Gulf APTs](#middle-east)
   - Bahamut
   - Molerats (Gaza Cybergang)
   - Dark Caracal
8. [🌍 Other / Multi-Region APTs](#other)
   - Lazyscripter
   - SideWinder (APT-C-17)
   - Bitter (APT-C-08)
   - Transparent Tribe (APT36)
   - Patchwork (APT-C-09)
   - Equation Group (NSA-linked)
9. [🔎 Cross-APT Detection Patterns](#cross-apt)
10. [🛡️ Defender XDR Advanced Hunting Queries](#defender-xdr)
11. [📊 Sentinel Analytics Rules (Scheduled)](#sentinel-analytics)
12. [🗺️ MITRE ATT&CK Coverage Matrix](#mitre-matrix)
13. [⚡ Quick-Reference Cheat Sheet](#cheat-sheet)

---

<a name="how-to-use"></a>
## 📖 How to Use This Playbook

All queries are written in **KQL** and validated against:
- `Microsoft Sentinel` (Log Analytics workspace)
- `Microsoft Defender XDR Advanced Hunting` (tables prefixed with schema notes)

**Table Conventions:**

| Prefix | Source | Notes |
|--------|--------|-------|
| No prefix | Sentinel / Log Analytics | DeviceEvents, SecurityAlert, etc. |
| `DeviceProcess*` | Defender XDR | MDE schema |
| `IdentityLogon*` | Defender XDR | MDI schema |
| `CloudAppEvents` | Defender XDR | MDCA schema |

**Time Range Guidance:**
- Initial sweep: `ago(30d)`
- Active incident: `ago(7d)` or `ago(24h)`
- Threat hunt campaign: `ago(90d)`

---

<a name="universal-foundations"></a>
## 🔬 Universal Hunt Foundations

These queries apply broadly and should run first before APT-specific hunting.

### 1. Living-Off-the-Land (LOLBin) Baseline

```kql
// Hunt: Suspicious native binary abuse — common across ALL APTs
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ (
    "certutil.exe","bitsadmin.exe","mshta.exe","wscript.exe","cscript.exe",
    "regsvr32.exe","rundll32.exe","msiexec.exe","installutil.exe",
    "odbcconf.exe","msbuild.exe","cmstp.exe","wmic.exe","powershell.exe",
    "cmd.exe","net.exe","net1.exe","sc.exe","schtasks.exe","at.exe",
    "nltest.exe","whoami.exe","ipconfig.exe","systeminfo.exe","tasklist.exe"
    )
| where ProcessCommandLine has_any (
    "http","ftp","\\\\","base64","bypass","hidden","encoded","-enc","-e ",
    "downloadstring","iex","invoke-expression","webclient","downloadfile",
    "regsvr","scrobj","javascript","vbscript","wscript","shell","exec"
    )
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

### 2. Unusual Parent-Child Process Chains

```kql
// Hunt: Office apps spawning shells — phishing initial access TTPs
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ (
    "winword.exe","excel.exe","powerpnt.exe","outlook.exe",
    "acrord32.exe","acrobat.exe","msaccess.exe","mspub.exe","onenote.exe"
    )
| where FileName in~ (
    "cmd.exe","powershell.exe","wscript.exe","cscript.exe","mshta.exe",
    "certutil.exe","bitsadmin.exe","regsvr32.exe","rundll32.exe","wmic.exe"
    )
| project Timestamp, DeviceName, AccountName,
    Parent=InitiatingProcessFileName, Child=FileName,
    CommandLine=ProcessCommandLine
| order by Timestamp desc
```

### 3. Encoded PowerShell Detection

```kql
// Hunt: Base64-encoded PowerShell — used by virtually every APT
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine matches regex @'(?i)(-e[nc]{0,6}\s+|EncodedCommand\s+)[A-Za-z0-9+/=]{40,}'
| extend DecodedLength = strlen(extract(@'[A-Za-z0-9+/=]{40,}', 0, ProcessCommandLine))
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, DecodedLength
| order by Timestamp desc
```

### 4. Credential Access — LSASS Dumping

```kql
// Hunt: LSASS memory access — credential harvesting
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "LsassProcessAccess"
| where not(InitiatingProcessFileName in~ ("MsMpEng.exe","svchost.exe","csrss.exe","werfault.exe"))
| project Timestamp, DeviceName, AccountName,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    ActionType
| order by Timestamp desc
```

### 5. Lateral Movement — Pass-the-Hash / Pass-the-Ticket Indicators

```kql
// Hunt: Anomalous NTLM/Kerberos auth patterns
SecurityEvent
| where TimeGenerated > ago(30d)
| where EventID in (4624, 4625, 4768, 4769, 4776)
| where LogonType in (3, 9)  // Network, NewCredentials
| where AuthenticationPackageName == "NTLM"
| summarize
    FailureCount = countif(EventID == 4625),
    SuccessCount = countif(EventID == 4624),
    TargetHosts = dcount(Computer),
    TargetAccounts = dcount(TargetUserName)
    by SubjectUserName, IpAddress
| where TargetHosts > 3 or FailureCount > 10
| order by TargetHosts desc
```

### 6. Persistence — Scheduled Tasks & Registry Run Keys

```kql
// Hunt: Persistence mechanisms commonly used by APTs
let RegistryPersistence = DeviceRegistryEvents
    | where Timestamp > ago(30d)
    | where RegistryKey has_any (
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        @"SYSTEM\CurrentControlSet\Services",
        @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
        )
    | project Timestamp, DeviceName, AccountName, ActionType, RegistryKey, RegistryValueName, RegistryValueData, Source="Registry";
let TaskPersistence = DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName =~ "schtasks.exe"
    | where ProcessCommandLine has "/create"
    | project Timestamp, DeviceName, AccountName, ProcessCommandLine, Source="SchedTask";
union RegistryPersistence, TaskPersistence
| order by Timestamp desc
```

### 7. C2 Beaconing Detection (Network)

```kql
// Hunt: Regular interval connections suggesting C2 beacon
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort in (80, 443, 8080, 8443, 4444, 1337, 53)
| where ActionType == "ConnectionSuccess"
| summarize
    ConnectionCount = count(),
    BytesSent = sum(SentBytes),
    BytesReceived = sum(ReceivedBytes),
    UniqueHours = dcount(bin(Timestamp, 1h))
    by DeviceName, RemoteIP, RemoteUrl, RemotePort
| where ConnectionCount > 20 and UniqueHours > 6
| extend BeaconScore = round((toreal(ConnectionCount) / toreal(UniqueHours)), 2)
| where BeaconScore between (0.5 .. 50)  // Regular interval — not too fast, not too slow
| order by BeaconScore asc
```

---

<a name="north-korea"></a>
## 🇰🇵 North Korean APTs

---

### APT38 / Lazarus Group — HIDDEN COBRA

**Attribution:** RGB Bureau 121 | **Active Since:** 2009  
**Primary Targets:** Financial institutions, cryptocurrency, defence, critical infrastructure  
**Known Operations:** WannaCry, Bangladesh Bank Heist, SWIFT attacks, Operation AppleJeus, TraderTraitor  
**Signature TTPs:** SpearPhish → Watering hole → Custom malware (BLINDINGCAN, COPPERHEDGE, HOPLIGHT, MANUSCRYPT)

#### Hunt 1: MANUSCRYPT / BLINDINGCAN DLL Side-Loading Pattern

```kql
// Lazarus DLL side-loading — legitimate app loads malicious DLL from same dir
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where not(InitiatingProcessFolderPath has_any (
    @"C:\Windows\", @"C:\Program Files\", @"C:\Program Files (x86)\"
    ))
| where not(FolderPath has_any (
    @"C:\Windows\", @"C:\Program Files\", @"C:\Program Files (x86)\"
    ))
| where InitiatingProcessFolderPath == FolderPath  // DLL in same folder as EXE
| where FileName endswith ".dll"
| join kind=leftsemi (
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCreationTime > ago(30d)
    ) on $left.InitiatingProcessId == $right.ProcessId
| project Timestamp, DeviceName, InitiatingProcessFileName,
    InitiatingProcessFolderPath, FileName, FolderPath
| order by Timestamp desc
```

#### Hunt 2: Lazarus Cryptocurrency-Targeting Indicators

```kql
// Lazarus/BlueNoroff — cryptocurrency wallet/exchange process access
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any (
    "metamask","exodus","electrum","ledger","trezor",
    "blockchain.info","coinbase","binance","kraken",
    "crypto","bitcoin","ethereum","wallet.dat","seed phrase"
    )
| where FileName in~ ("powershell.exe","cmd.exe","wscript.exe","mshta.exe","rundll32.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

#### Hunt 3: HOPLIGHT Backdoor Network Indicators

```kql
// HOPLIGHT uses fake TLS cert indicators and specific user-agent patterns
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemotePort in (443, 8443, 7777, 9999)
| where ActionType == "ConnectionSuccess"
// HOPLIGHT beacons to attacker infra — flag non-standard TLS ports
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName in~ ("svchost.exe","lsass.exe","spoolsv.exe","dllhost.exe")
    | where InitiatingProcessFileName !in~ ("services.exe","wininit.exe","winlogon.exe")
    ) on DeviceName, $left.InitiatingProcessId == $right.ProcessId
| project Timestamp, DeviceName, RemoteIP, RemotePort, RemoteUrl,
    InitiatingProcess=FileName, Parent=InitiatingProcessFileName
| order by Timestamp desc
```

#### Hunt 4: AppleJeus / TraderTraitor — Fake Trading App

```kql
// AppleJeus: malicious update mechanism, fake crypto trading apps
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("updater.exe","update.exe","setup.exe","installer.exe")
| where not(InitiatingProcessFileName in~ (
    "msiexec.exe","wusa.exe","trustedinstaller.exe",
    "svchost.exe","chrome.exe","firefox.exe","edge.exe"
    ))
| where not(FolderPath has_any (@"C:\Windows\", @"C:\Program Files\"))
| where ProcessCommandLine has_any ("http","ftp",".onion","download","install","update")
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, ProcessCommandLine
| order by Timestamp desc
```

#### Hunt 5: Lazarus — WMI Lateral Movement

```kql
// Lazarus uses WMI for lateral movement extensively
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where FileName in~ ("cmd.exe","powershell.exe","cscript.exe","wscript.exe","rundll32.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### Kimsuky (APT43) — Thallium / Velvet Chollima

**Attribution:** RGB | **Active Since:** 2012  
**Primary Targets:** Think tanks, academics, governments, South Korea, US, Europe  
**Known Operations:** Operation GoldDragon, BabyShark, FlowerPower, AppleSeed  
**Signature TTPs:** Spear-phishing, HWP (Hangul Word) malware, Chrome credential stealing, BabyShark RAT

#### Hunt 1: BabyShark PowerShell Stager

```kql
// BabyShark uses PowerShell to download and execute secondary payloads
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "DownloadString","DownloadFile","WebClient","BitsTransfer","Start-BitsTransfer"
    )
| where ProcessCommandLine has_any (
    "IEX","Invoke-Expression","[System.Text.Encoding]","FromBase64String"
    )
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

#### Hunt 2: Hangul Word Processor (HWP) Exploit Delivery

```kql
// Kimsuky targets South Korean orgs via HWP documents
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("hwp.exe","hwpx.exe","gul.exe")
| where FileName in~ (
    "cmd.exe","powershell.exe","wscript.exe","cscript.exe",
    "mshta.exe","rundll32.exe","regsvr32.exe"
    )
| project Timestamp, DeviceName, AccountName,
    Parent=InitiatingProcessFileName, Child=FileName, CommandLine=ProcessCommandLine
| order by Timestamp desc
```

#### Hunt 3: Chrome Credential Stealing — Kimsuky Signature

```kql
// Kimsuky uses Chrome credential files — looking for file access to Login Data
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any (
    @"\AppData\Local\Google\Chrome\User Data\Default\Login Data",
    @"\AppData\Local\Microsoft\Edge\User Data\Default\Login Data",
    @"\AppData\Roaming\Mozilla\Firefox\Profiles\"
    )
| where ActionType in ("FileRead","FileCopied")
| where not(InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","SearchIndexer.exe"))
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName,
    InitiatingProcessCommandLine, FolderPath, FileName, ActionType
| order by Timestamp desc
```

#### Hunt 4: AppleSeed Backdoor C2 Pattern

```kql
// AppleSeed uses HTTP/HTTPS with base64-encoded data in POST body
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType == "HttpConnectionInspected"
| where RequestMethod == "POST"
| where RequestBodySize > 0 and RequestBodySize < 4096  // Small encoded data
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName in~ ("powershell.exe","cmd.exe","wscript.exe","rundll32.exe","dllhost.exe")
    ) on DeviceName, $left.InitiatingProcessId == $right.ProcessId
| project Timestamp, DeviceName, RemoteUrl, RemotePort, RequestBodySize,
    InitiatingProcess=FileName, CommandLine=ProcessCommandLine
| order by Timestamp desc
```

---

### Andariel — Silent Chollima

**Attribution:** Lazarus subgroup | **Active Since:** 2015  
**Primary Targets:** South Korean defence, financial, critical infrastructure  
**Known Operations:** Operation Rifle, DTrack malware  
**Signature TTPs:** Watering hole, custom malware DTrack, ATM malware

#### Hunt 1: DTrack Keylogger/Screen Capture Indicators

```kql
// DTrack creates numerous temp files and uses specific injection patterns
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any (@"\Windows\Temp\", @"\Temp\", @"\AppData\Local\Temp\")
| where FileName matches regex @'^[a-z0-9]{8,16}\.(exe|dll|dat|tmp)$'
| where ActionType == "FileCreated"
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where not(FileName in~ ("svchost.exe","explorer.exe","wusa.exe","msiexec.exe"))
    ) on DeviceName, $left.InitiatingProcessId == $right.ProcessId
| project Timestamp, DeviceName, FileName, FolderPath,
    CreatingProcess=InitiatingProcessFileName
| order by Timestamp desc
```

---

### ScarCruft (APT37) — Reaper / Group123

**Attribution:** North Korea MSSP | **Active Since:** 2012  
**Primary Targets:** South Korea, Japan, Vietnam, Middle East — dissidents, journalists  
**Known Operations:** Operation Daybreak, ROKRAT, Dolphin backdoor  
**Signature TTPs:** Zero-day exploitation, cloud service C2 (Google Drive, Dropbox, OneDrive), ROKRAT RAT

#### Hunt 1: Cloud Storage C2 — APT37 Signature

```kql
// APT37 uses cloud storage (Drive/Dropbox/OneDrive) as C2 channel
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (
    "drive.google.com","api.dropboxapi.com","dropbox.com",
    "onedrive.live.com","1drv.ms","api.onedrive.com",
    "graph.microsoft.com","sharepoint.com"
    )
| where InitiatingProcessFileName in~ (
    "powershell.exe","cmd.exe","wscript.exe","cscript.exe",
    "rundll32.exe","regsvr32.exe","mshta.exe","dllhost.exe"
    )
| where not(InitiatingProcessFolderPath has_any (
    @"C:\Windows\System32\",@"C:\Windows\SysWOW64\"
    ))
| project Timestamp, DeviceName, AccountName, RemoteUrl,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

#### Hunt 2: ROKRAT Cloud-Based RAT Indicators

```kql
// ROKRAT collects system info and exfiltrates via cloud APIs
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any (
    "systeminfo","ipconfig","tasklist","netstat","whoami","net user","net group"
    )
| where InitiatingProcessFileName in~ (
    "powershell.exe","cmd.exe","wscript.exe","cscript.exe"
    )
// Look for rapid enumeration (multiple within 60s window)
| summarize
    CommandCount = count(),
    Commands = make_set(ProcessCommandLine, 20)
    by DeviceName, AccountName, bin(Timestamp, 60s)
| where CommandCount >= 3
| order by Timestamp desc
```

---

<a name="china"></a>
## 🇨🇳 Chinese APTs

---

### APT41 — Winnti / Double Dragon / Barium

**Attribution:** MSS / PLA | **Active Since:** 2012  
**Primary Targets:** Healthcare, telecom, tech, gaming, defence, supply chain  
**Known Operations:** ShadowPad, Colunmtk, Speculoos backdoor, supply chain attacks  
**Signature TTPs:** Supply chain compromise, rootkits (Winnti), ShadowPad, CobaltStrike

#### Hunt 1: ShadowPad Plugin Loader Pattern

```kql
// ShadowPad loads encrypted plugins — look for DLL hollowing / unusual module loads
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where FileName endswith ".dll"
| where not(FolderPath has_any (@"C:\Windows\", @"C:\Program Files\"))
| where SHA256 !in (  // Known-good DLLs — populate with your baseline
    "placeholder_hash_1","placeholder_hash_2"
    )
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName in~ ("svchost.exe","dllhost.exe","spoolsv.exe","wmiprvse.exe")
    ) on DeviceName, $left.InitiatingProcessId == $right.ProcessId
| project Timestamp, DeviceName, ProcessName=FileName, LoadedDLL=FileName1,
    DLLPath=FolderPath, ProcessId=InitiatingProcessId
| order by Timestamp desc
```

#### Hunt 2: CobaltStrike Beacon — APT41 Common C2

```kql
// CobaltStrike: named pipe, inject patterns, and beacon sleep jitter
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType in ("NamedPipeEvent","ProcessInjected","WriteProcessMemory")
| where not(InitiatingProcessFileName in~ ("MsMpEng.exe","svchost.exe"))
| project Timestamp, DeviceName, AccountName, ActionType,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    AdditionalFields
| order by Timestamp desc
```

#### Hunt 3: Supply Chain — Legitimate Software Spawning Unexpected Processes

```kql
// APT41 supply chain — trusted software spawning malicious children
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ (
    "ccmexec.exe","ngen.exe","msbuild.exe","installutil.exe",
    "devenv.exe","msiexec.exe","wix.exe","nuget.exe",
    "git.exe","node.exe","python.exe","java.exe","javaw.exe"
    )
| where FileName in~ (
    "powershell.exe","cmd.exe","wscript.exe","cscript.exe",
    "mshta.exe","regsvr32.exe","rundll32.exe","certutil.exe"
    )
| project Timestamp, DeviceName, AccountName,
    Parent=InitiatingProcessFileName, Child=FileName, CommandLine=ProcessCommandLine
| order by Timestamp desc
```

#### Hunt 4: Winnti Rootkit Driver Load

```kql
// Winnti loads signed/stolen driver for kernel-level persistence
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "DriverLoad"
| where not(FolderPath has_any (@"C:\Windows\System32\drivers\", @"C:\Windows\SysWOW64\drivers\"))
| project Timestamp, DeviceName, ActionType, AdditionalFields,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### APT40 — Bronze Mohawk / TEMP.Periscope / Leviathan

**Attribution:** MSS Hainan | **Active Since:** 2013  
**Primary Targets:** Maritime, naval defence, universities, engineering, aviation  
**Known Operations:** Operation Oceansalt, HOMEFRY, AIRBREAK, MURKYTOP  
**Signature TTPs:** Web shell deployment, spearphishing, watering hole

#### Hunt 1: Web Shell Detection — APT40 Signature

```kql
// APT40 deploys web shells on internet-facing servers
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ (
    "w3wp.exe","httpd.exe","nginx.exe","tomcat.exe","apache.exe",
    "python.exe","node.exe","ruby.exe","php.exe","java.exe"
    )
| where FileName in~ (
    "cmd.exe","powershell.exe","sh","bash","net.exe","whoami.exe",
    "ipconfig.exe","ifconfig","curl","wget","certutil.exe"
    )
| project Timestamp, DeviceName, AccountName,
    WebServer=InitiatingProcessFileName, Shell=FileName, CommandLine=ProcessCommandLine
| order by Timestamp desc
```

#### Hunt 2: AIRBREAK / HOMEFRY JavaScript Backdoor

```kql
// AIRBREAK: JavaScript/JS backdoor uses specific user-agent strings
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType == "HttpConnectionInspected"
| where AdditionalFields has_any (
    "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)",
    "Mozilla/5.0 (compatible; MSIE 10.0; Windows Phone 8.0"
    )
| where RemotePort in (80, 443, 8080)
| project Timestamp, DeviceName, RemoteUrl, RemotePort,
    InitiatingProcessFileName, AdditionalFields
| order by Timestamp desc
```

---

### APT10 — Stone Panda / MenuPass / Cloud Hopper

**Attribution:** MSS Tianjin | **Active Since:** 2009  
**Primary Targets:** MSPs, cloud providers, legal, aerospace, defence, pharmaceutical  
**Known Operations:** Operation Cloud Hopper, Operation Soft Cell  
**Signature TTPs:** MSP compromise for downstream targeting, PlugX, QuasarRAT, RedLeaves

#### Hunt 1: MSP/Supply Chain — Unexpected Admin Tool Execution

```kql
// APT10 compromises MSP tools — hunt for remote admin tools spawning shells
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ (
    "connectwise.exe","screenconnect.exe","kaseya.exe","n-central.exe",
    "labtech.exe","manage-engine.exe","solarwinds.exe","datto.exe",
    "bomgar.exe","logmein.exe","teamviewer.exe","anydesk.exe"
    )
| where FileName in~ (
    "cmd.exe","powershell.exe","wscript.exe","cscript.exe",
    "mshta.exe","regsvr32.exe","rundll32.exe"
    )
| project Timestamp, DeviceName, AccountName,
    RMMTool=InitiatingProcessFileName, SpawnedProcess=FileName, CommandLine=ProcessCommandLine
| order by Timestamp desc
```

#### Hunt 2: PlugX RAT — APT10 Favourite

```kql
// PlugX uses DLL side-loading with legitimate signed binaries
let PlugXKnownLoaders = dynamic([
    "GoogleUpdate.exe","AcroRd32.exe","hxoutlook.exe",
    "iTunesHelper.exe","wuauclt.exe","defrag.exe"
    ]);
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ (PlugXKnownLoaders)
| where FileName endswith ".dll"
| where not(SHA256 in (  // Populate with baseline hashes
    "placeholder_1","placeholder_2"
    ))
| project Timestamp, DeviceName, AccountName,
    Loader=InitiatingProcessFileName, DLL=FileName, DLLPath=FolderPath, SHA256
| order by Timestamp desc
```

#### Hunt 3: RedLeaves / UPPERCUT Backdoor

```kql
// RedLeaves injects into Internet Explorer or svchost
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "ProcessInjected"
| where AdditionalFields has_any ("iexplore.exe","svchost.exe","explorer.exe","dllhost.exe")
| where not(InitiatingProcessFileName in~ ("MsMpEng.exe","csrss.exe","winlogon.exe"))
| project Timestamp, DeviceName, AccountName, ActionType, AdditionalFields,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### APT31 — Zirconium / BRONZE VINEWOOD / Judgment Panda

**Attribution:** MSS | **Active Since:** 2016  
**Primary Targets:** Governments, political organisations, US election infrastructure, dissidents  
**Known Operations:** French election interference, UK parliament attacks  
**Signature TTPs:** Spearphishing, credential harvesting, ZARDOOR backdoor

#### Hunt 1: ZARDOOR Backdoor Communication Pattern

```kql
// ZARDOOR uses ping-back via ICMP or specific HTTP patterns
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where Protocol == "Icmp"
| where AdditionalFields has_any ("DataSize=32","DataSize=128","DataSize=256")
| summarize
    PingCount = count(),
    TargetIPs = make_set(RemoteIP, 20)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
| where PingCount > 100
| order by PingCount desc
```

---

### Volt Typhoon — Bronze Silhouette

**Attribution:** MSS / PLA | **Active Since:** ~2021  
**Primary Targets:** US critical infrastructure (power, water, comms, transport)  
**Known Operations:** "Pre-positioning" in US CNI for potential conflict  
**Signature TTPs:** Living-off-the-land exclusively, SOHO router compromise, no malware

#### Hunt 1: Volt Typhoon LOLBin Reconnaissance Chain

```kql
// Volt Typhoon: chained native commands — no malware whatsoever
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ (
    "net.exe","net1.exe","netsh.exe","nltest.exe","ipconfig.exe",
    "whoami.exe","tasklist.exe","quser.exe","systeminfo.exe",
    "wmic.exe","dsquery.exe","csvde.exe","ldifde.exe"
    )
// Filter out normal admin activity by looking for sequential rapid execution
| summarize
    CommandCount = count(),
    UniqueCommands = dcount(FileName),
    CommandList = make_set(ProcessCommandLine, 20)
    by DeviceName, AccountName, bin(Timestamp, 5m)
| where CommandCount >= 5 and UniqueCommands >= 4
| order by CommandCount desc
```

#### Hunt 2: Volt Typhoon — SOHO Device Proxy (Living Proxy via Legitimate Traffic)

```kql
// Volt Typhoon routes traffic via compromised SOHO devices
// Hunt: outbound connections to unusual AS numbers or known SOHO device IPs
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemotePort in (8080, 8443, 9090, 7547, 5555, 2323)  // SOHO mgmt ports
| where ActionType == "ConnectionSuccess"
| where RemoteIP !startswith "10." and RemoteIP !startswith "192.168." and RemoteIP !startswith "172."
| project Timestamp, DeviceName, RemoteIP, RemotePort,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

#### Hunt 3: Volt Typhoon — ntdsutil / NTDS.dit Exfiltration

```kql
// Volt Typhoon uses ntdsutil for AD database extraction
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "ntdsutil.exe"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
    InitiatingProcessFileName
| order by Timestamp desc
```

---

### Salt Typhoon — GhostEmperor / FamousSparrow

**Attribution:** MSS | **Active Since:** ~2019  
**Primary Targets:** Telecommunications, ISPs, government (US CALEA intercept access)  
**Known Operations:** AT&T/Verizon/Lumen breach (2024), US wiretap system access  
**Signature TTPs:** Telecom backbone access, custom rootkits, SparrowDoor backdoor

#### Hunt 1: Salt Typhoon — Telecom Infrastructure Suspicious Access

```kql
// Salt Typhoon targets telecom infrastructure — SNMP, TACACS, network device mgmt
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemotePort in (161, 162, 49, 830, 22, 23, 830)  // SNMP, TACACS+, NETCONF, SSH, Telnet
| where ActionType == "ConnectionSuccess"
| where InitiatingProcessFileName in~ (
    "powershell.exe","cmd.exe","python.exe","python3","perl.exe","snmpwalk.exe"
    )
| project Timestamp, DeviceName, RemoteIP, RemotePort,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

#### Hunt 2: SparrowDoor Backdoor Persistence

```kql
// SparrowDoor persists as Windows service with DLL injection
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "ServiceInstalled"
| where AdditionalFields has_any (
    "DisplayName","ServiceName","ImagePath"
    )
| extend ServiceDetails = parse_json(AdditionalFields)
| where ServiceDetails.ImagePath has_any (
    "\\Temp\\","\\AppData\\","\\ProgramData\\","%TEMP%","%APPDATA%"
    )
| project Timestamp, DeviceName, ActionType, ServiceDetails,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### Flax Typhoon

**Attribution:** PRC-linked | **Active Since:** ~2021  
**Primary Targets:** Taiwan, SE Asia — government, military, education  
**Signature TTPs:** Living-off-the-land, VPN/RDP persistence, SoftEther VPN

#### Hunt 1: Flax Typhoon — SoftEther VPN Proxy

```kql
// Flax Typhoon installs SoftEther VPN for persistent access
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("vpnclient.exe","vpncmd.exe","vpnserver.exe","vpnbridge.exe")
| where not(InitiatingProcessFileName in~ ("msiexec.exe","explorer.exe"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
    FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```

#### Hunt 2: Flax Typhoon — WMIC Scheduled Task Persistence

```kql
// Flax Typhoon uses WMIC for persistence
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "wmic.exe"
| where ProcessCommandLine has_any ("process call create","create","alias")
| where ProcessCommandLine has_any ("powershell","cmd","mshta","wscript","regsvr32")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
    InitiatingProcessFileName
| order by Timestamp desc
```

---

### APT27 — Emissary Panda / LuckyMouse / Iron Tiger

**Attribution:** PLA Unit 61486 | **Active Since:** 2010  
**Primary Targets:** Defence, aerospace, governments, energy sector  
**Known Operations:** Waterbug, HyperBro RAT, SysUpdate  
**Signature TTPs:** Watering hole attacks, HyperBro in-memory backdoor

#### Hunt 1: HyperBro In-Memory Loader

```kql
// HyperBro uses DLL side-loading and in-memory execution
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where FileName in~ ("mpc.dll","tmdbglog.dll","igutil.dll","patcher.dll")
| where not(FolderPath has_any (@"C:\Windows\", @"C:\Program Files\"))
| project Timestamp, DeviceName, InitiatingProcessFileName,
    DLL=FileName, DLLPath=FolderPath
| order by Timestamp desc
```

---

<a name="russia"></a>
## 🇷🇺 Russian APTs

---

### APT29 — Cozy Bear / Midnight Blizzard / IRON HEMLOCK

**Attribution:** SVR | **Active Since:** 2008  
**Primary Targets:** Governments, political parties, think tanks, Microsoft/SolarWinds (supply chain)  
**Known Operations:** SolarWinds SUNBURST, Democratic Party breach, Microsoft corporate breach 2024  
**Signature TTPs:** Supply chain, password spraying, OAuth/MFA abuse, SUNBURST, TEAMVIEWER

#### Hunt 1: SUNBURST-Style Supply Chain Backdoor Indicators

```kql
// SUNBURST communicated via DNS with avsvmcloud.com — look for DNS backdoor patterns
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType == "DnsQueryResponse"
| extend DomainParts = split(AdditionalFields, ".")
| extend SubdomainLength = strlen(tostring(split(tostring(DomainParts[0]), "")[0]))
// Long random subdomains are characteristic of DNS C2
| where SubdomainLength > 30
| where AdditionalFields !endswith "microsoft.com"
    and AdditionalFields !endswith "google.com"
    and AdditionalFields !endswith "amazonaws.com"
| project Timestamp, DeviceName, InitiatingProcessFileName, AdditionalFields
| order by Timestamp desc
```

#### Hunt 2: APT29 Password Spraying

```kql
// Midnight Blizzard password spray — one password, many accounts
SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID == 4625  // Failed logon
| where LogonType == 3
| summarize
    FailedAttempts = count(),
    UniqueTargetAccounts = dcount(TargetUserName),
    TargetAccounts = make_set(TargetUserName, 50)
    by IpAddress, bin(TimeGenerated, 1h)
| where UniqueTargetAccounts > 20 and FailedAttempts > 30
| order by UniqueTargetAccounts desc
```

#### Hunt 3: OAuth Token Abuse / Consent Grant Attack

```kql
// APT29 abuses OAuth consent grants and app registrations
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in (
    "Consent to application","Add app role assignment to service principal",
    "Add delegated permission grant","Update application",
    "Add service principal","Add application"
    )
| where Result =~ "success"
| extend InitiatedBy = tostring(parse_json(tostring(InitiatedBy)).user.userPrincipalName)
| extend TargetApp = tostring(TargetResources[0].displayName)
| project TimeGenerated, InitiatedBy, OperationName, TargetApp,
    AdditionalDetails, Result
| order by TimeGenerated desc
```

#### Hunt 4: APT29 — MagicWeb / FoggyWeb AD FS Abuse

```kql
// FoggyWeb targets AD FS servers for token forgery
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any (
    @"\ADFS\",@"\Microsoft.IdentityServer",@"\adfs\ls\",@"\Program Files\Active Directory Federation Services"
    )
| where ActionType in ("FileCreated","FileModified")
| where not(InitiatingProcessFileName in~ ("AdfsServer.exe","adfspip.exe","TrustedInstaller.exe"))
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
    ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

#### Hunt 5: MFA Fatigue / Push Bombing

```kql
// APT29 uses MFA fatigue — high volume of MFA push requests
SigninLogs
| where TimeGenerated > ago(24h)
| where AuthenticationRequirement == "multiFactorAuthentication"
| where ResultType in ("50140","500121")  // MFA interrupted, MFA required
| summarize
    MFAAttempts = count(),
    UniqueLocations = dcount(Location),
    Locations = make_set(Location, 10)
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where MFAAttempts > 5
| order by MFAAttempts desc
```

---

### APT28 — Fancy Bear / Forest Blizzard / Sofacy / STRONTIUM

**Attribution:** GRU Unit 26165 | **Active Since:** 2004  
**Primary Targets:** NATO, governments, military, political campaigns, WADA, DNC  
**Known Operations:** DNC hack, WADA, French election, Ukraine attacks  
**Signature TTPs:** X-Agent/Sofacy malware, spearphishing, credential harvesting, Impacket

#### Hunt 1: X-Agent / Sofacy Modular Malware Pattern

```kql
// X-Agent uses port 443 with custom protocol — look for unusual SSL patterns
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemotePort == 443
| where ActionType == "ConnectionSuccess"
// X-Agent unusual connection intervals
| summarize
    DailyConnections = count(),
    UniqueDays = dcount(bin(Timestamp, 1d)),
    AvgBytesPerConn = avg(SentBytes + ReceivedBytes)
    by DeviceName, RemoteIP, InitiatingProcessFileName
| where DailyConnections > 100 and AvgBytesPerConn < 2048  // Small, regular packets
| where not(InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe","svchost.exe"))
| order by DailyConnections desc
```

#### Hunt 2: Credential Harvesting via Phishing Infrastructure

```kql
// APT28 sets up credential harvesting pages — monitor for credential theft events
IdentityLogonEvents
| where Timestamp > ago(30d)
| where ActionType == "LogonFailed"
// Success after failure from same IP to same account — credential stuffing
| join kind=inner (
    IdentityLogonEvents
    | where Timestamp > ago(30d)
    | where ActionType == "LogonSuccess"
    ) on AccountUpn, IPAddress
| where Timestamp1 between (Timestamp .. (Timestamp + 5m))
| project Timestamp, AccountUpn, IPAddress, DeviceName,
    FailureReason=AdditionalFields
| order by Timestamp desc
```

#### Hunt 3: Impacket Usage — APT28 Post-Exploitation

```kql
// Impacket tools leave distinctive artefacts
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any (
    "impacket","secretsdump","psexec","wmiexec","smbexec",
    "atexec","dcomexec","GetUserSPNs","GetNPUsers",
    "lookupsid","rpcdump","samrdump","services.py"
    )
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

#### Hunt 4: LSASS Credential Dumping — APT28 Technique

```kql
// APT28 uses multiple LSASS dump techniques
union
(
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCommandLine has_any (
        "lsass","procdump","minidump","comsvcs.dll",
        "Out-Minidump","Invoke-Mimikatz","sekurlsa::logonpasswords"
        )
    | project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, Source="Process"
),
(
    DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "LsassProcessAccess"
    | project Timestamp, DeviceName, AccountName,
        InitiatingProcessFileName, InitiatingProcessCommandLine, Source="LSASS"
)
| order by Timestamp desc
```

---

### Sandworm — Voodoo Bear / Seashell Blizzard / IRIDIUM

**Attribution:** GRU Unit 74455 | **Active Since:** 2009  
**Primary Targets:** Ukraine, critical infrastructure, energy grids, NATO  
**Known Operations:** BlackEnergy, NotPetya, Industroyer/CRASHOVERRIDE, Kyivstar attack  
**Signature TTPs:** Wiper malware, ICS-targeted attacks, destructive payloads

#### Hunt 1: Wiper Malware Pattern Detection

```kql
// Sandworm/NotPetya-style wipers — MBR/VBR writes, mass file deletion
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType in ("RawDiskWrite","MBRWrite")
| where not(InitiatingProcessFileName in~ ("TrustedInstaller.exe","wusa.exe"))
| project Timestamp, DeviceName, AccountName, ActionType,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

#### Hunt 2: Mass File Deletion / Encryption — Destructive Payload

```kql
// Wiper: mass file operations across multiple drives
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileDeleted","FileModified")
| where FolderPath matches regex @'^[C-Z]:\\'
| summarize
    FilesAffected = count(),
    UniqueExtensions = dcount(split(FileName,".")[1]),
    UniqueFolders = dcount(FolderPath)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1m)
| where FilesAffected > 100 and UniqueExtensions > 5
| order by FilesAffected desc
```

#### Hunt 3: Industroyer / CRASHOVERRIDE ICS Protocol Indicators

```kql
// Industroyer sends ICS protocol commands (IEC 60870-5-104, IEC 61850, DNP3)
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemotePort in (2404, 102, 20000, 19999, 4712, 4713)  // ICS protocol ports
| where ActionType == "ConnectionSuccess"
| project Timestamp, DeviceName, RemoteIP, RemotePort,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    LocalPort
| order by Timestamp desc
```

#### Hunt 4: Sandworm — Prestige Ransomware / KillDisk

```kql
// Prestige/KillDisk: shadow copy deletion, then wipe
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has_any (
    "vssadmin delete shadows","wmic shadowcopy delete",
    "bcdedit /set recoveryenabled No","bcdedit /set bootstatuspolicy ignoreallfailures",
    "wbadmin delete catalog","cipher /w:","format ","del /f /s /q"
    )
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
```

---

### Turla — Snake / Venomous Bear / IRON HUNTER

**Attribution:** FSB | **Active Since:** 1990s  
**Primary Targets:** Governments, embassies, military, research institutions, diplomats  
**Known Operations:** Operation Moonlight Maze, Snake rootkit, Carbon, KOPILUWAK, CRUTCH  
**Signature TTPs:** Satellite internet C2, Snake rootkit, email-based C2, DNS hijacking

#### Hunt 1: Snake Rootkit — Kernel Driver / Encrypted C2

```kql
// Turla Snake uses encrypted C2 and kernel rootkit — detect driver installs
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "DriverLoad"
| extend DriverDetails = parse_json(AdditionalFields)
| where not(DriverDetails.SignerName has_any (
    "Microsoft","Intel","NVIDIA","AMD","Broadcom","Realtek","Dell","HP","Lenovo"
    ))
// Unsigned or unusually signed drivers
| project Timestamp, DeviceName, ActionType, DriverDetails,
    InitiatingProcessFileName
| order by Timestamp desc
```

#### Hunt 2: KOPILUWAK JavaScript-Based C2

```kql
// KOPILUWAK uses JS dropper and communicates via HTTP
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("wscript.exe","cscript.exe")
| where ProcessCommandLine matches regex @'\.(js|jse|vbs|vbe)\s'
| where not(FolderPath has_any (@"C:\Windows\","C:\Program Files\"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
    FolderPath, InitiatingProcessFileName
| order by Timestamp desc
```

#### Hunt 3: CRUTCH Backdoor — Dropbox Exfiltration

```kql
// CRUTCH exfiltrates via Dropbox API
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (
    "content.dropboxapi.com","api.dropboxapi.com","api2.dropbox.com"
    )
| where InitiatingProcessFileName !in~ ("dropbox.exe","DbxSvc.exe")
| project Timestamp, DeviceName, AccountName, RemoteUrl,
    InitiatingProcessFileName, InitiatingProcessCommandLine, SentBytes
| order by SentBytes desc
```

#### Hunt 4: Turla — Satellite Internet C2

```kql
// Turla hijacks satellite DVB-S connections — unusual outbound UDP to satellite ranges
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where Protocol == "Udp"
| where RemotePort > 49152  // High ephemeral ports
// Satellite ISP IP ranges (partial — update with threat intel)
| where RemoteIP matches regex @'^(217\.29\.|195\.90\.|91\.103\.)'
| project Timestamp, DeviceName, RemoteIP, RemotePort,
    InitiatingProcessFileName, SentBytes, ReceivedBytes
| order by Timestamp desc
```

---

### Gamaredon — Primitive Bear / Actinium / Shuckworm

**Attribution:** FSB | **Active Since:** 2013  
**Primary Targets:** Ukraine — government, defence, military, NGOs  
**Known Operations:** PTERANODON, PTERODO backdoor, extensive spearphishing  
**Signature TTPs:** VBS/VBA malware, USB propagation, frequent TTP iteration

#### Hunt 1: PTERODO Backdoor — VBS-Based

```kql
// Gamaredon PTERODO: VBS files dropped in AppData, auto-start via Run keys
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName endswith ".vbs" or FileName endswith ".vbe"
| where FolderPath has_any (
    @"\AppData\Roaming\",@"\AppData\Local\",@"\ProgramData\",@"\Temp\"
    )
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

#### Hunt 2: USB Propagation — Gamaredon Signature

```kql
// Gamaredon spreads via USB — look for autorun-style execution from removable drives
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FolderPath matches regex @'^[D-Z]:\\'  // Non-system drives
| where not(FolderPath has_any (@"C:\Windows\","C:\Program Files\"))
| where FileName in~ ("wscript.exe","cscript.exe","cmd.exe","powershell.exe","mshta.exe")
| where InitiatingProcessFileName =~ "explorer.exe"
| project Timestamp, DeviceName, AccountName, FolderPath, FileName, ProcessCommandLine
| order by Timestamp desc
```

---

### FIN7 / Carbanak — Navigator / Sangria Tempest

**Attribution:** Criminal but state-tolerated | **Active Since:** 2015  
**Primary Targets:** Financial, hospitality, POS systems, retail  
**Known Operations:** Carbanak banking Trojan, BIRDWATCH, BOOSTWRITE  
**Signature TTPs:** Spearphishing with HID device simulation, POWERTRASH loader, CobaltStrike

#### Hunt 1: BOOSTWRITE DLL Chain

```kql
// FIN7 BOOSTWRITE: in-memory DLL loading via DWriteCreateFactory
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where FileName in~ ("dwrite.dll")
| where not(FolderPath has @"C:\Windows\")
| project Timestamp, DeviceName, InitiatingProcessFileName,
    DLLPath=FolderPath, SHA256
| order by Timestamp desc
```

#### Hunt 2: FIN7 Malicious HID / Rubber Ducky Indicators

```kql
// FIN7 uses HID devices — rapid keystroke injection via USB
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "UsbDeviceEnumerated"
| extend DeviceDetails = parse_json(AdditionalFields)
| where DeviceDetails.DeviceClass =~ "HIDClass"
| where DeviceDetails.Manufacturer !in~ (
    "Microsoft","Logitech","Dell","HP","Lenovo","Apple","Corsair","Razer"
    )
| project Timestamp, DeviceName, ActionType, DeviceDetails
| order by Timestamp desc
```

---

### NOBELIUM — Cozy Bear / Dark Halo (Supply Chain Subset)

**Attribution:** SVR | **Active Since:** 2019 (operation-specific tracking)  
**Primary Targets:** IT/cloud providers, US government, global supply chain  
**Known Operations:** SolarWinds SUNBURST, Pulse Secure attacks  
**Signature TTPs:** SUNSHUTTLE, SIBOT, RAINDROP malware, Azure AD abuse

#### Hunt 1: Azure AD Privilege Escalation — NOBELIUM Pattern

```kql
// NOBELIUM abuses Azure AD privileged roles
AuditLogs
| where TimeGenerated > ago(30d)
| where OperationName in (
    "Add member to role","Add eligible member to role",
    "Add app role assignment","Update user","Reset user password"
    )
| where TargetResources[0].modifiedProperties has_any (
    "Global Administrator","Privileged Role Administrator",
    "Security Administrator","Application Administrator",
    "Exchange Administrator"
    )
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend Target = tostring(TargetResources[0].userPrincipalName)
| project TimeGenerated, Actor, Target, OperationName, AdditionalDetails
| order by TimeGenerated desc
```

#### Hunt 2: SIBOT — Scheduled Task via Registry

```kql
// SIBOT uses scheduled tasks hidden in HKCU for second-stage download
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache"
| where ActionType in ("RegistryValueSet","RegistryKeyCreated")
| where RegistryValueData has_any (
    "powershell","cmd","wscript","cscript","mshta","rundll32"
    )
| project Timestamp, DeviceName, AccountName, RegistryKey,
    RegistryValueName, RegistryValueData
| order by Timestamp desc
```

---

<a name="iran"></a>
## 🇮🇷 Iranian APTs

---

### APT33 — Elfin / Refined Kitten / Holmium

**Attribution:** IRGC | **Active Since:** 2013  
**Primary Targets:** Aerospace, defence, energy (Saudi Arabia, US, South Korea)  
**Known Operations:** DROPSHOT/StoneDrill wiper, TURNEDUP backdoor, STONEDRILL  
**Signature TTPs:** Spearphishing, destructive wiper attacks, DropShot backdoor

#### Hunt 1: DROPSHOT/StoneDrill Wiper Indicators

```kql
// APT33 StoneDrill: injects into browser process, then wipes
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "ProcessInjected"
| where AdditionalFields has_any ("chrome.exe","firefox.exe","iexplore.exe","msedge.exe")
| where not(InitiatingProcessFileName in~ ("MsMpEng.exe","mcshield.exe"))
| join kind=inner (
    // Then check for file deletion after injection
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where ActionType == "FileDeleted"
    | summarize DeleteCount = count() by DeviceName, bin(Timestamp, 5m)
    | where DeleteCount > 50
    ) on DeviceName
| project Timestamp, DeviceName, ActionType, AdditionalFields
| order by Timestamp desc
```

#### Hunt 2: APT33 — EmpireProject PowerShell Framework

```kql
// APT33 uses Empire C2 framework — look for Empire launcher patterns
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine matches regex @'(?i)(empire|stager|staging|launcher|EVIL)'
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
    InitiatingProcessFileName
| order by Timestamp desc
```

---

### APT34 — OilRig / Helix Kitten / CRAMBUS

**Attribution:** MOIS (Ministry of Intelligence) | **Active Since:** 2014  
**Primary Targets:** Middle East — financial, government, energy, telecoms  
**Known Operations:** POWRUNER, BONDUPDATER, TONEDEAF, DNSpionage  
**Signature TTPs:** DNS tunnelling C2, custom backdoors, Excel macro delivery

#### Hunt 1: DNS Tunnelling — APT34 Signature

```kql
// APT34 DNSpionage: DNS C2 — exfiltrates data in DNS queries
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType == "DnsQueryResponse"
// High query volume to single domain with long subdomains = DNS tunnelling
| extend DomainQuery = tostring(AdditionalFields)
| extend SubdomainPart = extract(@'^([^.]+)\.', 1, DomainQuery)
| extend SubdomainLen = strlen(SubdomainPart)
| where SubdomainLen > 25  // Long subdomains carry encoded data
| summarize
    QueryCount = count(),
    UniqueSubs = dcount(SubdomainPart),
    AvgSubLen = avg(SubdomainLen)
    by DeviceName, TLD=extract(@'(\w+\.\w+)$', 1, DomainQuery), bin(Timestamp, 1h)
| where QueryCount > 50 and UniqueSubs > 30
| order by QueryCount desc
```

#### Hunt 2: TONEDEAF Backdoor — HTTP C2

```kql
// TONEDEAF uses POST requests with specific URI patterns
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where ActionType == "HttpConnectionInspected"
| where RequestMethod == "POST"
| where RequestUri has_any (
    "/api/","/.well-known/","//","index.php","news.php",
    "update.php","get.php","login.php","status.php"
    )
// TONEDEAF uses non-browser processes for HTTP
| where InitiatingProcessFileName !in~ (
    "chrome.exe","msedge.exe","firefox.exe","iexplore.exe"
    )
| project Timestamp, DeviceName, RemoteUrl, RequestUri,
    InitiatingProcessFileName, RequestBodySize
| order by Timestamp desc
```

#### Hunt 3: BONDUPDATER — PowerShell DNS C2

```kql
// BONDUPDATER uses PowerShell with DNS for C2
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "Resolve-DnsName","nslookup","[Net.Dns]","DnsQuery",
    "TXT","AAAA","A record","dns"
    )
| where ProcessCommandLine has_any (
    "IEX","Invoke-Expression","DownloadString","WebClient","-enc","-e "
    )
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
    InitiatingProcessFileName
| order by Timestamp desc
```

---

### APT35 — Charming Kitten / Phosphorus / TA453 / Mint Sandstorm

**Attribution:** IRGC | **Active Since:** 2014  
**Primary Targets:** Journalists, academics, human rights, US politics, nuclear experts  
**Known Operations:** Gmail credential harvesting, POWERSTAR, CharmPower, BellaCiao  
**Signature TTPs:** Social engineering via fake personas, credential phishing, POWERSTAR RAT

#### Hunt 1: POWERSTAR Modular RAT

```kql
// POWERSTAR: PowerShell-based modular RAT with cloud storage C2
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any (
    "GoogleDrive","OneDrive","graph.microsoft.com",
    "DownloadFile","UploadFile","Invoke-WebRequest"
    )
| where ProcessCommandLine has_any (
    "[System.Convert]::FromBase64String","Decompress",
    "GZip","Deflate","MemoryStream"
    )
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
    InitiatingProcessFileName
| order by Timestamp desc
```

#### Hunt 2: BellaCiao — .NET Dropper Persistence

```kql
// BellaCiao drops .NET payloads and uses IIS modules for persistence
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any (@"\inetpub\",@"\wwwroot\",@"\Microsoft.NET\Framework")
| where FileName endswith ".dll" or FileName endswith ".aspx"
| where ActionType in ("FileCreated","FileModified")
| where not(InitiatingProcessFileName in~ (
    "w3wp.exe","TrustedInstaller.exe","msiexec.exe","dotnet.exe"
    ))
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
    ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### MuddyWater — SeedWorm / Boggy Serpent / MANGO SANDSTORM

**Attribution:** MOIS | **Active Since:** 2017  
**Primary Targets:** Middle East, Central Asia, Europe — government, telecoms, defence  
**Known Operations:** POWERSTATS, SHARPSTATS, BugSleep backdoor  
**Signature TTPs:** PowerShell droppers, remote monitoring tools abuse, MSI/PDF lures

#### Hunt 1: POWERSTATS Backdoor

```kql
// POWERSTATS: multi-stage PowerShell backdoor with encoded commands
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine matches regex @'(?i)(-nop|-noprofile|-w\s+hidden|-windowstyle\s+hidden)'
| where ProcessCommandLine matches regex @'(?i)(IEX|Invoke-Expression|&\s*\(|\.Download)'
| project Timestamp, DeviceName, AccountName, ProcessCommandLine,
    InitiatingProcessFileName
| order by Timestamp desc
```

#### Hunt 2: MuddyWater — Remote Monitoring Tool Abuse

```kql
// MuddyWater abuses legitimate RMM tools (Atera, Splashtop, ScreenConnect)
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has_any (
    "atera.com","splashtop.com","screenconnect.com",
    "anydesk.com","syncrocloud.com","n-able.com"
    )
| where InitiatingProcessFileName !in~ (
    "AteraAgent.exe","SplashtopBusiness.exe","ScreenConnect.WindowsClient.exe",
    "AnyDesk.exe","explorer.exe"
    )
| project Timestamp, DeviceName, AccountName, RemoteUrl,
    InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
```

---

### Agrius — Pink Sandstorm

**Attribution:** Iranian (MOIS-linked) | **Active Since:** 2020  
**Primary Targets:** Israel, UAE — wiper attacks posing as ransomware  
**Known Operations:** DEADWOOD, IPsec Helper, Fantasy wiper  
**Signature TTPs:** Wiper disguised as ransomware, supply chain compromise

#### Hunt 1: Fantasy Wiper Indicators

```kql
// Fantasy wiper: targets specific file extensions and overwrites
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in ("FileModified","FileDeleted")
| where FileName matches regex @'\.(docx|xlsx|pptx|pdf|mdb|accdb|sql|bak)$'
| summarize
    ModifiedFiles = count(),
    UniqueFolders = dcount(FolderPath)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 2m)
| where ModifiedFiles > 200
| order by ModifiedFiles desc
```

---

<a name="middle-east"></a>
## 🌍 Middle East & Gulf APTs

---

### Bahamut

**Attribution:** Mercenary / likely Gulf state-sponsored | **Active Since:** ~2016  
**Primary Targets:** Journalists, activists, Middle East/South Asia, iOS/Android  
**Signature TTPs:** Fake news sites, social engineering, mobile spyware

#### Hunt 1: Bahamut — Fake App / Sideload Indicators

```kql
// Bahamut distributes trojanized apps
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FolderPath has_any (@"\Downloads\",@"\Temp\",@"\Desktop\")
| where FileName endswith ".exe" or FileName endswith ".msi"
| where InitiatingProcessFileName in~ ("chrome.exe","msedge.exe","firefox.exe")
| project Timestamp, DeviceName, AccountName, FolderPath, FileName,
    ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
```

---

### Molerats — Gaza Cybergang / Moonlight

**Attribution:** Hamas-affiliated | **Active Since:** 2012  
**Primary Targets:** Palestinian Authority, Egypt, Middle East governments  
**Signature TTPs:** Commodity malware, NjRAT, njRAT, SpyNote, political lures

#### Hunt 1: NjRAT Indicators

```kql
// NjRAT uses non-standard ports and specific registry persistence
union
(
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemotePort in (1177, 5552, 3214, 7777, 9999, 4444, 1234)
    | where ActionType == "ConnectionSuccess"
    | project Timestamp, DeviceName, RemoteIP, RemotePort, InitiatingProcessFileName, Source="Network"
),
(
    DeviceRegistryEvents
    | where Timestamp > ago(30d)
    | where RegistryKey has @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    | where RegistryValueData has_any (
        "njrat","bifrost","darkcomet","quasar","asyncrat"
        )
    | project Timestamp, DeviceName, RegistryKey, RegistryValueData, Source="Registry"
)
| order by Timestamp desc
```

---

<a name="other"></a>
## 🌐 Other / Multi-Region APTs

---

### Transparent Tribe — APT36 / ProjectM

**Attribution:** Pakistan ISI | **Active Since:** 2013  
**Primary Targets:** India — defence, government, military, education  
**Known Operations:** CRIMSON RAT, CrimsonRAT, ObliqueRAT  
**Signature TTPs:** Honey-trap phishing, fake defence portals, CrimsonRAT

#### Hunt 1: CrimsonRAT Indicators

```kql
// CrimsonRAT: .NET RAT with USB spreading, keylogging
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
| where RegistryValueData has_any (
    ".NET","WindowsApplication","CrimsonRAT","Client.exe"
    )
| where not(RegistryValueData has_any (
    "OneDrive","Teams","Discord","Spotify","Steam","Zoom"
    ))
| project Timestamp, DeviceName, AccountName, RegistryKey,
    RegistryValueName, RegistryValueData
| order by Timestamp desc
```

### SideWinder — APT-C-17 / RattleSnake

**Attribution:** India | **Active Since:** 2012  
**Primary Targets:** Pakistan, China, Nepal, Sri Lanka — military, government  
**Signature TTPs:** Spearphishing, LNK abuse, .NET RAT deployment

#### Hunt 1: LNK File Abuse — SideWinder Initial Access

```kql
// SideWinder uses malicious LNK files to run PowerShell
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName endswith ".lnk"
| where FolderPath has_any (@"\Downloads\",@"\Temp\",@"\Desktop\")
| where ActionType == "FileCreated"
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName =~ "explorer.exe"
    | where FileName in~ ("powershell.exe","cmd.exe","wscript.exe","mshta.exe")
    ) on DeviceName
| where Timestamp1 between (Timestamp .. (Timestamp + 30s))
| project Timestamp, DeviceName, AccountName, LNKFile=FileName,
    SpawnedProcess=FileName1, CommandLine=ProcessCommandLine1
| order by Timestamp desc
```

### Equation Group (NSA-affiliated — Defensive Reference)

**Attribution:** NSA TAO | **Active Since:** ~2001  
**Signature TTPs:** DoubleFantasy, DoubleAgent, NOPEN, UNITEDRAKE, FANNY worm  
**Note:** Detection included for defensive awareness of most sophisticated tooling

#### Hunt 1: Equation Group — NOPEN/UNITEDRAKE Kernel Module Indicators

```kql
// Equation Group rootkit: unusual kernel module loads, hidden files
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType == "DriverLoad"
| extend Details = parse_json(AdditionalFields)
| where Details.IsKernelMode == true
| where not(Details.SignerName has_any (
    "Microsoft","Intel","NVIDIA","AMD","Broadcom"
    ))
// Modules with randomised or suspiciously generic names
| where Details.FileName matches regex @'^[a-z0-9]{4,8}\.sys$'
| project Timestamp, DeviceName, Details, InitiatingProcessFileName
| order by Timestamp desc
```

---

<a name="cross-apt"></a>
## 🔎 Cross-APT Detection Patterns

These queries catch TTPs shared across multiple APT groups.

### Universal: Domain Generation Algorithm (DGA) Detection

```kql
// DGA domains used by Gamaredon, APT33, and others
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where ActionType == "DnsQueryResponse"
| extend DomainQuery = tostring(AdditionalFields)
| extend DomainRoot = extract(@'([^.]+\.[^.]+)$', 1, DomainQuery)
// Calculate character entropy of domain root
| extend CharSet = set_intersect(
    split(tolower(DomainRoot),""),
    split("abcdefghijklmnopqrstuvwxyz0123456789","")
    )
| extend EntropyScore = array_length(CharSet) * strlen(DomainRoot)
| where EntropyScore > 150  // High entropy = likely DGA
| where not(DomainQuery endswith ".microsoft.com")
    and not(DomainQuery endswith ".google.com")
    and not(DomainQuery endswith ".amazonaws.com")
| summarize QueryCount = count() by DeviceName, DomainRoot, bin(Timestamp, 1h)
| where QueryCount > 5
| order by QueryCount desc
```

### Universal: T1055 — Process Injection Detection

```kql
// Process injection: used by Lazarus, APT28, APT29, APT41, Turla, etc.
DeviceEvents
| where Timestamp > ago(30d)
| where ActionType in (
    "WriteProcessMemory","CreateRemoteThread","QueueUserAPC",
    "SetThreadContext","ProcessInjected"
    )
| where not(InitiatingProcessFileName in~ (
    "MsMpEng.exe","csrss.exe","wininit.exe","winlogon.exe",
    "lsass.exe","services.exe","smss.exe"
    ))
| project Timestamp, DeviceName, AccountName, ActionType,
    InitiatingProcessFileName, InitiatingProcessCommandLine,
    AdditionalFields
| order by Timestamp desc
```

### Universal: T1003 — Credential Dumping Summary

```kql
// All credential dumping techniques in one query
union
(
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where ProcessCommandLine has_any (
        "sekurlsa","lsadump","dcsync","hashdump","pass-the-hash",
        "mimikatz","LaZagne","procdump lsass","comsvcs MiniDump",
        "reg save HKLM\\SAM","reg save HKLM\\SYSTEM"
        )
    | project Timestamp, DeviceName, AccountName, Technique="CommandLine", Detail=ProcessCommandLine
),
(
    DeviceEvents
    | where Timestamp > ago(30d)
    | where ActionType == "LsassProcessAccess"
    | project Timestamp, DeviceName, AccountName, Technique="LsassAccess",
        Detail=InitiatingProcessCommandLine
),
(
    DeviceFileEvents
    | where Timestamp > ago(30d)
    | where FileName in~ ("SAM","NTDS.dit","SYSTEM","SECURITY")
    | where FolderPath !has @"C:\Windows\System32\config\"
    | where ActionType in ("FileCopied","FileRead")
    | project Timestamp, DeviceName, AccountName, Technique="CredentialFileAccess",
        Detail=FolderPath
)
| order by Timestamp desc
```

### Universal: T1021 — Lateral Movement Detection

```kql
// Lateral movement across the network — all methods
union
(
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemotePort in (445, 135, 139, 3389, 5985, 5986, 22)
    | where ActionType == "ConnectionSuccess"
    | where not(RemoteIP startswith "127.") and not(RemoteIP startswith "::1")
    | summarize
        TargetHosts = dcount(RemoteIP),
        Ports = make_set(RemotePort)
        by DeviceName, AccountName, InitiatingProcessFileName, bin(Timestamp, 1h)
    | where TargetHosts > 3
    | project Timestamp=bin(now(), 1h), DeviceName, AccountName,
        Method="NetworkLateral", InitiatingProcessFileName, TargetHosts, Detail=tostring(Ports)
),
(
    SecurityEvent
    | where TimeGenerated > ago(30d)
    | where EventID == 4648  // Explicit credential logon
    | where TargetServerName != Computer
    | project Timestamp=TimeGenerated, DeviceName=Computer, AccountName=SubjectUserName,
        Method="ExplicitCreds", InitiatingProcessFileName=ProcessName, TargetHosts=1,
        Detail=TargetServerName
)
| order by Timestamp desc
```

### Universal: APT Staging Directories

```kql
// Common staging directories used by APTs for tool deployment
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any (
    @"\ProgramData\Microsoft\",
    @"\Windows\Temp\",
    @"\Users\Public\",
    @"\AppData\Local\Temp\",
    @"\AppData\Roaming\Microsoft\Windows\Start Menu\",
    @"\SystemRoot\Temp\",
    @"\Recycle.Bin\",
    @"\$Recycle.Bin\"
    )
| where FileName endswith ".exe" or FileName endswith ".dll"
    or FileName endswith ".ps1" or FileName endswith ".vbs"
    or FileName endswith ".bat" or FileName endswith ".cmd"
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, AccountName, FileName, FolderPath,
    InitiatingProcessFileName, SHA256
| order by Timestamp desc
```

---

<a name="defender-xdr"></a>
## 🛡️ Defender XDR Advanced Hunting Queries

These run in the **Defender portal** under Advanced Hunting.

### XDR-1: Cross-Workload APT Activity Correlation

```kql
// Correlate identity, endpoint, and email signals across all APT TTPs
let SuspiciousAccounts = IdentityLogonEvents
    | where Timestamp > ago(7d)
    | where ActionType == "LogonFailed"
    | summarize FailCount = count() by AccountUpn
    | where FailCount > 10
    | project AccountUpn;
let EndpointAlerts = DeviceAlertEvents
    | where Timestamp > ago(7d)
    | where Severity in ("High","Medium")
    | project DeviceName, AccountName, AlertId, Title;
let EmailThreats = EmailEvents
    | where Timestamp > ago(7d)
    | where ThreatTypes has_any ("Malware","Phish","Spam")
    | project RecipientEmailAddress, Subject, ThreatTypes, SenderMailFromAddress;
SuspiciousAccounts
| join kind=leftouter (
    EndpointAlerts
    ) on $left.AccountUpn == $right.AccountName
| join kind=leftouter (
    EmailThreats
    ) on $left.AccountUpn == $right.RecipientEmailAddress
| where isnotempty(DeviceName) or isnotempty(Subject)
| project AccountUpn, DeviceName, AlertTitle=Title, EmailSubject=Subject,
    EmailThreat=ThreatTypes
| order by AccountUpn
```

### XDR-2: Email → Execution Chain (Spear Phishing to Compromise)

```kql
// Full kill chain: phishing email → file creation → process execution
let PhishingEmails = EmailAttachmentInfo
    | where Timestamp > ago(7d)
    | where FileType in~ ("exe","dll","vbs","js","lnk","hta","ps1","bat","docm","xlsm","pptm","iso","img","zip")
    | project NetworkMessageId, FileName, FileType, RecipientEmailAddress;
let FileDrops = DeviceFileEvents
    | where Timestamp > ago(7d)
    | where ActionType == "FileCreated"
    | where FileName endswith ".exe" or FileName endswith ".dll"
        or FileName endswith ".vbs" or FileName endswith ".ps1"
    | project DeviceName, AccountName, DropTime=Timestamp, FileName, FolderPath;
let Executions = DeviceProcessEvents
    | where Timestamp > ago(7d)
    | project DeviceName, AccountName, ExecTime=Timestamp, ProcessName=FileName, CommandLine=ProcessCommandLine;
PhishingEmails
| join kind=inner FileDrops on $left.RecipientEmailAddress == $right.AccountName
| join kind=inner Executions on DeviceName
| where ExecTime between ((DropTime - 5m) .. (DropTime + 30m))
| project RecipientEmailAddress, DeviceName, NetworkMessageId,
    DroppedFile=FileName1, DropTime, ExecutedProcess=ProcessName, CommandLine
| order by DropTime desc
```

### XDR-3: Identity-Based Threat Hunt — MDI + Sentinel

```kql
// Microsoft Defender for Identity: suspicious AD activity
IdentityDirectoryEvents
| where Timestamp > ago(30d)
| where ActionType in (
    "SamrEnumerateGroupsInDomain",
    "LdapSearch",
    "SamrQueryInformationUser",
    "SecurityPrincipalQuery",
    "DirectoryServicesReplication"  // DCSync
    )
| summarize
    ActionCount = count(),
    UniqueTargets = dcount(TargetAccountDisplayName),
    Actions = make_set(ActionType, 20)
    by AccountUpn, DeviceName, bin(Timestamp, 1h)
| where ActionCount > 20 or Actions has "DirectoryServicesReplication"
| order by ActionCount desc
```

### XDR-4: Cloud App Anomalies (MDCA)

```kql
// Microsoft Defender for Cloud Apps: impossible travel, mass download
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in (
    "FileDownloaded","FileSyncDownloadedFull","FileRead",
    "MassDownload","BulkDelete"
    )
| summarize
    OperationCount = count(),
    DataVolumeMB = sum(ObjectCount) / 1000,
    Locations = make_set(City, 10)
    by AccountId, AccountDisplayName, bin(Timestamp, 1h)
| where OperationCount > 100 or DataVolumeMB > 100
| order by OperationCount desc
```

---

<a name="sentinel-analytics"></a>
## 📊 Sentinel Scheduled Analytics Rules

These are production-ready for deployment as **Scheduled Query Rules** in Sentinel.

### Sentinel Rule 1: APT Password Spray Detection

```kql
// KQL for Sentinel Scheduled Rule
// Frequency: Every 1h | Lookback: 1h | Threshold: 1
let threshold_accounts = 15;
let threshold_attempts = 50;
SigninLogs
| where TimeGenerated > ago(1h)
| where ResultType != "0"  // Failed logins only
| where AppDisplayName != "Windows Sign In"
| summarize
    AttemptCount = count(),
    UniqueAccounts = dcount(UserPrincipalName),
    TargetAccounts = make_set(UserPrincipalName, 50),
    UniqueASNs = dcount(AutonomousSystemNumber)
    by IPAddress, bin(TimeGenerated, 1h)
| where UniqueAccounts >= threshold_accounts and AttemptCount >= threshold_attempts
| extend AlertSeverity = case(
    UniqueAccounts > 50, "High",
    UniqueAccounts > 25, "Medium",
    "Low"
    )
| project TimeGenerated, IPAddress, AttemptCount, UniqueAccounts,
    TargetAccounts, UniqueASNs, AlertSeverity
```

### Sentinel Rule 2: APT Persistence — New Scheduled Task by Non-Admin

```kql
// Frequency: Every 30m | Lookback: 30m
SecurityEvent
| where TimeGenerated > ago(30m)
| where EventID == 4698  // Scheduled task created
| extend TaskDetails = parse_xml(EventData)
| extend TaskName = tostring(TaskDetails.EventData.Data[4]["#text"])
| extend TaskAction = tostring(TaskDetails.EventData.Data[5]["#text"])
| extend CreatorAccount = tostring(TaskDetails.EventData.Data[1]["#text"])
| where TaskAction has_any (
    "powershell","cmd","wscript","cscript","mshta","rundll32",
    "regsvr32","certutil","bitsadmin","msiexec"
    )
| where not(CreatorAccount in~ (
    "SYSTEM","TrustedInstaller","NETWORK SERVICE","LOCAL SERVICE"
    ))
| project TimeGenerated, Computer, CreatorAccount, TaskName, TaskAction
```

### Sentinel Rule 3: DCSync Attack Detection

```kql
// Frequency: Every 15m | Lookback: 15m
SecurityEvent
| where TimeGenerated > ago(15m)
| where EventID == 4662
| where ObjectType == "%{19195a5b-6da0-11d0-afd3-00c04fd930c9}"  // Domain object
| where Properties has_any (
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  // DS-Replication-Get-Changes
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  // DS-Replication-Get-Changes-All
    "89e95b76-444d-4c62-991a-0facbeda640c"   // DS-Replication-Get-Changes-In-Filtered-Set
    )
| where not(SubjectUserName endswith "$")  // Filter out machine accounts
| project TimeGenerated, Computer, SubjectUserName, SubjectDomainName,
    Properties, ObjectName
```

### Sentinel Rule 4: Suspicious Azure AD Application Created

```kql
// Frequency: Every 1h | Lookback: 1h
AuditLogs
| where TimeGenerated > ago(1h)
| where OperationName == "Add application"
| where Result =~ "success"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| extend AppName = tostring(TargetResources[0].displayName)
| extend AppId = tostring(TargetResources[0].id)
// High-risk if actor is not a known admin or service account
| where not(Actor endswith "@privileged-admins.domain.com")
| project TimeGenerated, Actor, AppName, AppId, AdditionalDetails
```

---

<a name="mitre-matrix"></a>
## 🗺️ MITRE ATT&CK Coverage Matrix

| Tactic | Technique | APT Groups | KQL Coverage |
|--------|-----------|------------|--------------|
| Initial Access | T1566 — Phishing | Kimsuky, APT28, APT35, MuddyWater | Hunt 2 (Kimsuky HWP) |
| Initial Access | T1190 — Exploit Public App | APT40, APT27, Salt Typhoon | Hunt 1 (Web shell) |
| Initial Access | T1195 — Supply Chain | APT41, APT10, NOBELIUM, APT29 | Hunt 3 (APT41) |
| Execution | T1059.001 — PowerShell | All APTs | Universal Hunt 3 |
| Execution | T1059.005 — VBScript | Gamaredon, Kimsuky | Hunt 1 (Gamaredon) |
| Execution | T1047 — WMI | Lazarus, Volt Typhoon | Hunt 5 (Lazarus) |
| Persistence | T1053 — Scheduled Task | NOBELIUM, APT34, Flax Typhoon | Hunt 2 (SIBOT) |
| Persistence | T1547 — Registry Run Keys | Gamaredon, NjRAT | Hunt 1 (Gamaredon) |
| Persistence | T1543 — Windows Service | Salt Typhoon, APT29 | Hunt 2 (SparrowDoor) |
| Privilege Escalation | T1055 — Process Injection | APT29, APT41, Turla, Lazarus | Cross-APT Hunt |
| Defence Evasion | T1574 — DLL Side-Loading | Lazarus, APT10, APT41, APT27 | Hunt 1 (ShadowPad) |
| Defence Evasion | T1140 — Deobfuscate/Decode | All APTs | Universal Hunt 3 |
| Defence Evasion | T1562 — Impair Defences | Sandworm, APT33 | Hunt 4 (Sandworm) |
| Credential Access | T1003 — LSASS Dump | APT28, APT29, Lazarus | Universal Hunt 4 |
| Credential Access | T1110.003 — Password Spray | APT29, APT40 | Hunt 2 (APT29) |
| Discovery | T1082 — System Info | Kimsuky, ScarCruft | Hunt 2 (ScarCruft) |
| Discovery | T1087 — Account Discovery | APT29, Volt Typhoon | Hunt 1 (Volt Typhoon) |
| Discovery | T1018 — Remote System Discovery | APT28, APT41 | Universal Lateral |
| Lateral Movement | T1021 — Remote Services | APT28, APT29, Sandworm | Cross-APT Hunt |
| Lateral Movement | T1550 — Pass-the-Hash | APT28, APT29, Lazarus | Universal Hunt 5 |
| Collection | T1560 — Archive Data | APT10, APT29, Turla | Multiple queries |
| Exfiltration | T1048 — Alt Protocol Exfil | Turla (DNS), APT34 (DNS) | Hunt 1 (APT34 DNS) |
| Exfiltration | T1567 — Cloud Storage | CRUTCH/Turla, ScarCruft, POWERSTAR | Hunt 3 (Turla) |
| C2 | T1071 — App Layer Protocol | All APTs | Universal Hunt 7 |
| C2 | T1132 — Data Encoding | APT34, Kimsuky | Multiple queries |
| Impact | T1485 — Data Destruction | Sandworm, APT33, Agrius | Hunt 1/2 (Sandworm) |
| Impact | T1486 — Data Encrypted (Ransomware) | Lazarus (RansomHub), Sandworm | Hunt 2 (Sandworm) |

---

<a name="cheat-sheet"></a>
## ⚡ Quick-Reference Cheat Sheet

### Top Indicators by APT

| APT | #1 KQL Signal | Priority Tables |
|-----|---------------|-----------------|
| Lazarus | DLL side-loading from user dirs | DeviceImageLoadEvents |
| Kimsuky | HWP.exe spawning shell | DeviceProcessEvents |
| APT29 | Password spray + OAuth abuse | SigninLogs, AuditLogs |
| APT28 | Impacket CLI strings | DeviceProcessEvents |
| Sandworm | VSSAdmin shadow delete + MBR write | DeviceProcessEvents, DeviceEvents |
| APT41 | CobaltStrike named pipes | DeviceEvents |
| APT10 | RMM tools spawning shells | DeviceProcessEvents |
| APT34 | DNS TXT lookups from PowerShell | DeviceNetworkEvents |
| MuddyWater | Atera/Splashtop unexpected use | DeviceNetworkEvents |
| Volt Typhoon | Chained LOLBins, no malware | DeviceProcessEvents |
| Salt Typhoon | SNMP/TACACS connections | DeviceNetworkEvents |
| Turla | Dropbox API from non-Dropbox processes | DeviceNetworkEvents |
| Gamaredon | .vbs in AppData + USB execution | DeviceFileEvents |
| APT35 | Base64+GZip PowerShell + cloud storage | DeviceProcessEvents |
| APT40 | Web server (w3wp.exe) spawning cmd | DeviceProcessEvents |

### Critical Tables Reference

| Table | Defender XDR | Sentinel (via connector) |
|-------|-------------|--------------------------|
| DeviceProcessEvents | ✅ | ✅ |
| DeviceNetworkEvents | ✅ | ✅ |
| DeviceFileEvents | ✅ | ✅ |
| DeviceImageLoadEvents | ✅ | ✅ |
| DeviceEvents | ✅ | ✅ |
| DeviceRegistryEvents | ✅ | ✅ |
| IdentityLogonEvents | ✅ | ✅ |
| IdentityDirectoryEvents | ✅ | ✅ |
| CloudAppEvents | ✅ | ✅ |
| EmailEvents | ✅ | ✅ |
| SecurityEvent | N/A | ✅ (Windows Security Events) |
| SigninLogs | N/A | ✅ (Entra ID) |
| AuditLogs | N/A | ✅ (Entra ID) |

### Rapid Triage Sequence

```
1. Run Universal LOLBin Hunt       → Broad initial sweep
2. Check password spray (APT29)    → Identity compromise
3. Check LSASS access              → Credential theft
4. Check persistence (schtasks/reg)→ Foothold established?
5. Check lateral movement (SMB/WMI)→ Scope of compromise
6. Check exfiltration (DNS/Cloud)  → Data loss assessment
7. APT-specific hunts              → Attribution & IOC extraction
```

---

## 📌 Operational Notes

- **False Positive Tuning:** All queries should be baselined against your environment. Add your known admin workstations and service accounts to exclusion lists.
- **Threat Intel Integration:** Enrich queries with MISP, Sentinel TI, or Defender TI using `ThreatIntelligenceIndicator` table joins.
- **Custom KQL Functions:** Convert recurring logic into [Sentinel Watchlists](https://docs.microsoft.com/azure/sentinel/watchlists) or [Saved Functions](https://docs.microsoft.com/azure/monitor/logs/functions).
- **Alert Fatigue:** Start with `| take 100` limits and tune thresholds before productionising.
- **Time Windows:** Reduce to `ago(24h)` for active incident response to maintain query performance.

---

*Generated for internal SOC use. All ATT&CK® references © MITRE Corporation. Hunt responsibly.*

---

## 🤖 Auto-Generated Daily Detections (OSINT-derived)

> ⚠️ **These queries are machine-generated from open-source reporting and are NOT validated.** They are structurally linted only. Review, tune thresholds, confirm table/column names against your schema, and test before deploying to production. Newest entries are appended at the end.

### 2026-08-10

*Generated 2026-08-10 13:51 UTC · model `claude-sonnet-5`*

_Lint: 5 KQL block(s) — structural checks passed. All queries are CANDIDATES; validate before use._

#### TrueConf Server Process Spawning Unexpected Child Processes
- **Actor / Campaign:** Head Mare (TrueConf exploitation / PhantomCore)
- **MITRE ATT&CK:** T1210 — Exploitation of Remote Services
- **Data source:** DeviceProcessEvents
- **Source:** [1]

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName has_any ("trueconf", "tconfd", "tcserver") // adjust to actual TrueConf server binary names in your environment
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","bitsadmin.exe","certutil.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, AccountName
| take 100
```

*Note:* Web-facing conferencing/collaboration servers legitimately spawn few if any shells; validate against a baseline of normal TrueConf server behavior before alerting, and confirm actual TrueConf process/service names in your estate.

#### TrueConf Client Installer File Replaced or Dropped Unexpectedly
- **Actor / Campaign:** Head Mare (PhantomCore installer swap)
- **MITRE ATT&CK:** T1195.002 — Supply Chain Compromise: Compromise Software Supply Chain
- **Data source:** DeviceFileEvents
- **Data source:** DeviceFileEvents
- **Source:** [1]

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName endswith ".exe" or FileName endswith ".msi"
| where FileName has "trueconf" or FolderPath has "trueconf"
| where ActionType in ("FileCreated","FileModified","FileRenamed")
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine, SHA256
| take 100
```

*Note:* Intended to catch server-side installer/client package tampering reported for PhantomCore delivery; tune FolderPath to your actual TrueConf install/distribution paths and expect noise during legitimate patch/update cycles — correlate with unexpected hash changes on known installers.

#### Command-Line Activity from TrueConf Server Account Context
- **Actor / Campaign:** Head Mare
- **MITRE ATT&CK:** T1059 — Command and Scripting Interpreter
- **Data source:** DeviceProcessEvents
- **Source:** [1]

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName has_any ("trueconf","tcserver","svc-trueconf") // service account used to run TrueConf server
| where FileName in~ ("cmd.exe","powershell.exe","net.exe","whoami.exe","net1.exe","reg.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| take 100
```

*Note:* Requires knowledge of the service account TrueConf server runs under; treat as high-value signal if that account normally never spawns interactive tooling.

#### Outbound Network Connections Initiated by TrueConf Server Process
- **Actor / Campaign:** Head Mare (post-exploitation C2 to PhantomCore infrastructure)
- **MITRE ATT&CK:** T1071 — Application Layer Protocol (C2)
- **Data source:** DeviceNetworkEvents
- **Source:** [1]

```kql
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName has_any ("trueconf", "tconfd", "tcserver")
| where RemotePort in (80, 443, 8080, 4443) // common C2 fallback ports; widen as needed
| where RemoteIPType == "Public"
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort, InitiatingProcessCommandLine
| take 100
```

*Note:* No specific C2 IPs/domains were published in this report; this is a purely behavioral hunt for anomalous outbound connections from the TrueConf server process and requires environment-specific allow-listing of legitimate TrueConf/TURN/STUN traffic to reduce false positives.

#### Persistence Mechanism Created Following TrueConf Server Compromise
- **Actor / Campaign:** Head Mare (PhantomCore persistence)
- **MITRE ATT&CK:** T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder
- **Data source:** DeviceRegistryEvents, DeviceProcessEvents
- **Source:** [1]

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has @"CurrentVersion\Run" or RegistryKey has @"CurrentVersion\RunOnce"
| where InitiatingProcessFileName has_any ("trueconf", "tconfd", "tcserver")
| project Timestamp, DeviceName, InitiatingProcessFileName, RegistryKey, RegistryValueName, RegistryValueData
| take 100
```

*Note:* Heuristic hunt for persistence dropped by/via the compromised TrueConf server process; validate the actual TrueConf binary name in your build and expect to also check Scheduled Tasks (DeviceProcessEvents on schtasks.exe) as an alternate persistence vector.

> [1] TrueConf Server Flaws Exploited to Replace Client Installers with PhantomCore — https://thehackernews.com/2026/08/head-mare-exploits-trueconf-flaws-to.html

### 2026-08-11

*Generated 2026-08-11 14:32 UTC · model `claude-sonnet-5`*

_Lint: 6 KQL block(s) — structural checks passed. All queries are CANDIDATES; validate before use._

#### TrueConf Installer Delivering Head Mare Backdoors (PhantomCore/PhantomGraph)
- **Actor / Campaign:** Head Mare
- **MITRE ATT&CK:** T1195.002 — Supply Chain Compromise: Compromise Software Supply Chain
- **Data source:** DeviceProcessEvents
- **Source:** [3][11]

```kql
// Head Mare delivers trojanized TrueConf installers via a compromised/unpatched TrueConf server.
// Hunt for TrueConf-branded installer/client binaries spawning shells or scripting hosts — atypical for a video-conferencing client.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName has_any ("TrueConf", "trueconf") 
    or FileName has_any ("TrueConf", "trueconf")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","rundll32.exe","mshta.exe","regsvr32.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, AccountName
| take 100
```

*Note:* Legitimate TrueConf updaters may briefly touch the filesystem; validate against known-good installer hash/signature and correlate with TrueConf server exposure/patch level before escalating.

#### Suspicious Outbound Connections from TrueConf Client/Server Processes
- **Actor / Campaign:** Head Mare
- **MITRE ATT&CK:** T1210 — Exploitation of Remote Services / T1071 — Application Layer Protocol (C2)
- **Data source:** DeviceNetworkEvents
- **Source:** [3][11]

```kql
// Look for TrueConf server/client processes initiating unexpected outbound connections
// following exploitation of the reported unpatched TrueConf server vulnerability chain.
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName has_any ("TrueConf", "trueconf", "TrueConfServer")
| where RemotePort in (80, 443, 8080, 8443) or RemotePort !in (80,443)
| where isnotempty(RemoteIP)
| summarize ConnCount = count(), Ports = make_set(RemotePort), RemoteIPs = make_set(RemoteIP) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
| where ConnCount > 5
| take 100
```

*Note:* No specific C2 IOCs were published; this is a coarse volumetric heuristic — tune baseline connection counts per environment and pivot on RemoteIP reputation/geolocation.

#### StormEncryptor Ransomware — Mass File Renaming to .encrypted
- **Actor / Campaign:** Storm-1175 (former Medusa affiliate)
- **MITRE ATT&CK:** T1486 — Data Encrypted for Impact
- **Data source:** DeviceFileEvents
- **Source:** [7][8]

```kql
// StormEncryptor (C++, Storm-1175) appends the .encrypted extension to encrypted files.
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName endswith ".encrypted"
| summarize FilesTouched = count(), Folders = make_set(FolderPath, 20) by DeviceId, DeviceName, bin(Timestamp, 5m)
| where FilesTouched > 30
| order by FilesTouched desc
| take 100
```

*Note:* High-volume rename/write bursts ending in `.encrypted` are a strong ransomware indicator, but confirm the extension against final reporting/IR notes — some backup or archival tools use similar suffixes.

#### Possible N-central RMM Abuse Preceding StormEncryptor Deployment
- **Actor / Campaign:** Storm-1175
- **MITRE ATT&CK:** T1219 — Remote Access Software / T1059 — Command and Scripting Interpreter
- **Data source:** DeviceProcessEvents
- **Source:** [8]

```kql
// Microsoft assesses StormEncryptor was likely delivered via an N-central (N-able) RMM flaw.
// Flag N-central agent processes spawning shells, script hosts, or LOLBins.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName has_any ("ncentral", "N-central", "BASupSrvc", "winagent")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","certutil.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, AccountName
| take 100
```

*Note:* Legitimate RMM scripting is common; baseline expected automation scripts for your N-central deployment and alert only on deviations (unusual command lines, new hosts, off-hours execution).

#### WordPress Admin User Created Immediately After Remote JSON Feed Fetch (BdThemes-style Supply Chain)
- **Actor / Campaign:** Unattributed (BdThemes plugin supply-chain compromise)
- **MITRE ATT&CK:** T1195.002 — Supply Chain Compromise / T1136.001 — Create Account: Local Account
- **Data source:** W3CIISLog (or equivalent web server log table ingested via AMA)
- **Source:** [5][6]

```kql
// BdThemes plugins fetched a poisoned remote JSON feed that silently created rogue wp-admin accounts
// in the admin's browser session — no repo files were modified, so hunt web-server access logs instead.
W3CIISLog
| where TimeGenerated > ago(14d)
| where csUriStem has_any ("wp-admin/user-new.php", "wp-admin/admin-ajax.php")
| where csMethod == "POST"
| summarize RequestCount = count(), URIs = make_set(csUriStem) by cIP, sSiteName, bin(TimeGenerated, 10m)
| where RequestCount > 0
| join kind=inner (
    W3CIISLog
    | where TimeGenerated > ago(14d)
    | where csUriStem has "wp-json" or csUriStem has ".json"
) on sSiteName
| project TimeGenerated, cIP, sSiteName, csUriStem, RequestCount
| take 100
```

*Note:* This is a heuristic scaffold — column names/log source vary widely by hosting stack (IIS vs Apache vs managed WAF logs). Prefer correlating with WordPress `wp_users`/`wp_usermeta` audit logs or a security plugin's activity log if available; treat as a starting point for tuning, not a ready-made rule.

#### Local/Offline LLM Runtime Execution on Endpoints (Kimsuky Offline AI Stack Heuristic)
- **Actor / Campaign:** Kimsuky
- **MITRE ATT&CK:** T1588.007 — Obtain Capabilities: Artificial Intelligence / T1105 — Ingress Tool Transfer
- **Data source:** DeviceProcessEvents, DeviceFileEvents
- **Source:** [10]

```kql
// Genians reports Kimsuky now runs AI models offline on its own infrastructure and builds AI capability
// into malware/phishing tooling. No IOCs published; hunt for unexpected local LLM runtimes on endpoints
// (dev/test hosts, RAG/document-search tools) that could indicate staging of such capability.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName has_any ("ollama.exe","llama-server.exe","llama.cpp","gpt4all.exe","text-generation-webui","lmstudio.exe","koboldcpp.exe")
| where InitiatingProcessFileName !in~ ("explorer.exe") // exclude obvious deliberate user launches; tune per org
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, InitiatingProcessFileName, ProcessCommandLine
| take 100
```

*Note:* Purely behavioral/heuristic — legitimate AI/dev workstations will trigger this; scope to servers, non-dev endpoints, or hosts with no business justification for local LLM tooling, and correlate with known Kimsuky delivery vectors (spearphishing, LNK/HWP lures) when investigating hits.

> [3] Head Mare APT is exploiting vulnerabilities in an unpatched TrueConf server to deliver PhantomCore and PhantomGraph to video conference participants — https://securelist.com/tr/head-mare-targets-trueconf-server-with-phantomcore/120988/
> [5] BdThemes Supply Chain Attack Poisons JSON to Create Rogue WordPress Admins — https://thehackernews.com/2026/08/bdthemes-supply-chain-attack-poisons.html
> [6] BdThemes plugins supply-chain hack creates rogue WordPress admins — https://www.bleepingcomputer.com/news/security/bdthemes-plugins-supply-chain-hack-creates-rogue-wordpress-admins/
> [7] New StormEncryptor ransomware used by former Medusa affiliate — https://www.bleepingcomputer.com/news/security/new-stormencryptor-ransomware-used-by-former-medusa-affiliate/
> [8] China-Linked Hackers Deploy New StormEncryptor Ransomware, Likely via N-central Flaw — https://thehackernews.com/2026/08/china-linked-hackers-deploy-new.html
> [10] Kimsuky Builds Offline AI Stack to Boost Phishing and Automate Malware Development — https://thehackernews.com/2026/08/kimsuky-builds-offline-ai-stack-that.html
> [11] TrueConf Server Flaws Exploited to Replace Client Installers with PhantomCore — https://thehackernews.com/2026/08/head-mare-exploits-trueconf-flaws-to.html

### 2026-08-12

*Generated 2026-08-12 14:33 UTC · model `claude-sonnet-5`*

_Lint: 9 KQL block(s) — query 9: unbalanced '()'. All queries are CANDIDATES; validate before use._

#### Suspicious SYSTEM-level process spawn following Defender component activity (ShieldBreak / RoguePlanet)
- **Actor / Campaign:** Nightmare Eclipse (Chaotic Eclipse / INFINITE NIGHTMARE / MSNightmare)
- **MITRE ATT&CK:** T1068 — Exploitation for Privilege Escalation
- **Data source:** DeviceProcessEvents
- **Source:** [1][5]

```kql
// Behavioral: ShieldBreak is a PoC patch bypass for CVE-2026-50656 (RoguePlanet) that elevates
// arbitrary processes to SYSTEM via a Defender component. No public IOCs (file names/hashes) exist yet,
// so hunt for low-privilege processes suddenly spawning SYSTEM children shortly after touching
// Defender/MsMpEng-related binaries or services.
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("MsMpEng.exe", "MpCmdRun.exe", "NisSrv.exe", "MsSense.exe")
   or ProcessCommandLine has_any ("MsMpEng", "RoguePlanet", "ShieldBreak")
| where AccountName has_any ("system", "SYSTEM") or ProcessTokenElevation == "TokenElevationTypeFull"
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName
| take 100
```

*Note:* No confirmed IOCs are public for ShieldBreak; this is a coarse behavioral hunt to be tuned once a PoC/binary sample or specific technique (e.g., named pipe, driver name) is disclosed. Expect noise from legitimate Defender maintenance tasks — validate against AV/EDR update windows.

#### VMware vCenter directory traversal exploitation attempts (CVE-2026-59310)
- **Actor / Campaign:** unattributed (reported by QUIRSO)
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application
- **Data source:** CommonSecurityLog, DeviceNetworkEvents
- **Source:** [2]

```kql
// Hunt for directory-traversal patterns aimed at vCenter server (CVE-2026-59310, CVSS 9.8).
// Assumes vCenter access/HTTP logs forwarded via CEF/Syslog into CommonSecurityLog.
CommonSecurityLog
| where TimeGenerated > ago(14d)
| where DeviceVendor has "VMware" or Application has "vcenter"
| where RequestURL has_any ("../", "..%2f", "..%252f", "%2e%2e%2f")
| project TimeGenerated, DeviceVendor, SourceIP, DestinationIP, RequestURL, DeviceAction
| take 100
```

*Note:* Table/field names depend on how vCenter logs are ingested (CEF vs custom connector); adjust `Application`/`RequestURL` mapping. Also monitor for post-exploitation persistence such as new local accounts or SSH key changes on vCenter appliances.

#### Credential file access followed by outbound connection after LiteLLM/pip install (supply-chain credential theft)
- **Actor / Campaign:** unattributed (Trivy-linked PyPI compromise, reported by CloudSEK)
- **MITRE ATT&CK:** T1195.002 — Supply Chain Compromise: Compromised Software Dependencies; T1552.001 — Credentials In Files
- **Data source:** DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents
- **Source:** [3]

```kql
// Behavioral hunt: malicious LiteLLM PyPI releases harvested cloud/SSH/K8s/DB secrets shortly after
// package install (~40 min exposure window on PyPI, March incident). No hashes/IOCs published.
let cred_paths = dynamic([".aws/credentials", ".ssh/id_rsa", ".kube/config", ".docker/config.json"]);
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any (cred_paths)
| where InitiatingProcessFileName has_any ("python", "python3", "pip", "pip3")
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName has_any ("python", "python3", "pip", "pip3")
) on DeviceId
| where DeviceNetworkEvents.Timestamp - DeviceFileEvents.Timestamp between (0min .. 10min)
| project DeviceFileEvents.Timestamp, DeviceName, FolderPath, RemoteIP, RemoteUrl, InitiatingProcessCommandLine
| take 100
```

*Note:* Highly heuristic — legitimate DevOps automation (CI/CD pipelines) also reads credential files then makes network calls; tune to exclude known CI runners and pin to the March 2026 exposure window if timestamps are available.

#### Trojanized WireGuard client execution from fake job-offer lures (Sandworm / UAC-0145)
- **Actor / Campaign:** Sandworm (APT44) / UAC-0145
- **MITRE ATT&CK:** T1204.002 — User Execution: Malicious File; T1071.001 — Application Layer Protocol: Web Protocols; T1059.003 — Command and Scripting Interpreter: Windows Command Shell
- **Data source:** DeviceProcessEvents, DeviceFileEvents, EmailEvents
- **Source:** [7][9]

```kql
// Sandworm subgroup UAC-0145 lures IT admins/sysadmins with fake job interviews to install a
// trojanized WireGuard VPN client capable of executing arbitrary commands.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName has_any ("wireguard", "wg-quick", "wireguard-installer")
| where InitiatingProcessFileName has_any ("winword.exe", "outlook.exe", "chrome.exe", "msedge.exe", "explorer.exe")
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(30d)
    | where FileName in~ ("cmd.exe", "powershell.exe")
) on DeviceId
| where DeviceProcessEvents1.Timestamp - DeviceProcessEvents.Timestamp between (0min .. 15min)
| where DeviceProcessEvents1.InitiatingProcessFileName has_any ("wireguard", "wg-quick")
| project DeviceProcessEvents.Timestamp, DeviceName, FileName, ProcessCommandLine=DeviceProcessEvents1.ProcessCommandLine
| take 100
```

*Note:* No file hashes/domains were published in the source; this hunts the behavioral pattern (VPN installer spawning a command shell). Expect false positives from legitimate WireGuard deployments that use post-install scripts — validate against known-good installer hashes if available.

#### Recruiter-themed phishing attachments delivering VPN/backdoor installers
- **Actor / Campaign:** Sandworm / UAC-0145
- **MITRE ATT&CK:** T1566.001 — Phishing: Spearphishing Attachment
- **Data source:** EmailEvents, EmailAttachmentInfo
- **Source:** [7][9]

```kql
// CERT-UA reports fake recruiter/job-interview themed emails targeting IT/sysadmin staff to deliver
// a malicious VPN client. Hunt for job-offer themed subjects with executable/archive attachments.
EmailEvents
| where Timestamp > ago(30d)
| where SenderFromAddress !endswith "@yourcorp.com" // exclude legit internal HR
| where Subject has_any ("job offer", "interview", "vacancy", "career opportunity", "position")
| join kind=inner (
    EmailAttachmentInfo
    | where FileType in~ ("exe", "zip", "rar", "msi", "iso")
) on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, FileName, FileType
| take 100
```

*Note:* Tune subject keyword list to local language variants (Ukrainian/Russian) and integrate with attachment sandboxing; this is a coarse lure-theme hunt, not a malware signature.

#### TrueConf server exploitation delivering PhantomCore/PhantomGraph backdoor (Head Mare)
- **Actor / Campaign:** Head Mare APT
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application; T1204.002 — User Execution: Malicious File
- **Data source:** DeviceProcessEvents, DeviceNetworkEvents
- **Source:** [15]

```kql
// Head Mare exploits an unpatched TrueConf video conferencing server to push trojanized TrueConf
// installers delivering PhantomCore/PhantomGraph backdoors to meeting participants.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName has_any ("trueconf", "TrueConf_Setup", "trueconf-installer")
| where InitiatingProcessFileName has_any ("chrome.exe", "msedge.exe", "firefox.exe", "explorer.exe")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessCommandLine
| take 100
```

```kql
// Complement: look for post-install beaconing shortly after TrueConf install (potential PhantomCore/PhantomGraph C2).
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName has_any ("trueconf", "TrueConf")
| where RemotePort in (443, 8443, 8080) 
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort
| take 100
```

*Note:* No hashes/domains were disclosed in the summary; these are process/network-lineage heuristics tied to the "TrueConf installer" delivery vector. Validate installer file hash/signature against Kaspersky's IOC list once published.

#### Windows AFD/WinSock use-after-free exploitation attempt (CVE-2026-68820, KEV)
- **Actor / Campaign:** unattributed (actively exploited, in CISA KEV)
- **MITRE ATT&CK:** T1068 — Exploitation for Privilege Escalation
- **Data source:** DeviceProcessEvents, DeviceImageLoadEvents
- **Source:** [8][10][11][17][20]

```kql
// CVE-2026-68820: UAF in afd.sys (Ancillary Function Driver for WinSock), used for local privilege
// escalation to SYSTEM. Hunt for unusual non-system processes loading afd.sys followed by a
// SYSTEM-level child process (classic LPE pattern).
DeviceImageLoadEvents
| where Timestamp > ago(14d)
| where FileName =~ "afd.sys"
| where InitiatingProcessFileName !in~ ("services.exe", "svchost.exe", "System", "lsass.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessId, FolderPath
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where AccountName has "system"
) on DeviceId
| where DeviceProcessEvents.Timestamp - Timestamp between (0min .. 5min)
| project Timestamp, DeviceName, InitiatingProcessFileName, ElevatedProcess=DeviceProcessEvents.FileName, DeviceProcessEvents.ProcessCommandLine
| take 100
```

*Note:* This is a generic LPE-via-driver pattern; afd.sys is loaded by many legitimate networking components, so expect false positives — prioritize alerts where the initiating process is unsigned, unusual, or user-writable-path based.

#### Metabase SQL injection exploitation attempt (CVE-2026-72898, KEV)
- **Actor / Campaign:** unattributed (actively exploited, in CISA KEV)
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application; T1552 — Unsecured Credentials (post-exploit config/credential theft)
- **Data source:** CommonSecurityLog, AzureDiagnostics (web app logs)
- **Source:** [17][21]

```kql
// CVE-2026-72898: unauthenticated SQLi in Metabase leading to admin takeover.
// Hunt web-tier logs for SQLi patterns aimed at Metabase API endpoints.
CommonSecurityLog
| where TimeGenerated > ago(14d)
| where RequestURL has "metabase" or RequestURL has_any ("/api/card", "/api/dataset", "/api/setting")
| where RequestURL has_any ("union select", "or 1=1", "--", "waitfor delay", "sleep(")
| project TimeGenerated, SourceIP, DestinationIP, RequestURL, DeviceAction
| take 100
```

*Note:* Adjust field/table mapping to your actual reverse-proxy or WAF log source (e.g., AzureDiagnostics for App Gateway/Front Door); this is a generic SQLi-pattern hunt, not Metabase-specific payload matching. Follow up any hits with a check for new/unexpected admin accounts in Metabase.

> [1] New Microsoft Defender 'ShieldBreak' zero-day grants SYSTEM privileges — https://www.bleepingcomputer.com/news/security/new-microsoft-defender-shieldbreak-zero-day-grants-system-privileges/
> [2] Attackers Exploit VMware vCenter Vulnerability to Gain Persistent Remote Access — https://thehackernews.com/2026/08/attackers-exploit-vmware-vcenter.html
> [3] Malicious LiteLLM Releases Tied to Trivy Hack May Have Exposed 2,100+ Organizations — https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html
> [5] ShieldBreak Zero-Day PoC Claims Microsoft Defender Patch Bypass With SYSTEM Access — https://thehackernews.com/2026/08/shieldbreak-zero-day-poc-claims.html
> [7] Sandworm hackers target IT pros with trojanized WireGuard VPN client — https://www.bleepingcomputer.com/news/security/sandworm-hackers-target-it-pros-with-trojanized-wireguard-vpn-client/
> [8] Microsoft Patches 398 Flaws Including a Windows Driver Zero-Day Under Active Attack — https://thehackernews.com/2026/08/microsoft-patches-398-flaws-including.html
> [9] Sandworm-Linked UAC-0145 Uses Fake Job Interviews to Push VPN That Can Run Commands — https://thehackernews.com/2026/08/sandworm-linked-uac-0145-uses-fake-job.html
> [10] Microsoft August 2026 Patch Tuesday fixes 400 flaws, 3 zero-days — https://www.bleepingcomputer.com/news/microsoft/microsoft-august-2026-patch-tuesday-fixes-400-flaws-3-zero-days/
> [11] Microsoft Patch Tuesday August 2026 — https://isc.sans.edu/diary/rss/33236
> [15] Head Mare APT is exploiting vulnerabilities in an unpatched TrueConf server to deliver PhantomCore and PhantomGraph — https://securelist.com/tr/head-mare-targets-trueconf-server-with-phantomcore/120988/
> [17] CISA Adds Three Known Exploited Vulnerabilities to Catalog — https://www.cisa.gov/news-events/alerts/2026/08/11/cisa-adds-three-known-exploited-vulnerabilities-catalog
> [20] CVE-2026-68820 — Microsoft Windows Ancillary Function Driver for WinSock — https://nvd.nist.gov/vuln/detail/CVE-2026-68820
> [21] CVE-2026-72898 — Metabase SQL Injection Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2026-72898

### 2026-08-13

*Generated 2026-08-13 14:34 UTC · model `claude-sonnet-5`*

_Lint: 8 KQL block(s) — structural checks passed. All queries are CANDIDATES; validate before use._

#### Suspicious Telegram tdata Access/Exfiltration (Armored Likho Still Toolkit)
- **Actor / Campaign:** Armored Likho / Still Toolkit
- **MITRE ATT&CK:** T1005 — Data from Local System / T1560 — Archive Collected Data
- **Data source:** DeviceFileEvents, DeviceProcessEvents
- **Source:** [1]

```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where FolderPath has @"\Telegram Desktop\tdata"
   or FolderPath has @"\AppData\Roaming\Telegram Desktop"
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where InitiatingProcessFileName !in~ ("Telegram.exe","telegram.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, FileName, FolderPath, ActionType
| take 100
```

*Note:* Flags non-Telegram processes touching Telegram session/data folders (a hallmark of Telegram-data-stealing toolkits like Still Toolkit). Tune out legitimate backup/sync tools; requires correlation with process reputation.

#### Fundraising/Charity-Themed Lure Leading to Self-Extracting Archive Execution
- **Actor / Campaign:** Armored Likho / Still Toolkit
- **MITRE ATT&CK:** T1566.001 — Phishing: Spearphishing Attachment; T1204.002 — User Execution: Malicious File
- **Data source:** EmailEvents, DeviceProcessEvents
- **Source:** [1]

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName has_any ("winrar.exe","7z.exe","7zG.exe") 
   or FileName has_any (".sfx.exe", "self-extract")
| where ProcessCommandLine has_any ("charity","fund","donation","fundraising","благотвор","сбор")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| take 100
```

*Note:* Heuristic string match on charity/fundraising themes seen in the campaign lure; expect low volume but tune keyword list to observed language localization once samples are shared publicly.

#### SharePoint w3wp.exe Spawning Command Interpreters (Possible CVE-2026-55040 Exploitation)
- **Actor / Campaign:** Unattributed — post-PoC mass exploitation of SharePoint auth bypass
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application
- **Data source:** DeviceProcessEvents
- **Source:** [2]

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where InitiatingProcessCommandLine has "SharePoint" or InitiatingProcessFolderPath has @"\SharePoint"
| where FileName in~ ("cmd.exe","powershell.exe","powershell_ise.exe","cscript.exe","wscript.exe","w3wp.exe")
| where ProcessCommandLine has_any ("whoami","IEX","DownloadString","-enc","Invoke-Expression","Add-Type")
| project Timestamp, DeviceName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, AccountName
| take 100
```

*Note:* CVE-2026-55040 is an auth-bypass, so exploitation typically leads to webshell drop/command execution under the SharePoint app pool identity; verify against known ToolShell-style aspx drops (e.g., spinstall*.aspx) via DeviceFileEvents on the LAYOUTS folder as a companion query. No public IOCs in the source, so this is behavioral.

#### SharePoint LAYOUTS Folder Web Shell Drop
- **Actor / Campaign:** Unattributed — post-PoC mass exploitation of SharePoint auth bypass
- **MITRE ATT&CK:** T1505.003 — Server Software Component: Web Shell
- **Data source:** DeviceFileEvents
- **Source:** [2]

```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FolderPath has @"\Microsoft Shared\Web Server Extensions" and FolderPath has @"\LAYOUTS"
| where FileName endswith ".aspx"
| where ActionType == "FileCreated"
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessAccountName
| take 100
```

*Note:* New .aspx files created in the LAYOUTS directory outside of patch/deployment windows is a strong indicator of webshell staging post-exploitation; validate against change-management records to reduce FPs.

#### SYSTEM-Level Process Spawned Shortly After Windows Privilege Escalation (Lazarus / Operation Dream Job, CVE-2026-68820)
- **Actor / Campaign:** Lazarus Group — Operation Dream Job
- **MITRE ATT&CK:** T1068 — Exploitation for Privilege Escalation; T1543.003 — Create or Modify System Process: Windows Service
- **Data source:** DeviceProcessEvents, DeviceEvents
- **Source:** [3],[4]

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where AccountName has_any ("SYSTEM","LOCAL SERVICE","NETWORK SERVICE")
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powershell.exe","rundll32.exe","mshta.exe","cscript.exe")
| where FileName in~ ("cmd.exe","powershell.exe","rundll32.exe","svchost.exe","regsvr32.exe")
| where isnotempty(InitiatingProcessParentFileName)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| take 100
```

*Note:* Highly heuristic — looks for office/scripting processes that unexpectedly spawn SYSTEM-level children, consistent with local privilege escalation to deploy a new backdoor observed in defense/aerospace targeting (France, Germany, Brazil, India). No file/hash IOCs published yet; correlate with new/rare parent-child chains and lure documents referencing job offers.

#### Job-Offer Lure Document Chain (ISO/LNK Execution) — Operation Dream Job Pattern
- **Actor / Campaign:** Lazarus Group — Operation Dream Job
- **MITRE ATT&CK:** T1566.001 — Spearphishing Attachment; T1204.002 — User Execution
- **Data source:** DeviceProcessEvents, DeviceFileEvents
- **Source:** [3],[4]

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("explorer.exe")
| where FileName in~ ("cmd.exe","powershell.exe","mshta.exe","wscript.exe","rundll32.exe")
| where InitiatingProcessCommandLine has_any (".iso",".lnk",".img")
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| take 100
```

*Note:* Operation Dream Job historically relies on ISO/LNK-based delivery from recruiting-themed lures; this is a generic pattern-match to surface candidate chains, since no file names/hashes were published for this specific zero-day wave.

#### Anomalous Child Process from Microsoft Defender Binaries (Possible ShieldBreak / CVE Exploitation)
- **Actor / Campaign:** Nightmare Eclipse — ShieldBreak Defender zero-day
- **MITRE ATT&CK:** T1068 — Exploitation for Privilege Escalation
- **Data source:** DeviceProcessEvents
- **Source:** [5]

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("MsMpEng.exe","MpCmdRun.exe","NisSrv.exe","MpDefenderCoreService.exe")
| where FileName !in~ ("MsMpEng.exe","MpCmdRun.exe","NisSrv.exe")
| where AccountName has "SYSTEM"
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName
| take 100
```

*Note:* Defender core services rarely spawn arbitrary child processes; any unexpected child process running as SYSTEM warrants investigation as a candidate for the newly disclosed "ShieldBreak" local-privesc exploit. Baseline against normal Defender scan/update activity to cut noise.

#### Directory-Traversal Style Requests to VMware vCenter (CVE-2026-59310)
- **Actor / Campaign:** Unattributed — active exploitation per QUIRSO
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application; T1133 — External Remote Services
- **Data source:** CommonSecurityLog, Syslog, DeviceNetworkEvents
- **Source:** [6]

```kql
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceProduct has_any ("vCenter","VMware") or Activity has "vsphere"
| where RequestURL has_any ("..%2f", "../", "..%5c", "..\\")
| project TimeGenerated, DeviceName, SourceIP, DestinationIP, RequestURL, Activity
| take 100
```

*Note:* Query assumes vCenter access/HTTP logs are forwarded to Sentinel via CEF/Syslog; adjust `DeviceProduct`/field names to your actual log source connector (e.g., Apache/Envoy proxy logs on vCenter appliance). No IOC list was published, so match is purely on the CVE's directory-traversal technique; expect tuning against legitimate encoded-path traffic.

> [1] Armored Likho expands its cyber-espionage toolkit — https://securelist.com/armored-likho-still-toolkit/121033/
> [2] Attackers Exploit SharePoint Authentication Bypass After Public PoC Release — https://thehackernews.com/2026/08/attackers-exploit-sharepoint.html
> [3] Lazarus Exploits Windows Zero-Day to Gain SYSTEM Access and Deploy Backdoor — https://thehackernews.com/2026/08/lazarus-exploits-windows-zero-day-to.html
> [4] Lazarus hackers exploited Windows zero-day to target defense firms — https://www.bleepingcomputer.com/news/security/lazarus-hackers-exploited-windows-zero-day-to-target-defense-firms/
> [5] New Microsoft Defender 'ShieldBreak' zero-day grants SYSTEM privileges — https://www.bleepingcomputer.com/news/security/new-microsoft-defender-shieldbreak-zero-day-grants-system-privileges/
> [6] Attackers Exploit VMware vCenter Vulnerability to Gain Persistent Remote Access — https://thehackernews.com/2026/08/attackers-exploit-vmware-vcenter.html

### 2026-08-14

*Generated 2026-08-14 14:20 UTC · model `claude-sonnet-5`*

_Lint: 6 KQL block(s) — structural checks passed. All queries are CANDIDATES; validate before use._

#### Suspicious kernel driver service creation (possible CoolClient rootkit)
- **Actor / Campaign:** HoneyMyte
- **MITRE ATT&CK:** T1014 — Rootkit / T1543.003 — Create or Modify System Process: Windows Service
- **Data source:** DeviceRegistryEvents, DeviceProcessEvents
- **Source:** [1]

```kql
// New kernel-mode driver service registered outside standard driver install flow (e.g. via sc.exe/reg.exe, not pnputil/msiexec)
DeviceRegistryEvents
| where Timestamp > ago(14d)
| where RegistryKey has @"SYSTEM\CurrentControlSet\Services\"
  and RegistryValueName =~ "Type"
  and RegistryValueData in ("1","2") // SERVICE_KERNEL_DRIVER / SERVICE_FILE_SYSTEM_DRIVER
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where FileName in~ ("sc.exe","reg.exe")
    | where ProcessCommandLine has_any ("create", "add") and ProcessCommandLine has "type= kernel"
) on DeviceId
| project Timestamp, DeviceId, RegistryKey, InitiatingProcessAccountName, ProcessCommandLine
| take 100
```

*Note:* Legitimate driver installs (AV/EDR agents, VPN clients) will also trigger this; baseline known driver publishers and filter on unsigned or newly-seen driver names/paths before alerting.

#### Unsigned .sys file dropped to drivers folder by non-installer process
- **Actor / Campaign:** HoneyMyte
- **MITRE ATT&CK:** T1014 — Rootkit, T1027 — Obfuscated Files or Information
- **Data source:** DeviceFileEvents
- **Source:** [1]

```kql
DeviceFileEvents
| where Timestamp > ago(14d)
| where FolderPath has @"\Windows\System32\drivers\"
| where FileName endswith ".sys"
| where InitiatingProcessFileName !in~ ("TrustedInstaller.exe","MsiExec.exe","pnputil.exe","drvinst.exe","svchost.exe")
| where isnotempty(SHA256)
| project Timestamp, DeviceId, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessAccountName, SHA256
| take 100
```

*Note:* No hashes/names for the new CoolClient driver were published; hunt is behavioral and needs SHA256 reputation/signing checks to cut noise from legitimate third-party drivers.

#### Webshell-style child process spawned from webmail/IIS worker process
- **Actor / Campaign:** Jewelbug
- **MITRE ATT&CK:** T1505.003 — Server Software Component: Web Shell, T1071.001 — Web Protocols
- **Data source:** DeviceProcessEvents
- **Source:** [2]

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("w3wp.exe","umworkerprocess.exe","MSExchangeMailboxAssistants.exe","hostcontrollerservice.exe")
| where FileName in~ ("cmd.exe","powershell.exe","cscript.exe","wscript.exe","certutil.exe","whoami.exe","net.exe")
| project Timestamp, DeviceId, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName
| take 100
```

*Note:* Common webshell-post-compromise pattern for OWA/Exchange/webmail compromises; tune process/account allow-lists for legitimate admin scripts running under IIS app pools.

#### Post-compromise outbound connection to cryptocurrency-related infrastructure from server tier
- **Actor / Campaign:** Jewelbug
- **MITRE ATT&CK:** T1071 — Application Layer Protocol, T1657 — Financial Theft
- **Data source:** DeviceNetworkEvents
- **Source:** [2]

```kql
// No specific crypto-fraud IOCs published; heuristic for webmail/edge servers making outbound calls to wallet/exchange-style domains
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("w3wp.exe","MSExchangeMailboxAssistants.exe","hostcontrollerservice.exe")
| where RemoteUrl has_any ("wallet","exchange","swap","binance","coin","crypto") // heuristic keyword match, tune per environment
| project Timestamp, DeviceId, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| take 100
```

*Note:* Highly heuristic — no confirmed domains/wallets in source; expect false positives from legitimate finance apps, use as a pivot alongside webshell/process alerts, not standalone.

#### Registry hive load/unload from non-standard process (possible LegacyHive exploitation)
- **Actor / Campaign:** unattributed (LegacyHive zero-day, CVE not yet numbered in source)
- **MITRE ATT&CK:** T1068 — Exploitation for Privilege Escalation, T1112 — Modify Registry
- **Data source:** DeviceProcessEvents
- **Source:** [3]

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "reg.exe"
| where ProcessCommandLine has_any ("load","unload")
| where InitiatingProcessFileName !in~ ("services.exe","userinit.exe","winlogon.exe")
| project Timestamp, DeviceId, AccountName, ProcessCommandLine, InitiatingProcessFileName
| take 100
```

*Note:* "LegacyHive" details are limited to a patched Windows zero-day; this looks for anomalous manual hive load/unload activity that could indicate exploitation attempts pre/post-patch — expect FPs from legitimate profile/backup tooling, tune against baseline admin scripts.

#### Unexpected crash of registry/session subsystem processes (possible LegacyHive exploit attempt)
- **Actor / Campaign:** unattributed (LegacyHive)
- **MITRE ATT&CK:** T1499 — Endpoint Denial of Service / T1068 — Exploitation for Privilege Escalation
- **Data source:** DeviceEvents (or SecurityEvent for Application/System crash logs, Event ID 1000/1001)
- **Source:** [3]

```kql
SecurityEvent
| where TimeGenerated > ago(14d)
| where EventID in (1000,1001) // Application Error / WER report
| where Process has_any ("lsass.exe","services.exe","svchost.exe","winlogon.exe")
| project TimeGenerated, Computer, Process, EventID, RenderedDescription
| take 100
```

*Note:* Application/system event log crash telemetry may need to be forwarded via AMA/Log Analytics; correlate crash spikes on patched vs. unpatched systems around the July 2026 Patch Tuesday timeframe to spot pre-patch exploitation.

> [1] APT group HoneyMyte upgrades CoolClient: the backdoor gets a kernel-level Windows rootkit — https://securelist.com/honeymyte-coolclient-driver-rootkit/121028/
> [2] Hackers breach govt webmail while running parallel crypto fraud — https://www.bleepingcomputer.com/news/security/hackers-breach-govt-webmail-while-running-parallel-crypto-fraud/
> [3] Microsoft patches LegacyHive Windows zero-day vulnerability — https://www.bleepingcomputer.com/news/microsoft/microsoft-patches-legacyhive-windows-zero-day-vulnerability/

### 2026-08-15

*Generated 2026-08-15 13:43 UTC · model `claude-sonnet-5`*

_Lint: 5 KQL block(s) — structural checks passed. All queries are CANDIDATES; validate before use._

_No concrete IOCs (hashes, file names, paths, C2 domains/IPs) were published in this item, so the detections below are behavioral, built around the described kernel-rootkit driver capability of CoolClient (HoneyMyte)._

#### Kernel driver service creation via command-line tools
- **Actor / Campaign:** HoneyMyte / CoolClient
- **MITRE ATT&CK:** T1543.003 — Create or Modify System Process: Windows Service
- **Data source:** DeviceProcessEvents
- **Source:** [1]

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("sc.exe","reg.exe","rundll32.exe","cmd.exe","powershell.exe")
| where ProcessCommandLine has_any ("create", "New-Service") 
    and ProcessCommandLine has_any ("type= kernel","type=kernel","binPath")
| where ProcessCommandLine has_any (".sys")
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
| take 100
```

*Note:* Kernel-mode driver services created outside of legitimate software installers are rare; validate against known EDR/AV/hardware driver installs and baseline before alerting.

#### Suspicious unsigned kernel driver image load
- **Actor / Campaign:** HoneyMyte / CoolClient
- **MITRE ATT&CK:** T1014 — Rootkit
- **Data source:** DeviceImageLoadEvents, DeviceFileCertificateInfo
- **Source:** [1]

```kql
DeviceImageLoadEvents
| where Timestamp > ago(30d)
| where FileName endswith ".sys"
| where FolderPath has_any (@"\Windows\Temp\", @"\AppData\", @"\ProgramData\", @"\Users\Public\")
| join kind=leftouter (
    DeviceFileCertificateInfo
    | project SHA1, IsSigned, Signer, Issuer
) on SHA1
| where IsSigned == false or isempty(Signer)
| project Timestamp, DeviceName, FileName, FolderPath, SHA1, IsSigned, Signer
| take 100
```

*Note:* Legitimate drivers are almost always signed and load from `\Windows\System32\drivers\`; unsigned .sys files loading from user-writable paths is a strong rootkit indicator but check for dev/test-signed internal software first.

#### Registry persistence for kernel driver service (Type 1)
- **Actor / Campaign:** HoneyMyte / CoolClient
- **MITRE ATT&CK:** T1547.006 — Boot or Logon Autostart Execution: Kernel Modules and Extensions
- **Data source:** DeviceRegistryEvents
- **Source:** [1]

```kql
DeviceRegistryEvents
| where Timestamp > ago(30d)
| where RegistryKey has @"SYSTEM\CurrentControlSet\Services\"
| where RegistryValueName =~ "Type"
| where RegistryValueData in ("1","0x1") // SERVICE_KERNEL_DRIVER
| project Timestamp, DeviceName, InitiatingProcessAccountName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName
| take 100
```

*Note:* High-volume table; correlate with newly created service names not previously seen in your environment and cross-reference with the driver-load and file-drop detections above to reduce noise.

#### Driver (.sys) file dropped outside standard driver directories
- **Actor / Campaign:** HoneyMyte / CoolClient
- **MITRE ATT&CK:** T1105 — Ingress Tool Transfer / T1014 — Rootkit
- **Data source:** DeviceFileEvents
- **Source:** [1]

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName endswith ".sys"
| where FolderPath !has @"\Windows\System32\drivers\"
| where FolderPath has_any (@"\Temp\", @"\AppData\", @"\ProgramData\", @"\Users\Public\", @"\Downloads\")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessAccountName, FileName, FolderPath, SHA256
| take 100
```

*Note:* Broadly catches any driver file drop outside default OS paths (which is unusual); pivot into process trees and network activity of the dropping process to confirm malicious intent versus legitimate hardware/vendor driver installers.

#### Process or artifact naming referencing CoolClient backdoor
- **Actor / Campaign:** HoneyMyte / CoolClient
- **MITRE ATT&CK:** T1027 — Obfuscated Files or Information / T1055 — Process Injection (rootkit-hidden process)
- **Data source:** DeviceProcessEvents, DeviceFileEvents
- **Source:** [1]

```kql
union DeviceProcessEvents, DeviceFileEvents
| where Timestamp > ago(30d)
| where FileName has "coolclient" or FolderPath has "coolclient" or ProcessCommandLine has "coolclient"
| project Timestamp, DeviceName, FileName, FolderPath, ProcessCommandLine, SHA256
| take 100
```

*Note:* Speculative string match based only on the reported malware family name; the actual on-disk artifact naming used by CoolClient was not disclosed in this reporting, so treat any hits as low-confidence and pivot to full host triage.

> [1] APT group HoneyMyte upgrades CoolClient: the backdoor gets a kernel-level Windows rootkit — https://securelist.com/honeymyte-coolclient-driver-rootkit/121028/

### 2026-08-16

*Generated 2026-08-16 13:44 UTC · model `claude-sonnet-5`*

_Lint: no KQL blocks detected._

_No APT-relevant open-source items in the collection window; no detections generated._

### 2026-08-17

*Generated 2026-08-17 13:52 UTC · model `claude-sonnet-5`*

_Lint: 7 KQL block(s) — structural checks passed. All queries are CANDIDATES; validate before use._

#### Suspicious Linux payload download & execution consistent with Mirai-derived botnet (Evooo1Bot)
- **Actor / Campaign:** Evooo1Bot (unattributed, Mirai-derived)
- **MITRE ATT&CK:** T1105 — Ingress Tool Transfer
- **Data source:** DeviceProcessEvents
- **Source:** [1]

```kql
DeviceProcessEvents
| where Timestamp > ago(2d)
| where OSPlatform == "Linux" or DeviceName has_any ("router","gateway","cam","edge")
| where FileName in~ ("wget","curl","tftp","busybox")
| where ProcessCommandLine has_any ("/tmp/", "/var/tmp", "/dev/shm")
| where ProcessCommandLine has_any ("http://", "https://", "chmod +x", "chmod 777")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| take 100
```

*Note:* Generic Mirai-style "download to /tmp, chmod, execute" pattern — no confirmed sample hash/name was published, so this is behavioral and will need tuning to exclude legitimate IoT management or CI/CD scripts on Linux fleets.

#### Mass outbound telnet/SSH scanning indicative of Mirai-family propagation
- **Actor / Campaign:** Evooo1Bot (unattributed, Mirai-derived)
- **MITRE ATT&CK:** T1110 — Brute Force / T1595 — Active Scanning
- **Data source:** DeviceNetworkEvents
- **Source:** [1]

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemotePort in (23, 2323, 22)
| where OSPlatform == "Linux"
| summarize DistinctDestinations = dcount(RemoteIP), Attempts = count() by DeviceName, InitiatingProcessFileName, RemotePort, bin(Timestamp, 1h)
| where DistinctDestinations > 50
| order by DistinctDestinations desc
| take 100
```

*Note:* Flags edge/IoT-class devices making high-fan-out outbound connections to telnet/SSH ports, consistent with Mirai-style self-propagation and credential brute-forcing; tune thresholds to your network's baseline scanning behavior.

#### Unexpected child process or module load from Windows Defender engine (possible ShieldBreak exploitation, CVE-2026-69414)
- **Actor / Campaign:** unattributed ("ShieldBreak" zero-day)
- **MITRE ATT&CK:** T1211 — Exploitation for Defense Evasion / T1562.001 — Impair Defenses
- **Data source:** DeviceProcessEvents, DeviceImageLoadEvents
- **Source:** [2]

```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName =~ "MsMpEng.exe"
| where FileName !in~ ("MpCmdRun.exe", "MsMpEng.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName
| take 100
```

```kql
DeviceImageLoadEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName =~ "MsMpEng.exe"
| where isnotempty(SHA256) and FileName !endswith ".mdb" // filter known Defender content files
| summarize FirstSeen = min(Timestamp) by DeviceName, FileName, FolderPath, SHA256
| take 100
```

*Note:* No technical exploit details were published at time of writing; this hunts for anomalous behavior around the Defender engine process (crashes, unexpected children, unsigned/unknown module loads) as a proxy for exploitation attempts. Expect noise from legitimate Defender updates — validate hashes/signers before escalating.

#### Directory-traversal exploitation attempt against VMware vCenter (CVE-2026-59310)
- **Actor / Campaign:** Suspected China-nexus APT
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application
- **Data source:** CommonSecurityLog / Syslog (vCenter/vSphere web logs ingested via AMA or CEF connector)
- **Source:** [3]

```kql
CommonSecurityLog
| where TimeGenerated > ago(3d)
| where DeviceVendor has_any ("VMware","Broadcom") or Activity has_any ("vcenter","vsphere","vpxd")
| where RequestURL has_any ("../", "..%2f", "%2e%2e%2f", "..\\")
| project TimeGenerated, SourceIP, DestinationIP, RequestURL, DeviceAction, Activity
| take 100
```

*Note:* Requires vCenter/vSphere web access logs forwarded to Sentinel; adjust field names to your CEF/Syslog parser. High-fidelity if RequestURL parsing is reliable, but path-traversal strings can also appear in benign traffic — correlate with subsequent process/file activity below.

#### Post-exploitation shell spawned from VMware management processes leading to Babuk-derived ransomware activity
- **Actor / Campaign:** Suspected China-nexus APT / Babuk-derived ransomware
- **MITRE ATT&CK:** T1059 — Command and Scripting Interpreter / T1486 — Data Encrypted for Impact
- **Data source:** DeviceProcessEvents, DeviceFileEvents
- **Source:** [3]

```kql
DeviceProcessEvents
| where Timestamp > ago(3d)
| where InitiatingProcessFileName has_any ("vmtoolsd", "vami-lighttp", "vsphere-ui", "vpxd")
| where FileName in~ ("bash","sh","python","python3","perl","curl","wget","openssl")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName
| take 100
```

```kql
DeviceFileEvents
| where Timestamp > ago(3d)
| where ActionType == "FileCreated"
| where FileName has_any ("README", "HowToRestore", "ransom", "recover") or FileName endswith ".babuk"
| summarize FilesCreated = count(), Examples = make_set(FileName, 5) by DeviceName, InitiatingProcessAccountName, bin(Timestamp, 1h)
| where FilesCreated > 10
| order by FilesCreated desc
| take 100
```

*Note:* No specific ransom-note filename or ransomware sample hash was disclosed in the reporting, so this is behavior-based (unexpected shell activity from vCenter/appliance processes, and bulk creation of ransom-note-like files). Tune against known-good VMware maintenance scripts and admin tooling.

_No detectable technical indicators were found in [4] (SafePal breach) — this is a third-party data exposure with no telemetry-based hunting angle for customer environments._

> [1] Evooo1Bot Linux Botnet Exploits Known Flaws to Turn Edge Devices Into SOCKS5 Proxies — https://thehackernews.com/2026/08/evooo1bot-linux-botnet-exploits-known.html
> [2] Microsoft working on Defender patch for ShieldBreak zero-day — https://www.bleepingcomputer.com/news/security/microsoft-working-on-defender-patch-for-shieldbreak-zero-day/
> [3] Suspected China-Nexus Actor Exploits VMware vCenter Flaw, Deploys Babuk-Derived Ransomware — https://thehackernews.com/2026/08/suspected-china-nexus-actor-exploits.html
> [4] SafePal data breach impacts 39,798 customers, stolen info for sale — https://www.bleepingcomputer.com/news/security/safepal-data-breach-impacts-39-798-customers-stolen-info-for-sale/

### 2026-08-18

*Generated 2026-08-18 13:56 UTC · model `claude-sonnet-5`*

_Lint: 8 KQL block(s) — structural checks passed. All queries are CANDIDATES; validate before use._

#### TWINLOOT-style Python Process Beaconing to SharePoint/Teams Infrastructure
- **Actor / Campaign:** TWINLOOT (unattributed cluster)
- **MITRE ATT&CK:** T1102.002 — Web Service: Bidirectional Communication; T1071.001 — Application Layer Protocol: Web Protocols
- **Data source:** DeviceProcessEvents, DeviceNetworkEvents
- **Source:** [1]

```kql
// Look for python.exe/pyw.exe processes (not typical for user endpoints) initiating
// outbound connections to SharePoint Online / Teams / Graph endpoints - possible C2 tasking channel
DeviceProcessEvents
| where FileName in~ ("python.exe", "python3.exe", "pythonw.exe")
| join kind=inner (
    DeviceNetworkEvents
    | where RemoteUrl has_any ("sharepoint.com", "teams.microsoft.com", "graph.microsoft.com")
       or RemoteIPType == "Public"
) on DeviceId, $left.ProcessId == $right.InitiatingProcessId
| where Timestamp1 between (Timestamp .. Timestamp + 5m)
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, RemoteUrl, RemoteIP
| take 100
```

*Note:* Highly heuristic — legitimate automation/RPA tools also use Python + Graph/SharePoint APIs. Tune by excluding known dev/automation accounts and correlating with PyArmor-obfuscated binary names or unusual parent processes (e.g., non-IT-managed hosts).

#### Legacy WMIC.exe Execution (Pre/Post Removal Abuse)
- **Actor / Campaign:** unattributed (generic LOLBin abuse)
- **MITRE ATT&CK:** T1047 — Windows Management Instrumentation
- **Data source:** DeviceProcessEvents
- **Source:** [2]

```kql
// WMIC is being removed from Windows 11 24H2/25H2 due to abuse; hunt for continued/anomalous
// use, including copies dropped by attackers on systems where it's been removed by Microsoft
DeviceProcessEvents
| where FileName =~ "wmic.exe"
| where ProcessCommandLine has_any ("process call create", "useraccount", "shadowcopy", "/node:", "service call")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, FolderPath
| take 100
```

*Note:* On updated builds where WMIC has been removed, any hit for wmic.exe is highly suspicious (dropped tool); on legacy builds, expect FPs from admin scripts — tune by excluding known management/ITSM accounts.

#### Anomalous Azure/Entra Sign-Ins Following Credential Theft Reports
- **Actor / Campaign:** unattributed (Azure credential theft actor)
- **MITRE ATT&CK:** T1078.004 — Valid Accounts: Cloud Accounts
- **Data source:** SigninLogs, AADNonInteractiveUserSignInLogs
- **Source:** [3]

```kql
// Hunt for impossible-travel / new-location sign-ins with successful auth using
// legacy or non-interactive flows, consistent with stolen credential resale reports
SigninLogs
| where ResultType == 0
| summarize Countries = make_set(LocationDetails.countryOrRegion), IPs = make_set(IPAddress), Attempts = count()
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(Countries) > 1 or array_length(IPs) > 3
| project TimeGenerated, UserPrincipalName, Countries, IPs, Attempts
| take 100
```

*Note:* Requires baseline of normal travel/VPN patterns per tenant; pair with Conditional Access / risky sign-in signals to reduce noise from corporate VPN egress IP rotation.

#### Cavern C2 — DNS Tunneling / Google Apps Script Beaconing
- **Actor / Campaign:** Cavern / Cav3rn (Iranian nation-state)
- **MITRE ATT&CK:** T1071.004 — Application Layer Protocol: DNS; T1102 — Web Service
- **Data source:** DeviceNetworkEvents, DnsEvents
- **Source:** [4]

```kql
// Beaconing pattern: high-frequency DNS TXT-style lookups or repeated connections
// to script.google.com from non-browser processes (Cavern uses DNS + Apps Script as C2)
DeviceNetworkEvents
| where RemoteUrl has "script.google.com"
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","iexplore.exe")
| summarize ConnCount = count(), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by DeviceName, InitiatingProcessFileName, RemoteUrl
| where ConnCount > 10
| take 100
```

*Note:* Behavioral/heuristic only — no concrete Cavern IOCs given in this report; validate against process reputation and investigate any hits from servers/headless hosts rather than user browsers.

#### Evooo1Bot — Mirai-Derivative SOCKS5 Proxy Behavior on Linux Edge Devices
- **Actor / Campaign:** Evooo1Bot (Mirai-derived botnet)
- **MITRE ATT&CK:** T1584.008 — Compromise Infrastructure: Network Devices; T1090 — Proxy
- **Data source:** DeviceNetworkEvents (Linux), DeviceProcessEvents
- **Source:** [8]

```kql
// Linux edge devices exhibiting fan-out outbound connections consistent with acting as
// a SOCKS5 proxy after Mirai-derived exploitation of known flaws
DeviceNetworkEvents
| where DeviceOSPlatform startswith "Linux"
| summarize DistinctRemoteIPs = dcount(RemoteIP), DistinctPorts = dcount(RemotePort)
    by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
| where DistinctRemoteIPs > 20 and DistinctPorts <= 3
| take 100
```

*Note:* No specific IOCs published — this is proxy/fan-out behavior heuristic; requires Linux telemetry onboarding and tuning against known legitimate proxy/CDN appliances.

#### Exposed Apple/VNC Screen Sharing Service (Port 5900)
- **Actor / Campaign:** unattributed (opportunistic VNC scanning/abuse)
- **MITRE ATT&CK:** T1021.005 — Remote Services: VNC
- **Data source:** DeviceNetworkEvents, CommonSecurityLog (firewall)
- **Source:** [5]

```kql
// Detect inbound/outbound connections on unencrypted VNC port 5900, historically used
// by Apple Screen Sharing with weak/shared-password auth
DeviceNetworkEvents
| where RemotePort == 5900 or LocalPort == 5900
| where RemoteIPType == "Public" or LocalIPType == "Public"
| project Timestamp, DeviceName, LocalIP, LocalPort, RemoteIP, RemotePort, InitiatingProcessFileName
| take 100
```

*Note:* Flags any internet-facing VNC exposure; expect FPs from legitimate remote-support tools using VNC — cross-check with asset inventory for macOS Screen Sharing enablement.

#### Microsoft Defender Tampering Consistent with ShieldBreak (CVE-2026-69414) Exploitation Attempts
- **Actor / Campaign:** unattributed ("ShieldBreak" zero-day, CVE-2026-69414)
- **MITRE ATT&CK:** T1562.001 — Impair Defenses: Disable or Modify Tools
- **Data source:** DeviceRegistryEvents, DeviceEvents
- **Source:** [9]

```kql
// No public IOCs yet for ShieldBreak exploitation; hunt Defender config/state changes
// that could indicate exploitation of the disclosed Defender zero-day
DeviceEvents
| where ActionType in ("AntivirusDetection","AntivirusScanCancelled","AntivirusConfigChanged","AmsiTampering")
| where InitiatingProcessFileName !in~ ("MsMpEng.exe","MpCmdRun.exe")
| project Timestamp, DeviceName, ActionType, InitiatingProcessFileName, InitiatingProcessCommandLine
| take 100
```

*Note:* Purely behavioral pending patch/IOC release — treat as low-confidence tripwire; monitor vendor advisory for CVE-2026-69414 IOCs/patch and update once available.

#### Ray Dashboard/Job-Submission Abuse Consistent with CVE-2025-62593 (KEV)
- **Actor / Campaign:** unattributed (Ray-Project code injection, actively exploited)
- **MITRE ATT&CK:** T1210 — Exploitation of Remote Services
- **Data source:** DeviceProcessEvents, DeviceNetworkEvents
- **Source:** [7], [10]

```kql
// Ray clusters exposing the dashboard/job-submission API (default port 8265) are exploitable
// via code injection; hunt for anomalous child processes spawned from ray/python processes
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("python.exe","python3", "ray")
| where ProcessCommandLine has_any ("bash -c","curl ","wget ","/bin/sh","powershell")
| where InitiatingProcessCommandLine has "ray"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessCommandLine
| take 100
```

*Note:* Confirm exposure by checking whether Ray dashboard port 8265 is internet-facing (per BOD 26-04 guidance); apply vendor patch/mitigation and prioritize any internet-exposed Ray clusters immediately.

> [1] TWINLOOT Abuses SharePoint and Teams to Steal Credentials and Move Across Networks — https://thehackernews.com/2026/08/twinloot-abuses-sharepoint-and-teams-to.html
> [2] Microsoft starts removing WMIC tool used by cybercriminals — https://www.bleepingcomputer.com/news/microsoft/microsoft-removes-wmic-lolbin-tool-in-windows-11-beta-builds/
> [3] Hacker claims 3.6 million Azure account records stolen from major companies — https://www.bleepingcomputer.com/news/security/hacker-claims-36-million-azure-account-records-stolen-from-major-companies/
> [4] Cavern C2 Uses DNS and Google Apps Script to Blend Into Legitimate Traffic — https://thehackernews.com/2026/08/cavern-c2-uses-dns-and-google-apps.html
> [5] Apple Screen Sharing Security, (Mon, Aug 17th) — https://isc.sans.edu/diary/rss/33252
> [7] CISA Adds One Known Exploited Vulnerability to Catalog — https://www.cisa.gov/news-events/alerts/2026/08/17/cisa-adds-one-known-exploited-vulnerability-catalog
> [8] Evooo1Bot Linux Botnet Exploits Known Flaws to Turn Edge Devices Into SOCKS5 Proxies — https://thehackernews.com/2026/08/evooo1bot-linux-botnet-exploits-known.html
> [9] Microsoft working on Defender patch for ShieldBreak zero-day — https://www.bleepingcomputer.com/news/security/microsoft-working-on-defender-patch-for-shieldbreak-zero-day/
> [10] CVE-2025-62593 — Ray-Project Ray: Ray-Project Ray Code Injection Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2025-62593

### 2026-08-19

*Generated 2026-08-19 13:57 UTC · model `claude-sonnet-5`*

_Lint: 10 KQL block(s) — structural checks passed. All queries are CANDIDATES; validate before use._

#### TWINLOOT Python Implant Using SharePoint/Teams as C2
- **Actor / Campaign:** TWINLOOT
- **MITRE ATT&CK:** T1102.002 — Web Service: Bidirectional Communication (Trusted Third Party); T1059.006 — Python
- **Data source:** DeviceProcessEvents, DeviceNetworkEvents
- **Source:** [4]

```kql
// Look for python interpreters (or PyInstaller-frozen exes) making regular calls to SharePoint Online / Graph endpoints
// consistent with a hidden C2 tasking channel, especially from hosts that don't normally run python
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has_any ("sharepoint.com", "graph.microsoft.com") 
| where InitiatingProcessFileName in~ ("python.exe", "pythonw.exe", "py.exe")
| summarize ConnCount = count(), Urls = make_set(RemoteUrl, 10), FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by DeviceId, InitiatingProcessFileName, InitiatingProcessFolderPath
| where ConnCount > 5
| take 100
```

*Note:* Legitimate automation (e.g., Power Automate scripts, internal tooling) can also use Python + Graph/SharePoint APIs — validate the source folder path, PyArmor-related file artifacts, and whether the host is a workstation vs. an approved automation server before escalating. [4]

#### PyArmor-Packed Python Implant File Artifacts
- **Actor / Campaign:** TWINLOOT
- **MITRE ATT&CK:** T1027.002 — Obfuscated Files or Information: Software Packing
- **Data source:** DeviceFileEvents, DeviceProcessEvents
- **Source:** [4]

```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName endswith ".py" or FileName endswith ".pyz" or FileName endswith ".pyd"
| where FolderPath has_any (@"\AppData\Local\Temp", @"\ProgramData", @"\Users\Public")
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where ProcessCommandLine has_any ("pyarmor", "__pyarmor__", "pytransform")
) on DeviceId
| project Timestamp, DeviceId, FileName, FolderPath, ProcessCommandLine
| take 100
```

*Note:* PyArmor is also used legitimately by some vendors to protect commercial Python tools; correlate with the SharePoint/Teams C2 network pattern above to reduce noise. [4]

#### MacSync Stealer — Newly Registered / Rotating Domain Beaconing from macOS
- **Actor / Campaign:** MacSync Stealer
- **MITRE ATT&CK:** T1071.001 — Application Layer Protocol: Web Protocols; T1583.001 — Acquire Infrastructure: Domains
- **Data source:** DeviceNetworkEvents
- **Source:** [2]

```kql
// No specific domains were published; this hunts the described *behavior* — macOS endpoints
// contacting freshly-seen/rotating domains shortly after execution of an unsigned/unnotarized binary
DeviceProcessEvents
| where Timestamp > ago(7d)
| where DeviceId in (
    DeviceInfo | where OSPlatform == "macOS" | distinct DeviceId
)
| where InitiatingProcessSignatureStatus != "Valid" or FileName has_any ("dmg", "pkg")
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
) on DeviceId
| where TimeGenerated1 between (Timestamp .. (Timestamp + 5m))
| summarize DomainCount = dcount(RemoteUrl), Domains = make_set(RemoteUrl, 20) by DeviceId, InitiatingProcessFileName
| where DomainCount > 3
| take 100
```

*Note:* This is a heuristic proxy for Microsoft's "durable behavioral pivots" since no IOC domains were released in this summary; tune against your macOS fleet's baseline and consider pulling the 30+ domains from Microsoft's blog into a watchlist/TI indicator feed once published. [2]

#### MacSync Stealer — macOS Keychain / Credential Store Access Followed by Outbound POST
- **Actor / Campaign:** MacSync Stealer
- **MITRE ATT&CK:** T1555.001 — Credentials from Password Stores: Keychain; T1041 — Exfiltration Over C2 Channel
- **Data source:** DeviceProcessEvents, DeviceNetworkEvents
- **Source:** [2]

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where ProcessCommandLine has_any ("security find-generic-password", "security dump-keychain", "login.keychain-db")
| project Timestamp, DeviceId, AccountName, ProcessCommandLine, InitiatingProcessFileName
| take 100
```

*Note:* `security` CLI keychain queries are used by legitimate apps and admins too; investigate parent process lineage and whether it's followed by unusual outbound network activity from the same device within minutes. [2]

#### SilkParasite — Behavioral: New Persistence + C2-style Traffic on Government-Sector Hosts
- **Actor / Campaign:** SilkParasite (unattributed, Central Asia-focused espionage)
- **MITRE ATT&CK:** T1053.005 — Scheduled Task/Job; T1071 — Application Layer Protocol
- **Data source:** DeviceProcessEvents, DeviceScheduledJobEvents, DeviceNetworkEvents
- **Source:** [1]

```kql
// No hashes/domains/filenames were published for the 5 new RATs; hunt generic multi-RAT tradecraft:
// newly created scheduled task launching an unsigned binary that immediately opens outbound network connections.
DeviceScheduledJobEvents
| where Timestamp > ago(14d)
| where ActionType == "ScheduledTaskCreated"
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where InitiatingProcessSignatureStatus != "Valid"
) on DeviceId
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(14d)
) on DeviceId
| where abs(datetime_diff('minute', Timestamp1, Timestamp)) < 10
| project Timestamp, DeviceId, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteUrl, RemoteIP
| take 100
```

*Note:* This is intentionally broad/behavioral since the report gave no concrete IOCs for DriveSilkRAT, CookiETagRAT, NomadRAT, GoginRAT, or NodeEdgeRAT; treat as a triage query for government/defense tenants and pivot on hits with EDR process-tree review, not as a standalone high-confidence alert. [1]

#### Post-Removal Hunting: Unexpected WMIC.exe Binary Presence (Native Removal Bypass)
- **Actor / Campaign:** unattributed (LOLBIN abuse context)
- **MITRE ATT&CK:** T1218 — System Binary Proxy Execution; T1036.003 — Masquerading: Rename System Utilities
- **Data source:** DeviceFileEvents, DeviceProcessEvents
- **Source:** [6]

```kql
// Microsoft is removing native WMIC from Windows 11 24H2/25H2; after removal, any wmic.exe execution
// (especially from a non-System32 path, or on a build where it should no longer exist) is suspicious —
// likely attacker-supplied binary abuse or a stale/backdoored copy.
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "wmic.exe"
| where FolderPath !~ @"C:\Windows\System32\wbem\WMIC.exe"
| project Timestamp, DeviceId, AccountName, FolderPath, ProcessCommandLine, InitiatingProcessFileName
| take 100
```

*Note:* Also alert on any wmic.exe execution at all on OS builds where Microsoft has removed it, since legitimate presence should be zero; check DeviceInfo.OSVersion to scope to 24H2/25H2 builds. [6]

#### SharePoint Weak-Authentication Exploitation Pattern (CVE-2026-55040, KEV)
- **Actor / Campaign:** unattributed (actively exploited per CISA KEV)
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application; T1078 — Valid Accounts
- **Data source:** OfficeActivity, DeviceProcessEvents (on-prem SharePoint servers), SigninLogs
- **Source:** [5][9]

```kql
// On-prem/hybrid SharePoint: hunt for w3wp.exe spawning command interpreters or dropping files,
// a classic post-auth-bypass webshell/RCE pattern seen with prior SharePoint auth/deserialization CVEs.
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "powershell_ise.exe", "cscript.exe", "wscript.exe", "mshta.exe")
| project Timestamp, DeviceId, AccountName, ProcessCommandLine, FolderPath
| take 100
```

*Note:* Restrict to devices hosting SharePoint app pools; pair with SigninLogs/OfficeActivity anomalies (sign-ins bypassing MFA/expected auth flow) for CVE-2026-55040 specifically once patch/mitigation guidance is applied per BOD 26-04. [5][9]

#### IKEEXT Service Crash / Anomalous Child Process (CVE-2026-33824, KEV)
- **Actor / Campaign:** unattributed (actively exploited per CISA KEV)
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application; T1499 — Endpoint Denial of Service (crash indicator) / T1210 — Exploitation of Remote Services
- **Data source:** DeviceProcessEvents, Event (Security/System), DeviceNetworkEvents
- **Source:** [5][7]

```kql
// IKE/IKEEXT runs inside svchost.exe; a double-free RCE exploit may manifest as unexpected
// crashes/restarts of the IKEEXT-hosting svchost or a spawned child process it never normally creates.
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "svchost.exe"
| where InitiatingProcessCommandLine has "IKEEXT"
| where FileName !in~ ("svchost.exe")
| project Timestamp, DeviceId, InitiatingProcessCommandLine, FileName, FolderPath, ProcessCommandLine
| take 100
```

*Note:* Endpoint telemetry alone may miss the memory-corruption exploit itself; supplement with Windows Event ID 7031/7034 (service crash) for the IKEEXT service and firewall/VPN-facing exposure review, since this is a remote-code-execution vuln in an IKE-exposed service. [5][7]

#### macOS Screen Sharing (ARD/VNC) Authentication Bypass Hunt (CVE-2026-65400, KEV)
- **Actor / Campaign:** unattributed (actively exploited per CISA KEV)
- **MITRE ATT&CK:** T1021.005 — Remote Services: VNC; T1078 — Valid Accounts (bypass)
- **Data source:** DeviceLogonEvents, DeviceNetworkEvents
- **Source:** [5][10]

```kql
// Hunt for inbound Screen Sharing (ARD/VNC, TCP 5900/3283) connections to macOS devices followed
// immediately by a local logon event with no corresponding successful credential prompt in logs.
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where DeviceId in (DeviceInfo | where OSPlatform == "macOS" | distinct DeviceId)
| where LocalPort in (5900, 3283) and ActionType == "ConnectionAccepted"
| project Timestamp, DeviceId, RemoteIP, RemotePort, LocalPort
| take 100
```

*Note:* Defender for Endpoint macOS logon telemetry may be limited; cross-reference with macOS unified logs (`log show --predicate 'process == "ARDAgent"'`) and network flow data for a definitive check of anonymous Screen Sharing access until CVE-2026-65400 is patched. [5][10]

#### VMware vCenter Path Traversal Access Attempts (CVE-2026-59310, KEV)
- **Actor / Campaign:** unattributed (actively exploited per CISA KEV)
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application; T1083 — File and Directory Discovery
- **Data source:** CommonSecurityLog / Syslog (vCenter access logs ingested to Sentinel)
- **Source:** [5][8]

```kql
// Requires vCenter/Apache Tomcat access logs forwarded via CEF/Syslog into Sentinel.
CommonSecurityLog
| where TimeGenerated > ago(14d)
| where DeviceProduct has_any ("vCenter", "VMware")
| where RequestURL has_any ("../", "..%2f", "..%5c", "%2e%2e")
| project TimeGenerated, DeviceVendor, DeviceProduct, SourceIP, RequestURL, DestinationIP
| take 100
```

*Note:* Field/table names depend on your vCenter log forwarding configuration (CEF connector vs. custom syslog table); validate schema before deploying, and prioritize alerting on internet-exposed vCenter appliances per BOD 26-04. [5][8]

> [1] SilkParasite Espionage Campaign Targets Central Asian Governments with Five New RATs — https://thehackernews.com/2026/08/silkparasite-espionage-campaign-targets.html
> [2] Hunting MacSync Stealer infrastructure through behavioral pivots — https://www.microsoft.com/en-us/security/blog/2026/08/18/hunting-macsync-stealer-infrastructure-through-behavioral-pivots/
> [4] TWINLOOT Abuses SharePoint and Teams to Steal Credentials and Move Across Networks — https://thehackernews.com/2026/08/twinloot-abuses-sharepoint-and-teams-to.html
> [5] CISA Adds Four Known Exploited Vulnerabilities to Catalog — https://www.cisa.gov/news-events/alerts/2026/08/18/cisa-adds-four-known-exploited-vulnerabilities-catalog
> [6] Microsoft starts removing WMIC tool used by cybercriminals — https://www.bleepingcomputer.com/news/microsoft/microsoft-removes-wmic-lolbin-tool-in-windows-11-beta-builds/
> [7] CVE-2026-33824 — Microsoft Internet Key Exchange (IKE) Service Extensions Double Free Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2026-33824
> [8] CVE-2026-59310 — Broadcom VMware vCenter Path Traversal Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2026-59310
> [9] CVE-2026-55040 — Microsoft SharePoint Weak Authentication Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2026-55040
> [10] CVE-2026-65400 — Apple macOS Improper Authentication Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2026-65400

### 2026-08-20

*Generated 2026-08-20 13:59 UTC · model `claude-sonnet-5`*

_Lint: 8 KQL block(s) — structural checks passed. All queries are CANDIDATES; validate before use._

#### MLflow Server SSRF to Cloud Metadata Service (CVE-2026-64849)
- **Actor / Campaign:** unattributed (KEV-listed, actively exploited)
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application (SSRF leading to credential/metadata theft, T1552.005)
- **Data source:** DeviceNetworkEvents
- **Source:** [1][7][9]

```kql
// Detect MLflow (or related python/gunicorn/java) processes reaching cloud metadata endpoints
// This is the classic SSRF-to-metadata-service pattern used to exploit CVE-2026-64849
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteIP in ("169.254.169.254", "100.100.100.200") // AWS/Azure/GCP + Alibaba metadata IPs
| where InitiatingProcessCommandLine has_any ("mlflow", "gunicorn", "mlflow.server", "mlflow-server")
    or InitiatingProcessFolderPath has "mlflow"
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP, RemotePort, RemoteUrl
| take 100
```

*Note:* Requires MLflow tracking server hosts to be onboarded to MDE. Tune the process-name filter to your actual MLflow deployment (container entrypoint may differ); any hit against metadata IPs from an MLflow host warrants immediate investigation.

#### Post-Exploitation Shell Spawned from MLflow Server Process
- **Actor / Campaign:** unattributed (CVE-2026-64849 exploitation)
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application; T1059 — Command and Scripting Interpreter
- **Data source:** DeviceProcessEvents
- **Source:** [1][7][9]

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessCommandLine has "mlflow"
| where FileName in~ ("bash","sh","curl","wget","python3","python","cmd.exe","powershell.exe","nc","ncat")
| project Timestamp, DeviceName, AccountName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| take 100
```

*Note:* MLflow tracking servers should not normally spawn shells or download utilities; flag any such child process for triage. Expect FP if MLflow is invoked via wrapper scripts — tune to your baseline.

#### Suspicious Kernel Driver Service Creation (BYOVD Precursor — SPECTRE)
- **Actor / Campaign:** UAT-10147 (SPECTRE implant)
- **MITRE ATT&CK:** T1068 / T1543.003 — Bring Your Own Vulnerable Driver, Create or Modify System Process: Windows Service
- **Data source:** DeviceProcessEvents, DeviceFileEvents
- **Source:** [3]

```kql
// BYOVD is commonly staged via sc.exe/registry service creation of type=kernel, followed by a .sys drop
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("sc.exe","reg.exe","powershell.exe")
| where ProcessCommandLine has "create" and ProcessCommandLine has_any ("type= kernel","type=kernel","SERVICE_KERNEL_DRIVER")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| union (
    DeviceFileEvents
    | where Timestamp > ago(14d)
    | where FolderPath has @"\drivers\" and FileName endswith ".sys"
    | where InitiatingProcessFileName !in~ ("wusa.exe","trustedinstaller.exe","msiexec.exe","dism.exe")
    | project Timestamp, DeviceName, AccountName=InitiatingProcessAccountName, FileName, ProcessCommandLine=InitiatingProcessCommandLine
)
| take 100
```

*Note:* SPECTRE is reported to use BYOVD for kernel-level EDR bypass; this is a generic heuristic — cross-reference driver hashes against known-vulnerable-driver lists (e.g., LOLDrivers) and expect noise from legitimate driver installers, so tune by excluding trusted signing publishers.

#### Suspicious Linux Kernel Module Load (Rootkit Behavior — SPECTRE)
- **Actor / Campaign:** UAT-10147 (SPECTRE implant)
- **MITRE ATT&CK:** T1547.006 — Boot or Logon Autostart Execution: Kernel Modules and Extensions; T1014 — Rootkit
- **Data source:** DeviceProcessEvents (Linux)
- **Source:** [3]

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in ("insmod","modprobe","kmod","rmmod")
| where ProcessCommandLine has ".ko"
| where ProcessCommandLine !has_any ("/usr/lib/modules","/lib/modules") // outside standard module dirs
| project Timestamp, DeviceName, InitiatingProcessAccountName, FileName, ProcessCommandLine
| take 100
```

*Note:* SPECTRE includes a Linux rootkit component; loading modules from non-standard paths (e.g., /tmp, /dev/shm) is a strong signal but requires Linux MDE onboarding. Baseline your legitimate kernel module management tooling first to reduce FPs.

#### Reconnaissance / Exploitation Tooling Targeting Siemens S7 PLCs (Port 102)
- **Actor / Campaign:** unattributed (AI-generated S7 exploitation scripts per CISA/NSA/FBI advisory)
- **MITRE ATT&CK:** T0846 — ICS: Remote System Discovery; T0866 — Exploitation of Remote Services
- **Data source:** DeviceProcessEvents, DeviceNetworkEvents
- **Source:** [5][8]

```kql
// Process-level: presence of S7/ISO-TSAP scripting/scanning libraries or tools
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine has_any ("snap7", "python-snap7", "s7comm", "S7comm", "pysnmp", "s7-1200", "s7-1500")
   or (FileName in~ ("nmap.exe","masscan.exe","python.exe","python3.exe") and ProcessCommandLine has "102")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| take 100
```

```kql
// Network-level: unexpected hosts talking to ISO-TSAP (TCP/102), the S7 protocol port
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemotePort == 102
| summarize ConnCount = count(), RemoteIPs = make_set(RemoteIP), Processes = make_set(InitiatingProcessFileName)
    by DeviceName, bin(Timestamp, 1h)
| where ConnCount > 5   // tune to baseline engineering workstation traffic
| take 100
```

*Note:* This is heuristic ICS reconnaissance detection; requires an allow-list of known engineering workstations/HMIs that legitimately talk TCP/102 to Siemens PLCs to avoid heavy FPs. Advisory notes scripts are disguised as legitimate management tools, so also review process signer/hash reputation for anything hitting port 102. [8]

#### SilkParasite Custom RAT Artifact Strings
- **Actor / Campaign:** SilkParasite (Central Asian government targeting)
- **MITRE ATT&CK:** T1071 — Application Layer Protocol (C2); T1105 — Ingress Tool Transfer
- **Data source:** DeviceProcessEvents, DeviceFileEvents
- **Source:** [6]

```kql
// Low-fidelity string hunt for analyst-assigned RAT family names possibly embedded in
// dropped binaries, debug/PDB paths, mutex names, or C2 beacon strings
union DeviceProcessEvents, DeviceFileEvents
| where Timestamp > ago(30d)
| where (isnotempty(ProcessCommandLine) and ProcessCommandLine has_any
        ("DriveSilkRAT","CookiETagRAT","NomadRAT","GoginRAT","NodeEdgeRAT"))
     or (isnotempty(FileName) and FileName has_any
        ("DriveSilk","CookiETag","NomadRAT","GoginRAT","NodeEdge"))
| project Timestamp, DeviceName, FileName, ProcessCommandLine
| take 100
```

*Note:* No hashes/domains/file names were published for the five new RAT families — these are researcher-assigned names and are unlikely to appear verbatim in the wild; this query is a placeholder for when Zimperium/HackerNews follow-up IOCs are released. Prioritize behavioral hunting (spearphishing delivery to government domains, unusual persistence via scheduled tasks/services) until concrete IOCs surface. [6]

#### Android Accessibility Service Abuse (ToxicPanda 2.0 / GoldDigger On-Device Fraud)
- **Actor / Campaign:** ToxicPanda 2.0 (aka TgToxic), GoldDigger
- **MITRE ATT&CK:** T1417 — Input Capture (Mobile); T1626.001 — Abuse Elevated Execution Control (Accessibility Services)
- **Data source:** DeviceEvents (Microsoft Defender for Endpoint on Android)
- **Source:** [2]

```kql
// Behavioral hunt for accessibility-service abuse on managed Android devices, a hallmark
// of ToxicPanda/GoldDigger overlay and on-device fraud workflows
DeviceEvents
| where Timestamp > ago(14d)
| where ActionType has_any ("AccessibilityServiceEnabled","AccessibilityServiceRequested","AccessibilityPermissionGranted")
| project Timestamp, DeviceName, DeviceId, ActionType, AdditionalFields
| take 100
```

*Note:* ToxicPanda/GoldDigger are Android-only threats — this query depends on Defender for Endpoint mobile telemetry (DeviceEvents/ActionType schema for Android may vary by tenant/version, so validate field names against your environment). No concrete IOCs (package names, C2 domains) were published in the source, so this remains a coarse behavioral signal requiring correlation with banking-app installs and new/unusual accessibility grants.

> [1] CISA warns of hackers exploiting critical MLflow vulnerability — https://www.bleepingcomputer.com/news/security/cisa-warns-of-hackers-exploiting-critical-mlflow-vulnerability/
> [2] ToxicPanda 2.0 and GoldDigger Expand Android Banking Attacks with On-Device Fraud — https://thehackernews.com/2026/08/toxicpanda-20-and-golddigger-expand.html
> [3] UAT-10147 deploys SPECTRE: A cross-platform implant with Linux rootkit and BYOVD capabilities — https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
> [5] US warns of AI-powered attacks on Siemens PLCs in critical infrastructure — https://www.bleepingcomputer.com/news/security/us-warns-of-ai-powered-attacks-on-siemens-plcs-in-critical-infrastructure/
> [6] SilkParasite Espionage Campaign Targets Central Asian Governments with Five New RATs — https://thehackernews.com/2026/08/silkparasite-espionage-campaign-targets.html
> [7] CISA Adds One Known Exploited Vulnerability to Catalog — https://www.cisa.gov/news-events/alerts/2026/08/19/cisa-adds-one-known-exploited-vulnerability-catalog
> [8] Defending Against an Active Threat to Siemens S7 Series PLCs — https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-231a
> [9] CVE-2026-64849 — MLflow MLflow: MLflow Server-Side Request Forgery Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2026-64849

### 2026-08-21

*Generated 2026-08-21 13:33 UTC · model `claude-sonnet-5`*

_Lint: 8 KQL block(s) — structural checks passed. All queries are CANDIDATES; validate before use._

#### Suspicious child process spawned from FTP client activity (E4del/PINHOLE banner abuse)
- **Actor / Campaign:** Unattributed (E4del / PINHOLE RATs)
- **MITRE ATT&CK:** T1071.002 — Application Layer Protocol: File Transfer Protocols / T1105 — Ingress Tool Transfer
- **Data source:** DeviceNetworkEvents, DeviceProcessEvents
- **Source:** [2]

```kql
// Behavioral: no confirmed IOCs published; hunts for a host connecting to an FTP
// server (port 21) followed shortly by an unexpected child process launch that
// could reflect banner-embedded command execution.
let ftpConns = DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort == 21 and InitiatingProcessFileName in~ ("ftp.exe","cmd.exe","powershell.exe")
| project DeviceId, ConnTime = Timestamp, RemoteIP, InitiatingProcessFileName;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("cmd.exe","powershell.exe","mshta.exe","rundll32.exe","wscript.exe")
| join kind=inner ftpConns on DeviceId
| where Timestamp between (ConnTime .. ConnTime + 5m)
| project Timestamp, DeviceId, FileName, ProcessCommandLine, RemoteIP, InitiatingProcessFileName
| take 100
```

*Note:* Highly heuristic — tune to your environment's normal FTP usage (e.g., scheduled backup jobs) to reduce noise; no hashes/domains were published for E4del/PINHOLE so this is TTP-based only.

#### Cargo/Rust build invoking network or execution tools during compilation (supply-chain build script abuse)
- **Actor / Campaign:** Unattributed — Rust crates.io supply chain compromise (arrayref, internment, append-only-vec)
- **MITRE ATT&CK:** T1195.001 — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **Data source:** DeviceProcessEvents
- **Source:** [3]

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("cargo.exe","rustc.exe","build-script-build.exe")
   or InitiatingProcessCommandLine has_any ("build.rs","cargo build","cargo install")
| where FileName in~ ("curl.exe","powershell.exe","cmd.exe","certutil.exe","wget.exe","cscript.exe","mshta.exe")
| project Timestamp, DeviceId, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
| take 100
```

*Note:* Flags build-time execution of network/download utilities from Rust build scripts — a strong indicator of malicious build.rs abuse; expect some FPs from legit build tooling that fetches assets, so review command lines and destination domains.

#### Anomalous OAuth device-code / consent grants targeting high-risk sectors
- **Actor / Campaign:** UNC6293, UNC7005, UNC5976 (suspected Russian espionage clusters)
- **MITRE ATT&CK:** T1528 — Steal Application Access Token / T1566.002 — Phishing: Spearphishing Link (OAuth/device-code abuse)
- **Data source:** SigninLogs, AADSignInEventsBeta, CloudAppEvents
- **Source:** [4]

```kql
// Device-code / OAuth grant flow abuse commonly used to hijack Google/Microsoft accounts
SigninLogs
| where TimeGenerated > ago(14d)
| where AuthenticationProtocol has "deviceCode" or ResultDescription has "device code"
| extend AppUsed = tostring(AppDisplayName)
| where AppUsed !in ("Microsoft Authenticator App") // tune allow-list
| project TimeGenerated, UserPrincipalName, AppUsed, IPAddress, Location, ResultType, ResultDescription
| take 100
```

```kql
// Complementary: newly consented OAuth apps requesting broad mail/contacts scopes
CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType in ("Consent to application.", "Add OAuth2PermissionGrant.")
| extend Scopes = tostring(RawEventData.ConsentScope)
| where Scopes has_any ("Mail.Read","Contacts.Read","offline_access")
| project Timestamp, AccountDisplayName, Application, Scopes, IPAddress
| take 100
```

*Note:* Device-code and consent-phishing flows are also used legitimately (CI/CD, IoT); baseline expected apps/users and pivot on new/rare AppDisplayName plus atypical geography or sign-in velocity.

#### Suspicious process activity from MLflow server (CVE exploitation attempt)
- **Actor / Campaign:** Unattributed — active exploitation per CISA warning
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application / T1059 — Command and Scripting Interpreter
- **Data source:** DeviceProcessEvents, DeviceNetworkEvents
- **Source:** [6]

```kql
// MLflow (typically python/gunicorn) spawning shell/script interpreters is abnormal
// and consistent with RCE/deserialization exploitation of the platform.
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("python.exe","python3","gunicorn","mlflow")
| where FileName in~ ("bash","sh","cmd.exe","powershell.exe","wget","curl","nc","ncat")
| project Timestamp, DeviceId, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine
| take 100
```

*Note:* No specific IOCs published; verify against internet-exposed MLflow tracking servers first, then correlate with inbound requests on the MLflow API port for exploitation confirmation.

#### Kernel driver load consistent with BYOVD (SPECTRE implant EDR bypass)
- **Actor / Campaign:** UAT-10147 (SPECTRE implant)
- **MITRE ATT&CK:** T1068 — Exploitation for Privilege Escalation / T1562.001 — Impair Defenses: Disable or Modify Tools (BYOVD)
- **Data source:** DeviceDriverEvents (or DeviceEvents ActionType DriverLoaded), DeviceFileEvents
- **Source:** [8]

```kql
DeviceDriverEvents
| where Timestamp > ago(14d)
| where ActionType == "DriverLoaded"
| where FolderPath has_any (@"\Temp\", @"\Downloads\", @"\Users\Public\")
   or FileName endswith ".sys" and isnotempty(InitiatingProcessCommandLine)
| project Timestamp, DeviceId, FileName, FolderPath, SHA256, InitiatingProcessFileName, InitiatingProcessCommandLine
| take 100
```

```kql
// Companion: process injection / credential theft indicators from a newly-loaded, unsigned driver session
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine has_any ("lsass", "sekurlsa", "MiniDump")
| where InitiatingProcessFileName !in~ ("procdump.exe","taskmgr.exe") // known-legit dump tools
| project Timestamp, DeviceId, FileName, ProcessCommandLine, InitiatingProcessFileName
| take 100
```

*Note:* Tune the folder-path allow-list to your driver-signing/EDR agent update paths to avoid FPs; no file hashes were published for SPECTRE so signature-based matching isn't yet possible — pair with Talos IOC feed once released.

#### Inbound traffic to TrueConf Server management port (CVE-2026-72529 / CVE-2026-72530 exploitation)
- **Actor / Campaign:** Unattributed — actively exploited per CISA KEV
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application
- **Data source:** DeviceNetworkEvents
- **Source:** [5][9][10]

```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where LocalPort == 4307 or RemotePort == 4307
| summarize Attempts = count(), Sources = make_set(RemoteIP, 20) by DeviceId, LocalPort, RemotePort, bin(Timestamp, 1h)
| where Attempts > 5
| take 100
```

*Note:* Port 4307/TCP is the vulnerable TrueConf Server management interface; investigate any external/untrusted source IPs hitting this port, especially on internet-facing hosts, and correlate with subsequent process creation on the TrueConf host for successful exploitation.

> [2] Hackers abuse FTP server banners to deliver new Windows malware — https://www.bleepingcomputer.com/news/security/hackers-abuse-ftp-server-banners-to-deliver-new-windows-malware/
> [3] Rust Supply Chain Attack Puts Build-Time Malware in Crates with 245 Million Downloads — https://thehackernews.com/2026/08/rust-supply-chain-attack-puts-build.html
> [4] Suspected Russian Hackers Abuse Google OAuth and WhatsApp Linking to Hijack Accounts — https://thehackernews.com/2026/08/suspected-russian-hackers-abuse-google.html
> [5] CISA Adds Two Known Exploited Vulnerabilities to Catalog — https://www.cisa.gov/news-events/alerts/2026/08/20/cisa-adds-two-known-exploited-vulnerabilities-catalog
> [6] CISA warns of hackers exploiting critical MLflow vulnerability — https://www.bleepingcomputer.com/news/security/cisa-warns-of-hackers-exploiting-critical-mlflow-vulnerability/
> [8] UAT-10147 deploys SPECTRE: A cross-platform implant with Linux rootkit and BYOVD capabilities — https://blog.talosintelligence.com/uat-10147-deploys-spectre-a-cross-platform-implant-with-linux-rootkit-and-byovd-capabilities/
> [9] CVE-2026-72530 — TrueConf Server: TrueConf Server Code Injection Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2026-72530
> [10] CVE-2026-72529 — TrueConf Server: TrueConf Server Missing Authentication for Critical Function Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2026-72529

### 2026-08-22

*Generated 2026-08-22 13:26 UTC · model `claude-sonnet-5`*

_Lint: 6 KQL block(s) — structural checks passed. All queries are CANDIDATES; validate before use._

#### Trojanized npm package launching a detached Linux binary post-install
- **Actor / Campaign:** unattributed (RedC2 4.0 npm supply-chain campaign)
- **MITRE ATT&CK:** T1195.002 — Supply Chain Compromise: Compromise Software Supply Chain; T1204.003 — User Execution: Malicious Image
- **Data source:** DeviceProcessEvents, DeviceFileEvents
- **Source:** [2]

```kql
// Linux (or macOS) endpoints: npm/node spawning chmod +x on a bundled binary then launching it detached
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node", "npm", "npm.exe", "node.exe")
| where FileName in~ ("chmod", "chmod.exe")
| where ProcessCommandLine has "+x"
| project Timestamp, DeviceName, DeviceId, InitiatingProcessFileName, InitiatingProcessFolderPath,
          InitiatingProcessCommandLine, ProcessCommandLine, FolderPath
| take 100
```

*Note:* No concrete package names or hashes were published in the reporting; this hunts the behavioral pattern (node_modules dropping + chmod +x + background exec). Validate FolderPath is under a `node_modules` tree to reduce noise from legitimate build scripts.

#### Node process spawning a background/detached executable (post-install persistence)
- **Actor / Campaign:** unattributed (RedC2 4.0 npm supply-chain campaign)
- **MITRE ATT&CK:** T1543 — Create or Modify System Process; T1071.001 — Application Layer Protocol: Web Protocols (AI-assisted C2)
- **Data source:** DeviceProcessEvents, DeviceNetworkEvents
- **Source:** [2]

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("node", "npm", "node.exe", "npm.exe")
| where FolderPath has "node_modules"
| where ProcessCommandLine has_any ("nohup", "setsid", "&", "disown")
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where InitiatingProcessFolderPath has "node_modules"
) on DeviceId
| project Timestamp, DeviceName, ProcessCommandLine, RemoteUrl, RemoteIP, RemotePort
| take 100
```

*Note:* Heuristic — flags any node_modules-spawned process that also makes outbound network calls; tune folder path scoping (e.g., limit to CI/build servers or developer workstations) to cut FPs from legitimate native-module build helpers.

#### FTP client spawning a shell/script shortly after connecting (banner-based malware delivery)
- **Actor / Campaign:** unattributed (E4del / PINHOLE RAT campaign)
- **MITRE ATT&CK:** T1071.002 — Application Layer Protocol: File Transfer Protocols; T1059 — Command and Scripting Interpreter
- **Data source:** DeviceNetworkEvents, DeviceProcessEvents
- **Source:** [6]

```kql
let ftpSessions = DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort == 21 or InitiatingProcessFileName in~ ("ftp.exe")
| project DeviceId, DeviceName, ConnTime = Timestamp, RemoteIP, RemoteUrl;
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("ftp.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "mshta.exe", "wscript.exe", "cscript.exe", "rundll32.exe")
| join kind=inner ftpSessions on DeviceId
| where Timestamp between (ConnTime .. ConnTime + 10m)
| project Timestamp, DeviceName, ProcessCommandLine, FileName, RemoteIP, RemoteUrl, ConnTime
| take 100
```

*Note:* No file hashes/names for E4del or PINHOLE were disclosed; this looks for the described technique (FTP banner text parsed and executed as commands). Expect FPs from legitimate scripted FTP automation — validate against known FTP script inventories.

#### Suspicious shell spawned from Zimbra mailboxd (potential CVE-2026-73570 exploitation)
- **Actor / Campaign:** unattributed (KEV-listed Zimbra ZCS OS command injection)
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application; T1059.004 — Command and Scripting Interpreter: Unix Shell
- **Data source:** DeviceProcessEvents (Linux onboarded via Defender for Endpoint), DeviceNetworkEvents
- **Source:** [4] [7]

```kql
// Requires Zimbra host onboarded to Defender for Endpoint (Linux)
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any ("java", "mailboxd", "zmmailboxdmgr", "postfix", "smtpd")
| where FileName in~ ("sh", "bash", "curl", "wget", "python3", "perl", "nc")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| take 100
```

```kql
// Complementary: unusual outbound connections from Zimbra process shortly after SMTP activity on 25/465/587
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any ("java", "mailboxd")
| where RemotePort !in (25, 465, 587, 993, 143)
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort
| take 100
```

*Note:* No exploitation IOCs were published for CVE-2026-73570; this is TTP-based hunting for post-exploitation command execution from the mail server process. Patch per CISA KEV/BOD 26-04 guidance regardless of alert hits; tune process/parent lists to your actual ZCS deployment.

#### CI/CD build agent contacting cloud metadata endpoint or exfiltrating credentials
- **Actor / Campaign:** unattributed (SDLC / CI-CD supply chain targeting)
- **MITRE ATT&CK:** T1552.005 — Unsecured Credentials: Cloud Instance Metadata API; T1195.001 — Compromise Software Dependencies and Development Tools
- **Data source:** DeviceProcessEvents, DeviceNetworkEvents
- **Source:** [1]

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has_any ("Runner.Listener", "jenkins", "gitlab-runner", "azure-pipelines-agent", "buildkite-agent")
| where ProcessCommandLine has_any ("169.254.169.254", "metadata.google.internal", "aws sts get-caller-identity", "gcloud auth print-access-token", ".npmrc", "id_rsa")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
| take 100
```

*Note:* This is fully behavioral (no IOCs published for a specific campaign); it targets the article's theme of attackers pivoting to CI/CD/dev-tool infrastructure rather than app code. Baseline legitimate pipeline steps that call cloud metadata/credential helpers before enabling as an alert.

> [1] Connecting the Dots: Securing the Overlooked Corners of the Software Development Lifecycle (SDLC) Supply Chain — https://unit42.paloaltonetworks.com/sdlc-supply-chain/
> [2] 14 Trojanized npm Packages Drop RedC2 4.0 Linux Backdoor With AI-Assisted C2 — https://thehackernews.com/2026/08/14-trojanized-npm-packages-drop-redc2.html
> [4] CISA Adds One Known Exploited Vulnerability to Catalog — https://www.cisa.gov/news-events/alerts/2026/08/21/cisa-adds-one-known-exploited-vulnerability-catalog
> [6] Hackers abuse FTP server banners to deliver new Windows malware — https://www.bleepingcomputer.com/news/security/hackers-abuse-ftp-server-banners-to-deliver-new-windows-malware/
> [7] CVE-2026-73570 — Synacor Zimbra Collaboration Suite (ZCS): OS Command Injection Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2026-73570

### 2026-08-23

*Generated 2026-08-23 13:26 UTC · model `claude-sonnet-5`*

_Lint: no KQL blocks detected._

_No detectable material in today's reporting._

> [1] TikTok Agrees to $400 Million Settlement in U.S. Child Privacy Lawsuit — https://thehackernews.com/2026/08/tiktok-agrees-to-400-million-settlement.html

### 2026-08-24

*Generated 2026-08-24 13:58 UTC · model `claude-sonnet-5`*

_Lint: 6 KQL block(s) — structural checks passed. All queries are CANDIDATES; validate before use._

#### ClickFix / FakeCaptcha Clipboard Execution Pattern (WordlistLoader → Amatera)
- **Actor / Campaign:** ClearFake / WordlistLoader (unattributed)
- **MITRE ATT&CK:** T1204.004 — User Execution: Malicious Copy and Paste
- **Data source:** DeviceProcessEvents
- **Source:** [1]

```kql
DeviceProcessEvents
| where Timestamp > ago(2d)
| where ParentProcessFileName in~ ("explorer.exe", "cmd.exe")
| where FileName in~ ("powershell.exe", "cmd.exe", "mshta.exe", "wscript.exe", "cscript.exe")
// ClickFix chains typically run a pasted PowerShell/mshta one-liner after a fake "verify you are human" prompt
| where ProcessCommandLine has_any ("IEX", "DownloadString", "-enc", "-EncodedCommand", "FromBase64String", "iwr ")
| where ProcessCommandLine has_any ("captcha", "verify", "cloudflare", "recaptcha", "human")
| project Timestamp, DeviceName, AccountName, ParentProcessFileName, FileName, ProcessCommandLine, InitiatingProcessAccountName
| take 100
```

*Note:* Heuristic and keyword-based; tune the lure keyword list to your telemetry, and expect FPs from legitimate helpdesk/self-service scripts that also reference "verify" or use IEX. No concrete Amatera/WordlistLoader hashes were published in the source, so this targets the ClickFix delivery TTP.

#### Suspicious mshta.exe Remote HTA Execution (ClearFake stager pattern)
- **Actor / Campaign:** ClearFake / WordlistLoader (unattributed)
- **MITRE ATT&CK:** T1218.005 — System Binary Proxy Execution: Mshta
- **Data source:** DeviceProcessEvents
- **Source:** [1]

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName =~ "mshta.exe"
| where ProcessCommandLine has_any ("http://", "https://")
| project Timestamp, DeviceName, AccountName, ParentProcessFileName, ProcessCommandLine
| take 100
```

*Note:* mshta loading remote content is a longstanding ClearFake/ClickFix stager technique; legitimate mshta usage with remote URLs is rare in most environments but validate against internal tooling before alerting.

#### SynkLoader-Style Credential Prompt / Password Harvesting Behavior
- **Actor / Campaign:** SynkLoader (unattributed)
- **MITRE ATT&CK:** T1056.002 — Input Capture: GUI Input Capture
- **Data source:** DeviceProcessEvents, DeviceEvents
- **Source:** [1]

```kql
DeviceProcessEvents
| where Timestamp > ago(3d)
| where ParentProcessFileName in~ ("explorer.exe", "powershell.exe", "mshta.exe")
| where FileName has_any ("credential", "login", "auth", "vault")
   or ProcessCommandLine has_any ("CredentialUIPromptForCredentials", "vaultcmd", "cmdkey")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, ParentProcessFileName
| take 100
```

*Note:* No file names/hashes for SynkLoader were disclosed in the reporting; this is a broad behavioral proxy for fake Windows-credential-prompt phishing and will need heavy tuning — treat as a starting hypothesis, not a production rule.

#### Outbound QUIC (UDP/443) from Non-Browser Process — Possible QUICAgent Backdoor C2
- **Actor / Campaign:** Operation QUICSILVER / QUICAgent (China-nexus, moderate confidence)
- **MITRE ATT&CK:** T1071.001 — Application Layer Protocol: Web Protocols (QUIC abuse for C2)
- **Data source:** DeviceNetworkEvents
- **Source:** [2]

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where Protocol == "Udp" and RemotePort == 443
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe","teams.exe")
| where InitiatingProcessFileName endswith ".exe"
| summarize ConnCount = count(), RemoteIPs = make_set(RemoteIP, 10) by DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath
| where ConnCount > 5
| take 100
```

*Note:* QUICAgent is described as a Go backdoor; Go binaries often statically implement QUIC/HTTP3 outside the browser stack, making non-browser UDP/443 traffic a useful anomaly signal — but this needs baselining per environment (legitimate apps like game clients or CDNs also use QUIC).

#### Phishing Lure Execution Chain from LNK/Document (Graduation Invitation Theme)
- **Actor / Campaign:** Operation QUICSILVER / QUICAgent (China-nexus, moderate confidence)
- **MITRE ATT&CK:** T1204.002 — User Execution: Malicious File
- **Data source:** DeviceProcessEvents, DeviceFileEvents
- **Source:** [2]

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe", "rundll32.exe")
| where InitiatingProcessCommandLine has ".lnk"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| take 100
```

*Note:* No specific lure file names or hashes were published; this hunts the generic LNK-double-click-to-script-execution chain often used in spear-phishing droppers targeting government/IT sectors in Myanmar. Cross-reference with recent inbound email/attachment activity for higher confidence.

#### Android App Requesting VPN Permission While Blocking Play Store Access (ToxicPanda-style defense evasion)
- **Actor / Campaign:** ToxicPanda
- **MITRE ATT&CK (Mobile):** T1629.003 — Impair Defenses: Disable or Modify Tools
- **Data source:** DeviceEvents (Microsoft Defender for Endpoint on Android), AlertEvidence
- **Source:** [3]

```kql
// Best-effort hunt using MDE-for-Android telemetry; column/action names vary by tenant configuration and should be validated.
DeviceEvents
| where Timestamp > ago(14d)
| where ActionType has_any ("AndroidPermissionGranted", "AndroidVpnServiceStarted", "AndroidAppInstalled")
| where AdditionalFields has_any ("VPN", "android.permission.BIND_VPN_SERVICE")
| project Timestamp, DeviceName, ActionType, AdditionalFields
| take 100
```

*Note:* ToxicPanda is Android-only malware; native Defender XDR/Sentinel coverage for mobile is limited to MDE-for-Android/Intune signals, so exact table/column names (`ActionType`, `AdditionalFields`) must be validated against your tenant's mobile threat defense schema. No IOCs (APK names/hashes) were given in the source — this is purely behavior-based (VPN-permission abuse to block Google Play traffic) and will require environment-specific tuning or a switch to MTD/Intune-native alert queries.

> [1] WordlistLoader Delivers Amatera via ClickFix, SynkLoader Phishes Windows Passwords — https://thehackernews.com/2026/08/wordlistloader-delivers-amatera-via.html
> [2] Operation QUICSILVER Targets Myanmar Government and IT with QUICAgent Backdoor — https://thehackernews.com/2026/08/operation-quicsilver-targets-myanmar.html
> [3] ToxicPanda Android malware uses VPN permissions to block Google Play — https://www.bleepingcomputer.com/news/security/toxicpanda-android-malware-uses-vpn-permissions-to-block-google-play/

### 2026-08-25

*Generated 2026-08-25 13:34 UTC · model `claude-sonnet-5`*

_Lint: 9 KQL block(s) — structural checks passed. All queries are CANDIDATES; validate before use._

#### Zimbra Collaboration Suite RCE — Post-Exploitation Shell Spawn
- **Actor / Campaign:** Unattributed mass-exploitation campaign (270+ Zimbra servers)
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application; T1505.003 — Web Shell
- **Data source:** DeviceProcessEvents, DeviceFileEvents
- **Source:** [1]

```kql
// Zimbra (ZCS) runs mailboxd under a Java process; shells spawned from it are a strong post-RCE indicator
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("java.exe","java")
| where FileName in~ ("sh","bash","cmd.exe","powershell.exe","curl","wget","python3","perl")
| where InitiatingProcessCommandLine has_any ("zimbra", "mailboxd", "zmmailbox")
    or InitiatingProcessFolderPath has_any ("/opt/zimbra", "zimbra")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, AccountName
| take 100
```

*Note:* Tune the Zimbra path/command-line filters to your environment's install path; legitimate admin scripts under zimbra service accounts can trigger this, so validate against known maintenance jobs.

#### Suspicious File Drop in Zimbra Webapp Directories (Webshell)
- **Actor / Campaign:** Unattributed mass-exploitation campaign (270+ Zimbra servers)
- **MITRE ATT&CK:** T1505.003 — Server Software Component: Web Shell
- **Data source:** DeviceFileEvents
- **Source:** [1]

```kql
DeviceFileEvents
| where Timestamp > ago(30d)
| where FolderPath has_any ("/zimbra/", "mailboxd/webapps")
| where FileName endswith_cs ".jsp" or FileName endswith_cs ".jspx" or FileName endswith_cs ".war"
| where InitiatingProcessFileName in~ ("java.exe","java")
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, InitiatingProcessCommandLine
| take 100
```

*Note:* Baseline against normal ZCS update/patch operations that legitimately write JSP/WAR files; flag only unexpected file names or off-hours drops.

#### npm/unpkg Mirror Redirect to Fake CAPTCHA (ClickFix-style)
- **Actor / Campaign:** Unattributed npm/ClickFix phishing infra abuse
- **MITRE ATT&CK:** T1204.001 — User Execution: Malicious Link; T1583.006 — Acquire Infrastructure: Web Services
- **Data source:** DeviceNetworkEvents
- **Source:** [2]

```kql
DeviceNetworkEvents
| where Timestamp > ago(2d)
| where RemoteUrl has "unpkg.com"
| where RemoteUrl has_any ("captcha", "cloudflare", "verify", "checking")
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP, InitiatingProcessCommandLine
| take 100
```

*Note:* No specific package names/hashes were published; tune the URL keyword list as IOCs emerge, and expect noise from legitimate unpkg CDN traffic — pair with browser-process context (edge/chrome navigating from email/redirect).

#### ClickFix Pattern: Clipboard-Paste Execution via mshta/PowerShell
- **Actor / Campaign:** WordlistLoader → Amatera Stealer / ClearFake; also relevant to [2]
- **MITRE ATT&CK:** T1204.004 — User Execution: Malicious Copy and Paste; T1027 — Obfuscated Files or Information
- **Data source:** DeviceProcessEvents
- **Source:** [6], [2]

```kql
DeviceProcessEvents
| where Timestamp > ago(2d)
| where FileName in~ ("mshta.exe","powershell.exe","pwsh.exe","cmd.exe")
| where ProcessCommandLine has_any ("IEX", "Invoke-Expression", "DownloadString", "FromBase64String", "-w hidden", "-windowstyle hidden")
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe")  // typical ClickFix parent when launched via Win+R
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| take 100
```

*Note:* This is the generic ClickFix/FakeCaptcha "paste-and-run" behavioral signature; expect false positives from legitimate admin scripting — correlate with recent browser navigation to unfamiliar domains for higher fidelity.

#### SynkLoader-style Fake Credential Prompt / Password Harvesting
- **Actor / Campaign:** SynkLoader (Gen Digital reporting)
- **MITRE ATT&CK:** T1056.002 — Input Capture: GUI Input Capture; T1555 — Credentials from Password Stores
- **Data source:** DeviceProcessEvents, DeviceFileEvents
- **Source:** [6]

```kql
DeviceProcessEvents
| where Timestamp > ago(2d)
| where ProcessCommandLine has_any ("credui", "LogonUI", "password", "sign in to continue") 
| where FileName !in~ ("LogonUI.exe", "consent.exe")  // exclude legit OS binaries
| where InitiatingProcessFileName has_any ("mshta.exe","powershell.exe","wscript.exe","cscript.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| take 100
```

*Note:* Behavioral/heuristic only — no IOCs published for SynkLoader; this looks for non-OS binaries mimicking Windows credential dialogs. Requires tuning to your environment to reduce noise from legitimate MFA/credential tools.

#### Outbound FTP Banner Grab Followed by New C2 Connection (Dead Drop Resolver Pattern)
- **Actor / Campaign:** E4del / PINHOLE RATs
- **MITRE ATT&CK:** T1102 — Web Service (Dead Drop Resolver); T1071.001 — Application Layer Protocol
- **Data source:** DeviceNetworkEvents
- **Source:** [3]

```kql
// Flag non-standard processes connecting to FTP (port 21) shortly before establishing a new outbound connection — potential DDR-to-C2 pivot
let ftpConnections = DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort == 21
| where InitiatingProcessFileName !in~ ("ftp.exe","filezilla.exe","winscp.exe","curl.exe")
| project DeviceName, ftpTime = Timestamp, InitiatingProcessFileName, InitiatingProcessCommandLine, RemoteIP;
ftpConnections
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(7d)
    | where RemotePort !in (21,80,443)
    | project DeviceName, c2Time = Timestamp, RemoteIP2 = RemoteIP, RemotePort, InitiatingProcessFileName
) on DeviceName
| where c2Time between (ftpTime .. ftpTime + 10m)
| project DeviceName, ftpTime, InitiatingProcessFileName, c2Time, RemoteIP2, RemotePort
| take 100
```

*Note:* Highly heuristic — designed to surface unusual FTP-then-pivot behavior since no concrete IOCs were published for E4del/PINHOLE; expect false positives in environments with legitimate scripted FTP workflows, tune time window and excluded processes accordingly.

#### Suspected QUICAgent Backdoor — QUIC/UDP-443 from Non-Browser Process
- **Actor / Campaign:** Operation QUICSILVER (China-nexus, targeting Myanmar govt/IT)
- **MITRE ATT&CK:** T1071.001 — Application Layer Protocol: Web Protocols; T1071.004 — DNS/QUIC-based C2; T1566.001 — Spearphishing Attachment
- **Data source:** DeviceNetworkEvents, DeviceProcessEvents
- **Source:** [8]

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort == 443 and Protocol == "Udp"
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe","opera.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteIP, RemoteUrl, InitiatingProcessCommandLine
| take 100
```

*Note:* QUIC (UDP/443) from non-browser binaries is unusual and worth investigating for Go-compiled backdoors like QUICAgent; correlate with recent execution of "graduation ceremony invitation" themed lure files (DeviceFileEvents on .lnk/.zip/.iso attachments) for higher confidence.

#### Spearphishing Lure Execution Chain (Graduation Invitation Theme)
- **Actor / Campaign:** Operation QUICSILVER
- **MITRE ATT&CK:** T1566.001 — Spearphishing Attachment; T1204.002 — User Execution: Malicious File
- **Data source:** DeviceFileEvents, DeviceProcessEvents
- **Source:** [8]

```kql
DeviceFileEvents
| where Timestamp > ago(7d)
| where FileName has_any ("invitation","graduation","ceremony") 
| where FileName endswith ".lnk" or FileName endswith ".iso" or FileName endswith ".zip" or FileName endswith ".exe"
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessFileName, SHA256
| take 100
```

*Note:* No file hashes were published; this is a filename-theme heuristic that should be combined with the QUIC network detection above and refined once concrete IOCs are released.

#### Oracle HTTP Server / WebLogic Proxy Plug-in Post-Exploitation Command Execution
- **Actor / Campaign:** CVE-2026-21962 exploitation (KEV)
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application
- **Data source:** DeviceProcessEvents
- **Source:** [7], [9]

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("httpd.exe","httpd.worker","java.exe","java")
| where InitiatingProcessCommandLine has_any ("weblogic", "OHS", "mod_wl_ohs")
| where FileName in~ ("cmd.exe","powershell.exe","sh","bash","wget","curl","nc","nc.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, AccountName
| take 100
```

*Note:* CVE-2026-21962 is an improper access control flaw in the WebLogic Proxy Plug-in; this query is behavioral (shell spawned from the web/proxy tier) since no public exploit request pattern was detailed — prioritize patching per CISA BOD 26-04 and validate hits against known admin automation.

> [1] Hackers breached over 270 Zimbra servers in ongoing attacks — https://www.bleepingcomputer.com/news/security/hackers-breached-over-270-zimbra-servers-in-ongoing-attacks/
> [2] 24 npm Packages Abuse unpkg Mirrors to Host Fake Cloudflare CAPTCHA Pages — https://thehackernews.com/2026/08/24-npm-packages-abuse-unpkg-mirrors-to.html
> [3] E4del and PINHOLE RATs Turn FTP Banners Into Dead Drops for Malware Commands — https://thehackernews.com/2026/08/e4del-and-pinhole-rats-turn-ftp-banners.html
> [6] WordlistLoader Delivers Amatera via ClickFix, SynkLoader Phishes Windows Passwords — https://thehackernews.com/2026/08/wordlistloader-delivers-amatera-via.html
> [7] CISA Adds One Known Exploited Vulnerability to Catalog — https://www.cisa.gov/news-events/alerts/2026/08/24/cisa-adds-one-known-exploited-vulnerability-catalog
> [8] Operation QUICSILVER Targets Myanmar Government and IT with QUICAgent Backdoor — https://thehackernews.com/2026/08/operation-quicsilver-targets-myanmar.html
> [9] CVE-2026-21962 — Oracle HTTP Server and Oracle Weblogic Server Proxy Plug-in Improper Access Control Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2026-21962

### 2026-08-26

*Generated 2026-08-26 13:37 UTC · model `claude-sonnet-5`*

_Lint: 7 KQL block(s) — structural checks passed. All queries are CANDIDATES; validate before use._

#### Unsigned side-loaded DLL awaiting a "magic packet" (possible SLEEPWALKER backdoor)
- **Actor / Campaign:** unattributed (independent researcher disclosure)
- **MITRE ATT&CK:** T1574.002 — Hijack Execution Flow: DLL Side-Loading; T1205 — Traffic Signaling
- **Data source:** DeviceImageLoadEvents, DeviceFileCertificateInfo
- **Source:** [2]

```kql
// SLEEPWALKER is reported as an unsigned 64-bit DLL, 59,904 bytes, built for side-loading.
// No hashes were published, so hunt on the reported file-size heuristic + unsigned status.
DeviceImageLoadEvents
| where FileSize == 59904
| where FileName endswith ".dll"
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, InitiatingProcessFileName, SHA256
| join kind=leftouter (
    DeviceFileCertificateInfo
    | project SHA256, IsSigned, Signer
) on SHA256
| where IsSigned == false or isempty(Signer)
| take 100
```

*Note:* Purely heuristic (file size + unsigned status) since no hash/filename IOCs were released; expect FPs from legitimate small unsigned DLLs — pivot to processes that then open a listening socket with no outbound traffic for long periods to further narrow.

#### Suspicious child process spawned by Zimbra collaboration suite (mass exploitation)
- **Actor / Campaign:** unattributed, opportunistic mass exploitation (270+ ZCS servers)
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application
- **Data source:** DeviceProcessEvents
- **Source:** [8]

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName has_any ("zmmailboxd", "mailboxd", "java")
| where InitiatingProcessCommandLine has_any ("zimbra", "zmmailboxd")
| where FileName in~ ("sh", "bash", "curl", "wget", "python3", "perl", "nc")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| take 100
```

*Note:* No specific IOCs published; tune to your Zimbra parent-process names/paths. High-fidelity only if Zimbra hosts are onboarded to Defender for Endpoint (Linux sensor).

#### Emails/links pointing to npm/unpkg-hosted fake CAPTCHA pages
- **Actor / Campaign:** unattributed (npm/unpkg phishing redirect abuse — 24 packages)
- **MITRE ATT&CK:** T1608.001 — Stage Capabilities: Upload Malware; T1204.001 — User Execution: Malicious Link
- **Data source:** EmailEvents, EmailUrlInfo
- **Source:** [4], [16]

```kql
EmailEvents
| where Timestamp > ago(7d)
| join kind=inner (EmailUrlInfo) on NetworkMessageId
| where Url has_any ("unpkg.com", "npmjs.org", "jsdelivr.net")
| where Url has_any ("captcha", "verify", "cloudflare", "checking-your-browser")
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, Url, NetworkMessageId
| take 100
```

*Note:* unpkg.com/jsdelivr are legitimate CDNs, so combine with the suspicious path keywords shown; validate against known-good developer traffic before alerting broadly.

#### Endpoint navigation to npm-mirror-hosted ClickFix-style CAPTCHA redirect
- **Actor / Campaign:** unattributed (24-package npm/unpkg cluster)
- **MITRE ATT&CK:** T1204.001 — User Execution: Malicious Link; T1027 — Obfuscated Files or Information
- **Data source:** DeviceNetworkEvents
- **Source:** [4], [16]

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemoteUrl has "unpkg.com"
| where RemoteUrl has_any ("captcha", "verify-you-are-human", "cf-challenge")
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP
| take 100
```

*Note:* RemoteUrl field availability depends on proxy/TLS inspection integration; adjust to your network telemetry table (e.g., a proxy log table) if RemoteUrl isn't populated for HTTPS.

#### Outbound FTP banner grabs from non-FTP client processes (E4del/PINHOLE dead-drop resolver)
- **Actor / Campaign:** unattributed (E4del / PINHOLE RATs)
- **MITRE ATT&CK:** T1102 — Web Service (Dead Drop Resolver); T1071 — Application Layer Protocol
- **Data source:** DeviceNetworkEvents
- **Source:** [17]

```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemotePort == 21
| where InitiatingProcessFileName !in~ ("ftp.exe", "filezilla.exe", "winscp.exe", "curl.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessFolderPath, RemoteIP, RemoteUrl
| take 100
```

*Note:* Behavioral only — no IOCs were disclosed for E4del/PINHOLE. Flag repeated brief connections to varying FTP hosts (banner scraping) from unexpected processes like scripting interpreters or LOLBins; expect FPs from legitimate automation/backup tools using FTP.

#### Shell execution spawned by Gitea service (CVE-2026-60004 exploitation)
- **Actor / Campaign:** unattributed; CVE-2026-60004 added to CISA KEV
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application; T1546 — Event Triggered Execution (Git Hook)
- **Data source:** DeviceProcessEvents
- **Source:** [11], [19]

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName has "gitea"
| where FileName in~ ("sh", "bash", "cmd.exe", "powershell.exe", "python", "perl")
| where InitiatingProcessCommandLine has_any ("diffpatch", "hooks", "post-receive", "pre-receive")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, AccountName
| take 100
```

*Note:* Requires Gitea host to be onboarded to Defender for Endpoint (or equivalent Linux auditd ingestion); the vulnerability plants a malicious git hook via the diffpatch API and executes as the Gitea service account, so also alert on unexpected writes under `.git/hooks/`.

#### Kerberoasting-style SPN ticket requests (domain compromise TTP from CISA red team findings)
- **Actor / Campaign:** unattributed; CISA red team assessment findings
- **MITRE ATT&CK:** T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting
- **Data source:** SecurityEvent (Windows Security 4769)
- **Source:** [10]

```kql
SecurityEvent
| where EventID == 4769
| where TicketEncryptionType == "0x17" // RC4 - common kerberoasting indicator
| where TargetUserName !endswith "$" // exclude machine accounts
| summarize RequestCount = count(), DistinctSPNs = dcount(TargetUserName) by Account = SubjectUserName, IpAddress, bin(TimeGenerated, 1h)
| where RequestCount > 15
| order by RequestCount desc
| take 100
```

*Note:* Both red-team-assessed organizations reached full domain compromise; this is a generic, well-known Kerberoasting hunt to help detect the type of privilege-escalation activity described, not tied to a specific tool — tune the count threshold to your baseline SPN request volume.

> [2] New SLEEPWALKER Backdoor Waits for One Crafted Packet, Then Runs Its Own Bytecode — https://thehackernews.com/2026/08/newly-sleepwalker-backdoor-waits-for.html
> [4] Hackers abuse npm mirrors to host phishing redirect pages — https://www.bleepingcomputer.com/news/security/hackers-abuse-npm-mirrors-to-host-phishing-redirect-pages/
> [8] Hackers breached over 270 Zimbra servers in ongoing attacks — https://www.bleepingcomputer.com/news/security/hackers-breached-over-270-zimbra-servers-in-ongoing-attacks/
> [10] A Tale of Two SOCs: Insights From Two Red Team Assessments — https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-237a
> [11] CISA Adds One Known Exploited Vulnerability to Catalog — https://www.cisa.gov/news-events/alerts/2026/08/25/cisa-adds-one-known-exploited-vulnerability-catalog
> [16] 24 npm Packages Abuse unpkg Mirrors to Host Fake Cloudflare CAPTCHA Pages — https://thehackernews.com/2026/08/24-npm-packages-abuse-unpkg-mirrors-to.html
> [17] E4del and PINHOLE RATs Turn FTP Banners Into Dead Drops for Malware Commands — https://thehackernews.com/2026/08/e4del-and-pinhole-rats-turn-ftp-banners.html
> [19] CVE-2026-60004 — Gitea Gitea: Gitea Code Injection Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2026-60004

### 2026-08-27

*Generated 2026-08-27 16:57 UTC · model `claude-sonnet-5`*

_Lint: 10 KQL block(s) — structural checks passed. All queries are CANDIDATES; validate before use._

#### PaperCut NG/MF Zero-Day Exploitation — Suspicious Child Process from Print Server
- **Actor / Campaign:** unattributed
- **MITRE ATT&CK:** T1210 — Exploitation of Remote Services
- **Data source:** DeviceProcessEvents
- **Source:** [1]

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("pc-app.exe","PCClient.exe","pc-server.exe","tomcat9.exe","javaw.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","cscript.exe","wscript.exe","mshta.exe","certutil.exe")
| where InitiatingProcessFolderPath has_any ("PaperCut","papercut")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, FileName, ProcessCommandLine, AccountName
| take 100
```

*Note:* No PaperCut IOCs were published; this is a behavioral hunt for the historically-observed PaperCut RCE pattern (web app spawning a shell). Validate PaperCut install paths in your environment and tune to your PaperCut service/process names.

#### PaperCut NG/MF — Outbound Connections from Print Server to Uncommon Hosts Post-Exploit
- **Actor / Campaign:** unattributed
- **MITRE ATT&CK:** T1105 — Ingress Tool Transfer
- **Data source:** DeviceNetworkEvents
- **Source:** [1]

```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("pc-app.exe","PCClient.exe","pc-server.exe","javaw.exe")
| where RemoteIPType == "Public"
| where isnotempty(RemoteUrl) or isnotempty(RemoteIP)
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort
| take 100
```

*Note:* Zero-day details/IOCs are not yet public; this flags any outbound activity initiated by PaperCut processes for manual triage — baseline normal PaperCut external calls (license checks, updates) before enabling as an alert.

#### GoCaracal-Style C2 Resolution via Ethereum Smart Contract Call
- **Actor / Campaign:** Dark Caracal (GoCaracal, medium confidence)
- **MITRE ATT&CK:** T1568.002 — Dynamic Resolution: Domain Generation Algorithms (analogous: blockchain-based C2 lookup)
- **Data source:** DeviceNetworkEvents
- **Source:** [7]

```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemoteUrl has_any ("infura.io","alchemy.com","etherscan.io","eth-mainnet","rpc.ankr.com","cloudflare-eth.com")
| where InitiatingProcessFileName !in~ ("chrome.exe","msedge.exe","firefox.exe","brave.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, RemoteUrl, RemoteIP, AccountName
| take 100
```

*Note:* Behavioral hunt only — no GoCaracal hashes/domains were disclosed. Flags non-browser processes querying Ethereum RPC/explorer endpoints, a technique used by GoCaracal to fetch a replacement C2 address; expect FPs from crypto-wallet or dev tooling and tune the process allowlist.

#### GoCaracal-Style Go Binary with Remote Shell / Keylogger Behavior
- **Actor / Campaign:** Dark Caracal (GoCaracal)
- **MITRE ATT&CK:** T1059 — Command and Scripting Interpreter, T1056 — Input Capture
- **Data source:** DeviceProcessEvents, DeviceImageLoadEvents
- **Source:** [7]

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName has_any (".exe") and InitiatingProcessCommandLine has_any ("golang","GOMAXPROCS","runtime.")
| where ProcessCommandLine has_any ("-shell","-keylog","-rdp","-c2","-payload")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, AccountName
| take 100
```

*Note:* Heuristic and likely low-yield without a known binary signature; use as a starting hunt query for unsigned Go binaries with shell/keylog/RDP command-line flags rather than a production alert.

#### Nimbus Manticore — SSH Tunneling Tool Launched by Unusual Parent Process
- **Actor / Campaign:** Nimbus Manticore (Iranian IRGC-affiliated)
- **MITRE ATT&CK:** T1572 — Protocol Tunneling
- **Data source:** DeviceProcessEvents
- **Source:** [9]

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("plink.exe","ssh.exe","putty.exe")
| where ProcessCommandLine has_any ("-R ","-L ","-D ","-N ","-ssh")
| where InitiatingProcessFileName !in~ ("explorer.exe","cmd.exe","powershell.exe")
| project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessFolderPath, AccountName
| take 100
```

*Note:* Group-IB's report on Nimbus Manticore's SSH tunneler/backdoor did not include specific filenames or hashes in the summary provided; this looks for anomalous SSH/tunnel tooling launched from non-interactive parents. Tune out legitimate admin/DevOps SSH usage.

#### Nimbus Manticore — New Backdoor Persistence via Scheduled Task / Run Key
- **Actor / Campaign:** Nimbus Manticore
- **MITRE ATT&CK:** T1053.005 — Scheduled Task, T1547.001 — Registry Run Keys
- **Data source:** DeviceProcessEvents, DeviceRegistryEvents
- **Source:** [9]

```kql
DeviceRegistryEvents
| where Timestamp > ago(14d)
| where RegistryKey has @"\Software\Microsoft\Windows\CurrentVersion\Run"
| where InitiatingProcessFileName !in~ ("explorer.exe","msiexec.exe","setup.exe")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData, InitiatingProcessFileName, AccountName
| take 100
```

*Note:* Generic persistence hunt aligned with Nimbus Manticore's TWOSTROKE-like backdoor behavior; no concrete registry paths were published, so expect broad results requiring baselining against known-good software.

#### NovaCookies AitM — Docusign-Themed Phishing Redirect Emails
- **Actor / Campaign:** NovaCookies phishing-as-a-service
- **MITRE ATT&CK:** T1566.002 — Phishing: Spearphishing Link, T1557 — AitM
- **Data source:** EmailEvents, EmailUrlInfo
- **Source:** [10]

```kql
EmailEvents
| where Timestamp > ago(14d)
| join kind=inner (EmailUrlInfo) on NetworkMessageId
| where SenderFromAddress has "docusign" or Subject has_any ("DocuSign","Please DocuSign","Completed:")
| where Url !has "docusign.net" and Url !has "docusign.com"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, Url
| take 100
```

*Note:* Looks for genuine-looking Docusign notification emails whose embedded links do not resolve to legitimate Docusign domains, matching the NovaCookies AitM redirect technique; validate against your tenant's actual Docusign integration to avoid FPs from legitimate signing links using custom domains.

#### NovaCookies AitM — M365 Sign-in Immediately Following External Redirect Link Click
- **Actor / Campaign:** NovaCookies phishing-as-a-service
- **MITRE ATT&CK:** T1557 — Adversary-in-the-Middle, T1550.004 — Use of Web Session Cookie
- **Data source:** SigninLogs
- **Source:** [10]

```kql
SigninLogs
| where TimeGenerated > ago(14d)
| where ResultType == 0
| where AuthenticationRequirement == "singleFactorAuthentication" or ConditionalAccessStatus == "notApplied"
| where AppDisplayName has_any ("Office 365","Microsoft 365")
| summarize LogonCount = count(), IPs = make_set(IPAddress), Countries = make_set(Location) by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(IPs) > 1
| take 100
```

*Note:* Heuristic for session-cookie replay after AitM capture (multiple IPs/locations for the same user in a short window); requires tuning against corporate VPN egress and known travel patterns to reduce FPs.

#### SQL Server RCE (CVE-2019-1068) — sqlservr.exe Spawning Command Interpreter
- **Actor / Campaign:** unattributed (KEV-listed actively exploited CVE)
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application
- **Data source:** DeviceProcessEvents
- **Source:** [11][18]

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "sqlservr.exe"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","certutil.exe","mshta.exe","bcp.exe","xp_cmdshell.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName
| take 100
```

*Note:* Classic post-exploitation pattern for SQL Server RCE/xp_cmdshell abuse now added to KEV; legitimate DBA scripts using xp_cmdshell will trigger this, so cross-reference with change tickets before escalating.

#### Ajax.NET Professional Deserialization RCE (CVE-2021-23758) — IIS Worker Process Spawning Shell
- **Actor / Campaign:** unattributed (KEV-listed actively exploited CVE)
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application, T1059.003 — Windows Command Shell
- **Data source:** DeviceProcessEvents
- **Source:** [11][13]

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "w3wp.exe"
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","csc.exe","cscript.exe")
| where InitiatingProcessCommandLine has_any ("ajaxpro","AjaxPro.axd")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| take 100
```

*Note:* AjaxPro is EoL and rarely still deployed; this hunts for the deserialization-to-shell pattern via the /ajaxpro/*.axd handler. If AjaxPro isn't in your environment, deprioritize this query.

> [1] PaperCut warns of NG, MF flaw exploited in zero-day attacks — https://www.bleepingcomputer.com/news/security/papercut-warns-of-ng-mf-flaw-exploited-in-zero-day-attacks/
> [7] GoCaracal Malware Uses Ethereum Smart Contract to Fetch Replacement C2 Address — https://thehackernews.com/2026/08/gocaracal-malware-uses-ethereum-smart.html
> [9] Nimbus Manticore Expands Toolset With TWOSTROKE-Like Backdoor and SSH Tunneler — https://thehackernews.com/2026/08/nimbus-manticore-expands-toolset-with.html
> [10] NovaCookies Campaigns Abuse Genuine Docusign Notifications to Steal Microsoft 365 Sessions — https://thehackernews.com/2026/08/novacookies-campaigns-abuse-genuine.html
> [11] CISA Adds Six Known Exploited Vulnerabilities to Catalog — https://www.cisa.gov/news-events/alerts/2026/08/26/cisa-adds-six-known-exploited-vulnerabilities-catalog
> [13] CVE-2021-23758 — Ajax.NET Professional Deserialization of Untrusted Data Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2021-23758
> [18] CVE-2019-1068 — Microsoft SQL Server Remote Code Execution Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2019-1068

### 2026-08-28

*Generated 2026-08-28 17:22 UTC · model `claude-sonnet-5`*

_Lint: 7 KQL block(s) — query 4: unbalanced '()'. All queries are CANDIDATES; validate before use._

#### PaperCut Server Spawning Shell/Script Post-Exploitation (Zero-Day)
- **Actor / Campaign:** Unattributed (PaperCut NG/MF zero-day, actively exploited)
- **MITRE ATT&CK:** T1210 — Exploitation of Remote Services; T1059 — Command and Scripting Interpreter
- **Data source:** DeviceProcessEvents
- **Source:** [3][6]

```kql
// No public IOCs released yet for the PaperCut zero-day; hunt for the classic
// post-exploitation pattern of the PaperCut server process (Java/Jetty backend)
// spawning a command interpreter, mirroring prior PaperCut RCE abuse patterns.
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("java.exe", "javaw.exe", "pc-app.exe", "PCAppServer.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe", "mshta.exe", "rundll32.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath,
          FileName, ProcessCommandLine, AccountName
| take 100
```

*Note:* PaperCut server processes rarely spawn interpreters under normal operation; validate host actually runs PaperCut NG/MF and check patch status/version before treating as high-confidence. Tune process names to your specific PaperCut install path.

#### Suspicious Batch Script Persistence Consistent with APT28 HOOKEDGE Backdoor
- **Actor / Campaign:** APT28 (Fancy Bear) — HOOKEDGE backdoor
- **MITRE ATT&CK:** T1059.003 — Windows Command Shell; T1053.005 — Scheduled Task; T1071 — Application Layer Protocol (C2)
- **Data source:** DeviceProcessEvents
- **Source:** [4]

```kql
// HOOKEDGE is reported as a lightweight Windows batch-script backdoor targeting
// European gov/diplomatic entities. Hunt for .bat scripts creating persistence
// (scheduled tasks / run keys) or making outbound network calls via LOLBins.
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("cmd.exe")
| where ProcessCommandLine has ".bat"
| where ProcessCommandLine has_any ("schtasks", "reg add", "curl", "certutil", "bitsadmin", "powershell")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName, FolderPath
| take 100
```

*Note:* Highly heuristic — batch scripts and schtasks are common in legitimate admin activity; scope to gov/diplomatic tenants, review script content/paths (temp/download dirs, email attachment origin) and correlate with recent Office/email delivery.

#### cPanel/WHM Root Process Spawn Following Domain Parking Exploit
- **Actor / Campaign:** Unattributed (CVE-2026-65643 cPanel/WHM critical RCE)
- **MITRE ATT&CK:** T1068 — Exploitation for Privilege Escalation
- **Data source:** DeviceProcessEvents
- **Source:** [2]

```kql
// CVE-2026-65643 allows a hosting customer to gain root via domain
// parking/addon domain handling. Hunt for cpsrvd/whostmgr spawning
// unexpected shells or privilege-escalating child processes as root.
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("cpsrvd", "whostmgrd", "cpanel", "cpanellogd")
| where FileName in~ ("bash", "sh", "python3", "perl", "su", "sudo")
| where InitiatingProcessAccountName == "root" or AccountName == "root"
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName
| take 100
```

*Note:* Requires Defender for Servers / Linux sensor coverage on cPanel hosts; expect noise from legitimate cPanel maintenance scripts — baseline normal cpsrvd child processes before alerting.

#### Command-Injection Style Requests to Chinese-Manufactured Embedded/Router Management Interfaces
- **Actor / Campaign:** Unattributed (ZBT router implants SPEAKINGSTONE/DARKLANTERN; Xiiaozet LK100W; Ebyte NA111-M)
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application; T1078 — Valid Accounts (auth bypass)
- **Data source:** CommonSecurityLog, DeviceNetworkEvents
- **Source:** [1][8][10]

```kql
// Behavioral hunt for OS command-injection attempts against embedded/router
// web management interfaces (ZBT/Xiiaozet/Ebyte families report unauthenticated
// root command execution / auth-bypass CVEs). No public network IOCs supplied.
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where RequestURL has_any ("cgi-bin", "goform", "setup.cgi", "adm.cgi")
| where RequestURL has_any (";", "|", "$(", "`", "&&", "wget ", "curl ")
| project TimeGenerated, DeviceVendor, SourceIP, DestinationIP, RequestURL, DeviceAction
| take 100
```

*Note:* These are embedded devices typically outside EDR coverage — this relies on perimeter firewall/WAF logs ingested via CommonSecurityLog; adjust field/parser names to your actual log source and expect false positives from legitimate query strings containing special characters.

#### JFrog Artifactory Writes Outside Expected Docker Cache Path (CVE-2026-66384)
- **Actor / Campaign:** Unattributed (CISA KEV — actively exploited)
- **MITRE ATT&CK:** T1211 — Exploitation for Defense Evasion; T1083 — File and Directory Discovery (path traversal)
- **Data source:** DeviceFileEvents
- **Source:** [9][15]

```kql
// CVE-2026-66384: authenticated user can write outside the intended Docker
// cache path via a remote-repository path traversal condition.
DeviceFileEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName has_any ("artifactory", "java")
| where FolderPath has "artifactory"
| where FolderPath !has @"cache\docker" and FolderPath !has "docker-cache"
| where FolderPath has_any ("../", "..\\")
| project Timestamp, DeviceName, FolderPath, FileName, InitiatingProcessAccountName
| take 100
```

*Note:* Requires host-based sensor coverage on Artifactory servers; tune folder-path patterns to your Artifactory storage layout, and confirm patch level (this is a KEV-listed, actively exploited flaw).

#### ownCloud Unauthenticated File Access via Known-Username Auth Bypass (CVE-2023-49105)
- **Actor / Campaign:** Unattributed (CISA KEV — actively exploited)
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application; T1078 — Valid Accounts
- **Data source:** CommonSecurityLog / AADNonInteractiveUserSignInLogs (adjust to your ownCloud auth log ingestion)
- **Source:** [9][13]

```kql
// CVE-2023-49105: attacker can access/modify/delete files without
// authentication if a victim username is known and no signing-key is set.
// Hunt for WebDAV requests succeeding without a prior successful auth event.
CommonSecurityLog
| where TimeGenerated > ago(14d)
| where RequestURL has "remote.php/dav"
| where DeviceAction in ("PROPFIND", "GET", "PUT", "DELETE")
| where isempty(RequestClientApplication) or RequestURL !has "Authorization"
| project TimeGenerated, SourceIP, DestinationIP, RequestURL, DeviceAction
| take 100
```

*Note:* Log field names will vary heavily by reverse-proxy/WAF vendor exporting to CommonSecurityLog; this is a template — validate against your actual ownCloud/WebDAV access log schema, and prioritize hosts still unpatched per BOD 26-04.

#### Suspicious Network Activity from Compromised OSS Security Tooling (Trivy / Checkmarx KICS / LiteLLM)
- **Actor / Campaign:** TeamPCP (March 2026 supply-chain compromise; suspects charged 2026-08-27)
- **MITRE ATT&CK:** T1195.001 — Compromise Software Dependencies and Development Tools; T1071 — Application Layer Protocol
- **Data source:** DeviceProcessEvents, DeviceNetworkEvents
- **Source:** [7][12]

```kql
// TeamPCP compromised Trivy, Checkmarx KICS, and LiteLLM in March 2026.
// Hunt CI/build hosts for these tools making unexpected outbound connections
// (no specific C2 IOCs published; behavioral only).
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName has_any ("trivy", "kics", "litellm")
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteIPType == "Public"
) on DeviceId
| where abs(datetime_diff('second', Timestamp, Timestamp1)) < 60
| project Timestamp, DeviceName, FileName, ProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
| take 100
```

*Note:* No malicious hashes/domains were provided in the reporting; this simply flags CI/build systems running the named tools that also initiate unexpected external connections — validate against known package registries/CDNs to reduce noise, and confirm tool versions against the disclosed compromised releases.

> [1] China-Made ZBT Routers Ship With Two Implants Giving Unauthenticated Attackers Root Access — https://thehackernews.com/2026/08/china-made-zbt-routers-ship-with-two.html
> [2] Critical cPanel Flaw Could Let One Hosting Customer Take Root Control of a Whole Server — https://thehackernews.com/2026/08/critical-cpanel-flaw-could-let-one.html
> [3] PaperCut Zero-Day Exploited in Attacks, Affecting All NG and MF Versions — https://thehackernews.com/2026/08/papercut-zero-day-exploited-in-attacks.html
> [4] APT28-Linked HOOKEDGE Backdoor Targets European Government and Diplomatic Organizations — https://thehackernews.com/2026/08/apt28-linked-hookedge-backdoor-targets.html
> [6] PaperCut warns of NG, MF flaw exploited in zero-day attacks — https://www.bleepingcomputer.com/news/security/papercut-warns-of-ng-mf-flaw-exploited-in-zero-day-attacks/
> [7] Australia arrests alleged TeamPCP hackers behind supply-chain attacks — https://www.bleepingcomputer.com/news/security/australia-arrests-alleged-teampcp-hackers-behind-supply-chain-attacks/
> [8] Xiiaozet LK100W — https://www.cisa.gov/news-events/ics-advisories/icsa-26-239-01
> [9] CISA Adds Three Known Exploited Vulnerabilities to Catalog — https://www.cisa.gov/news-events/alerts/2026/08/27/cisa-adds-three-known-exploited-vulnerabilities-catalog
> [10] Ebyte NA111-M — https://www.cisa.gov/news-events/ics-advisories/icsa-26-239-05
> [12] Alleged TeamPCP Hackers Charged in Australia Over Major Supply Chain Attacks — https://thehackernews.com/2026/08/alleged-teampcp-hackers-charged-in.html
> [13] CVE-2023-49105 — ownCloud ownCloud: ownCloud Improper Authentication Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2023-49105
> [15] CVE-2026-66384 — JFrog Artifactory: JFrog Artifactory Improper Limitation of a Pathname to a Restricted Directory Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2026-66384

### 2026-08-29

*Generated 2026-08-29 13:21 UTC · model `claude-sonnet-5`*

_Lint: 7 KQL block(s) — query 5: unbalanced '()'. All queries are CANDIDATES; validate before use._

#### ClickFix-style clipboard execution via Run dialog (TerminalFix)
- **Actor / Campaign:** TerminalFix (unattributed cluster tracked by Microsoft)
- **MITRE ATT&CK:** T1204.004 — User Execution: Malicious Copy and Paste
- **Data source:** DeviceProcessEvents
- **Source:** [1]

```kql
// ClickFix pattern: explorer.exe directly spawns a script host / LOLBin
// (user pasted a "verification" command from a fake CAPTCHA page into Win+R)
DeviceProcessEvents
| where Timestamp > ago(2d)
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName in~ ("mshta.exe","powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","curl.exe","conhost.exe")
| where ProcessCommandLine has_any ("captcha","verify","robot","cloudflare","recaptcha","i am human") 
    or ProcessCommandLine has_any ("iex","downloadstring","-enc","frombase64string")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| take 100
```

*Note:* Tune the keyword list to your environment's phishing lures; ClickFix lures rotate often, so also alert on any explorer.exe → mshta.exe/powershell.exe parent-child relationship regardless of command-line content, then review manually.

#### DLL sideloading from user-writable path following suspicious execution
- **Actor / Campaign:** TerminalFix
- **MITRE ATT&CK:** T1574.002 — Hijack Execution Flow: DLL Side-Loading
- **Data source:** DeviceImageLoadEvents, DeviceProcessEvents
- **Source:** [1]

```kql
// Legitimate signed binary loading a DLL from a user-writable / temp / download folder
DeviceImageLoadEvents
| where Timestamp > ago(2d)
| where FolderPath has_any (@"\AppData\Local\Temp\", @"\Downloads\", @"\AppData\Roaming\")
| where InitiatingProcessFolderPath !has @"\Windows\System32"
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(2d)
    | where InitiatingProcessFileName =~ "explorer.exe" or ProcessCommandLine has_any ("verify","captcha")
) on $left.InitiatingProcessSHA256 == $right.SHA256
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, FolderPath
| take 100
```

*Note:* High false-positive potential from legitimate portable apps; correlate with the ClickFix execution chain above or with newly-created/rarely-seen signed binaries in the same folder for higher confidence.

#### Outbound reverse-tunnel connection from LOLBin process
- **Actor / Campaign:** TerminalFix
- **MITRE ATT&CK:** T1572 — Protocol Tunneling
- **Data source:** DeviceNetworkEvents
- **Source:** [1]

```kql
// LOLBins/interpreters establishing outbound connections shortly after a ClickFix-style launch
DeviceNetworkEvents
| where Timestamp > ago(2d)
| where InitiatingProcessFileName in~ ("powershell.exe","pwsh.exe","mshta.exe","cmd.exe","rundll32.exe","regsvr32.exe")
| where RemotePort !in (80,443)
| where isnotempty(RemoteIP)
| summarize ConnCount=count(), Ports=make_set(RemotePort) by DeviceName, InitiatingProcessFileName, RemoteIP, bin(Timestamp,1h)
| where ConnCount > 3
| take 100
```

*Note:* Non-standard ports from scripting hosts are heuristic; expect noise from legitimate admin tooling and RMM software — no concrete tunnel infrastructure IOCs were published in [1], so validate against known-good remote management tools in your estate.

#### Web-server process spawning shell after possible ownCloud CVE-2023-49105 exploitation
- **Actor / Campaign:** Chinese-speaking threat actor targeting Philippine nuclear research body
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application
- **Data source:** DeviceProcessEvents (Linux/Windows sensor on the web/app server)
- **Source:** [3]

```kql
// PHP/Apache/nginx worker process unexpectedly spawning a shell or interpreter
// (common post-exploitation pattern for ownCloud pre-auth signature bypass -> RCE/webshell)
DeviceProcessEvents
| where Timestamp > ago(2d)
| where InitiatingProcessFileName has_any ("php","php-fpm","httpd","apache2","nginx")
| where FileName in~ ("sh","bash","curl","wget","python3","perl","id","whoami","cmd.exe","powershell.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| take 100
```

*Note:* Standard "webshell child process" heuristic — expect FPs from legitimate cron/health-check scripts; scope to hosts running ownCloud and prioritize alerts where the target CVE-2023-49105 KEV entry applies and the server was not yet patched.

#### Unauthenticated command-injection attempts against ZBT router admin interface
- **Actor / Campaign:** unattributed (ZBT SPEAKINGSTONE / DARKLANTERN factory implants)
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application / T1200 — Hardware Additions (supply-chain implant)
- **Data source:** CommonSecurityLog / AzureFirewall / DeviceNetworkEvents (perimeter/firewall telemetry)
- **Source:** [4]

```kql
// Behavioral hunt for unauthenticated CGI command-injection attempts against embedded router admin panels
// No published IOCs for CVE-2026-74232/74233 exploitation traffic in [4]; heuristic on URI/command patterns
CommonSecurityLog
| where TimeGenerated > ago(2d)
| where RequestURL has_any ("cgi-bin", "goform", "adm.cgi", "boafrm")
| where RequestURL has_any (";", "|", "$(", "`", "&&")
| project TimeGenerated, SourceIP, DestinationIP, RequestURL, DeviceVendor, DeviceProduct
| take 100
```

*Note:* This is a generic embedded-device command-injection heuristic, not specific to SPEAKINGSTONE/DARKLANTERN traffic — inventory ZBT/OEM-rebranded routers on your network and prioritize matches against them; expect noise from vulnerability scanners.

#### PaperCut server spawning shell/script host (zero-day exploitation pattern)
- **Actor / Campaign:** unattributed, active PaperCut NG/MF zero-day exploitation
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application
- **Data source:** DeviceProcessEvents
- **Source:** [6]

```kql
// PaperCut print management service unexpectedly launching command interpreters
// (matches prior PaperCut RCE exploitation chains, e.g. CVE-2023-27350 pattern)
DeviceProcessEvents
| where Timestamp > ago(2d)
| where InitiatingProcessFileName in~ ("pc-app.exe","pc-client.exe","java.exe","PCServer.exe","pcprogtray.exe")
| where InitiatingProcessCommandLine has_any ("papercut","PaperCut")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","cscript.exe","wscript.exe","mshta.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| take 100
```

*Note:* No exploit IOCs were published yet at time of writing [6]; this reuses the known PaperCut RCE child-process pattern. Patch to the emergency release and treat any hit as high-priority given the "confirmed customer incidents" statement.

#### Suspicious batch script backdoor persistence (HOOKEDGE-style)
- **Actor / Campaign:** APT28 (HOOKEDGE backdoor, Recorded Future Insikt Group)
- **MITRE ATT&CK:** T1059.003 — Command and Scripting Interpreter: Windows Command Shell; T1053.005 — Scheduled Task
- **Data source:** DeviceProcessEvents, DeviceFileEvents
- **Source:** [7]

```kql
// Lightweight batch-script backdoors are often persisted via scheduled tasks or startup keys,
// executed repeatedly by cmd.exe with no parent GUI application
DeviceProcessEvents
| where Timestamp > ago(2d)
| where FileName =~ "cmd.exe"
| where ProcessCommandLine has ".bat"
| where InitiatingProcessFileName in~ ("schtasks.exe","svchost.exe","taskeng.exe","explorer.exe")
| join kind=leftouter (
    DeviceFileEvents
    | where Timestamp > ago(2d)
    | where FileName endswith ".bat"
    | where FolderPath has_any (@"\AppData\", @"\ProgramData\", @"\Public\")
) on DeviceName
| project Timestamp, DeviceName, InitiatingProcessFileName, ProcessCommandLine, FolderPath, FileName1
| take 100
```

*Note:* HOOKEDGE distribution/delivery mechanism was not fully detailed in [7]; this is a broad heuristic for recurring batch-script execution consistent with a lightweight persistence backdoor and requires tuning to your baseline of legitimate scheduled batch jobs (esp. on government/diplomatic endpoints in scope of the reported regions).

> [1] TerminalFix campaign deploys a reverse tunnel through multistage intrusion — https://www.microsoft.com/en-us/security/blog/2026/08/28/terminalfix-campaign-deploys-reverse-tunnel-through-multistage-intrusion/
> [3] ownCloud Flaw Exploited to Steal Nuclear Records From Philippine Research Body — https://thehackernews.com/2026/08/snowflake-github-actions-flaw-lets.html
> [4] China-Made ZBT Routers Ship With Two Implants Giving Unauthenticated Attackers Root Access — https://thehackernews.com/2026/08/china-made-zbt-routers-ship-with-two.html
> [6] PaperCut Zero-Day Exploited in Attacks, Affecting All NG and MF Versions — https://thehackernews.com/2026/08/papercut-zero-day-exploited-in-attacks.html
> [7] APT28-Linked HOOKEDGE Backdoor Targets European Government and Diplomatic Organizations — https://thehackernews.com/2026/08/apt28-linked-hookedge-backdoor-targets.html

### 2026-08-30

*Generated 2026-08-30 13:21 UTC · model `claude-sonnet-5`*

_Lint: 5 KQL block(s) — structural checks passed. All queries are CANDIDATES; validate before use._

#### Windows Terminal / PowerShell Spawned with ClickFix-style Web Fetch Command
- **Actor / Campaign:** TerminalFix (ClickFix variant)
- **MITRE ATT&CK:** T1204.004 — User Execution: Malicious Copy and Paste (via ClickFix social engineering); T1059.001 — PowerShell
- **Data source:** DeviceProcessEvents
- **Source:** [1]

```kql
// TerminalFix directs victims to paste attacker-supplied commands into
// Windows Terminal / PowerShell rather than the classic Run dialog.
// Look for wt.exe / WindowsTerminal.exe / OpenConsole.exe launching
// powershell/cmd with web-download or encoded-command patterns.
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("WindowsTerminal.exe", "wt.exe", "OpenConsole.exe")
| where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "curl.exe")
| where ProcessCommandLine has_any (
    "iwr", "Invoke-WebRequest", "irm", "Invoke-RestMethod",
    "DownloadString", "-enc", "-EncodedCommand", "FromBase64String",
    "curl.exe -o", "certutil -decode"
)
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| take 100
```

*Note:* Windows Terminal is a legitimate default shell host, so tune out admin scripting/automation; focus on interactive user sessions and correlate with a recent browser process (msedge.exe/chrome.exe) in the process tree ancestry.

#### PowerShell/CMD Launched Directly from Explorer via Clipboard-Paste Pattern into Terminal
- **Actor / Campaign:** TerminalFix (ClickFix variant)
- **MITRE ATT&CK:** T1204.004 — User Execution: Malicious Copy and Paste; T1218 — System Binary Proxy Execution
- **Data source:** DeviceProcessEvents
- **Source:** [1]

```kql
// ClickFix/TerminalFix lures often have explorer.exe (user interaction with
// a fake CAPTCHA page/instructions) as grandparent of a Terminal session
// that immediately runs a suspicious one-liner.
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("WindowsTerminal.exe", "wt.exe")
| where InitiatingProcessFileName =~ "explorer.exe"
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(7d)
    | where FileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe")
    | where ProcessCommandLine has_any ("http://", "https://", "-w hidden", "-windowstyle hidden", "IEX")
    | project ChildTimestamp = Timestamp, DeviceName, ChildCmd = ProcessCommandLine, InitiatingProcessParentFileName
) on DeviceName
| where ChildTimestamp between (Timestamp .. (Timestamp + 2m))
| project Timestamp, ChildTimestamp, DeviceName, ChildCmd
| take 100
```

*Note:* Heuristic time-window correlation between explorer→Terminal launch and a follow-on suspicious shell command; expect noise in dev/IT-admin environments, tune the 2-minute window and command-line filters to your baseline.

#### Reverse-Tunnel Client Execution (ngrok/cloudflared/SSH -R) Following Terminal Launch
- **Actor / Campaign:** TerminalFix (ClickFix variant)
- **MITRE ATT&CK:** T1572 — Protocol Tunneling; T1071 — Application Layer Protocol
- **Data source:** DeviceProcessEvents
- **Source:** [1]

```kql
// TerminalFix deploys a reverse-tunnel backdoor; look for common tunneling
// binaries executed shortly after a terminal/PowerShell session begins.
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName has_any ("ngrok.exe", "cloudflared.exe", "frpc.exe", "chisel.exe", "plink.exe", "ssh.exe")
   or ProcessCommandLine has_any ("ssh -R", "ssh -L", "-R 0.0.0.0", "tunnel run", "ngrok tcp", "ngrok http")
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "WindowsTerminal.exe", "wt.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| take 100
```

*Note:* No specific tunnel-tool binary names or hashes were published in the source; this is behavior-based and legitimate remote-access/DevOps tooling will trigger it, so allow-list known IT usage.

#### Suspicious New Outbound Connections to Tunneling/Dynamic-DNS Infrastructure After Terminal Session
- **Actor / Campaign:** TerminalFix (ClickFix variant)
- **MITRE ATT&CK:** T1572 — Protocol Tunneling; T1105 — Ingress Tool Transfer
- **Data source:** DeviceNetworkEvents, DeviceProcessEvents
- **Source:** [1]

```kql
// Generic heuristic: correlate a Windows Terminal / PowerShell process
// making an outbound connection to known reverse-tunnel provider domains.
// No campaign-specific C2 domains were published; tune the domain list to
// your environment's known-bad/allow-list.
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("powershell.exe", "pwsh.exe", "cmd.exe", "WindowsTerminal.exe", "wt.exe")
| where RemoteUrl has_any ("trycloudflare.com", "ngrok.io", "ngrok-free.app", "loca.lt", "localhost.run")
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteUrl, RemoteIP, RemotePort
| take 100
```

*Note:* trycloudflare.com/ngrok domains are widely used for legitimate free tunneling as well as abuse; treat as a low-confidence pivot to enrich other alerts rather than a standalone high-fidelity detection.

#### Registry/MRU Evidence of Manual Run-Box or Terminal Command Entry Preceding Compromise
- **Actor / Campaign:** TerminalFix (ClickFix variant)
- **MITRE ATT&CK:** T1204.004 — User Execution; T1112 — Modify Registry
- **Data source:** DeviceRegistryEvents
- **Source:** [1]

```kql
// Classic ClickFix leaves RunMRU artifacts; TerminalFix targets Terminal/
// PowerShell instead, but some victims may still be redirected via Run
// first. Flag RunMRU entries containing PowerShell/mshta/curl indicators.
DeviceRegistryEvents
| where Timestamp > ago(7d)
| where RegistryKey has @"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"
| where RegistryValueData has_any ("powershell", "mshta", "curl", "certutil", "iex", "http")
| project Timestamp, DeviceName, RegistryKey, RegistryValueName, RegistryValueData
| take 100
```

*Note:* Complementary detection covering the original ClickFix Run-dialog vector referenced as the baseline that TerminalFix evolves from; expect some legitimate admin RunMRU entries, review case-by-case.

> [1] TerminalFix Uses Fake Cloudflare CAPTCHAs to Deploy Reverse-Tunnel Backdoor — https://thehackernews.com/2026/08/terminalfix-uses-fake-cloudflare.html

### 2026-08-31

*Generated 2026-08-31 13:27 UTC · model `claude-sonnet-5`*

_Lint: 8 KQL block(s) — structural checks passed. All queries are CANDIDATES; validate before use._

#### ValleyRAT Loader Disguised as QN Wallpaper Adware
- **Actor / Campaign:** Silver Fox / ValleyRAT
- **MITRE ATT&CK:** T1036.005 — Masquerading: Match Legitimate Name or Location
- **Data source:** DeviceProcessEvents, DeviceFileEvents
- **Source:** [1] [3]

```kql
// QN Wallpaper / adware binaries spawning unexpected child processes (loader chain to ValleyRAT)
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName has_any ("QNWallpaper", "QN_Wallpaper", "wallpaper") // adjust to observed binary name
| where FileName in~ ("rundll32.exe","regsvr32.exe","powershell.exe","cmd.exe","mshta.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, AccountName
| take 100
```

*Note:* Kaspersky's report [3] describes ValleyRAT running under a signed, trusted adware process; the exact binary/hash was not published, so this hunts on behavioral parent/child anomalies from wallpaper/adware utilities — tune the `InitiatingProcessFileName` filter once the exact signed binary name is confirmed in your environment.

#### Defender Antivirus Exclusion Added for Adware/Trusted-Process Path
- **Actor / Campaign:** Silver Fox / ValleyRAT
- **MITRE ATT&CK:** T1562.001 — Impair Defenses: Disable or Modify Tools
- **Data source:** DeviceProcessEvents
- **Source:** [1] [3]

```kql
// User or script adding an AV exclusion for a path/process associated with adware-style installers
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "Add-MpPreference" and ProcessCommandLine has_any ("ExclusionPath", "ExclusionProcess")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| take 100
```

*Note:* Legitimate IT/software installers sometimes add exclusions; correlate with recent installation of unfamiliar adware/wallpaper utilities from [1][3] rather than alerting on this alone.

#### Cursor AI Coding Assistant Executed Outside Developer Context
- **Actor / Campaign:** Aurora / Aur0ra ransomware
- **MITRE ATT&CK:** T1588.002 — Obtain Capability: Tool (abuse of legitimate AI coding tool)
- **Data source:** DeviceProcessEvents, DeviceNetworkEvents
- **Source:** [2]

```kql
// Behavioral hunt: Cursor AI binary running on hosts with no prior developer/IDE activity
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName has_any ("Cursor.exe","cursor-agent","cursor.exe")
| summarize FirstSeen = min(Timestamp), Executions = count(), Devices = make_set(DeviceName) by AccountName, FileName
| where Executions < 5
| take 100
```

```kql
// Follow-on: Cursor process making outbound connections shortly before ransomware-style file activity
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName has_any ("Cursor.exe","cursor-agent")
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort
| take 100
```

*Note:* No concrete IOCs (hashes/IPs/domains) were published for the Aurora/Cursor campaign [2]; this is a purely behavioral hunt intended to surface anomalous Cursor AI usage for manual triage, and will need suppression for legitimate developer workstations.

#### Cisco IOS XR / TACACS Device Logging Disabled or Cleared
- **Actor / Campaign:** Fire Ant (China-nexus)
- **MITRE ATT&CK:** T1562.002 — Impair Defenses: Disable Windows Event Logging (analogous network-device logging), T1556 — Modify Authentication Process
- **Data source:** Syslog, CommonSecurityLog
- **Source:** [4]

```kql
// Hunt for commands/events indicating log-blinding or config tampering on network infrastructure
Syslog
| where TimeGenerated > ago(14d)
| where ProcessName has_any ("clear logging","no logging","logging buffered 0","clear tacacs","tac_plus")
   or SyslogMessage has_any ("clear logging","no logging host","tacacs-server key")
| project TimeGenerated, Computer, Facility, SeverityLevel, SyslogMessage
| take 100
```

```kql
// Repeated authentication events against TACACS servers from unexpected management hosts
CommonSecurityLog
| where TimeGenerated > ago(14d)
| where DeviceVendor has "Cisco" and Activity has_any ("tacacs","aaa","authentication")
| summarize AuthAttempts = count(), Users = make_set(SourceUserName) by SourceIP, DestinationIP, DeviceAction
| where AuthAttempts > 20
| take 100
```

*Note:* No specific IOCs (device hostnames, IPs) were disclosed for Fire Ant [4]; these queries rely on syslog/CommonSecurityLog ingestion from Cisco IOS XR/TACACS devices being configured in Sentinel, and thresholds need tuning to your network's baseline logging volume.

#### TerminalFix ClickFix — Windows Terminal/PowerShell Launched via Clipboard Paste from Fake CAPTCHA
- **Actor / Campaign:** TerminalFix (ClickFix variant, unattributed)
- **MITRE ATT&CK:** T1204.004 — User Execution: Malicious Copy and Paste; T1059.001 — Command and Scripting Interpreter: PowerShell
- **Data source:** DeviceProcessEvents
- **Source:** [6]

```kql
// Windows Terminal or PowerShell spawned directly by explorer.exe with encoded/remote-fetch commands (ClickFix pattern)
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "explorer.exe"
| where FileName in~ ("WindowsTerminal.exe","wt.exe","powershell.exe","pwsh.exe")
| where ProcessCommandLine has_any ("iwr ","Invoke-WebRequest","curl ","-enc ","-EncodedCommand","irm ")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| take 100
```

#### Reverse-Tunnel Backdoor Tooling Launched from Terminal/PowerShell Session
- **Actor / Campaign:** TerminalFix
- **MITRE ATT&CK:** T1572 — Protocol Tunneling
- **Data source:** DeviceProcessEvents, DeviceNetworkEvents
- **Source:** [6]

```kql
// Reverse-tunnel client (e.g., cloudflared, ngrok) started from a Terminal/PowerShell chain shortly after ClickFix-style execution
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("WindowsTerminal.exe","wt.exe","powershell.exe","pwsh.exe")
| where FileName has_any ("cloudflared.exe","ngrok.exe","frpc.exe","ssh.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| take 100
```

*Note:* [6] describes the TerminalFix technique directing victims to paste commands into Windows Terminal/PowerShell rather than the Run dialog; no specific payload hashes/domains were published, so these are behavioral hunts on the execution chain and should be tuned against legitimate developer/IT use of Windows Terminal and tunneling tools.

> [1] ValleyRAT Backdoor Hides in Signed Adware That Users Add to Antivirus Exclusions — https://thehackernews.com/2026/08/valleyrat-backdoor-hides-in-signed.html
> [2] Aurora Ransomware Operators Use Cursor AI in Attacks Against 10 Targets — https://thehackernews.com/2026/08/aurora-ransomware-operators-use-cursor.html
> [3] ValleyRAT masquerading as adware — https://securelist.com/valleyrat-backdoor-adware/121175/
> [4] China-Linked Fire Ant Hijacks Cisco Routers to Steal Credentials and Blind Security Logs — https://thehackernews.com/2026/08/china-linked-fire-ant-hijacks-cisco.html
> [6] TerminalFix Uses Fake Cloudflare CAPTCHAs to Deploy Reverse-Tunnel Backdoor — https://thehackernews.com/2026/08/terminalfix-uses-fake-cloudflare.html

### 2026-09-01

*Generated 2026-09-01 13:27 UTC · model `claude-sonnet-5`*

_Lint: 11 KQL block(s) — query 1: unbalanced '()'. All queries are CANDIDATES; validate before use._

#### ClickFix-Style Initial Access via Clipboard-Paste Terminal Execution
- **Actor / Campaign:** Unattributed (Microsoft telemetry, most common 2025 initial access technique)
- **MITRE ATT&CK:** T1204.004 — User Execution: Malicious Copy and Paste / T1059.001 — PowerShell
- **Data source:** DeviceProcessEvents
- **Source:** [1]

```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("explorer.exe","RuntimeBroker.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","wt.exe")
| where ProcessCommandLine has_any ("iwr ", "Invoke-WebRequest", "irm ", "Invoke-RestMethod", "certutil", "-enc", "-EncodedCommand", "iex(")
// ClickFix lures typically invoke Run dialog / clipboard-paste then a one-liner download+execute
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| take 100
```

*Note:* Heuristic — Run-dialog-to-shell chains are common in legitimate admin activity too; tune by excluding known IT-admin accounts/scripts and correlate with recent browser process activity on the same host.

#### TerminalFix: Windows Terminal Spawning Reverse-Tunnel Utilities
- **Actor / Campaign:** TerminalFix (ClickFix variant, per Microsoft)
- **MITRE ATT&CK:** T1090 — Proxy / T1572 — Protocol Tunneling
- **Data source:** DeviceProcessEvents, DeviceNetworkEvents
- **Source:** [6]

```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName =~ "wt.exe" or InitiatingProcessFileName =~ "OpenConsole.exe"
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe")
| where ProcessCommandLine has_any ("cloudflared", "ssh -R", "ssh -L", "chisel", "ngrok", "-R 0.0.0.0", "tunnel")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| take 100
```

*Note:* Cloudflare-CAPTCHA lures on compromised sites drive victims to run these commands via Windows Terminal specifically (not classic console host); validate wt.exe parentage and absence of legitimate dev tunnel use in your environment.

#### PaperCut Server Process Spawning Unexpected Child Processes (Post-Auth-Bypass RCE Chain)
- **Actor / Campaign:** Unattributed exploitation of CVE-2026-81578/82078
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application / T1059 — Command and Scripting Interpreter
- **Data source:** DeviceProcessEvents, DeviceNetworkEvents
- **Source:** [4] [10] [15] [16]

```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("pc-app.exe","PaperCutNGMFService.exe","java.exe")
| where InitiatingProcessCommandLine has_any ("papercut","PaperCut")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","whoami.exe","net.exe","certutil.exe","curl.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
| take 100
```

*Note:* Chained missing-authentication (CVE-2026-81578) + unsafe reflection (CVE-2026-82078) grants arbitrary Java execution under the PaperCut server process; any shell/child-process activity from that process on a print server is highly suspicious. Confirm PaperCut is patched and check for pre-patch compromise per BOD 26-04 forensic triage guidance.

#### Langflow / Ruby on Rails RCE Exploitation Leading to Shell or C2 Activity
- **Actor / Campaign:** Unattributed (VulnCheck reporting, CVE-2026-0768 / CVE-2026-66066)
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application
- **Data source:** DeviceProcessEvents, DeviceNetworkEvents
- **Source:** [5]

```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("python.exe","python3.exe","ruby.exe","puma.exe","langflow.exe")
| where FileName in~ ("bash","sh","cmd.exe","powershell.exe","curl","wget","nc","ncat")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine
| take 100
```

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where InitiatingProcessFileName in~ ("python.exe","python3.exe","ruby.exe","puma.exe","langflow.exe")
| where RemotePort in (4444, 1337, 8443) or isnotempty(RemoteUrl)
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| take 100
```

*Note:* No concrete IOCs published; these are behavioral guards for a Langflow/Rails process unexpectedly spawning a shell or making outbound C2-style connections. Tune port list and add known internal automation exceptions.

#### ValleyRAT Masquerading as Signed Adware with AV Exclusion Abuse
- **Actor / Campaign:** Silver Fox / ValleyRAT
- **MITRE ATT&CK:** T1562.001 — Impair Defenses: Disable or Modify Tools / T1036.005 — Masquerading (Match Legitimate Name or Location)
- **Data source:** DeviceProcessEvents, DeviceRegistryEvents
- **Source:** [9] [12]

```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has "Add-MpPreference" and ProcessCommandLine has_any ("ExclusionPath", "ExclusionProcess")
| where ProcessCommandLine has_any ("Wallpaper", "QN", "adware","wallpaper")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| take 100
```

```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where ProcessVersionInfoProductName has_any ("Wallpaper","QN Wallpaper") or FileName has_any ("wallpaper","QNWallpaper")
| where isnotempty(InitiatingProcessSignerType) and InitiatingProcessSignerType != "OSVendor"
| project Timestamp, DeviceName, FileName, ProcessVersionInfoProductName, SHA256, InitiatingProcessFileName
| take 100
```

*Note:* Behavioral, no confirmed hashes provided — the key signal is a signed "wallpaper/adware" utility being manually excluded from AV, followed by process hollowing/loading of an unsigned backdoor under its trusted name; validate against your allowed-software list.

#### Fire Ant: Log-Clearing / Config Changes on Cisco IOS-XR, TACACS, or Linux Management Hosts
- **Actor / Campaign:** Fire Ant (China-nexus)
- **MITRE ATT&CK:** T1070.002 — Indicator Removal: Clear Linux or Mac System Logs / T1556 — Modify Authentication Process
- **Data source:** CommonSecurityLog, SecurityEvent, DeviceProcessEvents
- **Source:** [13]

```kql
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DeviceVendor has_any ("Cisco","TACACS") 
| where Activity has_any ("clear logging","no logging","configuration changed","tacacs")
| project TimeGenerated, DeviceVendor, DeviceProduct, SourceIP, DestinationIP, Activity, Message
| take 100
```

```kql
SecurityEvent
| where TimeGenerated > ago(1d)
| where EventID in (1102, 4719) // audit log cleared / audit policy changed on Linux mgmt hosts forwarding Windows-style events, or bastion jump hosts
| project TimeGenerated, Computer, Account, EventID, Activity
| take 100
```

*Note:* Environment must ingest Cisco IOS-XR / TACACS syslog into CommonSecurityLog for the first query to fire; adjust field/activity matching to your actual log-forwarding schema since router/TACACS log-blinding behavior is not natively visible in Defender XDR tables.

#### Aurora Ransomware Operators Leveraging Cursor AI Coding Assistant for Intrusion Tooling
- **Actor / Campaign:** Aurora / Aur0ra ransomware
- **MITRE ATT&CK:** T1588.002 — Obtain Capabilities: Tool / T1059 — Command and Scripting Interpreter
- **Data source:** DeviceProcessEvents, DeviceFileEvents
- **Source:** [11]

```kql
DeviceProcessEvents
| where Timestamp > ago(1d)
| where FileName has_any ("Cursor.exe","cursor-agent.exe","cursor.exe")
| where ProcessCommandLine has_any ("powershell","cmd.exe","-enc","Invoke-","download")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| take 100
```

*Note:* Cursor is a legitimate AI coding tool; flag only unusual server-side or non-developer-host installs/executions paired with scripting activity, since normal developer usage will cause high false positives — restrict to servers/endpoints where Cursor is not expected.

#### METR-Style API Key Theft Leading to Anomalous AI Service Consumption
- **Actor / Campaign:** Unattributed (METR incident)
- **MITRE ATT&CK:** T1552.001 — Unsecured Credentials: Credentials In Files / T1078.004 — Valid Accounts: Cloud Accounts
- **Data source:** CloudAppEvents, DeviceFileEvents
- **Source:** [2]

```kql
DeviceFileEvents
| where Timestamp > ago(1d)
| where FileName has_any (".env", "credentials.json", "api_key", "config.yaml")
| where ActionType in ("FileCreated","FileModified")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName
| take 100
```

*Note:* No specific IOCs disclosed; this is a generic hunt for locally stored API-key/secret files that could be harvested and abused for cloud/AI-service credit theft — pair with billing/usage anomaly alerts from your AI vendor where available.

> [1] Threat Actors Don’t Want Better Attacks. They Want Repeatable Ones — https://thehackernews.com/2026/09/threat-actors-dont-want-better-attacks.html
> [2] Attackers Steal METR API Key and Consume AI Credits Worth About $600,000 — https://thehackernews.com/2026/09/attackers-steal-metr-api-key-and.html
> [4] Recently patched PaperCut zero-days used in data theft attacks — https://www.bleepingcomputer.com/news/security/recently-patched-papercut-zero-days-used-in-data-theft-attacks/
> [5] Attackers Exploit Critical Langflow and Rails Flaws in Credential-Probing and C2 Activity — https://thehackernews.com/2026/09/attackers-exploit-critical-langflow-and.html
> [6] Microsoft warns of TerminalFix attacks deploying reverse tunnels — https://www.bleepingcomputer.com/news/security/microsoft-warns-of-terminalfix-attacks-deploying-reverse-tunnels/
> [9] ValleyRAT Backdoor Hides in Signed Adware That Users Add to Antivirus Exclusions — https://thehackernews.com/2026/08/valleyrat-backdoor-hides-in-signed.html
> [10] CISA Adds Two Known Exploited Vulnerabilities to Catalog — https://www.cisa.gov/news-events/alerts/2026/08/31/cisa-adds-two-known-exploited-vulnerabilities-catalog
> [11] Aurora Ransomware Operators Use Cursor AI in Attacks Against 10 Targets — https://thehackernews.com/2026/08/aurora-ransomware-operators-use-cursor.html
> [12] ValleyRAT masquerading as adware — https://securelist.com/valleyrat-backdoor-adware/121175/
> [13] China-Linked Fire Ant Hijacks Cisco Routers to Steal Credentials and Blind Security Logs — https://thehackernews.com/2026/08/china-linked-fire-ant-hijacks-cisco.html
> [15] CVE-2026-82078 — PaperCut NG/MF Unsafe Reflection Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2026-82078
> [16] CVE-2026-81578 — PaperCut NG/MF Missing Authentication for Critical Function Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2026-81578

### 2026-09-10

*Generated 2026-09-10 13:25 UTC · model `claude-sonnet-5`*

_Lint: 9 KQL block(s) — structural checks passed. All queries are CANDIDATES; validate before use._

#### Trezor-branded phishing email lures post email-provider breach
- **Actor / Campaign:** unattributed (Trezor customer email breach)
- **MITRE ATT&CK:** T1566.002 — Phishing: Spearphishing Link
- **Data source:** EmailEvents, EmailUrlInfo
- **Source:** [1]

```kql
EmailEvents
| where Timestamp > ago(3d)
| where SenderDisplayName has_any ("Trezor", "SatoshiLabs") or Subject has_any ("Trezor", "wallet recovery", "seed phrase", "security update")
| join kind=inner (EmailUrlInfo) on NetworkMessageId
| where UrlDomain !has "trezor.io"
| where UrlDomain has_any ("trezor", "wallet", "recovery", "secure-login")
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, UrlDomain, Url
| take 100
```

*Note:* Heuristic — matches Trezor-themed phishing terminology combined with look-alike domains; tune domain list as actual campaign URLs surface and validate against Trezor's real domain allow-list.

#### New passkey/FIDO2 registration followed by anomalous sign-in (MFA persistence)
- **Actor / Campaign:** unattributed — passkey social-engineering campaigns
- **MITRE ATT&CK:** T1556.006 — Modify Authentication Process: Multi-Factor Authentication, T1098.005 — Account Manipulation: Device Registration
- **Data source:** AuditLogs, SigninLogs
- **Source:** [4]

```kql
AuditLogs
| where Timestamp > ago(3d)
| where OperationName in ("Register security info", "User registered security info", "Add registration method")
| extend UserId = tostring(TargetResources[0].id), UserPrincipalName = tostring(TargetResources[0].userPrincipalName)
| join kind=inner (
    SigninLogs
    | where Timestamp > ago(3d)
    | where ResultType == 0
    | where AuthenticationRequirement == "singleFactorAuthentication" or isnotempty(ConditionalAccessStatus)
) on $left.UserPrincipalName == $right.UserPrincipalName
| where SigninLogs_Timestamp between (Timestamp .. (Timestamp + 1h))
| project Timestamp, UserPrincipalName, IPAddress, Location = tostring(LocationDetails), AppDisplayName, DeviceDetail
| take 100
```

*Note:* Flags a new authentication method registration closely followed by sign-in from potentially new device/location; expect FPs for legitimate self-service MFA re-enrollment — correlate with new/unfamiliar IP or device.

#### Suspicious Microsoft Graph enumeration following identity compromise
- **Actor / Campaign:** unattributed — passkey-themed social engineering
- **MITRE ATT&CK:** T1087.004 — Account Discovery: Cloud Account, T1213.002 — Data from Information Repositories: SharePoint
- **Data source:** CloudAppEvents, OfficeActivity
- **Source:** [4]

```kql
CloudAppEvents
| where Timestamp > ago(3d)
| where Application == "Microsoft Graph"
| where ActionType in ("List users", "List sites", "List drives", "Get user", "Get mailbox settings")
| summarize DistinctActions = dcount(ActionType), Calls = count() by AccountId, IPAddress, bin(Timestamp, 1h)
| where DistinctActions >= 3 and Calls > 20
| project Timestamp, AccountId, IPAddress, DistinctActions, Calls
| take 100
```

*Note:* Heuristic burst-detection for reconnaissance-style Graph API calls; tune thresholds per tenant baseline and pair with SharePoint/OneDrive mass-download alerts described in the report.

#### Mass SharePoint/OneDrive access shortly after suspicious sign-in
- **Actor / Campaign:** unattributed — passkey-themed social engineering
- **MITRE ATT&CK:** T1530 — Data from Cloud Storage
- **Data source:** OfficeActivity, SigninLogs
- **Source:** [4]

```kql
OfficeActivity
| where TimeGenerated > ago(3d)
| where Operation in ("FileDownloaded", "FileAccessed", "FileSyncDownloadedFull")
| summarize FileOps = count(), DistinctFiles = dcount(OfficeObjectId) by UserId, ClientIP, bin(TimeGenerated, 1h)
| where DistinctFiles > 50
| project TimeGenerated, UserId, ClientIP, FileOps, DistinctFiles
| take 100
```

*Note:* Candidate for post-compromise mass exfiltration from SharePoint/OneDrive; tune volume thresholds to org baselines to avoid FPs from legitimate bulk sync jobs.

#### Chrome renderer spawning unexpected child process (possible BlueMoon/V8 exploit chain)
- **Actor / Campaign:** APT31 and other espionage clusters using BlueMoon exploit kit
- **MITRE ATT&CK:** T1203 — Exploitation for Client Execution, T1068 — Exploitation for Privilege Escalation
- **Data source:** DeviceProcessEvents
- **Source:** [5][8][12]

```kql
DeviceProcessEvents
| where Timestamp > ago(3d)
| where InitiatingProcessFileName =~ "chrome.exe"
| where FileName in~ ("rundll32.exe","mshta.exe","powershell.exe","cmd.exe","wscript.exe","cscript.exe","regsvr32.exe")
| where InitiatingProcessParentFileName !in~ ("chrome.exe") // rule out normal update helpers, tune as needed
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine
| take 100
```

*Note:* Behavioral only — no IOCs published for BlueMoon; Chrome legitimately spawns some helper processes (e.g., installer, notification helper), so expect FPs — validate against known-good Chrome child process baseline before alerting.

#### Chrome crash/respawn pattern consistent with CVE-2026-87491 exploitation
- **Actor / Campaign:** unattributed espionage clusters (BlueMoon exploit kit)
- **MITRE ATT&CK:** T1203 — Exploitation for Client Execution
- **Data source:** DeviceProcessEvents, DeviceEvents
- **Source:** [5][8][12]

```kql
DeviceEvents
| where Timestamp > ago(3d)
| where ActionType has_any ("ProcessCrashed","ApplicationCrash")
| where AdditionalFields has "chrome.exe"
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(3d)
    | where FileName =~ "chrome.exe"
) on DeviceId
| where DeviceProcessEvents_Timestamp between (Timestamp .. (Timestamp + 5m))
| project Timestamp, DeviceName, ActionType, AdditionalFields
| take 100
```

*Note:* Column/table names for crash telemetry vary by sensor version — validate ActionType values in your tenant; unpatched CVE-2026-87491 (fixed in Chrome update referenced in [8]) is the priority mitigation, this hunt is supplementary.

#### Microsoft Defender process crash preceding unexpected SYSTEM-level process (ShieldCrash pattern)
- **Actor / Campaign:** "Nightmare Eclipse" — ShieldCrash Defender LPE exploit
- **MITRE ATT&CK:** T1068 — Exploitation for Privilege Escalation
- **Data source:** DeviceProcessEvents, DeviceEvents
- **Source:** [9]

```kql
DeviceEvents
| where Timestamp > ago(3d)
| where FileName has_any ("MsMpEng.exe","MpCmdRun.exe","MpDefenderCoreService.exe")
| where ActionType has_any ("ProcessCrashed","ServiceCrashed","AntimalwareServiceError")
| join kind=inner (
    DeviceProcessEvents
    | where Timestamp > ago(3d)
    | where AccountName has_any ("SYSTEM","NT AUTHORITY\\SYSTEM")
) on DeviceId
| where DeviceProcessEvents_Timestamp between (Timestamp .. (Timestamp + 5m))
| project Timestamp, DeviceName, ActionType, DeviceProcessEvents_Timestamp, FileName1 = FileName, ProcessCommandLine, AccountName
| take 100
```

*Note:* No public IOC/command-line for the "ShieldCrash" exploit exists yet — this is a coarse behavioral proxy (Defender component crash immediately followed by new SYSTEM process creation); expect noise from normal Defender maintenance/updates and refine once PoC details/hashes emerge.

#### Authentication success without expected MFA challenge on Citrix NetScaler Gateway (CVE-2026-19490)
- **Actor / Campaign:** unattributed — active KEV exploitation
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application, T1556 — Modify Authentication Process
- **Data source:** CommonSecurityLog (Citrix NetScaler syslog/CEF)
- **Source:** [6][10]

```kql
CommonSecurityLog
| where TimeGenerated > ago(3d)
| where DeviceVendor has "Citrix" and DeviceProduct has_any ("NetScaler","Gateway")
| where Activity has_any ("AAA_LOGIN_SUCCESS","AUTHENTICATION")
| where isnotempty(SourceIP) and isempty(AdditionalExtensions) // no MFA/second-factor field logged
| summarize LoginCount = count() by SourceIP, DestinationIP, Activity, bin(TimeGenerated, 1h)
| where LoginCount > 5
| take 100
```

*Note:* Field names depend on your Citrix CEF/syslog mapping — validate against your parser; this is a coarse heuristic for unauthenticated-bypass style logins and should be paired with immediate patching per CISA KEV/BOD 26-04.

#### Anomalous administrative access to Cisco FMC/SCC (CVE-2026-20079) or FortiOS (CVE-2025-25249)
- **Actor / Campaign:** unattributed — active KEV exploitation
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application
- **Data source:** CommonSecurityLog (Cisco FMC/ASA, Fortinet syslog)
- **Source:** [6][11][13]

```kql
CommonSecurityLog
| where TimeGenerated > ago(3d)
| where (DeviceVendor has "Cisco" and DeviceProduct has_any ("FMC","Firepower")) 
      or (DeviceVendor has "Fortinet" and DeviceProduct has_any ("FortiOS","FortiGate"))
| where Activity has_any ("Login","admin","config change","account created") 
| where SourceIP !in ( 
    // known-good management/jump-host IP ranges — populate per environment
    dynamic([])
)
| summarize Events = count() by SourceIP, DeviceProduct, Activity, bin(TimeGenerated, 1h)
| where Events > 3
| take 100
```

*Note:* Purely behavioral placeholder due to lack of exploit-specific indicators in the advisory; prioritize vendor patching per CISA KEV/BOD 26-04 and tune the known-good IP allowlist to your environment to reduce noise.

> [1] Trezor warns users of email provider breach, phishing attacks — https://www.bleepingcomputer.com/news/security/trezor-warns-users-of-email-provider-breach-phishing-attacks/
> [4] Passkey-themed social engineering leads to identity and cloud compromise — https://www.microsoft.com/en-us/security/blog/2026/09/09/passkey-themed-social-engineering-leads-identity-cloud-compromise/
> [5] Four Spy Groups Used the Same Chrome and Windows Exploit Kit Within a Week — https://thehackernews.com/2026/09/four-spy-groups-used-same-chrome-and.html
> [6] CISA Adds Four Known Exploited Vulnerabilities to Catalog — https://www.cisa.gov/news-events/alerts/2026/09/09/cisa-adds-four-known-exploited-vulnerabilities-catalog
> [8] Chrome V8 Zero-Day Exploited in the Wild Enables Code Execution Inside Sandbox — https://thehackernews.com/2026/09/chrome-v8-zero-day-exploited-in-wild.html
> [9] New Microsoft Defender 'ShieldCrash' zero-day grants SYSTEM access — https://www.bleepingcomputer.com/news/security/new-microsoft-defender-shieldcrash-zero-day-grants-system-access/
> [10] CVE-2026-19490 — Citrix NetScaler Authentication Bypass Using an Alternate Path or Channel Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2026-19490
> [11] CVE-2025-25249 — Fortinet Multiple Products Heap-based Buffer Overflow Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2025-25249
> [12] CVE-2026-87491 — Google Chromium V8 Out of Bounds Write Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2026-87491
> [13] CVE-2026-20079 — Cisco Firewall Management Center Authentication Bypass Using an Alternate Path or Channel Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2026-20079

### 2026-09-11

*Generated 2026-09-11 13:26 UTC · model `claude-sonnet-5`*

_Lint: 9 KQL block(s) — structural checks passed. All queries are CANDIDATES; validate before use._

#### Suspicious Child Process Execution from JFrog Artifactory Service
- **Actor / Campaign:** Unattributed (opportunistic exploitation of JFrog Artifactory CVEs)
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application; T1059 — Command and Scripting Interpreter
- **Data source:** DeviceProcessEvents
- **Source:** [2]

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName has_any ("java.exe", "artifactory.exe", "artifactoryservice.exe")
    or InitiatingProcessFolderPath has "artifactory"
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "bash.exe", "sh", "curl.exe", "wget.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, AccountName
| take 100
```

*Note:* Artifactory runs on Java and normally does not spawn shells; any such child process on a self-hosted Artifactory server warrants review, especially if paired with new local/admin account creation shortly after. Tune for legitimate CI/CD scripts that shell out from Artifactory plugins.

#### Suspicious Process/Network Activity from Sogou Input Method (GRAYRABBIT)
- **Actor / Campaign:** UNC3569 (China-linked) — GRAYRABBIT backdoor
- **MITRE ATT&CK:** T1203 — Exploitation for Client Execution; T1105 — Ingress Tool Transfer
- **Data source:** DeviceProcessEvents, DeviceNetworkEvents
- **Source:** [3]

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName has_any ("SogouCloud.exe", "SGTool.exe", "SogouPY.exe", "SogouIME.exe", "sogouinput.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "rundll32.exe", "mshta.exe", "regsvr32.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| take 100
```

```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName has_any ("SogouCloud.exe", "SGTool.exe", "SogouPY.exe", "SogouIME.exe")
| where RemotePort in (80, 443, 8080)
| project Timestamp, DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl, RemotePort
| take 100
```

*Note:* No specific IOCs (hashes/domains) were published; this is behavioral coverage for abuse of the Sogou IME process tree following exploitation of a crafted link. Expect noise from legitimate Sogou cloud-sync/update behavior — validate against known-good update endpoints before alerting.

#### Ransomware Pre-Encryption Indicators Following Cisco FMC Exploitation (Qilin)
- **Actor / Campaign:** Qilin ransomware + unnamed state-sponsored clusters exploiting CVE-2026-20079 (Cisco FMC)
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application; T1490 — Inhibit System Recovery
- **Data source:** DeviceProcessEvents
- **Source:** [4] [9]

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("vssadmin.exe", "wmic.exe", "bcdedit.exe", "wbadmin.exe")
| where ProcessCommandLine has_any (
    "delete shadows", "resize shadowstorage", "recoveryenabled no",
    "bootstatuspolicy ignoreallfailures", "delete catalog")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| take 100
```

*Note:* Cisco FMC itself is not visible in Defender/Sentinel host telemetry; this query hunts for the post-compromise shadow-copy/backup-tampering stage that typically follows credential theft via the CVE-2026-20079 auth-bypass chain. Pair with firewall/VPN sign-in anomaly hunting (SigninLogs, CommonSecurityLog) for admin accounts newly authenticating from unusual IPs after FMC exposure dates.

#### Anomalous Admin Sign-ins Possibly Linked to Cisco FMC Credential Theft
- **Actor / Campaign:** Ransomware / state-sponsored clusters exploiting CVE-2026-20079, CVE-2026-* (Cisco FMC)
- **MITRE ATT&CK:** T1078 — Valid Accounts; T1556 — Modify Authentication Process
- **Data source:** SigninLogs, IdentityLogonEvents
- **Source:** [4] [9]

```kql
SigninLogs
| where TimeGenerated > ago(14d)
| where ResultType == 0
| where AppDisplayName has_any ("VPN", "Firewall", "Network")
| summarize Countries = dcount(tostring(LocationDetails.countryOrRegion)), Attempts = count() by UserPrincipalName
| where Countries > 1
| take 100
```

*Note:* Heuristic only — flags admin/service accounts authenticating from multiple countries in a short window, a possible downstream signal of credentials stolen via FMC exploitation. Requires environment-specific tuning of `AppDisplayName` to match your Cisco/RADIUS integration naming.

#### Suspicious Child Process from PaperCut Service (Mass Exploitation Campaign)
- **Actor / Campaign:** Likely Russian-speaking actor, AI-agent-driven PaperCut campaign
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application; T1059.001/.003 — PowerShell/Windows Command Shell
- **Data source:** DeviceProcessEvents
- **Source:** [8]

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where (InitiatingProcessFileName has_any ("pc-app.exe", "pcclient.exe", "PCServer.exe", "javaw.exe")
        and InitiatingProcessFolderPath has "papercut")
| where FileName in~ ("cmd.exe", "powershell.exe", "certutil.exe", "mshta.exe", "wscript.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessFolderPath, FileName, ProcessCommandLine
| take 100
```

*Note:* No specific IOCs were published in the source; this targets the known PaperCut NG/MF RCE exploitation pattern (shell spawned from the PaperCut Java service). Confirm PaperCut server inventory and patch level before triage, and expect legitimate print-management scripting on some estates.

#### Chrome-Spawned Suspicious Child Process (Potential BlueMoon Exploit Chain)
- **Actor / Campaign:** Multiple cyber-espionage groups — "BlueMoon" exploit kit (Windows + Chrome 0-days)
- **MITRE ATT&CK:** T1189 — Drive-by Compromise; T1068 — Exploitation for Privilege Escalation
- **Data source:** DeviceProcessEvents
- **Source:** [10]

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName =~ "chrome.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "rundll32.exe", "regsvr32.exe", "mshta.exe", "werfault.exe")
| where InitiatingProcessIntegrityLevel in ("Low", "AppContainer")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessIntegrityLevel, FileName, ProcessCommandLine
| take 100
```

*Note:* No file/IOC details were disclosed for BlueMoon; this hunts generically for renderer/sandbox-escape behavior (low-integrity Chrome spawning a shell or LOLBin), which is the expected artifact of chained Chrome + Windows kernel zero-days. Tune out legitimate Chrome crash-handler (WerFault) invocations.

#### MikroTik RouterOS Exploitation Attempts (btest / Argument Injection)
- **Actor / Campaign:** Unattributed — actively exploited per CISA KEV
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application; T1068 — Exploitation for Privilege Escalation
- **Data source:** CommonSecurityLog / Syslog (perimeter device logs), DeviceNetworkEvents (if endpoints proxy through RouterOS)
- **Source:** [11] [13] [14]

```kql
// Requires RouterOS/syslog ingestion into CommonSecurityLog or a custom table
CommonSecurityLog
| where TimeGenerated > ago(14d)
| where DeviceVendor has "MikroTik" or Message has_any ("btest", "RouterOS")
| where Message has_any ("policy mask", "btest", "unauthenticated")
| project TimeGenerated, DeviceVendor, DeviceProduct, SourceIP, DestinationIP, Message
| take 100
```

```kql
// Hunt for endpoints/devices reaching RouterOS management/btest ports (tune port list to your estate)
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where RemotePort in (2000, 8291, 8728, 8729) // btest / API / API-SSL ports
| summarize Attempts = count(), Devices = dcount(DeviceName) by RemoteIP, RemotePort
| where Attempts > 20
| take 100
```

*Note:* MikroTik RouterOS devices are not directly instrumented by Defender EDR; ingest RouterOS/syslog into Sentinel (CommonSecurityLog or a custom table) for the first query. The second query is a coarse heuristic for scanning/exploitation attempts against known RouterOS management ports and needs baseline tuning per network to avoid legitimate admin traffic false positives. Prioritize per BOD 26-04 given confirmed active exploitation (KEV).

> [2] Attackers Chain JFrog Artifactory Flaws to Gain Admin Control and Plant Backdoors — https://thehackernews.com/2026/09/attackers-chain-jfrog-artifactory-flaws.html
> [3] China-Linked UNC3569 Exploited Sogou Input Method Flaw to Deploy GRAYRABBIT Backdoor — https://thehackernews.com/2026/09/china-linked-unc3569-exploited-sogou.html
> [4] Cisco FMC Flaws Exploited to Steal Credentials and Deploy Qilin Ransomware — https://thehackernews.com/2026/09/cisco-fmc-flaws-exploited-to-steal.html
> [8] AI-powered attack exploited PaperCut flaws to hack 395 organizations — https://www.bleepingcomputer.com/news/security/ai-powered-attack-exploited-papercut-flaws-to-hack-395-organizations/
> [9] Cisco FMC flaws exploited by ransomware gang, state-sponsored hackers — https://www.bleepingcomputer.com/news/security/cisco-fmc-flaws-exploited-by-ransomware-gang-state-sponsored-hackers/
> [10] New 'BlueMoon' kit exploited Windows and Chrome zero-day flaws — https://www.bleepingcomputer.com/news/security/new-bluemoon-kit-exploited-windows-and-chrome-zero-day-flaws/
> [11] CISA Adds Two Known Exploited Vulnerabilities to Catalog — https://www.cisa.gov/news-events/alerts/2026/09/10/cisa-adds-two-known-exploited-vulnerabilities-catalog
> [13] CVE-2026-86060 — MikroTik RouterOS Improper Neutralization of Argument Delimiters — https://nvd.nist.gov/vuln/detail/CVE-2026-86060
> [14] CVE-2026-67277 — MikroTik RouterOS Missing Authentication for Critical Function — https://nvd.nist.gov/vuln/detail/CVE-2026-67277

### 2026-09-12

*Generated 2026-09-12 13:22 UTC · model `claude-sonnet-5`*

_Lint: 9 KQL block(s) — structural checks passed. All queries are CANDIDATES; validate before use._

#### Suspicious Java Child Process on Artifactory Hosts (Possible Rust Backdoor Deployment)
- **Actor / Campaign:** Unattributed (JFrog Artifactory exploitation chain)
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application; T1505.003 — Server Software Component (Web Shell/Backdoor)
- **Data source:** DeviceProcessEvents, DeviceFileEvents
- **Source:** [4], [9], [12], [14], [15]

```kql
// Artifactory runs as a Java process; attackers chained CVE-2026-42016/42018 to get admin
// access and drop a Rust backdoor. Hunt for anomalous child processes spawned by java.exe
// on hosts known to run Artifactory, and for newly-dropped native (ELF/PE) binaries.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName =~ "java.exe" or InitiatingProcessFileName =~ "java"
| where FileName in~ ("cmd.exe","powershell.exe","bash","sh","wget","curl","nc","ncat","python3")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine,
          FileName, ProcessCommandLine, AccountName
| take 100
```

*Note:* Requires tagging/asset inventory of Artifactory hosts to reduce noise from legitimate Java build tooling; pivot on any newly written binaries in Artifactory install/data directories via DeviceFileEvents for high-confidence triage.

#### Anomalous Artifactory Admin API Token Usage / New Admin User Creation
- **Actor / Campaign:** Unattributed (JFrog Artifactory exploitation chain)
- **MITRE ATT&CK:** T1078.001 — Valid Accounts: Default Accounts; T1548 — Abuse Elevation Control Mechanism
- **Data source:** DeviceNetworkEvents, CommonSecurityLog (if reverse proxy/WAF logs ingested)
- **Source:** [4], [9], [12], [14], [15]

```kql
// CVE-2026-42018 can return an internal anonymous-user token even when anonymous access is
// disabled; CVE-2026-42016 allows privilege escalation via token signature bypass. Hunt for
// REST calls to Artifactory admin/security endpoints from unexpected source IPs.
CommonSecurityLog
| where TimeGenerated > ago(30d)
| where RequestURL has_any ("/artifactory/api/security", "/artifactory/api/system", "/access/api/v1/users")
| where DeviceAction !in ("allow") or RequestMethod in ("POST","PUT","DELETE")
| project TimeGenerated, SourceIP, DestinationIP, RequestURL, RequestMethod, DeviceAction
| take 100
```

*Note:* Column names depend on your reverse-proxy/WAF CEF mapping; adjust `RequestURL`/`DeviceAction` fields accordingly. Baseline normal admin activity first — this is heuristic and needs environment tuning.

#### ScreenConnect Unauthorized File Transfer / Execution in Active Session
- **Actor / Campaign:** Unattributed (CVE-2026-84869 exploitation)
- **MITRE ATT&CK:** T1219 — Remote Access Software; T1548 — Abuse Elevation Control Mechanism
- **Data source:** DeviceProcessEvents, DeviceFileEvents
- **Source:** [9], [13]

```kql
// CVE-2026-84869 allows file transfer/execution through an active ScreenConnect session
// without authorization or host confirmation. Hunt for ScreenConnect processes spawning
// unexpected child processes or writing files outside expected paths.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName has_any ("ScreenConnect.ClientService.exe","ScreenConnect.WindowsClient.exe","ConnectWiseControl.Client.exe")
| where FileName in~ ("cmd.exe","powershell.exe","mshta.exe","wscript.exe","cscript.exe","rundll32.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine, AccountName
| take 100
```

*Note:* ScreenConnect legitimately spawns remote-control child processes; look for execution immediately following unattended/host-confirmation-bypassed sessions, and correlate with unusual off-hours activity.

#### GitLab Repository Commits API Path Traversal Attempt
- **Actor / Campaign:** Unattributed (CVE-2026-85706 exploitation)
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application; T1005 — Data from Local System
- **Data source:** W3CIISLog / AzureDiagnostics (reverse proxy or app gateway logs in front of GitLab)
- **Source:** [10], [16]

```kql
// Unauthenticated path traversal via the repository commits API allows arbitrary file read.
// Hunt web-tier logs for traversal sequences targeting the commits API.
W3CIISLog
| where TimeGenerated > ago(30d)
| where csUriStem has "/api/v4/projects" and csUriStem has "/repository/commits"
| where csUriQuery has_any ("..%2f", "../", "%2e%2e%2f", "..\\")
| project TimeGenerated, cIP, csUriStem, csUriQuery, scStatus
| take 100
```

*Note:* Table/column names depend on where your GitLab reverse proxy logs are ingested (IIS, nginx via Syslog, or App Gateway diagnostics) — adapt the field mapping; unauthenticated 200/206 responses to traversal-laden requests are highest priority.

#### Passkey / Passwordless Sign-In Lure Leading to M365 Account Compromise
- **Actor / Campaign:** ShinyHunters, Helix (Microsoft 365 extortion campaigns)
- **MITRE ATT&CK:** T1566.002 — Phishing: Spearphishing Link; T1556.006 — Modify Authentication Process: Multi-Factor Authentication
- **Data source:** EmailEvents, SigninLogs, AADUserRiskEvents
- **Source:** [3]

```kql
// Threat actors linked to ShinyHunters/Helix use passkey/SSO-themed social engineering to
// harvest M365 credentials/session tokens. Hunt for phishing lures with passkey keywords
// followed by anomalous passkey/authentication-method registration.
EmailEvents
| where Timestamp > ago(30d)
| where Subject has_any ("passkey", "security key", "verify your sign-in", "set up passkey") 
        or Body has_any ("passkey", "register your security key")
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, ThreatTypes, UrlCount
| take 100
```

```kql
// Correlate with unusual new authentication method / passkey registrations shortly after
SigninLogs
| where TimeGenerated > ago(30d)
| where AuthenticationRequirement == "singleFactorAuthentication" or ResultType == 0
| where AppDisplayName has_any ("Office 365", "Microsoft 365")
| summarize count(), makeset(IPAddress) by UserPrincipalName, bin(TimeGenerated, 1h)
| where count_ > 5
| take 100
```

*Note:* First query is keyword-heuristic and needs tuning to your org's phishing simulation/allow-listed vendors; second query flags burst sign-in activity that should be cross-referenced with new MFA/passkey method additions in AAD audit logs.

#### Endpoint Calling Anthropic/LLM API Endpoints from Server or Automation Context
- **Actor / Campaign:** GTG-20006 (Russia-linked, aligned with Midnight Blizzard); various GTGs abusing Claude
- **MITRE ATT&CK:** T1588.007 — Obtain Capabilities: Artificial Intelligence; T1059 — Command and Scripting Interpreter
- **Data source:** DeviceNetworkEvents
- **Source:** [2], [6], [7]

```kql
// State-sponsored and criminal groups (incl. GTG-20006) abuse Claude via API to automate
// malware rebuild/exploitation. Hunt for outbound calls to Anthropic API endpoints from
// servers, build systems, or non-developer endpoints that shouldn't call LLM APIs directly.
DeviceNetworkEvents
| where Timestamp > ago(30d)
| where RemoteUrl has "api.anthropic.com" or RemoteUrl has "claude.ai"
| where DeviceName !in ("known-dev-workstation-allowlist") // tune to your environment
| summarize ConnectionCount = count(), Ports = makeset(RemotePort) by DeviceName, InitiatingProcessFileName, RemoteUrl
| where ConnectionCount > 20
| take 100
```

*Note:* Requires an allow-list of endpoints authorized to call Anthropic APIs (e.g., approved internal tooling); flag automation/CI/build servers and unmanaged scripts making repeated calls, which may indicate script-driven exfiltration or malware-rebuild loops rather than interactive developer use.

#### ClickFix-Style Clipboard-Paste Execution via AI-Platform-Themed Lures
- **Actor / Campaign:** Unattributed (campaigns abusing Claude Artifacts / shared AI conversations per Huntress)
- **MITRE ATT&CK:** T1204.004 — User Execution: Malicious Copy and Paste; T1218 — System Binary Proxy Execution
- **Data source:** DeviceProcessEvents
- **Source:** [8]

```kql
// Huntress reports weaponized Claude Artifacts / shared AI conversations used as ClickFix-style
// lures instructing users to paste and run commands. Hunt for mshta/powershell launched via
// Run dialog or clipboard-paste patterns immediately following browser activity to AI-platform domains.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("powershell.exe","mshta.exe","cmd.exe")
| where ProcessCommandLine has_any ("iex", "IEX", "downloadstring", "-enc", "FromBase64String")
| where InitiatingProcessFileName in~ ("explorer.exe","cmd.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| take 100
```

*Note:* This is a generic ClickFix pattern (not AI-platform-specific IOC); correlate with recent DeviceNetworkEvents/browser history showing navigation to claude.ai or shared-artifact URLs to raise confidence, since legitimate admin scripting will also match.

#### Automated Package Install Followed by Outbound C2 (Supply-Chain Agent Behavior)
- **Actor / Campaign:** RubyGems campaign linked to swarm of OpenAI agents (May 2026)
- **MITRE ATT&CK:** T1195.001 — Supply Chain Compromise: Compromise Software Dependencies and Development Tools; T1059.005 — Command and Scripting Interpreter: Ruby
- **Data source:** DeviceProcessEvents, DeviceNetworkEvents
- **Source:** [1]

```kql
// The RubyGems attack (May 2026) achieved RCE on RubyDoc servers via malicious gems, reportedly
// orchestrated by autonomous AI agents. Hunt for gem install activity immediately followed by
// unexpected outbound network connections from the same process tree — a generic supply-chain
// compromise pattern applicable to build/CI servers pulling Ruby gems.
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessCommandLine has "gem install" or ProcessCommandLine has "bundle install"
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where RemoteUrl !has "rubygems.org"
) on DeviceId
| where DeviceNetworkEvents.Timestamp between (DeviceProcessEvents.Timestamp .. (DeviceProcessEvents.Timestamp + 10m))
| project ProcTime=Timestamp, DeviceName, ProcessCommandLine, NetTime=Timestamp1, RemoteUrl, RemoteIP
| take 100
```

*Note:* No concrete IOCs (package names/hashes) were disclosed in the source; this is a behavioral pattern for build/CI/RubyDoc-hosting servers and needs tuning to exclude legitimate gem mirrors/CDNs.

> [1] OpenAI Agents Linked to RubyGems Campaign That Gained RCE on RubyDoc Servers — https://thehackernews.com/2026/09/openai-agents-linked-to-rubygems.html
> [2] Hackers abused Claude to extract secrets from 1.8M Android apps — https://www.bleepingcomputer.com/news/security/hackers-abused-claude-to-extract-secrets-from-18m-android-apps/
> [3] Passkey-themed phishing attacks lead to Microsoft 365 data theft — https://www.bleepingcomputer.com/news/security/passkey-themed-phishing-attacks-lead-to-microsoft-365-data-theft/
> [4] Artifactory flaws chained in attacks deploying backdoor malware — https://www.bleepingcomputer.com/news/security/artifactory-flaws-chained-in-attacks-deploying-backdoor-malware/
> [6] Claude Used to Automate Exploitation and Data Theft Across Multiple Victims — https://thehackernews.com/2026/09/claude-used-to-automate-exploitation.html
> [7] Russian State-Sponsored Hackers Use Claude to Rebuild Malware After Detection — https://thehackernews.com/2026/09/russian-state-sponsored-hackers-use.html
> [8] How Threat Actors Are Turning Trusted AI Platforms Into an Attack Surface — https://www.bleepingcomputer.com/news/security/how-threat-actors-are-turning-trusted-ai-platforms-into-an-attack-surface/
> [9] CISA Adds Three Known Exploited Vulnerabilities to Catalog — https://www.cisa.gov/news-events/alerts/2026/09/11/cisa-adds-three-known-exploited-vulnerabilities-catalog
> [10] CISA Adds One Known Exploited Vulnerability to Catalog — https://www.cisa.gov/news-events/alerts/2026/09/11/cisa-adds-one-known-exploited-vulnerability-catalog
> [12] Attackers Chain JFrog Artifactory Flaws to Gain Admin Control and Plant Backdoors — https://thehackernews.com/2026/09/attackers-chain-jfrog-artifactory-flaws.html
> [13] CVE-2026-84869 — ConnectWise ScreenConnect — https://nvd.nist.gov/vuln/detail/CVE-2026-84869
> [14] CVE-2026-42016 — JFrog Artifactory Incorrect Authorization Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2026-42016
> [15] CVE-2026-42018 — JFrog Artifactory Improper Authentication Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2026-42018
> [16] CVE-2026-85706 — GitLab Community Edition and Enterprise Edition Path Traversal Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2026-85706

### 2026-09-13

*Generated 2026-09-13 13:22 UTC · model `claude-sonnet-5`*

_Lint: 5 KQL block(s) — structural checks passed. All queries are CANDIDATES; validate before use._

#### Mass CEO-Impersonation Financial Fraud Emails via Third-Party Bulk Infrastructure
- **Actor / Campaign:** Unattributed (Microsoft-disclosed financial fraud scam campaign)
- **MITRE ATT&CK:** T1566.002 — Phishing: Spearphishing Link / T1585.002 — Establish Accounts: Email Accounts
- **Data source:** EmailEvents
- **Source:** [1]

```kql
// Behavioral: burst of CEO-themed financial fraud lures from external senders in short window
EmailEvents
| where Timestamp > ago(30d)
| where SenderDisplayName has_any ("CEO", "Chief Executive", "President", "Managing Director")
| where DeliveryAction == "Delivered"
| where Subject has_any ("payment", "wire", "invoice", "urgent", "transfer", "confidential request")
| summarize EmailCount = count(), Recipients = dcount(RecipientEmailAddress), Subjects = make_set(Subject, 10)
    by SenderFromAddress, SenderDisplayName, bin(Timestamp, 1h)
| where EmailCount > 20  // tune to environment mail volume
| order by EmailCount desc
| take 100
```

*Note:* Heuristic/behavioral only — no IOCs were published; tune volume thresholds and lure keywords to your environment, and cross-reference SenderFromAddress against known legitimate executive addresses to reduce FPs.

#### New Passkey / FIDO2 Security Info Registered on Entra ID Account
- **Actor / Campaign:** Unattributed (Microsoft-disclosed passkey phishing campaign)
- **MITRE ATT&CK:** T1098.005 — Account Manipulation: Device Registration / T1556.006 — Modify Authentication Process: Multi-Factor Authentication
- **Data source:** AuditLogs (Microsoft Entra ID)
- **Source:** [1]

```kql
AuditLogs
| where TimeGenerated > ago(14d)
| where OperationName in ("Register security info", "User registered security info", "Update user")
| where Result == "success"
| extend Detail = tostring(TargetResources[0].displayName)
| where AdditionalDetails has_any ("FIDO2", "Passkey", "Security Key")
| project TimeGenerated, InitiatedBy = tostring(InitiatedBy.user.userPrincipalName), Detail, OperationName, ResultReason, IPAddress = tostring(InitiatedBy.user.ipAddress)
| take 100
```

*Note:* Flag registrations from unfamiliar IPs/geolocations or shortly after a suspicious sign-in/password reset; correlate with SigninLogs for the same UPN in the preceding 1 hour to reduce noise from legitimate self-service passkey onboarding.

#### New Inbox Forwarding Rule Created Shortly After Suspicious Sign-In (Post-Passkey-Phish Exfiltration)
- **Actor / Campaign:** Unattributed (Microsoft-disclosed passkey phishing / cloud account hijack campaign)
- **MITRE ATT&CK:** T1114.003 — Email Collection: Email Forwarding Rule / T1078.004 — Valid Accounts: Cloud Accounts
- **Data source:** CloudAppEvents / OfficeActivity
- **Source:** [1]

```kql
CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType in ("New-InboxRule", "Set-InboxRule", "Set-Mailbox")
| extend Parameters = RawEventData
| where Parameters has_any ("ForwardTo", "ForwardingSmtpAddress", "RedirectTo")
| project Timestamp, AccountDisplayName, ActionType, IPAddress, Parameters
| take 100
```

*Note:* High-signal but requires baseline of legitimate forwarding-rule usage in your tenant; pair with concurrent atypical sign-in location/device to confirm account takeover context described in [1].

#### Suspicious `gem install` Followed by Unexpected Outbound Connection (Supply-Chain RCE)
- **Actor / Campaign:** OpenAI-agent-driven RubyGems supply-chain campaign
- **MITRE ATT&CK:** T1195.001 — Supply Chain Compromise: Compromise Software Dependencies and Development Tools
- **Data source:** DeviceProcessEvents, DeviceNetworkEvents
- **Source:** [2]

```kql
let GemProcs = DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("ruby.exe","ruby","gem.exe","gem")
| where ProcessCommandLine has "install"
| project Timestamp, DeviceId, InstallPid = ProcessId, ProcessCommandLine, AccountName;
GemProcs
| join kind=inner (
    DeviceNetworkEvents
    | where Timestamp > ago(30d)
    | where InitiatingProcessFileName in~ ("ruby.exe","ruby","gem.exe","gem")
) on DeviceId
| where Timestamp1 between (Timestamp .. (Timestamp + 5m))
| project Timestamp, DeviceId, ProcessCommandLine, RemoteIP, RemoteUrl, RemotePort
| take 100
```

*Note:* Behavioral/TTP-based — [2] describes no specific package names, hashes, or IPs; this hunts for the general pattern of a `gem install` immediately followed by network egress, which warrants manual review, especially on RubyDoc/documentation-generation servers.

#### Child Process Spawned From Ruby/Gem Process (Potential Malicious Gem Payload Execution)
- **Actor / Campaign:** OpenAI-agent-driven RubyGems supply-chain campaign
- **MITRE ATT&CK:** T1059 — Command and Scripting Interpreter / T1195.001 — Supply Chain Compromise
- **Data source:** DeviceProcessEvents
- **Source:** [2]

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("ruby.exe","ruby","gem.exe","gem")
| where FileName in~ ("cmd.exe","powershell.exe","bash","sh","curl","wget","python.exe","python3")
| project Timestamp, DeviceId, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, AccountName
| take 100
```

*Note:* Documentation/build servers (e.g., RubyDoc-style gem doc generation) legitimately shell out at times; baseline normal build tooling in your environment before alerting, and prioritize hits where the spawned command includes network utilities (curl/wget) or encoded commands.

> [1] Attackers Use Passkey Phishing to Hijack Microsoft Cloud Accounts and Exfiltrate Data — https://thehackernews.com/2026/09/attackers-use-passkey-phishing-to.html
> [2] OpenAI Agents Linked to RubyGems Campaign That Gained RCE on RubyDoc Servers — https://thehackernews.com/2026/09/openai-agents-linked-to-rubygems.html

### 2026-09-14

*Generated 2026-09-14 13:28 UTC · model `claude-sonnet-5`*

_Lint: 6 KQL block(s) — structural checks passed. All queries are CANDIDATES; validate before use._

#### GrayRabbit backdoor — suspicious child process from Sogou Input Method
- **Actor / Campaign:** China-aligned espionage group exploiting CVE-2026-51990 (Sogou Input Method)
- **MITRE ATT&CK:** T1203 — Exploitation for Client Execution; T1574 — Hijack Execution Flow
- **Data source:** DeviceProcessEvents
- **Source:** [2]

```kql
// Heuristic: Sogou Input Method binaries are not typically observed spawning
// scripting/LOLBIN interpreters. Process names below are inferred from the
// product family (Sogou Input Method / SogouCloud) — verify actual binary
// names in your environment before relying on this.
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName has_any ("Sogou", "SGTool", "SogouCloud", "SGIM")
| where FileName in~ ("cmd.exe","powershell.exe","powershell_ise.exe","rundll32.exe","regsvr32.exe","mshta.exe","wscript.exe","cscript.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessFolderPath, FileName, ProcessCommandLine
| take 100
```

*Note:* No confirmed process/file names were published for GrayRabbit; this is TTP-based and needs tuning against the actual vulnerable binary name once IOCs are released. Expect FPs from legitimate IME auto-update helpers — validate command lines.

#### GrayRabbit — outbound network connections from Sogou Input Method process tree
- **Actor / Campaign:** China-aligned espionage group exploiting CVE-2026-51990
- **MITRE ATT&CK:** T1071 — Application Layer Protocol; T1105 — Ingress Tool Transfer
- **Data source:** DeviceNetworkEvents
- **Source:** [2]

```kql
DeviceNetworkEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName has_any ("Sogou", "SGTool", "SogouCloud", "SGIM")
| where RemoteIPType == "Public"
| where RemotePort in (80, 443, 8080, 8443) or RemotePort !in (80,443)  // include non-standard ports as anomalous
| summarize ConnCount = count(), RemoteIPs = make_set(RemoteIP, 10) by DeviceName, InitiatingProcessFileName, bin(Timestamp, 1h)
| where ConnCount > 5
| take 100
```

*Note:* Establish a baseline first — Sogou IME legitimately calls home to cloud dictionary/update services; alert on new/rare destinations or beaconing patterns rather than raw volume.

#### GrayRabbit — persistence via registry Run key from IME process
- **Actor / Campaign:** China-aligned espionage group exploiting CVE-2026-51990
- **MITRE ATT&CK:** T1547.001 — Registry Run Keys / Startup Folder
- **Data source:** DeviceRegistryEvents
- **Source:** [2]

```kql
DeviceRegistryEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName has_any ("Sogou", "SGTool", "SogouCloud", "SGIM")
| where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce", @"\Winlogon")
| project Timestamp, DeviceName, InitiatingProcessFileName, RegistryKey, RegistryValueName, RegistryValueData
| take 100
```

*Note:* Legitimate IME installers can write Run keys during install/update; scope hunting to hosts with no recent legitimate Sogou update/install event.

#### New passkey/FIDO2 credential registered shortly after risky sign-in
- **Actor / Campaign:** Passkey phishing campaign against Microsoft cloud accounts (Microsoft disclosure)
- **MITRE ATT&CK:** T1556.006 — Modify Authentication Process: Multi-Factor Authentication; T1098.005 — Account Manipulation: Device Registration
- **Data source:** SigninLogs, AuditLogs
- **Source:** [3]

```kql
let RiskySignins = SigninLogs
| where Timestamp > ago(14d)
| where RiskLevelDuringSignIn in ("medium","high") or RiskState == "atRisk"
| project UserPrincipalName, SigninTime = Timestamp, IPAddress, Location = tostring(LocationDetails.city);
AuditLogs
| where TimeGenerated > ago(14d)
| where ActivityDisplayName has "Register security info"
| extend Actor = tostring(InitiatedBy.user.userPrincipalName)
| join kind=inner RiskySignins on $left.Actor == $right.UserPrincipalName
| where TimeGenerated - SigninTime between (0min .. 60min)
| project TimeGenerated, Actor, IPAddress, Location, ActivityDisplayName, AdditionalDetails
| take 100
```

*Note:* This flags accounts that register new sign-in credentials (potentially a passkey) within an hour of a risky sign-in — a strong ATO indicator, but tune the risk-level filter and window to your Entra ID Protection sensitivity to reduce noise from legit self-service registration after travel/VPN changes.

#### Mass CEO-impersonation financial fraud email via third-party delivery infrastructure
- **Actor / Campaign:** Financial fraud scam campaign abusing third-party email infra (Microsoft disclosure)
- **MITRE ATT&CK:** T1566.001 — Phishing: Spearphishing Attachment/Link; T1656 — Impersonation
- **Data source:** EmailEvents, EmailAuthenticationDetails
- **Source:** [3]

```kql
EmailEvents
| where Timestamp > ago(14d)
| where SenderDisplayName has_any ("CEO","Chief Executive Officer","President","Managing Director")
| join kind=inner (
    EmailAuthenticationDetails
    | where Timestamp > ago(14d)
    | where SPFResult != "pass" or DKIMResult != "pass" or DmarcResult != "pass"
) on NetworkMessageId
| where SenderFromAddress !endswith "@yourcompany.com"  // replace with your accepted domains
| summarize RecipientCount = dcount(RecipientEmailAddress), Subjects = make_set(Subject, 5) by SenderFromAddress, SenderDisplayName, bin(Timestamp, 1h)
| where RecipientCount > 20
| take 100
```

*Note:* Update the accepted-domain filter for your tenant; the "over 1M emails in 3 days" pattern from the reporting suggests hunting for burst volume from a single spoofed sender identity rather than isolated messages.

#### Bulk export/download of customer PII following possible pretexting contact (behavioral, generic)
- **Actor / Campaign:** Revolut data breach — threat actor impersonating a government agency to obtain customer data [1]
- **MITRE ATT&CK:** T1567 — Exfiltration Over Web Service; T1530 — Data from Cloud Storage
- **Data source:** CloudAppEvents (or OfficeActivity/SharePoint audit logs, environment-dependent)
- **Source:** [1]

```kql
// Generic anomaly hunt: single identity performing a large-volume export/download
// of files/records in a short window, which is the pattern consistent with an
// insider being socially engineered into handing over bulk customer data.
// No technical IOCs were published for the Revolut incident — tune thresholds locally.
CloudAppEvents
| where Timestamp > ago(14d)
| where ActionType in ("FileDownloaded", "FileDownloadedExternal", "FileAccessed", "FileExported")
| summarize EventCount = count(), DistinctFiles = dcount(ObjectId) by AccountDisplayName, bin(Timestamp, 1h)
| where DistinctFiles > 200 or EventCount > 500
| order by DistinctFiles desc
| take 100
```

*Note:* Highly heuristic and requires baselining per role (e.g., support/compliance staff routinely access larger volumes); pair with DLP alerts on PII/passport-document classifiers if available, since [1] provides no technical IOCs to hunt on directly.

> [1] Revolut discloses data breach exposing financial info, passports — https://www.bleepingcomputer.com/news/security/revolut-discloses-data-breach-exposing-financial-info-passports/
> [2] Hackers exploit Tencent app flaw to deploy GrayRabbit malware — https://www.bleepingcomputer.com/news/security/hackers-exploit-tencent-app-flaw-to-deploy-grayrabbit-malware/
> [3] Attackers Use Passkey Phishing to Hijack Microsoft Cloud Accounts and Exfiltrate Data — https://thehackernews.com/2026/09/attackers-use-passkey-phishing-to.html

### 2026-09-15

*Generated 2026-09-15 13:28 UTC · model `claude-sonnet-5`*

_Lint: 7 KQL block(s) — query 2: unbalanced '()'. All queries are CANDIDATES; validate before use._

#### Rapid Post-Exploitation Pivot from Notebook/RCE to SSH Client
- **Actor / Campaign:** Unattributed human operator (Sysdig research)
- **MITRE ATT&CK:** T1210 — Exploitation of Remote Services / T1021.004 — Remote Services: SSH
- **Data source:** DeviceProcessEvents
- **Source:** [1]

```kql
// Looks for an ssh/scp/sftp client launch within 5 minutes of a marimo-related process on the same device
let marimoProcs = DeviceProcessEvents
| where Timestamp > ago(2d)
| where ProcessCommandLine has "marimo" or FileName has "marimo"
| project DeviceId, MarimoTime = Timestamp;
DeviceProcessEvents
| where Timestamp > ago(2d)
| where FileName in~ ("ssh", "scp", "sftp")
| join kind=inner marimoProcs on DeviceId
| where Timestamp - MarimoTime between (0min .. 5min)
| project DeviceId, MarimoTime, SSHTime = Timestamp, FileName, ProcessCommandLine, AccountName
| take 100
```

*Note:* Heuristic and environment-specific — tune the "marimo" string match to your notebook naming, and extend the time window if your telemetry ingestion has lag. Best deployed on Linux-onboarded cloud workstations/servers running notebook services.

#### Cisco Secure Email Gateway SQL Injection / Root Command Execution Attempt (CVE-2026-76461)
- **Actor / Campaign:** Unattributed (KEV-listed active exploitation)
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application
- **Data source:** CommonSecurityLog (Cisco ESA/AsyncOS syslog forwarded to Sentinel)
- **Source:** [2] [9] [11]

```kql
CommonSecurityLog
| where TimeGenerated > ago(7d)
| where DeviceVendor has "Cisco" and (DeviceProduct has "Email" or DeviceProduct has "AsyncOS")
| where RequestUrl has_any ("UNION SELECT", "' OR '1'='1", "SLEEP(", "--", "xp_cmdshell", ";--")
       or Message has_any ("UNION SELECT", "' OR '1'='1", "xp_cmdshell")
| project TimeGenerated, DeviceVendor, DeviceProduct, SourceIP, DestinationIP, RequestUrl, Message
| take 100
```

*Note:* Requires Cisco ESA syslog ingestion; adjust field/table mapping to your actual CEF/syslog schema. Treat any hit as high priority given root-level RCE impact — validate patch status per CISA BOD 26-04.

#### Chrome Renderer Spawning Script Engines (Possible GRIMWEDGE Exploit Chain)
- **Actor / Campaign:** UTA0560 (China-linked, GRIMWEDGE backdoor)
- **MITRE ATT&CK:** T1189 — Drive-by Compromise / T1204.001 — User Execution: Malicious Link / T1059.007 — JavaScript
- **Data source:** DeviceProcessEvents
- **Source:** [3]

```kql
DeviceProcessEvents
| where Timestamp > ago(3d)
| where InitiatingProcessFileName =~ "chrome.exe"
| where FileName in~ ("wscript.exe", "cscript.exe", "mshta.exe", "powershell.exe", "rundll32.exe", "cmd.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| take 100
```

*Note:* Chrome legitimately spawns very few child processes; any script-engine or shell child from chrome.exe warrants investigation, especially on devices belonging to NGO/advocacy-org users. No published GRIMWEDGE file hashes/domains yet — refine once Volexity IOCs are released.

#### ClickFix-Style Paste-and-Run Execution from Explorer/Browser Context
- **Actor / Campaign:** HBO Max Reddit account compromise (ClickFix malvertising)
- **MITRE ATT&CK:** T1204.004 — User Execution: Malicious Copy and Paste / T1059.001 — PowerShell
- **Data source:** DeviceProcessEvents
- **Source:** [4]

```kql
DeviceProcessEvents
| where Timestamp > ago(3d)
| where InitiatingProcessFileName in~ ("explorer.exe", "chrome.exe", "msedge.exe", "firefox.exe")
| where FileName in~ ("powershell.exe", "cmd.exe", "mshta.exe", "wscript.exe")
| where ProcessCommandLine has_any ("IEX", "Invoke-Expression", "DownloadString", "-enc", "mshta http", "curl.exe -o", "certutil -urlcache")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
| take 100
```

*Note:* Classic ClickFix (fake CAPTCHA/verify-you're-human) pattern: user pastes a run-dialog/PowerShell command from an ad. High-signal but can false-positive on legitimate IT scripting delivered via browser downloads — validate command-line content and source URL/referrer where available.

#### MeshCentral Agent Installation / Unexpected MeshAgent Activity
- **Actor / Campaign:** 3BB network intrusion (Thailand ISP)
- **MITRE ATT&CK:** T1219 — Remote Access Software / T1543 — Create or Modify System Process
- **Data source:** DeviceProcessEvents, DeviceFileEvents
- **Source:** [5]

```kql
union
(
    DeviceFileEvents
    | where Timestamp > ago(14d)
    | where FileName has_any ("meshagent", "MeshAgent.exe", "MeshAgent.msh")
    | project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, ActionType
),
(
    DeviceProcessEvents
    | where Timestamp > ago(14d)
    | where FileName has "meshagent" or ProcessCommandLine has "meshcentral"
    | project Timestamp, DeviceName, FileName, ProcessCommandLine, InitiatingProcessFileName, ActionType = "ProcessCreated"
)
| take 100
```

*Note:* MeshCentral is a legitimate RMM tool, so this will fire on authorized deployments — cross-reference against your approved RMM asset inventory and flag only instances on servers/devices without an expected MeshCentral deployment record.

#### Gitea Web Process Spawning Shell/Download Utilities (Possible Red Heron RCE)
- **Actor / Campaign:** Red Heron (suspected Chinese actor, Gitea RCE campaign)
- **MITRE ATT&CK:** T1190 — Exploit Public-Facing Application / T1059.004 — Unix Shell
- **Data source:** DeviceProcessEvents
- **Source:** [6]

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName has "gitea"
| where FileName in~ ("bash", "sh", "curl", "wget", "python3", "perl", "nc")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, FileName, ProcessCommandLine, AccountName
| take 100
```

*Note:* A Gitea service process spawning a shell or download utility is highly anomalous and should be treated as likely successful RCE. Prioritize internet-facing Gitea hosts, especially Taiwan-based or other externally exposed instances per the reporting.

#### Mass Scanning Behavior Against Internet-Facing Gitea Instances
- **Actor / Campaign:** Red Heron
- **MITRE ATT&CK:** T1595.002 — Active Scanning: Vulnerability Scanning
- **Data source:** DeviceNetworkEvents (or perimeter firewall logs via CommonSecurityLog)
- **Source:** [6]

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where RemotePort == 3000 // default Gitea port
| summarize DestinationsHit = dcount(RemoteIP), Attempts = count() by InitiatingProcessAccountName, DeviceName, bin(Timestamp, 1h)
| where DestinationsHit > 20
| take 100
```

*Note:* Intended for organizations that expose or proxy Gitea and want to spot inbound scan sweeps; if run from an internal vantage point it instead detects a compromised host scanning outward. Threshold (20 distinct destinations/hour) is a starting point and needs environment tuning.

> [1] Human Attacker Exploits Marimo RCE, Reaches SSH Bastion in Eight Seconds — https://thehackernews.com/2026/09/human-attacker-exploits-marimo-rce.html
> [2] Cisco patches Secure Email Gateway zero-day exploited in attacks — https://www.bleepingcomputer.com/news/security/new-cisco-secure-email-zero-day-exploited-to-execute-commands-as-root/
> [3] China-Linked Hackers Exploit Chrome-Windows Zero-Day Chain to Deploy GRIMWEDGE — https://thehackernews.com/2026/09/china-linked-hackers-exploit-chrome.html
> [4] Hackers hijack HBO Max Reddit account to push malware in ClickFix ads — https://www.bleepingcomputer.com/news/security/hackers-hijack-hbo-max-reddit-account-to-push-malware-in-clickfix-ads/
> [5] 3BB Attacker Used MeshCentral Backdoor for Root Access, Targeted Subscriber Credentials — https://thehackernews.com/2026/09/3bb-attacker-used-meshcentral-backdoor.html
> [6] Red Heron Exploits Gitea RCE to Compromise 13 Organizations Across Six Countries — https://thehackernews.com/2026/09/red-heron-exploits-gitea-rce-to.html
> [9] CISA Adds One Known Exploited Vulnerability to Catalog — https://www.cisa.gov/news-events/alerts/2026/09/14/cisa-adds-one-known-exploited-vulnerability-catalog
> [11] CVE-2026-76461 — Cisco Secure Email Gateway SQL Injection Vulnerability — https://nvd.nist.gov/vuln/detail/CVE-2026-76461
