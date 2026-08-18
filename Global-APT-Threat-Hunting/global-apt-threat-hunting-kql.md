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
