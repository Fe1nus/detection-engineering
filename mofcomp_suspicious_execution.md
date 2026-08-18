## Rule summary

`mofcomp.exe` compiles MOF files into the WMI repository. A MOF can define a complete event
subscription, so compiling one plants a payload that fires on an attacker-chosen trigger and can run
with `SYSTEM` privileges via `WmiPrvSE.exe`.

---

## Detection logic

Matching on image name and original filename together means a renamed copy still hits. Nothing
checks the file being compiled, since `mofcomp` takes any name and any extension. Installers and WMI
do most of the legitimate compiling, so a shell or script host as the parent is worth surfacing, as
is a source path in `temp` or user-writable directories. Either one alerts on its own.

---

## KQL

```kusto
let Lookback = 7d;
let suspParents = dynamic(["cmd.exe", "powershell.exe", "pwsh.exe", "wsl.exe", "wscript.exe", "cscript.exe"]);
let suspPaths = dynamic([@"\appdata\local\temp", @"\appdata\roaming\", @"\users\public\", @"\windows\temp\"]);
DeviceProcessEvents
| where TimeGenerated > ago(Lookback)
| where FileName =~ "mofcomp.exe" or ProcessVersionInfoOriginalFileName =~ "mofcomp.exe"
| extend suspParent = (InitiatingProcessFileName in~ (suspParents))
| extend suspPath = (ProcessCommandLine has_any (suspPaths))
| extend benignWMI = (InitiatingProcessFileName =~ "wmiprvse.exe" and ProcessCommandLine has @"\windows\temp\" and ProcessCommandLine matches regex @'(?i)\.mof(\s|"|$)')
| where (suspParent or suspPath) and not(benignWMI)
| project TimeGenerated, DeviceName, FileName, ProcessVersionInfoOriginalFileName, FolderPath, SHA1, ProcessCommandLine, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessParentFileName
```

---

## ATT&CK mapping

| Tactic               | Technique                                                                               |
| -------------------- | --------------------------------------------------------------------------------------- |
| Persistence          | [T1546.003 — WMI Event Subscription](https://attack.mitre.org/techniques/T1546/003/)     |
| Privilege Escalation | [T1546.003 — WMI Event Subscription](https://attack.mitre.org/techniques/T1546/003/)     |
| Execution            | [T1047 — Windows Management Instrumentation](https://attack.mitre.org/techniques/T1047/) |
| Defense Evasion      | [T1218 — System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)      |

---

## References

- [Microsoft — mofcomp](https://learn.microsoft.com/en-us/windows/win32/wmisdk/mofcomp)
- [MITRE ATT&CK — T1546.003 WMI Event Subscription](https://attack.mitre.org/techniques/T1546/003/)
- [The DFIR Report — SELECT XMRig FROM SQLServer (11 Jul 2022)](https://thedfirreport.com/2022/07/11/select-xmrig-from-sqlserver/)
- [SANS — Finding Evil WMI Event Consumers with Disk Forensics](https://www.sans.org/blog/finding-evil-wmi-event-consumers-with-disk-forensics)
