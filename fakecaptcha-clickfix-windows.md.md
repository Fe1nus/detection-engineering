## Rule summary

This rule detects ClickFix/FakeCaptcha activity involving the Windows Run dialog (Win+R) using the RunMRU registry artifact as the primary signal. It focuses on LOLBin execution and groups binaries into two categories: those that support remote execution by name alone and those that require a specific parameter to enable execution.

---

## Detection logic

### LOLBin categories

**Category 1 — Direct remote execution** (matched by name only): any RunMRU entry containing one of these binaries warrants further investigation.

| LOLBin(s)                  | Remote execution surface                                         |
| -------------------------- | ---------------------------------------------------------------- |
| `powershell`, `pwsh`       | Retrieves and executes remote content                            |
| `mshta`                    | Executes remote HTA/script content                               |
| `rundll32`                 | Remote DLL execution via UNC/WebDAV paths                        |
| `regsvr32`                 | Remote scriptlet execution via `scrobj.dll`                      |
| `msiexec`                  | Remote MSI/MST/DLL execution                                     |
| `wmic`                     | Remote XSL execution via `/format:`                              |
| `hh`                       | Remote CHM/HTML Help                                             |
| `ieexec`                   | Downloads and executes remote .NET assemblies                    |
| `cmstp`                    | Remote INF execution                                             |
| `pcalua`                   | Execution from network paths                                     |
| `scriptrunner`             | Script execution in App-V environments                           |
| `syncappvpublishingserver` | Can proxy PowerShell execution without invoking `powershell.exe` |
| `wscript`, `cscript`       | Remote script execution from UNC/WebDAV paths                    |

**Category 2 — Conditional remote execution** (name + parameter required):

| LOLBin            | Required condition             | Rationale                                                                                             |
| ----------------- | ------------------------------ | ----------------------------------------------------------------------------------------------------- |
| `cmd` / `comspec` | `/c` or `/k` + UNC/WebDAV path | Executes commands from remote paths but does not retrieve content itself                              |
| `bitsadmin`       | `setnotifycmdline`             | File transfer utility by default. This option enables execution                                       |
| `ftp`             | `-s:`                          | Script mode enables automated command execution and may be abused through shell escapes (`!`) within the script |

## KQL

```kusto
let DirectRemoteExecLOLBins = dynamic([
    "powershell","pwsh","mshta","rundll32","regsvr32","msiexec",
    "wmic","hh","ieexec","cmstp","pcalua","scriptrunner",
    "syncappvpublishingserver","wscript","cscript"]);
let ConditionalRemoteExecLOLBins = dynamic(["cmd","comspec","bitsadmin","ftp"]);
let ConditionalRemoteExecParameters = @"(?i)(\bcmd(\.exe)?\b|\bcomspec\b).*/[ck]\b.*(\\\\|davwwwroot|@(ssl|\d+)\\)|\bbitsadmin(\.exe)?\b.*setnotifycmdline|\bftp(\.exe)?\b.*-s:";
DeviceRegistryEvents
| where TimeGenerated > ago(30d)
| where ActionType =~ "RegistryValueSet" and InitiatingProcessFileName =~ "explorer.exe"
| where RegistryKey endswith @"\RunMRU"
| where RegistryValueName != "MRUList"
| where (
    RegistryValueData has_any (DirectRemoteExecLOLBins)
    or (
        RegistryValueData has_any (ConditionalRemoteExecLOLBins)
        and RegistryValueData matches regex ConditionalRemoteExecParameters
    )
)
```

---

## ATT&CK Mapping

| Tactic                      | Technique                                                                               |
| --------------------------- | --------------------------------------------------------------------------------------- |
| Execution                   | [T1204 — User Execution](https://attack.mitre.org/techniques/T1204/)                    |
| Execution                   | [T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/) |
| Execution / Defense Evasion | [T1218 — System Binary Proxy Execution](https://attack.mitre.org/techniques/T1218/)     |
| Command and Control         | [T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/) ¹           |

> ¹ T1105 reflects the remote execution capability of the matched LOLBins. A RunMRU entry alone does not confirm that a payload was downloaded or transferred.

---

## References

* [Microsoft Security Blog: Think before you Click(Fix)](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/)
* [Microsoft Learn: DeviceRegistryEvents table in Microsoft Defender XDR](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table)
* [Cyber Triage: How to Investigate RunMRU](https://www.cybertriage.com/blog/how-to-investigate-runmru-2026/)
* [LOLBAS Project](https://lolbas-project.github.io/) — entries for the binaries listed above
