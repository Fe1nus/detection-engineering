## Rule summary

This hunt identifies JetBrains IDE plugins observed in endpoint file telemetry across Windows, macOS, and Linux. It can be used to scope developer exposure after reports of malicious JetBrains Marketplace plugins stealing AI provider API keys.

---

## Detection logic

The rule searches default JetBrains user plugin locations and extracts the plugin folder name from the matched path.

**Targeted paths**:

| OS | Path |
| -- | ---- |
| Windows | `%APPDATA%\JetBrains\<product><version>\plugins\<plugin>` |
| macOS | `~/Library/Application Support/JetBrains/<product><version>/plugins/<plugin>` |
| Linux | `~/.local/share/JetBrains/<product><version>/<plugin>` |

The product directory must contain a version number, which helps avoid unrelated JetBrains folders such as `Toolbox`, `Daemon`, and `Air`.

This is an exposure and inventory hunt. If the list of installed plugins is manageable, it can be reviewed manually for suspicious or unauthorized entries. In larger environments, this hunt should be combined with known indicators, network activity, or audit logs to identify evidence of abuse.

## KQL

```kusto
let JetBrainsPluginsPaths = @"(?i)(\\AppData\\Roaming\\JetBrains\\[^\\]*[0-9][^\\]*\\plugins\\[^\\]+|/Library/Application Support/JetBrains/[^/]*[0-9][^/]*/plugins/[^/]+|/\.local/share/JetBrains/[^/]*[0-9][^/]*/[^/]+)";
DeviceFileEvents
| where TimeGenerated > ago(30d)
| where FolderPath matches regex JetBrainsPluginsPaths
| extend ProductVersion = coalesce(
extract(@"(?i)\\AppData\\Roaming\\JetBrains\\([^\\]*[0-9][^\\]*)\\plugins\\", 1, FolderPath),
extract(@"(?i)/Library/Application Support/JetBrains/([^/]*[0-9][^/]*)/plugins/", 1, FolderPath),
extract(@"(?i)/\.local/share/JetBrains/([^/]*[0-9][^/]*)/", 1, FolderPath)
)
| extend PluginName = coalesce(
extract(@"(?i)\\AppData\\Roaming\\JetBrains\\[^\\]*[0-9][^\\]*\\plugins\\([^\\]+)", 1, FolderPath),
extract(@"(?i)/Library/Application Support/JetBrains/[^/]*[0-9][^/]*/plugins/([^/]+)", 1, FolderPath),
extract(@"(?i)/\.local/share/JetBrains/[^/]*[0-9][^/]*/([^/]+)", 1, FolderPath)
)
| summarize ProductVersions = make_set(ProductVersion), EventCount = count(), Devices = dcount(DeviceName), DeviceList = make_set(DeviceName), Users = make_set(InitiatingProcessAccountUpn), ExamplePaths = make_set(FolderPath, 5)
by PluginName
| order by EventCount desc
```
---

## ATT&CK Mapping

| Tactic | Technique |
| ------ | --------- |
| Initial Access | [T1195.002 — Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/) |
| Credential Access | [T1552.001 — Credentials In Files](https://attack.mitre.org/techniques/T1552/001/) |
| Exfiltration | [T1041 — Exfiltration Over C2 Channel](https://attack.mitre.org/techniques/T1041/) |

---

## References

* [BleepingComputer: Malicious JetBrains Marketplace plugins steal AI API keys from developers](https://www.bleepingcomputer.com/news/security/malicious-jetbrains-marketplace-plugins-steal-ai-api-keys-from-developers/)
* [JetBrains: Directories used by the IDE](https://www.jetbrains.com/help/idea/directories-used-by-the-ide-to-store-settings-caches-plugins-and-logs.html)
* [Microsoft Learn: DeviceFileEvents table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table)
