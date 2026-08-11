## Rule summary

This rule looks for Microsoft 365 sessions being kept alive by automated token refresh after an AiTM phishing compromise. It pulls successful Outlook sign-ins from the non-interactive log that carry an odd browser or user agent, groups them by `SessionId`, and measures the time between refreshes. Sessions that refresh roughly every eight hours, or that appear from three or more autonomous systems, are flagged.

The behaviour is described in Arctic Wolf Labs' "Payroll Pirates" reporting, which overlaps with the cluster Microsoft tracks as Storm-2755. After the victim authenticates through the AiTM proxy, the stolen session is maintained by the attacker's automation instead of the victim's mail client. That automation refreshes on a fixed schedule and exits through rotating residential proxies, so the `SessionId` stays the same while the IP address, ASN, and location change.

---

## Detection logic

Three signals to pay attention to:

**Client mismatch.** Under the Microsoft Outlook app, the DeviceDetail browser value is either empty for native clients or reflects the embedded rendering engine, which on Windows is Edge because new Outlook runs on WebView2. No Outlook client embeds Firefox, so its appearance here means the token is being used outside Outlook. Sessions in this campaign reported Firefox (131.0 and 151.0 have both been seen) or Python Requests while still naming Microsoft Outlook as the application. Version numbers change, so the rule matches on browser family.

**Refresh cadence.** Rows are sorted by user, session, and time, and `prev()` gives the gap to the previous sign-in in the same session. Gaps of seven to nine hours are counted. Legitimate clients refresh at irregular intervals driven by user activity. Two eight-hour gaps means the session has been maintained for at least sixteen hours.

**Session spread.** A single `SessionId` seen from three or more ASNs means the session is being replayed from infrastructure the user is not behind.

A hit means the session is not behaving like an interactive user. It is not confirmation of compromise. Pivot on the `SessionId` to the interactive sign-in that opened it and check the source address and browser and OS combination.

---

## KQL

```kusto
let Lookback = 14d;
AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(Lookback)
| where AppDisplayName == "Microsoft Outlook" and ResultType == "0"
| extend Browser = tostring(todynamic(DeviceDetail).browser)
| where Browser contains "Firefox" or UserAgent contains "python-requests"
| where isnotempty(SessionId)
| project TimeGenerated, UserPrincipalName, SessionId, IPAddress, AutonomousSystemNumber, Browser
| sort by UserPrincipalName asc, SessionId asc, TimeGenerated asc
| extend GapH = iff(prev(UserPrincipalName) == UserPrincipalName and prev(SessionId) == SessionId,
                    datetime_diff("minute", TimeGenerated, prev(TimeGenerated)) / 60.0, real(null))
| summarize SignIns = count(), EightHourGaps = countif(GapH between (7.0 .. 9.0)),
            DistinctIPs = dcount(IPAddress), DistinctASNs = dcount(AutonomousSystemNumber),
            FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated)
        by UserPrincipalName, SessionId
| where EightHourGaps >= 2 or DistinctASNs >= 3
| sort by EightHourGaps desc, DistinctASNs desc
```

---

## ATT&CK Mapping

| Tactic            | Technique                                                                                    |
| ----------------- | -------------------------------------------------------------------------------------------- |
| Credential Access | [T1557 — Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/)                 |
| Defense Evasion   | [T1550.001 — Application Access Token](https://attack.mitre.org/techniques/T1550/001/)        |
| Persistence       | [T1078.004 — Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)  |
| Collection        | [T1114.002 — Remote Email Collection](https://attack.mitre.org/techniques/T1114/002/)         |

---

## References

- [Arctic Wolf Labs: Payroll Pirates — Strange New Tides in BEC](https://arcticwolf.com/resources/blog/payroll-pirates-strange-new-tides-in-business-email-compromise/)
- [Microsoft: Investigating Storm-2755 payroll pirate attacks](https://www.microsoft.com/en-us/security/blog/2026/04/09/investigating-storm-2755-payroll-pirate-attacks-targeting-canadian-employees/)
- [Microsoft Learn: Non-interactive sign-in logs](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-noninteractive-sign-ins)
- [Microsoft Learn: AADNonInteractiveUserSignInLogs table](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/aadnoninteractiveusersigninlogs)
