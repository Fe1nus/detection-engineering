## Rule summary

With access to the Chrome DevTools Protocol on a live browser, an attacker can pull cookies, extract
saved-password material, and drive the browser as the user. App-Bound Encryption doesn't help here.
The browser decrypts its own data, and CDP just asks the browser for it. Device-bound session
cookies don't stop it either, though they do change its shape. The attacker has to keep working
through that browser on that host instead of lifting a token and replaying it from their own
infrastructure, which means a persistent foothold and live traffic rather than a quiet one-off
theft.

Chrome 136 made this harder. The remote-debugging switches are now ignored on the default profile
unless you also pass a non-standard `--user-data-dir`, and that gets you a clean profile with no
cookies in it. The technique here gets around that by never restarting the browser. It injects into
the running process and calls Chromium's internal `StartRemoteDebuggingServer` directly. The user's
profile stays loaded, and no switch ever lands on a command line, so anything keyed on launch
arguments won't see it. It isn't artifact-free though. Enabling CDP binds a local listening socket,
and a browser listening on a TCP port is unusual enough to be worth a hunt of its own.

---

## Detection logic

This rule scopes to `CreateRemoteThreadApiCall` because it gives the cleanest starting point. It
names the target process in `FileName`, so you can filter straight to browsers, and it carries the
initiator's name, path, command line and PID for follow-up. The other injection ActionTypes in
`DeviceEvents` are worth hunting through too, including the memory allocation, memory protect,
thread context and APC variants.

---

## KQL

```kusto
let Lookback = 7d;
let Browsers = dynamic(["chrome.exe","msedge.exe","brave.exe","opera.exe","vivaldi.exe"]);
let SystemInjectors = dynamic(["explorer.exe","svchost.exe","services.exe","csrss.exe","wininit.exe"]);
DeviceEvents
| where TimeGenerated > ago(Lookback)
| where ActionType == "CreateRemoteThreadApiCall"
| where FileName in~ (Browsers)
| where ProcessId != InitiatingProcessId
| extend InitPath = tolower(InitiatingProcessFolderPath)
| where not(InitiatingProcessFileName in~ (Browsers)
        and (InitPath contains @"\google\chrome\application"
          or InitPath contains @"\microsoft\edge\application"
          or InitPath contains @"\bravesoftware\"
          or InitPath contains @"\opera"
          or InitPath contains @"\vivaldi\application"))
| where not(InitiatingProcessFileName in~ (SystemInjectors)
        and InitPath startswith @"c:\windows\")
// Placeholder exclusions. Replace with your own baseline.
// Blank paths are kept on purpose. They are usually a protected or kernel-mode
// process with no normal process record, so run those down on the host itself.
| where isempty(InitPath)
     or not(InitPath startswith @"c:\programdata\microsoft\windows defender"
         or InitPath startswith @"c:\program files\cyberark\endpoint privilege manager")
| summarize
    InjectionCount      = count(),
    TargetBrowser       = make_set(FileName, 8),
    InjectorName        = make_set(InitiatingProcessFileName, 8),
    InjectorPath        = make_set(InitiatingProcessFolderPath, 8),
    InjectorCommandLine = make_set(InitiatingProcessCommandLine, 8),
    InjectorPIDs        = make_set(InitiatingProcessId, 20)
    by DeviceId, TargetDevice = DeviceName, ImpactedAccount = InitiatingProcessAccountName
| order by InjectionCount asc
```

---

## ATT&CK mapping

| Tactic | Technique |
| --- | --- |
| Collection | [T1185 — Browser Session Hijacking](https://attack.mitre.org/techniques/T1185/) |
| Credential Access | [T1539 — Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/) |
| Credential Access | [T1555.003 — Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/) |
| Defense Evasion | [T1055 — Process Injection](https://attack.mitre.org/techniques/T1055/) |

---

## References

- [SpecterOps — Return of the Cookie Monster (Andrew Gomez, 13 Aug 2026)](https://specterops.io/blog/2026/08/13/chrome-devtools-protocol-cookie-theft/)
- [Cedric Van Bockhaven — Modern Session Hijacking by Living off the DevTools Protocol (SOCON 2026)](https://specterops.io/so-con/)
- [DeathFlamingo — Enabling CDP in a running browser](https://deathflamingo.com/blog/cdp_enabler/)
- [Google — Changes to remote debugging in Chrome 136](https://developer.chrome.com/blog/remote-debugging-port)
- [Chrome DevTools Protocol reference](https://chromedevtools.github.io/devtools-protocol/)
