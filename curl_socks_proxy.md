## Rule summary

This rule detects curl run with proxy, SOCKS, or tunnel options, a common way to route traffic through a proxy or tunnel a protocol for command-and-control. It covers Windows, macOS, and Linux, and matches the short `-x` flag and the longer `--proxy`, `--socks5`, and `--proxytunnel` forms.

The rule only sees proxying configured on the command line. When the proxy comes from an environment variable (`ALL_PROXY`, `HTTPS_PROXY`, and similar) or a `.curlrc` file, there is nothing on the command line to match, and those cases are left to the companion DeviceFileEvents and DeviceNetworkEvents rules.

---

## Detection logic

The rule flags curl command lines carrying a proxy, SOCKS, or tunnel option, split into two groups by signal strength.

**Category 1** (tunnelling-grade) covers the SOCKS flags (`--socks4`, `--socks4a`, `--socks5`, `--socks5-hostname`), SOCKS proxy URLs (`socks4://`, `socks4a://`, `socks5://`, `socks5h://`), `--proxytunnel` (which tunnels non-HTTP protocols over the HTTP proxy via `CONNECT`), and `--preproxy`. These are rare in normal use and specific enough to alert on by themselves. `--socks5` is matched as a prefix, so its `-hostname`, `-basic`, and `-gssapi*` variants are caught as well.

**Category 2** (generic HTTP proxy) covers the short `-x` flag and `--proxy`, including sub-flags such as `--proxy-user`. These are common behind corporate egress proxies and in CI/CD, so they are better used for triage or correlation. `-x` is matched case-sensitively: `-x` is the proxy flag but `-X` is `--request`, so a case-insensitive match would fire on every `curl -X POST`.

A match only shows that curl was configured to use a proxy, not that anything was tunnelled. Confirm against DeviceNetworkEvents before treating a hit as C2.

---

## KQL

```kusto
let Lookback = 30d;
DeviceProcessEvents
| where TimeGenerated >= ago(Lookback)
| where FileName in~ ("curl","curl.exe")
or FolderPath endswith "/curl" or FolderPath endswith @"\curl.exe" or FolderPath endswith @"\curl"
or ProcessVersionInfoOriginalFileName in~ ("curl","curl.exe")
| where ProcessCommandLine matches regex @"(?-i)(?:^|\s)-x[=\s]*\S"
or ProcessCommandLine matches regex @"--(?:pre)?proxy\b"
or ProcessCommandLine matches regex @"--proxytunnel\b"
or ProcessCommandLine matches regex @"--socks(?:4a?|5)"
or ProcessCommandLine matches regex @"(?i)socks(?:4a?|5h?)://"
| extend ProxyTarget = coalesce(
extract(@"(?i)socks(?:4a?|5h?)://(\S+)", 1, ProcessCommandLine),
extract(@"(?-i)(?:^|\s)-x[=\s]*""?([^""\s]+)", 1, ProcessCommandLine),
extract(@"--(?:pre)?proxy[=\s]+""?([^""\s]+)", 1, ProcessCommandLine))
```
`ProxyTarget` is best-effort here. Quoting or shell-variable indirection such as `-x $VAR` will break the extraction.

---

## ATT&CK Mapping

| Tactic | Technique |
| --- | --- |
| Command and Control | [T1090 — Proxy](https://attack.mitre.org/techniques/T1090/) |
| Command and Control | [T1090.002 — External Proxy](https://attack.mitre.org/techniques/T1090/002/) |
| Command and Control | [T1572 — Protocol Tunneling](https://attack.mitre.org/techniques/T1572/) |

---

## References

- [Microsoft Learn: DeviceProcessEvents table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table)
- [MITRE ATT&CK: T1090 Proxy](https://attack.mitre.org/techniques/T1090/)
- [MITRE ATT&CK: T1572 Protocol Tunneling](https://attack.mitre.org/techniques/T1572/)
- [curl: proxy documentation](https://everything.curl.dev/usingcurl/proxies/)
- [curl: proxy environment variables](https://everything.curl.dev/usingcurl/proxies/env.html)
- [curl: manual page](https://curl.se/docs/manpage.html)
