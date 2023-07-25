# ASSESSMENT_NOTES
# Assesment Notes


## Kioptrix (192.168.1.109)
POTENTIAL VULNERABILITIES =>


(80/443) - Potentially vulnerable to OpenFuck (https://www.exploit-db.com/exploits/764), (https://github.com/heltonWernik/OpenLuck)

139 - Potentially vulnerable to trans2open (https://www.rapid7.com/db/modules/exploit/linux/samba/trans2open/), (https://www.exploit-db.com/exploits/7), (https://www.exploit-db.com/exploits/10)

22 - Potentially vulnerable to to buffer overflow (https://www.exploit-db.com/exploits/21402)

### nmap
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-24 19:23 PKT
Nmap scan report for 192.168.1.109
Host is up (0.00084s latency).
Not shown: 65529 closed tcp ports (reset)
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 2.9p2 (protocol 1.99)
| ssh-hostkey: 
|   1024 b8746cdbfd8be666e92a2bdf5e6f6486 (RSA1)
|   1024 8f8e5b81ed21abc180e157a33c85c471 (DSA)
|_  1024 ed4ea94a0614ff1514ceda3a80dbe281 (RSA)
|_sshv1: Server supports SSHv1
80/tcp    open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_http-title: Test Page for the Apache Web Server on Red Hat Linux
| http-methods: 
|_  Potentially risky methods: TRACE
111/tcp   open  rpcbind     2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1          32768/tcp   status
|_  100024  1          32768/udp   status
139/tcp   open  netbios-ssn Samba smbd (workgroup: MYGROUP)
443/tcp   open  ssl/https   Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
|_ssl-date: 2023-07-24T23:24:11+00:00; +9h00m05s from scanner time.
|_http-server-header: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2009-09-26T09:32:06
|_Not valid after:  2010-09-26T09:32:06
| sslv2: 
|   SSLv2 supported
|   ciphers: 
|     SSL2_RC2_128_CBC_EXPORT40_WITH_MD5
|     SSL2_RC4_128_EXPORT40_WITH_MD5
|     SSL2_RC4_128_WITH_MD5
|     SSL2_DES_64_CBC_WITH_MD5
|     SSL2_RC4_64_WITH_MD5
|     SSL2_RC2_128_CBC_WITH_MD5
|_    SSL2_DES_192_EDE3_CBC_WITH_MD5
|_http-title: 400 Bad Request
32768/tcp open  status      1 (RPC #100024)
MAC Address: 5C:BA:EF:4C:F7:C3 (Chongqing Fugui Electronics)
Device type: general purpose
Running: Linux 2.4.X
OS CPE: cpe:/o:linux:linux_kernel:2.4
OS details: Linux 2.4.9 - 2.4.18 (likely embedded)
Network Distance: 1 hop

Host script results:
|_clock-skew: 9h00m04s
|_smb2-time: Protocol negotiation failed (SMB2)
|_nbstat: NetBIOS name: KIOPTRIX, NetBIOS user: <unknown>, NetBIOS MAC: 000000000000 (Xerox)

TRACEROUTE
HOP RTT     ADDRESS
1   0.84 ms 192.168.1.109

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.54 seconds

#### 22
SSH
OpenSSH 2.9p2 (protocol 1.99)

#### 80/443
80/443 - 192.168.1.109 - 6:53PM
Interesting Items:

80/tcp    open  http        Apache httpd 1.3.20 ((Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b)

+ mod_ssl/2.8.4 - mod_ssl 2.8.7 and lower are vulnerable to a remote buffer overflow which may allow a remote shell. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0082, OSVDB-756.

Webalizer Version 2.01 - Information Disclosure - http://192.168.1.109/usage/usage_200909.html

##### nikto
nikto -h http://192.168.1.109
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          192.168.1.109
+ Target Hostname:    192.168.1.109
+ Target Port:        80
+ Start Time:         2023-07-24 18:59:08 (GMT5)
---------------------------------------------------------------------------
+ Server: Apache/1.3.20 (Unix)  (Red-Hat/Linux) mod_ssl/2.8.4 OpenSSL/0.9.6b
+ Server may leak inodes via ETags, header found with file /, inode: 34821, size: 2890, mtime: Thu Sep  6 08:12:46 2001
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ OSVDB-27487: Apache is vulnerable to XSS via the Expect header
+ mod_ssl/2.8.4 appears to be outdated (current is at least 2.8.31) (may depend on server version)
+ OpenSSL/0.9.6b appears to be outdated (current is at least 1.1.1). OpenSSL 1.0.0o and 0.9.8zc are also current.
+ Apache/1.3.20 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ OSVDB-838: Apache/1.3.20 - Apache 1.x up 1.2.34 are vulnerable to a remote DoS and possible code execution. CAN-2002-0392.
+ OSVDB-4552: Apache/1.3.20 - Apache 1.3 below 1.3.27 are vulnerable to a local buffer overflow which allows attackers to kill any process on the system. CAN-2002-0839.
+ OSVDB-2733: Apache/1.3.20 - Apache 1.3 below 1.3.29 are vulnerable to overflows in mod_rewrite and mod_cgi. CAN-2003-0542.
+ mod_ssl/2.8.4 - mod_ssl 2.8.7 and lower are vulnerable to a remote buffer overflow which may allow a remote shell. http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2002-0082, OSVDB-756.
+ Allowed HTTP Methods: GET, HEAD, OPTIONS, TRACE 
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ ///etc/hosts: The server install allows reading of any system file by adding an extra '/' to the URL.
+ OSVDB-682: /usage/: Webalizer may be installed. Versions lower than 2.01-09 vulnerable to Cross Site Scripting (XSS).
+ OSVDB-3268: /manual/: Directory indexing found.
+ OSVDB-3092: /manual/: Web server manual found.
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ OSVDB-3092: /test.php: This might be interesting...
+ /wp-content/themes/twentyeleven/images/headers/server.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wordpresswp-content/themes/twentyeleven/images/headers/server.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wp-includes/Requests/Utility/content-post.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wordpresswp-includes/Requests/Utility/content-post.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wp-includes/js/tinymce/themes/modern/Meuhy.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /wordpresswp-includes/js/tinymce/themes/modern/Meuhy.php?filesrc=/etc/hosts: A PHP backdoor file manager was found.
+ /assets/mobirise/css/meta.php?filesrc=: A PHP backdoor file manager was found.
+ /login.cgi?cli=aa%20aa%27cat%20/etc/hosts: Some D-Link router remote command execution.
+ /shell?cat+/etc/hosts: A backdoor was identified.
+ 8724 requests: 0 error(s) and 30 item(s) reported on remote host
+ End Time:           2023-07-24 18:59:27 (GMT5) (19 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

#### 139
Interesting Items:

SMB
Unix (Samba 2.2.1a)

Could Anonymously Connect to IPC but not Admin

### Findings


#### Test Page
![image](https://github.com/WahajJaved20/Hacked_Vulnerable_Boxes/assets/84095994/7f6ccf3f-1540-4706-b07d-4a79fc660b32)


#### Information Disclosure
404 page
![image](https://github.com/WahajJaved20/Hacked_Vulnerable_Boxes/assets/84095994/d72981f9-7d0d-417e-a681-f7063854b5fd)


Server Header Information Disclosure
![image](https://github.com/WahajJaved20/Hacked_Vulnerable_Boxes/assets/84095994/ac68f5a9-ffa3-405d-b510-fca51231dab4)



#### Undetected Malicious Activity
Bruteforcing SSH
![image](https://github.com/WahajJaved20/Hacked_Vulnerable_Boxes/assets/84095994/5401e73a-fa23-4e36-805e-496114e9a428)



### Exploitation


#### SMB- trans2open
![image](https://github.com/WahajJaved20/Hacked_Vulnerable_Boxes/assets/84095994/dee58b64-7cbc-4f3f-a563-b44e4c7e6b92)


#### 80 - modSSL
![image](https://github.com/WahajJaved20/Hacked_Vulnerable_Boxes/assets/84095994/ab618269-14ad-4d03-9935-744cfc08b5aa)


### Post Exploitation


#### shadow_file
cat /etc/shadow
root:$1$XROmcfDX$tF93GqnLHOJeGRHpaNyIs0:14513:0 :99999:7:::
bin:*:14513:0 :99999:7:::
daemon:*:14513:0 :99999:7:::
adm:*:14513:0 :99999:7:::
lp:*:14513:0 :99999:7:::
sync:*:14513:0 :99999:7:::
shutdown:*:14513:0 :99999:7:::
halt:*:14513:0 :99999:7:::
mail:*:14513:0 :99999:7:::
news:*:14513:0 :99999:7:::
uucp:*:14513:0 :99999:7:::
operator:*:14513:0 :99999:7:::
games:*:14513:0 :99999:7:::
gopher:*:14513:0 :99999:7:::
ftp:*:14513:0 :99999:7:::
nobody:*:14513:0 :99999:7:::
mailnull:!!:14513:0 :99999:7:::
rpm:!!:14513:0 :99999:7:::
xfs:!!:14513:0 :99999:7:::
rpc:!!:14513:0 :99999:7:::
rpcuser:!!:14513:0 :99999:7:::
nfsnobody:!!:14513:0 :99999:7:::
nscd:!!:14513:0 :99999:7:::
ident:!!:14513:0 :99999:7:::
radvd:!!:14513:0 :99999:7:::
postgres:!!:14513:0 :99999:7:::
apache:!!:14513:0 :99999:7:::
squid:!!:14513:0 :99999:7:::
pcap:!!:14513:0 :99999:7:::
john:$1$zL4.MR4t$26N4YpTGceBO0gTX6TAky1:14513:0 :99999:7:::
harold:$1$Xx6dZdOd$IMOGACl3r757dv17LZ9010:14513:0 :99999:7:::



#### passwd_file
cat /etc/passwd
root: x :0 :0:root:/root:/bin/bash                                                                                                                                                                                                             
bin: x :1:1:bin:/bin:/sbin/nologin                                                                                                                                                                                                            
daemon: x :2:2:daemon:/sbin:/sbin/nologin                                                                                                                                                                                                     
adm: x :3:4:adm:/var/adm:/sbin/nologin                                                                                                                                                                                                        
lp: x :4:7:lp:/var/spool/lpd:/sbin/nologin                                                                                                                                                                                                    
sync: x :5:0 :sync:/sbin:/bin/sync                                                                                                                                                                                                             
shutdown: x :6:0 :shutdown:/sbin:/sbin/shutdown                                                                                                                                                                                                
halt: x :7:0 :halt:/sbin:/sbin/halt                                                                                                                                                                                                            
mail: x :8:12:mail:/var/spool/mail:/sbin/nologin                                                                                                                                                                                              
news: x :9:13:news:/var/spool/news:                                                                                                                                                                                                           
uucp: x :10:14:uucp:/var/spool/uucp:/sbin/nologin                                                                                                                                                                                             
operator: x :11:0 :operator:/root:/sbin/nologin                                                                                                                                                                                                
games: x :12: 100:games:/usr/games:/sbin/nologin                                                                                                                                                                                               
gopher: x :13:30:gopher:/var/gopher:/sbin/nologin                                                                                                                                                                                             
ftp: x :14:50:FTP User:/var/ftp:/sbin/nologin                                                                                                                                                                                                 
nobody: x :99:99:Nobody:/:/sbin/nologin                                                                                                                                                                                                       
mailnull: x :47:47::/var/spool/mqueue:/dev/null                                                                                                                                                                                               
rpm: x :37:37::/var/lib/rpm:/bin/bash                                                                                                                                                                                                         
xfs: x :43:43:X Font Server:/etc/X11/fs:/bin/false                                                                                                                                                                                            
rpc: x :32:32:Portmapper RPC user:/:/bin/false                                                                                                                                                                                                
rpcuser: x :29:29:RPC Service User:/var/lib/nfs:/sbin/nologin                                                                                                                                                                                 
nfsnobody: x :65534:65534:Anonymous NFS User:/var/lib/nfs:/sbin/nologin                                                                                                                                                                       
nscd: x :28:28:NSCD Daemon:/:/bin/false                                                                                                                                                                                                       
ident: x :98:98:pident user:/:/sbin/nolcat /etc/passwd                                                                                                                                                                                        
ogin                                                                                                                                                                                                                                        
radvd: x :75:75:radvd user:/:/bin/false                                                                                                                                                                                                       
postgres: x :26:26:PostgreSQL Server:/var/lib/pgsql:/bin/bash                                                                                                                                                                                 
apache: x :48:48:Apache:/var/www:/bin/false                                                                                                                                                                                                   
squid: x :23:23::/var/spool/squid:/dev/null                                                                                                                                                                                                   
pcap: x :77:77::/var/arpwatch:/bin/nologin                                                                                                                                                                                                    
john: x :500:500::/home/john:/bin/bash                                                                                                                                                                                                        
harold: x :501:501::/home/harold:/bin/bash  

