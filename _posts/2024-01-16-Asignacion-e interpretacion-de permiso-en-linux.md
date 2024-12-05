---
layout: single
title: Asignacion e interpretacion de permiso en linux
excerpt:
date: 2024-01-16
classes: wide
header:
  teaser: ![](https://404zzero.github.io/zzero.github.io//assets/images/archivoslinux/kali_linux.jpg)
  teaser_home_page: true
categories:
  - hacking
  - linux
  - 
tags:  
  - hacking
  - linux
---

buenas. hoy vengo a explicar la asignacion e interpretacion de permisos en lix. 
voy a enseñaros que son es D RMX y todas las cosas rara que aparecen.

![](https://404zzero.github.io/zzero.github.io//assets/images/archivoslinux/Captura.PNG)

aqui tenemos un directorio llmando "Pepito", y vemos que pone "drwxr-xr-x"

lo promerimero que tenemos que saber esque esto se divide en 4 trozos: "d" "rwx" "r-x" "r-x"

cada grupo tiene un significado y un uso

## primer grupo

la "d" quiere decir directory o directorio por ello podemos determinar que es un fichero o carpeta.

si esta fuera una "f" seria fiel por lo que seria un archivo de cualquier extension.

## segundo grupo 

el segundo grupo nos dice los permisos que tiene el USUARIO QUE A CREADO EL FICHERO O ARCHIVO.

vale y para saber que permisos tiene nos tenemos que figar en la letras:

r=read
w=writing
x=execut

![](https://404zzero.github.io/zzero.github.io//assets/images/archivoslinux/4.PNG)

vale y que quiere decir esto, pues que si hay una "r" puede leer por lo que puede hacer un cat por ejemplo, si hay una "w" puede editar el archivo o crear archivos en un directorio y si hay una "x" quiere decir que podemos o ejecutar el archivo o acader al directorio.

## tercer grupo

el tercer grupo esta relacionado al grupo al que estas unido.

cada usuario independientemente tienen su propio grupo al crealos pero si quieres puedes añadirlos a un grupo con varios usuarios.

por ejemplo si estas quieres haceder a un fichero pero tiene restriciones si no eres de su mismo grupo pues se te aplicaran.

vale y para saber que permisos tiene nos tenemos que figar en la letras:

r=read
w=writing
x=execut

es exactamente lo mismo que en el segundo grupo.

que quiere decir esto, pues que si hay una "r" puede leer por lo que puede hacer un cat por ejemplo, si hay una "w" puede editar el archivo o crear archivos en un directorio y si hay una "x" quiere decir que podemos o ejecutar el archivo o acader al directorio.

## cuarto grupo

el ultimo grupo esta relacionado a que cosas pueden hacer otros usuarios.

por ejemplo mi usarios es zzero y yo quiero haceder a un fichero de pepito pues puede qu etenga restriciones

r=read
w=writing
x=execut

y vuelve a ser exactamente lo mismo

que quiere decir esto, pues que si hay una "r" puede leer por lo que puede hacer un cat por ejemplo, si hay una "w" puede editar el archivo o crear archivos en un directorio y si hay una "x" quiere decir que podemos o ejecutar el archivo o acader al directorio.

## conclusion

en esta caso seria "drwxr-xr-x" o "d" "rwx" "r-x" "r-x" por lo que podemos determinal lo siguiente:
 - es un directorio por la d
 - para el usuario creador (en esta caso pepito) tiene todos los permisos r=read w=writing x=execut
 - para grupos tienen todos menos el de modificar r=read w=writing x=execut
 - para otros usuarios tienen todos menos el de modificar r=read w=writing x=execut

## excepcion

si es el usuario "root" el que intenta modificar, pasar, crear SIEMPRE VA A PODER AUN TENIENDO RESTRIPCIONES
