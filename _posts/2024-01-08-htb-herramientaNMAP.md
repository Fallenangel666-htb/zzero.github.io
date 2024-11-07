---
layout: single
title: Nmap bash automated tool
excerpt: "tool that allows scanning in different ways with the nmap tool in bash"
date: 2024-01-08
classes: wide
header:
  teaser: /assets/images/Bash_Logo_Colored.svg.png
  teaser_home_page: true
categories:
  - bash
  - hacking
tags:  
  - vscode
  - kali
---

I have created a tool that automates port scanning by nmap in bash. This tool can do 4 different scans depending on the need.



## script

this time I'm not going to give you the whole code from the beginning and what I'm going to do is explain the code as I go along ok? great let's get started 

first we open in the linux terminal (remember that I am in kali/debian if you are in another distribution like arch alomejor does not work for you) and we use nano or vi to create the file where we are going to make the script and we put at the end of it .sh

![](/assets/images/captura.png)

great next thing is to check if you are root to be able to run nmap properly. to do this we will use an if and check if nustar id ends in 0 or 1. if it is 0 it won't let us run it because we are not root.

```bash
#!/bin/bash

if [ $(id -u) -ne 0 ]; then #hago comprovacion de si eres root
    echo -e "No eres root"
    exit
fi
```
ok with this verification we can move on to the next step which is to check if nmap is installed. 

```bash
#!/bin/bash

if ! command -v nmap &> /dev/null; then #este if comprueba con ! command -v nmap si nmap esta instalado
    echo -e "\n[!] Hay que instalar nmap en este PC"
    apt update && apt upgrade && apt install nmap #installo y  aprovecho para actualizar
fi
```
ok if you already have it perfect. i also take advantage with that previous code and update your system xd. well the next thing is to put the ip that we want to scan.

```bash
#!/bin/bash

read -p "Introduce la IP que quieres escanear: " ip #pido la ip que queremos escanear
```
perfect. i apologise again for putting the codes in spanish but i am a native spanish speaker. well the next thing we are going to do is to provide the scanning options which are 5.

```bash
#!/bin/bash

while true; do #entro en un bucle por si sale un aopcion no valida
    echo -e "\n1) Escaneo rápido pero con ruido"
    echo "2) Normal"
    echo "3) Escaneo silencioso"
    echo "4) Escaneo de servicios y versiones"
    echo "5) Nada, salir"
    read -p "Seleccione la opción que quiere usar: " opcion
```

it is worth adding that I implement a "while" in case none of the 5 options comes out so that it repeats in the form of a loop. and for almost the last thing we are going to make the scripts for each of the options (I use "case" because it seems better for this type of tool but you can use "if" if you want).

```bash
#!/bin/bash

    case $opcion in #el case es parecido al switch de por ejemplo c y es mejor para estos casos creo. esto se puede hacer con un if tambien
        1)
            clear && nmap -p- --open --min-rate 5000 -T5 -sS -Pn -n -v $ip > escaneo_rapido.txt && echo -e "Se ha guardado en escaneo_rapido.txt"
            exit
            ;;
        2)
            clear && nmap -p- --open $ip > escaneo_normal.txt && echo -e "Se ha guardado en escaneo_normal.txt"
            exit
            ;;
        3)
            clear && nmap -p- -T2 -sS -Pn -f $ip > escaneo_silencioso.txt && echo -e "Se ha guardado en escaneo_silencioso.txt"
            exit
            ;;
        4)
            clear && nmap -sV -sC $ip > escaneo_servicios.txt && echo -e "Se ha guardado en escaneo_servicios.txt"
            exit
            ;;
        5)
            break
            ;;
        *)
            echo -e "404_error"
            ;;
    esac
done
```
and with this we have created the tool. i'm going to leave the complete script below :'3

```bash
#!/bin/bash

#!/bin/bash

if [ $(id -u) -ne 0 ]; then #hago comprovacion de si eres root
    echo -e "No eres root"
    exit
fi

if ! command -v nmap &> /dev/null; then #este if comprueba con ! command -v nmap si nmap esta instalado
    echo -e "\n[!] Hay que instalar nmap en este PC"
    apt update && apt upgrade && apt install nmap #installo y  aprovecho para actualizar
fi

read -p "Introduce la IP que quieres escanear: " ip #pido la ip que queremos escanear

while true; do #entro en un bucle por si sale un aopcion no valida
    echo -e "\n1) Escaneo rápido pero con ruido"
    echo "2) Normal"
    echo "3) Escaneo silencioso"
    echo "4) Escaneo de servicios y versiones"
    echo "5) Nada, salir"
    read -p "Seleccione la opción que quiere usar: " opcion

    case $opcion in #el case es parecido al switch de por ejemplo c y es mejor para estos casos creo. esto se puede hacer con un if tambien
        1)
            clear && nmap -p- --open --min-rate 5000 -T5 -sS -Pn -n -v $ip > escaneo_rapido.txt && echo -e "Se ha guardado en escaneo_rapido.txt"
            exit
            ;;
        2)
            clear && nmap -p- --open $ip > escaneo_normal.txt && echo -e "Se ha guardado en escaneo_normal.txt"
            exit
            ;;
        3)
            clear && nmap -p- -T2 -sS -Pn -f $ip > escaneo_silencioso.txt && echo -e "Se ha guardado en escaneo_silencioso.txt"
            exit
            ;;
        4)
            clear && nmap -sV -sC $ip > escaneo_servicios.txt && echo -e "Se ha guardado en escaneo_servicios.txt"
            exit
            ;;
        5)
            break
            ;;
        *)
            echo -e "404_error"
            ;;
    esac
done
```
