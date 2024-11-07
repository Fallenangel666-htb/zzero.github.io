---
layout: single
title: automated "find" command tool
excerpt: 
date: 2024-01-09
classes: wide
header:
  teaser: /assets/images/Bash_Logo_Colored.svg.png
  teaser_home_page: true
categories:
  - bash
  - linux
tags:  
  - linux
  - bash
---

good. today I bring you a tool that I developed while I was in class and it is an automator of the find command but it can only search files for now. 

great so let's get started

## script

OK, I will do it as before and I will explain the code step by step. 

first i create a "while" condition so that it repeats and i put a "read" so that we can choose one of the options. i make these options because at least in my experience the find command has worked differently depending on whether you are root or not. 

```bash
#!/bin/bash

while true; do
    read -p "¿Quieres la versión con root o sin ser root? sin/con/salir: " version


```

great the next thing we are going to do is the verification of the "sin" option (sorry for putting it in Spanish but it's my language).

```bash
#!/bin/bash
    if [ "$version" == "sin" ]; then
        # Verifica si el usuario no es root (id -u = 0 indica root)
        if [ $(id -u) -eq 0 ]; then
            echo -e "Eres root. Mejor ejecuta el script sin ser root para un mejor funcionamiento."
            break
            exit

```

great once verified we can ask the user for the name of the file and launch the command

```bash
#!/bin/bash
        else
            # Pide el nombre del archivo y lo busca desde la raíz
            read -p "Dime el nombre del archivo y su extensión que buscas, buscaré desde la raíz: " archivo
            clear && find / -name "$archivo" 2>/dev/null
            break
            exit

```

great now we just have to do the same thing but with root

```bash
#!/bin/bash
    elif [ "$version" == "con" ]; then
        # Verifica si el usuario es root (id -u = 0 indica root)
        if [ $(id -u) -ne 0 ]; then
            echo -e "No eres root. El programa se cerrará."
            break
            exit
        else
            # Pide el nombre del archivo y lo busca desde la raíz
            read -p "Dime el nombre del archivo y su extensión que buscas, buscaré desde la raíz: " archivo
            clear && find / -name "$archivo" 2>/dev/null
            break
            exit
        fi

```

great. now we are going to create the script if you choose "salir".

```bash
#!/bin/bash
    elif [ "$version" == "salir" ]; then
        # Sale del bucle si se selecciona "salir"
        echo "Adiós"
        break
        exit
```

great and finally we are left with the case of an error and the programme is fixed.

```bash
#!/bin/bash
    else
        # Muestra un mensaje de error si se introduce algo no válido
        echo "Error 404. Introduce algo válido."
    fi
done


```

great so the script should look complete

```bash
  GNU nano 7.2                                          find.sh                                                    
#!/bin/bash

while true; do
    read -p "¿Quieres la versión con root o sin ser root? sin/con/salir: " version

    if [ "$version" == "sin" ]; then
        # Verifica si el usuario no es root (id -u = 0 indica root)
        if [ $(id -u) -eq 0 ]; then
            echo -e "Eres root. Mejor ejecuta el script sin ser root para un mejor funcionamiento."
            break
            exit
        else
            # Pide el nombre del archivo y lo busca desde la raíz
            read -p "Dime el nombre del archivo y su extensión que buscas, buscaré desde la raíz: " archivo
            clear && find / -name "$archivo" 2>/dev/null
            break
            exit
        fi
    elif [ "$version" == "con" ]; then
        # Verifica si el usuario es root (id -u = 0 indica root)
        if [ $(id -u) -ne 0 ]; then
            echo -e "No eres root. El programa se cerrará."
            break
            exit
        else
            # Pide el nombre del archivo y lo busca desde la raíz
            read -p "Dime el nombre del archivo y su extensión que buscas, buscaré desde la raíz: " archivo
            clear && find / -name "$archivo" 2>/dev/null
            break
            exit
        fi
    elif [ "$version" == "salir" ]; then
        # Sale del bucle si se selecciona "salir"
        echo "Adiós"
        break
        exit
    else
        # Muestra un mensaje de error si se introduce algo no válido
        echo "Error 404. Introduce algo válido."
    fi
done

```

I hope you find it useful and I'll come back later with the same code but in python. bye :'3
