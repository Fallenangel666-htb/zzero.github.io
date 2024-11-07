---
layout: single
title: linux update automation tool with python and bash
excerpt: "Are you just as tired of sudo apt update/upgrade or pacman -Syu ?"
date: 2024-01-07
classes: wide
header:
  teaser: /assets/images/codigos_python/portada_actu.png
  teaser_home_page: true
categories:
  - programin
  - automation 
tags:  
  - python
  - bash
---

if you are like me who use kali linux or parrot os you will probably have no problem to update it is very simple but the fact of having to write the necessary commands sometimes tires a little. that's why i created these escrips one python and another in bash to update debian or arch.

## Debian
first i will show how i made the debian code in python. (i put programmer's comments in spanish because it is my native language and i understand it better, sorry)

```python
#!/usr/bin/env python3

while True: #el while lo uso para cuando salga else (ninguan de las dos opciones) pues repita el programa desde el principio
    opcion = input("¿Quieres actualizar el sistema? (escribe 'si' o 'no'): ")

    if opcion == "si":
        import subprocess #importo subproces para que pueda ejecutar comandos
        subprocess.run(["sudo", "apt", "update"])
        subprocess.run(["sudo", "apt", "upgrade"])
        print("Sistema actualizado. :')")
        break  # Sale del bucle 
    elif opcion == "no":
        print("Actualización cancelada.")
        break  # Sale del bucle 
    else:
        print("Opción no válida. Por favor, escribe 'si' o 'no'.")

```
now the bash variant (this variant is a bit different because I added the dev null and thanks to that it runs in the background and we don't see how it updates, if you don't like it then just remove it). 

```bash
#!/bin/bash

while true; do #el while para que cuando salga el else se repita
    read -p "¿Quieres actualizar el sistema? (escribe 'si' o 'no'): " opcion

    if [ "$opcion" = "si" ]; then #el then se ponde despues de cada if para que funcione
        {
            sudo apt update
            sudo apt upgrade -y
        } > /dev/null 2>&1 #para que sirve esto? pues para que no se vea el proceso y se ejecute en segundo plano. si no gusta quitalo

        echo "Sistema actualizado en segundo plano."
        break
    elif [ "$opcion" = "no" ]; then
        echo "Actualización cancelada."
        break #para que no se repita
    else
        echo "Opción no válida. Por favor, escribe 'si' o 'no'."
    fi
done

```

## arch
now we move on to the python version of arch 

```python
#!/usr/bin/env python3

while True: #el while lo uso para cuando salga else (ninguan de las dos opciones) pues repita el programa desde el principio
    opcion = input("¿Quieres actualizar el sistema? (escribe 'si' o 'no'): ")

    if opcion == "si":
        import subprocess #importo subproces para que pueda ejecutar comandos
        subprocess.run(["sudo", "pacman", "-Syu"])
        print("Sistema actualizado.")
        break  # Sale del bucle 
    elif opcion == "no":
        print("Actualización cancelada.")
        break  # Sale del bucle 
    else:
        print("Opción no válida. Por favor, escribe 'si' o 'no'.")

```
and now the bash variant

```bash
#!/bin/bash

while true; do #el while para que cuando salga el else se repita
    read -p "¿Quieres actualizar el sistema? (escribe 'si' o 'no'): " opcion

    if [ "$opcion" = "si" ]; then #el then se ponde despues de cada if para que funcione
        {
            sudo pacman -Syu --noconfirm
        } > /dev/null 2>&1 #para que sirve esto? pues para que no se vea el proceso y se ejecute en segundo plano. si no gusta quitalo


        echo "Sistema actualizado en segundo plano."
        break
    elif [ "$opcion" = "no" ]; then
        echo "Actualización cancelada."
        break #para que no se repita
    else
        echo "Opción no válida. Por favor, escribe 'si' o 'no'."
    fi
done

```
## comments from the creator

well this is the first tool that I upload, I didn't want it to be a tool like automate nmap or hydra for example (I know how to do it but right now I'm trying to make my own website and I want to go for the easy way first). I wanted to upload something simple for the first time and so I don't have to worry about explanations. I will upload more and more focused on hackin.
greetings