---
layout: single
title: information on the hacking of the "comision obrera" in spain
excerpt: 
date: 2024-01-07
classes: wide
header:
  teaser: /assets/images/comisionesobreras/Logotipo_de_Comisiones_Obreras.svg.png
  teaser_home_page: true
categories:
  - hacking
  - linux
tags:  
  - hacking
---

** the first thing to make clear is that i am not the author of the hack and i am only uploading this for information purposes. all the information i have taken and translated comes from this website. **
[https://farlopa.noblogs.org/mariscada-virtual-en-el-servidor-de-comisiones-obreras]

## start
this hack was made on 2023/11/22

It's been a while since I've tried to root a server, and when I saw how sloppy the CCOO membership portal looked, I couldn't resist the temptation to do some testing.

This was the result.

At first glance, the page afiliate.ccoo.es consists of a personal data form to process the affiliation to the union.

![](/assets/images/comisionesobreras/ccoo1-768x338.png)

The URL includes filenames as parameters, so trying to change the path I've hit a Path Traversal vulnerability. I tried unsuccessfully to abuse /proc/ to inject code. I was also unable to poison the logs due to lack of permissions. However, I was able to enumerate data about the server.

![](/assets/images/comisionesobreras/ccoo2-768x212.png)

I noticed a letter E in front of the paths in the URL, and thinking that it could be a mounted volume, I tried to access different files by changing the letter. It turned out not to be a volume, but using the letter D I was able to read the source code of the PHP files without them being processed. This allowed me to understand a little better how coco.php works.

![](/assets/images/comisionesobreras/ccoo3-768x244.png)

E for execution and D or R for read and send. Depending on this, either processed or flat files will be included.

Investigating the code of the membership form I have seen that somewhere there is a file uploader that stores the uploads in /usr/paginas/v5.file/cms/ with the user's DNI as the filename.

![](/assets/images/comisionesobreras/ccoo4-768x112.png)

I have entered the shell code in the file I am going to upload to run it from coco.php.

![](/assets/images/comisionesobreras/ccoo5-768x116.png)

I have uploaded the file and completed the form.

![](/assets/images/comisionesobreras/ccoo6-768x339.png)

By accessing the path to the uploaded file I have confirmed that I can execute commands on the system as a www-data user.

![](/assets/images/comisionesobreras/ccoo7-768x173.png)

I have noticed that most of CCOO's subdomains, including the main one, operate under the same root, which will make it easier for me to do a massive defacement in the end.
I find authentication data for databases in several configuration files.


![](/assets/images/comisionesobreras/ccoo9-768x299.png)

I have been able to access the databases using the credentials. I run a reverse shell and export all the databases.

![](/assets/images/comisionesobreras/ccoo10-768x59.png)

After downloading the dump I found a table containing a plaintext password associated with an account called root.

![](/assets/images/comisionesobreras/ccoo11.png)

I innocently tried to identify myself using the password, and surprisingly it worked. However, I could have elevated privileges by exploiting CVE-2017-7533 since the system hasn't been updated for a while.

![](/assets/images/comisionesobreras/ccoo12.png)

After a while of saving files and databases, I have finally modified the startup. About 50 subdomains of ccoo.es show my index as I write this.

![](/assets/images/comisionesobreras/ccoo13-768x480.png)

## opinion

i am neither for nor against this. i limit myself to hackmyVM or hack the box machines but curiosity is sometimes very strong. i know that this person did not do it out of curiosity but this way we call the attention of the spanish government to improve cybersecurity.
maybe this way they will hire me in the future jaja .
