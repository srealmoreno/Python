import socket
from struct import unpack, pack
from select import select
from random import randint
from sys import exit
from time import sleep,time
from ipaddress import ip_network
from argparse import ArgumentParser,ArgumentTypeError
from threading import Thread,Event,Lock


LIST_ESPERA={} #Lista de espera para recibir respuestas
LIST_RECIBIDOS={} #Lista de recibidos para imprimir estadisticas
TOTAL_VIVOS = 0 #Para imprimir el total de vivos
BYTES = [] #Para recibir los bytes de respuesta


DEFAULT_TIMEOUT = 5 #Tiempo de espera predeterminado para esperar una respuesta
DEFAULT_INTERVAL= 0.025 #Tiempo de espera de intervalo predeterminado de envio a cada host 
DEFAULT_COUNT = 3 #Valor predeterminado de envio a cada host
DEFAULT_DEBUG = False #Para imprimir estadisticas

HILO_RECIBE_PONG = Thread() #Hilo que decodifica la respuestas
HILO_RECIBE_BYTES = Thread()#Hilo que recibe los bytes de respuesta


EVENT = Event() #Evento para matar a los hilos
MUTEX_LIST = Lock() #Lock (Semaforo) para exlusión mutua la variables LIST_ESPERA
MUTEX_BYTES = Lock() #Lock (Semaforo) para exlusión mutua la variables BYTES
DESCRIPTOR_LECTOR_A_COSUMIR = 0 

def calcular_checksum(DATOS):
    """
        Esta función calcula el checksum de la cabecera ICMP
        Para calcular el cheksum:
        1 - se divide el datagramam en palabras en 16 bits (2 bytes)
        2 - se suman, estas palabras
        3 - Al resultado de la suma se invierten los bits
        ejemplo con 2 números:
        datos[1,2,3,4]

        1 = 00000001
        2 = 00000010
        3 = 00000011
        4 = 00000100

        Se agrupará el 1 con el 2 y el 3 con el 4.
           
        Suma a nivel de bits:
           0 + 0 =  0
           0 + 1 =  1
           1 + 0 =  1
           1 + 1 = 10 (acarreo 1) 

        para agrupar en palabras de 16 bits: 
        El primer byte lo desplazamos 8 posiciones, es decir se le agregan 8 ceros a la derecha y se suma con el segundo byte
        
        palabra 1:
         
        (1)    0000000100000000
        (2)  + 0000000000000010
             = 0000000100000010
        
        palabra 2:
        
        (3)    0000001100000000
        (4)  + 0000000000000100
             = 0000001100000100
        
        palabra 1 + palabra 2:

        pal(1)    0000000100000010
        pal(2)  + 0000001100000100
        pal(3)  = 0000010000000110

        Invertir bits de la palabra 3: 
        resul  0000010000000110
        ~resul 1111101111111001

        cheksum = 64505 (en decimal) 
    """

    if DATOS == 0: #Si los datos son igual a cero, retorna 0
        return 0
    
    cheksum = 0
    # Vamos a recorrer el datagrama en 2 bytes a la vez
    # Datos es una 'cadena' de bytes
    for i in range(0, len(DATOS), 2):
        a = DATOS[i] 
        try:
            b = DATOS[i+1]
            # Si el usuario escribe un numero impar en la cantidad de datos dejamos b valiendo 0
        except IndexError:
            b = 0
        
        cheksum += ((a << 8)+b)
        # Se agrupan 2 bytes, el primer byte se convierte a un numero de 16 bits (desplazamiento << 8)
        # y se suman las palabras
    
    cheksum += (cheksum >> 16)
    # Esto es por si hay un acarreo en el ultimo bit por ejemplo 32768 + 32768    
    cheksum = int(format(cheksum, "016b").translate({ord('0'): '1', ord('1'): '0'}),2) & 65535
    # Invierte todos los bits de la suma resultante
    # format "016b" es para forzar la representación de 16 bits para el número (Si es menor a (2^16)-1 (65535))
    # translate es para invertir los bits
    #  1 pasa 0
    #  0 pasa 1
    # El operador & (and a nivel de bits)es si el numero sobrepasa 2 bytes (16 bits)
    # desechamos los bits que sobrepasan de derecha a izquierda
    # Por ejemplo:
    # 111110000000010000000 <- 21 bits
    # Se 'eliminarán' los bits despúes del numero 16 (contar de derecha a izquierda)
    # 0000000010000000 <- 16 bits 
    
    # Aunque puedes hacerlo con esta instrucción, según la documentacion de python3
    # cheksum = ~cheksum & 65535
    #El operador '~' significa -(n + 1) 
    #And a nivel de bits con (2^16)-1) para representar obtener el número de 16 bits positivo

    return cheksum


def salir():
    EVENT.set()
    exit(1)


def crear_cabecera_icmp(ICMP_DATA, ICMP_ID, ICMP_SEQ):
    """
        Esta función crea la cabecera ICMP, empaquetada
        \! significa que es big endian (representación)
        B significa char sin signo en C, en python es un int (de 8 bits)
        H significa short sin signo en C, en python es un int (de 16 bits)
        8 es el Tipo
        0 es el codigo (ECHO_REQUEST)
    """
    return pack("!BBHHH", 8, 0, calcular_checksum(ICMP_DATA), ICMP_ID, ICMP_SEQ)


def crear_icmp(ID, SEQ):
    """
        Esta función crea el datagrama ICMP 
    """
    return crear_cabecera_icmp(crear_cabecera_icmp(0, ID, SEQ), ID, SEQ)


def reiniciar_hilo(NOMBRE_FUNCION, DEBUG = False, TIMEOUT=0):
    """
    Esta función reincia el hilo que recibe las respuestas pong (ECHO_REPLY)
    """
    #la palabra reservada global, significa que me estoy refiriendo a una variable Global
    global HILO_RECIBE_PONG, HILO_RECIBE_BYTES
    if NOMBRE_FUNCION == recibir_pong:
        HILO_RECIBE_PONG = Thread(target=NOMBRE_FUNCION ,args=(EVENT,DEBUG,TIMEOUT))
        HILO_RECIBE_PONG.start()
    else:
        HILO_RECIBE_BYTES = Thread(target=NOMBRE_FUNCION ,args=(EVENT,))
        HILO_RECIBE_BYTES.start()
    #Hilo recibe pong y hilo recibe bytes es una variable tipo Thread
    #target (función) recibir pong, es la función que el hilo ejecutará
    #args sons los argumentos de dicha función. es un evento para poder terminar o matar el hilo
    #cuando el usuario presione CTRL + C
    #La función start, como su nombre lo indica, inicia el hilo
    

def enviar_ping(ID, DESTINATION, COUNT, INTERVAL, DEBUG, TIMEOUT):
    global LIST_ESPERA
    try:
        #socket.AF_INET signifca que utilizaremos ipv4
        #socket.SOCK_RAW significa que utilizaremos sockets raw
        #socket.IPPROTO_ICMP significa que será eñ protocolo ICMP (1)
        #Este socket esta al nivel de ICMP, es decir no crearemos la cabecera ethernet ni la cabecera ipv4, solo la cabecera ICMP
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        SEQ=0
    
        for i in range(COUNT):                
            #Sen to, es para enviar el mensaje ICMP ECHO_REQUEST
            #Esta función recibe 2 parametos, La cabecera (en bytes) ICMP y una tupla con la IP de destino
            #El 0 signicia un puerto, pero como es un mensaje ICMP no se utiliza
            if not HILO_RECIBE_BYTES.is_alive():
                    reiniciar_hilo(recibir_bytes)

            sock.sendto(crear_icmp(ID, SEQ), (DESTINATION, 0))

            #La función acquire() abre la sección critica
            MUTEX_LIST.acquire()
            
            if (DESTINATION, ID) in LIST_ESPERA:
                #Añadimos la secuencia y el tiempo de envio al diccionario de la IP y ID de destino
                LIST_ESPERA[DESTINATION,ID] += [[SEQ, time()]]
            else:
                #Creamos una clave con la IP y ID de destino
                LIST_ESPERA[DESTINATION, ID] = [[SEQ, time()]]
                #Es un array bidimensional ya que cada array contiene datos diferentes

            #La función release() cierra la sección critica
            MUTEX_LIST.release()

            #Si el hilo RECIBE PONG no esta vivo, lo reiniciamos
            if not HILO_RECIBE_PONG.isAlive():
                reiniciar_hilo(recibir_pong, DEBUG, TIMEOUT)

            if SEQ != 65535:
                SEQ += 1
            else:
                SEQ=0
            
            sleep(INTERVAL)
            

    except socket.error as error:
        if error.errno == 1:
            print("Ejecute el programa como adminstrador para enviar mensajes ICMP")
            salir()
        if error.errno == 13:
            print("Permiso denegado ¿Estas intentando hacer ping a difusión?")
            sock.close()

        if error.errno == 101:
            print("La red es inalcanzable")
            sock.close()
            EVENT.set()
            salir()
        if error.errno == 22:
            print("Argumento invalido: ", DESTINATION)
            sock.close()
            EVENT.set()
            salir()
        if error.errno == -9:
            print("Argumento invalido: ", DESTINATION)
            sock.close()
            salir()
        print("error", error)
        
    except Exception as error:
        print("error", error)
        sock.close()
        salir()
    
    """
        Ejemplo de como se vería LISTA_ESPERA
        COUNT = 2
        DESTINO = 192.168.0.1, 192.168.0.2

        Estrutura: 
        LISTA_ESPERA[DESTINO,ID_ALEATORIO]= [[secuencia, TIEMPO_DE_ENVIO]...]

        Salida:
        LISTA_ESPERA[192.168.0.1,100]= [[0, 1.000000],[1, 1.50000000]]
        LISTA_ESPERA[192.168.0.2,500]= [[0, 2.500000],[1, 4.00000000]]

        Recuerda que:
        Para acceder a los datos hay que recorrer el array bidimensional, y luego al array unimensional. Es decir que necesitaremos
        de 2 indexs para acceder a un valor

        Por ejemplo para acceder al tiempo de envio del primer mensaje enviado:

        Sintaxis:
        LISTA_ESPERA[DESTINO ó ID][0][1]

        #Acceder por IP
        print(LISTA_ESPERA[192.168.0.1][0][1])

        #Acceder por ID
        print(LISTA_ESPERA[100][0][1])

        Salida: 1.000000

        Tambíen se puede acceder por IP y por ID (Menos probalidad de repetido), aunque se 'supone' que no pueden haber 2 IP iguales
        en el diccionario

        print(LISTA_ESPERA['192.168.0.1',100][0][1])

        Salida: 1.000000
    
    """


def desempaquetar_ip(PAQUETE,FROM =0 , TO = 20):
    """
        Esta función desempaca el datagrama IP recivido en un diccionario o hasmap (array de nombres)
        Es para hacer mas sencilla la lectura de los datos
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 0
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |Version|  IHL  |   DSCP    |ECN|          Total Length         |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |         Identification        |Flags|      Fragment Offset    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |  Time to Live |    Protocol   |         Header Checksum       |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                       Source Address                          |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |                    Destination Address                        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        0 - Version y IHL
        1 - DF
        2 - Total Lenght
        3 - ID
        4 - Flags y Fragment
        5 - TTL
        6 - Protocol
        7 - Checksum
        8 - Source
        9 - Destination
        \! significa que es big endian (representación)
        B significa char sin signo en C, en python es un int (de 8 bits)
        H significa short sin signo en C, en python es un int (de 16 bits)
        s significa un char[] en C, en python es un string (de 8 bits por defecto)
        el numero antes de la 's' es para indicar el tamaño del string numero*8
        4s significa un char[] en C, en python es un string (de 32 bits por defecto)
    """
    #METODO UNPACK
    ip_header = unpack('!BBHHHBBH4s4s', PAQUETE[FROM:TO])
    
    dtgr_ip = {} #Declaración del hasmap
    
    dtgr_ip["version"]             = ip_header[0] >> 4              # IP Version 
    dtgr_ip["ihl"]                 = ip_header[0] & 15              # Header Legnth
    dtgr_ip["dsc"]                 = ip_header[1] >> 2              # Differentiate Services Codepoint - Differentiate Servic Field
    dtgr_ip["enc"]                 = ip_header[1] & 15              # Explicit Services Codepoint - Differentiate Servic Field
    dtgr_ip["total length"]        = ip_header[2]                   # Total lenght
    #dtgr_ip["total packet lenght"] = (ip_header[0] & 0xF) * 4      # Total packet lenght
    dtgr_ip["id"]                  = ip_header[3]                   # Identification
                                                    #32768
    dtgr_ip["rsb"]                 = ip_header[4] >> 15             # Reserver bit Flags # obtener el primer bit y desplazamiento a la derecha 15 bits
                                                    #16384
    dtgr_ip["dtf"]                 = (ip_header[4] & 0x4000) >> 14  # Don't fragments # obtener el segundo bit y desplazamiento a la derecha 14 bits
                                                    #8192
    dtgr_ip["mrf"]                 = (ip_header[4] & 0x2000) >> 13  # More fragments # obtener el primer bit y desplazamiento a la derecha 13 bits
                                                    #8191
    dtgr_ip["frag offset"]         = ip_header[4]  & 0x1fff         # Fragment offset
    dtgr_ip["ttl"]                 = ip_header[5]                   # time To live
    dtgr_ip["protocol"]            = ip_header[6]                   # Protocol
    dtgr_ip["checksum"]            = ip_header[7]                   # Checksum
    dtgr_ip["source address"]      = socket.inet_ntoa(ip_header[8]) # Source address
    dtgr_ip["destination address"] = socket.inet_ntoa(ip_header[9]) # Destination address
    
    return dtgr_ip


def desempaquetar_icmp(PAQUETE):
    """
        Esta función desempaca el datagrama ICMP recivido en un diccionario o hasmap (array de nombres)
        0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |     Type      |     Code      |          Checksum             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |           Identifier          |        Sequence Number        |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |     Data ...
        +-+-+-+-+-
        \! significa que es big endian (representación)
        B significa char sin signo en C, en python es un int (de 8 bits)
        H significa short sin signo en C, en python es un int (de 16 bits)
        
    """
    icmp_header = unpack("!BBHHH", PAQUETE[20:28])

    dtgr_icmp = {}
    dtgr_icmp["type"]     = icmp_header[0] # Type
    dtgr_icmp["code"]     = icmp_header[1] # Code
    dtgr_icmp["checksum"] = icmp_header[2] # Checksum
    dtgr_icmp["id"]       = icmp_header[3] # Identifier
    dtgr_icmp["seq"]      = icmp_header[4] # Sequence number
    
    #Si es tipo error desempaco la cabecera IP y ICMP que esta en los datos ICMP
    if dtgr_icmp["type"] == 3 or dtgr_icmp["type"] == 11:
        
        #Para agregar un hasmap en otro se utiliza el metodo update()
        dtgr_icmp.update(desempaquetar_ip(PAQUETE,28,48))       
        
        icmp_header = unpack("!BBHHH", PAQUETE[48:56])

        dtgr_icmp["type_"]     = icmp_header[0] # Type
        dtgr_icmp["code_"]     = icmp_header[1] # Code
        dtgr_icmp["checksum_"] = icmp_header[2] # Checksum
        dtgr_icmp["id_"]       = icmp_header[3] # Data Identifier
        dtgr_icmp["seq_"]      = icmp_header[4] # Data Sequence number
        dtgr_icmp["data_"]     = PAQUETE[56:]# Data
        
    else:
        dtgr_icmp["data"]     = PAQUETE[28:]# Data

    return dtgr_icmp


def recibir_bytes(event):
    global BYTES, DESCRIPTOR_LECTOR_A_COSUMIR
    #Declaramos un socket para recibir las respuestas ECHO_REPLY

    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    
    while not event.is_set():
        # select- Esperando la finalización de E / S
        # select( rlist , wlist , xlist [ , tiempo de espera ] ) 
        # Esta es una interfaz sencilla para la select()llamada al sistema Unix.
        # Los primeros tres argumentos son secuencias de 'objetos esperables': enteros que representan descriptores de archivos 
        # u objetos con un método sin parámetros llamado fileno()devolver dicho entero:
        # rlist : espere hasta que esté listo para leer
        # wlist : espere hasta que esté listo para escribir
        # xlist : espere una "condición excepcional" 
        # El argumento del tiempo de espera opcional especifica un tiempo de espera
        # como un número de coma flotante en segundos.
        # Un valor de tiempo de espera cero especifica que nunca se bloquea.
        # Cuando se alcanza el tiempo de espera sin que esté listo un descriptor de archivo, se devuelven tres listas vacías.

        if (select([sock], [], [], 0.5))[0] == []:
            continue

        tiempo_actual=time() #Obtener el tiempo en que se reciben los bytes
        recv_packet = sock.recv(56) #Recibir 56 bytes maximo
        #Optiene la cantidad de bytes que vamos a utilizar del socket
        #Normalmente solo son 28 bytes (20 de cabecera IP y 8 de cabecera ICMP)
        #Pero si recibimos un host inalcanzable son 56
        #(20 de cabecera IP, 8 de cabecera ICMP, 20 de cabecera IP en datos ICMP y 8 de cabecera ICMP en datos ICMP)
        MUTEX_BYTES.acquire() #Entramos a la sección critica
        BYTES += [[recv_packet, time()]] #Sumamos los bytes recibidos a la variable global BYTES
        DESCRIPTOR_LECTOR_A_COSUMIR += 1 #Sumamos el descriptor a consumir
        MUTEX_BYTES.release() #Salimos de la sección critica

    sock.close() 


def recibir_pong(event, DEBUG, TIMEOUT):
    
    """
        Esta función es la que recibe todas las respuestas del ECHO_REQUEST
        Es un hilo, entonces se esta ejecutando de manera paralela al hilo principal
    """
    #LIST_ESPERA, LIST_RECIBIDOS y TOTAL_VIVOS son variables globales que utlizaremos en esta función
    global LIST_ESPERA, LIST_RECIBIDOS,TOTAL_VIVOS, BYTES, DESCRIPTOR_LECTOR_A_COSUMIR,EVENT
    
    #Mientas no reciba la señal de detenerse el while se estará ejecutando
    #Esta señal es por si el usuario presiona CTRL + C para detener el programa, hay que
    #enviarle una señal al hilo para que se detenga
    while not event.is_set():  
        #Abrimos la sección critica porque vamos a acceder a la variable compartida LIST_ESPERA
        MUTEX_LIST.acquire()
        
        #Recorremos todas las claves y todos los datos de dicha clave para hacer un filtrado
        #Este filtrado es para eliminar los registro de TIEMPO_AGOTADO
        for KEY in LIST_ESPERA.copy().keys():
            #Se pregunta:
            #El tiempo actual - el tiempo_de_envío (x[1]), ¿Es menor al tiempo limite (tiempo agotado)?
            # Si la respuesta es True, el array quedará intacto,
            # de lo contrario (False), será omitdo 
            LIST_ESPERA[KEY]=[x for x in LIST_ESPERA[KEY] if time() - x[1] < TIMEOUT]
            # Hacer un for in y un FILTER ES LO MISMO, pero si te quieres ver más pro utiliza el filter 
            #LIST_ESPERA[KEY]=list(filter(lambda x: time() - x[1] < TIMEOUT, LIST_ESPERA[KEY]))
            
            #Si ya no queda ningún elemento asociado a la clave, la clave se eliminará
            if not LIST_ESPERA[KEY]:
                del LIST_ESPERA[KEY]
            
        #Si ya no queda ningún elemento en el diccionario (hash map)
        #Se cierra el bucle pero antes nos salimos de la sección critica
        if not LIST_ESPERA.items():
            MUTEX_LIST.release()
            break 
        #Cerramos la sección crítica
        MUTEX_LIST.release()

        MUTEX_BYTES.acquire()
        if DESCRIPTOR_LECTOR_A_COSUMIR > 0:
            paquete_actual=BYTES[0][0]
            tiempo_fin = BYTES[0][1]        
            DESCRIPTOR_LECTOR_A_COSUMIR -= 1
            del BYTES[0]
        else:
            MUTEX_BYTES.release()
            sleep(0.001)
            continue

        MUTEX_BYTES.release()

        #Convierte bytes a una cabecera IP    
        datagrama_ip = desempaquetar_ip(paquete_actual)
        
        #Convierte bytes a una cabecera ICMP
        datagrama_icmp = desempaquetar_icmp(paquete_actual) 
        
        
        if datagrama_icmp["type"] == 8:
            continue
            

        #Entramos a sección critica    
        MUTEX_LIST.acquire()
        
        #Creamos una variable auxiliar para buscar estos datos en el diccionario LIST_ESPERA
        ip_and_id = datagrama_ip["source address"], datagrama_icmp ["id"]

           
        #¿Es una respuesta (ECHO_REPLY) y es para mi?
        if datagrama_icmp["type"] == 0 and datagrama_icmp["code"] == 0 and ip_and_id in LIST_ESPERA:
            
            # Si existe una clave en LIST_RECIBIDOS creamos una y le indicamos al usuario que hay una respuesta de ese host
            if not datagrama_ip["source address"] in LIST_RECIBIDOS:
                #Crea una clave en el diccionario LIST_RECIBIDOS
                LIST_RECIBIDOS[datagrama_ip["source address"]] = []
                #Esos numeros raros es para escribir en verde la palabra 'Ok'
                print ("%s:\033[92m OK\033[0m" %(datagrama_ip["source address"]))
                TOTAL_VIVOS+=1
                # Esto básicamente es para que haya un orden en la pantalla y le indiquemos al usuario
                # Solamente una vez que ese host ha respondido al menos a un mensaje ICMP_REQUEST
                # independientemente de la cantidad de mensajes enviados

            #¿Cual respuesta es?, es decir cual es la secuencia de la respuesta?
            #La función enumerate nos devuelve el indice y los datos de la clave
            for i,datos in enumerate(LIST_ESPERA[ip_and_id]):
              
                if datagrama_icmp["seq"] == datos[0]:
                    #Agregamos la respuesta al diccionario LIST_RECIBIDOS
                    if DEBUG:
                        LIST_RECIBIDOS[datagrama_ip["source address"]]+=[[datos[0],datagrama_ip["ttl"], (tiempo_fin - datos[1])*1000]]
                    #* Eliminanos el array de la clave porque ya respondió
                    del LIST_ESPERA[ip_and_id][i]
                    break
            
            #Sino queda ningún elemento en la clave, eliminamos la clave
            if not LIST_ESPERA[ip_and_id]:
                del LIST_ESPERA[ip_and_id]

        
        #Si recibimos un código de error
        if (datagrama_icmp["type"] == 3 or datagrama_icmp["type"] == 11):
            #La variable auxiliar cambia porque el id y la ip de destino estan en los datos ICMP
            ip_and_id = datagrama_icmp["destination address"], datagrama_icmp ["id_"]
            #¿Está esa clave en la lista de espera?
            if ip_and_id in LIST_ESPERA:
                #¿Cual respuesta es?, es decir cual es la secuencia de la respuesta?
                for i,datos in enumerate(LIST_ESPERA[ip_and_id]):
                    #Eliminamos el array de la clave porque nos indicaron que no responde
                    if datagrama_icmp["seq_"] == datos[0]:
                        del LIST_ESPERA[ip_and_id][i]
                        #Cerramos el bucle porque no es necesario seguir recorriendo el array bidimensional
                        break

                #Sino queda ningún elemento en la clave, eliminamos la clave
                if not LIST_ESPERA[ip_and_id]:
                    del LIST_ESPERA[ip_and_id]
    
        
        #Si ya no queda ningún elemento en el diccionario (hash map)
        #Se cierra el bucle pero antes nos salimos de la sección critica
        if not LIST_ESPERA.items():
            MUTEX_LIST.release()
            break

        #Cerramos la sección crítica
        MUTEX_LIST.release()


def ufloat(value):
    try:
        ufloat = float(value)
        if ufloat <= 0:
            raise 
        return ufloat
    except Exception:
        raise ArgumentTypeError("%s no es un nuḿero valido, tiene que ser flotante positivo" % value)


def uint(VALUE):
    
    message = "%s no es un número valido. Tiene que ser un número " %VALUE
    
    uint = 0 

    try:
        uint = int(VALUE)
    except:
        raise ArgumentTypeError(message + "entero")
    else:    
        if uint < 1:
            raise ArgumentTypeError(message + "positivo")

    return uint


def ping(NETWORK:str, COUNT:int = DEFAULT_COUNT, TIMEOUT:float = DEFAULT_TIMEOUT, INTERVAL:float = DEFAULT_INTERVAL, DEBUG:bool = DEFAULT_DEBUG):
    
    try:
        network = ip_network(NETWORK) 
        for i in network.hosts():
            enviar_ping(ID=randint(0, 65535),DESTINATION=str(i), COUNT=COUNT, INTERVAL=INTERVAL, DEBUG=DEBUG,TIMEOUT=TIMEOUT)

    
        if HILO_RECIBE_PONG.isAlive():    
            HILO_RECIBE_PONG.join()

    except KeyboardInterrupt:
        pass
    except ValueError:
        print("Formato invalido", NETWORK)
        salir()

    EVENT.set()

    if DEBUG and TOTAL_VIVOS > 0:
        for i,datos in LIST_RECIBIDOS.items():
            print("-"*10,i,"-"*10)

            tiempo_minimo = -1
            tiempo_maximo = -1
            tiempo_avg = 0
                       
            for j in datos:
                if tiempo_maximo == -1:
                    tiempo_maximo = j[2]
                elif tiempo_maximo < j[2]:
                    tiempo_maximo = j[2]
                if tiempo_minimo == -1:
                    tiempo_minimo = j[2]
                elif tiempo_minimo > j[2]:
                    tiempo_minimo = j[2]
                
                tiempo_avg += j[2]

                print("secuencia: %d ttl: %d tiempo: %.2fms "%(j[0],j[1],j[2]))

            print("\n%d paquetes transmitidos, %d paquetes recibidos, %.2f%% paquetes perdidos, tiempo %0.2fms" %(COUNT,len(datos),(1-len(datos)/COUNT)*100, tiempo_avg ))
            print("rtt min/avg/max/ = %.2f/%.2f/%.2f ms" %(tiempo_minimo, tiempo_avg / len(datos) ,tiempo_maximo))    

            print("-"*33)
   
    
    print("Total Vivos: ",TOTAL_VIVOS)


if __name__ == '__main__':
    parser = ArgumentParser()    
    parser.description="Ping simple python 3: by: Salvador Real "
    parser.add_argument('-d', '--debug',   action='store_true',                     help='Imprimir estadisticas de los paquetes')
    parser.add_argument('-t', '--timeout', type=ufloat,  default=DEFAULT_TIMEOUT,   help='Especifica el tiempo de espera de la respuesta de la solicitud de ping en segundos (ECHO_REPLY). El valor predeterminado es %(default)s segundos')
    parser.add_argument('-c', '--count',   type=uint,    default=DEFAULT_COUNT,     help='Especifica la cantidad de veces que se debe enviar la solicitud de ping (ECHO_REQUEST) a cada host. El valor predeterminado es %(default)s')
    parser.add_argument('-i', '--interval',type=ufloat,  default=DEFAULT_INTERVAL,  help='Especifica el tiempo de espera de intervalo entre el envío de cada paquete en segundos. El valor predeterminado es %(default)s segundos')
    parser.add_argument('red',help="A.B.D.E/Mascara")
    args = parser.parse_args()


    ping(NETWORK=args.red, COUNT=args.count, TIMEOUT=args.timeout, INTERVAL=args.interval, DEBUG=args.debug)
