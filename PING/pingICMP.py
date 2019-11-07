import socket 
from argparse import ArgumentParser,ArgumentTypeError #Para los argumentos
from struct import unpack, pack #Para empaquetar y desempaquetar los datos
from select import select #Para esperar un tiempo X la respuesta pong (ECHO_REPLY)
from random import randint #Para generar el ID de la cabecera ICMP y generar los datos de la cabecera ICMP
from sys import exit #Para salirme del programa
from time import sleep,time #Para esperar un tiempo y obtener el tiempo actual
from binascii import hexlify #Para convertir los bytes una lectura legible

DEFAULT_SIZE_DATA=56 #Tamaño predeterminado de los datos ICMP
DEFAULT_COUNT=0      #Cantidad de veces predeterminada de envios ECHO_REQUEST (infinito) 
DEFAULT_INTERVAL=1   #Cantidad de tiempo de espera de intervalo entre envio de cada ECHO_REQUEST
DEFAULT_TIMEOUT=2    #Cantidad de tiempo de espera de la respuesta ECHO_REQUEST (ECHO_REPLY)


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

#Serialización bits cabecera IP
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

def crear_datos(SIZE):
    """
        Esta función crea los datos, con numeros aleatorios de 0 al 9
    """ 
    x = []
    for i in range(SIZE):
        x.append(randint(0, 9))
    return bytes(x)


def crear_icmp(ID, SEQ, LEN_DATA):
    """
        Esta función crea el datagrama ICMP con los datos
    """
    data = crear_datos(SIZE=LEN_DATA)

    empty_header = crear_cabecera_icmp(ICMP_DATA=0, ICMP_ID= ID, ICMP_SEQ=SEQ)

    return crear_cabecera_icmp(empty_header + data, ID, SEQ) + data


def enviar_ping(sock,  ID, SEQ, IP_DST, LEN_DATA):
    """
        Esta función envia el datagrama ICMP y retorna el tiempo en que lo envía
        la función crear_icmp devuelve el datagrama icmp (en bytes)
        el segundo argumento es la ip de destino con un puerto
        como es un mensaje icmp, no se utliza ningún puerto 
    """
                #Cabecera ICMP                  #IP destino
    sock.sendto(crear_icmp(ID, SEQ, LEN_DATA), (IP_DST, 0))
    #retorna el tiemo cuando se envio el mensaje para calcular el RTT (tiempo de ida y vuelta)
    return time()#perf_counter()

#Deserialización bits cabecera IP
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
    
    dtgr_ip = {} #Declaración del hashmap
    
    dtgr_ip["version"]             = ip_header[0] >> 4              # IP Version 
    dtgr_ip["ihl"]                 = ip_header[0] & 15              # Header Legnth
    dtgr_ip["dsc"]                 = ip_header[1] >> 2              # Differentiate Services Codepoint - Differentiate Servic Field
    dtgr_ip["enc"]                 = ip_header[1] & 15              # Explicit Services Codepoint - Differentiate Servic Field
    dtgr_ip["total length"]        = ip_header[2]                   # Total lenght
    #dtgr_ip["total packet lenght"] = (ip_header[0] & 0xF) * 4      # Total packet lenght
    dtgr_ip["id"]                  = ip_header[3]                   # Identification
                                                    #32768
    dtgr_ip["rsb"]                 = ip_header[4] >> 15  # Reserver bit Flags # obtener el primer bit y desplazamiento a la derecha 15 bits
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

    #if  (ip_header[0] & 0xF) > 5 :
    #    ip_options = unpack('!BB', PAQUETE[FROM +20 : TO +22])
    #    dtgr_ip["option type"] = ip_options[0]                      # option type
    #    dtgr_ip["option lenght"] = ip_options[0]                    # options lenght
        
        
    #METODO BITS a BITS 
    """ ip_header = bitstring.BitArray(PAQUETE[FROM:TO])
    
    print("Version:", ip_header[0:4].int)
    print("Header lenght:", ip_header[4:8].int)
    print("DSC", ip_header[8:14].int)
    print("ECN:", ip_header[14:16].int)
    print("Total length", ip_header[16:32].uint)
    print("ID", ip_header[32:48].uint)
    print("Reserver bit", ip_header[48:49].uint)
    print("Don't fragment ", ip_header[49:50].uint)
    print("More fragment ", ip_header[50:51].uint)
    print("Fragment offset ", ip_header[51:64].uint)
    print("TTL ", ip_header[64:72].int)
    print("Protcol", ip_header[72:80].int)
    print("Cheksum", ip_header[80:96].uint)
    print("Source Address",ip_header[96:104].uint, ip_header[104:112].uint, ip_header[112:120].uint, ip_header[120:128].uint)
    print("Destination Address", ip_header[128:136].uint, ip_header[136:144].uint,ip_header[144:152].uint, ip_header[152:160].uint)
    """
    
    return dtgr_ip

#Deserialización bits cabecera ICMP
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


def convertir_tipo_y_codigo_a_texto(TYPE, CODE):
    """
        Esta función traduce el tipo y codigo ICMP a texto
    """
    destination_unreachable = {
        0: "Red de destino inalcanzable",
        1: "Host de destino inalcanzable",
        2: "Protocolo inalcanzable",
        3: "Puerto de destino inalcanzable",
        5: "Ruta de origen fallida",
        6: "Red de destino desconocida",
        7: "Host de destino desconocido",
        8: "Host de origen aislado",
        13: "Paquete filtrado",
        14: "Respuesta de marca de tiempo"
    }
    time_exceeded = {
        0: "Tiempo de vida excedido"
    }
    try:
        if TYPE == 3:
            return destination_unreachable[CODE]
        if TYPE == 11:
            return time_exceeded[CODE]
    except:
        return "tipo=%s código=%s" %( TYPE, CODE)


def lookup(DESTINATION):
    """
        Esta función optiene la dirección IP del host y obtiene el alias de la IP (Si tiene)
        DNS lookup, DNS Resolución inversa
    """
    try:
        #Optiene el la dirección IP y alias de IP
        lookup = socket.gethostbyaddr(DESTINATION)
        return lookup[2][0],"%s (%s)" %(lookup[0], lookup[2][0])
    except socket.error:
        try:
            #Si no hay alias de IP, optiene la dirección IP del host
           lookup = socket.gethostbyname(DESTINATION)
           return lookup, lookup
        except socket.error:
            #Si no se obtiene dirección IP valida del host
            print("Destino: %s inalcanzable" %DESTINATION)
            exit(1)
            

def modo_depuracion(DATAGRAMA_IP, DATAGRAMA_ICMP,SEQ):
    """
        Esta función muestra por pantallla toda la información de los paquetes recibidos
    """
    print("_" * 70)
    print("\n\t    PAQUETE: %d\n" %SEQ)

    print("-"*10,"DATAGRAMA IP","-"*10)
    
    for i, v in DATAGRAMA_IP.items():
        print("\033[94m%s:\033[0m %s" %(i,v))
    
    print("-"*10,"DATAGRAMA ICMP","-"*10)

    for i, v in DATAGRAMA_ICMP.items():
        
        if "data" == i:
            v = (hexlify(DATAGRAMA_ICMP["data"])).decode('utf-8')
        
        if "data_" == i:
            v = (hexlify(DATAGRAMA_ICMP["data_"])).decode('utf-8')
        
        if "version" == i:
            print("-"*3,"DATAGRAMA IP EN DATOS ICMP","-"*3)
        
        if "type_" == i:
            print("-"*3,"DATAGRAMA ICMP EN DATOS ICMP","-"*3)

        print("\033[94m%s:\033[0m %s" %(i,v))
              
    print( "_" * 70, "\n")


def recibir_pong(SOCK, DESTINATION_ADDRESS, ID, SEQ, TIMEOUT, DEBUG):
    """
        Esta función recive la respuesta de la solictud ECHO_REQUEST
    """
    while True:

        #¿Se agoto el tiemo de espera? 
        if (select([SOCK], [], [], TIMEOUT))[0] == []:
            return False, None

        #Optiene el tiempo en que recive el paquete
        time_actual = time()#perf_counter()

        #Optiene la cantidad maxima de bytes del socket
        recv_packet = SOCK.recv(65535)

        #Convierte bytes a una cabecera IP
        datagrama_ip = desempaquetar_ip(recv_packet)
        
        #Convierte bytes a una cabecera ICMP
        datagrama_icmp = desempaquetar_icmp(recv_packet)

        #¿Es una respuesta (ECHO_REPLY) y es para mi?
        if datagrama_icmp["type"] == 0 and datagrama_icmp["code"] == 0 and datagrama_icmp["id"] == ID and datagrama_icmp["seq"] == SEQ:
            if DEBUG:
                modo_depuracion(datagrama_ip, datagrama_icmp, SEQ)
                    
            return True, len(datagrama_icmp["data"]), datagrama_icmp["seq"], datagrama_ip["ttl"], time_actual

        #¿Es inalcanzable o TTL agotado y es para mi?
        if (datagrama_icmp["type"] == 3 or datagrama_icmp["type"] == 11) and datagrama_icmp["id_"] == ID and datagrama_icmp["seq_"] == SEQ:
            if DEBUG:
                modo_depuracion(datagrama_ip, datagrama_icmp, SEQ)
            return False, datagrama_ip["source address"], datagrama_icmp["seq_"], datagrama_icmp["type"], datagrama_icmp["code"]

        #No es para mí, a esperar otro datagrama....


def ping(DESTINATION, SIZE_DATA=DEFAULT_SIZE_DATA, COUNT=DEFAULT_COUNT, INTERVAL=DEFAULT_INTERVAL, TIMEOUT=DEFAULT_INTERVAL, DEBUG=False):
    transmitidos = 0
    recibidos = 0
    paquete_error = 0
    tiempo_minimo = -1
    tiempo_maximo = -1
    tiempo_avg = 0
    try:
        #socket.AF_INET signifca que utilizaremos ipv4
        #socket.SOCK_RAW significa que utilizaremos sockets raw
        #socket.IPPROTO_ICMP significa que será eñ protocolo ICMP (1)
        #Este socket esta al nivel de ICMP, es decir no crearemos la cabecera ethernet ni la cabecera ipv4, solo la cabecera ICMP
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

        #Hago una solicitud DNS y uns DNS inversa
        ip_address, alias_address = lookup(DESTINATION)
        
        print("PING %s (%s) %d(%d) bytes de datos." %(DESTINATION,ip_address, SIZE_DATA,SIZE_DATA+28))
    
        #tiempo_entrada = perf_counter()
       
        i = 0
        SEQ = 0
        while True:
            id = randint(0, 65535)
            time_send = enviar_ping(sock, id, SEQ, ip_address, SIZE_DATA)
            if time_send != None:
                transmitidos += 1
                
                datos = recibir_pong(sock, ip_address, id, SEQ, TIMEOUT, DEBUG)

                if datos[0]:
                    recibidos += 1
                    rtt = (datos[4]-time_send)*1000
                    if tiempo_maximo == -1:
                        tiempo_maximo = rtt
                    elif tiempo_maximo < rtt:
                        tiempo_maximo = rtt

                    if tiempo_minimo == -1:
                        tiempo_minimo = rtt
                    elif tiempo_minimo > rtt:
                        tiempo_minimo = rtt
                    
                    tiempo_avg += rtt
                    print("%d bytes desde %s: icmp_seq=%d ttl=%d tiempo=%.2f ms" % (datos[1]+8, alias_address, datos[2], datos[3], rtt))
                else:
                    if datos[1] != None:
                        print("Desde %s icmp_seq=%d %s" % (datos[1], datos[2], convertir_tipo_y_codigo_a_texto(datos[3], datos[4])))
                        paquete_error+=1

            
            if i+1 != COUNT:
                sleep(INTERVAL)
            else:
                break

            if SEQ != 65535:
                SEQ += 1
            else:
                SEQ=0

            i += 1

    except socket.error as error:
        if error.errno == 1:
            print("Ejecute el programa como adminstrador para enviar mensajes ICMP")

        if error.errno == 13:
            print("Permiso denegado ¿Estas intentando hacer ping a difusión?")
            sock.close()
    
        if error.errno == 101:
            print("La red es inalcanzable")
            sock.close()
        if error.errno == 22:
            print("Argumento invalido: ", DESTINATION)
            sock.close()
        
        if error.errno == -9:
            print("Argumento invalido: ", ip_address)
            sock.close()
        
        print("error", error)
        exit(1)
    except KeyboardInterrupt as error:
        print("")
        sock.close()
    except Exception as error:
        print("error", error)
        sock.close()
        exit(1)
    
    if  transmitidos > 0:
        show_error=""
        if paquete_error >0:
            show_error="+%d errores, " %paquete_error

        print("-"*4, DESTINATION, "estadisticas", "-"*4)
        print("%d paquetes transmitidos, %d paquetes recibidos, %.2f%% paquetes perdidos, %stiempo %0.2fs" %(transmitidos,recibidos,(1-recibidos/transmitidos)*100,show_error, tiempo_avg ))
        
        if tiempo_maximo != -1:
            print("rtt min/avg/max/ = %.2f/%.2f/%.2f ms" %(tiempo_minimo, tiempo_avg / recibidos ,tiempo_maximo))


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
  
    
def uintlimite(VALUE):
        
    message = "%s no es un número valido. Tiene que ser un número " %VALUE
    
    uintli = 0 

    try:
        uintli = int(VALUE)
    except:
        raise ArgumentTypeError(message + "entero")
    else:    
        if uintli < 0:
            raise ArgumentTypeError(message + "mayor que 0")
        if uintli > 65507:
            raise ArgumentTypeError(message + "menor que 65507")
    
    return uintli


def ufloat(VALUE):
    message = "%s no es un número valido. Tiene que ser un número " %VALUE
    
    ufloat = 0 

    try:
        ufloat = float(VALUE)
    except:
        raise ArgumentTypeError(message + "flotante")
    else:

        if ufloat < 0:
            raise ArgumentTypeError(message + "mayor que 0")
        if ufloat > 8999999999:
            raise ArgumentTypeError(message + "menor o igual que 8999999999")

    return ufloat


if __name__ == '__main__':
    parser = ArgumentParser()    
    parser.description="Ping simple python 3: by: Salvador Real "
    parser.add_argument('-d', '--debug',   action='store_true',                     help='Imprimir información de los paquetes')
    parser.add_argument('-c', '--count',   type=uint,    default=DEFAULT_COUNT,     help='Especifica la cantidad de veces que se debe enviar la solicitud de ping (ECHO_REQUEST)')
    parser.add_argument('-t', '--timeout', type=ufloat,  default=DEFAULT_TIMEOUT,   help='Especifica el tiempo de espera de la respuesta de la solicitud de ping en segundos (ECHO_REPLY). El valor predeterminado es %(default)s segundos')
    parser.add_argument('-s', '--size',    type=uintlimite, default=DEFAULT_SIZE_DATA, help="Especifica el número de bytes de datos que se enviarán. El valor predeterminado es %d, que se traduce en %d bytes de datos ICMP más 8 bytes de datos del encabezado ICMP."%(DEFAULT_SIZE_DATA,DEFAULT_SIZE_DATA+8))
    parser.add_argument('-i', '--interval',type=ufloat,  default=DEFAULT_INTERVAL,  help='Especifica el tiempo de espera de intervalo entre el envío de cada paquete en segundos. El valor predeterminado es %(default)s segundo.')
    parser.add_argument('destino',type=str,help="Especifica la dirección IPv4 A.B.C.D o el nombre a resolver www.rdc.com")
    
    args = parser.parse_args()

    ping(args.destino, args.size, args.count, args.interval, args.timeout, args.debug)
