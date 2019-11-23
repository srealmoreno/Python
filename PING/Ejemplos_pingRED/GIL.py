"""
    La mayoria de lenguajes soportan la programación en paralelo (2 o más hilos ejecutandose al mismo tiempo).
    Sin embargo con python al utilizar hilos nunca se obtiene un verdadero paralelismo.
    Esto es porque el lenguaje esta diseñado para que solamente un hilo pueda ejecutarse a la vez.
"""
from time import sleep, time
from threading import Thread
from multiprocessing import Process
from sys import getrefcount


def fun(id):
    number = 100000000
    while number != 0:
        number -= 1

    # print("Soy hilo %d, eh terminado" % id)


if __name__ == "__main__":

    print("-"*40, "\n\tPrimer prueba: Hilos\nUsando 1 hilo")
    tiempo_inicio = time()
    t1 = Thread(target=fun, args=(1,))
    t1.start()
    t1.join()

    print("Tiempo de ejecución: %f segundos" %
          (time() - tiempo_inicio))

    print("-"*40 + "\n\tSegunda prueba: Hilos\nUsando 2 hilos")

    """
        En teoria como son hilos, se ejecutan en paralelo.
        el tiempo de ejecución debe de ser similar cuando utilizamos 1 hilo
    """

    tiempo_inicio = time()
    t1 = Thread(target=fun, args=(1,))
    t2 = Thread(target=fun, args=(1,))

    t1.start()
    t2.start()
    t1.join()
    t2.join()

    print("Tiempo de ejecución: %f segundos <- Doble" %
          (time() - tiempo_inicio))

    """
        El tiempo de ejecución se ha duplicado
        ¿A que se debe esto?
            En CPython, el bloqueo global del intérprete, o GIL, es un mutex que protege el acceso a los objetos de Python,
            evitando que múltiples hilos ejecuten códigos de bytes de Python a la vez.
            Este bloqueo es necesario principalmente porque la administración de memoria de CPython no es segura para subprocesos.

        ¿Porqué se utliza GIL si genera cuello de botella?
            Python tiene algo que ningún otro lenguaje tiene, que es un contador de referencia.
            Con la ayuda del contador de referencias, podemos contar el número total de referencias que se hacen internamente
            en Python para asignar un valor a un objeto de datos.
            Debido a este contador, podemos contar las referencias y cuando este contador llegue a cero,
            la variable o el objeto de datos se liberarán automáticamente.
            getrefcount(Object) #Para saber el contador de referencias de la variable

            Al tener hilos que se ejecutan en paralelo, este contador de referecias puede quedar en un estado inconsistente
            GIL da exclusión mutua al contador de referencias, NO al valor de el objeto.


        Foro explicativo:
            http://bitybyte.github.io/Python-GIL/
            https://www.genbeta.com/desarrollo/multiprocesamiento-en-python-global-interpreter-lock-gil
            https://codigofacilito.com/articulos/gil-python
            https://wiki.python.org/moin/GlobalInterpreterLock <- (English)
            https://docs.python.org/3/c-api/init.html#thread-state-and-the-global-interpreter-lock

            ¿Qué es exclusión mutua, sección crítica, variable compartida, mutex y semáforos?
                http://www.chuidiang.org/clinux/ipcs/semaforo.php <- Explicación con lenguaje C, las definiciones son similares a Python
                http://mundogeek.net/archivos/2008/04/18/threads-en-python/

        Video explicativo:
            https://www.youtube.com/watch?v=5WOIRAlyEjA&t=215s

        El paralelismo real se puede obtener utilizando multiprocesamiento eso es similar a fork() en lenguaje C.
        el multiprocesamiento asi como fork es un proceso más pesado que un hilo y tiene su espacio de memoria reservado
    """
    print("-"*40, "\n\tTecer prueba: Procesos\nUsando 1 proceso")
    tiempo_inicio = time()
    t1 = Process(target=fun, args=(1,))
    t1.start()
    t1.join()

    print("Tiempo de ejecución: %f segundos" %
          (time() - tiempo_inicio))

    print("-"*40 + "\n\tCuarta prueba: Procesos\nUsando 2 procesos")
    """
    En teoria como son hilos, se ejecutan en paralelo.
    el tiempo de ejecución debe de ser similar cuando utilizamos 1 proceso
    """

    tiempo_inicio = time()
    t1 = Process(target=fun, args=(1,))
    t2 = Process(target=fun, args=(1,))

    t1.start()
    t2.start()
    t1.join()
    t2.join()

    print("Tiempo de ejecución: %f segundos <- Similar" %
          (time() - tiempo_inicio))
    
    print("-"*40)

    """
        Multiprocesamiento
            pros:
            - Espacio de memoria separado
            - El código es generalmente sencillo
            - Aprovecha múltiples CPUs y núcleos
            - Evita las limitaciones de GIL para cPython
            - Elimina la mayoría de las necesidades de primitivas de sincronización
               a menos que use una memoria compartida (en su lugar, es más bien un modelo de comunicación para IPC)
            - Los procesos hijo son interrumpibles / killables.
            - El módulo de multiprocessing Python incluye abstracciones útiles con una interfaz muy parecida a la de threading.Thread
            - Una necesidad con cPython para el procesamiento enlazado a la CPU
            contras:
            - PC un poco más complicado con más sobrecarga (modelo de comunicación vs. memoria / objetos compartidos)
            - Huella de memoria más grande
        Multithreading
            pros:
            - Ligero – espacio de memoria bajo
            - Memoria compartida: facilita el acceso al estado desde otro contexto
            - Le permite crear fácilmente interfaces de usuario sensibles
            - Los módulos de extensión cPython C que lanzan correctamente GIL se ejecutarán en paralelo
            - Gran opción para aplicaciones enlazadas de E / S
            contras:
            - cPython – sujeto a la GIL
            - No interrumpible / killable
            - Si no sigue una cola de comandos / modelo de bomba de mensaje (utilizando el módulo de Queue ), el uso manual de las primitivas de sincronización se convierte en una necesidad (las decisiones son necesarias para la granularidad del locking)
            - El código suele ser más difícil de entender y de hacer bien: el potencial de las condiciones de la carrera aumenta dramáticamente
        
        Foro explicativo:
            https://www.geeksforgeeks.org/fork-system-call/ <- (English)
            https://www.pythond.com/19927/multiprocesamiento-vs-threading-python.html <- (Spanglish) 
    """