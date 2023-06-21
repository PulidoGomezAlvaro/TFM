# TFM
TFM: Ontologia Interoperable:

Los requerimientos para poner en marcha el escenario son escasos. 
Se necesitará disponer de las librerías OWLReady2 y rdflib de Python y de Kafka para ejecutar el análisis en tiempo real.

En este repositorio se encontrarán todos los archivos necesarios para construir el modelo, tanto los ficheros CSV como los Python. 
Los archivos CSV contendrán la información correspondiente al CU3 a modo de ejemplo.
Sin embargo, habrá un fichero denominado ‘Catálogos’ que contendrá una serie de datos CSV concatenados, correspondientes a cada uno de los escenarios contemplados en el modelo.

Seguidamente, se deben construir los CSV de información de contexto, activos, vulnerabilidades, amenazas y contramedidas con la información correspondiente de la organización, y según las directrices disponibles en este documento.
Es importante asegurarse de que tanto los archivos Python como los CSV deben estar almacenados en el mismo directorio bajo el mismo nivel de jerarquía.

Para ejecutar el modelo se debe introducir el siguiente comando:
> python3 classifier.py

Para introducir incidentes en tiempo real, primero se debe desplegar un servidor Apache Kafka.
Esto se lleva a cabo empleando cuatro terminales, en los dos primeros se inicia el servidor y en los otros dos se ejecutan el productor y el consumidor.
Es importante incorporarle al productor la vulnerabilidad y amenaza que se desea insertar en el mensaje.

  Terminal 1:
> cd kafka-3.4.0-src
> bin/zookeeper-server-start.sh config/zookeeper.properties

  Terminal 2:
> cd kafka-3.4.0-src
> bin/kafka-server-start.sh config/server.properties
>
  Terminal 3:
> python3 producer.py

  Terminal 4:
> python3 consumer.py

