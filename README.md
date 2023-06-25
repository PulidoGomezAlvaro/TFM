# TFM
TFM: Instrucciones para la implementación y ejecución del escenario de una ontologia interoperable para el análisis de riesgos.

-	Requisitos: los requerimientos para poner en marcha el escenario son escasos. Se necesitará disponer de las librerías de Python:
o	Owleady2
o	rdflib
o	csv
o	confluent_kafka 
Además, se necesitará contar Kafka para ejecutar el análisis de incidentes en tiempo real.

-	Estructura: todos los ficheros desarrollados en este TFM se encuentran disponibles en este repositorio. En este repositorio se encuentran dos carpetas: una de ellas contiene los catálogos de la metodología que se necesite emplear para un escenario concreto (‘Catalogos En Uso’). A modo de ejemplo, estos CSV contendrán los catálogos del CU2. La otra carpeta (‘Scripts’) contiene los tres scripts Python presentes en el modelo (Classifier.py, producer.py y consumer.py). Además de estas dos carpetas, también se podrá encontrar el fichero OWL correspondiente a la propia ontología, y un fichero denominado ‘Catálogos’ que contendrá una serie de datos CSV concatenados, correspondientes a cada uno de los escenarios contemplados en el modelo.

-	Ejecución: para iniciar el proceso, es necesario descargar los archivos disponibles en Github y mantener la jerarquía de archivos establecida en el repositorio. A continuación, se deben construir los CSV de información de contexto, activos, vulnerabilidades, amenazas y contramedidas con la información correspondiente de la organización, y según las directrices disponibles en este documento.
Para ejecutar el modelo se debe introducir el siguiente comando dentro del directorio de scripts:

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

