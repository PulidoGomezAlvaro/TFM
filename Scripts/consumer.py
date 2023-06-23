from confluent_kafka import Consumer, KafkaError
import os

c = Consumer({
    'bootstrap.servers': 'localhost:9092',
    'group.id': 'mygroup',
    'auto.offset.reset': 'earliest'
})

c.subscribe(['Incidente_TFM'])

while True:
    msg = c.poll(1.0)

    if msg is None:
        continue
    if msg.error():
        if msg.error().code() == KafkaError._PARTITION_EOF:
            continue
        else:
            print(msg.error())
            break

    print(f'Received message: {msg.value().decode("utf-8")}')
    
    # Dividir el mensaje en dos cadenas
    vulnerabilidad, amenaza = msg.value().decode('utf-8').split('|')
    vulnerabilidad = vulnerabilidad.strip('"')
    amenaza = amenaza.strip('"')

    # Escribir cada cadena en su respectivo archivo CSV
    with open('vulnerabilidades.csv', 'a') as file:
        file.write(vulnerabilidad + '\n')
    with open('amenazas.csv', 'a') as file:
        file.write(amenaza + '\n')

    os.system('python classifier.py')

c.close()
