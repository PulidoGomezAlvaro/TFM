from confluent_kafka import Producer

def delivery_report(err, msg):
    if err is not None:
        print(f'Message delivery failed: {err}')
    else:
        print(f'Message delivered to {msg.topic()} [{msg.partition()}]')

p = Producer({'bootstrap.servers': 'localhost:9092'})

vulnerabilidad = "WIL-30,3,8,Personal,Ingenieria social"
amenaza = "Ingenieria Social,Aprovechamiento de la buena voluntad de algunas personas para hacerles realizar actividades de interes para un tercero,WIL-30,Externo,1,1,1"

message = f'{vulnerabilidad}|{amenaza}'.encode('utf-8')
print(message,'Message')

p.produce('Incidente_TFM', message, callback=delivery_report)

p.flush()