
'''
import pika, json

params = pika.URLParameters(' ')
connection = pika.BlockingConnection(params)


channel = connection.channel()

def publishUser(method, body):
    properties = pika.BasicProperties(method)
    channel.basic_publish(exchange='', routing_key='4DpeU\.W6fe=pJbQ', body=json.dumps(body), properties=properties)
'''