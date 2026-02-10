from Colors import log, logCyan
log("loading Broker class...")

from Listener import Listener

import ast, meshtastic.serial_interface, time
from paho.mqtt import client as mqtt_client
from pubsub import pub
from functools import partial

class Broker:

    USERNAME='user1'
    PASSWORD='user1'

    def __init__(self, serial_port='/dev/serial0', broker='localhost', broker_port=2883):
        log("Initializing an MQTT broker")
        self.LISTENER = Listener(serial_port)
        logCyan(f"my MeshLora address is {self.LISTENER._node._num}")

        self.BROKER = broker
        self.PORT = broker_port
    
    def onConnect(self, client, userdata, flags, reason_code, properties):
        log("connected to the MQTT broker")
        client.subscribe('#')

    def onMessage(self, client, userdata, msg):
        log("received a message!")

        # a source of data has prepared msg for me !
        if msg.topic.startswith('meshlora/data'):
            topic = msg.topic.split("/")
            if 3 > len(topic):
                log("check if someone hasn't made your LoRa scheme destroyed")
                return

            try:
                payload_mqtt = ast.literal_eval(msg.payload[7:].decode() if b'!repost' == msg.payload[:7] else msg.payload.decode())
            except Exception as e:
                log(f"msg detected, but not a dict: {str(e)}")
                return

            payload_local = {'mqtt_id': msg.topic.split("/")[2], 'content': payload_mqtt['content'] }
            result = self.LISTENER.initDataSend(str(payload_local).encode(), payload_mqtt['dst'])
            if result['error']:
                log(f"a problem with data transmission: {result['description']}, trying again")
                return

            match result['status']:
                case 'keyseed':
                    if b'!repost' == msg.payload[:7]:
                        log(f"haven't received a Key Ack for a repost, dropping message")
                        return

                    log(f"got a Key Seed, 10-sec sleep for Key Ack and retry")
                    time.sleep(10)
                    self.CLIENT.publish(msg.topic, b'!repost' + msg.payload)
                    return
                case 'sent':
                    log(f"sent a Data package to {payload_mqtt['dst']}")
                    return

        # received sth?
        elif msg.topic.startswith('meshlora/received'):
            print("received")

        else:
            print("different")

    def subscribe(self):
        self.CLIENT = mqtt_client.Client(mqtt_client.CallbackAPIVersion.VERSION2)
        self.CLIENT.username_pw_set(self.USERNAME, self.PASSWORD)
        self.CLIENT.on_connect = self.onConnect
        self.CLIENT.on_message = self.onMessage
        self.CLIENT.connect(self.BROKER, self.PORT)

    def debug_run(self):
        self.subscribe()
        log("start a broker")
        self.CLIENT.loop_start()

    def send_message(self, topic, dst, message):
        payload = {'dst': dst, 'content': message}
        msg_info = self.CLIENT.publish(f"meshlora/data/{topic}", str(payload))
