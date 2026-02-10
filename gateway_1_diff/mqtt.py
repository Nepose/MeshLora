import paho.mqtt.client as mqtt
import re, time

def on_connect(client, userdata, flags, reason_code, properties):
    print(f"Connected with result code {reason_code}")
    #client.subscribe("$SYS/#")

# The callback for when a PUBLISH message is received from the server.
#def on_message(client, userdata, msg):
    #print(msg.topic+" "+str(msg.payload))

mqttc = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2)
mqttc.username_pw_set('user1', 'user1')
mqttc.connect("localhost", 2883, 60)
mqttc.loop_start()

while True:
    msg = input("Feel free to enter your Tweet!\n> ")

    while 280 < len(msg) :
        msg = input("Trop long !\n> ")

    payload = {'dst': 2956826960, 'content': re.sub('[\"\']+', '', msg)}

    mqttc.publish("meshlora/data/corridor_message", str(payload))
    print("Message sent!")
    time.sleep(5)
