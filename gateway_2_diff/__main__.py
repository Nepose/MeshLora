from Colors import log, logCyan, logListen
from Data import temperature
log("loading components")

DST_ADDR = 2956785160

try:
    from Broker import Broker
    from pubsub import pub
    from functools import partial
    import urllib.parse as url
    import time, meshtastic.serial_interface
    import RPi.GPIO as GPIO

#    GPIO.setmode(GPIO.BOARD)
#    GPIO.setup(11, GPIO.IN)

    button_state = 0
    broker = Broker()
    broker.debug_run()

    callback = partial(broker.LISTENER._onResponse, node=broker.LISTENER._node)
    pubListener, first = pub.subscribe(callback, 'meshtastic.receive.data')
    log("subscribed to meshtastic, listening")

    while True:

#        if 1 == button_state and 0 == GPIO.input(11):
#            logCyan("\nbutton click detected")
#
#            user_input = input("enter message, max 50 chars\n$ ")
#            while( 50 < len(user_input) ):
#                user_input = input("enter message, max 50 chars\n$ ")

#            temp = temperature()
#            if True == temp['error']:
#                time.sleep(1)
#                logCyan("couldn't read temperature :( try again later")
#                button_state = 0
#                continue

#            broker.send_message('temperature', DST_ADDR, temp['result'])
#            button_state = 0
#            time.sleep(1)
#            continue

#        button_state = GPIO.input(11)
        a = broker.LISTENER._node._serial.getMyNodeInfo()
        time.sleep(2)

except KeyboardInterrupt:
    log("gracefully exiting. Goodbye :3")
