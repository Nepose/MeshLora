import Protocol, Colors, Flags
import meshtastic.serial_interface

import time

class Node:

    def __init__(self, port='/dev/serial0'):
        self._port = port
        self._serial = meshtastic.serial_interface.SerialInterface(port)
        self._favorites = {}
        self._sent_box = {}
        self._received_box = {}
        self._chains = {}
        self._num = self._serial.myInfo.my_node_num
        self._lock = False

    def __call__(self):
        return self._received_box

    def log(self, prompt):
        print(f"{Colors.OKBLUE}[LOG] {prompt}{Colors.ENDC}")

    def sendFrame(self, dst, flag: Flags, payload, psk=None) -> dict:
        packet, psk = Protocol.build_packet(self._num, dst, flag, payload, psk)
        self._sent_box[psk] = []

        try:
            for x in packet:
                r = self._serial.sendData(x)
                self._sent_box[psk].append(r.id)
                self.log(f"{r.id} sent")
                time.sleep(6)
            return {'error': False, 'psk': psk}
        except Exception as e:
            return {'error': e}

    def verifyFrame(self, frame) -> dict:
        frame.pop('raw')
        raw = frame['decoded']['payload']

        if not Protocol.check_signature(raw):
            return {"error": "non-MeshLora"}

        return {"error": False, "frame": raw}
