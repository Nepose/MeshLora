import threading
import time

import Colors
import Flags
import meshtastic.serial_interface
import Protocol


class Node:
    def __init__(self, port="/dev/serial0"):
        self._port = port
        self._serial = meshtastic.serial_interface.SerialInterface(port)
        self._favorites = {}
        self._sent_box = {}
        self._received_box = {}
        self._chains = {}
        self._num = self._serial.myInfo.my_node_num
        self._lock = threading.Lock()

    def __call__(self):
        return self._received_box

    def sendFrame(self, dst, flag: Flags, payload, psk=None) -> dict:
        packet, psk = Protocol.build_packet(self._num, dst, flag, payload, psk)
        self._sent_box[psk] = []

        try:
            for x in packet:
                r = self._serial.sendData(x)
                self._sent_box[psk].append(r.id)
                Colors.log(f"{r.id} sent")
                time.sleep(6)
            return {"error": False, "psk": psk}
        except Exception as e:
            return {"error": e}

    def verifyFrame(self, frame) -> dict:
        frame.pop("raw")
        raw = frame["decoded"]["payload"]

        if not Protocol.check_signature(raw):
            return {"error": "non-MeshLora"}

        return {"error": False, "frame": raw}
