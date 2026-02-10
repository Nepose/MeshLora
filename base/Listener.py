from Colors import log, logCyan

from pubsub import pub
from secrets import token_hex
from Node import Node
from functools import partial
import random, sympy, ast
import Flags, Protocol, Cipher

_MIN_PRIME = 300000000
_MAX_PRIME = 500000000
_HEAD_LEN = 16

class Listener:

    def __init__(self, port='/dev/serial0'):
        self._node = Node(port)

    def _onResponse(self, packet, interface, node):
        '''
        Basically, a handler of incoming packages.
        '''
        raw = self._node.verifyFrame(packet)
        if raw['error']:
            log("received a non-MeshLora packet")

        result = Protocol.parse_frame(raw['frame']) 
        if self._node._lock:
            logCyan("error: node is locked at the moment, can't write on it")
            return

        if self._node._num == result['dst']:
            match result['flag']:
                case Flags.ACK:
                    x = ast.literal_eval(result['payload'].decode())
                    log(f"received an ACK for {x} from {result['src']}")

                    if x in self._node._sent_box:
                        self._node._sent_box.remove(x)

                        if 0 == len(self._node._sent_box[result['psk']]):
                            self._node._sent_box.pop(result['psk'])

                case Flags.KEY_SEED:
                    x = ast.literal_eval(result['payload'].decode())
                    if not all(k in x for k in ['g', 'p', 'A']):
                        log("received a malformed Key Seed announcement")
                        return

                    b = int(token_hex(6), 16)
                    B = pow(x['g'], b, x['p'])

                    self._node._lock = True
                    self._node._chains[result['src']] = x
                    self._node._chains[result['src']]['psk'] = result['psk']
                    self._node._chains[result['src']]['b'] = b
                    self._node._chains[result['src']]['B'] = B
                    self._node._chains[result['src']]['shared'] = pow(x['A'], b, x['p'])
                    self._node._lock = False

                    log(f"received a Key Seed {result['src']}, g: {x['g']}, p: {x['p']}, A: {x['A']}")
                    log(f"sending Key Ack with B: {B}, my b is {b}")
                    self._node.sendFrame(result['src'], Flags.KEY_ACK, str({'B': B}), result['psk'])

                case Flags.KEY_ACK:
                    x = ast.literal_eval(result['payload'].decode())
                    if not 'B' in x:
                        log(f"received a malformed Key Ack announcement from {result['src']}")
                        return

                    if not result['src'] in self._node._chains:
                        logCyan(f"received a Key Ack from a non-existent {result['src']}, take care of your system")
                        return

                    self._node._lock = True
                    t = self._node._chains[result['src']]
                    self._node._chains[result['src']]['B'] = x['B']
                    self._node._chains[result['src']]['shared'] = pow(x['B'], t['a'], t['p'])
                    self._node._lock = False

                    log(f"received a Key Ack from {result['src']}")


                case Flags.KEY_ERROR:
                    return

                case Flags.DATA:
                    if not result['src'] in self._node._chains:
                        log(f"received a Data from {result['src']} without a prior key exchange")
                        return

                    if b'!finish' != result['payload']:
                        payload = (int.from_bytes(result['payload']) ^ self._node._chains[result['src']]['shared']).to_bytes(length=len(result['payload']))
                    else:
                        payload = result['payload']

                    try:
                        self._node._received_box[result['src']][result['psk']][result['counter']] = payload
                    except KeyError:
                        self._node._received_box[result['src']] = {result['psk']: {result['counter']: payload}}

                    log(f"received a Data from {result['src']}: {payload}")

                    if "!finish" != payload.decode():
                        logCyan("not Finished yet, awaiting further data")
                        return

                    list_counter = self._node._received_box[result['src']][result['psk']]
                    max_counter = [counter for counter, content in list_counter.items() if b'!finish' == content][0]

                    for i in range(0, max_counter):
                        if i not in list(list_counter.keys()):
                            logCyan(f"package nr {i} not available, can't read the message!")
                            self._node._chains.pop(result['src'])
                            return

                    logCyan(f"total message: {b''.join(list(list_counter.values())).decode()[:-7]}")
                    
                    self._node.sendFrame(result['src'], Flags.ACK, str(result['psk']))
                    self._node._chains.pop(result['src'])
                    logCyan(f"cleaned keychain and sent ACK for {result['psk']}")

                case _:
                    log("received something strange to me! :(")

        else:
            log("received a packet NOT to me! :(")


    def initDataSend(self, data: bytes, dst: int) -> dict:

        if self._node._lock:
            return {"error": "node locked, try again"}

        # we have a key!
        if dst in self._node._chains and "shared" in self._node._chains[dst]:
            log("the key handshake was successful, sending data")

            payload = b''
            x = Protocol.MAX_PACKAGE_LEN - _HEAD_LEN
 
            try:
                for i in range(0, len(data), x):
                    payload += (int.from_bytes(data[0+i:x+i]) ^ self._node._chains[dst]['shared']).to_bytes(length=len(data[0+i:x+i]))
            except OverflowError as e:
                log("unexpected overflow error when sending data, try again !")
                return {'error': True, 'description': str(e)}

            log(f"preparing to send: {payload}")

            a = self._node.sendFrame(dst, Flags.DATA, payload)
            if not a['error']:
                log("data send successfully")
                self._node._chains.pop(dst)
                return {'error': False, 'status': 'sent'}

            return {'error': a['error']}

        # we don't have a key

        log("the key exchange hasn't been performed yet or wasn't completed, sending Key Seed")

        p = sympy.randprime(_MIN_PRIME, _MAX_PRIME)
        g = Cipher.find_generator_mod_prime(p)
        a = int(token_hex(6), 16)
        A = pow(g, a, p)

        self._node._lock = True

        self._node._chains[dst] = {
            'g': g,
            'p': p,
            'a': a,
            'A': A
        }
        self._node._lock = False

        log(self._node._chains[dst])

        x = self._node.sendFrame(dst, Flags.KEY_SEED, str({'g': g, 'p': p, 'A': A})) 
        if x['error']:
            return {"error": x['error']['e'], "status": 'keyseed'}

        self._node._chains[dst]['psk'] = x['psk']
        return {"error": False, "status": 'keyseed'}
