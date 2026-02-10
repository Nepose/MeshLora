A LoRa-powered resillient network system, meant to provide connectivity whenever the Internet base network might not be accessible.

## How

The project is based on a set of [Meshtastic](https://github.com/meshtastic/python) modules, leveraging their ability to create a de-facto mesh network over the P2P protocol. On top of that, the Meshlora protocol is added, providing with means of simple end-to-end ciphering and handshake-like confirmation.

## PoC

The repo provides a proof-of-concept, realised using three *gateways* (that's, RPi Zero + Heltec LoRa module available to be called at `/dev/serial0`) with fixed Meshtastic addresses. In order to launch the system, one has to install `base/` content to the separate folder on Raspberry Pi and `python .` there.
