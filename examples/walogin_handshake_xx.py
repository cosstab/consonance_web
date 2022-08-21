from consonance_web.structs.keypair import KeyPair
from consonance_web.protocol import WANoiseProtocol
from consonance_web.config import client
from consonance_web.streams.segmented.wa import WASegmentedStream
from consonance_web.streams.arbitrary.arbitrary_socket import SocketArbitraryStream
from consonance_web.config.templates.useragent_samsung_s9p import SamsungS9PUserAgentConfig
import consonance_web
import uuid
import dissononce
import websocket
import logging
import sys

consonance_web.logger.setLevel(logging.DEBUG)
dissononce.logger.setLevel(logging.DEBUG)

# Generate a new keypair
KEYPAIR = KeyPair.generate()
# create full configuration which will translate later into a protobuf payload
WA_VERSION = "2.2230.10"
PROTOCOL_VERSION = (5, 2) #WA header = b'WA\x05\x02'
ENDPOINT = "wss://web.whatsapp.com/ws/chat"
ORIGIN = "https://web.whatsapp.com"
CLIENT_CONFIG = client.get_new_client(WA_VERSION)

if __name__ == "__main__":
    ws = websocket.WebSocket()
    ws.connect(ENDPOINT, header={"Origin: " + ORIGIN})

    # use WASegmentedStream for sending/receiving in frames
    stream = WASegmentedStream(SocketArbitraryStream(ws))
    # initialize WANoiseProtocol
    wa_noiseprotocol = WANoiseProtocol(*PROTOCOL_VERSION)
    # start the protocol, this should a XX handshake since
    # we are not passing the remote static public key
    try:
        wa_noiseprotocol.start(stream, CLIENT_CONFIG, KEYPAIR)
        print("Handshake completed, checking authentication...")
        # we are now in transport phase, first incoming data
        # will indicate whether we are authenticated
        first_transport_data = wa_noiseprotocol.receive()
        print(str(first_transport_data)) #This message contains QR Code info
        '''# fourth + fifth byte are status, [237, 38] is failure
        if first_transport_data[3] == 51:
            print("Authentication succeeded")
        elif list(first_transport_data[3:5]) == [237, 38]:
            print("Authentication failed")
            sys.exit(1)
        else:
            print("Unrecognized authentication response: %s" % (first_transport_data[3]))
            sys.exit(1)'''
    except Exception as e:
        print("Handshake failed: " + str(e))
        sys.exit(1)
