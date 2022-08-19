from consonance_web.structs.keypair import KeyPair
from consonance_web.structs.publickey import PublicKey
from consonance_web.protocol import WANoiseProtocol
from consonance_web.config.client import ClientConfig
from consonance_web.streams.segmented.wa import WASegmentedStream
from consonance_web.streams.arbitrary.arbitrary_socket import SocketArbitraryStream
from consonance_web.config.templates.useragent_samsung_s9p import SamsungS9PUserAgentConfig
import consonance_web
import uuid
import dissononce
import socket
import logging
import sys
import base64

consonance_web.logger.setLevel(logging.DEBUG)
dissononce.logger.setLevel(logging.DEBUG)

# username is phone number
USERNAME = 123456789
# on Android fetch client_static_keypair from /data/data/com.whatsapp/shared_prefs/keystore.xml
KEYPAIR = KeyPair.from_bytes(
    base64.b64decode(b"YJa8Vd9pG0KV2tDYi5V+DMOtSvCEFzRGCzOlGZkvBHzJvBE5C3oC2Fruniw0GBGo7HHgR4TjvjI3C9AihStsVg==")
)
WA_PUBLIC = PublicKey(
    base64.b64decode(b"qJWvSttNopqgQ2CgXYTc4jmSUKWd1Rv2QTMbQyYpKwY=")
)
# same phone_id/fdid used at registration.
# on Android it's phoneid_id under /data/data/com.whatsapp/shared_prefs/com.whatsapp_preferences.xml
PHONE_ID = uuid.uuid4().__str__()
# create full configuration which will translate later into a protobuf payload
CONFIG = ClientConfig(
    username=USERNAME,
    passive=True,
    useragent=SamsungS9PUserAgentConfig(
        app_version="2.21.21.18",
        phone_id=PHONE_ID
    ),
    pushname="consonance",
    short_connect=True
)
PROTOCOL_VERSION = (4, 0)
ENDPOINT = ("e1.whatsapp.net", 443)
HEADER = b"WA" + bytes(PROTOCOL_VERSION)

if __name__ == "__main__":
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(ENDPOINT)
    # send WA header indicating protocol version
    s.send(HEADER)
    # use WASegmentedStream for sending/receiving in frames
    stream = WASegmentedStream(SocketArbitraryStream(s))
    # initialize WANoiseProtocol
    wa_noiseprotocol = WANoiseProtocol(*PROTOCOL_VERSION)
    # start the protocol, this should attempt a IK handshake since we
    # specifying the remote static public key. The handshake should
    # succeeds if the WA_PUBLIC is valid, but authentication should fail.
    try:
        wa_noiseprotocol.start(stream, CONFIG, KEYPAIR, rs=WA_PUBLIC)
        print("Handshake completed, checking authentication...")
        # we are now in transport phase, first incoming data
        # will indicate whether we are authenticated
        first_transport_data = wa_noiseprotocol.receive()
        # fourth + fifth byte are status, [237, 38] is failure
        if first_transport_data[3] == 51:
            print("Authentication succeeded")
        elif list(first_transport_data[3:5]) == [237, 38]:
            print("Authentication failed")
            sys.exit(1)
        else:
            print("Unrecognized authentication response: %s" %
                    (list(first_transport_data[3:5])))
    except:
        print("Handshake failed")
        sys.exit(1)
