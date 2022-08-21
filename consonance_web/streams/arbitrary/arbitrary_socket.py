from websocket import WebSocket

from .arbitrary import ArbitraryStream


class SocketArbitraryStream(ArbitraryStream):
    def __init__(self, socket):
        """
        :param socket:
        :type socket: WebSocket
        """
        self._socket = socket # type: WebSocket

    def read(self):
        return self._socket.recv()

    def write(self, data):
        self._socket.send_binary(data)
