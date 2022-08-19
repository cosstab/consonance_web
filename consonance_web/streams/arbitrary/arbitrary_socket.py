from websocket import WebSocket

from .arbitrary import ArbitraryStream


class SocketArbitraryStream(ArbitraryStream):
    def __init__(self, socket):
        """
        :param socket:
        :type socket: WebSocket
        """
        self._socket = socket # type: WebSocket

    def read(self, readsize):
        return self._socket.recv(readsize)

    def write(self, data):
        self._socket.send_binary(data)
