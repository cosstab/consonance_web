from websocket import WebSocket

from .arbitrary import ArbitraryStream


class SocketArbitraryStream(ArbitraryStream):
    def __init__(self, socket):
        """
        :param socket:
        :type socket: WebSocket
        """
        self._socket = socket # type: WebSocket

    async def read(self):
        return await self._socket.recv()

    async def write(self, data):
        await self._socket.send(data)
