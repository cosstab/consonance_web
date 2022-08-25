import struct

from .segmented import SegmentedStream
from ..arbitrary.arbitrary import ArbitraryStream


class WASegmentedStream(SegmentedStream):
    def __init__(self, dynamicstream):
        """
        :param dynamicstream:
        :type dynamicstream:  DataStream
        """
        self._datastream = dynamicstream # type: ArbitraryStream

    async def read_segment(self):
        return (await self._datastream.read())[3:] #Remove 3 first bytes containings message size

    async def write_segment(self, data, prologue=None):
        if len(data) >= 16777216:
            raise ValueError("data too large to write; length=%d" % len(data))

        if prologue is not None:
            await self._datastream.write(prologue + struct.pack('>I', len(data))[1:] + data)
        else:
            await self._datastream.write(struct.pack('>I', len(data))[1:] + data)
        
