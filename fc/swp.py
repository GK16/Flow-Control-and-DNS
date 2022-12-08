import enum
import logging
import llp
import queue
import struct
import threading


class SWPType(enum.IntEnum):
    DATA = ord('D')
    ACK = ord('A')


class SWPPacket:
    _PACK_FORMAT = '!BI'
    _HEADER_SIZE = struct.calcsize(_PACK_FORMAT)
    MAX_DATA_SIZE = 1400  # Leaves plenty of space for IP + UDP + SWP header

    def __init__(self, type, seq_num, data=b''):
        self._type = type
        self._seq_num = seq_num
        self._data = data

    @property
    def type(self):
        return self._type

    @property
    def seq_num(self):
        return self._seq_num

    @property
    def data(self):
        return self._data

    def to_bytes(self):
        header = struct.pack(SWPPacket._PACK_FORMAT, self._type.value,
                             self._seq_num)
        return header + self._data

    @classmethod
    def from_bytes(cls, raw):
        header = struct.unpack(SWPPacket._PACK_FORMAT,
                               raw[:SWPPacket._HEADER_SIZE])
        type = SWPType(header[0])
        seq_num = header[1]
        data = raw[SWPPacket._HEADER_SIZE:]
        return SWPPacket(type, seq_num, data)

    def __str__(self):
        return "%s %d %s" % (self._type.name, self._seq_num, repr(self._data))


class SWPSender:
    _SEND_WINDOW_SIZE = 5
    _TIMEOUT = 1

    def __init__(self, remote_address, loss_probability=0):
        self._llp_endpoint = llp.LLPEndpoint(remote_address=remote_address,
                                             loss_probability=loss_probability)

        # Start receive thread
        self._recv_thread = threading.Thread(target=self._recv)
        self._recv_thread.start()

        # TODO: Add additional state variables
        self.buffer = {}
        self.timerMemo = {}
        self.lastAck = 0
        self.seqCounter = -1
        self.semaphore = threading.Semaphore(self._SEND_WINDOW_SIZE)

    def send(self, data):
        for i in range(0, len(data), SWPPacket.MAX_DATA_SIZE):
            self._send(data[i:i + SWPPacket.MAX_DATA_SIZE])

    def _send(self, data):
        # TODO
        # 1. Wait for a free space in the send window — a semaphore is the simplest way to handle this.
        #    A semaphore manages an internal counter which is decremented by each acquire() call
        self.semaphore.acquire()

        # 2. Assign the chunk of data a sequence number—the first chunk of data is assigned sequence number 0,
        #    and the sequence number is incremented for each subsequent chunk of data.
        self.seqCounter += 1
        seqNum = self.seqCounter + 1

        # 3. Add the chunk of data to a buffer—in case it needs to be retransmitted.
        self.buffer[seqNum] = data

        # 4. Send the data in an SWP packet with the appropriate type (D) and sequence number —
        #    use the SWPPacket class to construct such a packet
        #    and use the send method provided by the LLPEndpoint class to transmit the packet across the network.
        swpPacket = SWPPacket(SWPType.DATA, seqNum, data)
        self._llp_endpoint.send(swpPacket.to_bytes())

        # 5. Start a retransmission timer — the Timer class provides a convenient way to do this;
        #    the timeout should be 1 second, defined by the constant SWPSender._TIMEOUT;
        #    when the timer expires, the _retransmit method should be called.
        timer = threading.Timer(self._TIMEOUT, self._retransmit, [seqNum])
        timer.start()
        self.timerMemo[seqNum] = timer

        return

    def _retransmit(self, seq_num):
        # TODO

        renewed_timer = threading.Timer(self._TIMEOUT, self._retransmit, [seq_num])
        self.timerMemo.update({seq_num: renewed_timer})
        renewed_timer.start()

        # send pkt
        data = self.buffer[seq_num]
        pkt = SWPPacket(SWPType.DATA, seq_num, data)
        self._llp_endpoint.send(pkt.to_bytes())

        return

    def _recv(self):
        while True:
            # Receive SWP packet
            raw = self._llp_endpoint.recv()
            if raw is None:
                continue
            packet = SWPPacket.from_bytes(raw)
            logging.debug("Received: %s" % packet)

            # TODO
            if not packet.type is SWPType.ACK:
                continue

            seq_num = packet.seq_num
            if seq_num > self.lastAck:
                (self.timerMemo[seq_num]).cancel()
                for i in range(self.lastAck + 1, seq_num + 1):
                    del self.buffer[i]
                    self.timerMemo[i].cancel()
                    del self.timerMemo[i]
                    self.semaphore.release()
                self.lastAck = seq_num

        return


class SWPReceiver:
    _RECV_WINDOW_SIZE = 5

    def __init__(self, local_address, loss_probability=0):
        self._llp_endpoint = llp.LLPEndpoint(local_address=local_address,
                                             loss_probability=loss_probability)

        # Received data waiting for application to consume
        self._ready_data = queue.Queue()

        # Start receive thread
        self._recv_thread = threading.Thread(target=self._recv)
        self._recv_thread.start()

        # TODO: Add additional state variables
        self.buffer = []
        self.ack = 0

    def recv(self):
        return self._ready_data.get()

    def _recv(self):
        while True:
            # Receive data packet
            raw = self._llp_endpoint.recv()
            packet = SWPPacket.from_bytes(raw)
            logging.debug("Received: %s" % packet)

            # TODO
            if not packet.type is SWPType.DATA:
                continue

            if not packet.seq_num > self.ack:
                pkt = SWPPacket(SWPType.ACK, self.ack)
                self._llp_endpoint.send(pkt.to_bytes())
                continue

            repeat = 0
            for i in range(0, len(self.buffer)):
                if (packet.seq_num == self.buffer[i].seq_num):
                    repeat = 1
                    break

            if repeat == 1:
                pkt = SWPPacket(SWPType.ACK, self.ack)
                self._llp_endpoint.send(pkt.to_bytes())
                continue

            self.buffer.append(packet)
            if self._ready_data.qsize() + len(self.buffer) > self._RECV_WINDOW_SIZE:
                maxN = 0
                maxIndex = -1
                for i in range(0, len(self.buffer)):
                    if self.buffer[i].seq_num > maxN:
                        maxN = self.buffer[i].seq_num
                        maxIndex = i
                self.buffer.pop(maxIndex)

            found = 0

            for i in range(0, len(self.buffer)):
                for j in range(0, len(self.buffer)):
                    if self.buffer[j].seq_num == self.ack + 1:
                        self._ready_data.put(self.buffer.pop(j).data)
                        self.ack = self.ack + 1
                        found = 1
                        break
                if found == 0:
                    break

            pkt = SWPPacket(SWPType.ACK, self.ack)
            self._llp_endpoint.send(pkt.to_bytes())

        return
