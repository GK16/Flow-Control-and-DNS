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
        self.Buffer = {}
        self.Timers = {}
        self.LAST_ACK = 0
        self.LAST_SENT = 0
        self.sem = threading.Semaphore(self._SEND_WINDOW_SIZE)

    def send(self, data):
        for i in range(0, len(data), SWPPacket.MAX_DATA_SIZE):
            self._send(data[i:i + SWPPacket.MAX_DATA_SIZE])

    def _send(self, data):
        # wait for free space
        self.sem.acquire()

        # ger seq#
        SEQ = self.LAST_SENT + 1
        self.LAST_SENT += 1

        # add to buffer

        self.Buffer.update({SEQ: data})
        timer = threading.Timer(self._TIMEOUT, self._retransmit, [SEQ])
        timer.start()
        self.Timers.update({SEQ: timer})

        # send pkt
        pkt = SWPPacket(SWPType.DATA, SEQ, data)
        self._llp_endpoint.send(pkt.to_bytes())

        return

    def _retransmit(self, seq_num):

        renewed_timer = threading.Timer(self._TIMEOUT, self._retransmit, [seq_num])
        self.Timers.update({seq_num: renewed_timer})
        renewed_timer.start()

        # send pkt
        data = self.Buffer[seq_num]
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

            if not packet.type is SWPType.ACK:
                continue

            seq_num = packet.seq_num
            if seq_num > self.LAST_ACK:
                (self.Timers[seq_num]).cancel()
                for i in range(self.LAST_ACK + 1, seq_num + 1):
                    del self.Buffer[i]
                    self.Timers[i].cancel()
                    del self.Timers[i]
                    self.sem.release()
                self.LAST_ACK = seq_num
        return


class SWPReceiver:
    _RECV_WINDOW_SIZE = 1

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