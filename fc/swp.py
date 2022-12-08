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
        # 1. Send the data in an SWP packet with the appropriate type (D) and sequence number
        #    use the SWPPacket class to construct such a packet
        #    and use the send method provided by the LLPEndpoint class to transmit the packet across the network.
        data = self.buffer[seq_num]
        pkt = SWPPacket(SWPType.DATA, seq_num, data)
        self._llp_endpoint.send(pkt.to_bytes())

        # 2. Start a retransmission timer—the Timer class provides a convenient way to do this;
        #    the timeout should be 1 second, defined by the constant SWPSender._TIMEOUT;
        #    when the timer expires, the _retransmit method should be called.
        timer = threading.Timer(self._TIMEOUT, self._retransmit, [seq_num])
        self.timerMemo[seq_num] = timer
        timer.start()
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
            # 1. ignore any packets that aren’t SWP ACKs.
            if packet.type is not SWPType.ACK:
                continue

            # 2. ignore SWP ACKs acked
            seqNum = packet.seq_num
            if seqNum <= self.lastAck:
                continue

            # 3. Cancel the retransmission timer for that chunk of data.
            tempTimer = self.timerMemo[seqNum]
            tempTimer.cancel()

            # 4. Discard that chunk of data.
            #    the SWP ACKs are cumulative, so even though an SWP ACK packet only contains one sequence number,
            #    the ACK effectively acknowledges all chunks of data up to
            #    and including the chunk of data associated with the sequence number in the SWP ACK.
            for ind in range(self.lastAck + 1, seqNum + 1, 1):
                if ind in self.buffer:
                    self.buffer.pop(ind)
                if ind in self.timerMemo:
                    temp = self.timerMemo.pop(ind)
                    temp.cancel()
                self.semaphore.release()
            self.lastAck = seqNum

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
        self.memo = {}
        self.lastAck = 0

    def recv(self):
        return self._ready_data.get()

    def _recv(self):
        while True:
            # Receive data packet
            raw = self._llp_endpoint.recv()
            packet = SWPPacket.from_bytes(raw)
            logging.debug("Received: %s" % packet)

            # TODO
            # 0. Check Packet Type
            if packet.type is not SWPType.DATA:
                continue

            # 1. Check if the chunk of data was already acknowledged
            #    and retransmit an SWP ACK containing the highest acknowledged sequence number.
            seqNum = packet.seq_num
            if seqNum <= self.lastAck or seqNum in self.memo:
                logging.debug("already acknowledged: " + str(seqNum))
                pkt = SWPPacket(SWPType.ACK, self.lastAck)
                self._llp_endpoint.send(pkt.to_bytes())
                continue

            # 2. Add the chunk of data to a buffer — in case it is out of order.
            self.buffer.append(packet)
            self.memo[seqNum] = True

            #   handle overflow
            self.buffer.sort(key=lambda pk: pk.seq_num)
            if self._ready_data.qsize() + len(self.memo) > self._RECV_WINDOW_SIZE:
                temp = self.buffer.pop()
                self.memo.pop(temp.seq_num)

            # 3. Traverse the buffer, starting from the first buffered chunk of data,
            #    until reaching a “hole”—i.e., a missing chunk of data.
            #    All chunks of data prior to this hole should be placed in the _ready_data queue,
            #    which is where data is read from when an “application” calls recv, and removed from the buffer.
            flag = False
            for i in range(0, len(self.buffer)):
                for j in range(0, len(self.buffer)):
                    if self.buffer[j].seq_num == self.lastAck + 1:
                        temp = self.buffer.pop(j)
                        self.memo.pop(temp.seq_num)
                        self._ready_data.put(temp.data)
                        self.lastAck += 1
                        flag = True
                        break
                if not flag:
                    break

            # 4. Send an acknowledgement for the highest sequence number for which all data chunks up to
            #    and including that sequence number have been received.
            swpPacket = SWPPacket(SWPType.ACK, self.lastAck)
            self._llp_endpoint.send(swpPacket.to_bytes())

        return
