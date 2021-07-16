#!/Library/Frameworks/Python.framework/Versions/3.7/bin/python3
# coding: utf-8
import socket
import time
import sys


def parse_param():
    usage = "python3 sor-client.py server_ip_address server_udp_port_number " \
            "client_buffer_size client_payload_length read_file_name write_file_name " \
            "[read_file_name write_file_name]*"
    if len(sys.argv) < 7:
        print(usage)
        sys.exit(-1)
    server_ip = sys.argv[1]
    try:
        server_port = int(sys.argv[2])
        client_buffer_size = int(sys.argv[3])
        client_payload_length = int(sys.argv[4])
    except ValueError:
        print(usage)
        sys.exit(-1)
    index = 5
    request_files = []
    target_files = []
    while index < len(sys.argv):
        request_files.append(sys.argv[index])
        index += 1
        if index >= len(sys.argv):
            print(usage)
            sys.exit(1)
        target_files.append(sys.argv[index])
        index += 1
    return server_ip, server_port, client_buffer_size, client_payload_length, request_files, target_files


server_ip, server_port, buffer_size, mss, request_files, target_files = parse_param()


class Segment:
    def __init__(self, commands: list, headers: dict, content: bytes):
        self._commands = commands
        self._content = content
        self._send_time = int(round(time.time() * 1000))
        self.seq = headers["Sequence"]
        self.ack = headers["Acknowledgement"]
        self.len = headers["Length"]
        self.window = headers["Window"]

    def is_command(self, command: str) -> bool:
        return command in self._commands

    def get_commands(self):
        return "|".join(self._commands)

    def get_content(self):
        return self._content

    def get_content_len(self):
        return len(self._content)

    def assemble(self) -> bytes:
        b = bytes()
        b += ("|".join(self._commands) + "\n").encode("utf-8")
        b += ("Sequence: %d\n" % self.seq).encode("utf-8")
        b += ("Acknowledgement: %d\n" % self.ack).encode("utf-8")
        b += ("Length: %d\n" % self.len).encode("utf-8")
        b += ("Window: %d\n" % self.window).encode("utf-8")
        b += "\n".encode("utf-8")
        b += self._content
        return b

    def time_out(self):
        return int(round(time.time() * 1000)) - self._send_time > 300  # timeout = 300ms

    def touch(self):
        self._send_time = int(round(time.time() * 1000))

    def __eq__(self, other):
        return self.seq == other.seq


def parse_rdp_packet(data: bytes) -> Segment:
    headers = {}
    i = 0
    while i < len(data):
        if chr(data[i]) != '\n':
            i += 1
            continue
        i += 1
        # find two consecutive '\n'
        if i < len(data) and chr(data[i]) == '\n':
            i += 1
            break
    lines = data[:i].decode("utf-8").split("\n")
    commands = lines.pop(0).split("|")
    for line in lines:
        if line == "":
            continue
        header = line.split(": ")
        headers[header[0].strip()] = int(header[1].strip())
    content = data[i:]
    return Segment(commands, headers, content)


class FileWriter:

    def __init__(self, file_name):
        self.file_name = file_name
        self.file = open(file_name, "wb+")

    def write(self, content):
        cnt = 0
        while cnt < len(content):
            cnt = cnt + self.file.write(content[cnt:])

    def close(self):
        self.file.flush()
        self.file.close()


class HTTPClient:
    def __init__(self, requests: list, target_files: list):
        self._close = False
        self._requests = requests
        self._target_files = target_files
        self._file_writer = None

        self._current_request = None
        self._current_write_filename = None

        self._current_content_length = -1

        self._index = 0
        self._write_index = 0

    @staticmethod
    def parse_http_body(body: bytes) -> (str, dict):
        index = body.find(b"\r\n\r\n")
        resp_line_headers = body[:index + 4].decode("utf-8").split("\r\n")
        status = resp_line_headers.pop(0).split(" ")[1]
        headers = {}
        for line in resp_line_headers:
            if line == "":
                continue
            line = line.split(": ")
            headers[line[0]] = line[1]
        return status, headers, body[index + 4:]

    def deliver(self, body: bytes):
        if not self._file_writer:
            status, headers, content = HTTPClient.parse_http_body(body)
            self._current_content_length = int(headers["Content-Length"])
            self._file_writer = FileWriter(self._target_files[self._write_index])
            self._file_writer.write(content)
            self._current_content_length -= len(content)
        else:
            self._file_writer.write(body)
            self._current_content_length -= len(body)
        if self._current_content_length == 0:
            self._file_writer.close()
            self._file_writer = None
            self._write_index += 1

    def has_data(self) -> bool:
        return len(self._requests) != self._index

    def completed(self):
        return len(self._requests) == self._index and len(self._target_files) == self._write_index

    def get_data(self) -> bytes:
        request_line = "GET /%s HTTP/1.0\r\n" % self._requests[self._index]
        if len(self._requests) - 1 != self._index:
            request_header = "Connection: keep-alive\r\n\r\n"
        else:
            request_header = "Connection: close\r\n\r\n"
        self._index += 1
        return (request_line + request_header).encode("utf-8")


class ClientTransportService:
    def __init__(self, server_ip: str, server_port: int, recv_wnd: int, requests: list, target_files: list):
        self._server_addr = (server_ip, server_port)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._recv_queue = []
        self._send_queue = []
        self._flow_control_wnd = 4096  # send window
        self._recv_wnd = recv_wnd  # recv window, used to tell client how much bytes can send

        self._sequence = 0  # current sequence
        self._ack = 0  # expected data
        self._state = "not_connected"  # syn_sent, established
        self._to_be_close = False

        self._upper_layer = HTTPClient(requests, target_files)

        self._buffer_size = 2048
        self._sock.settimeout(0.001)

    def log(self, action, segment: Segment):
        to_be_print = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))
        to_be_print += ": %s; %s; " % (action, segment.get_commands())
        to_be_print += "Sequence: %d; " % segment.seq
        to_be_print += "Length: %d; " % segment.len
        to_be_print += "Acknowledgement: %d; " % segment.ack
        to_be_print += "Window: %d; " % segment.window
        print(to_be_print)

    def connect(self):
        commands = ["SYN"]
        headers = {"Sequence": self._sequence, "Acknowledgement": self._ack, "Window": self._recv_wnd, "Length": 0}
        seg = Segment(commands, headers, bytes())

        self._sock.sendto(seg.assemble(), self._server_addr)
        self._send_queue.append(seg)
        self._state = "syn_sent"
        self._sequence += 1  # syn consume one sequence

        while True:
            try:
                data, addr = self._sock.recvfrom(self._buffer_size)
                seg = parse_rdp_packet(data)
                self.log("Receive", seg)
                if seg.is_command("ACK") and seg.is_command("SYN"):
                    self._send_queue.pop(0)
                    self._ack = seg.seq + 1
                    self._flow_control_wnd = seg.window

                    rdp_body = self._upper_layer.get_data()
                    commands = ["ACK", "DAT"]
                    headers = {"Sequence": self._sequence, "Acknowledgement": self._ack,
                               "Window": self._recv_wnd, "Length": len(rdp_body)}
                    seg = Segment(commands, headers, rdp_body)
                    self._send_queue.append(seg)

                    self._flow_control_wnd -= len(rdp_body)
                    self._sequence += len(rdp_body)

                    self._sock.sendto(seg.assemble(), self._server_addr)
                    self._state = "established"
                    self.log("Send", seg)
                    break
            except socket.timeout:
                pass
            seg: Segment = self._send_queue[0]
            if seg.time_out():
                seg.touch()
                self._sock.sendto(seg.assemble(), self._server_addr)
                self.log("Send", seg)

    def issue_request(self):
        last_recv = 0
        repeat_time = 1
        while not self._upper_layer.completed():

            # test if exist pipelining requests, issue requests if have any
            while self._upper_layer.has_data() and self._flow_control_wnd > 0:
                rdp_body = self._upper_layer.get_data()
                commands = ["DAT", "ACK"]
                headers = {"Sequence": self._sequence, "Acknowledgement":
                    self._ack, "Window": self._recv_wnd, "Length": len(rdp_body)}
                seg = Segment(commands, headers, rdp_body)
                self._send_queue.append(seg)
                # every time send a packet, decrement the flow control window and
                # increment the sequence by length of rdp_body
                self._flow_control_wnd -= len(rdp_body)
                self._sequence += len(rdp_body)
                # send the packet and print log
                self._sock.sendto(seg.assemble(), self._server_addr)
                self.log("Send", seg)

            # receive data from server
            self._sock.settimeout(1 / 1000)
            try:
                while self._recv_wnd >= 0:
                    data, addr = self._sock.recvfrom(self._buffer_size)
                    packet = parse_rdp_packet(data)
                    if packet in self._recv_queue:
                        continue
                    # every time receive a packet, enqueue the packet and
                    # decrement the receive window
                    self._recv_queue.append(packet)
                    self._recv_wnd -= packet.get_content_len()
                    self.log("Receive", packet)
            except socket.timeout:
                pass
            # sort the segment by their sequence number
            self._recv_queue.sort(key=lambda seg: seg.seq)

            # handle every sequence received
            while len(self._recv_queue) > 0:
                seg: Segment = self._recv_queue[0]
                if seg.seq < self._ack:
                    self._recv_queue.pop(0)
                    continue
                # exist gap, send ack immediately
                if seg.seq != self._ack:
                    commands = ["ACK"]
                    headers = {"Sequence": self._sequence, "Acknowledgement": self._ack, "Window": self._recv_wnd,
                               "Length": 0}
                    # ack does not need to cache
                    ack_seg = Segment(commands, headers, bytes())
                    self._sock.sendto(ack_seg.assemble(), self._server_addr)
                    self.log("Send", ack_seg)
                    break
                # if the packet is expected, pop the packet, increment the ack number
                self._recv_queue.pop(0)
                self._ack += seg.len

                # process stream of ack
                if seg.is_command("ACK"):
                    while len(self._send_queue) > 0:
                        seg_sent: Segment = self._send_queue[0]
                        # if ack number larger than the packet have sent, pop the packet
                        # increment the flow control window
                        if seg.ack >= seg_sent.seq + seg_sent.len:
                            self._send_queue.pop(0)
                            self._flow_control_wnd += seg_sent.len
                        else:
                            break
                    # handle the fast retransmission case
                    if seg.ack == last_recv:
                        repeat_time += 1
                    else:
                        last_recv = seg.ack
                        repeat_time = 1
                    if repeat_time >= 3:
                        if not seg.is_command("DAT") and len(self._send_queue) > 0:
                            self._sock.sendto(self._send_queue[0].assemble(), self._server_addr)
                            self.log("Send", self._send_queue[0])
                        repeat_time = 1

                # process stream of data
                if seg.is_command("DAT"):
                    # deliver the data to http layer
                    self._upper_layer.deliver(seg.get_content())
                    # after deliver the data, we have more space to receive
                    # increment the receive window size, and send the ack
                    self._recv_wnd += seg.len
                    commands = ["ACK"]
                    headers = {"Sequence": self._sequence, "Acknowledgement": self._ack, "Window": self._recv_wnd,
                               "Length": 0}
                    ack_seg = Segment(commands, headers, bytes())
                    self._sock.sendto(ack_seg.assemble(), self._server_addr)
                    self.log("Send", ack_seg)

            # handle time out
            if len(self._send_queue) > 0:
                seg: Segment = self._send_queue[0]
                if seg.time_out():
                    seg.touch()
                    self._sock.sendto(seg.assemble(), self._server_addr)
                    self.log("Send", seg)

    def disconnect(self):
        while self._state != "CLOSED":
            timeout = False
            try:
                data, addr = self._sock.recvfrom(self._buffer_size)
                packet = parse_rdp_packet(data)
            except socket.timeout:
                timeout = True
            if not timeout:
                self.log("Receive", packet)
                if self._state == "established":
                    if packet.is_command("FIN"):
                        self._ack += 1
                        commands = ["FIN", "ACK"]
                        headers = {"Sequence": self._sequence, "Acknowledgement": self._ack, "Window": self._recv_wnd,
                                   "Length": 0}
                        seg = Segment(commands, headers, bytes())
                        self._sock.sendto(seg.assemble(), self._server_addr)
                        self._send_queue.append(seg)
                        self.log("Send", seg)
                        self._sequence += 1
                        self._state = "LAST_ACK"
                        continue
                if self._state == "LAST_ACK":
                    if packet.is_command("ACK"):
                        if packet.seq == self._ack:
                            break
            if self._state == "established":
                continue
            if self._state == "LAST_ACK":
                seg: Segment = self._send_queue[0]
                if seg.time_out():
                    seg.touch()
                    self._sock.sendto(seg.assemble(), self._server_addr)
                    self.log("Send", seg)
                    continue


client = ClientTransportService(server_ip, server_port, buffer_size, request_files, target_files)
client.connect()
client.issue_request()
client.disconnect()
