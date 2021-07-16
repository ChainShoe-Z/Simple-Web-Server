#!/Library/Frameworks/Python.framework/Versions/3.7/bin/python3
# coding: utf-8
import socket
import sys
import threading
import os
import time


class Segment:
    def __init__(self, commands: list, headers: dict, content: bytes):
        self._commands = commands
        self._content = content
        self._send_time = int(round(time.time()*1000))
        self.seq = headers["Sequence"]
        self.ack = headers["Acknowledgement"]
        self.len = headers["Length"]
        self.window = headers["Window"]

    def is_command(self, command: str) -> bool:
        return command in self._commands

    def get_content(self):
        return self._content

    def get_content_len(self):
        return len(self._content)

    def assemble(self) -> bytes:
        b = bytes()
        b += ("|".join(self._commands)+"\n").encode("utf-8")
        b += ("Sequence: %d\n" % self.seq).encode("utf-8")
        b += ("Acknowledgement: %d\n" % self.ack).encode("utf-8")
        b += ("Length: %d\n" % self.len).encode("utf-8")
        b += ("Window: %d\n" % self.window).encode("utf-8")
        b += "\n".encode("utf-8")
        b += self._content
        return b

    def time_out(self):
        return int(round(time.time()*1000))-self._send_time > 300 # timeout = 300ms

    def touch(self):
        self._send_time = int(round(time.time()*1000))


def parse_param():
    usage = "python3 sor-server.py server_ip_address server_udp_port_number " \
            "server_buffer_size server_payload_length"
    if len(sys.argv) != 5:
        print(usage)
        sys.exit(-1)
    server_ip = sys.argv[1]
    try:
        server_port = int(sys.argv[2])
        server_buffer_size = int(sys.argv[3])
        server_payload_length = int(sys.argv[4])
    except ValueError:
        print(usage)
        sys.exit(-1)
    return server_ip, server_port, server_buffer_size, server_payload_length


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


ip_address, port, buffer_size, mss = parse_param()
# print(ip_address, port, buffer_size, payload_length)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind((ip_address, port))
client_dict = {}
client_dict_lock = threading.Lock()


class FileReader:
    def __init__(self, file_name):
        if not os.path.exists(file_name):
            raise FileExistsError("file %s is not exist" % file_name)
        self.file_name = file_name
        self.file = open(file_name, 'rb')
        self.file_size = os.path.getsize(file_name)

    def read(self, size=1024):
        content = bytes()
        while len(content) < size \
                and self.file.tell() < self.file_size:
            content = content + self.file.read(size - len(content))
        return content

    def remain(self):
        return self.file_size-self.file.tell()

    def reach_end(self):
        return self.file.tell() >= self.file_size


class HTTPServer:
    def __init__(self):
        self.close = False
        self._pipe = []
        self._data_to_send = []
        self._file_reader = None

    def deliver(self, data: bytes):
        filename, self.close = HTTPServer.parse_http_request(data)
        self._pipe.append(filename)

    @staticmethod
    def parse_http_request(data: bytes):
        msg = data.decode("utf-8")
        msgs = msg.split("\n")
        filename, close = None, False
        tmp = msgs[0].split(" ")
        if tmp[0] != "GET":
            raise Exception("bad request")
        filename = tmp[1]
        for line in msgs[1:]:
            if line.startswith("Connection: "):
                if line.replace("Connection: ", "").startswith("close"):
                    close = True
        return filename[1:], close

    def get_data(self, client_addr, allow_byes=mss) -> bytes:
        bad_resp_line = "HTTP/1.0 400 Bad Request\r\n"
        ok_resp_line = "HTTP/1.0 200 OK"
        connection_keep_alive = "Connection: keep-alive\r\n"
        bad_resp_body = "<html><head></head><body><h1>400 Bad Request</h1></body></html>".encode("utf-8")
        if self._file_reader and not self._file_reader.reach_end():
            return self._file_reader.read(allow_byes)
        else:
            filename = self._pipe.pop(0)
            to_be_print = time.ctime()
            to_be_print += " %s:%d" % (client_addr[0], client_addr[1])
            to_be_print += " GET /%s HTTP/1.0; " % filename
            if not os.path.exists(filename):
                to_be_print += bad_resp_line.strip("\r\n")
                http_resp_line_and_header = (bad_resp_line + connection_keep_alive + (
                        "Content-Length: %s\r\n\r\n" % len(bad_resp_body))).encode("utf-8")
                rdp_body = http_resp_line_and_header + bad_resp_body
            else:
                to_be_print += ok_resp_line.strip("\r\n")
                self._file_reader = FileReader(filename)
                http_resp_line_and_header = (ok_resp_line + connection_keep_alive + "Content-Length: %d\r\n\r\n"
                             % self._file_reader.file_size).encode("utf-8")
                file_bytes_to_send = allow_byes - len(http_resp_line_and_header)
                content = self._file_reader.read(file_bytes_to_send)
                rdp_body = http_resp_line_and_header + content
            print(to_be_print)
            return rdp_body


    def has_data(self):
        return len(self._pipe) != 0 or (
                self._file_reader and not self._file_reader.reach_end())


class ServerTransportService(threading.Thread):
    def __init__(self, client_addr, recv_wnd=4096):
        threading.Thread.__init__(self)
        self._client_addr = client_addr
        self._recv_queue = []
        self._private_recv_queue = []
        self._send_queue = []
        self._flow_control_wnd = 4096   # send window
        self._recv_wnd = recv_wnd       # recv window, used to tell client how much bytes can send

        self._sequence = 0              # current sequence
        self._ack = 0                   # expected data
        self._semaphore = threading.Semaphore(0)
        self._state = "not_connected" # syn_received, established,

        self._upper_layer = HTTPServer()

    def enque(self, seg: Segment):
        self._recv_queue.append(seg)
        self._semaphore.release()

    # TODO: delete, used to debug
    def recv(self):
        s.settimeout(1/1000)
        try:
            data, addr = s.recvfrom(buffer_size)
        except socket.timeout:
            raise socket.timeout
        packet = parse_rdp_packet(data)
        self.enque(packet)

    def connect(self):
        self._semaphore.acquire()
        seg: Segment = self._recv_queue.pop(0)
        if not seg.is_command("SYN"):
            return
        # assemble the syn|ack packet, syn from peer consume one sequence
        self._ack = seg.seq + 1
        self._flow_control_wnd = seg.window
        commands = ["SYN", "ACK"]
        headers = {"Sequence": self._sequence, "Length": 0, "Acknowledgement": self._ack,
                    "Window": self._recv_wnd}
        seg: Segment = Segment(commands, headers, bytes())
        s.sendto(seg.assemble(), self._client_addr)
        self._sequence += 1 # syn consume one sequence
        self._send_queue.append(seg)
        self._state = "syn_received"
        # wait for the ack
        while True:
            # used to debug
            # TODO: delete
            '''
            try:
                self.recv()
            except socket.timeout:
                continue
            '''
            recv_data = self._semaphore.acquire(timeout=0.001)
            if recv_data:
                seg: Segment = self._recv_queue.pop(0)
                if self._ack == seg.seq:
                    self._state = "established"
                    self._send_queue.pop(0)
                    if seg.is_command("DAT"):
                        self._upper_layer.deliver(seg.get_content())
                        self._ack += seg.len
                    break
                else:
                    s.sendto(self._send_queue[0].assemble(), self._client_addr)
            else:
                seg:Segment = self._send_queue[0]
                if seg.time_out():
                    seg.touch()
                    s.sendto(seg.assemble(), self._client_addr)


    def handle_requests(self):
        if self._state != "established":
            return
        last_recv = 0
        repeat_time = 1

        # keep going until http connection will be closed or http dont have data to sent
        while len(self._send_queue) > 0 or not self._upper_layer.close or self._upper_layer.has_data():
            # send requested files
            while self._upper_layer.has_data() and self._flow_control_wnd > 0:
                if self._flow_control_wnd > mss:
                    rdp_body = self._upper_layer.get_data(client_addr=self._client_addr)
                else:
                    rdp_body = self._upper_layer.get_data(client_addr=self._client_addr, allow_byes=self._flow_control_wnd)
                commands = ["DAT"]
                headers = {"Sequence": self._sequence, "Acknowledgement": self._ack, "Length": len(rdp_body), "Window": self._recv_wnd}
                # send the segment until the flow control window is 0
                seg = Segment(commands, headers, rdp_body)
                s.sendto(seg.assemble(), self._client_addr)
                self._send_queue.append(seg)
                self._sequence += len(rdp_body)
                self._flow_control_wnd -= len(rdp_body)

            # wait for acks
            while self._recv_wnd >= 0:
                '''
                try:
                    self.recv()
                except socket.timeout:
                    break
                '''
                recv_data = self._semaphore.acquire(timeout=0.001)
                if not recv_data:
                    break
                seg: Segment = self._recv_queue.pop(0)
                self._private_recv_queue.append(seg)
                self._recv_wnd -= seg.len

            # sort the segments have been sent by their sequence
            self._private_recv_queue.sort(key=lambda seg: seg.seq)
            while len(self._private_recv_queue) > 0:
                seg: Segment = self._private_recv_queue[0]
                # duplicated packet, discard it
                if seg.seq < self._ack:
                    self._private_recv_queue.pop(0)
                    continue
                # if the sequence if not what we expected, then gap appear,
                # send the acknowledgement immediately
                if seg.seq != self._ack:
                    commands = ["ACK"]
                    headers = {"Sequence": self._sequence, "Acknowledgement": self._ack, "Window": self._recv_wnd,
                               "Length": 0}
                    ack_seg = Segment(commands, headers, bytes())
                    s.sendto(ack_seg.assemble(), self._client_addr)
                    break
                # pop the segment and increment the ack number
                self._private_recv_queue.pop(0)
                self._ack += seg.len

                if seg.is_command("ACK"):
                    while len(self._send_queue) > 0:
                        header_seg: Segment = self._send_queue[0]
                        if seg.ack >= header_seg.seq + header_seg.len:
                            self._send_queue.pop(0)
                            self._flow_control_wnd += header_seg.len
                        else:
                            break
                    # handle fast retransmission
                    if seg.ack == last_recv:
                        repeat_time += 1
                    else:
                        last_recv = seg.ack
                        repeat_time = 1
                    if repeat_time >= 3:
                        s.sendto(self._send_queue[0].assemble(), self._client_addr)
                        repeat_time = 1
                if seg.is_command("DAT"):
                    self._upper_layer.deliver(seg.get_content())
                    self._recv_wnd += seg.len
                    commands = ["ACK"]
                    headers = {"Sequence": self._sequence, "Acknowledgement": self._ack, "Window": self._recv_wnd,
                               "Length": 0}
                    ack_seg = Segment(commands, headers, bytes())
                    s.sendto(ack_seg.assemble(), self._client_addr)
            # handle time out
            if len(self._send_queue) > 0:
                seg: Segment = self._send_queue[0]
                if seg.time_out():
                    seg.touch()
                    s.sendto(seg.assemble(), self._client_addr)

    def disconnect(self):
        commands = ["FIN"]
        headers = {"Sequence": self._sequence, "Acknowledgement": self._ack, "Window": self._recv_wnd, "Length": 0}
        seg = Segment(commands, headers, bytes())
        self._send_queue.append(seg)
        s.sendto(seg.assemble(), self._client_addr)
        self._sequence += 1 # fin consume one sequence
        while self._state != "TIME_WAIT":
            # TODO: Remove
            '''
            try:
                self.recv()
            except socket.timeout:
                pass
            '''
            recv_data = self._semaphore.acquire(timeout=0.001)
            if recv_data:
                seg = self._recv_queue.pop(0)
                if seg.seq == self._ack:
                    commands = ["ACK"]
                    self._ack += 1
                    headers = {"Sequence": self._sequence, "Acknowledgement": self._ack, "Window": self._recv_wnd,
                               "Length": 0}
                    ack_seg = Segment(commands, headers, bytes())
                    s.sendto(ack_seg.assemble(), self._client_addr)
                    self._state = "TIME_WAIT"
            else:
                seg: Segment = self._send_queue[0]
                if seg.time_out():
                    seg.touch()
                    s.sendto(seg.assemble(), self._client_addr)

    def run(self) -> None:
        self.connect()
        self.handle_requests()
        self.disconnect()


while True:
    s.settimeout(None)
    data, addr = s.recvfrom(buffer_size)
    key = "%s:%d" % (addr[0], addr[1])
    # print(key)
    packet = parse_rdp_packet(data)
    if key in client_dict:
        client = client_dict[key]
        client.enque(packet)
    else:
        client_dict_lock.acquire()
        client = ServerTransportService(addr, buffer_size)
        client_dict[key] = client
        client_dict_lock.release()
        client.enque(packet)
        client.start()
