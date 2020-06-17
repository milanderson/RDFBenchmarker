import socket, struct, binascii, argparse

class TCPPacketSniffer():
    def __init__(self, host="", port=-1, bufferSize=100000, outFname=""):
        self.host = host
        self.port = port
        self.bufferSize = bufferSize
        self.outfile = open(outFname, "w") if outFname else None

    def _log(self, msg):
        if self.outfile is not None:
            self.outfile.write(msg)
        else:
            print(msg)

    def isMatch(self, packet):
        #TODO: Better IP checking
        return hasattr(packet, "ipFrame") and hasattr(packet, "tcpFrame") and \
        (self.host in ["", "0.0.0.0"] or self.host == packet.ipFrame.tar_ip) and \
        (self.port == -1 or self.port == packet.tcpFrame.tar_port)

    def run(self):
        s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))

        while True:
            data, addr = s.recvfrom(self.bufferSize)
            p = Packet(data, addr)
            if self.isMatch(p):
                # WRITE DATA HERE
                # self.log(------)
                print('aa')
                pass

class Packet():
    def __init__(self, data, addr):
        self.addr = addr
        self.ethFrame = EthernetFrame(data)
        if self.ethFrame.protocol in [EthernetFrame.PROTOCOL.IPV4, EthernetFrame.PROTOCOL.IPv6]:
            self.ipFrame = IPFrame(self.ethFrame.data)

            if self.ipFrame.protocol == IPFrame.PROTOCOL.TCP:
                self.tcpFrame = TCPFrame(self.ipFrame.data)

class EthernetFrame():
    class PROTOCOL():
        IPV4 = "0800"
        IPv6 = "86DD"
        ARP = "0806"

    def __init__(self, data):
        self.dst_mac, self.src_mac, self.protocol, self.data = EthernetFrame._parseFrame(data)

    @staticmethod
    def _parseFrame(data):
        dest_mac, src_mac, proto = struct.unpack('! 6s 6s 2s', data[:14])
        return EthernetFrame._get_mac_addr(dest_mac), EthernetFrame._get_mac_addr(src_mac), binascii.hexlify(proto), data[14:]

    @staticmethod
    def _get_mac_addr(addr):
        bytes_str = map(lambda x: '{:02x}'.format(ord(x)), addr)
        mac_addr = ':'.join(bytes_str).upper()
        return mac_addr

class IPFrame():
    class PROTOCOL():
        ICMP = 1
        TCP = 6
        UDP = 17
        SCTP = 132

    def __init__(self, data):
        self.version = ord(data[0]) >> 4
        self.header_len = (ord(data[0]) & 0xF) * 4
        if self.version == 4:
            self.packet_len, self.ttl, self.protocol, src, target = struct.unpack('! H 4x B B 2x 4s 4s', data[2:20])
            self.src_ip = socket.inet_ntoa(src)
            self.tar_ip =socket.inet_ntoa(target)
            self.data = data[self.header_len:]

class TCPFrame():
    def __init__(self, data):
        self.src_port, self.tar_port, self.seq_no, self.ack_no, self.header_len, self.window = struct.unpack("! H H I I B 1x H", data[:16])
        self.header_len = (self.header_len >> 4) * 4
        self.data = data[self.header_len:]

def main(**kwargs):
    wobey = TCPPacketSniffer(**kwargs)
    wobey.run()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Capture and log TCP traffic')
    parser.add_argument('-host', type=str, action='store', default="0.0.0.0", help='Set recieving IP')
    parser.add_argument('-port', type=int, action='store', default=-1, help='Set receiving port')
    parser.add_argument('-bufferSize', '-B', type=int, action='store', default=10000, help='Set read buffer size, default 100000')
    parser.add_argument('-outFname', '-F', type=str, action='store', default="", help='Set ouput filename, defaults to stdout')

    args = parser.parse_args()
    main(**vars(args))
