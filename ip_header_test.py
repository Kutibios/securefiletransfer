import socket
import struct
import time
from typing import List, Tuple

class IPHeader:
    def __init__(self, source_ip: str, dest_ip: str, data: bytes = b''):
        self.version = 4
        self.ihl = 5
        self.tos = 0
        self.total_length = 20 + len(data)  # IP header (20) + data
        self.identification = int(time.time()) & 0xFFFF
        self.flags = 0
        self.fragment_offset = 0
        self.ttl = 64
        self.protocol = socket.IPPROTO_TCP
        self.checksum = 0
        self.source_ip = socket.inet_aton(source_ip)
        self.dest_ip = socket.inet_aton(dest_ip)
        self.data = data

    def calculate_checksum(self) -> int:
        header = self.pack()
        if len(header) % 2 != 0:
            header += b'\0'
        
        words = struct.unpack("!%dH" % (len(header) // 2), header)
        total = sum(words)
        
        while total >> 16:
            total = (total & 0xFFFF) + (total >> 16)
        
        return ~total & 0xFFFF

    def pack(self) -> bytes:
        ver_ihl = (self.version << 4) + self.ihl
        flags_frag = (self.flags << 13) + self.fragment_offset
        
        return struct.pack('!BBHHHBBH4s4s',
                          ver_ihl,
                          self.tos,
                          self.total_length,
                          self.identification,
                          flags_frag,
                          self.ttl,
                          self.protocol,
                          self.checksum,
                          self.source_ip,
                          self.dest_ip)

    def set_flags(self, df: bool = False, mf: bool = False):
        self.flags = 0
        if df:
            self.flags |= 0x4000  # Don't Fragment
        if mf:
            self.flags |= 0x2000  # More Fragments

    def set_fragment_offset(self, offset: int):
        self.fragment_offset = offset

    def set_ttl(self, ttl: int):
        self.ttl = ttl

def fragment_packet(data: bytes, mtu: int = 1500) -> List[bytes]:
    """Veriyi MTU boyutuna göre parçalara ayırır."""
    fragments = []
    header_size = 20  # IP header size
    max_data_size = mtu - header_size
    
    # Veriyi parçalara ayır
    for i in range(0, len(data), max_data_size):
        fragment_data = data[i:i + max_data_size]
        fragment = IPHeader('127.0.0.1', '127.0.0.1', fragment_data)
        
        # Son parça değilse MF bayrağını ayarla
        if i + max_data_size < len(data):
            fragment.set_flags(mf=True)
        
        # Fragment offset'i ayarla
        fragment.set_fragment_offset(i // 8)
        
        # Checksum'ı hesapla ve ayarla
        fragment.checksum = fragment.calculate_checksum()
        
        fragments.append(fragment.pack() + fragment_data)
    
    return fragments

def reassemble_packets(fragments: List[bytes]) -> bytes:
    """Parçalanmış paketleri birleştirir."""
    # Fragment offset'e göre sırala
    sorted_fragments = sorted(fragments, key=lambda x: struct.unpack('!H', x[6:8])[0] & 0x1FFF)
    
    # Veriyi birleştir
    reassembled_data = b''
    for fragment in sorted_fragments:
        # IP header'ı atla (20 byte)
        data = fragment[20:]
        reassembled_data += data
    
    return reassembled_data

def send_fragmented_packet(sock: socket.socket, data: bytes, dest_addr: Tuple[str, int], mtu: int = 1500):
    """Veriyi parçalara ayırıp gönderir."""
    fragments = fragment_packet(data, mtu)
    
    for fragment in fragments:
        sock.sendto(fragment, dest_addr)
        time.sleep(0.1)  # Parçalar arası küçük gecikme

def test_packet_fragmentation():
    """Paket parçalama ve birleştirme testi."""
    try:
        # Raw socket oluştur
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        
        # Test verisi oluştur (MTU'dan büyük)
        test_data = b'X' * 3000
        
        # Veriyi parçalara ayır ve gönder
        print("[*] Veri parçalanıyor ve gönderiliyor...")
        send_fragmented_packet(sock, test_data, ('127.0.0.1', 0))
        
        print("[+] Test tamamlandı!")
        
    except PermissionError:
        print("[!] Bu programı çalıştırmak için Yönetici (Admin) izni gerekiyor!")
    except Exception as e:
        print(f"[!] Hata: {e}")

if __name__ == "__main__":
    test_packet_fragmentation()
