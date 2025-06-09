import socket
import struct
import time
import binascii
from typing import List, Dict, Tuple
from dataclasses import dataclass
from datetime import datetime

@dataclass
class IPHeader:
    version: int
    ihl: int
    tos: int
    total_length: int
    identification: int
    flags: int
    fragment_offset: int
    ttl: int
    protocol: int
    header_checksum: int
    source_ip: str
    dest_ip: str

@dataclass
class TCPHeader:
    source_port: int
    dest_port: int
    sequence: int
    ack_number: int
    data_offset: int
    flags: int
    window: int
    checksum: int
    urgent_pointer: int

class PacketAnalyzer:
    def __init__(self, interface: str = "lo"):
        self.interface = interface
        self.socket = None
        self.packet_count = 0
        self.packet_history: List[Tuple[datetime, bytes]] = []
        
    def start_capture(self):
        """Raw socket ile paket yakalamayı başlatır."""
        try:
            self.socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            self.socket.bind((self.interface, 0))
            print(f"[+] {self.interface} arayüzünde paket yakalama başladı")
        except Exception as e:
            print(f"[!] Paket yakalama başlatılamadı: {e}")
            return False
        return True

    def stop_capture(self):
        """Paket yakalamayı durdurur."""
        if self.socket:
            self.socket.close()
            self.socket = None
            print("[+] Paket yakalama durduruldu")

    def parse_ip_header(self, data: bytes) -> IPHeader:
        """IP başlığını parse eder."""
        # IP başlık yapısı
        # 0                   1                   2                   3
        # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |Version|  IHL  |Type of Service|          Total Length         |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |         Identification        |Flags|      Fragment Offset    |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |  Time to Live |    Protocol   |         Header Checksum       |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                       Source Address                          |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                    Destination Address                        |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        
        version_ihl = data[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        
        tos = data[1]
        total_length = struct.unpack('!H', data[2:4])[0]
        identification = struct.unpack('!H', data[4:6])[0]
        
        flags_fragment = struct.unpack('!H', data[6:8])[0]
        flags = (flags_fragment >> 13) & 0x7
        fragment_offset = flags_fragment & 0x1FFF
        
        ttl = data[8]
        protocol = data[9]
        header_checksum = struct.unpack('!H', data[10:12])[0]
        
        source_ip = socket.inet_ntoa(data[12:16])
        dest_ip = socket.inet_ntoa(data[16:20])
        
        return IPHeader(
            version=version,
            ihl=ihl,
            tos=tos,
            total_length=total_length,
            identification=identification,
            flags=flags,
            fragment_offset=fragment_offset,
            ttl=ttl,
            protocol=protocol,
            header_checksum=header_checksum,
            source_ip=source_ip,
            dest_ip=dest_ip
        )

    def parse_tcp_header(self, data: bytes) -> TCPHeader:
        """TCP başlığını parse eder."""
        # TCP başlık yapısı
        # 0                   1                   2                   3
        # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |          Source Port          |       Destination Port        |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                        Sequence Number                        |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |                    Acknowledgment Number                      |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |  Data |           |U|A|P|R|S|F|                               |
        # | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
        # |       |           |G|K|H|T|N|N|                               |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        # |           Checksum            |         Urgent Pointer        |
        # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        
        source_port = struct.unpack('!H', data[0:2])[0]
        dest_port = struct.unpack('!H', data[2:4])[0]
        sequence = struct.unpack('!I', data[4:8])[0]
        ack_number = struct.unpack('!I', data[8:12])[0]
        
        data_offset_flags = struct.unpack('!H', data[12:14])[0]
        data_offset = (data_offset_flags >> 12) & 0xF
        flags = data_offset_flags & 0x1FF
        
        window = struct.unpack('!H', data[14:16])[0]
        checksum = struct.unpack('!H', data[16:18])[0]
        urgent_pointer = struct.unpack('!H', data[18:20])[0]
        
        return TCPHeader(
            source_port=source_port,
            dest_port=dest_port,
            sequence=sequence,
            ack_number=ack_number,
            data_offset=data_offset,
            flags=flags,
            window=window,
            checksum=checksum,
            urgent_pointer=urgent_pointer
        )

    def analyze_packet(self, packet: bytes) -> Dict:
        """Paketi analiz eder ve detaylı bilgi döndürür."""
        try:
            # Ethernet başlığını atla (14 byte)
            ip_data = packet[14:]
            ip_header = self.parse_ip_header(ip_data)
            
            # TCP başlığını parse et
            tcp_data = ip_data[ip_header.ihl * 4:]
            tcp_header = self.parse_tcp_header(tcp_data)
            
            # Paket içeriğini al
            payload = tcp_data[tcp_header.data_offset * 4:]
            
            return {
                'timestamp': datetime.now(),
                'ip_header': ip_header,
                'tcp_header': tcp_header,
                'payload': payload,
                'payload_hex': binascii.hexlify(payload).decode(),
                'payload_size': len(payload)
            }
            
        except Exception as e:
            print(f"[!] Paket analiz hatası: {e}")
            return None

    def capture_packets(self, count: int = 10):
        """Belirtilen sayıda paket yakalar ve analiz eder."""
        if not self.socket:
            if not self.start_capture():
                return
        
        print(f"[*] {count} paket yakalanıyor...")
        
        while self.packet_count < count:
            try:
                packet = self.socket.recvfrom(65535)[0]
                self.packet_count += 1
                
                # Paketi analiz et
                analysis = self.analyze_packet(packet)
                if analysis:
                    self.packet_history.append((analysis['timestamp'], packet))
                    
                    # Paket detaylarını yazdır
                    print(f"\nPaket #{self.packet_count}")
                    print(f"Kaynak: {analysis['ip_header'].source_ip}:{analysis['tcp_header'].source_port}")
                    print(f"Hedef: {analysis['ip_header'].dest_ip}:{analysis['tcp_header'].dest_port}")
                    print(f"Protokol: {analysis['ip_header'].protocol}")
                    print(f"Bayrak: {analysis['tcp_header'].flags}")
                    print(f"Veri Boyutu: {analysis['payload_size']} byte")
                    
            except KeyboardInterrupt:
                print("\n[!] Paket yakalama kullanıcı tarafından durduruldu")
                break
            except Exception as e:
                print(f"[!] Paket yakalama hatası: {e}")
                continue
        
        self.stop_capture()

    def save_capture(self, filename: str):
        """Yakalanan paketleri dosyaya kaydeder."""
        try:
            with open(filename, 'wb') as f:
                for timestamp, packet in self.packet_history:
                    # Timestamp ve paket boyutunu yaz
                    f.write(struct.pack('!dI', timestamp.timestamp(), len(packet)))
                    # Paketi yaz
                    f.write(packet)
            print(f"[+] Yakalanan paketler {filename} dosyasına kaydedildi")
        except Exception as e:
            print(f"[!] Paket kaydetme hatası: {e}")

def main():
    analyzer = PacketAnalyzer()
    
    # Test paketlerini yakala
    analyzer.capture_packets(count=5)
    
    # Yakalanan paketleri kaydet
    analyzer.save_capture('capture.pcap')

if __name__ == "__main__":
    main() 