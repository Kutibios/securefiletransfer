import socket
import struct
import time
import ctypes
import binascii
from typing import List, Dict, Tuple, Optional, Any
from dataclasses import dataclass
from datetime import datetime

# Windows specific constants
SIO_RCVALL = ctypes.c_ulong(0x98000001)
RCVALL_ON = 1
RCVALL_OFF = 0

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
    checksum: int
    source_ip: str
    dest_ip: str

@dataclass
class TCPHeader:
    source_port: int
    dest_port: int
    sequence: int
    ack: int
    flags: int
    window: int
    checksum: int
    urgent: int

class PacketAnalyzer:
    def __init__(self):
        self.socket = None
        self.is_capturing = False
        self.packet_count = 0
        self.packet_history: List[Tuple[datetime, bytes]] = []
        self.ws2_32 = ctypes.WinDLL('ws2_32.dll')
        self.WSAIoctl = self.ws2_32.WSAIoctl

    def start_capture(self, interface: Optional[str] = None):
        """Start packet capture on the specified interface"""
        try:
            # Create raw socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            
            # Bind to all interfaces
            self.socket.bind(('0.0.0.0', 0))
            
            # Enable promiscuous mode using WSAIoctl
            self.WSAIoctl(
                self.socket.fileno(),
                SIO_RCVALL,
                ctypes.byref(ctypes.c_ulong(RCVALL_ON)),
                ctypes.sizeof(ctypes.c_ulong(RCVALL_ON)),
                None,
                0,
                None,
                None
            )
            
            self.is_capturing = True
            print("[+] Packet capture started successfully")
        except Exception as e:
            if self.socket:
                self.socket.close()
                self.socket = None
            raise RuntimeError(f"Could not start packet capture: {str(e)}")

    def stop_capture(self):
        """Stop packet capture"""
        if self.socket:
            try:
                # Disable promiscuous mode
                self.WSAIoctl(
                    self.socket.fileno(),
                    SIO_RCVALL,
                    ctypes.byref(ctypes.c_ulong(RCVALL_OFF)),
                    ctypes.sizeof(ctypes.c_ulong(RCVALL_OFF)),
                    None,
                    0,
                    None,
                    None
                )
                print("[+] Promiscuous mode disabled")
            except:
                pass
            self.socket.close()
            self.socket = None
            print("[+] Socket closed")
        self.is_capturing = False

    def parse_ip_header(self, data: bytes) -> IPHeader:
        """Parse IP header from raw packet data"""
        try:
            # Unpack IP header (20 bytes)
            ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
            
            version_ihl = ip_header[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            
            return IPHeader(
                version=version,
                ihl=ihl,
                tos=ip_header[1],
                total_length=ip_header[2],
                identification=ip_header[3],
                flags=ip_header[4] >> 13,
                fragment_offset=ip_header[4] & 0x1FFF,
                ttl=ip_header[5],
                protocol=ip_header[6],
                checksum=ip_header[7],
                source_ip=socket.inet_ntoa(ip_header[8]),
                dest_ip=socket.inet_ntoa(ip_header[9])
            )
        except Exception as e:
            raise ValueError(f"Invalid IP header: {str(e)}")

    def parse_tcp_header(self, data: bytes) -> TCPHeader:
        """Parse TCP header from raw packet data"""
        try:
            # Skip IP header (20 bytes)
            tcp_header = struct.unpack('!HHLLBBHHH', data[20:40])
            
            return TCPHeader(
                source_port=tcp_header[0],
                dest_port=tcp_header[1],
                sequence=tcp_header[2],
                ack=tcp_header[3],
                flags=tcp_header[4],
                window=tcp_header[5],
                checksum=tcp_header[6],
                urgent=tcp_header[7]
            )
        except Exception as e:
            raise ValueError(f"Invalid TCP header: {str(e)}")

    def analyze_packet(self) -> Optional[Dict[str, Any]]:
        """Capture and analyze a single packet"""
        if not self.is_capturing or not self.socket:
            return None

        try:
            # Receive packet
            data, addr = self.socket.recvfrom(65535)
            
            # Parse headers
            ip_header = self.parse_ip_header(data)
            
            # Get protocol name
            protocol = {
                1: 'ICMP',
                6: 'TCP',
                17: 'UDP'
            }.get(ip_header.protocol, f'Unknown({ip_header.protocol})')
            
            # Get packet info
            info = ''
            if ip_header.protocol == 6:  # TCP
                tcp_header = self.parse_tcp_header(data)
                info = f'TCP {tcp_header.source_port} -> {tcp_header.dest_port}'
            elif ip_header.protocol == 17:  # UDP
                udp_header = struct.unpack('!HHHH', data[20:28])
                info = f'UDP {udp_header[0]} -> {udp_header[1]}'
            
            return {
                'timestamp': time.strftime('%H:%M:%S'),
                'source': ip_header.source_ip,
                'destination': ip_header.dest_ip,
                'protocol': protocol,
                'length': len(data),
                'info': info
            }

        except Exception as e:
            print(f"Error analyzing packet: {e}")
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
                analysis = self.analyze_packet()
                if analysis:
                    self.packet_history.append((analysis['timestamp'], packet))
                    
                    # Paket detaylarını yazdır
                    print(f"\nPaket #{self.packet_count}")
                    print(f"Kaynak: {analysis['source']}")
                    print(f"Hedef: {analysis['destination']}")
                    print(f"Protokol: {analysis['protocol']}")
                    print(f"Paket Boyutu: {analysis['length']} byte")
                    print(f"Bilgi: {analysis['info']}")
                    
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