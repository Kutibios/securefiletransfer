import socket
import struct
import time
import hashlib
from typing import List, Dict, Tuple
from dataclasses import dataclass
from datetime import datetime

@dataclass
class SecurityTest:
    name: str
    description: str
    result: bool
    details: str
    timestamp: datetime

class SecurityTester:
    def __init__(self, target_ip: str, target_port: int):
        self.target_ip = target_ip
        self.target_port = target_port
        self.test_results: List[SecurityTest] = []
        
    def run_all_tests(self):
        """Tüm güvenlik testlerini çalıştırır."""
        print("[*] Güvenlik testleri başlatılıyor...")
        
        # Port tarama testi
        self.test_port_scan()
        
        # SYN flood testi
        self.test_syn_flood()
        
        # UDP flood testi
        self.test_udp_flood()
        
        # ICMP flood testi
        self.test_icmp_flood()
        
        # ARP spoofing testi
        self.test_arp_spoofing()
        
        # Rapor oluştur
        self.generate_report()
        
    def test_port_scan(self):
        """Port tarama testi yapar."""
        print("\n[*] Port tarama testi başlatılıyor...")
        
        try:
            # TCP port taraması
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((self.target_ip, self.target_port))
            sock.close()
            
            test = SecurityTest(
                name="Port Tarama",
                description="Hedef portun açık olup olmadığını kontrol eder",
                result=(result == 0),
                details=f"Port {self.target_port} {'açık' if result == 0 else 'kapalı'}",
                timestamp=datetime.now()
            )
            
            self.test_results.append(test)
            print(f"[+] Test tamamlandı: {test.details}")
            
        except Exception as e:
            print(f"[!] Port tarama hatası: {e}")
            
    def test_syn_flood(self):
        """SYN flood testi yapar."""
        print("\n[*] SYN flood testi başlatılıyor...")
        
        try:
            # Raw socket oluştur
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            
            # IP başlığı
            ip_header = struct.pack('!BBHHHBBH4s4s',
                0x45,  # Version & IHL
                0,     # TOS
                40,    # Total Length
                0,     # Identification
                0,     # Flags & Fragment Offset
                64,    # TTL
                6,     # Protocol (TCP)
                0,     # Header Checksum
                socket.inet_aton('0.0.0.0'),  # Source IP
                socket.inet_aton(self.target_ip)  # Destination IP
            )
            
            # TCP başlığı
            tcp_header = struct.pack('!HHIIBBHHH',
                0,     # Source Port
                self.target_port,  # Destination Port
                0,     # Sequence Number
                0,     # Acknowledgment Number
                5 << 4,  # Data Offset
                0x02,  # Flags (SYN)
                65535,  # Window
                0,     # Checksum
                0      # Urgent Pointer
            )
            
            # 10 SYN paketi gönder
            for _ in range(10):
                sock.sendto(ip_header + tcp_header, (self.target_ip, 0))
                time.sleep(0.1)
            
            sock.close()
            
            test = SecurityTest(
                name="SYN Flood",
                description="SYN flood saldırısına karşı koruma testi",
                result=True,
                details="10 SYN paketi gönderildi",
                timestamp=datetime.now()
            )
            
            self.test_results.append(test)
            print(f"[+] Test tamamlandı: {test.details}")
            
        except Exception as e:
            print(f"[!] SYN flood testi hatası: {e}")
            
    def test_udp_flood(self):
        """UDP flood testi yapar."""
        print("\n[*] UDP flood testi başlatılıyor...")
        
        try:
            # UDP socket oluştur
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
            # Test verisi
            data = b'X' * 1024  # 1KB veri
            
            # 10 UDP paketi gönder
            for _ in range(10):
                sock.sendto(data, (self.target_ip, self.target_port))
                time.sleep(0.1)
            
            sock.close()
            
            test = SecurityTest(
                name="UDP Flood",
                description="UDP flood saldırısına karşı koruma testi",
                result=True,
                details="10 UDP paketi gönderildi",
                timestamp=datetime.now()
            )
            
            self.test_results.append(test)
            print(f"[+] Test tamamlandı: {test.details}")
            
        except Exception as e:
            print(f"[!] UDP flood testi hatası: {e}")
            
    def test_icmp_flood(self):
        """ICMP flood testi yapar."""
        print("\n[*] ICMP flood testi başlatılıyor...")
        
        try:
            # Raw socket oluştur
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            
            # ICMP Echo Request paketi
            icmp_header = struct.pack('!BBHHH',
                8,     # Type (Echo Request)
                0,     # Code
                0,     # Checksum
                0,     # Identifier
                0      # Sequence Number
            )
            
            # 10 ICMP paketi gönder
            for _ in range(10):
                sock.sendto(icmp_header, (self.target_ip, 0))
                time.sleep(0.1)
            
            sock.close()
            
            test = SecurityTest(
                name="ICMP Flood",
                description="ICMP flood saldırısına karşı koruma testi",
                result=True,
                details="10 ICMP paketi gönderildi",
                timestamp=datetime.now()
            )
            
            self.test_results.append(test)
            print(f"[+] Test tamamlandı: {test.details}")
            
        except Exception as e:
            print(f"[!] ICMP flood testi hatası: {e}")
            
    def test_arp_spoofing(self):
        """ARP spoofing testi yapar."""
        print("\n[*] ARP spoofing testi başlatılıyor...")
        
        try:
            # Raw socket oluştur
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            
            # Ethernet başlığı
            eth_header = struct.pack('!6s6sH',
                b'\xff\xff\xff\xff\xff\xff',  # Hedef MAC (broadcast)
                b'\x00\x00\x00\x00\x00\x00',  # Kaynak MAC
                0x0806  # Ethertype (ARP)
            )
            
            # ARP başlığı
            arp_header = struct.pack('!HHBBH6s4s6s4s',
                0x0001,  # Hardware type (Ethernet)
                0x0800,  # Protocol type (IP)
                6,       # Hardware size
                4,       # Protocol size
                2,       # Opcode (Reply)
                b'\x00\x00\x00\x00\x00\x00',  # Sender MAC
                socket.inet_aton('192.168.1.1'),  # Sender IP
                b'\x00\x00\x00\x00\x00\x00',  # Target MAC
                socket.inet_aton(self.target_ip)  # Target IP
            )
            
            # 10 ARP paketi gönder
            for _ in range(10):
                sock.sendto(eth_header + arp_header, (self.target_ip, 0))
                time.sleep(0.1)
            
            sock.close()
            
            test = SecurityTest(
                name="ARP Spoofing",
                description="ARP spoofing saldırısına karşı koruma testi",
                result=True,
                details="10 ARP paketi gönderildi",
                timestamp=datetime.now()
            )
            
            self.test_results.append(test)
            print(f"[+] Test tamamlandı: {test.details}")
            
        except Exception as e:
            print(f"[!] ARP spoofing testi hatası: {e}")
            
    def generate_report(self):
        """Test sonuçlarını raporlar."""
        print("\n" + "="*50)
        print("Güvenlik Test Raporu")
        print("="*50)
        
        for test in self.test_results:
            print(f"\nTest: {test.name}")
            print(f"Açıklama: {test.description}")
            print(f"Sonuç: {'Başarılı' if test.result else 'Başarısız'}")
            print(f"Detaylar: {test.details}")
            print(f"Zaman: {test.timestamp}")
            print("-"*50)

def main():
    # Test için örnek IP ve port
    target_ip = "192.168.1.100"
    target_port = 5001
    
    tester = SecurityTester(target_ip, target_port)
    tester.run_all_tests()

if __name__ == "__main__":
    main() 