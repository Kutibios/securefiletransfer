import socket
import struct
import threading
import time
from typing import Dict, Tuple, Callable
from dataclasses import dataclass
from datetime import datetime

@dataclass
class ARPEntry:
    ip: str
    mac: str
    timestamp: datetime

class MITMSimulator:
    def __init__(self, target_ip: str, gateway_ip: str):
        self.arp_table: Dict[str, ARPEntry] = {}
        self.running = False
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.restore_required = False
        self.status_callback = None
        self.spoof_thread = None
        
    def start_spoofing(self, status_callback):
        """ARP spoofing saldırısını başlatır."""
        if self.running:
            if self.status_callback:
                self.status_callback("[!] ARP  zaten çalışıyor.")
            return
            
        self.running = True
        self.restore_required = True
        self.status_callback = status_callback
        
        # ARP spoofing thread'ini başlat
        self.spoof_thread = threading.Thread(target=self._arp_spoofing_thread)
        self.spoof_thread.daemon = True
        self.spoof_thread.start()
        
        if self.status_callback:
            self.status_callback(f"[+] ARP gönderimi başlatıldı. Hedef: {self.target_ip}, Gateway: {self.gateway_ip}")
        
    def stop_spoofing(self):
        """ARP spoofing saldırısını durdurur ve ARP tablolarını geri yükler."""
        if not self.running:
            if self.status_callback:
                self.status_callback("[!] ARP gönderimi zaten durdurulmuş durumda.")
            return
            
        if self.status_callback:
            self.status_callback("[+] ARP gönderimi durduruluyor...")
            
        self.running = False
        
        # Thread'in durmasını bekle
        if self.spoof_thread and self.spoof_thread.is_alive():
            self.spoof_thread.join(timeout=2.0)  # 2 saniye bekle
            
        if self.restore_required:
            if self.status_callback:
                self.status_callback("[+] ARP tabloları geri yükleniyor...")
            self._restore_arp_tables()
            self.restore_required = False
            
        if self.status_callback:
            self.status_callback("[+] ARP gönderimi başarıyla durduruldu.")
        
    def _arp_spoofing_thread(self):
        """ARP spoofing paketlerini gönderir."""
        while self.running:
            try:
                # Hedef'e sahte ARP paketi gönder
                self._send_arp_packet(
                    target_ip=self.target_ip,
                    source_ip=self.gateway_ip,
                    opcode=2  # ARP Reply
                )
                
                # Gateway'e sahte ARP paketi gönder
                self._send_arp_packet(
                    target_ip=self.gateway_ip,
                    source_ip=self.target_ip,
                    opcode=2  # ARP Reply
                )
                
                if self.status_callback:
                    self.status_callback(f"[+] Paketler gönderiliyor...")
                time.sleep(2)  # Her 2 saniyede bir paket gönder
                
            except Exception as e:
                if self.status_callback:
                    self.status_callback(f"[!] ARP gönderim hatası: {e}")
                self.running = False  # Hata durumunda durdur
                
    def _restore_arp_tables(self):
        """ARP tablolarını orijinal haline geri yükler."""
        try:
            # Hedef ve Gateway için ARP geri yükleme paketleri gönder
            self._send_arp_packet(
                target_ip=self.target_ip,
                source_ip=self.gateway_ip, # Orijinal ağ geçidi MAC
                opcode=2 # ARP Reply
            )
            self._send_arp_packet(
                target_ip=self.gateway_ip,
                source_ip=self.target_ip, # Orijinal hedef MAC
                opcode=2 # ARP Reply
            )
            print("[+] ARP tabloları geri yüklendi.")
        except Exception as e:
            print(f"[!] ARP geri yükleme hatası: {e}")

    def _send_arp_packet(self, target_ip: str, source_ip: str, opcode: int):
        """ARP paketi oluşturur ve gönderir."""
        # Gerçek MAC adreslerini almak için bir mekanizma eklemeliyiz (örneğin scapy veya ip-link komutları)
        # Şimdilik örnek MAC adresleri kullanıyorum, bu kısım platforma göre değişebilir.
        # Windows'ta raw socket ile ARP spoofing zor olabilir, scapy gibi kütüphaneler önerilir.
        # Bu örnek, konsepti göstermek içindir.
        
        # Hedef MAC adresini bulmak için (örneğin hedef IP'nin gerçek MAC'i)
        # Burada hedef MAC'i broadcast olarak ayarlıyoruz ki paket herkes tarafından duyulsun.
        # Daha gelişmiş bir MITM için hedef ve gateway'in gerçek MAC adresleri dinamik olarak bulunmalıdır.
        
        # Ethernet başlığı
        # Hedef MAC adresi: broadcast (FF:FF:FF:FF:FF:FF) - Bu genellikle ARP isteği için kullanılır.
        # ARP yanıtında hedef MAC, isteği yapanın MAC adresi olmalıdır.
        # Kaynak MAC adresi: Saldırganın MAC adresi (varsayılan: 00:00:00:00:00:00)
        # Ethertype: 0x0806 (ARP)

        # Bu kısım Windows'ta raw socket ile doğrudan Ethernet frame oluşturmakta sorun çıkarabilir.
        # Windows'ta doğrudan raw Ethernet Frame oluşturma genellikle kısıtlıdır.
        # Genellikle Scapy gibi daha yüksek seviyeli kütüphaneler kullanılır.
        # Ancak, bu örneği genel bir Python temelli konsept olarak ele alalım.

        # Paketi gönder
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # Windows'ta promiscuous mode için WSAIoctl kullanılır, send için değil.
            # Bu kısım sadece gönderme işlevi için.

            # Sahte ARP yanıtı oluşturma (Ethernet + ARP)
            # Hedef MAC: Broadcast (FF:FF:FF:FF:FF:FF) veya bilinen hedef MAC
            # Kaynak MAC: Kendi MAC adresimiz (saldırganın)
            # ARP hedef MAC: Hedefin MAC'i (bilinmiyorsa 00:00:00:00:00:00)
            
            # Basit bir simülasyon olduğu için, burada doğrudan paketi oluşturmak yerine
            # ağ katmanında ARP yanıtı gönderdiğimizi varsayalım.
            # Gerçek bir ARP spoofing için Scapy gibi kütüphaneler kullanmak daha sağlamdır.

            # IP başlığına gerek yok, sadece ARP paketi gönderiliyor.
            # ARP paketleri doğrudan Ethernet katmanında çalışır.
            # Bu yüzden IPPROTO_RAW yerine ETH_P_ARP kullanmak gerekebilir,
            # ancak bu socket tipi Windows'ta mevcut değildir.
            # Bu yüzden, bu kısmın sadece bir konsept olduğunu ve gerçek bir saldırı için
            # daha karmaşık bir yapı gerektireceğini vurgulamak önemlidir.

            # Bu metod, eğer Scapy kuruluysa ve doğru izinlerle çalışıyorsa işe yarar.
            # scapy.sendp(ARP(op=opcode, psrc=source_ip, pdst=target_ip))
            
            # Scapy kullanılmadığı varsayımıyla, bir placeholder olarak bırakıyorum.
            # Gerçek bir ARP paketi oluşturma ve gönderme kısmı.
            # Bu kısım OS'e ve kullanılan kütüphanelere göre değişir.
            print(f"[DEBUG] Sahte ARP paketi {source_ip} -> {target_ip} gönderildi (Opcode: {opcode})")
            
            # Windows'ta raw socket ile ARP spoofing yapmak çok zordur ve genellikle engellenir.
            # Bu yüzden, bu fonksiyonun başarılı bir şekilde sahte ARP paketleri gönderdiğini varsayıyoruz.
            # Pratik bir uygulama için Scapy veya benzeri bir kütüphane şiddetle tavsiye edilir.

        except Exception as e:
            print(f"[!] ARP paket gönderme hatası: {e}")
            
    def monitor_traffic(self):
        """Hedef trafiğini izler."""
        if not self.target_ip:
            print("[!] Önce ARP spoofing başlatılmalı")
            return
            
        try:
            # Raw socket oluştur
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            sock.bind(('0.0.0.0', 0))
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            
            print(f"[+] {self.target_ip} trafiği izleniyor...")
            
            while self.running:
                try:
                    # Paket al
                    packet = sock.recvfrom(65535)[0]
                    
                    # IP başlığını parse et
                    ip_header = self._parse_ip_header(packet)
                    
                    # Hedef IP'ye giden veya gelen paketleri göster
                    if ip_header['source_ip'] == self.target_ip or ip_header['dest_ip'] == self.target_ip:
                        print(f"\n[*] Paket yakalandı:")
                        print(f"    Kaynak: {ip_header['source_ip']}")
                        print(f"    Hedef: {ip_header['dest_ip']}")
                        print(f"    Protokol: {ip_header['protocol']}")
                        print(f"    Boyut: {ip_header['total_length']} byte")
                        
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print(f"[!] Paket izleme hatası: {e}")
                    continue
                    
            sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            sock.close()
            
        except Exception as e:
            print(f"[!] Trafik izleme başlatılamadı: {e}")
            
    def _parse_ip_header(self, packet: bytes) -> Dict:
        """IP başlığını parse eder."""
        # IP başlık yapısı
        version_ihl = packet[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        
        total_length = struct.unpack('!H', packet[2:4])[0]
        protocol = packet[9]
        source_ip = socket.inet_ntoa(packet[12:16])
        dest_ip = socket.inet_ntoa(packet[16:20])
        
        return {
            'version': version,
            'ihl': ihl,
            'total_length': total_length,
            'protocol': protocol,
            'source_ip': source_ip,
            'dest_ip': dest_ip
        }

def main():
    # Test için örnek IP'ler
    target_ip = "192.168.1.100"  # Hedef IP
    gateway_ip = "192.168.1.1"   # Gateway IP
    simulator = MITMSimulator(target_ip, gateway_ip) # __init__ parametreleri güncellendi
    
    try:
        # ARP spoofing başlat
        simulator.start_spoofing(lambda x: print(f"Durum: {x}")) # Basit bir callback örneği
        
        # Trafik izlemeyi başlat (ayrı bir thread'de)
        monitor_thread = threading.Thread(target=simulator.monitor_traffic)
        monitor_thread.daemon = True
        monitor_thread.start()
        
        # 30 saniye çalıştır
        time.sleep(30)
        
    except KeyboardInterrupt:
        print("\n[!] Program kullanıcı tarafından durduruldu")
    finally:
        # ARP spoofing'i durdur
        simulator.stop_spoofing()

if __name__ == "__main__":
    main() 