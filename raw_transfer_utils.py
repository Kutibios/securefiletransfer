import socket
import struct
import os
import time
from collections import defaultdict

MTU = 1400  # Maksimum fragment boyutu (IP header hariç)

# Basit IP header oluşturucu
def create_ip_header(source_ip, dest_ip, total_length, identification, flags, fragment_offset, ttl=64, proto=socket.IPPROTO_UDP):
    version_ihl = (4 << 4) + 5
    tos = 0
    checksum = 0
    src_addr = socket.inet_aton(source_ip)
    dst_addr = socket.inet_aton(dest_ip)
    ip_header = struct.pack('!BBHHHBBH4s4s',
        version_ihl, tos, total_length, identification,
        (flags << 13) + fragment_offset, ttl, proto, checksum, src_addr, dst_addr)
    # Checksum hesapla
    checksum = calc_checksum(ip_header)
    ip_header = struct.pack('!BBHHHBBH4s4s',
        version_ihl, tos, total_length, identification,
        (flags << 13) + fragment_offset, ttl, proto, checksum, src_addr, dst_addr)
    return ip_header

def calc_checksum(header):
    if len(header) % 2:
        header += b'\0'
    res = sum(struct.unpack('!%dH' % (len(header) // 2), header))
    while res > 0xffff:
        res = (res & 0xffff) + (res >> 16)
    return ~res & 0xffff

class RawFileSender:
    def __init__(self, source_ip, dest_ip, dest_port):
        self.source_ip = source_ip
        self.dest_ip = dest_ip
        self.dest_port = dest_port
        self.sock = None

    def send_file_fragmented(self, file_path):
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Dosya bulunamadı: {file_path}")

        with open(file_path, 'rb') as f:
            data = f.read()
        
        fragments = [data[i:i+MTU] for i in range(0, len(data), MTU)]
        identification = int(time.time()) & 0xFFFF  # Her transfer için benzersiz ID
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        print(f"Toplam {len(fragments)} fragment gönderilecek.")

        for i, fragment in enumerate(fragments):
            flags = 1 if i < len(fragments) - 1 else 0  # Son fragment değilse MF=1
            offset = (i * MTU) // 8
            udp_header = struct.pack('!HHHH', 12345, self.dest_port, 8 + len(fragment), 0)
            total_length = 20 + 8 + len(fragment)
            ip_header = create_ip_header(self.source_ip, self.dest_ip, total_length, identification, flags, offset)
            packet = ip_header + udp_header + fragment
            self.sock.sendto(packet, (self.dest_ip, 0))
            print(f"Fragment {i+1}/{len(fragments)} gönderildi.")
            time.sleep(0.01) # Çok hızlı göndermemek için
        self.sock.close()
        print("Tüm fragmentlar gönderildi.")

class RawFileReceiver:
    def __init__(self, listen_ip, listen_port, output_path):
        self.listen_ip = listen_ip
        self.listen_port = listen_port
        self.output_path = output_path
        self.sock = None
        self.buffer = FragmentBuffer()

    def start_receiving(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        self.sock.bind((self.listen_ip, 0))
        # Windows'ta promiscuous mode gerekebilir, ancak raw socket'e bind ile dinlemek yeterli olabilir.
        # self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON) # Yönetici yetkisi gerektirir
        print("Fragmentlar bekleniyor...")
        start_time = time.time()
        while True:
            if time.time() - start_time > 60: # 60 saniye zaman aşımı
                print("Zaman aşımı. Alım tamamlandı (tamamlanmamış olabilir).")
                break
            try:
                packet, addr = self.sock.recvfrom(65535)
                
                # IP header'ı parse et
                ip_header_len = (packet[0] & 0xF) * 4
                ip_header = packet[:ip_header_len]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                
                identification = iph[3]
                flags = (iph[4] >> 13) & 0x7
                mf = (flags & 0x1)
                offset = iph[4] & 0x1FFF

                # UDP header'ı ve datayı al
                udp_header_start = ip_header_len
                udp_header_end = udp_header_start + 8
                udp_header = packet[udp_header_start:udp_header_end]
                udp = struct.unpack('!HHHH', udp_header)
                
                # Hedef portu kontrol et
                if udp[1] != self.listen_port:
                    continue # Bu port için değilse atla

                data = packet[udp_header_end:]
                
                self.buffer.add_fragment(identification, offset, mf, data)
                print(f"Fragment offset={offset}, mf={mf}, len={len(data)} alındı.")

                if self.buffer.is_complete(identification):
                    print("Tüm fragmentlar alındı, dosya birleştiriliyor...")
                    file_data = self.buffer.reassemble(identification)
                    os.makedirs(os.path.dirname(self.output_path), exist_ok=True)
                    with open(self.output_path, 'wb') as f:
                        f.write(file_data)
                    print(f"Dosya kaydedildi: {self.output_path}")
                    del self.buffer.fragments[identification] # Birleşen parçaları sil
                    del self.buffer.lengths[identification]
                    break # Tek dosya için

            except socket.timeout:
                print("Alım zaman aşımı.")
                break
            except Exception as e:
                print(f"Alıcı hatası: {e}")
                break
        self.sock.close()
        print("Alıcı kapatıldı.")

class FragmentBuffer:
    def __init__(self):
        self.fragments = defaultdict(dict)  # {identification: {offset: data}}
        self.lengths = {}

    def add_fragment(self, identification, offset, mf, data):
        self.fragments[identification][offset] = data
        if mf == 0:
            self.lengths[identification] = offset * 8 + len(data) + 28 # IP(20) + UDP(8)

    def is_complete(self, identification):
        if identification not in self.lengths:
            return False
        
        expected_total_len = self.lengths[identification]
        current_received_len = sum(len(d) for d in self.fragments[identification].values())
        # Fragment offsetleri 8'e bölünmüş halde olduğu için, toplam boyutu hesaplarken bunu dikkate almalıyız.
        # Buradaki kontrol daha karmaşık olabilir, şimdilik toplam data uzunluğuna bakıyoruz.
        
        # En basit kontrol: Son fragment alındıysa ve tüm offsetler varsa.
        if expected_total_len == 0: # Henüz MF=0 paketi gelmediyse veya sıfır uzunlukta ise
            return False

        # Tüm beklenen offsetler gelmiş mi kontrolü (basit versiyon)
        # Gelen en büyük offset, toplam uzunluğu hesaplamaya yardımcı olur.
        max_offset_received = max(self.fragments[identification].keys())
        # Tüm parçalar geldiyse, son parçanın bitişi toplam uzunluğa eşit olmalı
        # Bu kontrol daha sağlam hale getirilebilir.
        return (max_offset_received * 8 + len(self.fragments[identification][max_offset_received])) >= (expected_total_len - 28) # -28 IP+UDP header

    def reassemble(self, identification):
        offsets = sorted(self.fragments[identification].keys())
        reassembled_data = b''
        for o in offsets:
            reassembled_data += self.fragments[identification][o]
        return reassembled_data 