import socket
import struct
import os
import logging
import time
from tqdm import tqdm
from crypto_utils import decrypt_data, get_file_hash
from typing import Callable, Optional

# Loglama ayarları
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('client.log'),
        logging.StreamHandler()
    ]
)

SHARED_KEY = b"BuBirGizliAnahtar!"

class FileTransferClient:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.socket = None

    def connect(self):
        """Connect to the server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        logging.info(f"Connected to server at {self.host}:{self.port}")

    def send_file(self, file_path: str, progress_callback: Optional[Callable[[int], None]] = None):
        """Send a file to the server"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        if not os.path.isfile(file_path):
            raise IsADirectoryError(f"Not a file: {file_path}")

        try:
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)
            
            logging.info(f"Sending file: {file_name} ({file_size} bytes)")

            # Send file info
            header = struct.pack('!Q', file_size)
            self.socket.sendall(header)
            self.socket.sendall(file_name.encode())

            # Send file data
            sent_size = 0
            with open(file_path, 'rb') as f:
                while sent_size < file_size:
                    data = f.read(4096)
                    if not data:
                        break
                    self.socket.sendall(data)
                    sent_size += len(data)
                    if progress_callback:
                        progress = int((sent_size / file_size) * 100)
                        progress_callback(progress)

            if sent_size == file_size:
                logging.info(f"File sent successfully: {file_path}")
            else:
                raise ConnectionError(f"Incomplete file transfer. Sent {sent_size} of {file_size} bytes")

        except Exception as e:
            logging.error(f"Error sending file: {e}")
            raise
        finally:
            self.close()

    def close(self):
        """Close the connection"""
        if self.socket:
            self.socket.close()
            self.socket = None
            logging.info("Connection closed")

def veri_al(sock, boyut, timeout=None):
    sock.settimeout(timeout)
    alinan_veri = b''
    try:
        while len(alinan_veri) < boyut:
            kalan_boyut = boyut - len(alinan_veri)
            veri = sock.recv(min(4096, kalan_boyut))
            if not veri:
                logging.warning("Sunucudan veri alınamadı, bağlantı kapanmış olabilir.")
                break
            alinan_veri += veri
    except socket.timeout:
        logging.warning("Veri alımı zaman aşımına uğradı.")
    except Exception as e:
        logging.error(f"Veri alımı sırasında hata oluştu: {e}")
    finally:
        sock.settimeout(None) # Zaman aşımını sıfırla
    return alinan_veri

def dosya_kaydet(filepath, data):
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, 'wb') as f:
            f.write(data)
        logging.info(f"Dosya kaydedildi: {filepath}")
    except Exception as e:
        logging.error(f"Dosya kaydedilirken hata oluştu: {e}")

def main():
    HOST = '127.0.0.1'
    PORT = 5001
    RECEIVED_FILE_PATH = "files/received/received_testfile.txt"

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((HOST, PORT))
        logging.info(f"Sunucuya bağlanıldı: {HOST}:{PORT}")

        # Kimlik doğrulama adımı
        client_socket.sendall(SHARED_KEY)
        auth_response = client_socket.recv(1024)
        if auth_response == b"AUTH_SUCCESS":
            logging.info("Kimlik doğrulama başarılı.")

            # Şifreleme anahtarını al
            key = veri_al(client_socket, 32, timeout=5) # 32 byte anahtar
            if not key or len(key) != 32:
                logging.error("Geçersiz veya eksik şifreleme anahtarı alındı.")
                return
            logging.info("Şifreleme anahtarı alındı.")

            # Şifreli veri boyutunu al
            encrypted_size_bytes = veri_al(client_socket, struct.calcsize('!I'), timeout=5)
            if not encrypted_size_bytes or len(encrypted_size_bytes) != struct.calcsize('!I'):
                logging.error("Şifreli veri boyutu alınamadı veya geçersiz.")
                return
            encrypted_size = struct.unpack('!I', encrypted_size_bytes)[0]
            logging.info(f"Alınacak şifreli veri boyutu: {encrypted_size} byte")

            # Şifreli veriyi al
            encrypted_data = b''
            with tqdm(total=encrypted_size, unit='B', unit_scale=True, desc="Veri Alınıyor") as pbar:
                while len(encrypted_data) < encrypted_size:
                    chunk = veri_al(client_socket, min(4096, encrypted_size - len(encrypted_data)), timeout=10)
                    if not chunk:
                        logging.error("Şifreli veri alımı eksik veya bağlantı koptu.")
                        break
                    encrypted_data += chunk
                    pbar.update(len(chunk))
            
            if len(encrypted_data) != encrypted_size:
                logging.error("Şifreli veri beklenenden küçük alındı.")
                return
            logging.info("Şifreli veri başarıyla alındı.")

            # Hash değerini al
            received_hash = veri_al(client_socket, 64, timeout=5) # SHA-256 hash 64 byte
            if not received_hash or len(received_hash) != 64:
                logging.error("Hash değeri alınamadı veya geçersiz.")
                return
            logging.info("Hash değeri alındı.")

            # Veriyi deşifre et ve hash kontrolü yap
            decrypted_data = decrypt_data(encrypted_data, key)
            calculated_hash = get_file_hash(decrypted_data)

            if calculated_hash == received_hash:
                logging.info("Hash kontrolü başarılı: Dosya bütünlüğü sağlandı.")
                dosya_kaydet(RECEIVED_FILE_PATH, decrypted_data)
                logging.info("Dosya transferi başarıyla tamamlandı!")
            else:
                logging.error("Hash kontrolü başarısız: Dosya bütünlüğü bozulmuş olabilir.")

        elif auth_response == b"AUTH_FAILED":
            logging.error("Kimlik doğrulama başarısız. Sunucu bağlantıyı reddetti.")
        else:
            logging.error(f"Sunucudan beklenmeyen kimlik doğrulama yanıtı alındı: {auth_response.decode()}")

    except ConnectionRefusedError:
        logging.error(f"Bağlantı reddedildi: {HOST}:{PORT} adresinde sunucu çalışmıyor olabilir.")
    except Exception as e:
        logging.error(f"Bir hata oluştu: {e}")
    finally:
        client_socket.close()
        logging.info("İstemci bağlantısı kapatıldı.")

if __name__ == '__main__':
    main()
