import socket
import struct
import os
import logging
from crypto_utils import generate_key, encrypt_data, get_file_hash

# Logging yapılandırması
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler("server.log"),
                        logging.StreamHandler()
                    ])

SHARED_KEY = b"BuBirGizliAnahtar!"

def dosya_kontrol(filepath):
    if not os.path.exists(filepath):
        logging.error(f"Dosya bulunamadı: {filepath}")
        return False
    if not os.path.isfile(filepath):
        logging.error(f"Geçersiz dosya yolu: {filepath}")
        return False
    return True

def main():
    HOST = '0.0.0.0'
    PORT = 5001
    FILE_TO_SEND = "files/to_send/testfile.txt"

    if not dosya_kontrol(FILE_TO_SEND):
        logging.error("Gönderilecek dosya mevcut değil veya geçersiz. Sunucu başlatılamıyor.")
        return

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    logging.info(f"Sunucu {HOST}:{PORT} üzerinde dinliyor...")

    while True:
        client_socket, client_address = server_socket.accept()
        logging.info(f"Gelen bağlantı: {client_address}")
        
        try:
            # Kimlik doğrulama adımı
            auth_msg = client_socket.recv(1024)
            if auth_msg == SHARED_KEY:
                client_socket.sendall(b"AUTH_SUCCESS")
                logging.info(f"İstemci {client_address} kimlik doğrulamasını başarıyla geçti.")

                # Anahtar oluştur ve istemciye gönder
                key = generate_key()
                client_socket.sendall(key)
                logging.info("Şifreleme anahtarı istemciye gönderildi.")

                # Dosyayı oku, şifrele ve gönder
                with open(FILE_TO_SEND, 'rb') as f:
                    file_data = f.read()
                encrypted_data = encrypt_data(file_data, key)
                file_hash = get_file_hash(file_data)

                # Dosya boyutunu gönder
                client_socket.sendall(struct.pack('!I', len(encrypted_data)))
                logging.info(f"Şifreli veri boyutu ({len(encrypted_data)} byte) istemciye gönderildi.")
                
                # Şifreli veriyi ve hash'i gönder
                client_socket.sendall(encrypted_data)
                logging.info("Şifreli veri istemciye gönderildi.")
                client_socket.sendall(file_hash)
                logging.info("Dosya hash'i istemciye gönderildi.")
                
                logging.info(f"Dosya {FILE_TO_SEND} istemciye başarıyla gönderildi.")

            else:
                client_socket.sendall(b"AUTH_FAILED")
                logging.warning(f"İstemci {client_address} kimlik doğrulamasını geçemedi. Bağlantı kapatılıyor.")

        except ConnectionResetError:
            logging.warning(f"İstemci {client_address} bağlantıyı kesti.")
        except Exception as e:
            logging.error(f"İstemci {client_address} ile iletişimde hata: {e}")
        finally:
            client_socket.close()
            logging.info(f"İstemci bağlantısı {client_address} kapatıldı.")

if __name__ == '__main__':
    main()
