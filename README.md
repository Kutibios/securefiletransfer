# Güvenli Dosya Transferi Projesi

Bu proje, güvenli dosya transferi için geliştirilmiş bir Python uygulamasıdır. Kriptografik güvenlik önlemleri ve ağ performans analizi özellikleri içerir.

## Özellikler

- Güvenli dosya transferi
- Kriptografik şifreleme
- Ağ performans analizi
- Paket analizi
- MITM (Man-in-the-Middle) simülasyonu
- GUI arayüzü

## Gereksinimler

- Python 3.x
- Gerekli Python paketleri:
  - cryptography
  - scapy
  - tkinter
  - numpy
  - matplotlib

## Kurulum

1. Projeyi klonlayın:
```bash
git clone https://github.com/Kutibios/securefiletransfer.git
```

2. Gerekli paketleri yükleyin:
```bash
pip install -r requirements.txt
```

## Kullanım

1. Sunucuyu başlatın:
```bash
python server.py
```

2. İstemciyi başlatın:
```bash
python client.py
```

3. GUI arayüzünü başlatın:
```bash
python gui.py
```

## Proje Yapısı

- `server.py`: Sunucu uygulaması
- `client.py`: İstemci uygulaması
- `gui.py`: Grafiksel kullanıcı arayüzü
- `crypto_utils.py`: Kriptografik işlemler için yardımcı fonksiyonlar
- `raw_transfer_utils.py`: Ham veri transferi için yardımcı fonksiyonlar
- `network_performance.py`: Ağ performans analizi
- `packet_analyzer.py`: Paket analizi
- `mitm_simulator.py`: MITM saldırı simülasyonu
- `security_tests.py`: Güvenlik testleri

## Güvenlik

Proje, dosya transferlerini güvenli hale getirmek için çeşitli kriptografik önlemler içerir:
- Asimetrik şifreleme
- Simetrik şifreleme
- Hash fonksiyonları
- Dijital imzalar

## Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakın.
