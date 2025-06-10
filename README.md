# Güvenli Dosya Transferi Projesi

Bu proje, güvenli dosya transferi için geliştirilmiş kapsamlı bir Python uygulamasıdır. Kriptografik güvenlik önlemleri, ağ performans analizi ve güvenlik testleri içerir.

## Proje Hakkında

Bu proje, dosya transferlerini güvenli hale getirmek ve ağ performansını analiz etmek için geliştirilmiştir. Temel amacı, dosyaların güvenli bir şekilde transfer edilmesini sağlamak ve bu süreçte oluşabilecek güvenlik açıklarını tespit etmektir.

## Proje Yapısı

```
securefiletransfer/
├── server.py                 # Sunucu uygulaması
├── client.py                 # İstemci uygulaması
├── gui.py                    # Grafiksel kullanıcı arayüzü
├── crypto_utils.py           # Kriptografik işlemler
├── raw_transfer_utils.py     # Ham veri transferi
├── network_performance.py    # Ağ performans analizi
├── packet_analyzer.py        # Paket analizi
├── mitm_simulator.py         # MITM saldırı simülasyonu
├── security_tests.py         # Güvenlik testleri
├── files/                    # Dosya transfer klasörü
│   ├── to_send/             # Gönderilecek dosyalar
│   └── received/            # Alınan dosyalar
├── downloads/               # İndirilen dosyalar
├── .gitignore              
└── README.md               # Proje dokümantasyonu
```

## Özellikler ve Bileşenler

### 1. Güvenli Dosya Transferi
- Sunucu-istemci mimarisi ile güvenli dosya transferi
- Otomatik şifreleme ve doğrulama
- Büyük dosyaların parçalı transferi
- Transfer durumu takibi

### 2. Kriptografik Güvenlik
- RSA asimetrik şifreleme (anahtar değişimi için)
- AES simetrik şifreleme (veri transferi için)
- SHA-256 hash fonksiyonları (bütünlük kontrolü için)
- Dijital imzalar (kimlik doğrulama için)

### 3. Ağ Performans Analizi
- Bant genişliği ölçümü
- Gecikme süresi analizi
- Paket kaybı tespiti
- Performans grafikleri ve raporları

### 4. Paket Analizi
- TCP/IP paketlerinin detaylı analizi
- Protokol bazlı filtreleme
- Paket içerik inceleme
- Ağ trafiği izleme

### 5. MITM Simülasyonu
- Man-in-the-Middle saldırı simülasyonu
- Güvenlik açığı tespiti
- Saldırı senaryoları
- Koruma önlemleri testi

### 6. GUI Arayüzü
- Kullanıcı dostu arayüz
- Gerçek zamanlı transfer durumu
- Performans grafikleri
- Güvenlik durumu göstergeleri

## Detaylı Bileşen Açıklamaları

### server.py
Sunucu uygulaması, gelen bağlantıları kabul eder ve dosya transferlerini yönetir. Özellikler:
- Çoklu istemci desteği
- Otomatik port yönetimi
- Güvenlik protokolleri uygulaması
- Hata yönetimi ve loglama

### client.py
İstemci uygulaması, sunucuya bağlanır ve dosya transferlerini gerçekleştirir. Özellikler:
- Otomatik sunucu keşfi
- Dosya seçimi ve transfer
- İlerleme takibi
- Hata kurtarma

### gui.py
Grafiksel kullanıcı arayüzü, tüm işlemleri görsel olarak yönetir. Özellikler:
- Dosya seçim arayüzü
- Transfer durumu göstergeleri
- Performans grafikleri
- Güvenlik durumu paneli

### crypto_utils.py
Kriptografik işlemler için yardımcı fonksiyonlar içerir:
- Anahtar üretimi
- Şifreleme/şifre çözme
- Hash hesaplama
- İmza oluşturma/doğrulama

### raw_transfer_utils.py
Ham veri transferi için temel fonksiyonlar:
- Veri paketleme
- Paket sıralama
- Hata düzeltme
- Akış kontrolü

### network_performance.py
Ağ performans analizi araçları:
- Bant genişliği ölçümü
- Gecikme analizi
- Performans raporlama
- Optimizasyon önerileri

### packet_analyzer.py
Paket analiz araçları:
- Paket yakalama
- Protokol analizi
- Trafik filtreleme
- Güvenlik taraması

### mitm_simulator.py
MITM saldırı simülasyonu:
- Saldırı senaryoları
- Güvenlik testleri
- Zafiyet tespiti
- Koruma önlemleri

### security_tests.py
Güvenlik test araçları:
- Şifreleme testleri
- Protokol testleri
- Güvenlik açığı taraması
- Performans testleri

## Kurulum

1. Gerekli Python sürümünü yükleyin (Python 3.x)
2. Projeyi klonlayın:
```bash
git clone https://github.com/Kutibios/securefiletransfer.git
```
3. Gerekli paketleri yükleyin:
```bash
pip install -r requirements.txt
```

## Kullanım Kılavuzu

### Temel Kullanım
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

### Gelişmiş Kullanım
- Performans analizi için:
```bash
python network_performance.py
```
- Paket analizi için:
```bash
python packet_analyzer.py
```
- Güvenlik testleri için:
```bash
python security_tests.py
```

## Güvenlik Özellikleri

### Şifreleme
- RSA 2048-bit anahtar uzunluğu
- AES-256 şifreleme
- SHA-256 hash fonksiyonu
- Dijital imzalar

### Güvenlik Protokolleri
- TLS 1.3 desteği
- Perfect Forward Secrecy
- Oturum yönetimi
- Güvenli anahtar değişimi

## Hata Ayıklama

Yaygın hatalar ve çözümleri:
1. Bağlantı hatası:
   - Port numarasını kontrol edin
   - Güvenlik duvarı ayarlarını kontrol edin
2. Performans sorunları:
   - Ağ bağlantınızı kontrol edin
   - Sistem kaynaklarını kontrol edin
3. Güvenlik uyarıları:
   - Sertifikaları kontrol edin
   - Anahtar dosyalarını kontrol edin



## Lisans

Bu proje MIT lisansı altında lisanslanmıştır. Detaylar için `LICENSE` dosyasına bakın.

## İletişim

Proje Sahibi - [@Kutibios](https://github.com/Kutibios)
E-posta: [leventkutaysezer@gmail.com](mailto:leventkutaysezer@gmail.com)
Proje Linki: [https://github.com/Kutibios/securefiletransfer](https://github.com/Kutibios/securefiletransfer)
