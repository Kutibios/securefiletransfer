import sys
import os
import platform
import socket
import struct
import time
import hashlib # For integrity check in standard transfer
from tqdm import tqdm # For progress bar in standard transfer
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QPushButton, QLabel, QLineEdit, 
                           QTextEdit, QFileDialog, QTabWidget, QProgressBar,
                           QComboBox, QGroupBox, QGridLayout, QMessageBox,
                           QTableWidget, QTableWidgetItem, QHeaderView, QCheckBox)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont, QIcon
from raw_transfer_utils import RawFileSender, RawFileReceiver
from crypto_utils import generate_key, encrypt_data, decrypt_data, get_file_hash

# --- Re-adding necessary imports ---
from network_performance import NetworkPerformanceAnalyzer
from packet_analyzer_win import PacketAnalyzer
from security_tests import SecurityTester # Ensure this is imported for SecurityTestTab
# --- End of re-added imports ---

SHARED_KEY = b"BuBirGizliAnahtar!" # Define SHARED_KEY here as well for standard transfer

class FileTransferThread(QThread):
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    transfer_completed = pyqtSignal(bool, str)

    def __init__(self, mode, host, port, file_path=None):
        super().__init__()
        self.mode = mode
        self.host = host
        self.port = port
        self.file_path = file_path
        self.is_running = False

    def run(self):
        self.is_running = True
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if self.mode == 'send':
                # Client logic for sending (TCP)
                sock.connect((self.host, self.port))
                self.status_updated.emit("Sunucuya bağlanıldı...")
                
                # Authentication
                sock.sendall(SHARED_KEY)
                auth_response = sock.recv(1024)
                if auth_response != b"AUTH_SUCCESS":
                    self.transfer_completed.emit(False, "Kimlik doğrulama başarısız.")
                    return
                self.status_updated.emit("Kimlik doğrulama başarılı.")

                # Get encryption key
                key = sock.recv(32)
                if len(key) != 32:
                    self.transfer_completed.emit(False, "Geçersiz şifreleme anahtarı alındı.")
                    return

                with open(self.file_path, 'rb') as f:
                    file_data = f.read()
                encrypted_data = encrypt_data(file_data, key)
                file_hash = get_file_hash(file_data) # Hash of original data

                sock.sendall(struct.pack('!I', len(encrypted_data))) # Send encrypted data size
                time.sleep(0.1)
                sock.sendall(encrypted_data) # Send encrypted data
                time.sleep(0.1)
                sock.sendall(file_hash) # Send hash of original data
                self.progress_updated.emit(100)
                self.transfer_completed.emit(True, "Dosya başarıyla gönderildi!")

            else: # receive mode (TCP)
                # Server logic for receiving (TCP)
                server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_sock.bind((self.host, self.port))
                server_sock.listen(1)
                self.status_updated.emit("İstemci bekleniyor...")
                client_sock, addr = server_sock.accept()
                self.status_updated.emit(f"İstemci bağlandı: {addr}")

                # Authentication
                auth_msg = client_sock.recv(1024)
                if auth_msg == SHARED_KEY:
                    client_sock.sendall(b"AUTH_SUCCESS")
                    self.status_updated.emit("Kimlik doğrulama başarılı.")
                else:
                    client_sock.sendall(b"AUTH_FAILED")
                    self.transfer_completed.emit(False, "Kimlik doğrulama başarısız.")
                    client_sock.close()
                    server_sock.close()
                    return

                # Send encryption key
                key = generate_key()
                client_sock.sendall(key)

                # Receive encrypted data size
                encrypted_size_bytes = client_sock.recv(struct.calcsize('!I'))
                encrypted_size = struct.unpack('!I', encrypted_size_bytes)[0]

                # Receive encrypted data with progress
                encrypted_data = b''
                with tqdm(total=encrypted_size, unit='B', unit_scale=True, desc="Veri Alınıyor") as pbar:
                    while len(encrypted_data) < encrypted_size:
                        chunk = client_sock.recv(min(4096, encrypted_size - len(encrypted_data)))
                        if not chunk:
                            self.transfer_completed.emit(False, "Veri alımı eksik veya bağlantı koptu.")
                            return
                        encrypted_data += chunk
                        pbar.update(len(chunk))
                        self.progress_updated.emit(int((len(encrypted_data) / encrypted_size) * 100))
                
                # Receive hash
                received_hash = client_sock.recv(64) # SHA-256 hash 64 byte

                # Decrypt and verify hash
                decrypted_data = decrypt_data(encrypted_data, key)
                calculated_hash = get_file_hash(decrypted_data)

                if calculated_hash == received_hash:
                    output_file_path = "files/received/received_testfile.txt" # Assuming fixed output path for simplicity
                    os.makedirs(os.path.dirname(output_file_path), exist_ok=True)
                    with open(output_file_path, 'wb') as f:
                        f.write(decrypted_data)
                    self.progress_updated.emit(100)
                    self.transfer_completed.emit(True, "Dosya başarıyla alındı ve kaydedildi!")
                else:
                    self.transfer_completed.emit(False, "Hash kontrolü başarısız: Dosya bütünlüğü bozulmuş olabilir.")

        except Exception as e:
            self.transfer_completed.emit(False, f"Transfer Hatası: {str(e)}")
        finally:
            self.is_running = False
            if sock:
                sock.close()
            if self.mode == 'receive' and 'server_sock' in locals() and server_sock:
                server_sock.close()
            if self.mode == 'receive' and 'client_sock' in locals() and client_sock:
                client_sock.close()

class RawTransferThread(QThread):
    progress_updated = pyqtSignal(int)
    status_updated = pyqtSignal(str)
    transfer_completed = pyqtSignal(bool, str)

    def __init__(self, mode, host, port, file_path=None):
        super().__init__()
        self.mode = mode
        self.host = host
        self.port = port
        self.file_path = file_path
        self.is_running = False

    def run(self):
        self.is_running = True
        try:
            if self.mode == 'send':
                sender = RawFileSender(self.host, self.host, self.port) # Source IP and Dest IP are the same for loopback
                self.status_updated.emit("Dosya Raw Socket ile gönderiliyor...")
                sender.send_file_fragmented(self.file_path)
                self.transfer_completed.emit(True, "Dosya Raw Socket ile başarıyla gönderildi!")
            else: # receive
                receiver = RawFileReceiver(self.host, self.port, self.file_path)
                self.status_updated.emit("Raw Socket ile fragmentlar bekleniyor...")
                receiver.start_receiving()
                self.transfer_completed.emit(True, "Dosya Raw Socket ile başarıyla alındı ve birleştirildi!")
        except Exception as e:
            self.transfer_completed.emit(False, f"Raw Socket Transfer Hatası: {str(e)}")
        finally:
            self.is_running = False

    def stop(self):
        self.is_running = False
        # Raw sockets usually don't have a clean 'stop' method like TCP sockets
        # The receiver has a timeout, so it will eventually stop if no more packets come

class FileTransferTab(QWidget):
    def __init__(self):
        super().__init__()
        self.transfer_thread = None
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Mode selection
        mode_layout = QHBoxLayout()
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(['Gönder', 'Al'])
        self.mode_combo.currentTextChanged.connect(self.on_mode_changed)
        mode_layout.addWidget(QLabel('Mod:'))
        mode_layout.addWidget(self.mode_combo)

        # Add raw socket checkbox
        self.raw_socket_checkbox = QCheckBox("Raw Socket Transfer")
        mode_layout.addWidget(self.raw_socket_checkbox)

        layout.addLayout(mode_layout)
        
        # Host and port
        host_layout = QHBoxLayout()
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText('Host (örn: 127.0.0.1)')
        self.host_input.setText('127.0.0.1')
        host_layout.addWidget(QLabel('Host:'))
        host_layout.addWidget(self.host_input)
        layout.addLayout(host_layout)
        
        port_layout = QHBoxLayout()
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText('Port (örn: 5000)')
        self.port_input.setText('5000')
        port_layout.addWidget(QLabel('Port:'))
        port_layout.addWidget(self.port_input)
        layout.addLayout(port_layout)
        
        # File selection
        file_layout = QHBoxLayout()
        self.file_path = QLineEdit()
        self.file_path.setReadOnly(True)
        self.file_button = QPushButton('Dosya Seç')
        self.file_button.clicked.connect(self.select_file)
        file_layout.addWidget(self.file_path)
        file_layout.addWidget(self.file_button)
        layout.addLayout(file_layout)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)
        
        # Status
        self.status_label = QLabel('Hazır')
        layout.addWidget(self.status_label)
        
        # Start/Stop buttons
        button_layout = QHBoxLayout()
        self.start_button = QPushButton('Başlat')
        self.start_button.clicked.connect(self.start_transfer)
        self.stop_button = QPushButton('Durdur')
        self.stop_button.clicked.connect(self.stop_transfer)
        self.stop_button.setEnabled(False)
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
        
    def on_mode_changed(self, mode):
        self.file_button.setEnabled(mode == 'Gönder')
        self.file_path.clear()
        
    def select_file(self):
        file_name, _ = QFileDialog.getOpenFileName(self, 'Dosya Seç')
        if file_name:
            self.file_path.setText(file_name)
            
    def start_transfer(self):
        if self.transfer_thread and self.transfer_thread.is_running:
            return
        
        host = self.host_input.text()
        try:
            port = int(self.port_input.text())
        except ValueError:
            QMessageBox.warning(self, 'Hata', 'Geçerli bir port numarası girin')
            return
        
        mode = 'send' if self.mode_combo.currentText() == 'Gönder' else 'receive'
        file_path = self.file_path.text() if mode == 'send' else None
        
        if mode == 'send' and not file_path:
            QMessageBox.warning(self, 'Hata', 'Lütfen bir dosya seçin')
            return

        # Check if raw socket transfer is selected and warn about admin privileges
        if self.raw_socket_checkbox.isChecked():
            if platform.system() == 'Windows':
                QMessageBox.warning(self, "Uyarı", "Raw Socket Transfer için Yönetici olarak çalıştırmanız gerekebilir.")
            self.transfer_thread = RawTransferThread(mode, host, port, file_path)
        else:
            self.transfer_thread = FileTransferThread(mode, host, port, file_path)

        self.transfer_thread.progress_updated.connect(self.update_progress)
        self.transfer_thread.status_updated.connect(self.update_status)
        self.transfer_thread.transfer_completed.connect(self.on_transfer_completed)
        self.transfer_thread.start()
        
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.status_label.setText('Transfer başlatılıyor...')
        
    def stop_transfer(self):
        if self.transfer_thread and self.transfer_thread.is_running:
            self.transfer_thread.stop()
            self.status_label.setText('Transfer durduruluyor...')
        
    def update_progress(self, value):
        self.progress_bar.setValue(value)
        
    def update_status(self, message):
        self.status_label.setText(message)
        
    def on_transfer_completed(self, success, message):
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_label.setText(message)
        if success:
            self.progress_bar.setValue(100)
        else:
            QMessageBox.warning(self, 'Hata', message)

class NetworkMonitorThread(QThread):
    metrics_updated = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, target_host):
        super().__init__()
        self.target_host = target_host
        self.is_running = False
        self.analyzer = NetworkPerformanceAnalyzer()

    def run(self):
        self.is_running = True
        while self.is_running:
            try:
                metrics = self.analyzer.run_performance_test(self.target_host)
                self.metrics_updated.emit(metrics)
            except Exception as e:
                self.error_occurred.emit(str(e))
            self.msleep(1000)  # Her saniye güncelle

    def stop(self):
        self.is_running = False

class NetworkMonitorTab(QWidget):
    def __init__(self):
        super().__init__()
        self.monitor_thread = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Hedef sunucu ayarları
        target_group = QGroupBox("Hedef Sunucu")
        target_layout = QHBoxLayout()
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText('Hedef IP (örn: 8.8.8.8)')
        self.target_input.setText('8.8.8.8')
        target_layout.addWidget(QLabel('Hedef:'))
        target_layout.addWidget(self.target_input)
        target_group.setLayout(target_layout)
        layout.addWidget(target_group)

        # Metrikler
        metrics_group = QGroupBox("Ağ Metrikleri")
        metrics_layout = QVBoxLayout()

        # Gecikme
        latency_layout = QHBoxLayout()
        self.latency_label = QLabel('Gecikme: -- ms')
        latency_layout.addWidget(self.latency_label)
        metrics_layout.addLayout(latency_layout)

        # Bant Genişliği
        bandwidth_layout = QHBoxLayout()
        self.bandwidth_label = QLabel('Bant Genişliği: -- Mbps')
        bandwidth_layout.addWidget(self.bandwidth_label)
        metrics_layout.addLayout(bandwidth_layout)

        # Paket Kaybı
        packet_loss_layout = QHBoxLayout()
        self.packet_loss_label = QLabel('Paket Kaybı: --%')
        packet_loss_layout.addWidget(self.packet_loss_label)
        metrics_layout.addLayout(packet_loss_layout)

        metrics_group.setLayout(metrics_layout)
        layout.addWidget(metrics_group)

        # Kontrol butonları
        control_layout = QHBoxLayout()
        self.start_button = QPushButton('İzlemeyi Başlat')
        self.start_button.clicked.connect(self.start_monitoring)
        self.stop_button = QPushButton('İzlemeyi Durdur')
        self.stop_button.clicked.connect(self.stop_monitoring)
        self.stop_button.setEnabled(False)
        control_layout.addWidget(self.start_button)
        control_layout.addWidget(self.stop_button)
        layout.addLayout(control_layout)

        # Log alanı
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        layout.addWidget(self.log_area)

        self.setLayout(layout)

    def start_monitoring(self):
        if self.monitor_thread and self.monitor_thread.is_running:
            return

        target = self.target_input.text()
        if not target:
            QMessageBox.warning(self, 'Hata', 'Lütfen bir hedef IP girin')
            return

        self.monitor_thread = NetworkMonitorThread(target)
        self.monitor_thread.metrics_updated.connect(self.update_metrics)
        self.monitor_thread.error_occurred.connect(self.handle_error)
        self.monitor_thread.start()

        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.log_area.append(f"İzleme başlatıldı: {target}")

    def stop_monitoring(self):
        if self.monitor_thread and self.monitor_thread.is_running:
            self.monitor_thread.stop()
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.log_area.append("İzleme durduruldu")

    def update_metrics(self, metrics):
        self.latency_label.setText(f"Gecikme: {metrics['latency']:.2f} ms")
        self.bandwidth_label.setText(f"Bant Genişliği: {metrics['bandwidth']:.2f} Mbps")
        self.packet_loss_label.setText(f"Paket Kaybı: {metrics['packet_loss']:.1f}%")
        self.log_area.append(f"Metrikler güncellendi: {metrics}")

    def handle_error(self, error_msg):
        self.log_area.append(f"Hata: {error_msg}")
        QMessageBox.warning(self, 'Hata', error_msg)

class PacketCaptureThread(QThread):
    packet_captured = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, analyzer):
        super().__init__()
        self.analyzer = analyzer
        self.is_running = False

    def run(self):
        self.is_running = True
        while self.is_running:
            try:
                packet = self.analyzer.analyze_packet()
                if packet:
                    self.packet_captured.emit(packet)
            except Exception as e:
                self.error_occurred.emit(str(e))
                break

    def stop(self):
        self.is_running = False
        self.analyzer.stop_capture()

class PacketAnalyzerTab(QWidget):
    def __init__(self):
        super().__init__()
        self.analyzer = PacketAnalyzer()
        self.capture_thread = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # Control buttons
        control_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Capture")
        self.stop_button = QPushButton("Stop Capture")
        self.stop_button.setEnabled(False)
        self.clear_button = QPushButton("Clear")
        
        self.start_button.clicked.connect(self.start_capture)
        self.stop_button.clicked.connect(self.stop_capture)
        self.clear_button.clicked.connect(self.clear_packets)
        
        control_layout.addWidget(self.start_button)
        control_layout.addWidget(self.stop_button)
        control_layout.addWidget(self.clear_button)
        layout.addLayout(control_layout)

        # Packet table
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(6)
        self.packet_table.setHorizontalHeaderLabels([
            "No.", "Time", "Source", "Destination", "Protocol", "Info"
        ])
        self.packet_table.setColumnWidth(0, 50)  # No.
        self.packet_table.setColumnWidth(1, 100)  # Time
        self.packet_table.setColumnWidth(2, 150)  # Source
        self.packet_table.setColumnWidth(3, 150)  # Destination
        self.packet_table.setColumnWidth(4, 100)  # Protocol
        self.packet_table.setColumnWidth(5, 300)  # Info
        
        layout.addWidget(self.packet_table)

        # Packet details
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setMaximumHeight(150)
        layout.addWidget(self.details_text)

        self.setLayout(layout)

        # Connect signals
        self.packet_table.itemSelectionChanged.connect(self.show_packet_details)

    def start_capture(self):
        try:
            self.analyzer.start_capture()
            self.capture_thread = PacketCaptureThread(self.analyzer)
            self.capture_thread.packet_captured.connect(self.add_packet)
            self.capture_thread.error_occurred.connect(self.show_error)
            self.capture_thread.start()
            
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to start capture: {str(e)}")

    def stop_capture(self):
        if self.capture_thread:
            self.capture_thread.stop()
            self.capture_thread.wait()
            self.capture_thread = None
        
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

    def clear_packets(self):
        self.packet_table.setRowCount(0)
        self.details_text.clear()

    def add_packet(self, packet):
        row = self.packet_table.rowCount()
        self.packet_table.insertRow(row)
        
        self.packet_table.setItem(row, 0, QTableWidgetItem(str(row + 1)))
        self.packet_table.setItem(row, 1, QTableWidgetItem(packet['timestamp']))
        self.packet_table.setItem(row, 2, QTableWidgetItem(packet['source']))
        self.packet_table.setItem(row, 3, QTableWidgetItem(packet['destination']))
        self.packet_table.setItem(row, 4, QTableWidgetItem(packet['protocol']))
        self.packet_table.setItem(row, 5, QTableWidgetItem(packet['info']))

    def show_packet_details(self):
        selected_items = self.packet_table.selectedItems()
        if not selected_items:
            return

        row = selected_items[0].row()
        details = []
        for col in range(self.packet_table.columnCount()):
            header = self.packet_table.horizontalHeaderItem(col).text()
            value = self.packet_table.item(row, col).text()
            details.append(f"{header}: {value}")
        
        self.details_text.setText("\n".join(details))

    def show_error(self, error_msg):
        QMessageBox.critical(self, "Error", error_msg)
        self.stop_capture()

class SecurityTestTab(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()
        # Connect buttons to functions
        self.port_scan_check.clicked.connect(self.run_port_scan)
        self.syn_flood_check.clicked.connect(self.run_syn_flood)
        self.udp_flood_check.clicked.connect(self.run_udp_flood)
        self.icmp_flood_check.clicked.connect(self.run_icmp_flood)
        self.arp_spoof_check.clicked.connect(self.run_arp_spoof)
        self.mitm_start_button.clicked.connect(self.run_mitm_simulation)
        self.mitm_stop_button.clicked.connect(self.stop_mitm_simulation)

    def init_ui(self):
        layout = QVBoxLayout()
        
        # Test hedefi
        target_group = QGroupBox("Test Hedefi")
        target_layout = QGridLayout()
        
        target_layout.addWidget(QLabel("IP Adresi:"), 0, 0)
        self.target_ip = QLineEdit("127.0.0.1")
        target_layout.addWidget(self.target_ip, 0, 1)
        
        target_layout.addWidget(QLabel("Port:"), 1, 0)
        self.target_port = QLineEdit("5001")
        target_layout.addWidget(self.target_port, 1, 1)
        
        target_group.setLayout(target_layout)
        
        # Test seçenekleri
        tests_group = QGroupBox("Test Seçenekleri")
        tests_layout = QVBoxLayout()
        
        self.port_scan_check = QPushButton("Port Tarama")
        self.syn_flood_check = QPushButton("SYN Flood")
        self.udp_flood_check = QPushButton("UDP Flood")
        self.icmp_flood_check = QPushButton("ICMP Flood")
        self.arp_spoof_check = QPushButton("ARP Spoofing")
        
        # MITM Simülasyonu
        mitm_group = QGroupBox("MITM Simülasyonu")
        mitm_layout = QGridLayout()

        mitm_layout.addWidget(QLabel("Hedef IP:"), 0, 0)
        self.mitm_target_ip = QLineEdit("192.168.1.1") # Varsayılan değer
        mitm_layout.addWidget(self.mitm_target_ip, 0, 1)

        mitm_layout.addWidget(QLabel("Gateway IP:"), 1, 0)
        self.mitm_gateway_ip = QLineEdit("192.168.1.1") # Varsayılan değer
        mitm_layout.addWidget(self.mitm_gateway_ip, 1, 1)

        self.mitm_start_button = QPushButton("MITM Simülasyonu Başlat")
        self.mitm_stop_button = QPushButton("MITM Simülasyonu Durdur")
        self.mitm_stop_button.setEnabled(False) # Başlangıçta devre dışı

        mitm_layout.addWidget(self.mitm_start_button, 2, 0, 1, 2)
        mitm_layout.addWidget(self.mitm_stop_button, 3, 0, 1, 2)

        mitm_group.setLayout(mitm_layout)

        tests_layout.addWidget(self.port_scan_check)
        tests_layout.addWidget(self.syn_flood_check)
        tests_layout.addWidget(self.udp_flood_check)
        tests_layout.addWidget(self.icmp_flood_check)
        tests_layout.addWidget(self.arp_spoof_check)
        tests_layout.addWidget(mitm_group) # MITM grubunu ekle
        
        tests_group.setLayout(tests_layout)
        
        # Test sonuçları
        self.test_results = QTextEdit()
        self.test_results.setReadOnly(True)
        
        # Layout'a widget'ları ekle
        layout.addWidget(target_group)
        layout.addWidget(tests_group)
        layout.addWidget(self.test_results)
        
        self.setLayout(layout)

    def run_port_scan(self):
        ip = self.target_ip.text()
        port = int(self.target_port.text())
        try:
            # from security_tests import SecurityTester (already imported at top)
            tester = SecurityTester(ip, port)
            tester.test_port_scan()
            if tester.test_results:
                last = tester.test_results[-1]
                self.test_results.append(f"Port Scan Sonucu: {last.details}")
            else:
                self.test_results.append("Port Scan Sonucu: Sonuç bulunamadı.")
        except Exception as e:
            self.test_results.append(f"Port Scan Hatası: {str(e)}")

    def run_syn_flood(self):
        if platform.system() == 'Windows':
            self.test_results.append("SYN Flood Hatası: Bu test Windows'ta desteklenmiyor. Desteklenen bir sistemde (ör. Linux) deneyebilirsiniz.")
            return
        ip = self.target_ip.text()
        port = int(self.target_port.text())
        try:
            # from security_tests import SecurityTester (already imported at top)
            tester = SecurityTester(ip, port)
            tester.test_syn_flood()
            if tester.test_results:
                last = tester.test_results[-1]
                self.test_results.append(f"SYN Flood Sonucu: {last.details}")
            else:
                self.test_results.append("SYN Flood Sonucu: Sonuç bulunamadı.")
        except Exception as e:
            self.test_results.append(f"SYN Flood Hatası: {str(e)}")

    def run_udp_flood(self):
        ip = self.target_ip.text()
        port = int(self.target_port.text())
        try:
            # from security_tests import SecurityTester (already imported at top)
            tester = SecurityTester(ip, port)
            tester.test_udp_flood()
            if tester.test_results:
                last = tester.test_results[-1]
                self.test_results.append(f"UDP Flood Sonucu: {last.details}")
            else:
                self.test_results.append("UDP Flood Sonucu: Sonuç bulunamadı.")
        except Exception as e:
            self.test_results.append(f"UDP Flood Hatası: {str(e)}")

    def run_icmp_flood(self):
        ip = self.target_ip.text()
        port = int(self.target_port.text())
        try:
            # from security_tests import SecurityTester (already imported at top)
            tester = SecurityTester(ip, port)
            tester.test_icmp_flood()
            if tester.test_results:
                last = tester.test_results[-1]
                self.test_results.append(f"ICMP Flood Sonucu: {last.details}")
            else:
                self.test_results.append("ICMP Flood Sonucu: Sonuç bulunamadı.")
        except Exception as e:
            self.test_results.append(f"ICMP Flood Hatası: {str(e)}")

    def run_arp_spoof(self):
        ip = self.target_ip.text()
        port = int(self.target_port.text())
        try:
            # from security_tests import SecurityTester (already imported at top)
            tester = SecurityTester(ip, port)
            tester.test_arp_spoofing()
            if tester.test_results:
                last = tester.test_results[-1]
                self.test_results.append(f"ARP Spoofing Sonucu: {last.details}")
            else:
                self.test_results.append("ARP Spoofing Sonucu: Sonuç bulunamadı.")
        except Exception as e:
            self.test_results.append(f"ARP Spoofing Hatası: {str(e)}")

    def run_mitm_simulation(self):
        target_ip = self.mitm_target_ip.text()
        gateway_ip = self.mitm_gateway_ip.text()
        
        if not target_ip or not gateway_ip:
            self.test_results.append("MITM Simülasyonu Hatası: Hedef IP ve Gateway IP boş bırakılamaz.")
            return

        self.test_results.append(f"MITM Simülasyonu Başlatılıyor: Hedef={target_ip}, Gateway={gateway_ip}")
        self.mitm_start_button.setEnabled(False)
        self.mitm_stop_button.setEnabled(True)

        self.mitm_thread = MITMThread(target_ip, gateway_ip)
        self.mitm_thread.status_updated.connect(self.update_mitm_status)
        self.mitm_thread.mitm_error.connect(self.handle_mitm_error)
        self.mitm_thread.finished.connect(self.on_mitm_finished)
        self.mitm_thread.start()

    def stop_mitm_simulation(self):
        if hasattr(self, 'mitm_thread') and self.mitm_thread.isRunning():
            self.mitm_thread.stop()
            self.test_results.append("MITM Simülasyonu Durduruluyor...")
        else:
            self.test_results.append("MITM Simülasyonu zaten çalışmıyor.")

    def update_mitm_status(self, message):
        self.test_results.append(f"MITM Durumu: {message}")

    def handle_mitm_error(self, error_msg):
        self.test_results.append(f"MITM Hatası: {error_msg}")
        self.on_mitm_finished() # Hata durumunda butonları sıfırla

    def on_mitm_finished(self):
        self.test_results.append("MITM Simülasyonu Tamamlandı.")
        self.mitm_start_button.setEnabled(True)
        self.mitm_stop_button.setEnabled(False)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle('Ağ Güvenlik ve Performans Analiz Sistemi')
        self.setGeometry(100, 100, 1200, 800) # Genişliği artır
        
        # Ana widget ve layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)
        
        # Tab widget
        self.tabs = QTabWidget()
        
        # Tab'ları oluştur
        self.file_transfer_tab = FileTransferTab()
        self.network_monitor_tab = NetworkMonitorTab()
        self.packet_analyzer_tab = PacketAnalyzerTab()
        self.security_test_tab = SecurityTestTab()
        
        # Tab'ları ekle
        self.tabs.addTab(self.file_transfer_tab, "Dosya Transferi")
        self.tabs.addTab(self.network_monitor_tab, "Ağ Monitörü")
        self.tabs.addTab(self.packet_analyzer_tab, "Paket Analizi")
        self.tabs.addTab(self.security_test_tab, "Güvenlik Testleri")
        
        layout.addWidget(self.tabs)
        
        # Status bar
        self.statusBar().showMessage('Hazır')

class MITMThread(QThread):
    status_updated = pyqtSignal(str)
    mitm_error = pyqtSignal(str)

    def __init__(self, target_ip, gateway_ip):
        super().__init__()
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self._is_running = True
        self.simulator = None

    def run(self):
        try:
            from mitm_simulator import MITMSimulator
            # Initialize MITM simulator
            self.simulator = MITMSimulator(self.target_ip, self.gateway_ip)
            
            # Define a callback function that emits the status signal
            def status_callback(message):
                if self._is_running:  # Sadece thread çalışıyorsa sinyal gönder
                    self.status_updated.emit(message)
            
            # Start ARP spoofing with the callback
            self.simulator.start_spoofing(status_callback)
            
            # Thread'in durmasını bekle
            while self._is_running:
                self.msleep(100)  # 100ms bekle
                
        except ImportError:
            self.mitm_error.emit("Hata: mitm_simulator.py bulunamadı veya içe aktarılamadı.")
        except Exception as e:
            self.mitm_error.emit(f"MITM Simülasyonu sırasında hata oluştu: {str(e)}")
        finally:
            if self.simulator:
                self.simulator.stop_spoofing()

    def stop(self):
        self._is_running = False
        if self.simulator:
            self.status_updated.emit("MITM Simülasyonu durduruluyor...")
            self.simulator.stop_spoofing()
        self.quit()
        self.wait(3000)  # 3 saniye bekle

def main():
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main() 