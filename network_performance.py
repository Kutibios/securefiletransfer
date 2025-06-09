import socket
import time
import statistics
import subprocess
import platform
import threading
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass
from datetime import datetime

@dataclass
class NetworkMetrics:
    latency: float  # milliseconds
    bandwidth: float  # Mbps
    packet_loss: float  # percentage
    timestamp: datetime

class NetworkPerformanceAnalyzer:
    def __init__(self, target_host: str = "127.0.0.1", port: int = 5001):
        self.target_host = target_host
        self.port = port
        self.metrics_history: List[NetworkMetrics] = []
        self.ping_count = 4
        self.packet_size = 32
        self.timeout = 1.0
        
    def measure_latency(self, target: str) -> float:
        """Measure network latency using ICMP ping"""
        try:
            if platform.system().lower() == "windows":
                ping_cmd = ["ping", "-n", str(self.ping_count), "-w", str(int(self.timeout * 1000)), target]
            else:
                ping_cmd = ["ping", "-c", str(self.ping_count), "-W", str(int(self.timeout)), target]

            result = subprocess.run(ping_cmd, capture_output=True, text=True)
            output = result.stdout

            # Parse ping output
            times = []
            for line in output.split('\n'):
                if "time=" in line or "time<" in line:
                    try:
                        time_str = line.split("time=")[-1].split()[0].replace("ms", "")
                        times.append(float(time_str))
                    except (IndexError, ValueError):
                        continue

            if not times:
                raise ValueError("No valid ping responses")

            return statistics.mean(times)

        except Exception as e:
            raise RuntimeError(f"Latency measurement failed: {str(e)}")

    def measure_bandwidth(self, target: str) -> float:
        """Estimate bandwidth using ICMP ping with different packet sizes"""
        try:
            # Test with different packet sizes
            packet_sizes = [32, 64, 128, 256, 512, 1024]
            bandwidths = []

            for size in packet_sizes:
                if platform.system().lower() == "windows":
                    ping_cmd = ["ping", "-n", "4", "-l", str(size), "-w", str(int(self.timeout * 1000)), target]
                else:
                    ping_cmd = ["ping", "-c", "4", "-s", str(size), "-W", str(int(self.timeout)), target]

                result = subprocess.run(ping_cmd, capture_output=True, text=True)
                output = result.stdout

                # Parse ping output for time
                times = []
                for line in output.split('\n'):
                    if "time=" in line or "time<" in line:
                        try:
                            time_str = line.split("time=")[-1].split()[0].replace("ms", "")
                            times.append(float(time_str))
                        except (IndexError, ValueError):
                            continue

                if times:
                    avg_time = statistics.mean(times)
                    # Calculate bandwidth: (packet_size * 8) / (time / 1000)
                    bandwidth = (size * 8) / (avg_time / 1000)
                    bandwidths.append(bandwidth)

            if not bandwidths:
                raise ValueError("No valid bandwidth measurements")

            # Return average bandwidth in Mbps
            return statistics.mean(bandwidths) / 1_000_000

        except Exception as e:
            raise RuntimeError(f"Bandwidth measurement failed: {str(e)}")

    def measure_packet_loss(self, target: str) -> float:
        """Measure packet loss percentage using ICMP ping"""
        try:
            if platform.system().lower() == "windows":
                ping_cmd = ["ping", "-n", str(self.ping_count), "-w", str(int(self.timeout * 1000)), target]
            else:
                ping_cmd = ["ping", "-c", str(self.ping_count), "-W", str(int(self.timeout)), target]

            result = subprocess.run(ping_cmd, capture_output=True, text=True)
            output = result.stdout

            # Parse ping output for packet loss
            for line in output.split('\n'):
                if platform.system().lower() == "windows":
                    if "Kayıp" in line:  # Windows Türkçe
                        try:
                            loss_str = line.split("(")[1].split("%")[0]
                            return float(loss_str)
                        except (IndexError, ValueError):
                            continue
                    elif "Lost" in line:  # Windows İngilizce
                        try:
                            loss_str = line.split("(")[1].split("%")[0]
                            return float(loss_str)
                        except (IndexError, ValueError):
                            continue
                else:
                    if "packet loss" in line.lower():
                        try:
                            loss_str = line.split("%")[0].split()[-1]
                            return float(loss_str)
                        except (IndexError, ValueError):
                            continue

            # Eğer paket kaybı bilgisi bulunamazsa, ping yanıtlarını say
            responses = 0
            for line in output.split('\n'):
                if "time=" in line or "time<" in line:
                    responses += 1

            if responses == 0:
                return 100.0  # Hiç yanıt yoksa %100 kayıp
            else:
                return ((self.ping_count - responses) / self.ping_count) * 100

        except Exception as e:
            raise RuntimeError(f"Packet loss measurement failed: {str(e)}")

    def simulate_network_conditions(self, packet_loss: float = 0.0, delay: int = 0):
        """tc komutu ile ağ koşullarını simüle eder."""
        if platform.system() != "Linux":
            print("[!] Bu özellik sadece Linux sistemlerde çalışır")
            return
            
        try:
            # Mevcut tc kurallarını temizle
            subprocess.run(["tc", "qdisc", "del", "dev", "lo", "root"], 
                         stderr=subprocess.PIPE)
            
            # Yeni tc kuralları ekle
            cmd = ["tc", "qdisc", "add", "dev", "lo", "root", "netem"]
            
            if packet_loss > 0:
                cmd.extend(["loss", f"{packet_loss}%"])
            if delay > 0:
                cmd.extend(["delay", f"{delay}ms"])
                
            subprocess.run(cmd)
            print(f"[+] Ağ koşulları simüle edildi: {packet_loss}% paket kaybı, {delay}ms gecikme")
            
        except Exception as e:
            print(f"[!] Ağ koşulları simülasyonunda hata: {e}")

    def run_performance_test(self, target: str) -> Dict[str, float]:
        """Run all performance tests and return metrics"""
        try:
            latency = self.measure_latency(target)
            bandwidth = self.measure_bandwidth(target)
            packet_loss = self.measure_packet_loss(target)

            return {
                'latency': latency,
                'bandwidth': bandwidth,
                'packet_loss': packet_loss
            }

        except Exception as e:
            raise RuntimeError(f"Performance test failed: {str(e)}")

    def generate_report(self) -> str:
        """Ölçüm sonuçlarını raporlar."""
        if not self.metrics_history:
            return "Henüz ölçüm yapılmadı"
            
        report = "Ağ Performans Raporu\n"
        report += "=" * 50 + "\n\n"
        
        # Ortalama değerleri hesapla
        avg_latency = statistics.mean(m.latency for m in self.metrics_history)
        avg_bandwidth = statistics.mean(m.bandwidth for m in self.metrics_history)
        avg_packet_loss = statistics.mean(m.packet_loss for m in self.metrics_history)
        
        report += f"Ortalama Gecikme: {avg_latency:.2f} ms\n"
        report += f"Ortalama Bant Genişliği: {avg_bandwidth:.2f} Mbps\n"
        report += f"Ortalama Paket Kaybı: {avg_packet_loss:.2f}%\n"
        
        return report

def main():
    analyzer = NetworkPerformanceAnalyzer()
    
    # Test senaryoları
    print("[*] Normal ağ koşullarında test başlıyor...")
    try:
        metrics = analyzer.run_performance_test("8.8.8.8")
        print(f"Network Metrics:")
        print(f"Latency: {metrics['latency']:.2f} ms")
        print(f"Bandwidth: {metrics['bandwidth']:.2f} Mbps")
        print(f"Packet Loss: {metrics['packet_loss']:.1f}%")
    except Exception as e:
        print(f"Error: {e}")
    
    print("\n[*] Yüksek paket kaybı simülasyonu...")
    analyzer.simulate_network_conditions(packet_loss=10.0)
    try:
        metrics = analyzer.run_performance_test("8.8.8.8")
        print(f"Network Metrics:")
        print(f"Latency: {metrics['latency']:.2f} ms")
        print(f"Bandwidth: {metrics['bandwidth']:.2f} Mbps")
        print(f"Packet Loss: {metrics['packet_loss']:.1f}%")
    except Exception as e:
        print(f"Error: {e}")
    
    print("\n[*] Yüksek gecikme simülasyonu...")
    analyzer.simulate_network_conditions(delay=100)
    try:
        metrics = analyzer.run_performance_test("8.8.8.8")
        print(f"Network Metrics:")
        print(f"Latency: {metrics['latency']:.2f} ms")
        print(f"Bandwidth: {metrics['bandwidth']:.2f} Mbps")
        print(f"Packet Loss: {metrics['packet_loss']:.1f}%")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main() 