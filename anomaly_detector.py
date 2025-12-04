#!/usr/bin/env python3
"""
Network Anomaly Detection Module using Scapy
By: Devon Mann
Part of IT359 Network Security Scanner Project
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether
import threading
import time
import json
from datetime import datetime, timedelta
from collections import defaultdict
import statistics
import matplotlib.pyplot as plt
import pandas as pd
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np

class AnomalyDetector:
    def __init__(self):
        self.is_monitoring = False
        self.sniff_thread = None
        self.packet_count = 0
        self.start_time = None
        self.detection_results = {}
        
        # Traffic statistics
        self.stats = {
            'total_packets': 0,
            'packets_by_protocol': defaultdict(int),
            'packets_by_ip': defaultdict(int),
            'packets_by_port': defaultdict(int),
            'packet_sizes': [],
            'timestamps': []
        }
        
        # Thresholds for anomaly detection
        self.thresholds = {
            'packet_rate': 100,  # packets per second
            'port_scan_threshold': 10,  # packets to different ports from same IP
            'syn_flood_threshold': 20,  # SYN packets per second
            'large_packet_size': 1500,  # bytes
            'arp_spoof_threshold': 5,  # ARP responses per second
        }
        
        # Detected anomalies
        self.anomalies = []
    
    def start_monitoring(self, interface=None, duration=60):
        """Start network traffic monitoring"""
        self.is_monitoring = True
        self.packet_count = 0
        self.start_time = datetime.now()
        self.anomalies = []
        self._reset_stats()
        
        # Start sniffing in separate thread
        self.sniff_thread = threading.Thread(
            target=self._sniff_traffic,
            args=(interface, duration)
        )
        self.sniff_thread.daemon = True
        self.sniff_thread.start()
        
        # Start analysis thread
        analysis_thread = threading.Thread(
            target=self._analyze_traffic,
            args=(duration,)
        )
        analysis_thread.daemon = True
        analysis_thread.start()
    
    def _sniff_traffic(self, interface, duration):
        """Sniff network traffic"""
        try:
            # Set timeout for sniffing
            end_time = time.time() + duration
            
            def packet_handler(packet):
                if time.time() > end_time or not self.is_monitoring:
                    return False
                
                self._process_packet(packet)
                return True
            
            # Start sniffing
            if interface:
                sniff(iface=interface, prn=packet_handler, store=0, timeout=duration)
            else:
                sniff(prn=packet_handler, store=0, timeout=duration)
                
        except Exception as e:
            print(f"Sniffing error: {e}")
        finally:
            self.is_monitoring = False
    
    def _process_packet(self, packet):
        """Process individual packet"""
        self.packet_count += 1
        self.stats['total_packets'] += 1
        timestamp = datetime.now()
        self.stats['timestamps'].append(timestamp)
        
        # Protocol analysis
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            self.stats['packets_by_ip'][ip_src] += 1
            
            # Packet size
            packet_size = len(packet)
            self.stats['packet_sizes'].append(packet_size)
            
            # Protocol type
            if TCP in packet:
                self.stats['packets_by_protocol']['TCP'] += 1
                port = packet[TCP].dport
                self.stats['packets_by_port'][port] += 1
                
                # Check for SYN flood
                if packet[TCP].flags == 'S':  # SYN packet
                    self._check_syn_flood(ip_src, timestamp)
                
                # Check for port scanning
                self._check_port_scan(ip_src, port, timestamp)
            
            elif UDP in packet:
                self.stats['packets_by_protocol']['UDP'] += 1
                if UDP in packet:
                    port = packet[UDP].dport
                    self.stats['packets_by_port'][port] += 1
            
            elif ICMP in packet:
                self.stats['packets_by_protocol']['ICMP'] += 1
                self._check_icmp_flood(ip_src, timestamp)
        
        elif ARP in packet:
            self.stats['packets_by_protocol']['ARP'] += 1
            self._check_arp_spoofing(packet)
        
        # Check packet rate
        self._check_packet_rate(timestamp)
        
        # Check for large packets (potential data exfiltration)
        if 'packet_sizes' in self.stats and self.stats['packet_sizes']:
            if packet_size > self.thresholds['large_packet_size']:
                self._detect_anomaly(
                    "Large Packet Detected",
                    f"Large packet ({packet_size} bytes) from {ip_src if IP in packet else 'Unknown'}",
                    "Medium"
                )
    
    def _check_packet_rate(self, timestamp):
        """Check for high packet rate (potential DoS)"""
        if len(self.stats['timestamps']) > 10:
            recent_packets = [t for t in self.stats['timestamps'] 
                            if t > timestamp - timedelta(seconds=1)]
            
            if len(recent_packets) > self.thresholds['packet_rate']:
                self._detect_anomaly(
                    "High Packet Rate",
                    f"High packet rate detected: {len(recent_packets)} packets/second",
                    "High"
                )
    
    def _check_syn_flood(self, ip_src, timestamp):
        """Check for SYN flood attack"""
        # Track SYN packets per source IP
        if not hasattr(self, 'syn_packets'):
            self.syn_packets = defaultdict(list)
        
        self.syn_packets[ip_src].append(timestamp)
        
        # Remove old entries (older than 1 second)
        self.syn_packets[ip_src] = [t for t in self.syn_packets[ip_src] 
                                  if t > timestamp - timedelta(seconds=1)]
        
        if len(self.syn_packets[ip_src]) > self.thresholds['syn_flood_threshold']:
            self._detect_anomaly(
                "SYN Flood Attack",
                f"Possible SYN flood from {ip_src}: {len(self.syn_packets[ip_src])} SYN packets/second",
                "Critical"
            )
    
    def _check_port_scan(self, ip_src, port, timestamp):
        """Check for port scanning activity"""
        if not hasattr(self, 'scanned_ports'):
            self.scanned_ports = defaultdict(set)
        
        self.scanned_ports[ip_src].add(port)
        
        # Check number of unique ports scanned in last 10 seconds
        if len(self.scanned_ports[ip_src]) > self.thresholds['port_scan_threshold']:
            self._detect_anomaly(
                "Port Scanning Detected",
                f"Possible port scan from {ip_src}: {len(self.scanned_ports[ip_src])} unique ports",
                "High"
            )
    
    def _check_icmp_flood(self, ip_src, timestamp):
        """Check for ICMP flood (ping flood)"""
        if not hasattr(self, 'icmp_packets'):
            self.icmp_packets = defaultdict(list)
        
        self.icmp_packets[ip_src].append(timestamp)
        
        # Remove old entries
        self.icmp_packets[ip_src] = [t for t in self.icmp_packets[ip_src] 
                                    if t > timestamp - timedelta(seconds=1)]
        
        if len(self.icmp_packets[ip_src]) > 50:  # ICMP flood threshold
            self._detect_anomaly(
                "ICMP Flood Attack",
                f"Possible ICMP flood from {ip_src}",
                "High"
            )
    
    def _check_arp_spoofing(self, packet):
        """Check for ARP spoofing attacks"""
        if not hasattr(self, 'arp_responses'):
            self.arp_responses = defaultdict(list)
        
        timestamp = datetime.now()
        
        if packet[ARP].op == 2:  # ARP response
            ip_src = packet[ARP].psrc
            self.arp_responses[ip_src].append(timestamp)
            
            # Remove old entries
            self.arp_responses[ip_src] = [t for t in self.arp_responses[ip_src] 
                                        if t > timestamp - timedelta(seconds=1)]
            
            if len(self.arp_responses[ip_src]) > self.thresholds['arp_spoof_threshold']:
                self._detect_anomaly(
                    "ARP Spoofing Detected",
                    f"Possible ARP spoofing from {ip_src}: {len(self.arp_responses[ip_src])} ARP responses/second",
                    "High"
                )
    
    def _detect_anomaly(self, anomaly_type, description, severity):
        """Record detected anomaly"""
        anomaly = {
            'type': anomaly_type,
            'description': description,
            'severity': severity,
            'timestamp': datetime.now().isoformat(),
            'packet_count': self.packet_count
        }
        
        # Avoid duplicate alerts within 5 seconds
        if not any(a['type'] == anomaly_type and 
                  (datetime.now() - datetime.fromisoformat(a['timestamp'])).seconds < 5
                  for a in self.anomalies):
            self.anomalies.append(anomaly)
            print(f"🚨 {anomaly_type}: {description}")
    
    def _analyze_traffic(self, duration):
        """Analyze traffic patterns"""
        time.sleep(duration)
        self._generate_statistics()
    
    def _generate_statistics(self):
        """Generate traffic statistics"""
        if not self.stats['timestamps']:
            return
        
        # Calculate packet rate
        if len(self.stats['timestamps']) > 1:
            time_diff = (self.stats['timestamps'][-1] - self.stats['timestamps'][0]).total_seconds()
            if time_diff > 0:
                packet_rate = len(self.stats['timestamps']) / time_diff
            else:
                packet_rate = 0
        else:
            packet_rate = 0
        
        self.detection_results = {
            'statistics': {
                'total_packets': self.stats['total_packets'],
                'packet_rate': round(packet_rate, 2),
                'protocol_distribution': dict(self.stats['packets_by_protocol']),
                'top_source_ips': dict(sorted(
                    self.stats['packets_by_ip'].items(), 
                    key=lambda x: x[1], 
                    reverse=True
                )[:5]),
                'top_ports': dict(sorted(
                    self.stats['packets_by_port'].items(), 
                    key=lambda x: x[1], 
                    reverse=True
                )[:5]),
                'avg_packet_size': round(statistics.mean(self.stats['packet_sizes']), 2) 
                if self.stats['packet_sizes'] else 0,
            },
            'anomalies': self.anomalies,
            'monitoring_duration': len(self.stats['timestamps']),
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': datetime.now().isoformat()
        }
    
    def _reset_stats(self):
        """Reset statistics"""
        self.stats = {
            'total_packets': 0,
            'packets_by_protocol': defaultdict(int),
            'packets_by_ip': defaultdict(int),
            'packets_by_port': defaultdict(int),
            'packet_sizes': [],
            'timestamps': []
        }
    
    def stop_monitoring(self):
        """Stop traffic monitoring"""
        self.is_monitoring = False
        if self.sniff_thread:
            self.sniff_thread.join(timeout=2)
    
    def get_results(self):
        """Get detection results"""
        return self.detection_results
    
    def save_results(self, filename=None):
        """Save results to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"anomaly_results_{timestamp}.json"
        
        with open(f"data/{filename}", 'w') as f:
            json.dump(self.detection_results, f, indent=2)
        
        return f"data/{filename}"
    
    def generate_traffic_graph(self):
        """Generate traffic visualization graph"""
        if not self.stats['timestamps']:
            return None
        
        try:
            # Create time series data
            times = pd.to_datetime(self.stats['timestamps'])
            time_series = pd.Series(1, index=times)
            resampled = time_series.resample('1S').sum()
            
            fig, axes = plt.subplots(2, 2, figsize=(12, 8))
            fig.suptitle('Network Traffic Analysis', fontsize=16)
            
            # 1. Packet rate over time
            axes[0, 0].plot(resampled.index, resampled.values)
            axes[0, 0].set_title('Packet Rate Over Time')
            axes[0, 0].set_xlabel('Time')
            axes[0, 0].set_ylabel('Packets/Second')
            axes[0, 0].grid(True, alpha=0.3)
            
            # 2. Protocol distribution
            protocols = list(self.stats['packets_by_protocol'].keys())
            counts = list(self.stats['packets_by_protocol'].values())
            axes[0, 1].bar(protocols, counts)
            axes[0, 1].set_title('Protocol Distribution')
            axes[0, 1].set_xlabel('Protocol')
            axes[0, 1].set_ylabel('Packet Count')
            axes[0, 1].tick_params(axis='x', rotation=45)
            
            # 3. Top source IPs
            top_ips = sorted(self.stats['packets_by_ip'].items(), 
                           key=lambda x: x[1], reverse=True)[:5]
            ip_labels = [ip[0][:15] + '...' if len(ip[0]) > 15 else ip[0] 
                        for ip in top_ips]
            ip_counts = [ip[1] for ip in top_ips]
            axes[1, 0].bar(ip_labels, ip_counts)
            axes[1, 0].set_title('Top Source IPs')
            axes[1, 0].set_xlabel('IP Address')
            axes[1, 0].set_ylabel('Packet Count')
            axes[1, 0].tick_params(axis='x', rotation=45)
            
            # 4. Packet size distribution
            if self.stats['packet_sizes']:
                axes[1, 1].hist(self.stats['packet_sizes'], bins=20, alpha=0.7)
                axes[1, 1].set_title('Packet Size Distribution')
                axes[1, 1].set_xlabel('Packet Size (bytes)')
                axes[1, 1].set_ylabel('Frequency')
            
            plt.tight_layout()
            
            # Save figure
            filename = f"data/traffic_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
            plt.savefig(filename, dpi=100, bbox_inches='tight')
            plt.close()
            
            return filename
            
        except Exception as e:
            print(f"Error generating graph: {e}")
            return None
    
    def get_anomaly_summary(self):
        """Get summary of detected anomalies"""
        if not self.anomalies:
            return "No anomalies detected."
        
        summary = []
        by_severity = defaultdict(list)
        
        for anomaly in self.anomalies:
            by_severity[anomaly['severity']].append(anomaly)
        
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            if severity in by_severity:
                summary.append(f"{severity}: {len(by_severity[severity])} anomalies")
                for anomaly in by_severity[severity][:2]:  # Show first 2 of each
                    summary.append(f"  - {anomaly['type']}")
        
        return "\n".join(summary)

if __name__ == "__main__":
    detector = AnomalyDetector()
    print("🚨 Anomaly Detection Module - Ready for integration")