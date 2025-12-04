#!/usr/bin/env python3
"""
Network Anomaly Detection Module with WSL2/Windows support
By: Devon Mann
Part of IT359 Network Security Scanner Project
"""

import threading
import time
import json
from datetime import datetime, timedelta
from collections import defaultdict
import statistics
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import subprocess
import os
import re

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, Ether
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("⚠️ Scapy not available. Linux mode will be limited.")

class AnomalyDetector:
    def __init__(self):
        self.is_monitoring = False
        self.monitor_thread = None
        self.packet_count = 0
        self.start_time = None
        self.detection_results = {}
        self.detection_mode = "auto"  # auto, linux, windows
        
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
        
        # Windows-specific
        self.windows_netstat_data = []
        self.windows_perfmon_data = []
    
    def detect_environment(self):
        """Detect if we're running in WSL2 or native Linux"""
        try:
            with open('/proc/version', 'r') as f:
                if 'microsoft' in f.read().lower():
                    return "wsl2"
            return "linux"
        except:
            return "linux"
    
    def set_detection_mode(self, mode):
        """Set detection mode: auto, linux, windows"""
        self.detection_mode = mode
    
    def start_monitoring(self, interface=None, duration=60):
        """Start network traffic monitoring"""
        env = self.detect_environment()
        mode = self.detection_mode
        
        if mode == "auto":
            mode = "windows" if env == "wsl2" else "linux"
        
        self.is_monitoring = True
        self.packet_count = 0
        self.start_time = datetime.now()
        self.anomalies = []
        self._reset_stats()
        
        print(f"Starting anomaly detection in {mode} mode...")
        
        if mode == "linux":
            if not SCAPY_AVAILABLE:
                raise Exception("Scapy not available. Install with: pip install scapy")
            self._start_linux_monitoring(interface, duration)
        else:
            self._start_windows_monitoring(duration)
    
    def _start_linux_monitoring(self, interface, duration):
        """Start Linux-based monitoring using Scapy"""
        # Start sniffing in separate thread
        self.monitor_thread = threading.Thread(
            target=self._sniff_traffic,
            args=(interface, duration)
        )
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        # Start analysis thread
        analysis_thread = threading.Thread(
            target=self._analyze_traffic,
            args=(duration,)
        )
        analysis_thread.daemon = True
        analysis_thread.start()
    
    def _start_windows_monitoring(self, duration):
        """Start Windows-based monitoring using Windows tools"""
        self.monitor_thread = threading.Thread(
            target=self._monitor_windows_traffic,
            args=(duration,)
        )
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        
        # Start analysis thread
        analysis_thread = threading.Thread(
            target=self._analyze_windows_traffic,
            args=(duration,)
        )
        analysis_thread.daemon = True
        analysis_thread.start()
    
    def _monitor_windows_traffic(self, duration):
        """Monitor Windows network traffic using netsh and netstat"""
        import time  # <-- Add this line at the beginning of the method
    
        try:
            end_time = time.time() + duration
        
        # Find cmd.exe path
            cmd_path = self._get_cmd_path()
            if not cmd_path:
                raise Exception("cmd.exe not found in WSL2")
        
            while time.time() < end_time and self.is_monitoring:
            # Get network statistics using Windows commands
                timestamp = datetime.now()
            
            # 1. Get active connections (netstat)
                netstat_result = subprocess.run(
                    [cmd_path, '/c', 'netstat', '-an'], 
                    capture_output=True, text=True, timeout=5
                )
            
                if netstat_result.returncode == 0:
                    connections = self._parse_windows_netstat(netstat_result.stdout)
                    self.windows_netstat_data.append({
                        'timestamp': timestamp,
                        'connections': connections,
                        'total_connections': len(connections)
                    })
            
            # 2. Get network interface statistics (netsh)
                netsh_result = subprocess.run(
                    [cmd_path, '/c', 'netsh', 'interface', 'ip', 'show', 'stats'], 
                    capture_output=True, text=True, timeout=5
                )
            
                if netsh_result.returncode == 0:
                    interface_stats = self._parse_windows_netsh(netsh_result.stdout)
                    self.windows_perfmon_data.append({
                        'timestamp': timestamp,
                        'stats': interface_stats
                    })
            
            # 3. Detect anomalies from Windows data
                self._detect_windows_anomalies(timestamp)
            
            # Wait before next collection
                time.sleep(2)
            
        except Exception as e:
            print(f"Windows monitoring error: {e}")
            import traceback
            traceback.print_exc()  # <-- Add this for better error info
        finally:
            self.is_monitoring = False
    
    def _parse_windows_netstat(self, output):
        """Parse Windows netstat output"""
        connections = []
        
        for line in output.split('\n'):
            line = line.strip()
            if line and not line.startswith('Active') and not line.startswith('Proto'):
                parts = line.split()
                if len(parts) >= 4:
                    connection = {
                        'protocol': parts[0],
                        'local_address': parts[1],
                        'foreign_address': parts[2],
                        'state': parts[3] if len(parts) > 3 else 'LISTENING'
                    }
                    connections.append(connection)
                    
                    # Extract IP and port for statistics
                    if ':' in connection['local_address']:
                        ip_port = connection['local_address'].split(':')
                        if len(ip_port) == 2:
                            ip = ip_port[0]
                            port = ip_port[1]
                            
                            # Update statistics
                            self.stats['total_packets'] += 1
                            self.stats['timestamps'].append(datetime.now())
                            
                            if ip and ip != '0.0.0.0':
                                self.stats['packets_by_ip'][ip] += 1
                            
                            if port and port.isdigit():
                                self.stats['packets_by_port'][int(port)] += 1
                            
                            self.stats['packets_by_protocol'][connection['protocol']] += 1
        
        return connections
    
    def _parse_windows_netsh(self, output):
        """Parse Windows netsh interface statistics"""
        stats = {}
        current_section = None
        
        for line in output.split('\n'):
            line = line.strip()
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip()
                value = value.strip()
                
                if key and value:
                    stats[key] = value
        
        return stats
    
    def _detect_windows_anomalies(self, timestamp):
        """Detect anomalies from Windows network data"""
        # 1. Check for high connection rate
        if len(self.windows_netstat_data) > 5:
            recent_conns = [d for d in self.windows_netstat_data 
                          if d['timestamp'] > timestamp - timedelta(seconds=10)]
            
            if recent_conns:
                avg_conns = sum(d['total_connections'] for d in recent_conns) / len(recent_conns)
                
                if avg_conns > 100:  # High connection rate threshold
                    self._detect_anomaly(
                        "High Connection Rate",
                        f"High network connection rate detected: {avg_conns:.1f} connections",
                        "Medium"
                    )
        
        # 2. Check for suspicious ports
        recent_ports = defaultdict(int)
        for data in self.windows_netstat_data[-10:]:
            for conn in data.get('connections', []):
                if ':' in conn.get('local_address', ''):
                    port = conn['local_address'].split(':')[1]
                    if port.isdigit():
                        recent_ports[port] += 1
        
        # Check for port scanning patterns
        unique_ports = len(recent_ports)
        if unique_ports > self.thresholds['port_scan_threshold']:
            self._detect_anomaly(
                "Suspicious Port Activity",
                f"Multiple unique ports detected: {unique_ports} ports",
                "High"
            )
        
        # 3. Check for suspicious states
        suspicious_states = ['SYN_SENT', 'SYN_RECEIVED', 'FIN_WAIT', 'CLOSE_WAIT']
        suspicious_count = 0
        
        for data in self.windows_netstat_data[-5:]:
            for conn in data.get('connections', []):
                state = conn.get('state', '').upper()
                if any(susp_state in state for susp_state in suspicious_states):
                    suspicious_count += 1
        
        if suspicious_count > 20:
            self._detect_anomaly(
                "Suspicious Connection States",
                f"Multiple connections in suspicious states: {suspicious_count}",
                "Medium"
            )
    
    def _get_cmd_path(self):
        """Get path to cmd.exe in WSL2"""
        cmd_paths = [
            '/mnt/c/Windows/System32/cmd.exe',
            '/mnt/c/Windows/SysWOW64/cmd.exe',
        ]
        
        for path in cmd_paths:
            if os.path.exists(path):
                return path
        return None
    
    def _sniff_traffic(self, interface, duration):
        """Sniff network traffic using Scapy (Linux mode)"""
        try:
            if not SCAPY_AVAILABLE:
                raise Exception("Scapy not available")
            
            end_time = time.time() + duration
            
            def packet_handler(packet):
                if time.time() > end_time or not self.is_monitoring:
                    return False
                
                self._process_packet(packet)
                return True
            
            # Start sniffing
            if interface and interface != 'any':
                sniff(iface=interface, prn=packet_handler, store=0, timeout=duration)
            else:
                sniff(prn=packet_handler, store=0, timeout=duration)
                
        except Exception as e:
            print(f"Sniffing error: {e}")
        finally:
            self.is_monitoring = False
    
    def _process_packet(self, packet):
        """Process individual packet (Linux mode)"""
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
            'packet_count': self.packet_count,
            'mode': self.detection_mode
        }
        
        # Avoid duplicate alerts within 5 seconds
        if not any(a['type'] == anomaly_type and 
                  (datetime.now() - datetime.fromisoformat(a['timestamp'])).seconds < 5
                  for a in self.anomalies):
            self.anomalies.append(anomaly)
            print(f"🚨 {anomaly_type}: {description}")
    
    def _analyze_traffic(self, duration):
        """Analyze traffic patterns (Linux mode)"""
        time.sleep(duration)
        self._generate_statistics()
    
    def _analyze_windows_traffic(self, duration):
        """Analyze Windows traffic patterns"""
        import time  # <-- Add this
    
        try:
            time.sleep(duration + 2)  # Add buffer
            self._generate_statistics()
        except Exception as e:
            print(f"Windows analysis error: {e}")
    
    def _generate_statistics(self):
        """Generate traffic statistics"""
        if not self.stats['timestamps']:
            # For Windows mode, we might have data in windows_netstat_data
            if self.windows_netstat_data:
                total_conns = sum(d.get('total_connections', 0) for d in self.windows_netstat_data)
                self.stats['total_packets'] = total_conns
            else:
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
                'detection_mode': self.detection_mode,
                'windows_connections': len(self.windows_netstat_data) if hasattr(self, 'windows_netstat_data') else 0
            },
            'anomalies': self.anomalies,
            'monitoring_duration': len(self.stats['timestamps']),
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'end_time': datetime.now().isoformat(),
            'mode': self.detection_mode
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
        self.windows_netstat_data = []
        self.windows_perfmon_data = []
    
    def stop_monitoring(self):
        """Stop traffic monitoring"""
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=2)
    
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
        try:
            fig, axes = plt.subplots(2, 2, figsize=(12, 8))
            fig.suptitle(f'Network Traffic Analysis ({self.detection_mode} mode)', fontsize=16)
            
            if self.detection_mode == "windows" and self.windows_netstat_data:
                # Windows-specific graphs
                # 1. Connection count over time
                times = [d['timestamp'] for d in self.windows_netstat_data]
                conn_counts = [d['total_connections'] for d in self.windows_netstat_data]
                
                axes[0, 0].plot(times, conn_counts, marker='o')
                axes[0, 0].set_title('Active Connections Over Time')
                axes[0, 0].set_xlabel('Time')
                axes[0, 0].set_ylabel('Connections')
                axes[0, 0].grid(True, alpha=0.3)
                axes[0, 0].tick_params(axis='x', rotation=45)
                
                # 2. Protocol distribution from netstat
                protocol_counts = defaultdict(int)
                for data in self.windows_netstat_data:
                    for conn in data.get('connections', []):
                        protocol_counts[conn.get('protocol', 'UNKNOWN')] += 1
                
                if protocol_counts:
                    axes[0, 1].bar(protocol_counts.keys(), protocol_counts.values())
                    axes[0, 1].set_title('Protocol Distribution (Netstat)')
                    axes[0, 1].set_xlabel('Protocol')
                    axes[0, 1].set_ylabel('Count')
                
                # 3. Connection states
                state_counts = defaultdict(int)
                for data in self.windows_netstat_data:
                    for conn in data.get('connections', []):
                        state_counts[conn.get('state', 'UNKNOWN')] += 1
                
                if len(state_counts) <= 10:  # Only show if not too many states
                    axes[1, 0].bar(state_counts.keys(), state_counts.values())
                    axes[1, 0].set_title('Connection States')
                    axes[1, 0].set_xlabel('State')
                    axes[1, 0].set_ylabel('Count')
                    axes[1, 0].tick_params(axis='x', rotation=45)
                
                # 4. Port activity heatmap (simplified)
                port_activity = defaultdict(int)
                for data in self.windows_netstat_data:
                    for conn in data.get('connections', []):
                        if ':' in conn.get('local_address', ''):
                            port = conn['local_address'].split(':')[1]
                            if port.isdigit():
                                port_activity[int(port)] += 1
                
                if port_activity:
                    top_ports = sorted(port_activity.items(), key=lambda x: x[1], reverse=True)[:10]
                    ports = [str(p[0]) for p in top_ports]
                    counts = [p[1] for p in top_ports]
                    
                    axes[1, 1].bar(ports, counts)
                    axes[1, 1].set_title('Top Port Activity')
                    axes[1, 1].set_xlabel('Port')
                    axes[1, 1].set_ylabel('Activity Count')
                    axes[1, 1].tick_params(axis='x', rotation=45)
            
            else:
                # Linux mode graphs (original)
                if self.stats['timestamps']:
                    # 1. Packet rate over time
                    times = pd.to_datetime(self.stats['timestamps'])
                    time_series = pd.Series(1, index=times)
                    resampled = time_series.resample('1S').sum()
                    
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
        
        summary.append(f"Detection Mode: {self.detection_mode}")
        for severity in ['Critical', 'High', 'Medium', 'Low']:
            if severity in by_severity:
                summary.append(f"{severity}: {len(by_severity[severity])} anomalies")
                for anomaly in by_severity[severity][:2]:  # Show first 2 of each
                    summary.append(f"  - {anomaly['type']}")
        
        return "\n".join(summary)

if __name__ == "__main__":
    detector = AnomalyDetector()
    print("🚨 Anomaly Detection Module - Ready for integration")