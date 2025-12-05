#!/usr/bin/env python3
"""
WiFi Scanner Module with WSL2/Windows support
By: Devon Mann
Part of IT359 Network Security Scanner Project
"""

import subprocess
import threading
import time
import json
import os
import re
from datetime import datetime
import tempfile
import xml.etree.ElementTree as ET

class WiFiScanner:
    def __init__(self):
        self.is_scanning = False
        self.scan_process = None
        self.scan_results = {}
        self.temp_files = []
        self.scan_mode = "auto"  # auto, linux, windows
        
    def detect_environment(self):
        """Detect if we're running in WSL2 or native Linux"""
        try:
            with open('/proc/version', 'r') as f:
                if 'microsoft' in f.read().lower():
                    return "wsl2"
            return "linux"
        except:
            return "linux"  # Default to linux
    
    def set_scan_mode(self, mode):
        """Set scan mode: auto, linux, windows"""
        self.scan_mode = mode
    
    def check_dependencies(self):
        """Check if required tools are installed based on scan mode"""
        env = self.detect_environment()
        mode = self.scan_mode
    
        if mode == "auto":
            mode = "windows" if env == "wsl2" else "linux"
    
        if mode == "linux":
            required_tools = ['airmon-ng', 'airodump-ng', 'aircrack-ng', 'airgraph-ng']
            missing_tools = []
        
            for tool in required_tools:
                try:
                    subprocess.run(['which', tool], capture_output=True, check=True)
                except subprocess.CalledProcessError:
                    missing_tools.append(tool)
        
            return missing_tools
        
        else:  # windows mode - TEST CMD.EXE ACCESS
            missing_tools = []
        
        # Check if we can access cmd.exe
            cmd_paths = [
                '/mnt/c/Windows/System32/cmd.exe',
                '/mnt/c/Windows/SysWOW64/cmd.exe',
                'cmd.exe'  # Try without path as well
            ]
        
            cmd_found = False
            for cmd_path in cmd_paths:
                if os.path.exists(cmd_path):
                    cmd_found = True
                    try:
                    # Test if cmd.exe works
                        result = subprocess.run(
                            [cmd_path, '/c', 'echo', 'test'], 
                            capture_output=True, text=True, timeout=5
                        )
                        if result.returncode == 0:
                            return []  # No missing tools
                        else:
                            missing_tools.append(f'cmd.exe (exists but not working)')
                            break
                    except Exception as e:
                        missing_tools.append(f'cmd.exe ({str(e)[:50]})')
                        break
        
            if not cmd_found:
                missing_tools.append('Windows cmd.exe (not found in WSL2)')
        
            return missing_tools
    
    def get_interface_list(self):
        """Get list of available wireless interfaces based on scan mode"""
        env = self.detect_environment()
        mode = self.scan_mode
    
        if mode == "auto":
            mode = "windows" if env == "wsl2" else "linux"
    
        interfaces = []
    
        if mode == "linux":
        # Native Linux interface detection
            try:
                result = subprocess.run(['iwconfig'], capture_output=True, text=True)
                for line in result.stdout.split('\n'):
                    if 'IEEE 802.11' in line and 'no wireless' not in line:
                        iface = line.split()[0]
                        interfaces.append(iface)
            
            # Fallback to common names
                if not interfaces:
                    common_interfaces = ['wlan0', 'wlan1', 'wlp2s0', 'wlp3s0']
                    for iface in common_interfaces:
                        interfaces.append(f"{iface} (Linux)")
                    
            except Exception as e:
                print(f"Linux interface detection error: {e}")
            
        else:  # windows mode - USE FULL PATH TO CMD.EXE
        # Windows interface detection via WSL2
            try:
            # Use full path to cmd.exe
                cmd_path = '/mnt/c/Windows/System32/cmd.exe'
                if not os.path.exists(cmd_path):
                    cmd_path = '/mnt/c/Windows/SysWOW64/cmd.exe'  # Alternative path
            
                if os.path.exists(cmd_path):
                    result = subprocess.run(
                        [cmd_path, '/c', 'netsh', 'wlan', 'show', 'interfaces'], 
                        capture_output=True, text=True, timeout=10
                    )
                
                    if result.returncode == 0 and result.stdout:
                        lines = result.stdout.split('\n')
                        for line in lines:
                            line = line.strip()
                            if 'Name' in line and ':' in line:
                                iface_name = line.split(':', 1)[1].strip()
                                if iface_name:
                                    interfaces.append(f"{iface_name} (Windows)")
                    
                        if not interfaces:
                            interfaces.append(f"Wi-Fi (Windows)")
                    else:
                        interfaces.append(f"Wi-Fi (Windows)")
                else:
                # cmd.exe not found at expected locations
                    interfaces.append(f"Wi-Fi (Windows) - (cmd.exe not found)")
                
            except Exception as e:
                print(f"Windows interface detection error: {e}")
                interfaces.append(f"Wi-Fi (Windows)")
    
        return interfaces if interfaces else ['Wi-Fi (Windows)']
    
    def scan_networks(self, interface, duration=30):
        """Perform WiFi network scan using appropriate method"""
        env = self.detect_environment()
        mode = self.scan_mode
        
        if mode == "auto":
            mode = "windows" if env == "wsl2" else "linux"
        
        if mode == "linux":
            return self._scan_linux(interface, duration)
        else:
            return self._scan_windows(interface, duration)
    
    def _scan_linux(self, interface, duration=30):
        """Original Linux scanning method"""
        self.is_scanning = True
        
        # Remove (Linux) suffix if present
        interface = interface.replace(' (Linux)', '')
        
        # Create temporary output file
        output_file = tempfile.NamedTemporaryFile(prefix='airodump_', suffix='.csv', delete=False)
        output_file.close()
        self.temp_files.append(output_file.name)
        
        try:
            # Start monitor mode
            monitor_interface = self.start_monitor_mode(interface)
            if not monitor_interface:
                raise Exception("Failed to start monitor mode")
            
            # Start airodump-ng scan
            cmd = [
                'airodump-ng',
                '--write-interval', '2',
                '--output-format', 'csv',
                '--write', output_file.name.replace('.csv', ''),
                monitor_interface
            ]
            
            self.scan_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            
            # Let it run for specified duration
            start_time = time.time()
            while time.time() - start_time < duration and self.is_scanning:
                time.sleep(1)
                
                if os.path.exists(output_file.name):
                    self._parse_airodump_results(output_file.name)
            
            # Stop the scan
            self.stop_scan()
            
            # Stop monitor mode
            self.stop_monitor_mode(monitor_interface)
            
            # Final parse of results
            if os.path.exists(output_file.name):
                networks, clients = self._parse_airodump_results(output_file.name)
                self.scan_results['networks'] = networks
                self.scan_results['clients'] = clients
                self.scan_results['timestamp'] = datetime.now().isoformat()
                self.scan_results['mode'] = 'linux'
                
                return networks, clients
            
            return [], []
            
        except Exception as e:
            self.is_scanning = False
            raise e
    
    def _scan_windows(self, interface, duration=30):
        """Windows scanning method using netsh"""
        self.is_scanning = True
    
    # Remove (Windows) suffix if present
        interface = interface.replace(' (Windows)', '')
    
        try:
            networks = []
            clients = []
        
        # Find cmd.exe path
            cmd_path = '/mnt/c/Windows/System32/cmd.exe'
            if not os.path.exists(cmd_path):
                cmd_path = '/mnt/c/Windows/SysWOW64/cmd.exe'
        
            if not os.path.exists(cmd_path):
                raise Exception("cmd.exe not found in WSL2. Enable WSL interop.")
        
        # Get connected network info
            self.log_wifi_result(f"Getting WiFi information...")
        
        # Method 1: Get current connection info
            result = subprocess.run(
                [cmd_path, '/c', 'netsh', 'wlan', 'show', 'interfaces'], 
                capture_output=True, text=True, timeout=10
            )
        
            if result.returncode == 0 and result.stdout:
            # Parse the output for network info
                lines = result.stdout.split('\n')
                current_network = {}
            
                for line in lines:
                    line = line.strip()
                    if 'SSID' in line and ':' in line and 'BSSID' not in line:
                        essid = line.split(':', 1)[1].strip()
                        if essid:
                            current_network['essid'] = essid
                            current_network['bssid'] = 'Connected'
                            current_network['channel'] = 'Connected'
                            current_network['power'] = 'Connected'
                            current_network['privacy'] = 'Connected'
                            current_network['first_seen'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                            current_network['last_seen'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        
                            networks.append(current_network)
                            break
            
                if networks:
                    self.log_wifi_result(f"Found connected network: {networks[0].get('essid', 'Unknown')}")
        
        # Method 2: Try to get available networks (may require admin rights)
            try:
                scan_result = subprocess.run(
                    [cmd_path, '/c', 'netsh', 'wlan', 'show', 'networks'], 
                    capture_output=True, text=True, timeout=10
                )
            
                if scan_result.returncode == 0 and scan_result.stdout:
                # Simple parsing for available networks
                    lines = scan_result.stdout.split('\n')
                    current_essid = None
                
                    for line in lines:
                        line = line.strip()
                        if 'SSID' in line and ':' in line and 'BSSID' not in line:
                            essid = line.split(':', 1)[1].strip()
                            if essid and essid != networks[0].get('essid', ''):
                                networks.append({
                                    'essid': essid,
                                    'bssid': 'Available',
                                    'channel': 'Unknown',
                                    'power': 'Unknown',
                                    'privacy': 'Unknown',
                                    'first_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                    'last_seen': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                                })
            except Exception as e:
                self.log_wifi_result(f"Note: Could not scan all networks: {e}")
        
        # Get ARP table for clients
            try:
                client_result = subprocess.run(['arp', '-a'], capture_output=True, text=True)
                if client_result.returncode == 0:
                    for line in client_result.stdout.split('\n'):
                        if 'dynamic' in line.lower():
                            parts = line.split()
                            if len(parts) >= 2:
                                clients.append({
                                    'station_mac': parts[1],
                                    'bssid': 'LAN',
                                    'power': 'Unknown',
                                    'packets': 'Unknown'
                                })
            except Exception as e:
                self.log_wifi_result(f"ARP scan note: {e}")
        
            self.scan_results['networks'] = networks
            self.scan_results['clients'] = clients
            self.scan_results['timestamp'] = datetime.now().isoformat()
            self.scan_results['mode'] = 'windows'
        
            self.is_scanning = False
            return networks, clients
        
        except Exception as e:
            self.is_scanning = False
            raise Exception(f"Windows scan failed: {e}")
    
    def _parse_netsh_results(self, output):
        """Parse Windows netsh wlan show networks results"""
        networks = []
    
    # Split by "SSID" to find each network section
        sections = re.split(r'SSID\s*\d+\s*:', output)
    
        for section in sections[1:]:  # Skip first section (header)
            network = {}
            lines = section.split('\n')
        
            for line in lines:
                line = line.strip()
            
                if ':' in line:
                    key, value = line.split(':', 1)
                    key = key.strip()
                    value = value.strip()
                
                    if key == 'Network type':
                    # This is the network name line (comes after SSID #)
                        if 'essid' not in network and value:
                        # Extract ESSID from previous lines
                            for prev_line in lines[:3]:
                                if prev_line.strip() and ':' not in prev_line:
                                    network['essid'] = prev_line.strip()
                                    break
                
                    elif key == 'BSSID':
                        network['bssid'] = value
                
                    elif key == 'Signal':
                        signal = value.replace('%', '')
                        try:
                            signal_pct = int(signal)
                            approx_dbm = -20 - ((100 - signal_pct) * 0.8)
                            network['power'] = f"{approx_dbm:.1f}"
                        except:
                            network['power'] = signal
                
                    elif key == 'Channel':
                        network['channel'] = value
                
                    elif key == 'Authentication':
                        network['privacy'] = value
        
        # If we found an ESSID, add the network
            if 'essid' in network and network['essid']:
            # Add missing fields
                network['first_seen'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                network['last_seen'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                if 'bssid' not in network:
                    network['bssid'] = 'Unknown'
                if 'channel' not in network:
                    network['channel'] = 'Unknown'
                if 'power' not in network:
                    network['power'] = 'Unknown'
                if 'privacy' not in network:
                    network['privacy'] = 'Unknown'
            
                networks.append(network)
    
        return networks
    
    def _parse_arp_results(self, output):
        """Parse ARP table for client information"""
        clients = []
        
        for line in output.split('\n'):
            if 'dynamic' in line.lower() or 'static' in line.lower():
                parts = line.split()
                if len(parts) >= 2:
                    clients.append({
                        'station_mac': parts[1],
                        'bssid': 'LAN',
                        'power': 'Unknown',
                        'packets': 'Unknown'
                    })
        
        return clients
    
    def _parse_connected_network(self, output):
        """Parse connected network information from netsh wlan show interfaces"""
        network = {}
    
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
        
            if 'SSID' in line and ':' in line and 'BSSID' not in line:
                essid = line.split(':', 1)[1].strip()
                if essid:
                    network['essid'] = essid
        
            elif 'AP BSSID' in line and ':' in line:
                bssid = line.split(':', 1)[1].strip()
                if bssid:
                    network['bssid'] = bssid
        
            elif 'Signal' in line and ':' in line:
                signal = line.split(':', 1)[1].strip().replace('%', '')
                try:
                    signal_pct = int(signal)
                # Convert to dBm: 100% ≈ -20 dBm, 0% ≈ -100 dBm
                    approx_dbm = -20 - ((100 - signal_pct) * 0.8)
                    network['power'] = f"{approx_dbm:.1f}"
                except:
                    network['power'] = signal
        
            elif 'Channel' in line and ':' in line:
                channel = line.split(':', 1)[1].strip()
                network['channel'] = channel
        
            elif 'Authentication' in line and ':' in line:
                auth = line.split(':', 1)[1].strip()
                network['privacy'] = auth
    
    # Add required fields
        if 'essid' in network:
            network['first_seen'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            network['last_seen'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            if 'bssid' not in network:
                network['bssid'] = 'Unknown'
            if 'channel' not in network:
                network['channel'] = 'Unknown'
            if 'power' not in network:
                network['power'] = 'Unknown'
            if 'privacy' not in network:
                network['privacy'] = 'Unknown'
        
            return network
    
        return None

    # KEEP ALL YOUR EXISTING METHODS BELOW - they should still work
    def start_monitor_mode(self, interface='wlan0'):
        """Put wireless interface into monitor mode"""
        try:
            # Stop interfering processes
            subprocess.run(['airmon-ng', 'check', 'kill'], capture_output=True)
            
            # Start monitor mode
            result = subprocess.run(['airmon-ng', 'start', interface], 
                                  capture_output=True, text=True)
            
            if 'monitor mode' in result.stdout.lower():
                # Extract monitor interface name
                monitor_iface = f"{interface}mon"
                if not os.path.exists(f"/sys/class/net/{monitor_iface}"):
                    # Try other common naming conventions
                    for iface in os.listdir('/sys/class/net'):
                        if 'mon' in iface:
                            monitor_iface = iface
                            break
                return monitor_iface
            return None
            
        except Exception as e:
            raise Exception(f"Failed to start monitor mode: {e}")
    
    def stop_monitor_mode(self, monitor_interface):
        """Stop monitor mode and restore interface"""
        try:
            subprocess.run(['airmon-ng', 'stop', monitor_interface], capture_output=True)
            subprocess.run(['systemctl', 'restart', 'NetworkManager'], capture_output=True)
            return True
        except Exception as e:
            raise Exception(f"Failed to stop monitor mode: {e}")
    
    def _parse_airodump_results(self, csv_file):
        """Parse airodump-ng CSV output file"""
        networks = []
        clients = []
        
        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Split into network and client sections
            sections = content.split('\n\n')
            
            if len(sections) >= 1:
                # Parse networks
                network_lines = sections[0].strip().split('\n')
                for line in network_lines[1:]:  # Skip header
                    if line.strip() and not line.startswith('Station MAC'):
                        parts = line.split(',')
                        if len(parts) >= 14:
                            network = {
                                'bssid': parts[0].strip(),
                                'first_seen': parts[1].strip(),
                                'last_seen': parts[2].strip(),
                                'channel': parts[3].strip(),
                                'speed': parts[4].strip(),
                                'privacy': parts[5].strip(),
                                'cipher': parts[6].strip(),
                                'authentication': parts[7].strip(),
                                'power': parts[8].strip(),
                                'beacons': parts[9].strip(),
                                'iv': parts[10].strip(),
                                'lan_ip': parts[11].strip(),
                                'id_length': parts[12].strip(),
                                'essid': parts[13].strip().strip('"')
                            }
                            networks.append(network)
            
            if len(sections) >= 2:
                # Parse clients
                client_lines = sections[1].strip().split('\n')
                for line in client_lines[1:]:  # Skip header
                    if line.strip():
                        parts = line.split(',')
                        if len(parts) >= 6:
                            client = {
                                'station_mac': parts[0].strip(),
                                'first_seen': parts[1].strip(),
                                'last_seen': parts[2].strip(),
                                'power': parts[3].strip(),
                                'packets': parts[4].strip(),
                                'bssid': parts[5].strip(),
                                'probed_essids': parts[6].strip().strip('"') if len(parts) > 6 else ''
                            }
                            clients.append(client)
            
            return networks, clients
            
        except Exception as e:
            print(f"Error parsing airodump results: {e}")
            return networks, clients
    
    def generate_network_graph(self, graph_type='capr'):
        """Generate network graph using airgraph-ng"""
        if not self.scan_results.get('networks'):
            raise Exception("No scan results available. Please run a scan first.")
        
        # Only works with Linux scan results
        if self.scan_results.get('mode') != 'linux':
            raise Exception("Network graphs only available with Linux native scanning")
        
        try:
            # Create input file for airgraph-ng
            input_file = tempfile.NamedTemporaryFile(prefix='airgraph_', suffix='.csv', delete=False, mode='w')
            
            # Write network data in format expected by airgraph-ng
            for network in self.scan_results['networks']:
                line = f"{network['bssid']},{network['power']},{network['beacons']},{network['essid']}\n"
                input_file.write(line)
            
            input_file.close()
            self.temp_files.append(input_file.name)
            
            # Generate graph
            output_file = tempfile.NamedTemporaryFile(prefix='network_graph_', suffix='.png', delete=False)
            output_file.close()
            self.temp_files.append(output_file.name)
            
            cmd = [
                'airgraph-ng',
                '-i', input_file.name,
                '-o', output_file.name,
                '-g', graph_type
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0 and os.path.exists(output_file.name):
                return output_file.name
            else:
                raise Exception(f"Airgraph-ng failed: {result.stderr}")
                
        except Exception as e:
            raise Exception(f"Failed to generate network graph: {e}")
    
    def generate_client_graph(self):
        """Generate client-access point relationship graph"""
        if not self.scan_results.get('networks') or not self.scan_results.get('clients'):
            raise Exception("No client data available.")
        
        # Only works with Linux scan results
        if self.scan_results.get('mode') != 'linux':
            raise Exception("Client graphs only available with Linux native scanning")
        
        try:
            # Create input file for airgraph-ng
            input_file = tempfile.NamedTemporaryFile(prefix='client_graph_', suffix='.csv', delete=False, mode='w')
            
            # Write client-AP relationships
            for client in self.scan_results['clients']:
                if client['bssid'] != '(not associated)':
                    line = f"{client['station_mac']},{client['bssid']}\n"
                    input_file.write(line)
            
            input_file.close()
            self.temp_files.append(input_file.name)
            
            # Generate graph
            output_file = tempfile.NamedTemporaryFile(prefix='client_graph_', suffix='.png', delete=False)
            output_file.close()
            self.temp_files.append(output_file.name)
            
            cmd = [
                'airgraph-ng',
                '-i', input_file.name,
                '-o', output_file.name,
                '-g', 'cpg'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0 and os.path.exists(output_file.name):
                return output_file.name
            else:
                raise Exception(f"Airgraph-ng failed: {result.stderr}")
                
        except Exception as e:
            raise Exception(f"Failed to generate client graph: {e}")
    
    def stop_scan(self):
        """Stop current scan"""
        self.is_scanning = False
        if self.scan_process:
            self.scan_process.terminate()
            try:
                self.scan_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.scan_process.kill()
    
    def cleanup(self):
        """Clean up temporary files"""
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    os.unlink(temp_file)
            except:
                pass
        self.temp_files = []

    def log_wifi_result(self, message):
        """Log messages from within the scanner - used for Windows mode"""
        print(f"WiFiScanner: {message}")
    
    def save_results(self, filename=None):
        """Save scan results to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"wifi_scan_results_{timestamp}.json"
        
        with open(f"data/{filename}", 'w') as f:
            json.dump(self.scan_results, f, indent=2)
        
        return f"data/{filename}"

# For standalone testing
if __name__ == "__main__":
    scanner = WiFiScanner()
    print("📡 WiFi Scanner Module - Ready for integration")