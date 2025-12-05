#!/usr/bin/env python3
"""
Network Scanner Module
By: Devon Mann
Part of IT359 Network Security Scanner Project
"""

import nmap
import json
from datetime import datetime

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
        self.scan_results = {}
        self.is_scanning = False
    
    def basic_scan(self, target='192.168.1.0/24'):
        """Perform basic network discovery scan"""
        self.is_scanning = True
        
        try:
            # Simple ping scan to find active hosts
            self.nm.scan(hosts=target, arguments='-sn')
            
            active_hosts = []
            for host in self.nm.all_hosts():
                if not self.is_scanning:
                    break
                if self.nm[host].state() == 'up':
                    host_info = {
                        'ip': host,
                        'hostname': self.nm[host].hostname(),
                        'status': self.nm[host].state()
                    }
                    active_hosts.append(host_info)
            
            self.scan_results['basic_scan'] = {
                'timestamp': datetime.now().isoformat(),
                'target': target,
                'active_hosts': active_hosts
            }
            
            self.is_scanning = False
            return active_hosts
            
        except Exception as e:
            self.is_scanning = False
            raise e
    
    def detailed_scan(self, target='192.168.1.0/24'):
        """Perform detailed port and service scan"""
        self.is_scanning = True
        
        try:
            # Comprehensive scan with OS and service detection
            scan_args = '-sS -O -sV --version-intensity 5'
            self.nm.scan(hosts=target, arguments=scan_args)
            
            detailed_results = []
            for host in self.nm.all_hosts():
                if not self.is_scanning:
                    break
                if self.nm[host].state() == 'up':
                    host_data = {
                        'ip': host,
                        'hostname': self.nm[host].hostname(),
                        'status': self.nm[host].state(),
                        'ports': []
                    }
                    
                    # Get OS information
                    if 'osmatch' in self.nm[host]:
                        host_data['os_guess'] = self.nm[host]['osmatch'][0]['name'] if self.nm[host]['osmatch'] else 'Unknown'
                    
                    # Get open ports and services
                    for proto in self.nm[host].all_protocols():
                        ports = self.nm[host][proto].keys()
                        for port in ports:
                            port_info = self.nm[host][proto][port]
                            host_data['ports'].append({
                                'protocol': proto,
                                'port': port,
                                'state': port_info['state'],
                                'service': port_info['name'],
                                'version': port_info.get('version', 'Unknown'),
                                'product': port_info.get('product', 'Unknown')
                            })
                    
                    detailed_results.append(host_data)
            
            self.scan_results['detailed_scan'] = {
                'timestamp': datetime.now().isoformat(),
                'target': target,
                'hosts': detailed_results
            }
            
            self.is_scanning = False
            return detailed_results
            
        except Exception as e:
            self.is_scanning = False
            raise e
    
    def scan_specific_host(self, host_ip):
        """Scan a specific host in detail"""
        return self.detailed_scan(host_ip)
    
    def save_results(self, filename=None):
        """Save scan results to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"scan_results_{timestamp}.json"
        
        with open(f"data/{filename}", 'w') as f:
            json.dump(self.scan_results, f, indent=2)
        
        return f"data/{filename}"
    
    def stop_scan(self):
        """Stop current scan"""
        self.is_scanning = False

# For standalone testing
