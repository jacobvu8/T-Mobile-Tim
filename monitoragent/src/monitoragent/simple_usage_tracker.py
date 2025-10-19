#!/usr/bin/env python
"""
Simple Network Usage Tracker using packet sniffing
This version uses scapy which is more reliable for packet capture
"""
import time
import json
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.live import Live
from collections import defaultdict
from pathlib import Path

try:
    from scapy.all import sniff, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class SimpleUsageTracker:
    def __init__(self):
        self.console = Console()
        self.usage_data = defaultdict(lambda: {
            "total_sent": 0,
            "total_received": 0,
            "packet_count_sent": 0,
            "packet_count_received": 0,
            "hostname": "Unknown",
            "first_seen": None,
            "last_seen": None
        })
        self.data_file = Path("usage_data.json")
        self.my_ip = self.get_my_ip()
        # Auto-detect local network prefix (e.g., "192.168.12" from "192.168.12.119")
        if self.my_ip:
            self.local_network = '.'.join(self.my_ip.split('.')[:-1])
        else:
            self.local_network = "192.168.1"  # fallback
        self.load_data()
    
    def load_data(self):
        """Load previously saved usage data"""
        if self.data_file.exists():
            try:
                with open(self.data_file, 'r') as f:
                    saved_data = json.load(f)
                    for ip, data in saved_data.items():
                        if data.get("first_seen"):
                            try:
                                data["first_seen"] = datetime.fromisoformat(data["first_seen"])
                            except:
                                data["first_seen"] = None
                        if data.get("last_seen"):
                            try:
                                data["last_seen"] = datetime.fromisoformat(data["last_seen"])
                            except:
                                data["last_seen"] = None
                        self.usage_data[ip].update(data)
                self.console.print("[green]Loaded previous usage data[/green]")
            except Exception as e:
                self.console.print(f"[yellow]Could not load previous data: {e}[/yellow]")
    
    def save_data(self):
        """Save usage data to file"""
        try:
            with open(self.data_file, 'w') as f:
                json.dump(dict(self.usage_data), f, indent=2, default=str)
        except Exception as e:
            self.console.print(f"[red]Error saving data: {e}[/red]")
    
    def get_my_ip(self):
        """Get local machine's IP"""
        import socket
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            self.my_ip = s.getsockname()[0]
            s.close()
            return self.my_ip
        except:
            return None
    
    def packet_callback(self, packet):
        """Callback for each captured packet"""
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                packet_size = len(packet)
                current_time = datetime.now()
                
                # Only track local network IPs
                if src_ip.startswith(self.local_network):
                    if self.usage_data[src_ip]["first_seen"] is None:
                        self.usage_data[src_ip]["first_seen"] = current_time
                    
                    self.usage_data[src_ip]["last_seen"] = current_time
                    self.usage_data[src_ip]["total_sent"] += packet_size
                    self.usage_data[src_ip]["packet_count_sent"] += 1
                
                if dst_ip.startswith(self.local_network):
                    if self.usage_data[dst_ip]["first_seen"] is None:
                        self.usage_data[dst_ip]["first_seen"] = current_time
                    
                    self.usage_data[dst_ip]["last_seen"] = current_time
                    self.usage_data[dst_ip]["total_received"] += packet_size
                    self.usage_data[dst_ip]["packet_count_received"] += 1
                    
        except Exception as e:
            pass  # Silently ignore packet errors
    
    def capture_packets(self, duration=30):
        """Capture packets for specified duration"""
        if not SCAPY_AVAILABLE:
            self.console.print("[red]Scapy not installed![/red]")
            self.console.print("[yellow]Install with: pip install scapy[/yellow]")
            return False
        
        try:
            self.console.print(f"[yellow]Capturing packets for {duration} seconds...[/yellow]")
            self.console.print("[yellow]This requires sudo/root access![/yellow]\n")
            
            # Get local IP
            my_ip = self.get_my_ip()
            self.console.print(f"[cyan]Your IP: {my_ip}[/cyan]")
            self.console.print(f"[cyan]Monitoring network: {self.local_network}.x[/cyan]\n")
            
            # Sniff packets
            packets = sniff(
                timeout=duration,
                prn=self.packet_callback,
                store=False,
                filter=f"ip and net {self.local_network}.0/24"
            )
            
            self.console.print(f"[green]Captured packets from {len(self.usage_data)} unique IPs[/green]\n")
            return True
            
        except PermissionError:
            self.console.print("[red]Permission denied! Run with sudo: sudo python simple_usage_tracker.py[/red]")
            return False
        except Exception as e:
            self.console.print(f"[red]Error capturing packets: {e}[/red]")
            return False
    
    def get_hostnames(self):
        """Get hostnames using nmap"""
        try:
            import subprocess
            import re
            
            self.console.print("[cyan]Looking up hostnames (this may take a moment)...[/cyan]")
            
            result = subprocess.run(
                ['nmap', '-sn', '-T4', f'{self.local_network}.0/24'],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            current_ip = None
            for line in result.stdout.splitlines():
                host_match = re.search(r'Nmap scan report for (.+)', line)
                if host_match:
                    host_info = host_match.group(1)
                    ip_match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', host_info)
                    if ip_match:
                        current_ip = ip_match.group(1)
                        hostname = host_info.split('(')[0].strip()
                        if current_ip in self.usage_data:
                            self.usage_data[current_ip]["hostname"] = hostname
        except Exception as e:
            self.console.print(f"[yellow]Could not resolve hostnames: {e}[/yellow]")
    
    def format_bytes(self, bytes_val):
        """Format bytes to human readable format"""
        bytes_val = float(bytes_val)
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.2f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.2f} PB"
    
    def create_usage_table(self):
        """Create a rich table with usage information"""
        table = Table(
            title=f"📊 Network Usage Tracker - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            show_header=True,
            header_style="bold magenta",
            border_style="blue"
        )
        
        table.add_column("IP Address", style="green")
        table.add_column("Hostname", style="cyan")
        table.add_column("Sent", style="yellow", justify="right")
        table.add_column("Received", style="yellow", justify="right")
        table.add_column("Total", style="bold red", justify="right")
        table.add_column("Packets", style="blue", justify="right")
        table.add_column("Last Seen", style="blue")
        
        # Sort by total usage
        sorted_ips = sorted(
            self.usage_data.items(),
            key=lambda x: x[1]["total_sent"] + x[1]["total_received"],
            reverse=True
        )
        
        for ip, data in sorted_ips:
            total_bytes = data["total_sent"] + data["total_received"]
            if total_bytes == 0:
                continue
            
            total_packets = data["packet_count_sent"] + data["packet_count_received"]
            
            if data["last_seen"]:
                if isinstance(data["last_seen"], datetime):
                    last_seen = data["last_seen"].strftime("%H:%M:%S")
                else:
                    last_seen = str(data["last_seen"])[:8]
            else:
                last_seen = "Never"
            
            table.add_row(
                ip,
                data["hostname"][:20],
                self.format_bytes(data["total_sent"]),
                self.format_bytes(data["total_received"]),
                self.format_bytes(total_bytes),
                str(total_packets),
                last_seen
            )
        
        if not sorted_ips or all(d[1]["total_sent"] + d[1]["total_received"] == 0 for d in sorted_ips):
            table.add_row("No usage data", "-", "-", "-", "-", "-", "-")
        
        return table
    
    def monitor_once(self, duration=30):
        """Track usage once and display"""
        self.console.print("[bold cyan]Starting Network Usage Capture...[/bold cyan]\n")
        
        # Capture packets
        success = self.capture_packets(duration)
        if not success:
            return
        
        # Get hostnames
        self.get_hostnames()
        
        # Display table
        table = self.create_usage_table()
        self.console.print("\n")
        self.console.print(table)
        
        # Save data
        self.save_data()
        self.console.print(f"\n[dim]Data saved to: {self.data_file.absolute()}[/dim]")
        
        # Show summary
        total_ips = len([ip for ip, data in self.usage_data.items() 
                        if data["total_sent"] + data["total_received"] > 0])
        self.console.print(f"[green]Tracked {total_ips} active devices[/green]")
    
    def monitor_continuous(self, refresh_interval=30):
        """Continuously monitor usage"""
        self.console.print("[bold green]Starting Continuous Network Monitoring...[/bold green]")
        self.console.print(f"Capture interval: {refresh_interval} seconds")
        self.console.print("Press Ctrl+C to stop\n")
        
        try:
            while True:
                # Capture packets
                success = self.capture_packets(refresh_interval)
                if not success:
                    break
                
                # Get hostnames periodically
                self.get_hostnames()
                
                # Display table
                self.console.clear()
                table = self.create_usage_table()
                self.console.print(table)
                
                # Save data
                self.save_data()
                
                self.console.print(f"\n[dim]Next capture starting...[/dim]")
        
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Monitoring stopped by user[/yellow]")
            self.save_data()
            self.console.print("[green]Usage data saved![/green]")


if __name__ == "__main__":
    import sys
    
    tracker = SimpleUsageTracker()
    
    if len(sys.argv) > 1 and sys.argv[1] == "--continuous":
        refresh_interval = int(sys.argv[2]) if len(sys.argv) > 2 else 30
        tracker.monitor_continuous(refresh_interval)
    else:
        duration = int(sys.argv[1]) if len(sys.argv) > 1 else 30
        tracker.monitor_once(duration)