import subprocess
import re
import time
from datetime import datetime
from rich.console import Console
from rich.table import Table
from rich.live import Live
from collections import defaultdict
import socket

class NetworkMonitor:
    def __init__(self):
        self.console = Console()
        self.device_history = defaultdict(lambda: {"first_seen": None, "last_seen": None, "status": "offline"})
    
    def get_local_network(self):
        """Get the local network IP range"""
        try:
            # Get local IP address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            # Convert to network range (assumes /24 subnet)
            ip_parts = local_ip.split('.')
            network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            self.console.print(f"[cyan]Local IP: {local_ip}[/cyan]")
            self.console.print(f"[cyan]Scanning network: {network}[/cyan]\n")
            
            return network
        except Exception as e:
            self.console.print(f"[yellow]Could not detect network, using default 192.168.1.0/24[/yellow]")
            return "192.168.1.0/24"
    
    def scan_network(self):
        """Scan the network for connected devices using nmap"""
        try:
            network = self.get_local_network()
            
            self.console.print("[yellow]Running nmap scan (this may take 10-30 seconds)...[/yellow]")
            
            # Run nmap with fast scan and OS detection
            # -sn: Ping scan (no port scan)
            # -T4: Faster timing
            result = subprocess.run(
                ['nmap', '-sn', '-T4', network], 
                capture_output=True, 
                text=True,
                timeout=60
            )
            
            self.console.print("[green]Scan complete! Parsing results...[/green]\n")
            
            lines = result.stdout.splitlines()
            devices = []
            current_time = datetime.now()
            
            current_host = None
            current_ip = None
            current_mac = None
            
            for line in lines:
                # Match "Nmap scan report for hostname (ip)" or "Nmap scan report for ip"
                host_match = re.search(r'Nmap scan report for (.+)', line)
                if host_match:
                    host_info = host_match.group(1)
                    
                    # Extract IP and hostname
                    ip_match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', host_info)
                    if ip_match:
                        current_ip = ip_match.group(1)
                        current_host = host_info.split('(')[0].strip()
                    else:
                        # Just IP, no hostname
                        ip_only_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', host_info)
                        if ip_only_match:
                            current_ip = ip_only_match.group(1)
                            current_host = "Unknown"
                    
                    current_mac = None
                
                # Match "MAC Address: XX:XX:XX:XX:XX:XX (Vendor)"
                mac_match = re.search(r'MAC Address: ([0-9A-Fa-f:]+)\s*(\((.+)\))?', line)
                if mac_match and current_ip:
                    current_mac = mac_match.group(1)
                    vendor = mac_match.group(3) if mac_match.group(3) else "Unknown Vendor"
                    
                    self.console.print(f"[green]✓ Found: {current_host} - {current_ip} - {current_mac} ({vendor})[/green]")
                    
                    # Track device history
                    device_key = f"{current_ip}_{current_mac}"
                    if self.device_history[device_key]["first_seen"] is None:
                        self.device_history[device_key]["first_seen"] = current_time
                    
                    self.device_history[device_key]["last_seen"] = current_time
                    self.device_history[device_key]["status"] = "online"
                    
                    devices.append({
                        "Hostname": current_host if current_host != current_ip else "Unknown",
                        "IP": current_ip,
                        "MAC": current_mac,
                        "Vendor": vendor,
                        "First Seen": self.device_history[device_key]["first_seen"].strftime("%H:%M:%S"),
                        "Last Seen": current_time.strftime("%H:%M:%S"),
                        "Status": "🟢 Online"
                    })
                    
                    current_host = None
                    current_ip = None
                    current_mac = None
                
                # If we found a host but no MAC (could be the gateway/router)
                if 'Host is up' in line and current_ip and not current_mac:
                    self.console.print(f"[blue]✓ Found: {current_host} - {current_ip} (No MAC - likely router/gateway)[/blue]")
                    
                    device_key = f"{current_ip}_no_mac"
                    if self.device_history[device_key]["first_seen"] is None:
                        self.device_history[device_key]["first_seen"] = current_time
                    
                    self.device_history[device_key]["last_seen"] = current_time
                    self.device_history[device_key]["status"] = "online"
                    
                    devices.append({
                        "Hostname": current_host if current_host != current_ip else "Gateway/Router",
                        "IP": current_ip,
                        "MAC": "N/A",
                        "Vendor": "Local Gateway",
                        "First Seen": self.device_history[device_key]["first_seen"].strftime("%H:%M:%S"),
                        "Last Seen": current_time.strftime("%H:%M:%S"),
                        "Status": "🟢 Online"
                    })
                    
                    current_host = None
                    current_ip = None
            
            self.console.print(f"\n[bold green]Total devices found: {len(devices)}[/bold green]\n")
            return devices
        
        except subprocess.TimeoutExpired:
            self.console.print("[red]Scan timed out! Try a smaller network range.[/red]")
            return []
        except FileNotFoundError:
            self.console.print("[red]nmap not found! Please install it with: brew install nmap[/red]")
            return []
        except Exception as e:
            self.console.print(f"[red]Error scanning network: {e}[/red]")
            import traceback
            self.console.print(f"[red]{traceback.format_exc()}[/red]")
            return []
    
    def create_table(self, devices):
        """Create a rich table with device information"""
        table = Table(
            title=f"🌐 Network Device Monitor - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 
            show_header=True, 
            header_style="bold magenta",
            border_style="blue"
        )
        
        table.add_column("Hostname", style="cyan", no_wrap=True)
        table.add_column("IP Address", style="green")
        table.add_column("MAC Address", style="yellow")
        table.add_column("Vendor", style="magenta")
        table.add_column("First Seen", style="blue")
        table.add_column("Last Seen", style="blue")
        table.add_column("Status", justify="center")
        
        for device in devices:
            table.add_row(
                device["Hostname"],
                device["IP"],
                device["MAC"],
                device["Vendor"][:30],  # Truncate vendor name
                device["First Seen"],
                device["Last Seen"],
                device["Status"]
            )
        
        if not devices:
            table.add_row("No devices found", "-", "-", "-", "-", "-", "🔴 Offline")
        
        return table
    
    def monitor_continuous(self, refresh_interval=30):
        """Continuously monitor the network with live updates"""
        self.console.print("[bold green]Starting Continuous Network Monitor...[/bold green]")
        self.console.print(f"Refresh interval: {refresh_interval} seconds")
        self.console.print("Press Ctrl+C to stop\n")
        self.console.print("[yellow]Note: nmap scans take 10-30 seconds each[/yellow]\n")
        
        try:
            while True:
                devices = self.scan_network()
                table = self.create_table(devices)
                self.console.clear()
                self.console.print(table)
                
                self.console.print(f"\n[dim]Next scan in {refresh_interval} seconds...[/dim]")
                time.sleep(refresh_interval)
        
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Monitoring stopped by user[/yellow]")
    
    def monitor_once(self):
        """Scan the network once and display results"""
        self.console.print("[bold cyan]Running network scan with nmap...[/bold cyan]\n")
        devices = self.scan_network()
        table = self.create_table(devices)
        self.console.print(table)
        
        if not devices:
            self.console.print("\n[yellow]Troubleshooting tips:[/yellow]")
            self.console.print("1. Make sure nmap is installed: brew install nmap")
            self.console.print("2. Make sure you're connected to a network")
            self.console.print("3. Try running with sudo for better results: sudo python monitor_display.py")
            self.console.print("4. Some networks may block nmap scans")
        
        return devices


if __name__ == "__main__":
    import sys
    
    monitor = NetworkMonitor()
    
    # Check for command line arguments
    if len(sys.argv) > 1 and sys.argv[1] == "--continuous":
        refresh_interval = int(sys.argv[2]) if len(sys.argv) > 2 else 30
        monitor.monitor_continuous(refresh_interval)
    else:
        monitor.monitor_once()