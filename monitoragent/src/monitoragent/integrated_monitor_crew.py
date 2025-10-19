#!/usr/bin/env python
"""
Integrated Network Monitoring Crew
Combines device discovery and usage tracking with AI analysis
"""
# Load environment variables first
from dotenv import load_dotenv
import os

# Load .env file from current directory or parent directory
env_path = os.path.join(os.path.dirname(__file__), '.env')
if not os.path.exists(env_path):
    env_path = os.path.join(os.path.dirname(__file__), '..', '.env')
load_dotenv(env_path)

# Verify API key is loaded
if not os.getenv('OPENAI_API_KEY'):
    print("❌ ERROR: OPENAI_API_KEY not found in environment!")
    print("   Make sure you have a .env file with: OPENAI_API_KEY=your-key-here")
    exit(1)

from crewai import Agent, Crew, Process, Task
from crewai.tools import BaseTool
from typing import Type
from pydantic import BaseModel, Field
import subprocess
import re
import json
import time
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# Tool 1: Device Discovery
class DeviceDiscoveryInput(BaseModel):
    """Input schema for Device Discovery Tool"""
    duration: int = Field(default=30, description="How long to scan for devices in seconds")

class DeviceDiscoveryTool(BaseTool):
    name: str = "Device Discovery Scanner"
    description: str = (
        "Scans the local network using nmap to discover all connected devices. "
        "Returns a list of devices with their IP addresses, hostnames, and MAC addresses. "
        "Use this to find out what devices are on the network."
    )
    args_schema: Type[BaseModel] = DeviceDiscoveryInput
    
    def _run(self, duration: int = 30) -> str:
        """Discover devices on the network"""
        try:
            # Get local network
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            ip_parts = local_ip.split('.')
            network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            
            # Run nmap scan
            result = subprocess.run(
                ['nmap', '-sn', '-T4', network],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            devices = []
            current_ip = None
            current_host = None
            current_mac = None
            
            for line in result.stdout.splitlines():
                host_match = re.search(r'Nmap scan report for (.+)', line)
                if host_match:
                    host_info = host_match.group(1)
                    ip_match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', host_info)
                    if ip_match:
                        current_ip = ip_match.group(1)
                        current_host = host_info.split('(')[0].strip()
                    else:
                        ip_only_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', host_info)
                        if ip_only_match:
                            current_ip = ip_only_match.group(1)
                            current_host = "Unknown"
                    current_mac = None
                
                mac_match = re.search(r'MAC Address: ([0-9A-Fa-f:]+)\s*(\((.+)\))?', line)
                if mac_match and current_ip:
                    current_mac = mac_match.group(1)
                    vendor = mac_match.group(3) if mac_match.group(3) else "Unknown"
                    
                    devices.append({
                        "ip": current_ip,
                        "hostname": current_host if current_host != current_ip else "Unknown",
                        "mac": current_mac,
                        "vendor": vendor
                    })
                    current_ip = None
                    current_host = None
                    current_mac = None
                
                if 'Host is up' in line and current_ip and not current_mac:
                    devices.append({
                        "ip": current_ip,
                        "hostname": current_host if current_host != current_ip else "Gateway",
                        "mac": "N/A",
                        "vendor": "Local Gateway"
                    })
                    current_ip = None
                    current_host = None
            
            # Format output
            output = f"# Device Discovery Results\n\n"
            output += f"**Network:** {network}\n"
            output += f"**Devices Found:** {len(devices)}\n\n"
            output += "| IP Address | Hostname | MAC Address | Vendor |\n"
            output += "|------------|----------|-------------|--------|\n"
            
            for device in devices:
                output += f"| {device['ip']} | {device['hostname']} | {device['mac']} | {device['vendor']} |\n"
            
            return output
            
        except Exception as e:
            return f"Error discovering devices: {str(e)}"

# Tool 2: Usage Tracking
class UsageTrackingInput(BaseModel):
    """Input schema for Usage Tracking Tool"""
    duration: int = Field(default=30, description="How long to track usage in seconds")

class UsageTrackingTool(BaseTool):
    name: str = "Network Usage Tracker"
    description: str = (
        "Tracks actual network bandwidth usage per IP address by capturing packets. "
        "Shows how much data each device is sending and receiving. "
        "Requires sudo/root access. Use this to monitor bandwidth consumption."
    )
    args_schema: Type[BaseModel] = UsageTrackingInput
    
    def _run(self, duration: int = 30) -> str:
        """Track network usage"""
        try:
            # Check if scapy is available
            try:
                from scapy.all import sniff, IP
            except ImportError:
                return "Error: scapy not installed. Install with: pip install scapy"
            
            # Get local network info
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            ip_parts = local_ip.split('.')
            local_network = '.'.join(ip_parts[:-1])
            
            # Data collection
            usage_data = defaultdict(lambda: {
                "total_sent": 0,
                "total_received": 0,
                "packet_count": 0
            })
            
            def packet_callback(packet):
                try:
                    if IP in packet:
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                        packet_size = len(packet)
                        
                        if src_ip.startswith(local_network):
                            usage_data[src_ip]["total_sent"] += packet_size
                            usage_data[src_ip]["packet_count"] += 1
                        
                        if dst_ip.startswith(local_network):
                            usage_data[dst_ip]["total_received"] += packet_size
                            usage_data[dst_ip]["packet_count"] += 1
                except:
                    pass
            
            # Capture packets
            sniff(
                timeout=duration,
                prn=packet_callback,
                store=False,
                filter=f"ip and net {local_network}.0/24"
            )
            
            # Format output
            def format_bytes(bytes_val):
                for unit in ['B', 'KB', 'MB', 'GB']:
                    if bytes_val < 1024.0:
                        return f"{bytes_val:.2f} {unit}"
                    bytes_val /= 1024.0
                return f"{bytes_val:.2f} TB"
            
            output = f"# Network Usage Report\n\n"
            output += f"**Capture Duration:** {duration} seconds\n"
            output += f"**Active Devices:** {len(usage_data)}\n\n"
            output += "| IP Address | Sent | Received | Total | Packets |\n"
            output += "|------------|------|----------|-------|--------|\n"
            
            sorted_devices = sorted(
                usage_data.items(),
                key=lambda x: x[1]["total_sent"] + x[1]["total_received"],
                reverse=True
            )
            
            for ip, data in sorted_devices:
                total = data["total_sent"] + data["total_received"]
                output += f"| {ip} | {format_bytes(data['total_sent'])} | "
                output += f"{format_bytes(data['total_received'])} | "
                output += f"{format_bytes(total)} | {data['packet_count']} |\n"
            
            # Save to file for later analysis
            save_data = {}
            for ip, data in usage_data.items():
                save_data[ip] = {
                    "total_sent": data["total_sent"],
                    "total_received": data["total_received"],
                    "packet_count": data["packet_count"],
                    "last_seen": datetime.now().isoformat()
                }
            
            with open("usage_data.json", "w") as f:
                json.dump(save_data, f, indent=2)
            
            return output
            
        except Exception as e:
            return f"Error tracking usage: {str(e)}"

# Tool 3: Usage Analysis
class UsageAnalysisInput(BaseModel):
    """Input schema for Usage Analysis Tool"""
    pass

class UsageAnalysisTool(BaseTool):
    name: str = "Usage Data Analyzer"
    description: str = (
        "Analyzes saved usage data and provides insights about bandwidth patterns, "
        "top consumers, and network behavior. Use this after tracking usage."
    )
    args_schema: Type[BaseModel] = UsageAnalysisInput
    
    def _run(self) -> str:
        """Analyze usage data"""
        try:
            data_file = Path("usage_data.json")
            if not data_file.exists():
                return "No usage data found. Run the Network Usage Tracker tool first."
            
            with open(data_file, 'r') as f:
                usage_data = json.load(f)
            
            if not usage_data:
                return "Usage data file is empty."
            
            def format_bytes(bytes_val):
                bytes_val = float(bytes_val)
                for unit in ['B', 'KB', 'MB', 'GB']:
                    if bytes_val < 1024.0:
                        return f"{bytes_val:.2f} {unit}"
                    bytes_val /= 1024.0
                return f"{bytes_val:.2f} TB"
            
            total_sent = sum(d["total_sent"] for d in usage_data.values())
            total_received = sum(d["total_received"] for d in usage_data.values())
            total_usage = total_sent + total_received
            
            output = "# Network Usage Analysis\n\n"
            output += f"## Summary\n"
            output += f"- Total Devices: {len(usage_data)}\n"
            output += f"- Total Sent: {format_bytes(total_sent)}\n"
            output += f"- Total Received: {format_bytes(total_received)}\n"
            output += f"- Total Usage: {format_bytes(total_usage)}\n\n"
            
            output += "## Top Consumers\n\n"
            sorted_devices = sorted(
                usage_data.items(),
                key=lambda x: x[1]["total_sent"] + x[1]["total_received"],
                reverse=True
            )
            
            for i, (ip, data) in enumerate(sorted_devices[:5], 1):
                device_total = data["total_sent"] + data["total_received"]
                percentage = (device_total / total_usage * 100) if total_usage > 0 else 0
                
                output += f"### {i}. {ip}\n"
                output += f"- Usage: {format_bytes(device_total)} ({percentage:.1f}%)\n"
                output += f"- Sent: {format_bytes(data['total_sent'])}\n"
                output += f"- Received: {format_bytes(data['total_received'])}\n"
                
                # Traffic pattern
                if data["total_received"] > 0:
                    ratio = data["total_sent"] / data["total_received"]
                    if ratio > 2:
                        output += f"- Pattern: Upload-heavy (uploading/hosting)\n"
                    elif ratio < 0.5:
                        output += f"- Pattern: Download-heavy (streaming/browsing)\n"
                    else:
                        output += f"- Pattern: Balanced traffic\n"
                output += "\n"
            
            return output
            
        except Exception as e:
            return f"Error analyzing usage: {str(e)}"


class NetworkMonitoringCrew:
    def __init__(self):
        self.device_tool = DeviceDiscoveryTool()
        self.usage_tool = UsageTrackingTool()
        self.analysis_tool = UsageAnalysisTool()
    
    def create_crew(self):
        """Create the network monitoring crew"""
        
        # Network Monitor Agent
        monitor_agent = Agent(
            role="Network Monitoring Specialist",
            goal="Discover all devices on the network and track their bandwidth usage to provide comprehensive network insights",
            backstory="""You are an experienced network administrator with expertise in 
            network discovery, traffic analysis, and bandwidth monitoring. You use various 
            tools to scan networks, track usage, and provide detailed reports about network 
            activity. You're methodical and thorough in your analysis.""",
            tools=[self.device_tool, self.usage_tool, self.analysis_tool],
            verbose=True
        )
        
        # Comprehensive monitoring task
        monitoring_task = Task(
            description="""Perform a comprehensive network monitoring analysis:
            
            1. First, use the Device Discovery Scanner to find all devices on the network
            2. Then, use the Network Usage Tracker to monitor bandwidth usage (capture for 30 seconds)
            3. Finally, use the Usage Data Analyzer to analyze the collected data
            
            Provide a complete report that includes:
            - List of all discovered devices with their details
            - Bandwidth usage statistics for each device
            - Top bandwidth consumers
            - Traffic patterns (upload vs download behavior)
            - Overall network health assessment
            - Recommendations for optimization or investigation
            
            Be thorough and explain what you find in clear, non-technical language.""",
            expected_output="""A comprehensive markdown report with:
            - Device discovery results
            - Usage statistics
            - Top consumers
            - Traffic patterns
            - Recommendations""",
            agent=monitor_agent
        )
        
        # Create crew
        crew = Crew(
            agents=[monitor_agent],
            tasks=[monitoring_task],
            process=Process.sequential,
            verbose=True
        )
        
        return crew
    
    def run(self):
        """Run the network monitoring crew"""
        print("\n" + "="*70)
        print("🌐 Integrated Network Monitoring System")
        print("="*70)
        print("\n⚠️  NOTE: This requires sudo/root access for packet capture")
        print("   Run with: sudo python integrated_monitor_crew.py\n")
        
        crew = self.create_crew()
        result = crew.kickoff()
        
        # Save report
        report_file = Path(f"network_monitor_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md")
        with open(report_file, 'w') as f:
            f.write(str(result))
        
        print("\n" + "="*70)
        print("✅ Monitoring Complete!")
        print(f"📄 Report saved to: {report_file}")
        print("="*70 + "\n")
        
        return result


if __name__ == "__main__":
    import sys
    import os
    
    # Check if running with sudo
    if os.geteuid() != 0:
        print("\n⚠️  WARNING: This script requires sudo access for packet capture!")
        print("   Please run: sudo python integrated_monitor_crew.py\n")
        sys.exit(1)
    
    monitor = NetworkMonitoringCrew()
    monitor.run()