#!/usr/bin/env python
"""
Tim - T-Mobile Network Assistant
An AI assistant that helps you monitor and manage your network
"""
from dotenv import load_dotenv
import os

# Load environment variables
load_dotenv()

if not os.getenv('OPENAI_API_KEY'):
    print("❌ ERROR: OPENAI_API_KEY not found!")
    print("   Make sure you have a .env file with: OPENAI_API_KEY=your-key-here")
    exit(1)

from crewai import Agent, Crew, Process, Task
from crewai.tools import BaseTool
from typing import Type
from pydantic import BaseModel, Field
import subprocess
import re
import json
from datetime import datetime
from pathlib import Path
from collections import defaultdict

# Tool 1: Device Discovery
class DeviceDiscoveryInput(BaseModel):
    """Input for device discovery"""
    pass

class DeviceDiscoveryTool(BaseTool):
    name: str = "List Network Devices"
    description: str = (
        "Discovers and lists all devices currently connected to the network. "
        "Shows IP addresses, hostnames, MAC addresses, and device vendors. "
        "Use this when the user asks about connected devices, what's on the network, "
        "or wants to see all devices."
    )
    args_schema: Type[BaseModel] = DeviceDiscoveryInput
    
    def _run(self) -> str:
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
                        "hostname": current_host if current_host != current_ip else "Gateway/Router",
                        "mac": "N/A",
                        "vendor": "Local Gateway"
                    })
                    current_ip = None
                    current_host = None
            
            # Format output
            if not devices:
                return "No devices found on the network."
            
            output = f"Found {len(devices)} device(s) on network {network}:\n\n"
            
            for i, device in enumerate(devices, 1):
                output += f"{i}. {device['hostname']} ({device['ip']})\n"
                output += f"   MAC: {device['mac']}\n"
                output += f"   Vendor: {device['vendor']}\n\n"
            
            return output
            
        except Exception as e:
            return f"Error discovering devices: {str(e)}"


# Tool 2: Quick Usage Check
class QuickUsageInput(BaseModel):
    """Input for quick usage check"""
    duration: int = Field(default=10, description="Seconds to monitor (default 10)")

class QuickUsageTool(BaseTool):
    name: str = "Check Current Usage"
    description: str = (
        "Quickly checks current network usage by capturing packets for a short time. "
        "Shows which devices are actively using bandwidth right now. "
        "Use when user asks about current usage, who's using bandwidth, or what's happening now."
    )
    args_schema: Type[BaseModel] = QuickUsageInput
    
    def _run(self, duration: int = 10) -> str:
        """Quick usage check"""
        try:
            from scapy.all import sniff, IP
            
            # Get local network
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            
            ip_parts = local_ip.split('.')
            local_network = '.'.join(ip_parts[:-1])
            
            usage_data = defaultdict(lambda: {"sent": 0, "received": 0, "packets": 0})
            
            def packet_callback(packet):
                try:
                    if IP in packet:
                        src_ip = packet[IP].src
                        dst_ip = packet[IP].dst
                        size = len(packet)
                        
                        if src_ip.startswith(local_network):
                            usage_data[src_ip]["sent"] += size
                            usage_data[src_ip]["packets"] += 1
                        
                        if dst_ip.startswith(local_network):
                            usage_data[dst_ip]["received"] += size
                            usage_data[dst_ip]["packets"] += 1
                except:
                    pass
            
            sniff(timeout=duration, prn=packet_callback, store=False, 
                  filter=f"ip and net {local_network}.0/24")
            
            def format_bytes(b):
                for unit in ['B', 'KB', 'MB', 'GB']:
                    if b < 1024.0:
                        return f"{b:.2f} {unit}"
                    b /= 1024.0
                return f"{b:.2f} TB"
            
            if not usage_data:
                return f"No active network traffic detected during {duration} second monitoring period."
            
            sorted_devices = sorted(
                usage_data.items(),
                key=lambda x: x[1]["sent"] + x[1]["received"],
                reverse=True
            )
            
            output = f"Network usage captured over {duration} seconds:\n\n"
            
            for ip, data in sorted_devices:
                total = data["sent"] + data["received"]
                if total > 0:
                    output += f"📱 {ip}\n"
                    output += f"   Sent: {format_bytes(data['sent'])}\n"
                    output += f"   Received: {format_bytes(data['received'])}\n"
                    output += f"   Total: {format_bytes(total)} ({data['packets']} packets)\n\n"
            
            return output
            
        except ImportError:
            return "Error: scapy not installed. Install with: pip install scapy"
        except Exception as e:
            return f"Error checking usage: {str(e)}"


# Tool 3: Device Info Lookup
class DeviceInfoInput(BaseModel):
    """Input for device info lookup"""
    ip_address: str = Field(description="IP address to look up")

class DeviceInfoTool(BaseTool):
    name: str = "Get Device Info"
    description: str = (
        "Gets detailed information about a specific device by IP address. "
        "Shows hostname, MAC address, vendor, and checks if device is online. "
        "Use when user asks about a specific IP or device."
    )
    args_schema: Type[BaseModel] = DeviceInfoInput
    
    def _run(self, ip_address: str) -> str:
        """Get info about specific device"""
        try:
            # Ping to check if online
            ping_result = subprocess.run(
                ['ping', '-c', '1', '-W', '1', ip_address],
                capture_output=True,
                text=True
            )
            is_online = ping_result.returncode == 0
            
            # Try to get hostname
            try:
                import socket
                hostname = socket.gethostbyaddr(ip_address)[0]
            except:
                hostname = "Unknown"
            
            # Get MAC and vendor from arp
            arp_result = subprocess.run(
                ['arp', '-n', ip_address],
                capture_output=True,
                text=True
            )
            
            mac = "Unknown"
            for line in arp_result.stdout.splitlines():
                mac_match = re.search(r'([0-9a-fA-F:]+)', line)
                if mac_match and ':' in mac_match.group(1):
                    mac = mac_match.group(1)
                    break
            
            output = f"Device Information for {ip_address}:\n\n"
            output += f"Status: {'🟢 Online' if is_online else '🔴 Offline'}\n"
            output += f"Hostname: {hostname}\n"
            output += f"MAC Address: {mac}\n"
            
            if not is_online:
                output += "\nNote: Device is not responding to ping. It may be offline or blocking ICMP."
            
            return output
            
        except Exception as e:
            return f"Error looking up device info: {str(e)}"


# Tool 4: Historical Usage
class HistoricalUsageInput(BaseModel):
    """Input for historical usage"""
    pass

class HistoricalUsageTool(BaseTool):
    name: str = "View Historical Usage"
    description: str = (
        "Shows historical network usage data from previous monitoring sessions. "
        "Use when user asks about past usage, historical data, or trends over time."
    )
    args_schema: Type[BaseModel] = HistoricalUsageInput
    
    def _run(self) -> str:
        """View historical usage data"""
        try:
            data_file = Path("usage_data.json")
            if not data_file.exists():
                return "No historical usage data found. Run usage monitoring first."
            
            with open(data_file, 'r') as f:
                usage_data = json.load(f)
            
            if not usage_data:
                return "Historical usage data is empty."
            
            def format_bytes(b):
                b = float(b)
                for unit in ['B', 'KB', 'MB', 'GB']:
                    if b < 1024.0:
                        return f"{b:.2f} {unit}"
                    b /= 1024.0
                return f"{b:.2f} TB"
            
            sorted_devices = sorted(
                usage_data.items(),
                key=lambda x: x[1]["total_sent"] + x[1]["total_received"],
                reverse=True
            )
            
            output = "Historical Network Usage Data:\n\n"
            
            for ip, data in sorted_devices:
                total = data["total_sent"] + data["total_received"]
                if total > 0:
                    output += f"📊 {ip}\n"
                    output += f"   Total Usage: {format_bytes(total)}\n"
                    output += f"   Sent: {format_bytes(data['total_sent'])}\n"
                    output += f"   Received: {format_bytes(data['total_received'])}\n"
                    output += f"   Last Seen: {data.get('last_seen', 'Unknown')}\n\n"
            
            return output
            
        except Exception as e:
            return f"Error reading historical data: {str(e)}"


class Tim:
    """Tim - Your T-Mobile Network Assistant"""
    
    def __init__(self):
        self.device_tool = DeviceDiscoveryTool()
        self.usage_tool = QuickUsageTool()
        self.info_tool = DeviceInfoTool()
        self.history_tool = HistoricalUsageTool()
    
    def create_agent(self):
        """Create Tim agent"""
        return Agent(
            role="T-Mobile Network Assistant",
            goal="Help users understand and manage their home network by answering questions about connected devices and network usage",
            backstory="""You are Tim, a friendly and helpful T-Mobile network assistant. 
            You help customers understand what's happening on their home network. You can 
            discover devices, check network usage, and provide information about specific 
            devices. You explain technical information in simple, easy-to-understand language. 
            You're patient, thorough, and always try to be helpful.""",
            tools=[self.device_tool, self.usage_tool, self.info_tool, self.history_tool],
            verbose=True,
            allow_delegation=False
        )
    
    def ask(self, question: str):
        """Ask Tim a question"""
        agent = self.create_agent()
        
        task = Task(
            description=f"""The user asked: "{question}"
            
            Understand what the user wants and use the appropriate tools to help them.
            Provide a clear, friendly, and helpful response. Use simple language and 
            explain any technical terms. If you use a tool, explain what you found in 
            a conversational way.""",
            expected_output="A helpful, conversational response to the user's question",
            agent=agent
        )
        
        crew = Crew(
            agents=[agent],
            tasks=[task],
            process=Process.sequential,
            verbose=True
        )
        
        print("\n" + "="*70)
        print("🤖 Tim is thinking...")
        print("="*70 + "\n")
        
        result = crew.kickoff()
        
        print("\n" + "="*70)
        print("💬 Tim's Response:")
        print("="*70)
        print(f"\n{result}\n")
        
        return result
    
    def interactive(self):
        """Start interactive mode"""
        print("\n" + "="*70)
        print("👋 Hi! I'm Tim, your T-Mobile Network Assistant")
        print("="*70)
        print("\nI can help you with:")
        print("  • Listing devices on your network")
        print("  • Checking current network usage")
        print("  • Getting info about specific devices")
        print("  • Viewing historical usage data")
        print("\nType 'exit' or 'quit' to end the conversation")
        print("="*70 + "\n")
        
        while True:
            try:
                question = input("You: ").strip()
                
                if not question:
                    continue
                
                if question.lower() in ['exit', 'quit', 'bye']:
                    print("\n👋 Goodbye! Have a great day!\n")
                    break
                
                self.ask(question)
                print()
                
            except KeyboardInterrupt:
                print("\n\n👋 Goodbye! Have a great day!\n")
                break
            except Exception as e:
                print(f"\n❌ Error: {e}\n")


if __name__ == "__main__":
    import sys
    
    tim = Tim()
    
    if len(sys.argv) > 1:
        # Single question mode
        question = " ".join(sys.argv[1:])
        tim.ask(question)
    else:
        # Interactive mode
        tim.interactive()