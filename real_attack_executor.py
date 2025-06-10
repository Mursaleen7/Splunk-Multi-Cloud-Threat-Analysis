#!/usr/bin/env python3
"""
Real Attack Executor - Executes actual MITRE ATT&CK techniques
This script performs real attacks rather than generating synthetic logs
"""

import subprocess
import json
import time
import os
import sys
import requests
import base64
import socket
import threading
from datetime import datetime
from typing import Dict, List, Optional

class RealAttackExecutor:
    def __init__(self, splunk_hec_url: str = "http://localhost:8088/services/collector", 
                 hec_token: str = "1b0bb9cc-e884-4ae0-b3fa-9062f200b328"):
        self.hec_url = splunk_hec_url
        self.hec_token = hec_token
        self.headers = {
            "Authorization": f"Splunk {self.hec_token}",
            "Content-Type": "application/json"
        }
        self.attack_results = []
        
        # Create logs directory for local logging
        self.logs_dir = "attack_logs"
        os.makedirs(self.logs_dir, exist_ok=True)
        
    def log_attack_event(self, technique_id: str, technique_name: str, 
                        command: str, result: Dict, severity: str = "HIGH"):
        """Log real attack execution results to Splunk and local files"""
        event_data = {
            "time": int(time.time()),
            "sourcetype": "real_attack_execution",
            "source": "attack_executor",
            "event": {
                "technique_id": technique_id,
                "technique_name": technique_name,
                "command_executed": command,
                "execution_result": result,
                "severity": severity,
                "timestamp": datetime.now().isoformat(),
                "attack_type": "REAL_EXECUTION",
                "host": socket.gethostname(),
                "user": os.getenv('USER', 'unknown')
            }
        }
        
        # Try to log to Splunk HEC
        splunk_logged = False
        try:
            response = requests.post(self.hec_url, headers=self.headers, json=event_data, timeout=5)
            if response.status_code == 200:
                print(f"✅ Attack logged to Splunk: {technique_id} - {technique_name}")
                splunk_logged = True
            else:
                print(f"⚠️ Failed to log to Splunk: HTTP {response.status_code}")
        except Exception as e:
            print(f"⚠️ Splunk logging error: {e}")
        
        # Always log to local file for backup
        self.log_to_file(event_data, splunk_logged)
        
        # Store for later analysis
        self.attack_results.append(event_data)
    
    def log_to_file(self, event_data: Dict, splunk_logged: bool = False):
        """Log attack event to local file"""
        try:
            log_file = os.path.join(self.logs_dir, f"attack_execution_{datetime.now().strftime('%Y%m%d')}.json")
            
            # Add local logging metadata
            event_data["logged_to_splunk"] = splunk_logged
            event_data["local_log_time"] = datetime.now().isoformat()
            
            with open(log_file, 'a') as f:
                f.write(json.dumps(event_data) + '\n')
                
            if not splunk_logged:
                print(f"📝 Attack logged locally: {event_data['event']['technique_id']}")
                
        except Exception as e:
            print(f"⚠️ Local logging error: {e}")
    
    def execute_command(self, command: str, timeout: int = 30) -> Dict:
        """Execute a command and return results"""
        try:
            result = subprocess.run(
                command, 
                shell=True, 
                capture_output=True, 
                text=True, 
                timeout=timeout
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "return_code": result.returncode,
                "command": command
            }
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Command timed out after {timeout} seconds",
                "return_code": -1,
                "command": command
            }
        except Exception as e:
            return {
                "success": False,
                "stdout": "",
                "stderr": str(e),
                "return_code": -1,
                "command": command
            }
    
    def t1059_001_powershell_execution(self):
        """T1059.001 - PowerShell Command and Script Execution"""
        print("\n🎯 Executing T1059.001 - PowerShell Execution")
        
        # Real PowerShell commands for discovery
        commands = [
            "powershell.exe -Command \"Get-Process | Select-Object Name, Id, CPU | Sort-Object CPU -Descending | Select-Object -First 10\"",
            "powershell.exe -Command \"Get-WmiObject -Class Win32_ComputerSystem\"",
            "powershell.exe -Command \"Get-NetAdapter | Select-Object Name, InterfaceDescription, LinkSpeed\"",
            "powershell.exe -EncodedCommand " + base64.b64encode("Get-LocalUser".encode('utf-16le')).decode()
        ]
        
        for cmd in commands:
            print(f"Executing: {cmd[:80]}...")
            result = self.execute_command(cmd)
            self.log_attack_event("T1059.001", "PowerShell Execution", cmd, result)
            time.sleep(2)
    
    def t1018_remote_system_discovery(self):
        """T1018 - Remote System Discovery"""
        print("\n🔍 Executing T1018 - Remote System Discovery")
        
        # Real network discovery commands
        commands = [
            "arp -a",
            "netstat -an",
            "nslookup google.com",
            "ping -c 1 8.8.8.8",
            "netstat -rn",
            "ifconfig" if sys.platform != "win32" else "ipconfig /all"
        ]
        
        for cmd in commands:
            print(f"Executing: {cmd}")
            result = self.execute_command(cmd)
            self.log_attack_event("T1018", "Remote System Discovery", cmd, result)
            time.sleep(1)
    
    def t1082_system_information_discovery(self):
        """T1082 - System Information Discovery"""
        print("\n💻 Executing T1082 - System Information Discovery")
        
        # Real system information gathering
        commands = [
            "uname -a" if sys.platform != "win32" else "systeminfo",
            "whoami",
            "id" if sys.platform != "win32" else "whoami /all",
            "ps aux" if sys.platform != "win32" else "tasklist",
            "df -h" if sys.platform != "win32" else "wmic logicaldisk get size,freespace,caption",
            "env" if sys.platform != "win32" else "set"
        ]
        
        for cmd in commands:
            print(f"Executing: {cmd}")
            result = self.execute_command(cmd)
            self.log_attack_event("T1082", "System Information Discovery", cmd, result)
            time.sleep(1)
    
    def t1083_file_and_directory_discovery(self):
        """T1083 - File and Directory Discovery"""
        print("\n📁 Executing T1083 - File and Directory Discovery")
        
        # Real file system enumeration
        commands = [
            "find /tmp -type f -name '*.log' 2>/dev/null | head -10" if sys.platform != "win32" else "dir C:\\temp\\*.log",
            "ls -la /etc/passwd" if sys.platform != "win32" else "dir C:\\Windows\\System32\\drivers\\etc\\hosts",
            "find /home -name '*.ssh' 2>/dev/null | head -5" if sys.platform != "win32" else "dir C:\\Users\\*\\.ssh",
            "ls -la ~/.bash_history" if sys.platform != "win32" else "dir %USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt"
        ]
        
        for cmd in commands:
            print(f"Executing: {cmd}")
            result = self.execute_command(cmd)
            self.log_attack_event("T1083", "File and Directory Discovery", cmd, result)
            time.sleep(1)
    
    def t1057_process_discovery(self):
        """T1057 - Process Discovery"""
        print("\n⚙️ Executing T1057 - Process Discovery")
        
        # Real process enumeration
        commands = [
            "ps aux | grep -E '(ssh|http|mysql|postgres)'" if sys.platform != "win32" else "tasklist | findstr /i 'ssh http mysql postgres'",
            "ps -ef | head -20" if sys.platform != "win32" else "wmic process list brief",
            "pgrep -l python" if sys.platform != "win32" else "tasklist | findstr python",
            "lsof -i" if sys.platform != "win32" else "netstat -ano"
        ]
        
        for cmd in commands:
            print(f"Executing: {cmd}")
            result = self.execute_command(cmd)
            self.log_attack_event("T1057", "Process Discovery", cmd, result)
            time.sleep(1)
    
    def t1033_system_owner_discovery(self):
        """T1033 - System Owner/User Discovery"""
        print("\n👤 Executing T1033 - System Owner/User Discovery")
        
        # Real user enumeration
        commands = [
            "whoami",
            "id" if sys.platform != "win32" else "whoami /groups",
            "w" if sys.platform != "win32" else "query user",
            "last | head -10" if sys.platform != "win32" else "wmic netlogin list brief",
            "cat /etc/passwd | head -10" if sys.platform != "win32" else "net user"
        ]
        
        for cmd in commands:
            print(f"Executing: {cmd}")
            result = self.execute_command(cmd)
            self.log_attack_event("T1033", "System Owner/User Discovery", cmd, result)
            time.sleep(1)
    
    def t1016_system_network_configuration_discovery(self):
        """T1016 - System Network Configuration Discovery"""
        print("\n🌐 Executing T1016 - System Network Configuration Discovery")
        
        # Real network configuration discovery
        commands = [
            "ifconfig" if sys.platform != "win32" else "ipconfig /all",
            "route -n" if sys.platform != "win32" else "route print",
            "cat /etc/resolv.conf" if sys.platform != "win32" else "nslookup",
            "netstat -i" if sys.platform != "win32" else "netsh interface show interface",
            "ss -tuln" if sys.platform != "win32" else "netstat -an"
        ]
        
        for cmd in commands:
            print(f"Executing: {cmd}")
            result = self.execute_command(cmd)
            self.log_attack_event("T1016", "System Network Configuration Discovery", cmd, result)
            time.sleep(1)
    
    def t1070_004_file_deletion(self):
        """T1070.004 - File Deletion for Defense Evasion"""
        print("\n🗑️ Executing T1070.004 - File Deletion")
        
        # Create temporary files and then delete them (safe simulation)
        temp_files = [
            "/tmp/test_attack_file.txt" if sys.platform != "win32" else "C:\\temp\\test_attack_file.txt",
            "/tmp/fake_log.log" if sys.platform != "win32" else "C:\\temp\\fake_log.log"
        ]
        
        # Create files first
        for file_path in temp_files:
            create_cmd = f"echo 'test content' > {file_path}"
            print(f"Creating test file: {file_path}")
            result = self.execute_command(create_cmd)
            
            # Then delete them
            delete_cmd = f"rm -f {file_path}" if sys.platform != "win32" else f"del /f {file_path}"
            print(f"Deleting: {file_path}")
            result = self.execute_command(delete_cmd)
            self.log_attack_event("T1070.004", "File Deletion", delete_cmd, result)
            time.sleep(1)
    
    def create_c2_simulation(self):
        """Simulate Command and Control communication"""
        print("\n📡 Simulating C2 Communication")
        
        # Simulate DNS queries to suspicious domains
        suspicious_domains = [
            "malicious-c2-server.com",
            "attacker-infrastructure.net", 
            "evil-command-control.org"
        ]
        
        for domain in suspicious_domains:
            cmd = f"nslookup {domain}"
            print(f"DNS lookup: {domain}")
            result = self.execute_command(cmd)
            self.log_attack_event("T1071.004", "DNS C2 Communication", cmd, result)
            time.sleep(2)
    
    def export_attack_summary(self):
        """Export a summary of all attacks executed"""
        summary_file = os.path.join(self.logs_dir, f"attack_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        
        summary = {
            "execution_summary": {
                "total_attacks": len(self.attack_results),
                "execution_time": datetime.now().isoformat(),
                "techniques_executed": list(set([event['event']['technique_id'] for event in self.attack_results])),
                "commands_executed": len([event for event in self.attack_results if event['event']['execution_result']['success']]),
                "failed_commands": len([event for event in self.attack_results if not event['event']['execution_result']['success']])
            },
            "detailed_results": self.attack_results
        }
        
        try:
            with open(summary_file, 'w') as f:
                json.dump(summary, f, indent=2)
            print(f"📊 Attack summary exported to: {summary_file}")
        except Exception as e:
            print(f"⚠️ Failed to export summary: {e}")
    
    def run_comprehensive_attack_simulation(self):
        """Execute a comprehensive attack simulation"""
        print("🚨 STARTING REAL ATTACK SIMULATION")
        print("=" * 60)
        print("⚠️  WARNING: This executes real commands on the system")
        print("=" * 60)
        
        # Execute attack techniques in sequence
        attack_techniques = [
            self.t1082_system_information_discovery,
            self.t1033_system_owner_discovery,
            self.t1057_process_discovery,
            self.t1018_remote_system_discovery,
            self.t1016_system_network_configuration_discovery,
            self.t1083_file_and_directory_discovery,
            self.t1070_004_file_deletion,
            self.create_c2_simulation
        ]
        
        # Add PowerShell execution if on Windows or if PowerShell is available
        if sys.platform == "win32" or subprocess.run("which pwsh", shell=True, capture_output=True).returncode == 0:
            attack_techniques.insert(0, self.t1059_001_powershell_execution)
        
        for technique in attack_techniques:
            try:
                technique()
                time.sleep(3)  # Pause between techniques
            except Exception as e:
                print(f"❌ Error executing technique: {e}")
                continue
        
        print("\n✅ REAL ATTACK SIMULATION COMPLETE")
        print(f"📊 Total techniques executed: {len(attack_techniques)}")
        print("📝 All activities logged locally and to Splunk (if available)")
        
        # Export summary
        self.export_attack_summary()
        
        # Show log locations
        print(f"\n📂 Attack logs saved to: {self.logs_dir}/")
        print("📁 Log files created:")
        try:
            for log_file in os.listdir(self.logs_dir):
                print(f"  - {log_file}")
        except Exception as e:
            print(f"  Could not list log files: {e}")

def main():
    """Main execution function"""
    print("🎯 Real Attack Executor - MITRE ATT&CK Technique Implementation")
    print("⚠️  This tool executes REAL commands - use only in authorized environments")
    
    # Initialize executor
    executor = RealAttackExecutor()
    
    # Run comprehensive simulation
    executor.run_comprehensive_attack_simulation()

if __name__ == "__main__":
    main() 