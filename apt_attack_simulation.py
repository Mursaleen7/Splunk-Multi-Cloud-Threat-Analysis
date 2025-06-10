#!/usr/bin/env python3
"""
APT Attack Simulation - Operation Shadow Finance
Comprehensive Advanced Persistent Threat simulation targeting financial services
"""

import requests
import json
import time
import random
import datetime
from typing import Dict, List

class APTAttackSimulator:
    def __init__(self):
        self.hec_url = "http://localhost:8088/services/collector"
        self.hec_token = "1b0bb9cc-e884-4ae0-b3fa-9062f200b328"
        self.headers = {
            "Authorization": f"Splunk {self.hec_token}",
            "Content-Type": "application/json"
        }
        self.attack_timeline = []
        
    def send_event(self, event_data: Dict) -> bool:
        """Send event to Splunk HEC"""
        try:
            response = requests.post(self.hec_url, headers=self.headers, json=event_data)
            if response.status_code == 200:
                print(f"✅ Event sent: {event_data['event']['attack_stage']} - {event_data['event']['message'][:80]}...")
                return True
            else:
                print(f"❌ Failed to send event: HTTP {response.status_code}")
                return False
        except Exception as e:
            print(f"❌ Error sending event: {e}")
            return False
    
    def phase1_initial_access(self):
        """Phase 1: Initial Access via Phishing"""
        print("\n🎯 PHASE 1: INITIAL ACCESS SIMULATION")
        print("=" * 50)
        
        # Phishing email delivered
        event = {
            "time": int(time.time()),
            "sourcetype": "apt_attack",
            "source": "email_gateway",
            "event": {
                "attack_stage": "INITIAL_ACCESS",
                "technique_id": "T1566.001",
                "technique": "Spearphishing Attachment",
                "severity": "HIGH",
                "message": "Phishing email with malicious attachment delivered to finance_user@company.com",
                "src_ip": "203.0.113.45",
                "dest_ip": "192.168.10.25",
                "user": "finance_user",
                "attachment": "invoice_Q4_2024.pdf.exe",
                "email_subject": "Urgent: Q4 Financial Report Review Required",
                "sender": "cfo@fake-partner-company.com"
            }
        }
        self.send_event(event)
        time.sleep(1)
        
        # User opens malicious attachment
        event = {
            "time": int(time.time()),
            "sourcetype": "apt_attack",
            "source": "endpoint_detection",
            "event": {
                "attack_stage": "INITIAL_ACCESS",
                "technique_id": "T1204.002",
                "technique": "Malicious File Execution",
                "severity": "CRITICAL",
                "message": "User executed suspicious attachment: invoice_Q4_2024.pdf.exe",
                "src_ip": "192.168.10.25",
                "user": "finance_user",
                "process": "invoice_Q4_2024.pdf.exe",
                "parent_process": "explorer.exe",
                "command_line": "C:\\Users\\finance_user\\Downloads\\invoice_Q4_2024.pdf.exe",
                "file_hash": "d41d8cd98f00b204e9800998ecf8427e"
            }
        }
        self.send_event(event)
        time.sleep(2)
        
        # Credential harvesting
        event = {
            "time": int(time.time()),
            "sourcetype": "apt_attack",
            "source": "credential_monitor",
            "event": {
                "attack_stage": "CREDENTIAL_ACCESS",
                "technique_id": "T1555",
                "technique": "Credentials from Password Stores",
                "severity": "HIGH",
                "message": "Suspicious access to Windows Credential Store detected",
                "src_ip": "192.168.10.25",
                "user": "finance_user",
                "process": "invoice_Q4_2024.pdf.exe",
                "target": "Windows Credential Manager",
                "credentials_accessed": ["domain\\admin", "domain\\finance_user", "vpn_service_account"]
            }
        }
        self.send_event(event)
        time.sleep(1)
    
    def phase2_persistence(self):
        """Phase 2: Establish Persistence"""
        print("\n🔒 PHASE 2: PERSISTENCE ESTABLISHMENT")
        print("=" * 50)
        
        # Registry persistence
        event = {
            "time": int(time.time()),
            "sourcetype": "apt_attack",
            "source": "registry_monitor",
            "event": {
                "attack_stage": "PERSISTENCE",
                "technique_id": "T1547.001",
                "technique": "Registry Run Keys / Startup Folder",
                "severity": "HIGH",
                "message": "Malicious registry entry created for persistence",
                "src_ip": "192.168.10.25",
                "user": "finance_user",
                "registry_key": "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsSecurityUpdate",
                "registry_value": "C:\\Windows\\System32\\winsecupd.exe",
                "process": "reg.exe"
            }
        }
        self.send_event(event)
        time.sleep(1)
        
        # Scheduled task creation
        event = {
            "time": int(time.time()),
            "sourcetype": "apt_attack",
            "source": "task_scheduler",
            "event": {
                "attack_stage": "PERSISTENCE",
                "technique_id": "T1053.005",
                "technique": "Scheduled Task/Job",
                "severity": "HIGH",
                "message": "Suspicious scheduled task created: SystemMaintenanceTask",
                "src_ip": "192.168.10.25",
                "user": "finance_user",
                "task_name": "SystemMaintenanceTask",
                "task_command": "C:\\Windows\\System32\\winsecupd.exe -silent",
                "task_trigger": "Daily at 3:00 AM",
                "process": "schtasks.exe"
            }
        }
        self.send_event(event)
        time.sleep(1)
        
        # Service installation
        event = {
            "time": int(time.time()),
            "sourcetype": "apt_attack",
            "source": "service_monitor",
            "event": {
                "attack_stage": "PERSISTENCE",
                "technique_id": "T1543.003",
                "technique": "Windows Service",
                "severity": "CRITICAL",
                "message": "Malicious service installed: WindowsSecurityService",
                "src_ip": "192.168.10.25",
                "user": "finance_user",
                "service_name": "WindowsSecurityService",
                "service_path": "C:\\Windows\\System32\\winsecupd.exe",
                "service_description": "Windows Security Update Service",
                "startup_type": "Automatic"
            }
        }
        self.send_event(event)
        time.sleep(2)
    
    def phase3_privilege_escalation(self):
        """Phase 3: Privilege Escalation"""
        print("\n⬆️ PHASE 3: PRIVILEGE ESCALATION")
        print("=" * 50)
        
        # Local privilege escalation attempt
        event = {
            "time": int(time.time()),
            "sourcetype": "apt_attack",
            "source": "security_log",
            "event": {
                "attack_stage": "PRIVILEGE_ESCALATION",
                "technique_id": "T1548.002",
                "technique": "Bypass User Account Control",
                "severity": "HIGH",
                "message": "UAC bypass attempt detected using FODHELPER technique",
                "src_ip": "192.168.10.25",
                "user": "finance_user",
                "process": "fodhelper.exe",
                "target_process": "cmd.exe",
                "registry_modification": "HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command"
            }
        }
        self.send_event(event)
        time.sleep(1)
        
        # Successful privilege escalation
        event = {
            "time": int(time.time()),
            "sourcetype": "apt_attack",
            "source": "security_log",
            "event": {
                "attack_stage": "PRIVILEGE_ESCALATION",
                "technique_id": "T1134",
                "technique": "Access Token Manipulation",
                "severity": "CRITICAL",
                "message": "Process token elevated to SYSTEM privileges",
                "src_ip": "192.168.10.25",
                "user": "SYSTEM",
                "process": "winsecupd.exe",
                "old_privileges": "User",
                "new_privileges": "Administrator",
                "parent_process": "services.exe"
            }
        }
        self.send_event(event)
        time.sleep(1)
        
        # Domain reconnaissance
        event = {
            "time": int(time.time()),
            "sourcetype": "apt_attack",
            "source": "domain_controller",
            "event": {
                "attack_stage": "DISCOVERY",
                "technique_id": "T1087.002",
                "technique": "Domain Account Discovery",
                "severity": "MEDIUM",
                "message": "Suspicious domain enumeration activity detected",
                "src_ip": "192.168.10.25",
                "user": "SYSTEM",
                "process": "net.exe",
                "command_line": "net user /domain",
                "target_domain": "FINANCECOMPANY",
                "accounts_enumerated": 47
            }
        }
        self.send_event(event)
        time.sleep(2)
    
    def phase4_lateral_movement(self):
        """Phase 4: Lateral Movement"""
        print("\n↔️ PHASE 4: LATERAL MOVEMENT")
        print("=" * 50)
        
        # Network scanning
        event = {
            "time": int(time.time()),
            "sourcetype": "apt_attack",
            "source": "network_monitor",
            "event": {
                "attack_stage": "DISCOVERY",
                "technique_id": "T1018",
                "technique": "Remote System Discovery",
                "severity": "MEDIUM",
                "message": "Internal network scanning detected from compromised host",
                "src_ip": "192.168.10.25",
                "dest_ip_range": "192.168.10.0/24",
                "ports_scanned": [22, 80, 135, 139, 443, 445, 3389],
                "scan_type": "TCP Connect",
                "hosts_discovered": 15
            }
        }
        self.send_event(event)
        time.sleep(1)
        
        # SMB credential stuffing
        event = {
            "time": int(time.time()),
            "sourcetype": "apt_attack",
            "source": "smb_monitor",
            "event": {
                "attack_stage": "LATERAL_MOVEMENT",
                "technique_id": "T1021.002",
                "technique": "SMB/Windows Admin Shares",
                "severity": "HIGH",
                "message": "Suspicious SMB authentication attempts to multiple hosts",
                "src_ip": "192.168.10.25",
                "dest_ip": "192.168.10.50",
                "user": "domain\\admin",
                "service": "SMB",
                "share": "ADMIN$",
                "auth_attempts": 3,
                "status": "Failed"
            }
        }
        self.send_event(event)
        time.sleep(1)
        
        # Successful lateral movement
        event = {
            "time": int(time.time()),
            "sourcetype": "apt_attack",
            "source": "domain_controller",
            "event": {
                "attack_stage": "LATERAL_MOVEMENT",
                "technique_id": "T1021.002",
                "technique": "SMB/Windows Admin Shares",
                "severity": "CRITICAL",
                "message": "Successful lateral movement to database server",
                "src_ip": "192.168.10.25",
                "dest_ip": "192.168.10.100",
                "user": "domain\\dbadmin",
                "service": "SMB",
                "share": "C$",
                "auth_status": "Success",
                "target_hostname": "DB-SERVER-01"
            }
        }
        self.send_event(event)
        time.sleep(1)
        
        # Remote execution
        event = {
            "time": int(time.time()),
            "sourcetype": "apt_attack",
            "source": "endpoint_detection",
            "event": {
                "attack_stage": "EXECUTION",
                "technique_id": "T1569.002",
                "technique": "Service Execution",
                "severity": "CRITICAL",
                "message": "Remote service execution on database server",
                "src_ip": "192.168.10.25",
                "dest_ip": "192.168.10.100",
                "user": "domain\\dbadmin",
                "service_name": "RemoteExecSvc",
                "command": "C:\\Windows\\System32\\winsecupd.exe -install",
                "target_hostname": "DB-SERVER-01"
            }
        }
        self.send_event(event)
        time.sleep(2)
    
    def phase5_data_exfiltration(self):
        """Phase 5: Data Exfiltration"""
        print("\n📤 PHASE 5: DATA EXFILTRATION")
        print("=" * 50)
        
        # Database access
        event = {
            "time": int(time.time()),
            "sourcetype": "apt_attack",
            "source": "database_monitor",
            "event": {
                "attack_stage": "COLLECTION",
                "technique_id": "T1005",
                "technique": "Data from Local System",
                "severity": "CRITICAL",
                "message": "Unauthorized database query accessing sensitive financial data",
                "src_ip": "192.168.10.100",
                "user": "domain\\dbadmin",
                "database": "FinancialRecords",
                "query": "SELECT * FROM customer_accounts WHERE account_balance > 100000",
                "records_accessed": 2847,
                "data_types": ["account_numbers", "balances", "personal_info"]
            }
        }
        self.send_event(event)
        time.sleep(1)
        
        # Data compression
        event = {
            "time": int(time.time()),
            "sourcetype": "apt_attack",
            "source": "file_monitor",
            "event": {
                "attack_stage": "COLLECTION",
                "technique_id": "T1560.001",
                "technique": "Archive Collected Data",
                "severity": "HIGH",
                "message": "Large archive created containing financial data",
                "src_ip": "192.168.10.100",
                "user": "domain\\dbadmin",
                "process": "7z.exe",
                "archive_name": "system_backup_20241219.7z",
                "archive_size": "2.3 GB",
                "files_compressed": 2847,
                "compression_ratio": "85%"
            }
        }
        self.send_event(event)
        time.sleep(1)
        
        # Encrypted data transfer
        event = {
            "time": int(time.time()),
            "sourcetype": "apt_attack",
            "source": "network_monitor",
            "event": {
                "attack_stage": "EXFILTRATION",
                "technique_id": "T1041",
                "technique": "Exfiltration Over C2 Channel",
                "severity": "CRITICAL",
                "message": "Large encrypted data transfer to external IP address",
                "src_ip": "192.168.10.100",
                "dest_ip": "185.220.101.45",
                "dest_port": 443,
                "protocol": "HTTPS",
                "bytes_transferred": "2,400,000,000",
                "transfer_duration": "47 minutes",
                "encryption": "TLS 1.3"
            }
        }
        self.send_event(event)
        time.sleep(1)
        
        # C2 communication
        event = {
            "time": int(time.time()),
            "sourcetype": "apt_attack",
            "source": "dns_monitor",
            "event": {
                "attack_stage": "COMMAND_AND_CONTROL",
                "technique_id": "T1071.004",
                "technique": "DNS",
                "severity": "HIGH",
                "message": "Suspicious DNS queries to potential C2 domain",
                "src_ip": "192.168.10.100",
                "dns_query": "update.financial-security-service.com",
                "query_type": "TXT",
                "response": "dGFza19jb21wbGV0ZWQ=",
                "decoded_response": "task_completed"
            }
        }
        self.send_event(event)
        time.sleep(2)
    
    def phase6_cover_tracks(self):
        """Phase 6: Cover Tracks & Anti-Forensics"""
        print("\n🧹 PHASE 6: COVERING TRACKS")
        print("=" * 50)
        
        # Log deletion
        event = {
            "time": int(time.time()),
            "sourcetype": "apt_attack",
            "source": "security_log",
            "event": {
                "attack_stage": "DEFENSE_EVASION",
                "technique_id": "T1070.001",
                "technique": "Clear Windows Event Logs",
                "severity": "HIGH",
                "message": "Security event logs cleared on compromised system",
                "src_ip": "192.168.10.100",
                "user": "domain\\dbadmin",
                "process": "wevtutil.exe",
                "command_line": "wevtutil cl Security",
                "logs_cleared": ["Security", "System", "Application"]
            }
        }
        self.send_event(event)
        time.sleep(1)
        
        # File deletion
        event = {
            "time": int(time.time()),
            "sourcetype": "apt_attack",
            "source": "file_monitor",
            "event": {
                "attack_stage": "DEFENSE_EVASION",
                "technique_id": "T1070.004",
                "technique": "File Deletion",
                "severity": "MEDIUM",
                "message": "Suspicious file deletion pattern detected",
                "src_ip": "192.168.10.100",
                "user": "domain\\dbadmin",
                "process": "sdelete.exe",
                "files_deleted": [
                    "C:\\temp\\financial_data.sql",
                    "C:\\temp\\system_backup_20241219.7z",
                    "C:\\Windows\\System32\\winsecupd.exe"
                ],
                "deletion_method": "Secure deletion"
            }
        }
        self.send_event(event)
        time.sleep(1)
        
        # Timestomping
        event = {
            "time": int(time.time()),
            "sourcetype": "apt_attack",
            "source": "file_monitor",
            "event": {
                "attack_stage": "DEFENSE_EVASION",
                "technique_id": "T1070.006",
                "technique": "Timestomp",
                "severity": "MEDIUM",
                "message": "File timestamp manipulation detected",
                "src_ip": "192.168.10.100",
                "user": "domain\\dbadmin",
                "process": "timestomp.exe",
                "target_file": "C:\\Windows\\System32\\drivers\\malicious.sys",
                "original_timestamp": "2024-12-19 06:15:00",
                "modified_timestamp": "2024-01-15 09:30:00"
            }
        }
        self.send_event(event)
        time.sleep(2)
    
    def generate_comprehensive_attack(self):
        """Execute complete APT attack simulation"""
        print("🚨 STARTING COMPREHENSIVE APT ATTACK SIMULATION")
        print("=" * 60)
        print("🎯 Target: Financial Services Organization")
        print("⚔️ Operation: Shadow Finance")
        print("📅 Timeline: Multi-stage attack over simulated timeframe")
        print("=" * 60)
        
        start_time = time.time()
        
        # Execute all attack phases
        self.phase1_initial_access()
        self.phase2_persistence()
        self.phase3_privilege_escalation()
        self.phase4_lateral_movement()
        self.phase5_data_exfiltration()
        self.phase6_cover_tracks()
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n🎉 APT ATTACK SIMULATION COMPLETE")
        print(f"⏱️ Total simulation time: {duration:.2f} seconds")
        print(f"📊 Attack events generated: {len(self.attack_timeline)}")
        print(f"✅ All attack phases executed successfully")
        
        # Summary event
        summary_event = {
            "time": int(time.time()),
            "sourcetype": "apt_attack_summary",
            "source": "attack_simulator",
            "event": {
                "attack_stage": "SUMMARY",
                "operation": "Shadow Finance",
                "status": "COMPLETE",
                "duration_seconds": duration,
                "phases_executed": 6,
                "techniques_used": 15,
                "systems_compromised": ["192.168.10.25", "192.168.10.100"],
                "data_exfiltrated_gb": 2.4,
                "severity": "CRITICAL"
            }
        }
        self.send_event(summary_event)

if __name__ == "__main__":
    simulator = APTAttackSimulator()
    simulator.generate_comprehensive_attack() 