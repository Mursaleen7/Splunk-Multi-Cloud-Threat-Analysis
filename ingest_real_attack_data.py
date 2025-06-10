#!/usr/bin/env python3
"""
Real Attack Data Ingestion - Load REAL attack data into Splunk
This includes both real system-level attacks and REAL AWS API calls
"""

import json
import requests
import os
import urllib3
from datetime import datetime
import time

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Splunk HEC configuration
SPLUNK_HEC_URL = "https://localhost:8088/services/collector"
SPLUNK_HEC_TOKEN = "Splunk 12345678-1234-5678-9012-123456789012"

# Splunk REST API configuration
SPLUNK_REST_URL = "https://localhost:8089"
SPLUNK_USERNAME = "admin"
SPLUNK_PASSWORD = "TestPassword123!"

def send_to_splunk_hec(event_data, source, sourcetype):
    """Send data to Splunk via HEC"""
    headers = {
        "Authorization": SPLUNK_HEC_TOKEN,
        "Content-Type": "application/json"
    }
    
    payload = {
        "time": int(time.time()),
        "event": event_data,
        "source": source,
        "sourcetype": sourcetype,
        "index": "main"
    }
    
    try:
        response = requests.post(
            SPLUNK_HEC_URL, 
            json=payload, 
            headers=headers, 
            verify=False, 
            timeout=10
        )
        if response.status_code == 200:
            return True
        else:
            return False
    except Exception:
        return False

def send_to_splunk_rest(event_data, source, sourcetype):
    """Send data to Splunk via REST API as fallback"""
    url = f"{SPLUNK_REST_URL}/services/receivers/simple"
    
    # Convert event to JSON string for REST API
    if isinstance(event_data, dict):
        event_str = json.dumps(event_data)
    else:
        event_str = str(event_data)
    
    data = {
        "source": source,
        "sourcetype": sourcetype,
        "index": "main"
    }
    
    try:
        response = requests.post(
            url,
            auth=(SPLUNK_USERNAME, SPLUNK_PASSWORD),
            data=event_str,
            params=data,
            verify=False,
            timeout=10
        )
        return response.status_code == 200
    except Exception:
        return False

def ingest_attack_file(file_path):
    """Ingest a single attack file"""
    print(f"📂 Ingesting {file_path}...")
    
    # Determine source and sourcetype from filename
    filename = os.path.basename(file_path)
    if "aws_attack" in filename:
        source = "aws_attack_executor"
        sourcetype = "aws_attack_execution"
    elif "attack_summary" in filename:
        source = "real_attack_ingestion"
        sourcetype = "attack_summary"
    elif "attack_execution" in filename:
        source = "attack_executor"
        sourcetype = "real_attack_execution"
    else:
        source = "real_attack_ingestion"
        sourcetype = "attack_data"
    
    print(f"📂 Ingesting {file_path} as sourcetype '{sourcetype}'...")
    
    try:
        with open(file_path, 'r') as f:
            # Check if file contains line-delimited JSON (NDJSON)
            first_line = f.readline().strip()
            f.seek(0)
            
            if first_line.startswith('{"time"'):
                # NDJSON format - read line by line
                data = []
                for line in f:
                    line = line.strip()
                    if line:
                        data.append(json.loads(line))
            else:
                # Regular JSON format
                data = json.load(f)
        
        events_sent = 0
        events_failed = 0
        
        # Handle different JSON structures
        if isinstance(data, dict):
            if "detailed_results" in data:
                # This is an attack summary file - ingest individual events
                for event in data["detailed_results"]:
                    success = send_to_splunk_hec(event, source, sourcetype)
                    if not success:
                        success = send_to_splunk_rest(event, source, sourcetype)
                    
                    if success:
                        events_sent += 1
                    else:
                        events_failed += 1
                
                # Also ingest the summary
                summary_data = {k: v for k, v in data.items() if k != "detailed_results"}
                success = send_to_splunk_hec(summary_data, source, "attack_execution_summary")
                if not success:
                    send_to_splunk_rest(summary_data, source, "attack_execution_summary")
                
            elif isinstance(data, dict) and any(key in data for key in ["attacks", "aws_operations", "technique_id"]):
                # Single event
                success = send_to_splunk_hec(data, source, sourcetype)
                if not success:
                    success = send_to_splunk_rest(data, source, sourcetype)
                
                if success:
                    events_sent += 1
                else:
                    events_failed += 1
            else:
                # Generic dict - send as single event
                success = send_to_splunk_hec(data, source, sourcetype)
                if not success:
                    success = send_to_splunk_rest(data, source, sourcetype)
                
                if success:
                    events_sent += 1
                else:
                    events_failed += 1
        
        elif isinstance(data, list):
            # Array of events
            for event in data:
                success = send_to_splunk_hec(event, source, sourcetype)
                if not success:
                    success = send_to_splunk_rest(event, source, sourcetype)
                
                if success:
                    events_sent += 1
                else:
                    events_failed += 1
        
        if events_failed > 0 and events_sent == 0:
            print(f"🔄 Using REST API for {file_path}...")
            # Try entire file as single event via REST API
            success = send_to_splunk_rest(data, source, sourcetype)
            if success:
                events_sent = 1
                events_failed = 0
                print(f"✅ REST API ingestion successful: {events_sent} events")
            else:
                print(f"❌ Failed to ingest {file_path}")
        else:
            print(f"✅ Ingestion complete: {events_sent} events sent, {events_failed} failed")
    
    except json.JSONDecodeError as e:
        print(f"❌ JSON parsing error in {file_path}: {e}")
        return 0
    except Exception as e:
        print(f"❌ Error processing {file_path}: {e}")
        return 0
    
    return events_sent

def main():
    """Main ingestion function"""
    print("🎯 REAL ATTACK DATA INGESTION")
    print("=" * 50)
    
    attack_logs_dir = "attack_logs"
    if not os.path.exists(attack_logs_dir):
        print(f"❌ Attack logs directory '{attack_logs_dir}' not found")
        return
    
    total_events = 0
    
    # Get all JSON files in attack_logs directory
    json_files = [f for f in os.listdir(attack_logs_dir) if f.endswith('.json')]
    
    if not json_files:
        print("❌ No JSON files found in attack_logs directory")
        return
    
    print(f"📁 Found {len(json_files)} JSON files to ingest")
    
    for json_file in sorted(json_files):
        file_path = os.path.join(attack_logs_dir, json_file)
        
        # Check if file has been modified recently or is attack summary
        if "attack_summary" in json_file:
            print(f"📊 Attack Summary: {file_path}")
            events = ingest_attack_file(file_path)
            total_events += events
        elif "aws_attack" in json_file:
            print(f"☁️ AWS Attack Data: {file_path}")
            events = ingest_attack_file(file_path)
            total_events += events
        elif "attack_execution" in json_file:
            print(f"⚔️ Attack Execution Data: {file_path}")
            events = ingest_attack_file(file_path)
            total_events += events
    
    print("\n🎯 REAL ATTACK DATA INGESTION COMPLETE")
    print(f"📈 Total events ingested: {total_events}")
    print("🔍 Data types included:")
    print("   • Real system command execution")
    print("   • Real AWS API call results")
    print("   • MITRE ATT&CK technique mapping")
    print("   • Actual permission denials and successes")

if __name__ == "__main__":
    main() 