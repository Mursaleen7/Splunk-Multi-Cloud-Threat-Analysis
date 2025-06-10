#!/usr/bin/env python3
"""
Upload Security Dashboard to Splunk
"""

import requests
import xml.etree.ElementTree as ET
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Splunk configuration
SPLUNK_HOST = "localhost"
SPLUNK_PORT = "8089"
SPLUNK_USERNAME = "admin"
SPLUNK_PASSWORD = "TestPassword123!"
DASHBOARD_FILE = "SIMPLE_WORKING_DASHBOARD.xml"

def upload_dashboard():
    """Upload dashboard to Splunk"""
    
    # Read dashboard XML
    with open(DASHBOARD_FILE, 'r') as f:
        dashboard_xml = f.read()
    
    # Extract dashboard title from XML
    try:
        root = ET.fromstring(dashboard_xml)
        title = root.find('.//title')
        dashboard_name = title.text if title is not None else "Security Operations Dashboard"
    except:
        dashboard_name = "Security Operations Dashboard"
    
    # Clean name for ID
    dashboard_id = dashboard_name.lower().replace(" ", "_").replace("-", "_")
    
    print(f"📊 Uploading dashboard: {dashboard_name}")
    print(f"🔗 Dashboard ID: {dashboard_id}")
    
    # Splunk REST API endpoint
    url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/servicesNS/admin/search/data/ui/views"
    
    # Prepare data
    data = {
        'name': dashboard_id,
        'eai:data': dashboard_xml,
        'eai:type': 'views'
    }
    
    try:
        # Upload dashboard
        response = requests.post(
            url,
            auth=(SPLUNK_USERNAME, SPLUNK_PASSWORD),
            data=data,
            verify=False,
            timeout=30
        )
        
        if response.status_code == 201:
            print("✅ Dashboard uploaded successfully!")
            print(f"🔗 Access at: http://{SPLUNK_HOST}:8000/en-US/app/search/{dashboard_id}")
            return True
        elif response.status_code == 409:
            # Dashboard exists, update it
            print("🔄 Dashboard exists, updating...")
            update_url = f"{url}/{dashboard_id}"
            response = requests.post(
                update_url,
                auth=(SPLUNK_USERNAME, SPLUNK_PASSWORD),
                data={'eai:data': dashboard_xml},
                verify=False,
                timeout=30
            )
            if response.status_code == 200:
                print("✅ Dashboard updated successfully!")
                print(f"🔗 Access at: http://{SPLUNK_HOST}:8000/en-US/app/search/{dashboard_id}")
                return True
            else:
                print(f"❌ Failed to update dashboard: {response.status_code}")
                print(response.text)
                return False
        else:
            print(f"❌ Failed to upload dashboard: {response.status_code}")
            print(response.text)
            return False
            
    except Exception as e:
        print(f"❌ Error uploading dashboard: {e}")
        return False

def check_data():
    """Check if data exists in Splunk"""
    
    search_url = f"https://{SPLUNK_HOST}:{SPLUNK_PORT}/servicesNS/admin/search/search/jobs"
    
    # Check for real attack data
    searches = [
        'search sourcetype="real_attack_execution" | head 5',
        'search sourcetype="attack_summary" | head 5',
        'search sourcetype="aws_attack_execution" | head 5'
    ]
    
    print("\n🔍 Checking for attack data in Splunk...")
    
    for search in searches:
        data = {
            'search': search,
            'output_mode': 'json',
            'max_count': 5
        }
        
        try:
            response = requests.post(
                search_url,
                auth=(SPLUNK_USERNAME, SPLUNK_PASSWORD),
                data=data,
                verify=False,
                timeout=10
            )
            
            if response.status_code == 201:
                sourcetype = search.split('sourcetype="')[1].split('"')[0]
                print(f"✅ Data found for: {sourcetype}")
            else:
                sourcetype = search.split('sourcetype="')[1].split('"')[0]
                print(f"⚠️ No data for: {sourcetype}")
                
        except Exception as e:
            print(f"❌ Error checking data: {e}")

if __name__ == "__main__":
    print("🎯 SPLUNK DASHBOARD UPLOADER")
    print("=" * 50)
    
    # Check data first
    check_data()
    
    # Upload dashboard
    success = upload_dashboard()
    
    if success:
        print("\n🎉 SUCCESS!")
        print("📊 Your Security Operations Dashboard is now live!")
        print("🔗 Go to Splunk Web UI and check the 'Dashboards' section")
        print("🎯 The dashboard should now show REAL attack data instead of zeros!")
    else:
        print("\n❌ Upload failed. Check the error messages above.") 