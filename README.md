# 🛡️ Splunk Cloud Threat Analysis Platform

## 🔍 Project Overview

The **Splunk Cloud Attack Range** is a hands-on cybersecurity lab environment built for practical AWS security monitoring and MITRE ATT&CK-based attack simulation. This project combines **AWS infrastructure provisioning**, **Splunk dashboarding**, and **real attack execution** to create a complete security operations testbed.

![Security Operations Dashboard](./img/Screenshot%202025-06-14%20at%201.50.14%20AM.png)

The dashboard above demonstrates my implementation of real-time security monitoring with Splunk, including executive metrics, MITRE ATT&CK framework coverage, and detailed command execution monitoring. The "ELEVATED" threat assessment is dynamically calculated based on event volume thresholds.

## ✨ Key Features

### 🌩️ AWS Cloud Infrastructure & Security Monitoring
- **Terraform-automated AWS deployment** with EC2, VPC, IAM, and security group configuration
- **CloudTrail event collection** for AWS API activity monitoring 
- **Working with real AWS credentials** to demonstrate actual API response patterns
- **IAM permission boundaries testing** with real access denied messages

![AWS Attack Execution](./img/Screenshot%202025-06-14%20at%201.50.41%20AM.png)

As shown above, the system captures real AWS API calls, including access denied errors that demonstrate my understanding of AWS's permission model and how CloudTrail logs API activity. Each command is executed with proper technique mapping (T1537 - AWS Data Transfer in this example).

### 🔥 Real Attack Execution & Simulation
- **Genuine command execution** with subprocess-driven system commands
- **AWS API attack simulation** making actual API calls to test security controls
- **MITRE ATT&CK framework alignment** with proper technique mapping:
  - T1082 - System Information Discovery
  - T1083 - File and Directory Discovery
  - T1057 - Process Discovery
  - T1016 - System Network Configuration Discovery
  - T1049 - System Network Connections Discovery
  - and more...
- **Command & Control (C2) simulation** with DNS lookups and network discovery

![MITRE ATT&CK Coverage](./img/Screenshot%202025-06-14%20at%201.50.28%20AM.png)

The dashboard section above shows my implementation of MITRE ATT&CK framework monitoring. Each technique panel tracks specific attack patterns using carefully crafted Splunk queries that identify command patterns associated with that technique. The counts represent actual executed commands matching each technique signature.

### 📊 Interactive Security Dashboard
- **Real-time security metrics** with threat assessment indicators
- **Executive summary panels** showing attack activity at a glance
- **MITRE technique tracking** panels showing attack coverage
- **Security event timeline** for chronological attack visualization
- **Command execution monitor** showing detailed attack commands and results

![Security Event Analysis](./img/Screenshot%202025-06-14%20at%201.51.01%20AM.png)

The Security Event Analysis section demonstrates my understanding of how to correlate security events by technique, risk level, host, and source. This table implements dynamic risk scoring based on technique severity and provides analysts with the context needed for triage.

### 🐳 Container & Infrastructure Support
- **Docker containerization** for portable deployment
- **Optional Kubernetes (EKS) integration** for container orchestration
- **LocalStack support** for AWS service simulation in development
- **Splunk Universal Forwarder** configuration for data collection

## 🚀 Getting Started

### Prerequisites
- AWS Account with appropriate permissions
- Docker and Docker Compose
- Python 3.8+
- Terraform 1.0+

### Quick Start

1. **Clone Repository**
   ```bash
   git clone https://github.com/yourusername/splunk-cloud-attack-range.git
   cd splunk-cloud-attack-range
   ```

2. **Configure AWS Credentials**
   ```bash
   aws configure
   ```

3. **Deploy Local Environment**
   ```bash
   docker-compose up -d splunk
   ```

4. **Run Attack Simulation**
   ```bash
   python3 real_attack_executor.py
   python3 aws_attack_executor.py
   ```

5. **Upload & View Dashboard**
   ```bash
   python3 ingest_real_attack_data.py
   python3 upload_dashboard.py
   ```

## 💪 Skills Demonstrated

This project showcases practical skills in:

- **AWS Security Operations** - Understanding CloudTrail, API permissions, and security monitoring
- **Infrastructure as Code** - Using Terraform to deploy secure infrastructure
- **Security Monitoring** - Building functional Splunk dashboards for attack visibility
- **Attack Execution** - Writing code to perform realistic attack techniques
- **MITRE ATT&CK Framework** - Correct implementation of industry-standard technique mappings
- **Containerization** - Docker implementation for portable security tools
- **Python Security Automation** - Using Python to automate security tasks

## 📈 Technical Architecture

```
┌─────────────────────────┐      ┌───────────────────────┐      ┌──────────────────────┐
│                         │      │                       │      │                      │
│   AWS Infrastructure    │      │   Attack Execution    │      │   Splunk Platform    │
│                         │      │                       │      │                      │
│ ┌─────────────────────┐ │      │ ┌───────────────────┐ │      │ ┌──────────────────┐ │
│ │ EC2 Instances       │ │      │ │ Real Commands     │ │      │ │ Data Ingestion   │ │
│ └─────────────────────┘ │      │ └───────────────────┘ │      │ └──────────────────┘ │
│                         │      │                       │      │                      │
│ ┌─────────────────────┐ │      │ ┌───────────────────┐ │      │ ┌──────────────────┐ │
│ │ VPC/Security Groups │◄├──────┤►│ AWS API Calls     │◄├──────┤►│ Event Processing │ │
│ └─────────────────────┘ │      │ └───────────────────┘ │      │ └──────────────────┘ │
│                         │      │                       │      │                      │
│ ┌─────────────────────┐ │      │ ┌───────────────────┐ │      │ ┌──────────────────┐ │
│ │ CloudTrail Logs     │ │      │ │ Attack Logging    │ │      │ │ Dashboarding     │ │
│ └─────────────────────┘ │      │ └───────────────────┘ │      │ └──────────────────┘ │
│                         │      │                       │      │                      │
└─────────────────────────┘      └───────────────────────┘      └──────────────────────┘
```

## 🛠️ Security Implementation Details

### AWS API Attack Techniques
The project implements several AWS API attack techniques including:

```python
# From aws_attack_executor.py
def t1537_aws_data_transfer(self):
    """AWS Data Transfer technique"""
    # Check for accessible S3 buckets first
    accessible_buckets = []
    try:
        response = self.s3.list_buckets()
        for bucket in response['Buckets']:
            accessible_buckets.append(bucket['Name'])
    except Exception as e:
        self.log_attack_event("T1537", "AWS Data Transfer", "aws s3 ls", 
                              {"success": False, "error": str(e)})
    
    # Attempt to access bucket ACLs - commonly blocked by policies
    for bucket in accessible_buckets:
        cmd = f"aws s3api get-bucket-acl --bucket {bucket}"
        result = self.execute_command(cmd)
        self.log_attack_event("T1537", "AWS Data Transfer", cmd, result)
```

This code demonstrates my understanding of:
1. AWS S3 permission models
2. How to test for overly permissive bucket policies
3. Proper error handling for security testing
4. MITRE technique implementation (T1537)

### MITRE ATT&CK Framework Implementation

My MITRE ATT&CK implementation directly maps techniques to real commands:

```xml
<!-- From SIMPLE_WORKING_DASHBOARD.xml -->
<panel>
  <single>
    <title>T1083 • File Discovery</title>
    <search>
      <query>index=main ("ls" OR "dir" OR "find" OR "locate") earliest=-1h | stats count</query>
      <earliest>-1h</earliest>
      <latest>now</latest>
      <refresh>30s</refresh>
    </search>
    <option name="drilldown">none</option>
  </single>
</panel>
```

The above Splunk query demonstrates proper technique detection by:
1. Identifying file discovery commands accurately
2. Using pattern matching for common variations
3. Implementing proper time-based filtering
4. Creating actionable metrics for security analysts

## 🛠️ Advanced Usage

### Terraform Deployment
Deploy a complete AWS environment with:
```bash
python3 deploy_attack_range.py
```

### Custom Attack Chains
Extend attack sequences with your own techniques:
```python
# Add to real_attack_executor.py
def custom_attack_technique(self):
    cmd = "your command here"
    result = self.execute_command(cmd)
    self.log_attack_event("T1234", "Custom Technique", cmd, result)
```

### Dashboard Customization
Modify `SIMPLE_WORKING_DASHBOARD.xml` to create custom security visualizations.

## 📚 Learning Resources

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Splunk Documentation](https://docs.splunk.com/)
- [AWS Security Best Practices](https://aws.amazon.com/security/)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/)

---

*This project is designed for security education and authorized testing environments only. All attack simulations should be performed only in controlled environments.*
