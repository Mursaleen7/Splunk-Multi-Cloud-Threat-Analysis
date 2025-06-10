variable "config" {
  description = "Configuration object containing all attack range settings"
  type = object({
    # Global settings
    range_name               = string
    key_name                = string
    region                  = string
    private_key_path        = string
    public_key_path         = string
    ip_whitelist           = string
    attack_range_password   = string
    cloud_provider         = string
    
    # Instance settings
    instance_type_ec2       = string
    
    # Splunk settings
    splunk_server_private_ip = string
    splunk_url              = string
    splunk_binary           = string
    s3_bucket_url          = string
    splunk_cim_app         = string
    splunk_escu_app        = string
    splunk_asx_app         = string
    splunk_python_app      = string
    splunk_mltk_app        = string
    splunk_security_essentials_app = string
    splunk_aws_app         = string
    install_es             = string
    splunk_es_app          = string
    install_mltk           = string
    
    # Phantom settings
    phantom_server           = string
    phantom_server_private_ip = string
    phantom_community_username = string
    phantom_community_password = string
    phantom_app             = string
    
    # Kubernetes settings
    kubernetes              = string
    cluster_version         = string
    app                    = string
    repo_name              = string
    repo_url               = string
    
    # CloudTrail settings
    sqs_queue_url          = string
    
    # Atomic Red Team settings
    atomic_red_team_path   = string
  })
}
