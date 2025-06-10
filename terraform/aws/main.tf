terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.config.region
}

# State management
terraform {
  backend "local" {
    path = "./state/terraform.tfstate"
  }
}

# Network Module
module "networkModule" {
  source = "./modules/network"
  config = var.config
}

# Splunk Server Module
module "splunk-server" {
  source                 = "./modules/splunk-server"
  vpc_security_group_ids = module.networkModule.sg_vpc_id
  ec2_subnet_id         = module.networkModule.ec2_subnet_id
  phantom_server_instance = var.config.phantom_server == "1" ? module.phantom-server[0].phantom_server_instance : null
  config                = var.config
}

# Phantom Server Module (conditional)
module "phantom-server" {
  count                      = var.config.phantom_server == "1" ? 1 : 0
  source                     = "./modules/phantom-server"
  vpc_security_group_ids     = module.networkModule.sg_vpc_id
  ec2_subnet_id             = module.networkModule.ec2_subnet_id
  config                    = var.config
}

# Kubernetes Module (conditional)
module "kubernetes" {
  count                       = var.config.kubernetes == "1" ? 1 : 0
  source                      = "./modules/kubernetes"
  config                      = var.config
  vpc_id                      = module.networkModule.vpc_id
  vpc_private_subnets         = module.networkModule.vpc_private_subnets
  sg_worker_group_mgmt_one_id = module.networkModule.sg_worker_group_mgmt_one_id
  sg_worker_group_mgmt_two_id = module.networkModule.sg_worker_group_mgmt_two_id
}

# Outputs
output "splunk_public_ip" {
  description = "Public IP address of the Splunk server"
  value       = module.splunk-server.splunk_public_ip
}

output "splunk_web_url" {
  description = "Splunk Web URL"
  value       = "https://${module.splunk-server.splunk_public_ip}:8000"
}

output "phantom_public_ip" {
  description = "Public IP address of the Phantom server"
  value       = var.config.phantom_server == "1" ? module.phantom-server[0].phantom_public_ip : null
}

output "kubernetes_cluster_name" {
  description = "Name of the Kubernetes cluster"
  value       = var.config.kubernetes == "1" ? module.kubernetes[0].cluster_name : null
} 