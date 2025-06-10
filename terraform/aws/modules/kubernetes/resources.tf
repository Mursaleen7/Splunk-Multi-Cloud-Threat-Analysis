data "aws_eks_cluster" "cluster" {
  count = var.config.kubernetes ? 1 : 0
  name  = module.eks.cluster_id
}

data "aws_eks_cluster_auth" "cluster" {
  count = var.config.kubernetes ? 1 : 0
  name  = module.eks.cluster_id
}

# Removed legacy inline provider configuration - should be configured at root level

module "eks" {
  create_eks   = var.config.kubernetes
  source       = "terraform-aws-modules/eks/aws"
  version      = "~> 18.0"
  cluster_name = "kubernetes_${var.config.key_name}"
  subnets      = var.vpc_private_subnets
  cluster_enabled_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]
  cluster_version = var.config.cluster_version

  tags = {
    Environment = "training"
    GithubRepo  = "terraform-aws-eks"
    GithubOrg   = "terraform-aws-modules"
  }

  vpc_id = var.vpc_id

  node_groups = {
    worker_group_1 = {
      desired_capacity = 2
      max_capacity     = 2
      min_capacity     = 1
      instance_types   = ["t2.small"]
      
      additional_security_group_ids = [var.sg_worker_group_mgmt_one_id]
    }
    
    worker_group_2 = {
      desired_capacity = 1
      max_capacity     = 1
      min_capacity     = 1
      instance_types   = ["t2.medium"]
      
      additional_security_group_ids = [var.sg_worker_group_mgmt_two_id]
    }
  }
}
