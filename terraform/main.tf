terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "6.13.0"
    }

    random = {
      source  = "hashicorp/random"
      version = "3.7.2"
    }
  }

  # TODO: Uncomment after first apply to enable remote state
  #   backend "s3" {
  #     bucket = ""
  #     key = "infrastructure/terraform.tfstate"
  #     region = "us-east-1"
  #     encrypt = true
  #     dynamodb_table = ""
  #   }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terrraform"
    }
  }
}

module "networking" {
  source               = "./modules/networking"
  project_name         = var.project_name
  public_subnet_cidrs  = var.public_subnet_cidrs
  private_subnet_cidrs = var.private_subnet_cidrs

}

module "security" {
  source       = "./modules/security"
  project_name = var.project_name
  environment  = var.environment
  vpc_id       = module.networking.vpc_id
  depends_on = [module.networking]

}

module "compute" {
  source                    = "./modules/compute"
  project_name              = var.project_name
  vpc_id                    = module.networking.vpc_id
  private_subnet_ids        = module.networking.private_subnet_ids
  public_subnet_ids         = module.networking.public_subnet_ids
  cluster_role_arn          = module.security.eks_cluster_role_arn
  node_role_arn             = module.security.eks_node_role_arn
  cluster_security_group_id = module.security.eks_cluster_security_group_id
  kms_key_arn               = module.security.kms_key_arn
  nodes_security_group_id   = module.security.eks_nodes_security_group_id
  depends_on = [module.networking, module.security]
}

module "database" {
  source                  = "./modules/database"
  project_name            = var.project_name
  vpc_id                  = module.networking.vpc_id
  private_subnet_ids      = module.networking.private_subnet_ids
  rds_security_group_id   = module.security.rds_security_group_id
  redis_security_group_id = module.security.redis_security_group_id
  kms_key_arn             = module.security.kms_key_arn
  depends_on = [module.networking, module.security]
}

module "compliance" {
  source = "./modules/compliance"

  project_name                 = var.project_name
  environment                  = var.environment
  aws_region                   = var.aws_region
  finding_publishing_frequency = var.finding_publishing_frequency
  enable_s3_protection         = var.enable_s3_protection
  enable_kubernetes_protection = var.enable_kubernetes_protection
  enable_malware_protection    = var.enable_malware_protection
  notification_email           = var.notification_email
  depends_on = [module.networking, module.security, module.compute, module.database]

}

module "monitoring" {
  source = "./modules/monitoring"

  project_name       = var.project_name
  environment        = var.environment
  eks_cluster_name   = module.compute.cluster_name
  rds_instance_id    = module.database.rds_instance_id
  redis_cluster_id   = module.database.redis_cluster_id
  sns_topic_arn      = module.security.sns_topic_arn
  log_retention_days = 30

  depends_on = [
    module.compute,
    module.database,
    module.security
  ]
}



module "bonus" {
  source = "./modules/bonus"

  project_name       = var.project_name
  environment        = var.environment
  sns_topic_arn      = module.security.sns_topic_arn # Make sure this SNS topic exists and is passed here
  slack_webhook_url  = var.slack_webhook_url
  gemini_api_key     = var.gemini_api_key
  vpc_id             = module.networking.vpc_id
  private_subnet_ids = module.networking.private_subnet_ids
  depends_on = [module.networking, module.security, module.compute, module.database, module.compliance]

}



