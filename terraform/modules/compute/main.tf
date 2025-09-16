# EKS Cluster
resource "aws_eks_cluster" "main" {
  name     = "${var.project_name}-cluster"
  role_arn = var.cluster_role_arn
  version  = "1.28"

  vpc_config {
    subnet_ids              = concat(var.private_subnet_ids, var.public_subnet_ids)
    security_group_ids      = [var.cluster_security_group_id]
    endpoint_private_access = true
    endpoint_public_access  = true
  }

  encryption_config {
    provider {
      key_arn = var.kms_key_arn
    }
    resources = ["secrets"]
  }

  depends_on = [aws_cloudwatch_log_group.eks]

  tags = {
    Name = "${var.project_name}-eks-cluster"
  }
}

# CloudWatch Log Group for EKS
resource "aws_cloudwatch_log_group" "eks" {
  name              = "/aws/eks/${var.project_name}-cluster/cluster"
  retention_in_days = 7
  kms_key_id        = var.kms_key_arn
}

# EKS Node Group 1 (General Purpose)
resource "aws_eks_node_group" "general" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "general-nodes"
  node_role_arn   = var.node_role_arn
  subnet_ids      = var.private_subnet_ids
  scaling_config {
    desired_size = 2
    max_size     = 4
    min_size     = 1
  }

  update_config {
    max_unavailable = 1
  }

  instance_types = ["t3.medium"]
  capacity_type  = "ON_DEMAND"

  labels = {
    role = "general"
  }

  tags = {
    Name = "${var.project_name}-general-nodes"
  }

}

# EKS Node Group 2 (Spot Instances for cost optimization)
resource "aws_eks_node_group" "spot" {
  cluster_name    = aws_eks_cluster.main.name
  node_group_name = "spot-nodes"
  node_role_arn   = var.node_role_arn
  subnet_ids      = var.private_subnet_ids

  scaling_config {
    desired_size = 1
    max_size     = 3
    min_size     = 0
  }

  update_config {
    max_unavailable = 1
  }

  instance_types = ["t3.medium", "t3.large"]
  capacity_type  = "SPOT"

  labels = {
    role = "spot"
  }

  tags = {
    Name = "${var.project_name}-spot-nodes"
  }
}

# ECR Repository for Docker images
resource "aws_ecr_repository" "app" {
  name                 = "${var.project_name}-app"
  image_tag_mutability = "MUTABLE"

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = var.kms_key_arn
  }

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name = "${var.project_name}-app-repo"
  }
}

# ECR Lifecycle Policy
resource "aws_ecr_lifecycle_policy" "app" {
  repository = aws_ecr_repository.app.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 10 images"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["v"]
          countType     = "imageCountMoreThan"
          countNumber   = 10
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}