output "cluster_endpoint" {
  description = "Endpoint for EKS control plane"
  value       = aws_eks_cluster.main.endpoint
}

output "cluster_name" {
  description = "Name of the EKS cluster"
  value       = aws_eks_cluster.main.name
}

output "cluster_certificate_authority_data" {
  description = "Base64 encoded certificate data required to communicate with the cluster"
  value       = aws_eks_cluster.main.certificate_authority[0].data
}

output "ecr_repository_url" {
  description = "URL of the ECR repository"
  value       = aws_ecr_repository.app.repository_url
}

output "node_group_general_arn" {
  description = "ARN of the general node group"
  value       = aws_eks_node_group.general.arn
}

output "node_group_spot_arn" {
  description = "ARN of the spot node group"
  value       = aws_eks_node_group.spot.arn
}