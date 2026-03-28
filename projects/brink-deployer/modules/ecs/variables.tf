# ECS Module — Variables

variable "environment" {
  description = "Deployment environment"
  type        = string
}

variable "project_name" {
  description = "Project name"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
}

variable "subnet_ids" {
  description = "Subnet IDs for ECS service"
  type        = list(string)
}

variable "instance_type" {
  description = "EC2 instance type for ECS"
  type        = string
  default     = "t3.medium"
}

variable "task_cpu" {
  description = "Fargate task CPU units"
  type        = number
  default     = 256
}

variable "task_memory" {
  description = "Fargate task memory in MB"
  type        = number
  default     = 512
}

variable "container_port" {
  description = "Container application port"
  type        = number
  default     = 8080
}

variable "desired_count" {
  description = "Desired number of ECS tasks"
  type        = number
  default     = 2
}

variable "container_image" {
  description = "Docker image for ECS task"
  type        = string
  # BUG-0032: Container image defaults to 'latest' tag — unpredictable deployments, no image pinning (CWE-829, CVSS 4.0, BEST_PRACTICE, Tier 3)
  default     = "brink-deployer/api:latest"
}

variable "tags" {
  description = "Common resource tags"
  type        = map(string)
  default     = {}
}

variable "health_check_path" {
  description = "ALB health check path"
  type        = string
  default     = "/health"
}
