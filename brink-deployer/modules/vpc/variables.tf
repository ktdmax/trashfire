# VPC Module — Variables

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
}

variable "environment" {
  description = "Deployment environment"
  type        = string
}

variable "project_name" {
  description = "Project name"
  type        = string
}

variable "availability_zones" {
  description = "List of AZs for subnets"
  type        = list(string)
}

variable "tags" {
  description = "Common resource tags"
  type        = map(string)
  default     = {}
}

variable "enable_flow_logs" {
  description = "Enable VPC flow logs"
  type        = bool
  # BUG-0027: VPC flow logs default to disabled — no network traffic visibility (CWE-778, CVSS 6.0, HIGH, Tier 2)
  default     = false
}

variable "single_nat_gateway" {
  description = "Use a single NAT gateway (cost savings for non-prod)"
  type        = bool
  default     = true
}
