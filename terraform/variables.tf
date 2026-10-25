variable "aws_region" {
  description = "AWS region for the lab"
  type        = string
  default     = "ap-southeast-2"
}

variable "aws_profile" {
  description = "Local AWS CLI profile used to authenticate (via aws login)"
  type        = string
  default     = "dac"
}

variable "project_name" {
  description = "Prefix applied to resource names"
  type        = string
  default     = "dac"
}

variable "account_id" {
  description = "AWS account ID for the lab"
  type        = string
}
