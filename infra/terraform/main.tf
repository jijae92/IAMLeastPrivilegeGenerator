terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

resource "aws_s3_bucket" "cloudtrail" {
  bucket = "example-cloudtrail-ingest"
}

# TODO: Add Lambda, DynamoDB, and API Gateway equivalents
