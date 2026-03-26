# IAM role for the secrets-init-secrets-webhook ServiceAccount via EKS Pod Identity.
#
# Why Pod Identity:
# - No OIDC provider dependency — simpler trust policy
# - No annotation on the ServiceAccount — association is managed here in OpenTofu
# - No projected token volume in the pod spec — credentials injected by the
#   Pod Identity Agent daemonset transparently
# - Supports cross-account access and session tags out of the box

variable "aws_account_id" {
  type        = string
  description = "AWS account ID"
}

variable "cluster_name" {
  type        = string
  description = "EKS cluster name"
}

variable "webhook_namespace" {
  type        = string
  description = "Kubernetes namespace where the webhook is deployed"
  default     = "secrets-init-system"
}

variable "webhook_service_account" {
  type        = string
  description = "Kubernetes ServiceAccount name for the webhook"
  default     = "secrets-init-secrets-webhook"
}

variable "aws_region" {
  type        = string
  description = "AWS region"
}

# ── IAM policy ────────────────────────────────────────────────────────────────
# The webhook only needs ECR read access to discover image ENTRYPOINT/CMD.
# Secrets Manager access is NOT needed — secrets are resolved by secrets-init
# inside the target pod using the target pod's own Pod Identity credentials.

resource "aws_iam_policy" "secrets_webhook" {
  name        = "secrets-init-secrets-webhook"
  description = "Allows the secrets webhook to pull image configs from ECR"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ecr:GetAuthorizationToken",
          "ecr:BatchGetImage",
          "ecr:GetDownloadUrlForLayer",
        ]
        Resource = "*"
      }
    ]
  })
}

# ── IAM role with Pod Identity trust policy ───────────────────────────────────
# Pod Identity trust policy trusts pods.eks.amazonaws.com — no OIDC provider
# needed. The association below binds this role to the specific namespace and
# ServiceAccount so only the webhook pods can assume it.

resource "aws_iam_role" "secrets_webhook" {
  name        = "secrets-init-secrets-webhook"
  description = "Pod Identity role for the secrets-init-secrets-webhook Kubernetes ServiceAccount"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "pods.eks.amazonaws.com"
        }
        Action = [
          "sts:AssumeRole",
          "sts:TagSession"
        ]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "secrets_webhook" {
  role       = aws_iam_role.secrets_webhook.name
  policy_arn = aws_iam_policy.secrets_webhook.arn
}

# ── Pod Identity Association ──────────────────────────────────────────────────
# Binds the IAM role to the specific namespace + ServiceAccount combination.
# Only pods in webhook_namespace using webhook_service_account can assume the role.
# This replaces the need for ServiceAccount annotations — no cluster changes needed.

resource "aws_eks_pod_identity_association" "secrets_webhook" {
  cluster_name    = var.cluster_name
  namespace       = var.webhook_namespace
  service_account = var.webhook_service_account
  role_arn        = aws_iam_role.secrets_webhook.arn
}

# ── Outputs ───────────────────────────────────────────────────────────────────

output "role_arn" {
  value       = aws_iam_role.secrets_webhook.arn
  description = "IAM role ARN associated via Pod Identity — no Helm value needed"
}

output "pod_identity_association_id" {
  value       = aws_eks_pod_identity_association.secrets_webhook.association_id
  description = "Pod Identity Association ID for reference"
}
