output "endpoint" {
  value = "http://${var.cluster_name}.${var.cluster_namespace}.svc.cluster.local:9200"
}
output "domain_arn" {
  value       = ""
  description = "AWS-only — empty here for shape compatibility."
}
