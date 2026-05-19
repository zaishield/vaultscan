output "endpoint" { value = "https://${aws_opensearch_domain.this.endpoint}" }
output "domain_arn" { value = aws_opensearch_domain.this.arn }

# Master credentials must flow to the consolidated k8s Secret so
# analytics-worker can authenticate. Previously the random_password
# was generated, baked into the domain, then never surfaced — the
# worker booted with no credentials and silently failed to index.
output "master_user" {
  value = "admin"
}
output "master_password" {
  value     = random_password.master.result
  sensitive = true
}
