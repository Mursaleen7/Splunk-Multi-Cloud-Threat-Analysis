output "splunk_instance_id" {
  description = "ID of the Splunk EC2 instance"
  value       = aws_instance.splunk-server.id
}

output "splunk_public_ip" {
  description = "Public IP address of the Splunk server"
  value       = aws_eip.splunk_ip.public_ip
}

output "splunk_private_ip" {
  description = "Private IP address of the Splunk server"
  value       = aws_instance.splunk-server.private_ip
}

output "splunk_instance" {
  description = "The complete Splunk instance object"
  value       = aws_instance.splunk-server
} 