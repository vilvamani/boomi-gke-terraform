output "filestore_ip" {
  value       = google_filestore_instance.filestore_instance.networks.0.ip_addresses.0
}

output "bastion_vm_ip" {
 value = google_compute_instance.bastion.network_interface.0.access_config.0.nat_ip
}

output "cluster_name" {
  value = google_container_cluster.gke_cluster.name
}

output "gke_service_account" {
  description = "The email/name of the GKE service account"
  value       = google_service_account.gke_sa.email
}

output "bastion_service_account" {
  description = "The email/name of the bastion VM service account"
  value       = google_service_account.bastion_sa.email
}

output "master_version" {
  value       = google_container_cluster.gke_cluster.master_version
}

output "endpoint" {
  sensitive   = true
  value       = google_container_cluster.gke_cluster.endpoint
}

output "ingress_controller_ip" {
  value       = google_compute_address.ingress_ip.address
}
