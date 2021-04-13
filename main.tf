##################################################
########## Generate SSH Keys ##########
##################################################
resource "tls_private_key" "this" {
  algorithm = "RSA"
  rsa_bits  = "2048"
}

resource "local_file" "private_key" {
  filename        = "${path.module}/boomi.pem"
  content         = tls_private_key.this.private_key_pem
  file_permission = "0400"
}

##################################################
########## Enabling GCP Services ##########
##################################################
// Enable required services on the project
resource "google_project_service" "enable_service_apis" {
  count   = length(var.project_services)
  service = element(var.project_services, count.index)

  // Do not disable the service on destroy. On destroy, we are going to
  // destroy the project, but we need the APIs available to destroy the
  // underlying resources.
  disable_on_destroy = false
}

##################################################
########## Google Service Account ##########
##################################################
// Dedicated service account for the GKE Cluster
resource "google_service_account" "gke_sa" {
  account_id   = format("%s-gke-cluster", var.environment)
  display_name = "GKE Cluster Service Account"
}

// Add the service account to the project
resource "google_project_iam_member" "gke_service_account" {
  count  = length(var.service_account_iam_roles)
  member = format("serviceAccount:%s", google_service_account.gke_sa.email)
  role   = element(var.service_account_iam_roles, count.index)
}

// Dedicated service account for the Bastion instance
resource "google_service_account" "bastion_sa" {
  account_id   = format("%s-bastion", var.environment)
  display_name = "GKE Bastion Service Account"
}

// Add the service account to the project
resource "google_project_iam_member" "bastion_service_account" {
  count  = length(var.service_account_iam_roles)
  member = format("serviceAccount:%s", google_service_account.bastion_sa.email)
  role   = element(var.service_account_iam_roles, count.index)
}


##################################################
########## Google Virtual Private Cloud ##########
##################################################
// Create a network for GKE
resource "google_compute_network" "vpc_network" {
  name                    = format("%s-gke-vpc", var.environment)
  mtu                     = 1500
  auto_create_subnetworks = false
  routing_mode            = "REGIONAL"
}

// Create a subnet for GKE Cluster
resource "google_compute_subnetwork" "gke_subnet" {
  name                     = format("%s-gke-subnet", var.environment)
  ip_cidr_range            = var.gke_private_subnet
  region                   = var.region
  network                  = google_compute_network.vpc_network.self_link
  private_ip_google_access = false
}

// Create a subnet for Bastion VM
resource "google_compute_subnetwork" "bastion_subnet" {
  name                     = format("%s-bastion-subnet", var.environment)
  ip_cidr_range            = var.gke_public_subnet
  region                   = var.region
  network                  = google_compute_network.vpc_network.self_link
  private_ip_google_access = true
}

// Create an external NAT IP
resource "google_compute_address" "nat_ip" {
  name   = format("%s-nat-gateway-ip", var.environment)
  region = var.region
}

resource "google_compute_address" "ingress_ip" {
  name   = format("%s-gke-ingress-ip", var.environment)
  region = var.region
}

// Create a cloud router for use by the Cloud NAT
resource "google_compute_router" "cloud_router" {
  name    = format("%s-gke-cloud-router", var.environment)
  region  = var.region
  network = google_compute_network.vpc_network.id

  bgp {
    asn = 64514
  }
}

// Create a NAT router so the nodes can reach DockerHub, etc
resource "google_compute_router_nat" "cloud_nat" {
  name   = format("%s-nat-gateway", var.environment)
  router = google_compute_router.cloud_router.name
  region = var.region

  nat_ip_allocate_option = "MANUAL_ONLY"
  nat_ips                = [google_compute_address.nat_ip.self_link]

  source_subnetwork_ip_ranges_to_nat = "LIST_OF_SUBNETWORKS"
  subnetwork {
    name                    = google_compute_subnetwork.gke_subnet.self_link
    source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
  }

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

// Allow access to the Bastion Host via SSH
resource "google_compute_firewall" "ssh_all" {
  name          = format("%s-ssh-all", var.environment)
  network       = google_compute_network.vpc_network.name
  direction     = "INGRESS"
  source_ranges = ["0.0.0.0/0"]

  allow {
    protocol = "tcp"
    ports    = ["22", "3389"]
  }

  target_tags = var.bastion_tags
}

resource "google_compute_firewall" "web_traffic" {
  name          = format("%s-web-traffic", var.environment)
  network       = google_compute_network.vpc_network.name
  source_ranges = ["0.0.0.0/0"]
  direction     = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }
}

resource "google_compute_firewall" "gke_traffic" {
  name          = format("%s-gke-traffic", var.environment)
  network       = google_compute_network.vpc_network.name
  source_ranges = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
  direction     = "INGRESS"

  allow {
    protocol = "tcp"
    ports    = ["30000-32767"]
  }
}

##################################################
########## GKE Bastion Virtual Machine ##########
##################################################
// Bastion Host
locals {
  hostname = format("%s-bastion-vm", var.environment)
}

// The user-data script on Bastion instance provisioning
data "template_file" "startup_script" {
  template = <<-EOF
  #!/bin/bash
  #### Log the execution to a file ####
  exec 3>&1 4>&2
  trap 'exec 2>&4 1>&3' 0 1 2 3 RETURN
  exec 1>/var/log/configure-bastion.log 2>&1

  set -x
  
  sudo yum update -y
  sudo yum install -y tinyproxy git wget
  
  curl -LO "https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl"
  chmod +x ./kubectl
  sudo mv ./kubectl /usr/local/bin/kubectl
  kubectl version --client

  wget https://get.helm.sh/helm-v3.5.3-linux-amd64.tar.gz
  tar -zxvf helm-v3.5.3-linux-amd64.tar.gz
  mv linux-amd64/helm /usr/local/bin/helm

  sudo yum -y install nfs-utils
  sudo mkdir -p /mnt/boominfs

  git clone https://github.com/vilvamani/gcp-deployment-manager.git

  EOF
}

// The Bastion Host
resource "google_compute_instance" "bastion" {
  name         = local.hostname
  description  = "GKE bastion machine"
  machine_type = "g1-small"
  zone         = var.zone
  tags         = var.bastion_tags

  // Specify the Operating System Family and version.
  boot_disk {
    initialize_params {
      image = "centos-cloud/centos-7"
    }
  }

  scheduling {
    automatic_restart   = true
    on_host_maintenance = "MIGRATE"
  }

  // Ensure that when the bastion host is booted, it will have tinyproxy
  metadata_startup_script = data.template_file.startup_script.rendered

  // Define a network interface in the correct subnet.
  network_interface {
    subnetwork = google_compute_subnetwork.bastion_subnet.name

    // Add an ephemeral external IP.
    access_config {
      // Ephemeral IP
    }
  }

  metadata = {
    ssh-keys = "centos:${tls_private_key.this.public_key_openssh}"
  }

  // Allow the instance to be stopped by terraform when updating configuration
  allow_stopping_for_update = true

  service_account {
    email  = google_service_account.bastion_sa.email
    scopes = ["cloud-platform"]
  }

  // local-exec providers may run before the host has fully initialized. However, they
  // are run sequentially in the order they were defined.
  //
  // This provider is used to block the subsequent providers until the instance
  // is available.
  provisioner "local-exec" {
    command = <<EOF
        READY=""
        for i in $(seq 1 20); do
          if gcloud compute ssh ${local.hostname} --project ${var.project} --zone ${var.zone} --command uptime; then
            READY="yes"
            break;
          fi
          echo "Waiting for ${local.hostname} to initialize..."
          sleep 10;
        done
        if [[ -z $READY ]]; then
          echo "${local.hostname} failed to start in time."
          echo "Please verify that the instance starts and then re-run `terraform apply`"
          exit 1
        fi
EOF
  }

  depends_on = [google_project_iam_member.bastion_service_account]
}

##################################################
########## Google Cloud File Store ##########
##################################################
resource "google_filestore_instance" "filestore_instance" {
  name = format("%s-filestore", var.environment)
  zone = var.zone
  tier = "STANDARD"

  file_shares {
    name        = "boomifileshare"
    capacity_gb = 1024
  }

  networks {
    network = google_compute_network.vpc_network.name
    modes   = ["MODE_IPV4"]
  }

  depends_on = [google_project_iam_member.gke_service_account]
}

##################################################
########## Google Kubernetes Cluster ##########
##################################################
data "google_container_engine_versions" "default" {
  location = var.region
}

resource "google_container_cluster" "gke_cluster" {
  name     = format("%s-gke-private-cluster", var.environment)
  location = var.region

  network    = google_compute_network.vpc_network.id
  subnetwork = google_compute_subnetwork.gke_subnet.id

  logging_service    = "logging.googleapis.com/kubernetes"
  monitoring_service = "monitoring.googleapis.com/kubernetes"

  // Decouple the default node pool lifecycle from the cluster object lifecycle
  // by removing the node pool and specifying a dedicated node pool in a
  // separate resource below.
  remove_default_node_pool = "true"
  initial_node_count       = 1

  min_master_version = data.google_container_engine_versions.default.latest_master_version

  // Configure various addons
  addons_config {
    http_load_balancing {
      disabled = false
    }

    horizontal_pod_autoscaling {
      disabled = false
    }

    // Enable network policy (Calico)
    network_policy_config {
      disabled = false
    }
  }

  // Enable network policy configurations (like Calico) - for some reason this
  // has to be in here twice.
  network_policy {
    enabled  = "true"
    provider = "CALICO"
  }

  master_authorized_networks_config {
    cidr_blocks {
      display_name = "bastion"
      cidr_block   = format("%s/32", google_compute_instance.bastion.network_interface.0.network_ip)
    }
  }

  // Configure the cluster to have private nodes and private control plane access only
  private_cluster_config {
    enable_private_endpoint = "true"
    enable_private_nodes    = "true"
    master_ipv4_cidr_block  = "172.16.0.16/28"
  }

  // Allocate IPs in our subnetwork
  ip_allocation_policy {
    cluster_ipv4_cidr_block  = ""
    services_ipv4_cidr_block = ""
  }


  // Allow plenty of time for each operation to finish (default was 10m)
  timeouts {
    create = "30m"
    update = "30m"
    delete = "30m"
  }

  depends_on = [
    google_project_service.enable_service_apis,
    google_project_iam_member.gke_service_account,
    google_compute_router_nat.cloud_nat
  ]
}

##################################################
########## Google Kubernetes Node Pool ##########
##################################################
resource "google_container_node_pool" "primary_nodes_pool" {
  name       = format("%s-gke-primary-node-pool", var.environment)
  location   = var.region
  cluster    = google_container_cluster.gke_cluster.name
  node_count = 1

  // Repair any issues but don't auto upgrade node versions
  management {
    auto_repair  = "true"
    auto_upgrade = "true"
  }

  node_config {
    machine_type = "n1-standard-1"
    disk_type    = "pd-ssd"
    disk_size_gb = 50
    image_type   = "COS"

    // Use the cluster created service account for this node pool
    service_account = google_service_account.gke_sa.email

    // Use the minimal oauth scopes needed
    oauth_scopes = [
      "https://www.googleapis.com/auth/devstorage.read_only",
      "https://www.googleapis.com/auth/logging.write",
      "https://www.googleapis.com/auth/monitoring",
      "https://www.googleapis.com/auth/servicecontrol",
      "https://www.googleapis.com/auth/service.management.readonly",
      "https://www.googleapis.com/auth/trace.append",
    ]

    labels = {
      cluster = google_container_cluster.gke_cluster.name
    }

    metadata = {
      // Set metadata on the VM to supply more entropy
      google-compute-enable-virtio-rng = "true"
      // Explicitly remove GCE legacy metadata API endpoint
      disable-legacy-endpoints = "true"
    }
  }

  autoscaling {
    min_node_count = 1
    max_node_count = 2
  }

  timeouts {
    create = "30m"
    update = "20m"
    delete = "20m"
  }

  depends_on = [google_container_cluster.gke_cluster]
}

##################################################
########## GKE Cluster Deployment ##########
##################################################
resource "null_resource" "helm_nfs_provisioner_deploy" {
  provisioner "remote-exec" {
    connection {
      type        = "ssh"
      host        = google_compute_instance.bastion.network_interface.0.access_config.0.nat_ip
      user        = "centos"
      private_key = tls_private_key.this.private_key_pem
    }

    inline = [
      "sleep 60",
      "gcloud container clusters get-credentials ${google_container_cluster.gke_cluster.name} --region ${var.region}",
      "helm upgrade --install nfsprovisioner --set nfs.server=${google_filestore_instance.filestore_instance.networks.0.ip_addresses.0},nfs.path=/boomifileshare,storageClass.defaultClass=true,storageClass.reclaimPolicy=Retain,storageClass.accessModes=ReadWriteMany /gcp-deployment-manager/kubernetes/nfs-client-provisioner"
    ]
  }

  depends_on = [
    google_container_cluster.gke_cluster,
    google_container_node_pool.primary_nodes_pool,
    google_filestore_instance.filestore_instance
  ]
}

resource "null_resource" "boomi_k8s_deployment" {
  provisioner "remote-exec" {
    connection {
      type        = "ssh"
      host        = google_compute_instance.bastion.network_interface.0.access_config.0.nat_ip
      user        = "centos"
      private_key = tls_private_key.this.private_key_pem
    }

    inline = [
      "gcloud container clusters get-credentials ${google_container_cluster.gke_cluster.name} --region ${var.region}",
      "helm upgrade --install boomimolecule --namespace default --set auth.type=${var.boomi_authentication_type},secrets.token=${var.boomi_mfa_install_token},secrets.username=${var.boomi_username},secrets.password=${var.boomi_password},secrets.account=${var.boomi_account_id},volume.server=${google_filestore_instance.filestore_instance.networks.0.ip_addresses.0},storage.network=${google_compute_network.vpc_network.name},ingress.staticIpName=${google_compute_address.ingress_ip.address} /gcp-deployment-manager/kubernetes/boomi-molecule"
    ]
  }

  depends_on = [null_resource.helm_nfs_provisioner_deploy]
}
