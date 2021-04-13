provider "google" {
  version = "~> 3.63.0"
  project = var.project
  region  = var.region
  zone    = var.zone
}

provider "google-beta" {
  version = "~> 3.43.0"
  project = var.project
  region  = var.region
  zone    = var.zone
}

data "google_client_config" "current" {}
