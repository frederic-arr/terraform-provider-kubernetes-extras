data "kubernetesextras_manifest" "crds" {
  api_version = "apiextensions.k8s.io/v1"
  kind        = "CustomResourceDefinitions"
  name        = "ciliumnetworkpolicies.cilium.io"
  skip_raw    = true

  retry {
    attempts = 60
    duration = 5000
  }
}
