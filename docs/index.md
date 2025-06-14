---
# generated by https://github.com/hashicorp/terraform-plugin-docs
page_title: "kubernetesextras Provider"
subcategory: ""
description: |-
  Kubernetes Extras provider provides additional functionality for Kubernetes resources (mostly retrying/waiting for resource availability).
---

# kubernetesextras Provider

Kubernetes Extras provider provides additional functionality for Kubernetes resources (mostly retrying/waiting for resource availability).

## Example Usage

```terraform
provider "kubernetesextras" {
  kubernetes {
    host                   = var.host
    client_certificate     = var.client_certificate
    client_key             = var.client_key
    cluster_ca_certificate = var.cluster_ca_certificate
  }
}
```

<!-- schema generated by tfplugindocs -->
## Schema

### Optional

- `kubernetes` (Block, Optional) See the [Kubernetes provider documentation](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs) for more information. (see [below for nested schema](#nestedblock--kubernetes))

<a id="nestedblock--kubernetes"></a>
### Nested Schema for `kubernetes`

Optional:

- `client_certificate` (String) PEM-encoded client certificate for TLS authentication. Can be set with the `KUBE_CLIENT_CERT_DATA` environment variable.
- `client_key` (String) PEM-encoded client certificate key for TLS authentication. Can be set with the `KUBE_CLIENT_KEY_DATA` environment variable.
- `cluster_ca_certificate` (String) PEM-encoded root certificates bundle for TLS authentication. Can be set with the `KUBE_CLUSTER_CA_CERT_DATA` environment variable.
- `config_context` (String) Context to choose from the config file. Can be set with the `KUBE_CTX` environement variable.
- `config_context_auth_info` (String) Authentication info context of the kube config (name of the kubeconfig user, `--user` flag in `kubectl`). Can be set with the `KUBE_CTX_AUTH_INFO` environement variable.
- `config_context_cluster` (String) Cluster context of the kube config (name of the kubeconfig cluster, `--cluster` flag in `kubectl`). Can be set with the `KUBE_CTX_CLUSTER` environement variable.
- `config_path` (String) A path to a kube config file. Can be set with the `KUBE_CONFIG_PATHS` environement variable.
- `config_paths` (String) A list of paths to the kube config files. Can be set with the `KUBE_CONFIG_PATH` environement variable.
- `host` (String) The hostname (in form of URI) of Kubernetes master. Can be set with the `KUBE_HOST` environment variable.
- `insecure` (Boolean) Whether server should be accessed without verifying the TLS certificate. Can be set with the `tru` environment variable.
- `password` (String) The password to use for HTTP basic authentication when accessing the Kubernetes master endpoint. Can be set with the `KUBE_PASSWORD` environment variable.
- `proxy_url` (String) URL to the proxy to be used for all API requests. Can be set with the `KUBE_PROXY_URL` environment variable.
- `tls_server_name` (String) Server name passed to the server for SNI and is used in the client to check server certificates against. Can be set with the `KUBE_TLS_SERVER_NAME` environment variable.
- `token` (String) Token to authenticate an service account. Can be set with the `KUBE_TOKEN` environment variable.
- `username` (String) The username to use for HTTP basic authentication when accessing the Kubernetes master endpoint. Can be set with the `KUBE_USER` environment variable.
