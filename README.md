# Kubernetes Extras Provider for Terraform

The [Kubernetes Extras provider for Terraform](https://registry.terraform.io/providers/frederic-arr/kubernetes-extras/latest) is a plugin that brings additional functionality to the existing [Kubernetes provider](https://registry.terraform.io/providers/hashicorp/kubernetes). It is designed to be used in conjunction with the Kubernetes provider to provide additional resources and functionality.

Currently, the provider supports the following **data sources**:
- [Kubernetes Manifest](https://registry.terraform.io/providers/frederic-arr/kubernetes-extras/latest/docs/data-sources/manifest)
  Allows you to read a Kubernetes manifest file and use it as a data source in your Terraform configuration. The data source can automatically retry fetching the manifest if it is not found. This is useful when you are deploying resources that depend on other resources that may not be ready yet and are being created outside of Terraform.
