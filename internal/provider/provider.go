// Copyright (c) The Kubernetes Extras Provider for Terraform Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	restclient "k8s.io/client-go/rest"
)

// Ensure KubernetesExtrasProvider satisfies various provider interfaces.
var _ provider.Provider = &KubernetesExtrasProvider{}
var _ provider.ProviderWithFunctions = &KubernetesExtrasProvider{}

// KubernetesExtrasProvider defines the provider implementation.
type KubernetesExtrasProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// KubernetesExtrasProviderModel describes the provider data model.
type KubernetesExtrasProviderModel struct {
	Kubernetes types.Object `tfsdk:"kubernetes"`
}

type KubernetesExtrasProviderData struct {
	client *clientset.Clientset
	cfg    *restclient.Config
}

func (p *KubernetesExtrasProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "kubernetesextras"
	resp.Version = p.version
}

func (p *KubernetesExtrasProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Kubernetes Extras provider provides additional functionality for Kubernetes resources (mostly retrying/waiting for resource availability).",
		Blocks: map[string]schema.Block{
			"kubernetes": kubernetesSchema(),
		},
	}
}

func (p *KubernetesExtrasProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data KubernetesExtrasProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cfg := kubernetesConfigure(ctx, req, resp, fmt.Sprintf("Kubernetes Extras/%s Terraform/%s", p.version, req.TerraformVersion), data.Kubernetes)
	if resp.Diagnostics.HasError() {
		return
	}

	client := kubernetesClientset(ctx, req, resp, cfg)
	if resp.Diagnostics.HasError() {
		return
	}

	providerData := KubernetesExtrasProviderData{
		client: client,
		cfg:    cfg,
	}

	resp.DataSourceData = &providerData
	resp.ResourceData = &providerData
}

func (p *KubernetesExtrasProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{}
}

func (p *KubernetesExtrasProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewManifestDataSource,
	}
}

func (p *KubernetesExtrasProvider) Functions(ctx context.Context) []func() function.Function {
	return []func() function.Function{}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &KubernetesExtrasProvider{
			version: version,
		}
	}
}
