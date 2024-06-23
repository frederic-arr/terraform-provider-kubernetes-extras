// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	runtimeSchema "k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/rest"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ datasource.DataSource = &ManifestDataSource{}

func NewManifestDataSource() datasource.DataSource {
	return &ManifestDataSource{}
}

// ManifestDataSource defines the data source implementation.
type ManifestDataSource struct {
	cfg *rest.Config
}

// ManifestDataSourceModel describes the data source data model.
type ManifestDataSourceModel struct {
	Id         types.String `tfsdk:"id"`
	ApiVersion types.String `tfsdk:"api_version"`
	Kind       types.String `tfsdk:"kind"`
	Namespace  types.String `tfsdk:"namespace"`
	Name       types.String `tfsdk:"name"`
	SkipRaw    types.Bool   `tfsdk:"skip_raw"`
	Raw        types.String `tfsdk:"raw"`
	Retry      types.Object `tfsdk:"retry"`
}

func (d *ManifestDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_manifest"
}

func (d *ManifestDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manifest data source",
		Attributes: map[string]schema.Attribute{
			"api_version": schema.StringAttribute{
				MarkdownDescription: "Group and version of the manifest",
				Required:            true,
			},
			"kind": schema.StringAttribute{
				MarkdownDescription: "Kind of the manifest",
				Required:            true,
			},
			"namespace": schema.StringAttribute{
				MarkdownDescription: "Namespace of the manifest",
				Optional:            true,
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Name of the manifest",
				Required:            true,
			},
			"skip_raw": schema.BoolAttribute{
				MarkdownDescription: "Skip raw response of the server",
				Optional:            true,
			},
			"raw": schema.StringAttribute{
				MarkdownDescription: "Raw response of the server",
				Computed:            true,
			},
			"id": schema.StringAttribute{
				MarkdownDescription: "Full name of the manifest",
				Computed:            true,
			},
		},

		Blocks: map[string]schema.Block{
			"retry": retrySchema(),
		},
	}
}

func (d *ManifestDataSource) Configure(ctx context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	tflog.Debug(ctx, "Configuring CRD data source")

	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	data, ok := req.ProviderData.(*KubernetesExtrasProviderData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Data Source Configure Type",
			fmt.Sprintf("Expected *provider.KubernetesExtrasProviderData, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	d.cfg = rest.CopyConfig(data.cfg)
	tflog.Info(ctx, "Configured Manifest data source", map[string]any{"success": true})
}

func (d *ManifestDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data ManifestDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	gv, err := runtimeSchema.ParseGroupVersion(data.ApiVersion.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Failed to parse group version", fmt.Sprintf("Failed to parse group version: %s.", err))
		return
	}

	kind := data.Kind.ValueString()
	namespace := data.Namespace.ValueString()
	name := data.Name.ValueString()
	skip_raw := data.SkipRaw.ValueBool()

	var retryData retryModel
	if !data.Retry.IsNull() {
		resp.Diagnostics.Append(data.Retry.As(ctx, &retryData, basetypes.ObjectAsOptions{})...)
		if resp.Diagnostics.HasError() {
			return
		}
	}

	client, err := kubernetesClient(d.cfg, gv.Group, gv.Version)
	if err != nil {
		resp.Diagnostics.AddError("Failed to create client", fmt.Sprintf("Failed to create client: %s.", err))
		return
	}

	request := client.Get().Resource(kind).NamespaceIfScoped(namespace, namespace != "").Name(name)
	id := strings.Join(strings.Split(request.URL().Path, "/")[2:], "/")
	raw, err := retryDo(ctx, retryData, func() (*string, error) {
		tflog.Debug(ctx, "Reading manifest", map[string]any{"name": name})

		data, err := request.Do(ctx).Raw()
		if err != nil {
			return nil, err
		}

		var raw string
		if skip_raw {
			raw = ""
		} else {
			raw = string(data)
		}

		return &raw, nil
	}, func(err error) {
		tflog.Error(ctx, "Failed to get manifest", map[string]any{"error": err})
	})

	if err != nil {
		resp.Diagnostics.AddError("Manifest not found", fmt.Sprintf("The manifest was not found: %s.", err))
		return
	}

	data.Raw = types.StringPointerValue(raw)
	data.Id = types.StringValue(id)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
