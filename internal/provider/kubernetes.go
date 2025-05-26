// Copyright (c) The Kubernetes Extras Provider for Terraform Authors
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-framework/types/basetypes"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apimachineryschema "k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/kubectl/pkg/scheme"
)

type kubernetesModel struct {
	Host                  types.String `tfsdk:"host"`
	Username              types.String `tfsdk:"username"`
	Password              types.String `tfsdk:"password"`
	Insecure              types.Bool   `tfsdk:"insecure"`
	TlsServerName         types.String `tfsdk:"tls_server_name"`
	ClientCertificate     types.String `tfsdk:"client_certificate"`
	ClientKey             types.String `tfsdk:"client_key"`
	ClusterCaCertificate  types.String `tfsdk:"cluster_ca_certificate"`
	ConfigPaths           types.String `tfsdk:"config_paths"`
	ConfigPath            types.String `tfsdk:"config_path"`
	ConfigContext         types.String `tfsdk:"config_context"`
	ConfigContextAuthInfo types.String `tfsdk:"config_context_auth_info"`
	ConfigContextCluster  types.String `tfsdk:"config_context_cluster"`
	Token                 types.String `tfsdk:"token"`
	ProxyUrl              types.String `tfsdk:"proxy_url"`
}

func kubernetesSchema() schema.Block {
	return schema.SingleNestedBlock{
		MarkdownDescription: "See the [Kubernetes provider documentation](https://registry.terraform.io/providers/hashicorp/kubernetes/latest/docs) for more information.",
		Attributes: map[string]schema.Attribute{
			"host": schema.StringAttribute{
				Description: "The hostname (in form of URI) of Kubernetes master. Can be set with the `KUBE_HOST` environment variable.",
				Optional:    true,
			},
			"username": schema.StringAttribute{
				Description: "The username to use for HTTP basic authentication when accessing the Kubernetes master endpoint. Can be set with the `KUBE_USER` environment variable.",
				Optional:    true,
			},
			"password": schema.StringAttribute{
				Description: "The password to use for HTTP basic authentication when accessing the Kubernetes master endpoint. Can be set with the `KUBE_PASSWORD` environment variable.",
				Optional:    true,
			},
			"insecure": schema.BoolAttribute{
				Description: "Whether server should be accessed without verifying the TLS certificate. Can be set with the `tru` environment variable.",
				Optional:    true,
			},
			"tls_server_name": schema.StringAttribute{
				Description: "Server name passed to the server for SNI and is used in the client to check server certificates against. Can be set with the `KUBE_TLS_SERVER_NAME` environment variable.",
				Optional:    true,
			},
			"client_certificate": schema.StringAttribute{
				Description: "PEM-encoded client certificate for TLS authentication. Can be set with the `KUBE_CLIENT_CERT_DATA` environment variable.",
				Optional:    true,
			},
			"client_key": schema.StringAttribute{
				Description: "PEM-encoded client certificate key for TLS authentication. Can be set with the `KUBE_CLIENT_KEY_DATA` environment variable.",
				Optional:    true,
			},
			"cluster_ca_certificate": schema.StringAttribute{
				Description: "PEM-encoded root certificates bundle for TLS authentication. Can be set with the `KUBE_CLUSTER_CA_CERT_DATA` environment variable.",
				Optional:    true,
			},
			"config_path": schema.StringAttribute{
				Description: "A path to a kube config file. Can be set with the `KUBE_CONFIG_PATHS` environement variable.",
				Optional:    true,
			},
			"config_paths": schema.StringAttribute{
				Description: "A list of paths to the kube config files. Can be set with the `KUBE_CONFIG_PATH` environement variable.",
				Optional:    true,
			},
			"config_context": schema.StringAttribute{
				Description: "Context to choose from the config file. Can be set with the `KUBE_CTX` environement variable.",
				Optional:    true,
			},
			"config_context_auth_info": schema.StringAttribute{
				Description: "Authentication info context of the kube config (name of the kubeconfig user, `--user` flag in `kubectl`). Can be set with the `KUBE_CTX_AUTH_INFO` environement variable.",
				Optional:    true,
			},
			"config_context_cluster": schema.StringAttribute{
				Description: "Cluster context of the kube config (name of the kubeconfig cluster, `--cluster` flag in `kubectl`). Can be set with the `KUBE_CTX_CLUSTER` environement variable.",
				Optional:    true,
			},
			"token": schema.StringAttribute{
				Description: "Token to authenticate an service account. Can be set with the `KUBE_TOKEN` environment variable.",
				Optional:    true,
			},
			"proxy_url": schema.StringAttribute{
				Description: "URL to the proxy to be used for all API requests. Can be set with the `KUBE_PROXY_URL` environment variable.",
				Optional:    true,
			},
		},
	}
}

func kubernetesConfigure(ctx context.Context, _ provider.ConfigureRequest, resp *provider.ConfigureResponse, userAgent string, data basetypes.ObjectValue) *restclient.Config {
	tflog.Debug(ctx, "Configuring Kubernetes client")
	if data.IsNull() {
		resp.Diagnostics.AddError("Kubernetes provider configuration is missing", "The Kubernetes provider configuration is missing. Please provide the required configuration.")
		return nil
	}

	var kubernetesData kubernetesModel
	resp.Diagnostics.Append(data.As(ctx, &kubernetesData, basetypes.ObjectAsOptions{})...)
	if resp.Diagnostics.HasError() {
		return nil
	}

	tflog.Debug(ctx, "Gathering environment variables")
	host := os.Getenv("KUBE_HOST")
	username := os.Getenv("KUBE_USER")
	password := os.Getenv("KUBE_PASSWORD")
	insecure := os.Getenv("KUBE_INSECURE") == "true"
	tlsServerName := os.Getenv("KUBE_TLS_SERVER_NAME")
	clientCertificate := os.Getenv("KUBE_CLIENT_CERT_DATA")
	clientKey := os.Getenv("KUBE_CLIENT_KEY_DATA")
	clusterCaCertificate := os.Getenv("KUBE_CLUSTER_CA_CERT_DATA")
	configPaths := os.Getenv("KUBE_CONFIG_PATHS")
	configPath := os.Getenv("KUBE_CONFIG_PATH")
	configContext := os.Getenv("KUBE_CTX")
	configContextAuthInfo := os.Getenv("KUBE_CTX_AUTH_INFO")
	configContextCluster := os.Getenv("KUBE_CTX_CLUSTER")
	token := os.Getenv("KUBE_TOKEN")
	proxyUrl := os.Getenv("KUBE_PROXY_URL")

	tflog.Debug(ctx, "Overriding environment variables with provider configuration")
	if !kubernetesData.Host.IsNull() {
		host = kubernetesData.Host.ValueString()
	}

	if !kubernetesData.Username.IsNull() {
		username = kubernetesData.Username.ValueString()
	}

	if !kubernetesData.Password.IsNull() {
		password = kubernetesData.Password.ValueString()
	}

	if !kubernetesData.Insecure.IsNull() {
		insecure = kubernetesData.Insecure.ValueBool()
	}

	if !kubernetesData.TlsServerName.IsNull() {
		tlsServerName = kubernetesData.TlsServerName.ValueString()
	}

	if !kubernetesData.ClientCertificate.IsNull() {
		clientCertificate = kubernetesData.ClientCertificate.ValueString()
	}

	if !kubernetesData.ClientKey.IsNull() {
		clientKey = kubernetesData.ClientKey.ValueString()
	}

	if !kubernetesData.ClusterCaCertificate.IsNull() {
		clusterCaCertificate = kubernetesData.ClusterCaCertificate.ValueString()
	}

	if !kubernetesData.ConfigPaths.IsNull() {
		configPaths = kubernetesData.ConfigPaths.ValueString()
	}

	if !kubernetesData.ConfigPath.IsNull() {
		configPath = kubernetesData.ConfigPath.ValueString()
	}

	if !kubernetesData.ConfigContext.IsNull() {
		configContext = kubernetesData.ConfigContext.ValueString()
	}

	if !kubernetesData.ConfigContextAuthInfo.IsNull() {
		configContextAuthInfo = kubernetesData.ConfigContextAuthInfo.ValueString()
	}

	if !kubernetesData.ConfigContextCluster.IsNull() {
		configContextCluster = kubernetesData.ConfigContextCluster.ValueString()
	}

	if !kubernetesData.Token.IsNull() {
		token = kubernetesData.Token.ValueString()
	}

	if !kubernetesData.ProxyUrl.IsNull() {
		proxyUrl = kubernetesData.ProxyUrl.ValueString()
	}

	overrides := &clientcmd.ConfigOverrides{}
	loader := &clientcmd.ClientConfigLoadingRules{}

	if configPaths != "" {
		configPathAbs, err := filepath.Abs(configPath)
		if err == nil {
			_, err = os.Stat(configPathAbs)
		}

		if err != nil {
			resp.Diagnostics.AddAttributeError(
				path.Root("config_path"),
				fmt.Sprintf("Invalid path: %s: %s", configPathAbs, err.Error()),
				err.Error(),
			)
		}
		loader.ExplicitPath = configPathAbs
	}

	if configPaths != "" {
		precedence := filepath.SplitList(configPaths)
		for i, p := range precedence {
			absPath, err := filepath.Abs(p)
			if err == nil {
				_, err = os.Stat(absPath)
			}
			if err != nil {
				resp.Diagnostics.AddAttributeError(
					path.Root("config_paths"),
					fmt.Sprintf("Invalid path: %s: %s", absPath, err.Error()),
					err.Error(),
				)
			}
			precedence[i] = absPath
		}
		loader.Precedence = precedence
	}

	if host != "" {
		// Server has to be the complete address of the kubernetes cluster (scheme://hostname:port), not just the hostname,
		// because `overrides` are processed too late to be taken into account by `defaultServerUrlFor()`.
		// This basically replicates what defaultServerUrlFor() does with config but for overrides,
		// see https://github.com/kubernetes/client-go/blob/v12.0.0/rest/url_utils.go#L85-L87
		hasCA := len(overrides.ClusterInfo.CertificateAuthorityData) != 0
		hasCert := len(overrides.AuthInfo.ClientCertificateData) != 0
		defaultTLS := hasCA || hasCert || overrides.ClusterInfo.InsecureSkipTLSVerify
		host, _, err := restclient.DefaultServerURL(host, "", apimachineryschema.GroupVersion{}, defaultTLS)
		if err != nil {
			resp.Diagnostics.AddAttributeError(path.Root("host"), "Failed to parse host: %s", err.Error())
		}
		overrides.ClusterInfo.Server = host.String()
	}

	if username != "" {
		overrides.AuthInfo.Username = username
	}

	if password != "" {
		overrides.AuthInfo.Password = password
	}

	if insecure {
		overrides.ClusterInfo.InsecureSkipTLSVerify = true
	}

	if tlsServerName != "" {
		overrides.ClusterInfo.TLSServerName = tlsServerName
	}

	if clientKey != "" {
		overrides.AuthInfo.ClientKeyData = []byte(clientKey)
	}

	if clientCertificate != "" {
		overrides.AuthInfo.ClientCertificateData = []byte(clientCertificate)
	}

	if clusterCaCertificate != "" {
		overrides.ClusterInfo.CertificateAuthorityData = []byte(clusterCaCertificate)
	}

	if configContext != "" {
		overrides.CurrentContext = configContext
	}

	if configContextAuthInfo != "" {
		overrides.Context.AuthInfo = configContextAuthInfo
	}

	if configContextCluster != "" {
		overrides.CurrentContext = configContextCluster
	}

	if token != "" {
		overrides.AuthInfo.Token = token
	}

	if proxyUrl != "" {
		overrides.ClusterDefaults.ProxyURL = proxyUrl
	}

	if resp.Diagnostics.HasError() {
		return nil
	}

	tflog.Debug(ctx, "Creating Kubernetes API client configuration")
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loader, overrides)
	cfg, err := cc.ClientConfig()
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to create Kubernetes API client configuration",
			"An unexpected error occurred when creating the Kubernetes API client configuration. "+
				"If the error is not clear, please contact the provider developers.\n\n"+
				"Kubernetes Client Error: "+err.Error(),
		)
		return nil
	}

	cfg.UserAgent = userAgent
	return cfg
}

func kubernetesClientset(ctx context.Context, _ provider.ConfigureRequest, resp *provider.ConfigureResponse, cfg *restclient.Config) *clientset.Clientset {
	tflog.Debug(ctx, "Creating Kubernetes API client")
	client, err := clientset.NewForConfig(cfg)
	if err != nil {
		resp.Diagnostics.AddError(
			"Unable to create Kubernetes API client",
			"An unexpected error occurred when creating the Kubernetes API client. "+
				"If the error is not clear, please contact the provider developers.\n\n"+
				"Kubernetes Client Error: "+err.Error(),
		)
		return nil
	}

	tflog.Info(ctx, "Configured Kubernetes API client", map[string]any{"success": true})
	return client
}

func kubernetesClient(cfg *restclient.Config, group string, version string) (*restclient.RESTClient, error) {
	cfg.GroupVersion = &apimachineryschema.GroupVersion{
		Group:   group,
		Version: version,
	}

	if len(group) == 0 {
		cfg.APIPath = "/api"
	} else {
		cfg.APIPath = "/apis"
	}

	cfg.NegotiatedSerializer = serializer.NewCodecFactory(scheme.Scheme).WithoutConversion()
	return rest.RESTClientFor(cfg)
}
