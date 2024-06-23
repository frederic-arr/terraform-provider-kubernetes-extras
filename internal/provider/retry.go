package provider

import (
	"context"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
)

type retryModel struct {
	Attempts types.Int64 `tfsdk:"attempts"`
	Duration types.Int64 `tfsdk:"duration"`
}

func retrySchema() schema.Block {
	return schema.SingleNestedBlock{
		Attributes: map[string]schema.Attribute{
			"attempts": schema.Int64Attribute{
				Description: "The number of times the request is to be retried. For example, if `2` is specified, the request will be tried a maximum of 3 times.",
				Optional:    true,
			},
			"duration": schema.Int64Attribute{
				Description: "Duration to wait between retries in miliseconds. For example, if `2500` is specified, the request will be retried after 2.5 seconds.",
				Optional:    true,
			},
		},
	}
}

func retryDo[T any](ctx context.Context, retryData retryModel, fn func() (*T, error), onErr func(err error)) (data *T, err error) {
	backoff := wait.Backoff{
		Steps:    5,
		Duration: 2500 * time.Millisecond,
		Factor:   1.0,
		Jitter:   0.0,
	}

	if !retryData.Attempts.IsNull() {
		backoff.Steps = int(retryData.Attempts.ValueInt64())
	}

	if !retryData.Duration.IsNull() {
		backoff.Duration = time.Duration(retryData.Duration.ValueInt64()) * time.Millisecond
	}

	err = retry.OnError(backoff, func(err error) bool { return ctx.Err() == nil }, func() error {
		res, err := fn()
		if err != nil {
			onErr(err)
			return err
		}

		data = res
		return nil
	})

	return data, err
}
