package onepasswordsdk

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"slices"
	"strconv"
	"strings"

	"github.com/1password/onepassword-sdk-go"
	"github.com/woodleighschool/jamf-recovery-lock/internal/config"
	"github.com/woodleighschool/jamf-recovery-lock/internal/jamf"
)

type itemsAPI interface {
	Get(context.Context, string, string) (onepassword.Item, error)
	Create(context.Context, onepassword.ItemCreateParams) (onepassword.Item, error)
	Put(context.Context, onepassword.Item) (onepassword.Item, error)
	List(context.Context, string, ...onepassword.ItemListFilter) ([]onepassword.ItemOverview, error)
}

type Client struct {
	// The SDK finalizer releases the client; its item API does not retain it.
	sdk     *onepassword.Client
	items   itemsAPI
	vaultID string
}

func NewClient(ctx context.Context, cfg *config.Config, version string, _ *slog.Logger) (*Client, error) {
	client, err := onepassword.NewClient(ctx, onepassword.WithServiceAccountToken(cfg.OnePasswordToken), onepassword.WithIntegrationInfo("jamf-recovery-lock", version))
	if err != nil {
		return nil, safeError(ctx, "initialize client", err)
	}
	return &Client{sdk: client, items: client.Items(), vaultID: cfg.VaultID}, nil
}

func (c *Client) GetSecret(ctx context.Context, itemID string) (string, error) {
	defer runtime.KeepAlive(c.sdk)
	item, err := c.items.Get(ctx, c.vaultID, itemID)
	if err != nil {
		return "", safeError(ctx, "read item", err)
	}
	index, err := passwordIndex(item.Fields)
	if err != nil {
		return "", err
	}
	return item.Fields[index].Value, nil
}

func (c *Client) CreateSecret(ctx context.Context, device jamf.Device, value string) (string, error) {
	defer runtime.KeepAlive(c.sdk)
	// Recover a successful create whose UUID was not persisted before a crash.
	// Stable tags survive a device rename; legacy titles preserve prior items.
	deviceTag := "jamf-computer-id:" + strconv.Itoa(device.ID)
	suffix := fmt.Sprintf(" (%d) - Recovery Password", device.ID)
	overviews, err := c.items.List(ctx, c.vaultID)
	if err != nil {
		return "", safeError(ctx, "find device item", err)
	}
	existing := ""
	for _, overview := range overviews {
		owned := slices.Contains(overview.Tags, "jamf-recovery-lock") && slices.Contains(overview.Tags, deviceTag)
		if overview.State == onepassword.ItemStateArchived || (!owned && !strings.HasSuffix(overview.Title, suffix)) {
			continue
		}
		if existing != "" {
			return "", errors.New("1Password has multiple recovery items for this computer; reconcile mapping manually")
		}
		existing = overview.ID
	}
	if existing != "" {
		current, err := c.GetSecret(ctx, existing)
		if err != nil {
			return "", err
		}
		if current != value {
			return "", errors.New("1Password device item differs from confirmed password; reconcile mapping manually")
		}
		return existing, nil
	}
	item, err := c.items.Create(ctx, onepassword.ItemCreateParams{
		Title:    fmt.Sprintf("%s (%d) - Recovery Password", device.Name, device.ID),
		Category: onepassword.ItemCategoryPassword, VaultID: c.vaultID,
		Tags:   []string{"jamf-recovery-lock", deviceTag},
		Fields: []onepassword.ItemField{{ID: "password", Title: "password", FieldType: onepassword.ItemFieldTypeConcealed, Value: value}},
	})
	if err != nil {
		return "", safeError(ctx, "create item", err)
	}
	if item.ID == "" {
		return "", errors.New("1Password create returned an empty item ID")
	}
	return item.ID, nil
}

func (c *Client) UpdateSecret(ctx context.Context, itemID, value string) error {
	defer runtime.KeepAlive(c.sdk)
	item, err := c.items.Get(ctx, c.vaultID, itemID)
	if err != nil {
		return safeError(ctx, "read item for update", err)
	}
	index, err := passwordIndex(item.Fields)
	if err != nil {
		return err
	}
	item.Fields[index].Value = value
	_, err = c.items.Put(ctx, item)
	if err != nil {
		return safeError(ctx, "update item", err)
	}
	return nil
}

func passwordIndex(fields []onepassword.ItemField) (int, error) {
	index := -1
	for i, field := range fields {
		if field.ID != "password" {
			continue
		}
		if index >= 0 {
			return -1, errors.New("1Password item has duplicate password field IDs")
		}
		if field.FieldType != onepassword.ItemFieldTypeConcealed {
			return -1, errors.New("1Password password field is not concealed")
		}
		index = i
	}
	if index < 0 {
		return -1, errors.New("1Password item has no password field ID")
	}
	return index, nil
}

func safeError(ctx context.Context, operation string, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("1Password %s: %w", operation, ctx.Err())
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("1Password %s: %w", operation, err)
	}
	return fmt.Errorf("1Password %s failed (details suppressed)", operation)
}
