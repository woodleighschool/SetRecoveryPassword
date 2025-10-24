package onepasswordsdk

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/1password/onepassword-sdk-go"
	"github.com/woodleighschool/SetRecoveryPassword/internal/config"
	"github.com/woodleighschool/SetRecoveryPassword/internal/jamf"
)

type Client interface {
	GetSecret(string) (string, error)
	CreateSecret(*jamf.Device, string) (string, error)
	UpdateSecret(string, string) error
}

type opClient struct {
	client *onepassword.Client
	config *config.Config
	logger *slog.Logger
}

func NewClient(cfg *config.Config, logger *slog.Logger) (Client, error) {
	token := cfg.OnePasswordToken

	client, err := onepassword.NewClient(
		context.TODO(),
		onepassword.WithServiceAccountToken(token),
		onepassword.WithIntegrationInfo(cfg.Name, cfg.Version),
	)
	if err != nil {
		return nil, fmt.Errorf("unable to create onepassword client: %w", err)
	}

	return &opClient{
		client: client,
		config: cfg,
		logger: logger,
	}, nil
}

func (c *opClient) GetSecret(uuid string) (string, error) {
	c.logger.Debug("Retrieving password from 1Password", "uuid", uuid)
	secret, err := c.client.Secrets().Resolve(context.Background(), fmt.Sprintf("op://%s/%s/password", c.config.VaultID, uuid))
	if err != nil {
		return "", fmt.Errorf("unable to retrieve password from 1Password: %w", err)
	} else {
		return secret, nil
	}
}

func (c *opClient) CreateSecret(computer *jamf.Device, value string) (string, error) {
	c.logger.Debug("Attempting to create 1Password entry")
	params := onepassword.ItemCreateParams{
		Title:    fmt.Sprintf("%s (%d) - Recovery Password", computer.Name, computer.ID),
		Category: onepassword.ItemCategoryPassword,
		VaultID:  c.config.VaultID,
		Fields: []onepassword.ItemField{
			{
				ID:        "password",
				Title:     "password",
				FieldType: onepassword.ItemFieldTypeConcealed,
				Value:     value,
			},
		},
	}
	createdItem, err := c.client.Items().Create(context.Background(), params)
	if err != nil {
		return "", fmt.Errorf("failed to create 1Password entry: %w", err)
	} else {
		return createdItem.ID, nil
	}
}

func (c *opClient) UpdateSecret(uuid string, value string) error {
	item, err := c.client.Items().Get(context.Background(), c.config.VaultID, uuid)
	if err != nil {
		return fmt.Errorf("unable to get existing entry: %w", err)
	}
	for i := range item.Fields {
		if item.Fields[i].Title == "password" {
			item.Fields[i].Value = value
		}
	}

	_, err = c.client.Items().Put(context.Background(), item)
	if err != nil {
		return fmt.Errorf("failed to update entry: %w", err)
	}
	return nil
}
