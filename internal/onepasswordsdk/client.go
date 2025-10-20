package onepasswordsdk

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/1password/onepassword-sdk-go"
	"github.com/woodleighschool/SetRecoveryPassword/internal/config"
)

type Client interface {
	GetSecret(string) (string, error)
	SetSecret(string, string) error
}

type opClient struct {
	client *onepassword.Client
	config *config.Config
	logger *slog.Logger
}

func NewClient(cfg *config.Config, logger *slog.Logger) (Client, error) {
	token := cfg.ONEPASSWORD_TOKEN

	client, err := onepassword.NewClient(
		context.TODO(),
		onepassword.WithServiceAccountToken(token),
		onepassword.WithIntegrationInfo(cfg.Name, cfg.Version),
	)
	if err != nil {
		return _, fmt.Errorf("unable to create onepassword client: %w", err)
	}

	return &opClient{
		client: client,
		config: cfg,
		logger: logger,
	}, nil
}

func (c *opClient) GetSecret(id string) (string, error) {
	return "", nil
}

func (c *opClient) SetSecret(id string, value string) error {
	return nil
}
