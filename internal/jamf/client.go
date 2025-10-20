package jamf

import (
	"fmt"
	"log/slog"
	"math/rand"
	"net/url"
	"os"
	"time"

	"github.com/woodleighschool/SetRecoveryPassword/internal/config"
	"github.com/woodleighschool/go-api-sdk-jamfpro/sdk/jamfpro"
)

var seededRand *rand.Rand = rand.New(rand.NewSource(time.Now().UnixNano()))

type Device struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	ManagementID     string `json:"management_id"`
	RecoveryPassword string `json:"recovery_password"`
}

type Client interface {
	GetComputers() ([]Device, error)
	GetRecoveryPassword(device *Device) (string, error)
	SetRecoveryPassword(device *Device) error
	Close() error
}

type jamfClient struct {
	client *jamfpro.Client
	config *config.Config
	logger *slog.Logger
}

func (d *Device) GenerateNewRecoveryPassword(length int) {
	charset := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	d.RecoveryPassword = string(b)
}

func NewClient(cfg *config.Config, logger *slog.Logger) (Client, error) {
	if err := os.Setenv("INSTANCE_DOMAIN", cfg.InstanceDomain); err != nil {
		return nil, fmt.Errorf("failed to set INSTANCE_DOMAIN environment variable: %w", err)
	}
	if err := os.Setenv("CLIENT_ID", cfg.ClientID); err != nil {
		return nil, fmt.Errorf("failed to set CLIENT_ID environment variable: %w", err)
	}
	if err := os.Setenv("CLIENT_SECRET", cfg.ClientSecret); err != nil {
		return nil, fmt.Errorf("failed to set CLIENT_SECRET environment variable: %w", err)
	}
	if err := os.Setenv("AUTH_METHOD", cfg.AuthMethod); err != nil {
		return nil, fmt.Errorf("failed to set AUTH_METHOD environment variable: %w", err)
	}
	if err := os.Setenv("TOKEN_REFRESH_BUFFER_PERIOD_SECONDS", cfg.TokenRefreshBufferPeriod); err != nil {
		return nil, fmt.Errorf("failed to set TOKEN_REFRESH_BUFFER_PERIOD_SECONDS environment variable: %w", err)
	}
	if err := os.Setenv("TOKEN_BUFFER_PERIOD_SECONDS", cfg.TokenBufferPeriod); err != nil {
		return nil, fmt.Errorf("failed to set TOKEN_BUFFER_PERIOD_SECONDS environment variable: %w", err)
	}

	if err := os.Setenv("LOG_LEVEL", "fatal"); err != nil {
		return nil, fmt.Errorf("failed to set LOG_LEVEL environment variable: %w", err)
	}

	client, err := jamfpro.BuildClientWithEnv()
	if err != nil {
		return nil, fmt.Errorf("failed to initalise Jamf Pro client: %w", err)
	}

	return &jamfClient{
		client: client,
		config: cfg,
		logger: logger,
	}, nil
}

func (j *jamfClient) GetComputers() ([]Device, error) {
	j.logger.Debug("Getting all macOS devices")

	params := url.Values{}
	params.Set("page-size", "5000")
	params.Set("section", "GENERAL")
	params.Set("filter", "general.remoteManagement.managed==true")

	resp, err := j.client.GetComputersInventory(params)
	if err != nil {
		j.logger.Error("Error getting macOS device list", "error", err)
		return nil, fmt.Errorf("failed to get macOS device list: %w", err)
	}

	var computers []Device
	for i := 0; i < resp.TotalCount; i++ {
		deviceResp := resp.Results[i]

		device := Device{
			ID:           *deviceResp.ID,
			Name:         *deviceResp.General.Name,
			ManagementID: *deviceResp.General.ManagementId,
		}

		computers = append(computers, device)
	}

	return computers, nil
}

func (j *jamfClient) GetRecoveryPassword(device *Device) (string, error) {
	j.logger.Debug("Getting recovery password", "computer", device.Name)

	password, err := j.client.GetComputerRecoveryLockPasswordByID(device.ID)
	if err != nil {
		return "", fmt.Errorf("failed to get recovery password: %w", err)
	}

	return password.RecoveryLockPassword, nil
}

func (j *jamfClient) SetRecoveryPassword(device *Device) error {
	j.logger.Debug("Setting recovery password", "computer", device.Name)

	if !j.config.DryRun {
		mdmCommand := &jamfpro.ResourceMDMCommandRequest{
			CommandData: jamfpro.CommandData{
				CommandType: "SET_RECOVERY_LOCK",
				NewPassword: device.RecoveryPassword,
			},
			ClientData: []jamfpro.ClientData{jamfpro.ClientData{ManagementID: device.ManagementID}},
		}
		_, err := j.client.SendMDMCommandForCreationAndQueuing(mdmCommand)
		if err != nil {
			return fmt.Errorf("failed to set recovery password: %w", err)
		}
	}
	j.logger.Info("Set password successfully", "computer", device.Name)
	return nil
}

func (j *jamfClient) Close() error {
	return nil
}
