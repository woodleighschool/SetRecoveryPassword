package jamf

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/deploymenttheory/go-sdk-jamfpro-v2/jamfpro"
	sdkconfig "github.com/deploymenttheory/go-sdk-jamfpro-v2/jamfpro/config"
	"github.com/deploymenttheory/go-sdk-jamfpro-v2/jamfpro/constants"
	"github.com/deploymenttheory/go-sdk-jamfpro-v2/jamfpro/jamf_pro_api/computer_inventory"
	"github.com/deploymenttheory/go-sdk-jamfpro-v2/jamfpro/jamf_pro_api/mdm"
	"github.com/google/uuid"
	"github.com/woodleighschool/jamf-recovery-lock/internal/config"
	"go.uber.org/zap"
	"resty.dev/v3"
)

type Device struct {
	ID           int
	Name         string
	ManagementID string
}

type Command struct {
	UUID   string
	Type   string
	Status string
	Detail string
	SentAt time.Time
}

type Client struct{ sdk *jamfpro.Client }

func NewClient(cfg *config.Config, _ *slog.Logger) (*Client, error) {
	sdk, err := jamfpro.NewClient(&sdkconfig.AuthConfig{
		InstanceDomain: cfg.InstanceDomain, AuthMethod: constants.AuthMethodOAuth2,
		ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, HideSensitiveData: true,
	}, jamfpro.WithTimeout(time.Minute), jamfpro.WithLogger(zap.NewNop()))
	if err != nil {
		// SDK errors and logs can contain response bodies, including secrets.
		return nil, errors.New("initialize Jamf client: authentication or configuration failed")
	}
	return &Client{sdk: sdk}, nil
}

func (c *Client) Close() error {
	return c.sdk.GetTransport().GetHTTPClient().Close()
}

func (c *Client) Computers(ctx context.Context, id string) ([]Device, error) {
	var records []computer_inventory.ResourceComputerInventoryV4
	if id != "" {
		if n, err := strconv.Atoi(id); err != nil || n <= 0 {
			return nil, errors.New("computer ID must be a positive integer")
		}
		result, resp, err := c.sdk.JamfProAPI.ComputerInventory.GetDetailByIDV4(ctx, id)
		if err != nil {
			return nil, requestError(ctx, "read computer", resp, err)
		}
		records = append(records, *result)
	} else {
		result, resp, err := c.sdk.JamfProAPI.ComputerInventory.ListV4(ctx, map[string]string{
			"section": "GENERAL,HARDWARE", "filter": "general.remoteManagement.managed==true;hardware.appleSilicon==true", "sort": "id:asc",
		})
		if err != nil {
			return nil, requestError(ctx, "list computers", resp, err)
		}
		records = result.Results
	}
	devices := make([]Device, 0, len(records))
	for _, record := range records {
		if !record.General.RemoteManagement.Managed || !record.Hardware.AppleSilicon {
			continue
		}
		n, err := strconv.Atoi(record.ID)
		if err != nil || n <= 0 || record.General.ManagementId == "" {
			return nil, errors.New("jamf returned a managed computer with invalid identity")
		}
		if err := uuid.Validate(record.General.ManagementId); err != nil {
			return nil, errors.New("jamf returned an invalid management UUID")
		}
		devices = append(devices, Device{ID: n, Name: record.General.Name, ManagementID: record.General.ManagementId})
	}
	return devices, nil
}

func (c *Client) Password(ctx context.Context, device Device) (string, error) {
	result, resp, err := c.sdk.JamfProAPI.ComputerInventory.GetRecoveryLockPasswordByIDV4(ctx, strconv.Itoa(device.ID))
	if err != nil {
		return "", requestError(ctx, "read recovery password", resp, err)
	}
	return result.RecoveryLockPassword, nil
}

func (c *Client) Queue(ctx context.Context, device Device, password string) (string, error) {
	if password == "" {
		return "", errors.New("refusing to queue an empty recovery password")
	}
	if err := uuid.Validate(device.ManagementID); err != nil {
		return "", errors.New("invalid management UUID")
	}
	// v0.17.0's CommandData omits newPassword and SendCommand decodes an object;
	// Jamf returns an array. Use the SDK transport for this small payload correction.
	body := struct {
		CommandData struct {
			CommandType string `json:"commandType"`
			NewPassword string `json:"newPassword"`
		} `json:"commandData"`
		ClientData []mdm.ClientData `json:"clientData"`
	}{ClientData: []mdm.ClientData{{ManagementID: device.ManagementID}}}
	body.CommandData.CommandType = mdm.CommandTypeSetRecoveryLock
	body.CommandData.NewPassword = password
	var result []mdm.CommandResponse
	resp, err := c.sdk.GetTransport().NewRequest(ctx).DisableRetry().
		SetHeader("Accept", constants.ApplicationJSON).SetHeader("Content-Type", constants.ApplicationJSON).
		SetBody(body).SetResult(&result).Post(constants.EndpointJamfProCommands)
	if err != nil {
		return "", requestError(ctx, "queue recovery command (acceptance unconfirmed)", resp, err)
	}
	if resp == nil || resp.StatusCode() != 201 || len(result) != 1 {
		return "", errors.New("queue recovery command: response did not confirm exactly one command UUID")
	}
	if err := uuid.Validate(result[0].ID); err != nil {
		return "", errors.New("queue recovery command: response did not contain a valid command UUID")
	}
	return result[0].ID, nil
}

// commandRecord accommodates Jamf's current published commandState shape and
// the status field used by v2 command history. The SDK's narrower CommandInfo
// drops target identity and command error details from the published shape.
type commandRecord struct {
	mdm.ResourceMdmCommand
	Status string `json:"status"`
}

func (c *Client) commands(ctx context.Context, device Device, commandUUID string) ([]Command, error) {
	if err := uuid.Validate(device.ManagementID); err != nil {
		return nil, errors.New("invalid management UUID")
	}
	filter := "clientManagementId==" + device.ManagementID
	if commandUUID != "" {
		if err := uuid.Validate(commandUUID); err != nil {
			return nil, errors.New("invalid command UUID")
		}
		filter += ";uuid==" + commandUUID
	} else {
		filter += ";command=in=(SET_RECOVERY_LOCK,VERIFY_RECOVERY_LOCK)"
	}
	var records []commandRecord
	resp, err := c.sdk.GetTransport().NewRequest(ctx).SetHeader("Accept", constants.ApplicationJSON).
		SetQueryParams(map[string]string{"filter": filter, "sort": "dateSent:desc"}).
		GetPaginated(constants.EndpointJamfProCommands, func(data []byte) error {
			var page []commandRecord
			if err := json.Unmarshal(data, &page); err != nil {
				return err
			}
			records = append(records, page...)
			return nil
		})
	if err != nil {
		return nil, requestError(ctx, "read recovery command history", resp, err)
	}
	var envelope struct {
		TotalCount *int `json:"totalCount"`
	}
	if resp == nil || json.Unmarshal(resp.Bytes(), &envelope) != nil || envelope.TotalCount == nil || *envelope.TotalCount != len(records) {
		return nil, errors.New("jamf returned incomplete recovery command history")
	}
	commands := make([]Command, 0, len(records))
	seen := make(map[string]bool, len(records))
	for _, record := range records {
		if uuid.Validate(record.UUID) != nil || (commandUUID != "" && record.UUID != commandUUID) {
			return nil, errors.New("jamf returned an unexpected command UUID")
		}
		if seen[record.UUID] {
			return nil, errors.New("jamf returned duplicate command UUIDs")
		}
		seen[record.UUID] = true
		if record.Client != nil && record.Client.ManagementID != device.ManagementID {
			return nil, errors.New("jamf returned a command for another device")
		}
		switch record.CommandType {
		case mdm.CommandTypeSetRecoveryLock, "VERIFY_RECOVERY_LOCK":
		default:
			return nil, errors.New("jamf returned an unexpected recovery command type")
		}
		status := normalizeStatus(record.Status)
		if record.Status == "" {
			status = normalizeStatus(record.CommandState)
		}
		if record.Status != "" && record.CommandState != "" && status != normalizeStatus(record.CommandState) {
			return nil, errors.New("jamf returned contradictory command states")
		}
		detail := ""
		if record.CommandError != nil && (record.CommandError.ErrorCode != 0 || record.CommandError.ErrorDomain != "" || record.CommandError.ErrorEnglishDescription != "" || record.CommandError.ErrorLocalizedDescription != "") {
			status = "failed"
			detail = fmt.Sprintf("MDM error code %d", record.CommandError.ErrorCode)
			if strings.Contains(record.CommandError.ErrorEnglishDescription, "The provided recovery password failed to validate") || strings.Contains(record.CommandError.ErrorLocalizedDescription, "The provided recovery password failed to validate") {
				detail = "The provided recovery password failed to validate."
			}
		}
		var sentAt time.Time
		if record.DateSent != "" {
			var parseErr error
			sentAt, parseErr = time.Parse(time.RFC3339Nano, record.DateSent)
			if parseErr != nil {
				return nil, errors.New("jamf returned an invalid command submission timestamp")
			}
		}
		commands = append(commands, Command{UUID: record.UUID, Type: record.CommandType, Status: status, Detail: detail, SentAt: sentAt})
	}
	return commands, nil
}

func (c *Client) Commands(ctx context.Context, device Device) ([]Command, error) {
	return c.commands(ctx, device, "")
}

func (c *Client) Command(ctx context.Context, device Device, commandUUID string) (Command, error) {
	commands, err := c.commands(ctx, device, commandUUID)
	if err != nil {
		return Command{}, err
	}
	if len(commands) == 0 {
		return Command{UUID: commandUUID, Status: "unknown", Detail: "command UUID absent from Jamf history"}, nil
	}
	if len(commands) != 1 {
		return Command{}, errors.New("jamf returned duplicate command UUIDs")
	}
	if commands[0].Type != mdm.CommandTypeSetRecoveryLock {
		return Command{}, errors.New("stored UUID identifies a different command type")
	}
	return commands[0], nil
}

func normalizeStatus(status string) string {
	switch strings.ToUpper(strings.TrimSpace(status)) {
	case "PENDING", "NOT_NOW", "NOTNOW":
		return "pending"
	case "ACKNOWLEDGED":
		return "acknowledged"
	case "FAILED", "ERROR", "COMMAND_FORMAT_ERROR":
		return "failed"
	default:
		return "unknown"
	}
}

func requestError(ctx context.Context, operation string, resp *resty.Response, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("jamf %s: %w", operation, ctx.Err())
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("jamf %s: %w", operation, err)
	}
	if resp != nil {
		return fmt.Errorf("jamf %s: HTTP %d (response details suppressed)", operation, resp.StatusCode())
	}
	return fmt.Errorf("jamf %s: request failed (response details suppressed)", operation)
}
