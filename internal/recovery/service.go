package recovery

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/woodleighschool/jamf-recovery-lock/internal/config"
	"github.com/woodleighschool/jamf-recovery-lock/internal/jamf"
	"github.com/woodleighschool/jamf-recovery-lock/internal/state"
)

type Store interface {
	Get(context.Context, int) (*state.Entry, error)
	Save(context.Context, *state.Entry) error
}

type Jamf interface {
	Computers(context.Context, string) ([]jamf.Device, error)
	Password(context.Context, jamf.Device) (string, error)
	Commands(context.Context, jamf.Device) ([]jamf.Command, error)
	Queue(context.Context, jamf.Device, string) (string, error)
	Command(context.Context, jamf.Device, string) (jamf.Command, error)
}

type Secrets interface {
	GetSecret(context.Context, string) (string, error)
	CreateSecret(context.Context, jamf.Device, string) (string, error)
	UpdateSecret(context.Context, string, string) error
}

// Service reconciles one durable rotation per device. No run-count retry clock
// is meaningful: command evidence controls promotion, elapsed time alerts only.
type Service struct {
	Store   Store
	Jamf    Jamf
	Secrets Secrets
	Config  *config.Config
	Logger  *slog.Logger
}

type Summary struct{ Devices, Stable, Queued, Pending, Promoted, Blocked, Failed, WouldChange int }

func (s *Service) Run(ctx context.Context) (Summary, error) {
	var summary Summary
	devices, err := s.Jamf.Computers(ctx, s.Config.JamfID)
	if err != nil {
		return summary, fmt.Errorf("enumerate computers: %w", err)
	}
	summary.Devices = len(devices)
	for _, device := range devices {
		if err = ctx.Err(); err != nil {
			return summary, err
		}
		result, deviceErr := s.reconcile(ctx, device, time.Now().UTC())
		switch result {
		case "stable":
			summary.Stable++
		case "queued":
			summary.Queued++
		case "pending":
			summary.Pending++
		case "promoted":
			summary.Promoted++
		case "blocked":
			summary.Blocked++
		case "would-change":
			summary.WouldChange++
		}
		if deviceErr != nil {
			summary.Failed++
			s.Logger.ErrorContext(ctx, "recovery reconciliation failed", "device_id", device.ID, "command_state", result, "error", deviceErr)
		}
	}
	s.Logger.InfoContext(ctx, "recovery run completed", "devices", summary.Devices, "stable", summary.Stable, "queued", summary.Queued, "pending", summary.Pending, "promoted", summary.Promoted, "blocked", summary.Blocked, "failed", summary.Failed, "would_change", summary.WouldChange, "dry_run", s.Config.DryRun)
	if summary.Failed > 0 {
		return summary, fmt.Errorf("%d of %d devices failed recovery reconciliation", summary.Failed, summary.Devices)
	}
	return summary, nil
}

func (s *Service) reconcile(ctx context.Context, d jamf.Device, now time.Time) (string, error) {
	e, err := s.Store.Get(ctx, d.ID)
	if err != nil {
		return "", err
	}
	if e == nil {
		e = &state.Entry{ID: d.ID, Date: now.Format(time.RFC3339), Phase: state.Stable}
		return s.rotate(ctx, d, e, now)
	}
	if e.CommandUUID == "" && e.Password != nil && (e.Phase == state.Prepared || e.Phase == state.Pending || e.Phase == state.Blocked) {
		return s.correlate(ctx, d, e, now)
	}
	switch e.Phase {
	case state.Prepared:
		return s.block(ctx, e, "prepared row has invalid candidate or command state")
	case state.Blocked:
		return "blocked", fmt.Errorf("rotation blocked (command %s): %s", e.CommandUUID, e.LastError)
	case state.Pending:
		return s.pending(ctx, d, e, now)
	case state.Stable:
		if e.Password != nil || e.OPUUID == "" {
			return s.block(ctx, e, "stable row has invalid candidate or missing 1Password mapping")
		}
		jamfPassword, readErr := s.Jamf.Password(ctx, d)
		if readErr != nil {
			return "", readErr
		}
		confirmed, readErr := s.Secrets.GetSecret(ctx, e.OPUUID)
		if readErr != nil {
			return "", readErr
		}
		if confirmed == "" || jamfPassword != confirmed {
			return s.block(ctx, e, "Jamf reported password differs from the retained 1Password secret; repair current-password knowledge before rotation")
		}
		rotated, parseErr := parseDate(e.Date)
		if parseErr != nil {
			return s.block(ctx, e, "invalid stored rotation date; review state before rotation")
		}
		if now.Before(rotated.Add(s.Config.RotationAge)) {
			return "stable", nil
		}
		return s.rotate(ctx, d, e, now)
	default:
		return s.block(ctx, e, "unknown recovery state; review before rotation")
	}
}

func (s *Service) rotate(ctx context.Context, d jamf.Device, e *state.Entry, now time.Time) (string, error) {
	commands, err := s.Jamf.Commands(ctx, d)
	if err != nil {
		return "", fmt.Errorf("rotation preflight: %w", err)
	}
	for _, command := range commands {
		if command.Status == "pending" || command.Status == "unknown" {
			return "pending", fmt.Errorf("existing recovery command %s is %s; no new rotation submitted", command.UUID, command.Status)
		}
	}
	if s.Config.DryRun {
		return "would-change", nil
	}
	password, err := generatePassword(s.Config.PasswordLength)
	if err != nil {
		return "", err
	}
	e.Password = &password
	e.RequestedAt = &now
	e.Phase = state.Prepared
	e.CommandUUID = ""
	e.LastError = ""
	// Persist before sending. A crash between PostgreSQL and Jamf cannot be made
	// atomic: prepared survives as an explicit uncertain submission, never resent.
	if err = s.Store.Save(ctx, e); err != nil {
		return "", err
	}
	uuid, err := s.Jamf.Queue(ctx, d, password)
	if err != nil {
		// SDK/provider errors can include bodies containing the submitted password.
		// Keep a useful classification without persisting/logging the credential.
		reason := redactError(err.Error(), password)
		return s.block(ctx, e, "command submission failed or is uncertain: "+reason)
	}
	if uuid == "" {
		return s.block(ctx, e, "command submission returned no UUID; correlate Jamf history before repair")
	}
	e.CommandUUID = uuid
	e.Phase = state.Pending
	if err = s.Store.Save(ctx, e); err != nil {
		return "", fmt.Errorf("persist queued command %s; submission must not be repeated: %w", uuid, err)
	}
	s.Logger.InfoContext(ctx, "rotation queued", "device_id", d.ID, "command_uuid", uuid)
	return "queued", nil
}

// correlate recovers submission evidence without sending another candidate.
// Legacy dates were also grace-check timestamps, so they cannot identify a command.
func (s *Service) correlate(ctx context.Context, d jamf.Device, e *state.Entry, now time.Time) (string, error) {
	if *e.Password == "" {
		return s.block(ctx, e, "unconfirmed rotation has an empty candidate")
	}
	commands, err := s.Jamf.Commands(ctx, d)
	if err != nil {
		return "pending", fmt.Errorf("recover command evidence: %w", err)
	}
	var latest *jamf.Command
	unsettled := false
	missingTime := false
	latestCount := 0
	for i := range commands {
		command := &commands[i]
		if command.Type != "SET_RECOVERY_LOCK" {
			continue
		}
		if command.Status == "pending" || command.Status == "unknown" {
			unsettled = true
		}
		if command.SentAt.IsZero() {
			missingTime = true
			continue
		}
		if latest == nil || command.SentAt.After(latest.SentAt) {
			latest = command
			latestCount = 1
		} else if command.SentAt.Equal(latest.SentAt) {
			latestCount++
		}
	}
	if unsettled {
		return s.awaitCorrelation(ctx, d, e, now, "recovery set commands remain unsettled")
	}
	if latest == nil || missingTime || latestCount != 1 {
		return s.block(ctx, e, "recovery command history cannot identify the latest set command; candidate retained")
	}
	if e.RequestedAt != nil && latest.SentAt.Before(*e.RequestedAt) {
		return s.block(ctx, e, "latest set command predates the prepared candidate; submission remains unconfirmed")
	}
	if latest.Status == "failed" {
		return s.block(ctx, e, fmt.Sprintf("latest SET_RECOVERY_LOCK %s failed: %s", latest.UUID, redactError(latest.Detail, *e.Password)))
	}
	if latest.Status != "acknowledged" {
		return s.block(ctx, e, "latest set command is not acknowledged; candidate retained")
	}
	password, err := s.Jamf.Password(ctx, d)
	if err != nil {
		return "pending", err
	}
	if password != *e.Password {
		return s.awaitCorrelation(ctx, d, e, now, "acknowledged set command does not yet confirm the retained candidate")
	}
	e.CommandUUID = latest.UUID
	e.RequestedAt = &latest.SentAt
	e.Phase = state.Pending
	e.LastError = ""
	if !s.Config.DryRun {
		if err := s.Store.Save(ctx, e); err != nil {
			return "pending", fmt.Errorf("persist recovered command evidence: %w", err)
		}
	}
	s.Logger.InfoContext(ctx, "rotation command evidence recovered", "device_id", d.ID, "command_uuid", latest.UUID, "requested_at", latest.SentAt, "dry_run", s.Config.DryRun)
	return s.promote(ctx, d, e, now)
}

func (s *Service) awaitCorrelation(ctx context.Context, d jamf.Device, e *state.Entry, now time.Time, reason string) (string, error) {
	s.Logger.InfoContext(ctx, "rotation awaiting command correlation", "device_id", d.ID, "reason", reason)
	retained := e.RequestedAt
	if retained == nil {
		if date, err := parseDate(e.Date); err == nil {
			retained = &date
		}
	}
	if retained != nil && now.Sub(*retained) > s.Config.PendingAge {
		return "pending", fmt.Errorf("%s; candidate retained since at least %s", reason, retained.Format(time.RFC3339))
	}
	return "pending", nil
}

func (s *Service) pending(ctx context.Context, d jamf.Device, e *state.Entry, now time.Time) (string, error) {
	if e.Password == nil || *e.Password == "" || e.CommandUUID == "" || e.RequestedAt == nil {
		return s.block(ctx, e, "pending row is missing candidate, command UUID or request timestamp")
	}
	command, err := s.Jamf.Command(ctx, d, e.CommandUUID)
	if err != nil {
		return "pending", fmt.Errorf("read command %s: %w", e.CommandUUID, err)
	}
	switch command.Status {
	case "failed":
		return s.block(ctx, e, "MDM command failed: "+redactError(command.Detail, *e.Password))
	case "acknowledged":
		password, readErr := s.Jamf.Password(ctx, d)
		if readErr != nil {
			return "pending", readErr
		}
		if password == *e.Password {
			return s.promote(ctx, d, e, now)
		}
		// Acknowledgement may precede inventory/API propagation. Preserve the same
		// candidate and re-read on later runs, including after the alert threshold.
	case "pending", "unknown":
	default:
		return s.block(ctx, e, "unrecognized MDM status; review command history")
	}
	s.Logger.InfoContext(ctx, "rotation awaiting confirmation", "device_id", d.ID, "command_uuid", e.CommandUUID, "status", command.Status, "requested_at", *e.RequestedAt)
	if now.Sub(*e.RequestedAt) > s.Config.PendingAge {
		return "pending", fmt.Errorf("command %s has awaited confirmation since %s; candidate retained", e.CommandUUID, e.RequestedAt.Format(time.RFC3339))
	}
	return "pending", nil
}

func (s *Service) promote(ctx context.Context, d jamf.Device, e *state.Entry, now time.Time) (string, error) {
	if s.Config.DryRun {
		return "would-change", nil
	}
	if e.OPUUID == "" {
		uuid, err := s.Secrets.CreateSecret(ctx, d, *e.Password)
		if err != nil {
			return "pending", fmt.Errorf("create confirmed secret: %w", err)
		}
		if uuid == "" {
			return "pending", fmt.Errorf("1Password returned an empty item ID")
		}
		e.OPUUID = uuid
		if err = s.Store.Save(ctx, e); err != nil {
			return "pending", err
		}
	} else {
		if err := s.Secrets.UpdateSecret(ctx, e.OPUUID, *e.Password); err != nil {
			return "pending", fmt.Errorf("update confirmed secret: %w", err)
		}
	}
	e.Password = nil
	e.Phase = state.Stable
	e.Date = now.Format(time.RFC3339)
	e.LastError = ""
	// Retain the last command UUID and request time for diagnosis.
	if err := s.Store.Save(ctx, e); err != nil {
		return "pending", err
	}
	return "promoted", nil
}

func (s *Service) block(ctx context.Context, e *state.Entry, reason string) (string, error) {
	if !s.Config.DryRun {
		e.Phase = state.Blocked
		e.LastError = reason
		if err := s.Store.Save(ctx, e); err != nil {
			return "blocked", fmt.Errorf("%s; persist blocked state: %w", reason, err)
		}
	}
	if e.CommandUUID != "" {
		reason += " (command " + e.CommandUUID + ")"
	}
	return "blocked", fmt.Errorf("%s", reason)
}

func parseDate(value string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, value); err == nil {
		return t, nil
	}
	return time.Parse(time.UnixDate, value)
}

func generatePassword(length int) (string, error) {
	if length < 1 {
		return "", fmt.Errorf("password length must be positive")
	}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	password := make([]byte, length)
	for i := range password {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", fmt.Errorf("generate recovery password: %w", err)
		}
		password[i] = alphabet[n.Int64()]
	}
	return string(password), nil
}

func redactError(value, password string) string {
	if password == "" {
		return value
	}
	return strings.ReplaceAll(value, password, "[redacted]")
}
