package sync

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/woodleighschool/SetRecoveryPassword/internal/config"
	"github.com/woodleighschool/SetRecoveryPassword/internal/db"
	"github.com/woodleighschool/SetRecoveryPassword/internal/jamf"
	"github.com/woodleighschool/SetRecoveryPassword/internal/onepasswordsdk"
)

type Service struct {
	dbClient   db.Client
	jamfClient jamf.Client
	opClient   onepasswordsdk.Client
	config     *config.Config
	logger     *slog.Logger
}

func NewService(dbClient db.Client, jamfClient jamf.Client, opClient onepasswordsdk.Client, config *config.Config, logger *slog.Logger) *Service {
	return &Service{
		dbClient:   dbClient,
		jamfClient: jamfClient,
		opClient:   opClient,
		config:     config,
		logger:     logger,
	}
}

func (s *Service) Sync() error {
	s.logger.Info("Starting sync process")
	if s.config.DryRun {
		s.logger.Info("DRY_RUN enabled, no changes will be permanently made")
	}

	var computers []jamf.Device
	if s.config.JamfID != "" {
		computer, err := s.jamfClient.GetComputer(s.config.JamfID)
		if err != nil {
			s.logger.Error("Unable to get computer from Jamf", "computerID", s.config.JamfID, "error", err)
			return err
		}
		computers = []jamf.Device{*computer}
	} else {
		resp, err := s.jamfClient.GetComputers()
		if err != nil {
			s.logger.Error("Unable to get computers from Jamf", "error", err)
			return err
		}
		computers = resp
	}

	for i := range computers {
		computer := &computers[i]
		s.logger.Debug("Getting information from database", "computer", computer.Name)
		entry, err := s.dbClient.GetEntry(computer.ID)
		if err != nil {
			s.logger.Error("Unable to get infomation from database", "computer", computer.Name, "error", err)
			continue
		} else if entry == nil {
			s.NewDevice(computer)
			if err != nil {
				continue
			}
		} else {
			err := s.jamfClient.GetRecoveryPassword(computer)
			if err != nil {
				s.logger.Error("Unable to retrieve recovery password", "computer", computer.Name)
				continue
			}

			state, err := s.DetermineState(computer, entry)
			if err != nil {
				s.logger.Error("Unable to determine state, skipping out of caution", "computer", computer, "error", err)
				continue
			}

			switch state {
			case "JamfMissing":
				s.logger.Debug("No password found in Jamf", "computer", computer.Name)
				err := s.UpdateDevice(computer, entry)
				if err != nil {
					s.logger.Error("Unable to update device", "computer", computer.Name, "error", err)
					continue
				}
			case "JamfMismatch":
				s.logger.Debug("Password in database does not match password in Jamf", "computer", computer.Name)
				err := s.UpdateDevice(computer, entry)
				if err != nil {
					s.logger.Error("Unable to update device", "computer", computer.Name, "error", err)
				}
			case "Synced":
				s.logger.Debug("Password in Jamf matches password in database, migrating password to 1Password", "computer", computer)
				err := s.MigrateDevice(computer, entry)
				if err != nil {
					s.logger.Error("Unable to migrate password to 1Password", "computer", computer.Name, "error", err)
					continue
				}
			case "ErrorState":
				s.logger.Debug("Database entry has gotten into an abnormal state, resetting password to refresh state", "computer", computer.Name)
				err := s.ResetDevice(computer, entry)
				if err != nil {
					s.logger.Error("Unable to reset errored device", "computer", computer.Name, "error", err)
					continue
				}
			case "Expired":
				s.logger.Debug("Password has expired, setting a new one", "computer", computer.Name)
				err := s.ResetDevice(computer, entry)
				if err != nil {
					s.logger.Error("Unable to reset expired device", "computer", computer.Name, "error", err)
					continue
				}
			case "NoAction":
				s.logger.Debug("No action to be taken", "computer", computer.Name)
				continue
			default:
				s.logger.Warn("Unable to determine state, skipping out of caution", "computer", computer)
				continue
			}
		}
	}
	s.logger.Info("Device updates completed")
	return nil
}

func (s *Service) NewDevice(computer *jamf.Device) error {
	s.logger.Info("Computer not found in database, setting new password and creating record", "computer", computer.Name)
	computer.GenerateNewRecoveryPassword(s.config.PasswordLength)
	err := s.jamfClient.SetRecoveryPassword(computer)
	if err != nil {
		s.logger.Error("Unable to set recovery password", "computer", computer.Name, "error", err)
		return err
	}
	dateTime := time.Now().Format(time.UnixDate)
	err = s.dbClient.CreateEntry(&db.Entry{
		ID:       &computer.ID,
		Password: &computer.RecoveryPassword,
		Date:     &dateTime,
	})
	if err != nil {
		s.logger.Error("Unable to create database entry", "computer", computer.Name, "error", err)
	}
	return nil
}

func (s *Service) MigrateDevice(computer *jamf.Device, entry *db.Entry) error {
	if entry.OPUUID != nil {
		s.logger.Debug("Database entry already has 1Password UUID, updating password", "computer", computer.Name)
		err := s.opClient.UpdateSecret(*entry.OPUUID, *entry.Password)
		if err != nil {
			s.logger.Error("Unable to update 1Password entry", "computer", computer.Name, "error", err)
			return err
		}
	} else {
		s.logger.Debug("No 1Password UUID in database, creating new record", "computer", computer.Name)
		uuid, err := s.opClient.CreateSecret(computer, *entry.Password)
		if err != nil {
			s.logger.Error("Unable to create 1Password entry", "computer", computer.Name, "error", err)
			return err
		}
		entry.OPUUID = &uuid
	}
	s.logger.Debug("1Password updated, removing password from database and adding UUID", "computer", computer.Name)
	err := s.dbClient.UpdateEntryMigrate(entry)
	if err != nil {
		s.logger.Error("Unable to add 1Password UUID to database entry", "computer", computer.Name, "error", err)
	}
	return nil
}

func (s *Service) UpdateDevice(computer *jamf.Device, entry *db.Entry) error {
	if entry.GraceTicker == nil {
		s.logger.Debug("No grace ticker has been set, giving the system 7 days to sync before resetting", "computer", computer.Name)
		graceTicker := 7
		entry.GraceTicker = &graceTicker
		*entry.Date = time.Now().Format(time.UnixDate)
		err := s.dbClient.UpdateEntryTouch(entry)
		if err != nil {
			return fmt.Errorf("unable to set grace ticker: %w", err)
		}
	} else if *entry.GraceTicker > 0 {
		s.logger.Debug("Grace ticker is above 0, decreasing", "grace_ticker", entry.GraceTicker, "computer", computer.Name)
		*entry.GraceTicker -= 1
		*entry.Date = time.Now().Format(time.UnixDate)
		err := s.dbClient.UpdateEntryTouch(entry)
		if err != nil {
			return fmt.Errorf("unable to set grace ticker: %w", err)
		}
	} else {
		s.logger.Debug("Grace ticker is at 0, resetting password to try sync again", "computer", computer.Name)
		err := s.ResetDevice(computer, entry)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) ResetDevice(computer *jamf.Device, entry *db.Entry) error {
	computer.GenerateNewRecoveryPassword(s.config.PasswordLength)
	err := s.jamfClient.SetRecoveryPassword(computer)
	if err != nil {
		return fmt.Errorf("unable to set new password: %w", err)
	}
	entry.Password = &computer.RecoveryPassword
	*entry.Date = time.Now().Format(time.UnixDate)
	err = s.dbClient.UpdateEntryPassword(entry)
	if err != nil {
		return fmt.Errorf("unable to update password in database: %w", err)
	}
	return nil
}

func (s *Service) DetermineState(computer *jamf.Device, entry *db.Entry) (string, error) {
	if entry.Password != nil {
		if computer.RecoveryPassword == "" {
			return "JamfMissing", nil
		} else if computer.RecoveryPassword != *entry.Password {
			return "JamfMismatch", nil
		} else {
			return "Synced", nil
		}
	} else if entry.Password == nil {
		if entry.OPUUID == nil {
			return "ErrorState", nil
		}
		entryDate, err := time.Parse(time.UnixDate, *entry.Date)
		if err != nil {
			return "", fmt.Errorf("unable to parse date in database: %w", err)
		} else {
			thresholdDate := entryDate.AddDate(0, 0, 31)
			if thresholdDate.Before(time.Now()) {
				return "Expired", nil
			} else {
				return "NoAction", nil
			}
		}
	} else {
		return "", fmt.Errorf("unable to determine state")
	}
}
