package config

import (
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

// Config is the environment configuration for one reconciliation run.
type Config struct {
	InstanceDomain   string `env:"INSTANCE_DOMAIN,required,notEmpty"`
	ClientID         string `env:"CLIENT_ID,required,notEmpty"`
	ClientSecret     string `env:"CLIENT_SECRET,required,notEmpty"`
	JamfID           string `env:"JAMF_ID"`
	OnePasswordToken string `env:"ONEPASSWORD_TOKEN,required,notEmpty"`
	VaultID          string `env:"ONEPASSWORD_VAULT_ID,required,notEmpty"`
	DatabaseHost     string `env:"DATABASE_HOST,required,notEmpty"`
	DatabasePort     int    `env:"DATABASE_PORT" envDefault:"5432"`
	DatabaseUsername string `env:"DATABASE_USERNAME,required,notEmpty"`
	DatabasePassword string `env:"DATABASE_PASSWORD,required,notEmpty"`
	// Keep the existing ten-character password and 31-day rotation defaults.
	PasswordLength int           `env:"PASSWORD_LENGTH" envDefault:"10"`
	RotationAge    time.Duration `env:"ROTATION_AGE" envDefault:"744h"`
	// PendingAge alerts on an overdue command; it never triggers another rotation.
	PendingAge time.Duration `env:"PENDING_AGE" envDefault:"168h"`
	RunTimeout time.Duration `env:"RUN_TIMEOUT" envDefault:"30m"`
	LogLevel   slog.Level    `env:"LOG_LEVEL" envDefault:"info"`
	DryRun     bool          `env:"DRY_RUN" envDefault:"false"`
}

func Load() (*Config, error) {
	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		return nil, fmt.Errorf("configuration: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) Validate() error {
	if !strings.Contains(c.InstanceDomain, "://") {
		c.InstanceDomain = "https://" + c.InstanceDomain
	}
	u, err := url.Parse(c.InstanceDomain)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("INSTANCE_DOMAIN must be an HTTPS server URL or hostname")
	}
	c.InstanceDomain = strings.TrimRight(c.InstanceDomain, "/")
	if c.DatabasePort < 1 || c.DatabasePort > 65535 {
		return fmt.Errorf("DATABASE_PORT must be between 1 and 65535")
	}
	if c.PasswordLength < 1 {
		return fmt.Errorf("PASSWORD_LENGTH must be positive")
	}
	if c.RotationAge <= 0 || c.PendingAge <= 0 || c.RunTimeout <= 0 {
		return fmt.Errorf("ROTATION_AGE, PENDING_AGE and RUN_TIMEOUT must be positive durations")
	}
	if c.JamfID != "" {
		id, e := strconv.Atoi(c.JamfID)
		if e != nil || id <= 0 {
			return fmt.Errorf("JAMF_ID must be a positive integer")
		}
	}
	return nil
}
