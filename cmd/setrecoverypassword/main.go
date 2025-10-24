package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/robfig/cron/v3"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/woodleighschool/SetRecoveryPassword/internal/config"
	"github.com/woodleighschool/SetRecoveryPassword/internal/db"
	"github.com/woodleighschool/SetRecoveryPassword/internal/jamf"
	"github.com/woodleighschool/SetRecoveryPassword/internal/onepasswordsdk"
	"github.com/woodleighschool/SetRecoveryPassword/internal/sync"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		slog.Error("Command execution failed", "error", err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "setrecoverypassword",
		Short: "Jamf Pro Recovery Password Management Tool",
		Long:  "Sets a random recovery password for each computer in Jamf Pro according to configured schedules",

		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return update()
		},
	}

	flags := cmd.Flags()
	flags.String("schedule", "", "cron schedule expression for automatic sync (e.g., '0 2 * * *' for daily at 2 AM)")
	flags.String("log-level", "info", "logging level: debug, info, warn, error")
	flags.Bool("dry-run", false, "Run tool without making any changes")
	flags.Int("password-length", 10, "Desired password length for recovery passwords")
	flags.String("instance-domain", "", "Jamf Pro host")
	flags.String("client-id", "", "Jamf Pro API client id")
	flags.String("client-secret", "", "Jamf Pro API client secret")
	flags.String("jamf-id", "", "Jamf ID for running sync against a specific device")
	flags.String("onepassword-token", "", "1Password Service Account token")
	flags.String("onepassword-vault-id", "", "1Password Vault ID to store passwords in")
	flags.String("database-host", "", "PostgreSQL host to store state table in")
	flags.String("database-port", "", "PostgreSQL port")
	flags.String("database-username", "", "Username for PostgreSQL instance")
	flags.String("database-password", "", "Password for the PostgreSQL user")

	if err := viper.BindPFlag("schedule", flags.Lookup("schedule")); err != nil {
		panic(fmt.Sprintf("failed to bind schedule flag: %v", err))
	}

	if err := viper.BindPFlag("log_level", flags.Lookup("log-level")); err != nil {
		panic(fmt.Sprintf("failed to bind log-level flag: %v", err))
	}

	if err := viper.BindPFlag("dry_run", flags.Lookup("dry-run")); err != nil {
		panic(fmt.Sprintf("failed to bind dry-run flag: %v", err))
	}

	if err := viper.BindPFlag("password_length", flags.Lookup("password-length")); err != nil {
		panic(fmt.Sprintf("failed to bind password_length flags: %v", err))
	}

	if err := viper.BindPFlag("instance_domain", flags.Lookup("instance-domain")); err != nil {
		panic(fmt.Sprintf("failed to bind instance-domain flag: %v", err))
	}

	if err := viper.BindPFlag("client_id", flags.Lookup("client-id")); err != nil {
		panic(fmt.Sprintf("failed to bind client-id flag: %v", err))
	}

	if err := viper.BindPFlag("client_secret", flags.Lookup("client-secret")); err != nil {
		panic(fmt.Sprintf("failed to bind client-secret flag: %v", err))
	}

	if err := viper.BindPFlag("jamf_id", flags.Lookup("jamf-id")); err != nil {
		panic(fmt.Sprintf("failed to bind jamf-id flag: %v", err))
	}

	if err := viper.BindPFlag("onepassword_token", flags.Lookup("onepassword-token")); err != nil {
		panic(fmt.Sprintf("failed to bind onepassword-token flag: %v", err))
	}
	if err := viper.BindPFlag("onepassword_vault_id", flags.Lookup("onepassword-vault-id")); err != nil {
		panic(fmt.Sprintf("failed to bind onepassword-vault-id flag: %v", err))
	}

	if err := viper.BindPFlag("database_host", flags.Lookup("database-host")); err != nil {
		panic(fmt.Sprintf("failed to bind database-host flag: %v", err))
	}

	if err := viper.BindPFlag("database_port", flags.Lookup("database-port")); err != nil {
		panic(fmt.Sprintf("failed to bind database-port flag: %v", err))
	}

	if err := viper.BindPFlag("database_username", flags.Lookup("database-username")); err != nil {
		panic(fmt.Sprintf("failed to bind database-username flag: %v", err))
	}

	if err := viper.BindPFlag("database_password", flags.Lookup("database-password")); err != nil {
		panic(fmt.Sprintf("failed to bind database-password flag: %v", err))
	}

	viper.SetDefault("name", "setrecoverypassword")
	viper.SetDefault("version", version)
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	cmd.AddCommand(newVersionCmd())

	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("setrecoverypassword %s\n", version)
			fmt.Printf("commit: %s\n", commit)
			fmt.Printf("built: %s\n", date)
		},
	}
}

func update() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load configuration: %w", err)
	}

	logger := setupLogging(cfg)

	logger.Info("SetRecoveryPassword starting",
		"version", version,
		"log_level", cfg.LogLevel,
		"oneshot_mode", cfg.IsOneshot(),
	)

	dbClient, err := db.NewClient(cfg, logger)
	if err != nil {
		return fmt.Errorf("unable to create db client: %w", err)
	}

	jamfClient, err := jamf.NewClient(cfg, logger)
	if err != nil {
		return fmt.Errorf("unable to create jamf client: %w", err)
	}
	defer func() {
		if closeErr := jamfClient.Close(); closeErr != nil {
			logger.Warn("failed to close Jamf client", "error", closeErr)
		}
	}()

	onePasswordClient, err := onepasswordsdk.NewClient(cfg, logger)
	if err != nil {
		return fmt.Errorf("unable to create onepassword client: %w", err)
	}

	syncService := sync.NewService(dbClient, jamfClient, onePasswordClient, cfg, logger)

	if cfg.IsOneshot() {
		logger.Info("Running sync once (oneshot mode)")
		return syncService.Sync()
	}

	logger.Info("Setting up scheduled sync", "schedule", cfg.SyncSchedule)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	c := cron.New()

	_, err = c.AddFunc(cfg.SyncSchedule, func() {
		logger.Info("Starting scheduled sync")
		if err := syncService.Sync(); err != nil {
			logger.Error("Scheduled sync failed", "error", err)
		} else {
			logger.Info("Scheduled sync completed successfully")
		}
	})
	if err != nil {
		return fmt.Errorf("failed to add cron job: %w", err)
	}

	c.Start()
	defer c.Stop()

	logger.Info("Scheduler started, waiting for signals...")

	<-ctx.Done()
	logger.Info("Shutdown signal received, stopping...")

	return nil
}

func setupLogging(cfg *config.Config) *slog.Logger {
	opts := &slog.HandlerOptions{
		Level: cfg.GetLogLevel(),
	}

	handler := slog.NewJSONHandler(os.Stdout, opts)
	logger := slog.New(handler)

	slog.SetDefault(logger)

	return logger
}
