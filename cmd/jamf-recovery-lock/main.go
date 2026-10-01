package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/pflag"
	"github.com/woodleighschool/jamf-recovery-lock/internal/config"
	"github.com/woodleighschool/jamf-recovery-lock/internal/jamf"
	"github.com/woodleighschool/jamf-recovery-lock/internal/onepasswordsdk"
	"github.com/woodleighschool/jamf-recovery-lock/internal/recovery"
	"github.com/woodleighschool/jamf-recovery-lock/internal/state"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(); err != nil {
		logger.Error("jamf-recovery-lock failed", "error", err)
		os.Exit(1)
	}
}

func run() error {
	flags := pflag.NewFlagSet("jamf-recovery-lock", pflag.ContinueOnError)
	dryRun := flags.Bool("dry-run", false, "Inspect one run without changing Jamf, PostgreSQL or 1Password")
	showVersion := flags.Bool("version", false, "Show build version")
	help := flags.BoolP("help", "h", false, "Show usage")
	flags.SetOutput(os.Stderr)
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	if *help {
		_, _ = fmt.Fprintln(os.Stdout, "jamf-recovery-lock: reconcile Recovery Lock once. Configure using environment variables documented in README.md.")
		flags.PrintDefaults()
		return nil
	}
	if *showVersion {
		_, _ = fmt.Fprintf(os.Stdout, "jamf-recovery-lock %s\ncommit: %s\nbuilt: %s\n", version, commit, date)
		return nil
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if flags.Changed("dry-run") {
		cfg.DryRun = *dryRun
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
	signalCtx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, cfg.RunTimeout)
	defer cancel()
	logger.InfoContext(ctx, "jamf-recovery-lock starting", "version", version, "dry_run", cfg.DryRun)
	store, err := state.New(ctx, cfg, cfg.DryRun)
	if err != nil {
		return err
	}
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer closeCancel()
		if closeErr := store.Close(closeCtx); closeErr != nil {
			logger.Warn("close recovery state", "error", closeErr)
		}
	}()
	jamfClient, err := jamf.NewClient(cfg, logger)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := jamfClient.Close(); closeErr != nil {
			logger.Warn("close Jamf client", "error", closeErr)
		}
	}()
	secrets, err := onepasswordsdk.NewClient(ctx, cfg, version, logger)
	if err != nil {
		return err
	}
	service := recovery.Service{Store: store, Jamf: jamfClient, Secrets: secrets, Config: cfg, Logger: logger}
	_, err = service.Run(ctx)
	return err
}
