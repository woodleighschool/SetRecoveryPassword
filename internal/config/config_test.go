package config

import (
	"testing"
	"time"
)

func TestLoadValidatesProductionEnvironment(t *testing.T) {
	for k, v := range map[string]string{"INSTANCE_DOMAIN": "jamf.example.test", "CLIENT_ID": "client", "CLIENT_SECRET": "secret", "ONEPASSWORD_TOKEN": "token", "ONEPASSWORD_VAULT_ID": "vault", "DATABASE_HOST": "localhost", "DATABASE_USERNAME": "user", "DATABASE_PASSWORD": "password", "DATABASE_PORT": "6543", "PASSWORD_LENGTH": "12", "LOG_LEVEL": "debug"} {
		t.Setenv(k, v)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.InstanceDomain != "https://jamf.example.test" || cfg.DatabasePort != 6543 || cfg.PasswordLength != 12 || cfg.RotationAge != 31*24*time.Hour || cfg.LogLevel.String() != "DEBUG" {
		t.Fatalf("unexpected config: domain=%s port=%d length=%d", cfg.InstanceDomain, cfg.DatabasePort, cfg.PasswordLength)
	}
	for _, tc := range []struct{ k, v string }{{"DATABASE_PORT", "0"}, {"PASSWORD_LENGTH", "0"}, {"RUN_TIMEOUT", "0s"}, {"JAMF_ID", "invalid"}, {"INSTANCE_DOMAIN", "https://user:pass@jamf.example.test"}, {"LOG_LEVEL", "nonsense"}, {"DRY_RUN", "maybe"}} {
		t.Run(tc.k, func(t *testing.T) {
			t.Setenv(tc.k, tc.v)
			if _, err := Load(); err == nil {
				t.Fatal("invalid configuration accepted")
			}
		})
	}
}
