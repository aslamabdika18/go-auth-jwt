package config

import (
	"strings"
	"testing"
)

func validConfig() *Config {
	return &Config{
		AppName: "auth", AppEnv: "test", AppPort: "8080",
		DBHost: "localhost", DBPort: "5432", DBName: "auth_test",
		DBUser: "test", DBPassword: "secret", DBSSLMode: "disable",
		JWTSecret: "test-secret", JWTAccessTokenTTL: 15,
		JWTRefreshTokenTTL: 60,
	}
}

func TestValidateAcceptsValidConfig(t *testing.T) {
	if err := validConfig().Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestValidateRejectsMissingRequiredFields(t *testing.T) {
	fields := []struct {
		name string
		set  func(*Config)
	}{
		{"APP_NAME", func(c *Config) { c.AppName = "" }},
		{"APP_ENV", func(c *Config) { c.AppEnv = "" }},
		{"APP_PORT", func(c *Config) { c.AppPort = "" }},
		{"DB_HOST", func(c *Config) { c.DBHost = "" }},
		{"DB_PORT", func(c *Config) { c.DBPort = "" }},
		{"DB_NAME", func(c *Config) { c.DBName = "" }},
		{"DB_USER", func(c *Config) { c.DBUser = "" }},
		{"DB_PASSWORD", func(c *Config) { c.DBPassword = "" }},
		{"DB_SSLMODE", func(c *Config) { c.DBSSLMode = "" }},
		{"JWT_SECRET", func(c *Config) { c.JWTSecret = "" }},
	}

	for _, field := range fields {
		t.Run(field.name, func(t *testing.T) {
			cfg := validConfig()
			field.set(cfg)
			err := cfg.Validate()
			if err == nil {
				t.Fatal("Validate() expected an error")
			}
			if !strings.Contains(err.Error(), field.name) {
				t.Errorf("error %q does not mention %s", err, field.name)
			}
		})
	}
}

func TestValidateRejectsNonPositiveTokenTTL(t *testing.T) {
	tests := []struct {
		name string
		set  func(*Config)
	}{
		{"access TTL zero", func(c *Config) { c.JWTAccessTokenTTL = 0 }},
		{"access TTL negative", func(c *Config) { c.JWTAccessTokenTTL = -1 }},
		{"refresh TTL zero", func(c *Config) { c.JWTRefreshTokenTTL = 0 }},
		{"refresh TTL negative", func(c *Config) { c.JWTRefreshTokenTTL = -1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := validConfig()
			test.set(cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("Validate() expected an error")
			}
		})
	}
}
