package database

import (
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/aslamabdika18/go-auth-jwt/internal/config"
)

func TestConnectionStringEscapesCredentials(t *testing.T) {
	cfg := &config.Config{
		DBHost:     "localhost",
		DBPort:     "5432",
		DBName:     "auth db",
		DBUser:     "user@domain",
		DBPassword: `p@ss:/?#%`,
		DBSSLMode:  "require",
	}

	raw := ConnectionString(cfg)
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(ConnectionString()) error: %v", err)
	}

	if parsed.Scheme != "postgres" {
		t.Errorf("scheme = %q, want postgres", parsed.Scheme)
	}
	if parsed.Host != net.JoinHostPort(cfg.DBHost, cfg.DBPort) {
		t.Errorf("host = %q, want %q", parsed.Host, net.JoinHostPort(cfg.DBHost, cfg.DBPort))
	}
	if got := parsed.User.Username(); got != cfg.DBUser {
		t.Errorf("username = %q, want %q", got, cfg.DBUser)
	}
	password, ok := parsed.User.Password()
	if !ok {
		t.Fatal("URL does not contain a password")
	}
	if password != cfg.DBPassword {
		t.Errorf("password = %q, want original password", password)
	}
	if got := parsed.Query().Get("sslmode"); got != cfg.DBSSLMode {
		t.Errorf("sslmode = %q, want %q", got, cfg.DBSSLMode)
	}
	if got := parsed.Path; got != "/auth db" {
		t.Errorf("path = %q, want %q", got, "/auth db")
	}
}

func TestConnectionStringSupportsIPv6Host(t *testing.T) {
	cfg := &config.Config{
		DBHost: "2001:db8::1", DBPort: "5432", DBName: "auth",
		DBUser: "app", DBPassword: "secret", DBSSLMode: "disable",
	}

	parsed, err := url.Parse(ConnectionString(cfg))
	if err != nil {
		t.Fatalf("url.Parse(ConnectionString()) error: %v", err)
	}
	if parsed.Host != "[2001:db8::1]:5432" {
		t.Errorf("host = %q, want [2001:db8::1]:5432", parsed.Host)
	}
}

func TestConnectReturnsErrorForUnreachableDatabase(t *testing.T) {
	cfg := &config.Config{
		DBHost:     "127.0.0.1",
		DBPort:     "1",
		DBName:     "unreachable_test",
		DBUser:     "test",
		DBPassword: "test",
		DBSSLMode:  "disable",
	}

	start := time.Now()
	pool, err := Connect(cfg)
	if pool != nil {
		pool.Close()
	}
	if err == nil {
		t.Fatal("Connect() expected an error for an unreachable database")
	}
	if time.Since(start) > 7*time.Second {
		t.Fatalf("Connect() took %s, expected to respect its 5-second timeout", time.Since(start))
	}
}
