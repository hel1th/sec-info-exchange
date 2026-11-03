// Package config loads and validates application configuration.
package config

import (
	"fmt"
	"time"

	"github.com/caarlos0/env/v11"
)

// Config contains runtime settings.
type Config struct {
	HTTPAddr          string        `env:"HTTP_ADDR" envDefault:":8080"`
	ShutdownTimeout   time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"10s"`
	DatabaseURL       string        `env:"DATABASE_URL,required,notEmpty"`
	ReaderKey         string        `env:"API_READER_KEY,required,notEmpty"`
	WriterKey         string        `env:"API_WRITER_KEY,required,notEmpty"`
	RequestsPerMinute int           `env:"RATE_LIMIT_PER_MINUTE" envDefault:"120"`
	MaxBodyBytes      int64         `env:"MAX_BODY_BYTES" envDefault:"65536"`
}

// Load reads environment variables, applying defaults for local development.
func Load() (Config, error) {
	c, err := env.ParseAs[Config]()
	if err != nil {
		return Config{}, fmt.Errorf("parse configuration: %w", err)
	}
	if validationErr := c.validate(); validationErr != nil {
		return Config{}, validationErr
	}
	return c, nil
}
