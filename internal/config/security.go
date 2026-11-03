package config

import (
	"fmt"
	"strings"
)

func (c Config) validate() error {
	if c.ShutdownTimeout <= 0 {
		return fmt.Errorf("SHUTDOWN_TIMEOUT must be positive")
	}
	if len(c.ReaderKey) < 32 || len(c.WriterKey) < 32 || c.ReaderKey == c.WriterKey {
		return fmt.Errorf("API_READER_KEY and API_WRITER_KEY must be distinct and at least 32 bytes long")
	}
	if strings.TrimSpace(c.ReaderKey) != c.ReaderKey || strings.TrimSpace(c.WriterKey) != c.WriterKey {
		return fmt.Errorf("API keys must not have surrounding whitespace")
	}
	if c.RequestsPerMinute < 1 || c.RequestsPerMinute > 100000 {
		return fmt.Errorf("RATE_LIMIT_PER_MINUTE must be between 1 and 100000")
	}
	if c.MaxBodyBytes < 1 || c.MaxBodyBytes > 10485760 {
		return fmt.Errorf("MAX_BODY_BYTES must be between 1 and 10485760")
	}
	return nil
}
